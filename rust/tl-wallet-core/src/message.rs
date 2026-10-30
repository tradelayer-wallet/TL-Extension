//! BIP-137 message signing and verification.
//!
//! Legacy `signMessage` signed `sha256(message)` with the wallet key: no magic prefix, a
//! single hash, no recovery header. A page could therefore pick `message` so that
//! `sha256(message)` equals a transaction sighash and obtain a valid transaction signature
//! ("signing oracle"). The digest here is `sha256d(varint(len(magic)) || magic ||
//! varint(len(msg)) || msg)` with the per-network magic, which cannot be a transaction
//! sighash preimage, and the output is the 65-byte recoverable signature (header 31..=34 for
//! p2pkh, 39..=42 for p2wpkh) in base64.

use crate::address::{Address, AddressKind};
use crate::error::{Error, Result};
use crate::keys::Account;
use crate::network::{AccountKind, Network};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::Message;
use bitcoin::{CompressedPublicKey, ScriptBuf};

pub const MAX_SIGNED_MESSAGE_BYTES: usize = 64 * 1024;

fn push_varint(buf: &mut Vec<u8>, n: usize) {
    let n = n as u64;
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// The 32-byte digest that is signed for `message` on `network`.
pub fn message_digest(network: Network, message: &[u8]) -> [u8; 32] {
    let magic = network.params().message_magic.as_bytes();
    let mut buf = Vec::with_capacity(magic.len() + message.len() + 18);
    push_varint(&mut buf, magic.len());
    buf.extend_from_slice(magic);
    push_varint(&mut buf, message.len());
    buf.extend_from_slice(message);
    sha256d::Hash::hash(&buf).to_byte_array()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>> {
    const BAD: Error = Error::InvalidSignature("invalid base64");
    if !s.len().is_multiple_of(4) || s.len() > 4096 {
        return Err(BAD);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (ci, chunk) in bytes.chunks(4).enumerate() {
        let last = (ci + 1) * 4 == bytes.len();
        let mut n = 0u32;
        let mut pad = 0;
        for &c in chunk {
            n <<= 6;
            if c == b'=' {
                if !last {
                    return Err(BAD);
                }
                pad += 1;
            } else {
                if pad > 0 {
                    return Err(BAD);
                }
                let v = B64.iter().position(|x| *x == c).ok_or(BAD)?;
                n |= v as u32;
            }
        }
        if pad > 2 {
            return Err(BAD);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Sign without any authorization check. Crate-private: the public entry point is
/// [`crate::capability::sign_message`], which requires a matching signing capability.
pub(crate) fn sign_message_unchecked(account: &Account, message: &[u8]) -> Result<String> {
    if message.len() > MAX_SIGNED_MESSAGE_BYTES {
        return Err(Error::MessageTooLong {
            len: message.len(),
            max: MAX_SIGNED_MESSAGE_BYTES,
        });
    }
    let digest = message_digest(account.network(), message);
    let msg = Message::from_digest(digest);
    let key = account.receive_key();
    let sig = account.secp().sign_ecdsa_recoverable(&msg, key.secret());
    let (rec, compact) = sig.serialize_compact();
    let rec = u8::try_from(rec.to_i32()).map_err(|_| Error::InvalidSignature("recovery id"))?;
    let base = match account.network().params().account_kind {
        AccountKind::P2wpkh => 39u8,
        AccountKind::P2pkh => 31u8,
    };
    let mut out = [0u8; 65];
    out[0] = base + rec;
    out[1..].copy_from_slice(&compact);
    Ok(b64_encode(&out))
}

/// Verify a BIP-137 signature for `address` (p2pkh or p2wpkh) on its network. The header
/// range must match the address type.
pub fn verify_message(address: &Address, message: &[u8], signature_b64: &str) -> Result<bool> {
    if message.len() > MAX_SIGNED_MESSAGE_BYTES {
        return Err(Error::MessageTooLong {
            len: message.len(),
            max: MAX_SIGNED_MESSAGE_BYTES,
        });
    }
    let raw = b64_decode(signature_b64)?;
    if raw.len() != 65 {
        return Err(Error::InvalidSignature("signature must be 65 bytes"));
    }
    let header = raw[0];
    let (kind_ok, rec) = match (address.kind(), header) {
        (AddressKind::P2pkh, 31..=34) => (true, header - 31),
        (AddressKind::P2wpkh, 39..=42) => (true, header - 39),
        _ => (false, 0),
    };
    if !kind_ok {
        return Ok(false);
    }
    let rec_id =
        RecoveryId::from_i32(i32::from(rec)).map_err(|_| Error::InvalidSignature("recovery id"))?;
    let sig = RecoverableSignature::from_compact(&raw[1..], rec_id)
        .map_err(|_| Error::InvalidSignature("malformed compact signature"))?;
    let digest = message_digest(address.network(), message);
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let pk = match secp.recover_ecdsa(&Message::from_digest(digest), &sig) {
        Ok(pk) => pk,
        Err(_) => return Ok(false),
    };
    let cpk = CompressedPublicKey(pk);
    let expected: ScriptBuf = match address.kind() {
        AddressKind::P2pkh => ScriptBuf::new_p2pkh(&cpk.pubkey_hash()),
        _ => ScriptBuf::new_p2wpkh(&cpk.wpubkey_hash()),
    };
    Ok(expected.as_script() == address.script_pubkey())
}
