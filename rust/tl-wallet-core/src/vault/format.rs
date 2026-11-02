//! The versioned sealed-vault format.
//!
//! ```text
//! text   = "tlvault:" base64(blob)
//! blob   = header(60) || ciphertext || tag(16)
//! header = "TLVT" version(1) kind(1) network(1) kdf(1) p0(4,BE) p1(4,BE) p2(4,BE) salt(16) nonce(24)
//! kdf 1  = scrypt           p0 = log2(N), p1 = r, p2 = p
//! kdf 2  = PBKDF2-HMAC-SHA256  p0 = iterations, p1 = p2 = 0
//! key    = KDF(password, salt) -> 32 bytes
//! AEAD   = XChaCha20-Poly1305(key, nonce, aad = header(60 bytes), plaintext)
//! ```
//!
//! The whole header is associated data, so the version, payload kind, network and every KDF
//! parameter are authenticated: changing any of them (or the salt or nonce) changes the key or the
//! tag and decryption fails with [`VaultError::WrongPasswordOrTampered`], never with garbage.

use super::store::Random;
use super::{Secret, VaultError};
use crate::network::Network;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// The newest format this build writes and reads.
pub const CURRENT_VERSION: u8 = 1;
pub const TEXT_PREFIX: &str = "tlvault:";
const MAGIC: &[u8; 4] = b"TLVT";
pub const HEADER_LEN: usize = 60;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// A mnemonic is under 200 bytes; the cap bounds work done on hostile blobs.
pub const MAX_PLAINTEXT: usize = 1024;
const MAX_TEXT: usize = 8 * 1024;

/// What the sealed bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// A BIP-39 phrase in canonical spelling.
    MnemonicPhrase,
}

impl PayloadKind {
    fn tag(self) -> u8 {
        match self {
            PayloadKind::MnemonicPhrase => 1,
        }
    }

    fn from_tag(t: u8) -> Result<Self, VaultError> {
        match t {
            1 => Ok(PayloadKind::MnemonicPhrase),
            _ => Err(VaultError::Malformed("unknown payload kind")),
        }
    }
}

fn network_tag(n: Network) -> u8 {
    match n {
        Network::Ltc => 1,
        Network::LtcTest => 2,
        Network::Btc => 3,
        Network::BtcTest => 4,
        Network::Doge => 5,
        Network::DogeTest => 6,
        Network::LtcRegtest => 7,
        Network::BtcRegtest => 8,
    }
}

fn network_from_tag(t: u8) -> Result<Network, VaultError> {
    Ok(match t {
        1 => Network::Ltc,
        2 => Network::LtcTest,
        3 => Network::Btc,
        4 => Network::BtcTest,
        5 => Network::Doge,
        6 => Network::DogeTest,
        7 => Network::LtcRegtest,
        8 => Network::BtcRegtest,
        _ => return Err(VaultError::Malformed("unknown network tag")),
    })
}

/// Key-derivation function and its recorded parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Scrypt { log_n: u8, r: u32, p: u32 },
    Pbkdf2Sha256 { iterations: u32 },
}

impl Kdf {
    /// Default for new vaults: scrypt N = 2^15, r = 8, p = 1 (32 MiB, memory-hard).
    pub const DEFAULT: Kdf = Kdf::Scrypt {
        log_n: 15,
        r: 8,
        p: 1,
    };
    /// Cheapest accepted scrypt setting (1 MiB). For tests and constrained hosts only.
    pub const FLOOR_SCRYPT: Kdf = Kdf::Scrypt {
        log_n: 10,
        r: 8,
        p: 1,
    };
    /// PBKDF2 for hosts without the memory for scrypt: 600 000 iterations.
    pub const PBKDF2_DEFAULT: Kdf = Kdf::Pbkdf2Sha256 {
        iterations: 600_000,
    };

    /// Accepted window. The upper bounds cap memory (at most 2^28 bytes for scrypt) and time on
    /// attacker-supplied headers; the lower bounds refuse trivially weak settings.
    pub fn validate(&self) -> Result<(), VaultError> {
        match *self {
            Kdf::Scrypt { log_n, r, p } => {
                if !(10..=20).contains(&log_n) {
                    return Err(VaultError::KdfParamsOutOfRange(
                        "scrypt log_n not in 10..=20",
                    ));
                }
                if !(1..=16).contains(&r) {
                    return Err(VaultError::KdfParamsOutOfRange("scrypt r not in 1..=16"));
                }
                if !(1..=4).contains(&p) {
                    return Err(VaultError::KdfParamsOutOfRange("scrypt p not in 1..=4"));
                }
                // 128 * r * 2^log_n bytes
                if (r as u64) << (log_n as u32) > (1u64 << 21) {
                    return Err(VaultError::KdfParamsOutOfRange(
                        "scrypt memory above 256 MiB",
                    ));
                }
                Ok(())
            }
            Kdf::Pbkdf2Sha256 { iterations } => {
                if !(1_000..=4_000_000).contains(&iterations) {
                    return Err(VaultError::KdfParamsOutOfRange(
                        "pbkdf2 iterations not in 1000..=4000000",
                    ));
                }
                Ok(())
            }
        }
    }

    fn encode(&self) -> (u8, [u32; 3]) {
        match *self {
            Kdf::Scrypt { log_n, r, p } => (1, [log_n as u32, r, p]),
            Kdf::Pbkdf2Sha256 { iterations } => (2, [iterations, 0, 0]),
        }
    }

    fn decode(id: u8, p: [u32; 3]) -> Result<Kdf, VaultError> {
        let kdf = match id {
            1 => Kdf::Scrypt {
                log_n: u8::try_from(p[0])
                    .map_err(|_| VaultError::KdfParamsOutOfRange("scrypt log_n"))?,
                r: p[1],
                p: p[2],
            },
            2 => {
                if p[1] != 0 || p[2] != 0 {
                    return Err(VaultError::Malformed("pbkdf2 reserved parameters not zero"));
                }
                Kdf::Pbkdf2Sha256 { iterations: p[0] }
            }
            other => return Err(VaultError::UnsupportedKdf(other)),
        };
        kdf.validate()?;
        Ok(kdf)
    }

    fn derive(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let mut key = Zeroizing::new([0u8; 32]);
        match *self {
            Kdf::Scrypt { log_n, r, p } => {
                let params = scrypt::Params::new(log_n, r, p, 32)
                    .map_err(|_| VaultError::KdfParamsOutOfRange("scrypt parameters"))?;
                scrypt::scrypt(password, salt, &params, key.as_mut_slice())
                    .map_err(|_| VaultError::KdfParamsOutOfRange("scrypt output"))?;
            }
            Kdf::Pbkdf2Sha256 { iterations } => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, key.as_mut_slice());
            }
        }
        Ok(key)
    }
}

/// The authenticated header of a sealed blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub kind: PayloadKind,
    pub network: Network,
    pub kdf: Kdf,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4] = self.version;
        out[5] = self.kind.tag();
        out[6] = network_tag(self.network);
        let (id, p) = self.kdf.encode();
        out[7] = id;
        out[8..12].copy_from_slice(&p[0].to_be_bytes());
        out[12..16].copy_from_slice(&p[1].to_be_bytes());
        out[16..20].copy_from_slice(&p[2].to_be_bytes());
        out[20..36].copy_from_slice(&self.salt);
        out[36..60].copy_from_slice(&self.nonce);
        out
    }

    fn be32(b: &[u8]) -> u32 {
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        u32::from_be_bytes(a)
    }

    /// Parse the header of raw blob bytes. Version checks come first, before any KDF work.
    fn parse(blob: &[u8]) -> Result<Header, VaultError> {
        if blob.len() < HEADER_LEN + TAG_LEN {
            return Err(VaultError::Malformed("blob too short"));
        }
        if &blob[..4] != MAGIC {
            return Err(VaultError::Malformed("bad magic"));
        }
        let version = blob[4];
        if version == 0 || version > CURRENT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        let kind = PayloadKind::from_tag(blob[5])?;
        let network = network_from_tag(blob[6])?;
        let kdf = Kdf::decode(
            blob[7],
            [
                Self::be32(&blob[8..12]),
                Self::be32(&blob[12..16]),
                Self::be32(&blob[16..20]),
            ],
        )?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&blob[20..36]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[36..60]);
        Ok(Header {
            version,
            kind,
            network,
            kdf,
            salt,
            nonce,
        })
    }
}

fn decode_text(text: &str) -> Result<Vec<u8>, VaultError> {
    if text.len() > MAX_TEXT {
        return Err(VaultError::Malformed("blob too large"));
    }
    let body = text
        .strip_prefix(TEXT_PREFIX)
        .ok_or(VaultError::Malformed("missing tlvault: prefix"))?;
    STANDARD
        .decode(body.as_bytes())
        .map_err(|_| VaultError::Malformed("not base64"))
}

/// Read the header without a password. Unauthenticated: use only for display and routing.
pub fn peek(text: &str) -> Result<Header, VaultError> {
    Header::parse(&decode_text(text)?)
}

/// Seal `plaintext` under `password`.
pub fn seal(
    rng: &mut dyn Random,
    password: &str,
    plaintext: &[u8],
    kdf: Kdf,
    network: Network,
    kind: PayloadKind,
) -> Result<String, VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(VaultError::Malformed("plaintext too large"));
    }
    kdf.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut salt)?;
    rng.fill(&mut nonce)?;
    let header = Header {
        version: CURRENT_VERSION,
        kind,
        network,
        kdf,
        salt,
        nonce,
    };
    let aad = header.encode();
    let key = kdf.derive(password.as_bytes(), &salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Malformed("seal failed"))?;
    let mut blob = Vec::with_capacity(HEADER_LEN + ct.len());
    blob.extend_from_slice(&aad);
    blob.extend_from_slice(&ct);
    Ok(format!("{TEXT_PREFIX}{}", STANDARD.encode(blob)))
}

/// Open a sealed blob.
///
/// Rejects, in this order and before any KDF work: bad envelope, unknown or zero version,
/// version below `floor` ([`VaultError::Downgrade`]), unknown KDF or out-of-window parameters,
/// another network or payload kind. Then authenticates: wrong password and any modified byte
/// of the blob yield [`VaultError::WrongPasswordOrTampered`].
pub fn open(
    text: &str,
    password: &str,
    expected_network: Network,
    expected_kind: PayloadKind,
    floor: u8,
) -> Result<Secret, VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }
    let blob = decode_text(text)?;
    let header = Header::parse(&blob)?;
    if header.version < floor {
        return Err(VaultError::Downgrade {
            found: header.version,
            floor,
        });
    }
    if header.network != expected_network {
        return Err(VaultError::NetworkMismatch {
            expected: expected_network,
            found: header.network,
        });
    }
    if header.kind != expected_kind {
        return Err(VaultError::KindMismatch);
    }
    let key = header.kdf.derive(password.as_bytes(), &header.salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: &blob[HEADER_LEN..],
                aad: &blob[..HEADER_LEN],
            },
        )
        .map_err(|_| VaultError::WrongPasswordOrTampered)?;
    Ok(Secret::new(pt))
}
