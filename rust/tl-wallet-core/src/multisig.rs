//! P2WSH m-of-n multisig address construction (`addMultisig` / `addMultisigAddress`) and the
//! duplicate lookup of `getExistingMultisig`. Persistence (localStorage / chrome.storage)
//! stays in JS; this module only computes the record.

use crate::address::Address;
use crate::error::{Error, Result};
use crate::network::Network;
use crate::provider::MAX_MULTISIG_KEYS;
use crate::tx::{decode_hex, encode_hex};
use bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::script::Builder;
use bitcoin::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigRecord {
    pub address: String,
    /// Witness script hex (legacy `redeemScript`).
    pub witness_script_hex: String,
    pub script_pubkey_hex: String,
    pub pubkeys: Vec<String>,
    pub m: usize,
    pub network: Network,
}

/// Build the record for `m` of `pubkeys` (hex, compressed) on `network`. Keys must be valid
/// 33-byte compressed points and pairwise distinct, `1 <= m <= n <= 15`, and the network
/// must support segwit addresses.
pub fn multisig_record(network: Network, m: usize, pubkeys: &[String]) -> Result<MultisigRecord> {
    let n = pubkeys.len();
    if n == 0 || n > MAX_MULTISIG_KEYS {
        return Err(Error::InvalidMultisig("pubkey count"));
    }
    if m == 0 || m > n {
        return Err(Error::InvalidMultisig("threshold must satisfy 1 <= m <= n"));
    }
    let mut keys = Vec::with_capacity(n);
    for hex in pubkeys {
        let bytes = decode_hex(hex).ok_or(Error::InvalidMultisig("pubkey is not hex"))?;
        if bytes.len() != 33 {
            return Err(Error::InvalidMultisig("pubkey must be 33-byte compressed"));
        }
        let pk = PublicKey::from_slice(&bytes)
            .map_err(|_| Error::InvalidMultisig("pubkey is not a curve point"))?;
        if keys.contains(&pk) {
            return Err(Error::InvalidMultisig("duplicate pubkey"));
        }
        keys.push(pk);
    }
    let mut b = Builder::new().push_int(m as i64);
    for k in &keys {
        b = b.push_key(k);
    }
    let script = b
        .push_int(n as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let addr = Address::p2wsh(network, &script)?;
    Ok(MultisigRecord {
        address: addr.encode()?,
        witness_script_hex: encode_hex(script.as_bytes()),
        script_pubkey_hex: encode_hex(addr.script_pubkey().as_bytes()),
        pubkeys: pubkeys.to_vec(),
        m,
        network,
    })
}

/// `getExistingMultisig`: same threshold, same ordered keys, same explicit network.
pub fn find_existing<'a>(
    stored: &'a [MultisigRecord],
    network: Network,
    m: usize,
    pubkeys: &[String],
) -> Option<&'a MultisigRecord> {
    stored
        .iter()
        .find(|r| r.network == network && r.m == m && r.pubkeys == pubkeys)
}
