#![allow(dead_code)]
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Txid};
use tl_wallet_core::coin::Utxo;
use tl_wallet_core::*;

/// Public BIP39 test mnemonic. Synthetic: never holds funds.
pub const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// Second public test mnemonic (BIP39 vector).
pub const PHRASE_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

pub fn mnemonic(p: &str) -> ImportedMnemonic {
    ImportedMnemonic::parse_phrase(p).unwrap()
}

pub fn account(network: Network) -> Account {
    Account::from_mnemonic(&mnemonic(PHRASE), network, ChangeMode::SameAsReceive).unwrap()
}

pub fn account_b(network: Network) -> Account {
    Account::from_mnemonic(&mnemonic(PHRASE_B), network, ChangeMode::SameAsReceive).unwrap()
}

pub fn origin() -> Origin {
    Origin::from_url("https://layerwallet.com").unwrap()
}

pub fn other_origin() -> Origin {
    Origin::from_url("https://www.layerwallet.com").unwrap()
}

pub fn txid(byte: u8) -> Txid {
    Txid::from_byte_array([byte; 32])
}

pub fn utxo_for(a: &Account, byte: u8, vout: u32, sats: u64) -> Utxo {
    let script = a.receive_address().script_pubkey().to_owned();
    // For p2pkh (Dogecoin) accounts a real previous transaction is required.
    if script.is_p2pkh() {
        let mut outs = Vec::new();
        for i in 0..=vout {
            outs.push(TxOut {
                value: Amount::from_sat(if i == vout { sats } else { 1 }),
                script_pubkey: script.clone(),
            });
        }
        let prev = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: outs,
        };
        return Utxo {
            txid: prev.compute_txid(),
            vout,
            value: Sats(sats),
            script_pubkey: script,
            prev_tx: Some(prev),
        };
    }
    Utxo {
        txid: txid(byte),
        vout,
        value: Sats(sats),
        script_pubkey: script,
        prev_tx: None,
    }
}

pub fn plain_utxo(byte: u8, vout: u32, sats: u64, script: ScriptBuf) -> Utxo {
    Utxo {
        txid: txid(byte),
        vout,
        value: Sats(sats),
        script_pubkey: script,
        prev_tx: None,
    }
}

/// A third party address on `network` (public generator-point key).
pub fn stranger(network: Network) -> Address {
    let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let key = bitcoin::CompressedPublicKey::from_slice(&hex(g)).unwrap();
    Address::for_account_key(network, &key)
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
