//! Prints the BIP-137 known-answer inputs for the public "abandon ... about" test mnemonic
//! (BTC account 0 receive key). Used with Bitcoin Core regtest `signmessagewithprivkey`.
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network as BN, NetworkKind, PrivateKey};
use std::str::FromStr;
use tl_wallet_core::*;

fn main() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let m = ImportedMnemonic::parse_phrase(phrase).unwrap();
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Main, &m.to_seed()).unwrap();
    let k = master
        .derive_priv(&secp, &DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap())
        .unwrap();
    let wif = PrivateKey::new(k.private_key, BN::Regtest).to_wif();
    println!("WIF={wif}");
    let acct = Account::from_mnemonic(&m, Network::Btc, ChangeMode::SameAsReceive).unwrap();
    let origin = Origin::from_url("https://layerwallet.com").unwrap();
    let msg = b"TradeLayer BIP-137 known answer";
    let cap = SigningCapability::for_message(origin.clone(), acct.id(), 100, msg.to_vec());
    let req = Requester {
        origin,
        network: Network::Btc,
    };
    let sig = sign_message(cap, &req, &acct, 1, msg).unwrap();
    println!("RUST_SIG={sig}");
    println!("ADDR={}", acct.receive_address().encode().unwrap());
}
