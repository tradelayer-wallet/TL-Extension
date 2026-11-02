//! Regtest networks: explicit ids, bech32 prefixes and test-chain key versions.

use tl_wallet_core::{Account, Address, ChangeMode, ImportedMnemonic, Network};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn account(n: Network) -> Account {
    let m = ImportedMnemonic::parse_phrase(PHRASE).unwrap();
    Account::from_mnemonic(&m, n, ChangeMode::SameAsReceive).unwrap()
}

#[test]
fn regtest_ids_parse_strictly() {
    assert_eq!(Network::parse("BTCREGTEST").unwrap(), Network::BtcRegtest);
    assert_eq!(
        Network::parse("bitcoin-regtest").unwrap(),
        Network::BtcRegtest
    );
    assert_eq!(Network::parse("LTCREGTEST").unwrap(), Network::LtcRegtest);
    assert!(Network::parse("REGTEST").is_err());
    assert!(!Network::ALL.contains(&Network::BtcRegtest));
}

#[test]
fn regtest_addresses_use_the_regtest_hrp_and_testnet_paths() {
    let b = account(Network::BtcRegtest);
    let t = account(Network::BtcTest);
    let ba = b.receive_address().encode().unwrap();
    let ta = t.receive_address().encode().unwrap();
    assert!(ba.starts_with("bcrt1q"), "{ba}");
    // Same BIP84 testnet path (coin type 1), same key, different human-readable part.
    assert_eq!(&ba[4..ba.len() - 6], &ta[2..ta.len() - 6]);
    assert_eq!(
        b.receive_address().script_pubkey(),
        t.receive_address().script_pubkey()
    );
    let l = account(Network::LtcRegtest)
        .receive_address()
        .encode()
        .unwrap();
    assert!(l.starts_with("rltc1q"), "{l}");
}

#[test]
fn regtest_addresses_are_not_accepted_on_other_networks() {
    let ba = account(Network::BtcRegtest)
        .receive_address()
        .encode()
        .unwrap();
    assert!(Address::parse(Network::BtcRegtest, &ba).is_ok());
    assert!(Address::parse(Network::BtcTest, &ba).is_err());
    assert!(Address::parse(Network::Btc, &ba).is_err());
    let ta = account(Network::BtcTest)
        .receive_address()
        .encode()
        .unwrap();
    assert!(Address::parse(Network::BtcRegtest, &ta).is_err());
}
