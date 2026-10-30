//! Parity against vectors produced by `scripts/compare-legacy.cjs` from the pinned legacy
//! `lib/walletUtils.js` network parameters and the vendored bitcoinjs bundle.
mod common;
use common::*;
use std::collections::BTreeMap;
use tl_wallet_core::coin::FeePolicy;
use tl_wallet_core::multisig::multisig_record;
use tl_wallet_core::tx::{build_payment, segwit_sighash_hex, PaymentRequest};
use tl_wallet_core::*;

fn vectors() -> BTreeMap<String, String> {
    let text = include_str!("fixtures/legacy_vectors.txt");
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.trim_end_matches('\r').to_string()))
        .collect()
}

#[test]
fn network_params_match_legacy_objects() {
    let v = vectors();
    for n in Network::ALL {
        let p = n.params();
        let name = n.id();
        assert_eq!(v[&format!("params.{name}.path")], n.default_path());
        assert_eq!(
            v[&format!("params.{name}.pubKeyHash")],
            p.p2pkh_prefix.to_string()
        );
        assert_eq!(
            v[&format!("params.{name}.scriptHash")],
            p.p2sh_prefix.to_string()
        );
        assert_eq!(
            v[&format!("params.{name}.bech32")],
            p.bech32_hrp.unwrap_or("null")
        );
        // legacy messagePrefix = <len byte> + text
        let mut prefix = vec![p.message_magic.len() as u8];
        prefix.extend_from_slice(p.message_magic.as_bytes());
        assert_eq!(v[&format!("params.{name}.messagePrefixHex")], to_hex(&prefix));
    }
}

#[test]
fn derived_accounts_match_legacy_payments() {
    let v = vectors();
    for n in Network::ALL {
        let a = account(n);
        let name = n.id();
        assert_eq!(v[&format!("account.{name}.address")], a.info().unwrap().address);
        let script = to_hex(a.receive_address().script_pubkey().as_bytes());
        assert_eq!(v[&format!("account.{name}.script")], script);
        assert_eq!(v[&format!("decode.{name}.script")], script);
        let parsed = Address::parse(n, &v[&format!("account.{name}.address")]).unwrap();
        assert_eq!(parsed, a.receive_address());
    }
}

#[test]
fn p2pkh_p2sh_and_multisig_encodings_match_legacy() {
    let v = vectors();
    for n in Network::ALL {
        let name = n.id();
        let p2pkh = Address::parse(n, &v[&format!("p2pkh.{name}.G")]).unwrap();
        assert_eq!(p2pkh.kind(), AddressKind::P2pkh);
        assert_eq!(p2pkh.encode().unwrap(), v[&format!("p2pkh.{name}.G")]);
        let p2sh = Address::parse(n, &v[&format!("p2sh.{name}.address")]).unwrap();
        assert_eq!(p2sh.kind(), AddressKind::P2sh);
        assert_eq!(p2sh.encode().unwrap(), v[&format!("p2sh.{name}.address")]);
        let hash = &v[&format!("p2sh.{name}.hash20")];
        assert_eq!(
            to_hex(p2sh.script_pubkey().as_bytes()),
            format!("a914{hash}87")
        );
        if n.params().bech32_hrp.is_some() {
            let keys: Vec<String> = [
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            let rec = multisig_record(n, 2, &keys).unwrap();
            assert_eq!(rec.address, v[&format!("multisig.{name}.address")]);
            assert_eq!(
                rec.witness_script_hex,
                v[&format!("multisig.{name}.witnessScript")]
            );
            assert_eq!(rec.script_pubkey_hex, v[&format!("multisig.{name}.script")]);
        } else {
            let keys = vec![
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            ];
            assert!(multisig_record(n, 1, &keys).is_err());
        }
    }
}

#[test]
fn unsigned_tx_and_sighash_match_bitcoinjs() {
    let v = vectors();
    let a = account(Network::LtcTest);
    assert_eq!(a.info().unwrap().address, v["psbt.ltctest.own"]);
    let to = Address::parse(Network::LtcTest, &v["psbt.ltctest.recipient"]).unwrap();
    let utxos = [utxo_for(&a, 0x11, 0, 50_000)];
    let plan = build_payment(
        &a,
        &PaymentRequest {
            to: &to,
            amount: Sats(30_000),
            utxos: &utxos,
            fee: FeePolicy::Fixed(Sats(10_000)),
            max_fee: Sats(10_000),
            payload: Some(b"TL"),
        },
    )
    .unwrap();
    let raw = bitcoin::consensus::encode::serialize(&plan.psbt.unsigned_tx);
    assert_eq!(to_hex(&raw), v["psbt.ltctest.unsigned_tx"]);
    let sh = segwit_sighash_hex(
        &plan.psbt.unsigned_tx,
        0,
        a.receive_address().script_pubkey(),
        Sats(50_000),
    )
    .unwrap();
    assert_eq!(sh, v["psbt.ltctest.sighash_all_input0"]);
    assert_eq!(plan.fee, Sats(10_000));
    assert_eq!(plan.outputs.len(), 3);
}
