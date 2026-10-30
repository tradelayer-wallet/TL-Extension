//! Regression tests for the repaired legacy defects (README table, rows R1..R12).
mod common;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1};
use common::*;
use tl_wallet_core::coin::{FeePolicy, LEGACY_FIXED_FEE};
use tl_wallet_core::message::{message_digest, verify_message};
use tl_wallet_core::tx::{build_payment, parse_psbt_hex, summarize_psbt, PaymentRequest};
use tl_wallet_core::*;

fn req<'a>(
    to: &'a Address,
    amount: u64,
    utxos: &'a [tl_wallet_core::coin::Utxo],
) -> PaymentRequest<'a> {
    PaymentRequest {
        to,
        amount: Sats(amount),
        utxos,
        fee: FeePolicy::Fixed(LEGACY_FIXED_FEE),
        max_fee: Sats(20_000),
        payload: None,
    }
}

// R1: signTransaction paid change to the page-chosen fromKeyPair.address.
#[test]
fn r1_change_goes_to_wallet_owned_address_only() {
    let to = stranger(Network::LtcTest);
    for mode in [ChangeMode::SameAsReceive, ChangeMode::InternalChain] {
        let a =
            Account::from_mnemonic(&mnemonic(PHRASE), Network::LtcTest, mode).unwrap();
        let utxos = [utxo_for(&a, 1, 0, 100_000)];
        let plan = build_payment(&a, &req(&to, 30_000, &utxos)).unwrap();
        assert_eq!(plan.outputs.len(), 2);
        assert_eq!(plan.outputs[0].script.as_script(), to.script_pubkey());
        let change = &plan.outputs[1];
        assert_eq!(change.script.as_script(), a.change_address().script_pubkey());
        assert!(a.owns_script(&change.script));
        assert_eq!(change.value, Sats(60_000));
        if mode == ChangeMode::InternalChain {
            assert_ne!(
                a.change_address().script_pubkey(),
                a.receive_address().script_pubkey()
            );
        }
        // the request type has no from-address field: nothing a page sends can redirect change
        for o in &plan.outputs[1..] {
            assert_ne!(o.script.as_script(), to.script_pubkey());
        }
    }
}

// R2: legacy checked total >= amount only; change = total - amount - fee could be negative.
#[test]
fn r2_funds_must_cover_amount_plus_fee() {
    let a = account(Network::LtcTest);
    let to = stranger(Network::LtcTest);
    // 35_000 + 10_000 fee > 40_000 available: legacy proceeded with negative change.
    let utxos = [utxo_for(&a, 1, 0, 40_000)];
    let err = build_payment(&a, &req(&to, 35_000, &utxos)).unwrap_err();
    assert_eq!(
        err,
        Error::InsufficientFunds {
            needed: 45_000,
            available: 40_000
        }
    );
    // exactly amount + fee is fine and creates no change output
    let utxos = [utxo_for(&a, 1, 0, 45_000)];
    let plan = build_payment(&a, &req(&to, 35_000, &utxos)).unwrap();
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.fee, Sats(10_000));
}

// R3: missing/NaN amount silently became 0.0000546 (5460 sats).
#[test]
fn r3_amount_is_mandatory_and_not_dust() {
    let a = account(Network::LtcTest);
    let to = stranger(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    assert_eq!(
        build_payment(&a, &req(&to, 0, &utxos)).unwrap_err(),
        Error::DustOutput {
            value: 0,
            threshold: 5_460
        }
    );
    assert!(matches!(
        build_payment(&a, &req(&to, 5_459, &utxos)),
        Err(Error::DustOutput { .. })
    ));
    assert!(build_payment(&a, &req(&to, 5_460, &utxos)).is_ok());
}

// R4: signMessage signed sha256(message) with no prefix: a transaction-signing oracle.
#[test]
fn r4_message_signature_is_not_a_raw_hash_signature() {
    let a = account(Network::Btc);
    let msg = b"anything the page wants, e.g. a 32-byte sighash preimage";
    let cap = SigningCapability::for_message(origin(), a.id(), 10, msg.to_vec());
    let r = Requester {
        origin: origin(),
        network: Network::Btc,
    };
    let sig_b64 = sign_message(cap, &r, &a, 1, msg).unwrap();
    // The digest is prefixed and double-hashed, so it is never sha256(message).
    let legacy_digest = sha256::Hash::hash(msg).to_byte_array();
    assert_ne!(message_digest(Network::Btc, msg), legacy_digest);
    // And the signature does not verify as an ECDSA signature over the legacy digest.
    let raw = decode_b64(&sig_b64);
    assert_eq!(raw.len(), 65);
    let secp = Secp256k1::new();
    let sig = Signature::from_compact(&raw[1..]).unwrap();
    let pk = a.receive_address();
    let key = bitcoin::CompressedPublicKey::from_slice(&hex(
        &a.info().unwrap().public_key_hex,
    ))
    .unwrap();
    assert!(secp
        .verify_ecdsa(&Message::from_digest(legacy_digest), &sig, &key.0)
        .is_err());
    // It does verify against the BIP-137 digest.
    assert!(secp
        .verify_ecdsa(
            &Message::from_digest(message_digest(Network::Btc, msg)),
            &sig,
            &key.0
        )
        .is_ok());
    assert!(verify_message(&pk, msg, &sig_b64).unwrap());
    // Same bytes under a different network magic give a different digest.
    assert_ne!(
        message_digest(Network::Btc, msg),
        message_digest(Network::Ltc, msg)
    );
}

fn decode_b64(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | T.iter().position(|x| *x == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

// R5: page-supplied/implied network silently switched the signing network
// (normalizeNetwork -> LTC, resolveNetwork(undefined) -> LTCTEST, tryPayment alternate network).
#[test]
fn r5_network_is_never_defaulted_or_switched() {
    assert!(matches!(
        Network::parse("not-a-network"),
        Err(Error::UnknownNetwork(_))
    ));
    assert!(Network::parse("").is_err());
    // tryPayment retried an address on the alternate network. Now a testnet address is simply
    // invalid on the explicit network, and vice versa.
    let btc_test = account(Network::BtcTest).receive_address().encode().unwrap();
    assert!(Address::parse(Network::LtcTest, &btc_test).is_err());
    assert!(Address::parse(Network::Btc, &btc_test).is_err());
    assert!(Address::parse(Network::BtcTest, &btc_test).is_ok());
    // recipient on another network is refused at build time
    let a = account(Network::LtcTest);
    let wrong = stranger(Network::BtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    assert_eq!(
        build_payment(&a, &req(&wrong, 30_000, &utxos)).unwrap_err(),
        Error::NetworkMismatch {
            expected: Network::LtcTest,
            actual: Network::BtcTest
        }
    );
}

// R5b: the same base58 prefix byte is valid on several networks, so the network can never be
// inferred from the address string.
#[test]
fn r5b_address_strings_are_ambiguous_without_explicit_network() {
    let a = Address::parse(Network::BtcTest, "my6RhGaMEf8v9yyQKqiuUYniJLfyU4gzqe").unwrap();
    // Litecoin testnet shares the 0x6f p2pkh prefix with Bitcoin testnet.
    let b = Address::parse(Network::LtcTest, "my6RhGaMEf8v9yyQKqiuUYniJLfyU4gzqe").unwrap();
    assert_eq!(a.script_pubkey(), b.script_pubkey());
    assert_ne!(a.network(), b.network());
}

// R6: any script was signed with the wallet key; foreign UTXOs must be refused.
#[test]
fn r6_foreign_utxos_are_refused() {
    let a = account(Network::LtcTest);
    let to = stranger(Network::LtcTest);
    let foreign = plain_utxo(9, 0, 100_000, stranger(Network::LtcTest).script_pubkey().to_owned());
    assert_eq!(
        build_payment(&a, &req(&to, 30_000, &[foreign])).unwrap_err(),
        Error::InvalidInput("utxo script is not owned by this account")
    );
}

// R7: dust change used to be emitted; now folded into the fee, and the fee bound still holds.
#[test]
fn r7_dust_change_folds_into_fee_within_bound() {
    let a = account(Network::LtcTest);
    let to = stranger(Network::LtcTest);
    // change would be 5_459 (< 5_460 dust): folded
    let utxos = [utxo_for(&a, 1, 0, 30_000 + 10_000 + 5_459)];
    let plan = build_payment(&a, &req(&to, 30_000, &utxos)).unwrap();
    assert_eq!(plan.outputs.len(), 1);
    assert_eq!(plan.fee, Sats(15_459));
    // change exactly at dust: kept
    let utxos = [utxo_for(&a, 1, 0, 30_000 + 10_000 + 5_460)];
    let plan = build_payment(&a, &req(&to, 30_000, &utxos)).unwrap();
    assert_eq!(plan.outputs.len(), 2);
    assert_eq!(plan.outputs[1].value, Sats(5_460));
    assert_eq!(plan.fee, Sats(10_000));
    // folding that pushes the fee over the explicit bound is refused rather than burned
    let mut r = req(&to, 30_000, &utxos);
    let utxos2 = [utxo_for(&a, 1, 0, 30_000 + 10_000 + 5_459)];
    r.utxos = &utxos2;
    r.max_fee = Sats(12_000);
    assert_eq!(
        build_payment(&a, &r).unwrap_err(),
        Error::FeeAboveBound {
            fee: 15_459,
            bound: 12_000
        }
    );
}

// R8: signInputsInPsbt/patchPsbtForMultisig rewrote witnessUtxo.script of a supplied PSBT.
#[test]
fn r8_psbt_prevout_data_is_never_rewritten() {
    use tl_wallet_core::capability::{InputRef, OutputRef};
    use tl_wallet_core::tx::{psbt_to_hex, SignOptions};
    let a = account(Network::LtcTest);
    let b = account_b(Network::LtcTest);
    let g = stranger(Network::LtcTest);
    let keys: Vec<String> = [
        a.info().unwrap().public_key_hex,
        b.info().unwrap().public_key_hex,
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
    ]
    .to_vec();
    let rec = tl_wallet_core::multisig::multisig_record(Network::LtcTest, 2, &keys).unwrap();
    let ms_addr = Address::parse(Network::LtcTest, &rec.address).unwrap();
    // A PSBT whose prevout script is the real multisig address but the attacker supplies a
    // *different* witness script (e.g. 1-of-1 with the wallet key).
    let evil_ws = {
        let k = bitcoin::PublicKey::from_slice(&hex(&a.info().unwrap().public_key_hex)).unwrap();
        bitcoin::script::Builder::new()
            .push_int(1)
            .push_key(&k)
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
            .into_script()
    };
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: txid(7),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(40_000),
            script_pubkey: g.script_pubkey().to_owned(),
        }],
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
    let prev = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(50_000),
        script_pubkey: ms_addr.script_pubkey().to_owned(),
    };
    psbt.inputs[0].witness_utxo = Some(prev.clone());
    let before = psbt_to_hex(&psbt);
    let cap = SigningCapability::for_transaction(
        origin(),
        a.id(),
        100,
        vec![InputRef {
            outpoint: psbt.unsigned_tx.input[0].previous_output,
            value: Sats(50_000),
        }],
        vec![OutputRef {
            script: g.script_pubkey().to_owned(),
            value: Sats(40_000),
        }],
        Sats(10_000),
    );
    let r = Requester {
        origin: origin(),
        network: Network::LtcTest,
    };
    // out-of-band witness script that does not hash to the prevout script: refused
    let opts = SignOptions {
        witness_script_input0: Some(evil_ws),
        only_indices: Some(vec![0]),
        ..Default::default()
    };
    let err = tl_wallet_core::sign_psbt(cap, &r, &a, 1, psbt.clone(), &opts).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidPsbt("witness script does not match prevout script")
    );
    assert_eq!(psbt_to_hex(&psbt), before, "caller copy is untouched");
    // the matching witness script is accepted and signs, still without touching prevout data
    let cap = SigningCapability::for_transaction(
        origin(),
        a.id(),
        100,
        vec![InputRef {
            outpoint: psbt.unsigned_tx.input[0].previous_output,
            value: Sats(50_000),
        }],
        vec![OutputRef {
            script: g.script_pubkey().to_owned(),
            value: Sats(40_000),
        }],
        Sats(10_000),
    );
    let ws = bitcoin::ScriptBuf::from_bytes(hex(&rec.witness_script_hex));
    let opts = SignOptions {
        witness_script_input0: Some(ws),
        only_indices: Some(vec![0]),
        ..Default::default()
    };
    let out = tl_wallet_core::sign_psbt(cap, &r, &a, 1, psbt, &opts).unwrap();
    let tl_wallet_core::tx::SignOutcome::Partial { psbt_hex } = out else {
        panic!("expected partial");
    };
    let signed = parse_psbt_hex(&psbt_hex).unwrap();
    assert_eq!(signed.inputs[0].witness_utxo, Some(prev));
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
}

// R9: display fee was Math.max(in - out, 0) and unknown inputs counted as 0.
#[test]
fn r9_summary_does_not_hide_unknown_or_negative_fees() {
    let a = account(Network::LtcTest);
    let to = stranger(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    let plan = build_payment(&a, &req(&to, 30_000, &utxos)).unwrap();
    let own = [a.receive_address()];
    let s = summarize_psbt(&plan.psbt, Network::LtcTest, &own).unwrap();
    assert_eq!(s.fee, Some(Sats(10_000)));
    assert_eq!(s.total_in, Some(Sats(100_000)));
    assert!(s.outputs[1].is_change);
    assert!(!s.outputs[0].is_change);
    assert_eq!(s.outputs[0].address.as_deref(), Some(to.encode().unwrap().as_str()));
    // unknown input amount -> fee unknown, not zero
    let mut p2 = plan.psbt.clone();
    p2.inputs[0].witness_utxo = None;
    let s2 = summarize_psbt(&p2, Network::LtcTest, &own).unwrap();
    assert_eq!(s2.fee, None);
    assert_eq!(s2.total_in, None);
    assert_eq!(s2.inputs[0].value, None);
    // outputs exceeding inputs -> error, not "fee 0"
    let mut p3 = plan.psbt.clone();
    p3.unsigned_tx.output[0].value = bitcoin::Amount::from_sat(500_000);
    assert_eq!(
        summarize_psbt(&p3, Network::LtcTest, &own).unwrap_err(),
        Error::InvalidPsbt("outputs exceed inputs")
    );
}

// R10: the legacy import never validated the checksum or word list.
#[test]
fn r10_mnemonic_import_validation() {
    assert!(ImportedMnemonic::parse_phrase(PHRASE).is_ok());
    // uppercase and extra whitespace are tolerated (boxes are trimmed in the legacy UI)
    let loud = PHRASE.to_uppercase().replace(' ', "  ");
    assert!(ImportedMnemonic::parse_phrase(&loud).is_ok());
    // typo in the last word: checksum mismatch, previously a different wallet
    let bad = PHRASE.replace("about", "above");
    assert_eq!(
        ImportedMnemonic::parse_phrase(&bad).unwrap_err(),
        Error::InvalidMnemonic("checksum mismatch")
    );
    assert!(ImportedMnemonic::parse_phrase(&PHRASE.replace("about", "zzzzzz")).is_err());
    // wrong counts
    let eleven: Vec<&str> = PHRASE.split(' ').take(11).collect();
    assert!(ImportedMnemonic::from_words(&eleven).is_err());
    let mut thirteen: Vec<&str> = PHRASE.split(' ').collect();
    thirteen.push("about");
    assert!(ImportedMnemonic::from_words(&thirteen).is_err());
    // empty box and a box with two words (legacy joined it into a 13-word phrase)
    let mut boxes: Vec<&str> = PHRASE.split(' ').collect();
    boxes[3] = "";
    assert!(ImportedMnemonic::from_words(&boxes).is_err());
    let mut boxes: Vec<&str> = PHRASE.split(' ').collect();
    boxes[3] = "abandon abandon";
    assert!(ImportedMnemonic::from_words(&boxes).is_err());
    // non-ASCII input is rejected before normalization concerns arise
    assert!(ImportedMnemonic::parse_phrase(&PHRASE.replace("about", "abo\u{fb01}")).is_err());
    assert!(ImportedMnemonic::parse_phrase(&"a ".repeat(400)).is_err());
}

// R11: floating point amounts (Math.round(amount * 1e8)).
#[test]
fn r11_amounts_are_exact_decimals() {
    assert_eq!(Sats::from_coin_str("0.0001").unwrap(), Sats(10_000));
    assert_eq!(Sats::from_coin_str("0.0000546").unwrap(), Sats(5_460));
    assert_eq!(Sats::from_coin_str("1.00000001").unwrap(), Sats(100_000_001));
    // 0.1 + 0.2 style float errors cannot occur
    assert_eq!(
        Sats::from_coin_str("0.1")
            .unwrap()
            .checked_add(Sats::from_coin_str("0.2").unwrap())
            .unwrap(),
        Sats::from_coin_str("0.3").unwrap()
    );
    for bad in [
        "", ".", "1.", ".5", "-1", "+1", "1e3", "0.000000001", "1 ", " 1", "0x10", "1,5", "NaN",
        "Infinity", "٣",
    ] {
        assert!(Sats::from_coin_str(bad).is_err(), "{bad:?} must be rejected");
    }
    assert_eq!(
        Sats::from_coin_str("184467440737.09551616").unwrap_err(),
        Error::AmountOverflow
    );
    assert_eq!(Sats::from_coin_str("184467440737.09551615").unwrap(), Sats(u64::MAX));
    assert_eq!(Sats(u64::MAX).checked_add(Sats(1)), Err(Error::AmountOverflow));
    assert_eq!(Sats(123_456_789).to_coin_string(), "1.23456789");
}

// R12: OP_RETURN payloads were unbounded.
#[test]
fn r12_op_return_payload_is_bounded() {
    let a = account(Network::LtcTest);
    let to = stranger(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    let ok = [7u8; 80];
    let mut r = req(&to, 30_000, &utxos);
    r.payload = Some(&ok);
    assert_eq!(build_payment(&a, &r).unwrap().outputs.len(), 3);
    let big = [7u8; 81];
    r.payload = Some(&big);
    assert_eq!(
        build_payment(&a, &r).unwrap_err(),
        Error::PayloadTooLarge { len: 81, max: 80 }
    );
    // empty payload behaves like the legacy falsy check: no OP_RETURN output
    r.payload = Some(&[]);
    assert_eq!(build_payment(&a, &r).unwrap().outputs.len(), 2);
}
