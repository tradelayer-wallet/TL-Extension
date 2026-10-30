//! Signing capability: success paths, every refusal, and signature validity.
mod common;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use common::*;
use tl_wallet_core::capability::{authorize_message, authorize_tx, InputRef, OutputRef};
use tl_wallet_core::coin::FeePolicy;
use tl_wallet_core::tx::{
    build_payment, parse_psbt_hex, PaymentPlan, PaymentRequest, SignOptions, SignOutcome,
};
use tl_wallet_core::*;

fn plan_for(a: &Account, utxos: &[tl_wallet_core::coin::Utxo], amount: u64) -> PaymentPlan {
    let to = stranger(a.network());
    build_payment(
        a,
        &PaymentRequest {
            to: &to,
            amount: Sats(amount),
            utxos,
            fee: FeePolicy::Fixed(Sats(10_000)),
            max_fee: Sats(10_000),
            payload: None,
        },
    )
    .unwrap()
}

fn cap_for(a: &Account, plan: &PaymentPlan, fee_bound: u64) -> SigningCapability {
    SigningCapability::for_transaction(
        origin(),
        a.id(),
        1_000,
        plan.inputs.clone(),
        plan.outputs.clone(),
        Sats(fee_bound),
    )
}

fn req(network: Network) -> Requester {
    Requester {
        origin: origin(),
        network,
    }
}

#[test]
fn signs_p2wpkh_and_signature_verifies() {
    let a = account(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 60_000), utxo_for(&a, 2, 1, 50_000)];
    let plan = plan_for(&a, &utxos, 80_000);
    assert_eq!(plan.inputs.len(), 2);
    let cap = cap_for(&a, &plan, 10_000);
    let out = sign_psbt(
        cap,
        &req(Network::LtcTest),
        &a,
        1,
        plan.psbt.clone(),
        &SignOptions {
            finalize: true,
            ..Default::default()
        },
    )
    .unwrap();
    let SignOutcome::Final { raw_tx_hex, txid } = out else {
        panic!("expected final");
    };
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex(&raw_tx_hex)).unwrap();
    assert_eq!(tx.compute_txid().to_string(), txid);
    assert_eq!(tx.output, plan.psbt.unsigned_tx.output);
    let secp = Secp256k1::new();
    let spk = a.receive_address().script_pubkey().to_owned();
    let key =
        bitcoin::CompressedPublicKey::from_slice(&hex(&a.info().unwrap().public_key_hex)).unwrap();
    let values = [60_000u64, 50_000];
    // the selection is largest-first: inputs are in value order
    let mut cache = SighashCache::new(&tx);
    for (i, input) in tx.input.iter().enumerate() {
        let w: Vec<&[u8]> = input.witness.iter().collect();
        assert_eq!(w.len(), 2);
        assert_eq!(w[1], key.to_bytes());
        let sig = bitcoin::ecdsa::Signature::from_slice(w[0]).unwrap();
        assert_eq!(sig.sighash_type, EcdsaSighashType::All);
        let sh = cache
            .p2wpkh_signature_hash(
                i,
                &spk,
                bitcoin::Amount::from_sat(values[i]),
                EcdsaSighashType::All,
            )
            .unwrap();
        use bitcoin::hashes::Hash;
        secp.verify_ecdsa(
            &Message::from_digest(sh.to_byte_array()),
            &sig.signature,
            &key.0,
        )
        .unwrap();
    }
}

#[test]
fn signs_dogecoin_p2pkh_with_previous_transaction() {
    let a = account(Network::DogeTest);
    let utxos = [utxo_for(&a, 1, 0, 400_000_000)];
    let to = stranger(Network::DogeTest);
    let plan = build_payment(
        &a,
        &PaymentRequest {
            to: &to,
            amount: Sats(200_000_000),
            utxos: &utxos,
            fee: FeePolicy::Fixed(Sats(1_000_000)),
            max_fee: Sats(1_000_000),
            payload: None,
        },
    )
    .unwrap();
    let cap = cap_for(&a, &plan, 1_000_000);
    let out = sign_psbt(
        cap,
        &req(Network::DogeTest),
        &a,
        1,
        plan.psbt.clone(),
        &SignOptions {
            finalize: true,
            ..Default::default()
        },
    )
    .unwrap();
    let SignOutcome::Final { raw_tx_hex, .. } = out else {
        panic!("expected final");
    };
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex(&raw_tx_hex)).unwrap();
    assert!(tx.input[0].witness.is_empty());
    assert!(!tx.input[0].script_sig.is_empty());
    // verify against the legacy sighash
    let spk = a.receive_address().script_pubkey().to_owned();
    let cache = SighashCache::new(&tx);
    let sh = cache
        .legacy_signature_hash(0, &spk, EcdsaSighashType::All.to_u32())
        .unwrap();
    let mut ins = tx.input[0].script_sig.instructions();
    let sig_bytes = match ins.next().unwrap().unwrap() {
        bitcoin::script::Instruction::PushBytes(b) => b.as_bytes().to_vec(),
        _ => panic!(),
    };
    let sig = bitcoin::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
    let key =
        bitcoin::CompressedPublicKey::from_slice(&hex(&a.info().unwrap().public_key_hex)).unwrap();
    use bitcoin::hashes::Hash;
    Secp256k1::new()
        .verify_ecdsa(
            &Message::from_digest(sh.to_byte_array()),
            &sig.signature,
            &key.0,
        )
        .unwrap();
}

#[test]
fn dogecoin_p2pkh_input_without_previous_tx_is_refused() {
    let a = account(Network::DogeTest);
    let mut u = utxo_for(&a, 1, 0, 400_000_000);
    u.prev_tx = None;
    let to = stranger(Network::DogeTest);
    let err = build_payment(
        &a,
        &PaymentRequest {
            to: &to,
            amount: Sats(200_000_000),
            utxos: &[u],
            fee: FeePolicy::Fixed(Sats(1_000_000)),
            max_fee: Sats(1_000_000),
            payload: None,
        },
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidInput("p2pkh utxo requires prev_tx"));
}

#[test]
fn every_mismatch_is_denied() {
    let a = account(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    let plan = plan_for(&a, &utxos, 30_000);
    let id = a.id();
    let good = cap_for(&a, &plan, 10_000);
    let r = req(Network::LtcTest);

    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &plan.inputs, &plan.outputs),
        Ok(Sats(10_000))
    );
    // expiry is exclusive and uses the injected clock
    assert_eq!(
        authorize_tx(&good, &r, &id, 999, &plan.inputs, &plan.outputs),
        Ok(Sats(10_000))
    );
    assert_eq!(
        authorize_tx(&good, &r, &id, 1_000, &plan.inputs, &plan.outputs),
        Err(Denied::Expired)
    );
    // origin
    let other = Requester {
        origin: other_origin(),
        network: Network::LtcTest,
    };
    assert_eq!(
        authorize_tx(&good, &other, &id, 1, &plan.inputs, &plan.outputs),
        Err(Denied::OriginMismatch)
    );
    // network of the request
    assert_eq!(
        authorize_tx(
            &good,
            &req(Network::BtcTest),
            &id,
            1,
            &plan.inputs,
            &plan.outputs
        ),
        Err(Denied::NetworkMismatch)
    );
    // account on another network (even if the requester says the approved network)
    let other_net_acct = account(Network::BtcTest).id();
    assert_eq!(
        authorize_tx(&good, &r, &other_net_acct, 1, &plan.inputs, &plan.outputs),
        Err(Denied::NetworkMismatch)
    );
    // different account on the same network
    let b = account_b(Network::LtcTest).id();
    assert_eq!(
        authorize_tx(&good, &r, &b, 1, &plan.inputs, &plan.outputs),
        Err(Denied::AccountMismatch)
    );
    // extra input
    let mut ins = plan.inputs.clone();
    ins.push(InputRef {
        outpoint: bitcoin::OutPoint {
            txid: txid(9),
            vout: 0,
        },
        value: Sats(1),
    });
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &ins, &plan.outputs),
        Err(Denied::UnapprovedInput(1))
    );
    // approved outpoint with a different amount
    let mut ins = plan.inputs.clone();
    ins[0].value = Sats(ins[0].value.0 + 1);
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &ins, &plan.outputs),
        Err(Denied::UnapprovedInput(0))
    );
    // duplicated input
    let mut ins = plan.inputs.clone();
    ins.push(ins[0].clone());
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &ins, &plan.outputs),
        Err(Denied::DuplicateInput)
    );
    // extra output / changed output script / changed value / dropped output
    let mut outs = plan.outputs.clone();
    outs.push(OutputRef {
        script: stranger(Network::LtcTest).script_pubkey().to_owned(),
        value: Sats(1),
    });
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &plan.inputs, &outs),
        Err(Denied::OutputsNotApproved)
    );
    let mut outs = plan.outputs.clone();
    outs[0].value = Sats(outs[0].value.0 - 1);
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &plan.inputs, &outs),
        Err(Denied::OutputsNotApproved)
    );
    let mut outs = plan.outputs.clone();
    outs[1].script = stranger(Network::LtcTest).script_pubkey().to_owned();
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &plan.inputs, &outs),
        Err(Denied::OutputsNotApproved)
    );
    let outs = vec![plan.outputs[0].clone()];
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &plan.inputs, &outs),
        Err(Denied::OutputsNotApproved)
    );
    // same multiset in a different order is the same transaction content
    let mut outs = plan.outputs.clone();
    outs.reverse();
    assert_eq!(
        authorize_tx(&good, &r, &id, 1, &plan.inputs, &outs),
        Ok(Sats(10_000))
    );
    // fee bound
    let tight = cap_for(&a, &plan, 9_999);
    assert_eq!(
        authorize_tx(&tight, &r, &id, 1, &plan.inputs, &plan.outputs),
        Err(Denied::FeeAboveBound)
    );
    // wrong kind
    let m = SigningCapability::for_message(origin(), a.id(), 10, b"x".to_vec());
    assert_eq!(
        authorize_tx(&m, &r, &id, 1, &plan.inputs, &plan.outputs),
        Err(Denied::WrongKind)
    );
    assert_eq!(
        authorize_message(&good, &r, &id, 1, b"x"),
        Err(Denied::WrongKind)
    );
}

#[test]
fn outputs_exceeding_inputs_or_overflow_are_denied() {
    let a = account(Network::LtcTest);
    let spk = a.receive_address().script_pubkey().to_owned();
    let op = bitcoin::OutPoint {
        txid: txid(1),
        vout: 0,
    };
    let ins = vec![InputRef {
        outpoint: op,
        value: Sats(1_000),
    }];
    let outs = vec![OutputRef {
        script: spk.clone(),
        value: Sats(2_000),
    }];
    let cap = SigningCapability::for_transaction(
        origin(),
        a.id(),
        10,
        ins.clone(),
        outs.clone(),
        Sats(u64::MAX),
    );
    assert_eq!(
        authorize_tx(&cap, &req(Network::LtcTest), &a.id(), 1, &ins, &outs),
        Err(Denied::InvalidAmounts)
    );
    let big_ins = vec![
        InputRef {
            outpoint: op,
            value: Sats(u64::MAX),
        },
        InputRef {
            outpoint: bitcoin::OutPoint {
                txid: txid(2),
                vout: 0,
            },
            value: Sats(1),
        },
    ];
    let cap = SigningCapability::for_transaction(
        origin(),
        a.id(),
        10,
        big_ins.clone(),
        vec![],
        Sats(u64::MAX),
    );
    assert_eq!(
        authorize_tx(&cap, &req(Network::LtcTest), &a.id(), 1, &big_ins, &[]),
        Err(Denied::InvalidAmounts)
    );
}

#[test]
fn sign_psbt_refuses_a_tampered_psbt_and_leaves_no_signature() {
    let a = account(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    let plan = plan_for(&a, &utxos, 30_000);
    // page swaps the recipient after the user approved
    let mut tampered = plan.psbt.clone();
    tampered.unsigned_tx.output[0].script_pubkey = a.receive_address().script_pubkey().to_owned();
    let err = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        tampered,
        &SignOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Error::Denied(Denied::OutputsNotApproved));
    // page inflates the fee by lowering the change
    let mut tampered = plan.psbt.clone();
    tampered.unsigned_tx.output[1].value = bitcoin::Amount::from_sat(1);
    let err = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        tampered,
        &SignOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Error::Denied(Denied::OutputsNotApproved));
    // psbt with unknown input amount cannot be authorized
    let mut blind = plan.psbt.clone();
    blind.inputs[0].witness_utxo = None;
    let err = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        blind,
        &SignOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidPsbt("input amount unknown"));
}

#[test]
fn seller_flag_signs_only_input_zero_and_leaves_psbt_partial() {
    let a = account(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 60_000), utxo_for(&a, 2, 0, 50_000)];
    let plan = plan_for(&a, &utxos, 80_000);
    let out = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        plan.psbt.clone(),
        &SignOptions {
            only_indices: Some(vec![0]),
            finalize: false,
            ..Default::default()
        },
    )
    .unwrap();
    let SignOutcome::Partial { psbt_hex } = out else {
        panic!("partial expected");
    };
    let p = parse_psbt_hex(&psbt_hex).unwrap();
    assert_eq!(p.inputs[0].partial_sigs.len(), 1);
    assert_eq!(p.inputs[1].partial_sigs.len(), 0);
    // finalizing a half-signed psbt fails instead of emitting garbage
    let err = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        p,
        &SignOptions {
            only_indices: Some(vec![0]),
            finalize: true,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::InvalidPsbt("cannot finalize: input lacks signatures")
    );
    // out-of-range index
    let err = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        plan.psbt.clone(),
        &SignOptions {
            only_indices: Some(vec![5]),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidPsbt("input index out of range"));
}

#[test]
fn non_all_sighash_requests_are_refused() {
    let a = account(Network::LtcTest);
    let utxos = [utxo_for(&a, 1, 0, 100_000)];
    let mut plan = plan_for(&a, &utxos, 30_000);
    plan.psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(0x83));
    let err = sign_psbt(
        cap_for(&a, &plan, 10_000),
        &req(Network::LtcTest),
        &a,
        1,
        plan.psbt.clone(),
        &SignOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, Error::InvalidPsbt("only SIGHASH_ALL is signed"));
}

#[test]
fn message_capability_is_exact() {
    let a = account(Network::Ltc);
    let r = req(Network::Ltc);
    let cap = SigningCapability::for_message(origin(), a.id(), 50, b"hello".to_vec());
    assert_eq!(authorize_message(&cap, &r, &a.id(), 1, b"hello"), Ok(()));
    assert_eq!(
        authorize_message(&cap, &r, &a.id(), 1, b"hello!"),
        Err(Denied::MessageMismatch)
    );
    assert_eq!(
        authorize_message(&cap, &r, &a.id(), 50, b"hello"),
        Err(Denied::Expired)
    );
    let bad = sign_message(cap, &r, &a, 1, b"HELLO");
    assert_eq!(bad, Err(Error::Denied(Denied::MessageMismatch)));
    let big = vec![0u8; 64 * 1024 + 1];
    let cap = SigningCapability::for_message(origin(), a.id(), 50, big.clone());
    assert!(matches!(
        sign_message(cap, &r, &a, 1, &big),
        Err(Error::MessageTooLong { .. })
    ));
}

#[test]
fn two_of_three_multisig_two_signers_finalize() {
    let a = account(Network::LtcTest);
    let b = account_b(Network::LtcTest);
    let third = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string();
    let keys = vec![
        a.info().unwrap().public_key_hex,
        b.info().unwrap().public_key_hex,
        third,
    ];
    let rec = tl_wallet_core::multisig::multisig_record(Network::LtcTest, 2, &keys).unwrap();
    let ms = Address::parse(Network::LtcTest, &rec.address).unwrap();
    let dest = stranger(Network::LtcTest);
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
            script_pubkey: dest.script_pubkey().to_owned(),
        }],
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(50_000),
        script_pubkey: ms.script_pubkey().to_owned(),
    });
    let ws = bitcoin::ScriptBuf::from_bytes(hex(&rec.witness_script_hex));
    psbt.inputs[0].witness_script = Some(ws.clone());
    let mk = |acct: &Account| {
        SigningCapability::for_transaction(
            origin(),
            acct.id(),
            100,
            vec![InputRef {
                outpoint: psbt.unsigned_tx.input[0].previous_output,
                value: Sats(50_000),
            }],
            vec![OutputRef {
                script: dest.script_pubkey().to_owned(),
                value: Sats(40_000),
            }],
            Sats(10_000),
        )
    };
    let r = req(Network::LtcTest);
    let SignOutcome::Partial { psbt_hex } =
        sign_psbt(mk(&a), &r, &a, 1, psbt.clone(), &SignOptions::default()).unwrap()
    else {
        panic!()
    };
    let half = parse_psbt_hex(&psbt_hex).unwrap();
    // one signature is not enough to finalize
    assert!(sign_psbt(
        mk(&a),
        &r,
        &a,
        1,
        half.clone(),
        &SignOptions {
            finalize: true,
            ..Default::default()
        }
    )
    .is_err());
    let SignOutcome::Final { raw_tx_hex, .. } = sign_psbt(
        mk(&b),
        &r,
        &b,
        1,
        half,
        &SignOptions {
            finalize: true,
            ..Default::default()
        },
    )
    .unwrap() else {
        panic!()
    };
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex(&raw_tx_hex)).unwrap();
    let w: Vec<&[u8]> = tx.input[0].witness.iter().collect();
    assert_eq!(w.len(), 4);
    assert!(w[0].is_empty());
    assert_eq!(w[3], ws.as_bytes());
    // both signatures verify against the BIP143 p2wsh sighash
    let mut cache = SighashCache::new(&tx);
    let sh = cache
        .p2wsh_signature_hash(
            0,
            &ws,
            bitcoin::Amount::from_sat(50_000),
            EcdsaSighashType::All,
        )
        .unwrap();
    use bitcoin::hashes::Hash;
    let secp = Secp256k1::new();
    for (sig_bytes, acct) in [(w[1], &a), (w[2], &b)] {
        let sig = bitcoin::ecdsa::Signature::from_slice(sig_bytes).unwrap();
        let key =
            bitcoin::CompressedPublicKey::from_slice(&hex(&acct.info().unwrap().public_key_hex))
                .unwrap();
        secp.verify_ecdsa(
            &Message::from_digest(sh.to_byte_array()),
            &sig.signature,
            &key.0,
        )
        .unwrap();
    }
}
