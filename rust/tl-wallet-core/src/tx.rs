//! Transaction/PSBT building, display summary and (capability-gated) signing.
//!
//! Ported from `signTransaction` (build side), `buildUnsignedPSBT`, `signInputsInPsbt` and
//! `summarizePsbtForDisplay`. Segwit v0 (`p2wpkh`, `p2wsh` multisig) and legacy `p2pkh`
//! (Dogecoin) spends are supported; the sighash is always `SIGHASH_ALL`.
//!
//! Repaired legacy defects (see README): change goes to a wallet-owned address, inputs must
//! be owned by the wallet, funds are checked against `amount + fee`, the display fee no
//! longer hides missing/negative values, and witness data of a supplied PSBT is never
//! rewritten (`patchPsbtForMultisig`).

use crate::address::Address;
use crate::amount::Sats;
use crate::capability::{InputRef, OutputRef};
use crate::coin::{select_largest_first, FeePolicy, Selection, Utxo};
use crate::error::{Error, Result};
use crate::keys::Account;
use crate::network::Network;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::{OP_CHECKMULTISIG, OP_RETURN};
use bitcoin::blockdata::script::Instruction;
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, PublicKey, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// Standard relay limit for the OP_RETURN payload.
pub const MAX_OP_RETURN_BYTES: usize = 80;
/// Bound on inputs/outputs accepted from a PSBT.
pub const MAX_PSBT_IO: usize = 1_000;

#[derive(Debug, Clone)]
pub struct PaymentRequest<'a> {
    pub to: &'a Address,
    pub amount: Sats,
    pub utxos: &'a [Utxo],
    pub fee: FeePolicy,
    pub max_fee: Sats,
    pub payload: Option<&'a [u8]>,
}

#[derive(Debug, Clone)]
pub struct PaymentPlan {
    pub network: Network,
    pub psbt: Psbt,
    pub selection: Selection,
    pub inputs: Vec<InputRef>,
    pub outputs: Vec<OutputRef>,
    pub fee: Sats,
}

fn op_return_script(payload: &[u8]) -> Result<ScriptBuf> {
    if payload.len() > MAX_OP_RETURN_BYTES {
        return Err(Error::PayloadTooLarge {
            len: payload.len(),
            max: MAX_OP_RETURN_BYTES,
        });
    }
    let buf = PushBytesBuf::try_from(payload.to_vec())
        .map_err(|_| Error::InvalidInput("payload cannot be pushed"))?;
    Ok(ScriptBuf::new_op_return(buf))
}

/// Build an unsigned payment PSBT for `account`.
///
/// Outputs, in legacy order: recipient, change (only when above dust, always to the
/// wallet-owned change address of `account`), optional `OP_RETURN` payload. Every candidate
/// UTXO must be one of the account's own scripts.
pub fn build_payment(account: &Account, req: &PaymentRequest<'_>) -> Result<PaymentPlan> {
    let network = account.network();
    if req.to.network() != network {
        return Err(Error::NetworkMismatch {
            expected: network,
            actual: req.to.network(),
        });
    }
    let dust = Sats(network.params().dust_sats);
    if req.amount < dust {
        return Err(Error::DustOutput {
            value: req.amount.0,
            threshold: dust.0,
        });
    }
    for u in req.utxos {
        if !account.owns_script(&u.script_pubkey) {
            return Err(Error::InvalidInput(
                "utxo script is not owned by this account",
            ));
        }
        validate_prev_tx(u)?;
    }
    let payload = req.payload.filter(|p| !p.is_empty());
    let op_return = payload.map(op_return_script).transpose()?;
    let selection = select_largest_first(req.utxos, req.amount, &req.fee, req.max_fee, dust)?;

    let mut outputs = vec![OutputRef {
        script: req.to.script_pubkey().to_owned(),
        value: req.amount,
    }];
    if selection.change.0 > 0 {
        outputs.push(OutputRef {
            script: account.change_address().script_pubkey().to_owned(),
            value: selection.change,
        });
    }
    if let Some(s) = op_return {
        outputs.push(OutputRef {
            script: s,
            value: Sats(0),
        });
    }
    let inputs: Vec<InputRef> = selection
        .selected
        .iter()
        .map(|u| InputRef {
            outpoint: u.outpoint(),
            value: u.value,
        })
        .collect();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|o| TxOut {
                value: Amount::from_sat(o.value.0),
                script_pubkey: o.script.clone(),
            })
            .collect(),
    };
    let mut psbt =
        Psbt::from_unsigned_tx(tx).map_err(|_| Error::InvalidPsbt("cannot create psbt"))?;
    for (slot, u) in psbt.inputs.iter_mut().zip(selection.selected.iter()) {
        if u.script_pubkey.is_p2pkh() {
            slot.non_witness_utxo = u.prev_tx.clone();
        } else {
            slot.witness_utxo = Some(TxOut {
                value: Amount::from_sat(u.value.0),
                script_pubkey: u.script_pubkey.clone(),
            });
        }
    }
    let fee = selection.fee;
    Ok(PaymentPlan {
        network,
        psbt,
        selection,
        inputs,
        outputs,
        fee,
    })
}

/// Legacy `p2pkh` sighash does not commit to the input amount, so the previous transaction
/// must be supplied and must match the outpoint, script and value.
fn validate_prev_tx(u: &Utxo) -> Result<()> {
    if !u.script_pubkey.is_p2pkh() {
        return Ok(());
    }
    let prev = u
        .prev_tx
        .as_ref()
        .ok_or(Error::InvalidInput("p2pkh utxo requires prev_tx"))?;
    if prev.compute_txid() != u.txid {
        return Err(Error::InvalidInput("prev_tx does not match txid"));
    }
    let out = prev
        .output
        .get(u.vout as usize)
        .ok_or(Error::InvalidInput("vout out of range"))?;
    if out.script_pubkey != u.script_pubkey || out.value.to_sat() != u.value.0 {
        return Err(Error::InvalidInput("prev_tx output differs from utxo"));
    }
    Ok(())
}

/// Amount and script of input `i`, taken from the PSBT's own previous-output data.
fn prevout(psbt: &Psbt, i: usize) -> Result<TxOut> {
    let txin = psbt
        .unsigned_tx
        .input
        .get(i)
        .ok_or(Error::InvalidPsbt("input index"))?;
    let data = psbt
        .inputs
        .get(i)
        .ok_or(Error::InvalidPsbt("input index"))?;
    if let Some(prev) = &data.non_witness_utxo {
        if prev.compute_txid() != txin.previous_output.txid {
            return Err(Error::InvalidPsbt("non_witness_utxo txid mismatch"));
        }
        return prev
            .output
            .get(txin.previous_output.vout as usize)
            .cloned()
            .ok_or(Error::InvalidPsbt("non_witness_utxo vout"));
    }
    data.witness_utxo
        .clone()
        .ok_or(Error::InvalidPsbt("input amount unknown"))
}

/// Inputs and outputs exactly as the PSBT presents them; the capability is checked against
/// this, not against request fields.
pub(crate) fn presented(psbt: &Psbt) -> Result<(Vec<InputRef>, Vec<OutputRef>)> {
    if psbt.unsigned_tx.input.len() > MAX_PSBT_IO || psbt.unsigned_tx.output.len() > MAX_PSBT_IO {
        return Err(Error::InvalidPsbt("too many inputs or outputs"));
    }
    let mut inputs = Vec::with_capacity(psbt.unsigned_tx.input.len());
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let po = prevout(psbt, i)?;
        inputs.push(InputRef {
            outpoint: txin.previous_output,
            value: Sats(po.value.to_sat()),
        });
    }
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| OutputRef {
            script: o.script_pubkey.clone(),
            value: Sats(o.value.to_sat()),
        })
        .collect();
    Ok((inputs, outputs))
}

/// Parse a PSBT from hex (bounded).
pub fn parse_psbt_hex(hex: &str) -> Result<Psbt> {
    if hex.len() > 8 * 1024 * 1024 || !hex.len().is_multiple_of(2) {
        return Err(Error::InvalidPsbt("hex length"));
    }
    let bytes = decode_hex(hex).ok_or(Error::InvalidPsbt("not hex"))?;
    Psbt::deserialize(&bytes).map_err(|_| Error::InvalidPsbt("malformed psbt"))
}

pub fn psbt_to_hex(psbt: &Psbt) -> String {
    encode_hex(&psbt.serialize())
}

pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------- display summary

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSummary {
    pub index: usize,
    pub address: Option<String>,
    pub value: Option<Sats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSummary {
    pub index: usize,
    pub address: Option<String>,
    pub value: Sats,
    pub is_change: bool,
    pub is_op_return: bool,
    pub op_return_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtSummary {
    pub network: Network,
    pub inputs: Vec<InputSummary>,
    pub outputs: Vec<OutputSummary>,
    /// `None` when any input amount is unknown.
    pub total_in: Option<Sats>,
    pub total_out: Sats,
    /// `None` when any input amount is unknown. Outputs exceeding inputs is an error rather
    /// than a fee of zero (legacy `Math.max(in - out, 0)`).
    pub fee: Option<Sats>,
}

fn address_string(network: Network, script: &Script) -> Option<String> {
    Address::from_script(network, script)
        .ok()
        .and_then(|a| a.encode().ok())
}

fn op_return_text(script: &Script) -> Option<String> {
    script.instructions().find_map(|ins| match ins {
        Ok(Instruction::PushBytes(b)) => Some(String::from_utf8_lossy(b.as_bytes()).into_owned()),
        _ => None,
    })
}

/// Port of `summarizePsbtForDisplay`. `own` lists the wallet's own addresses for the
/// change flag.
pub fn summarize_psbt(psbt: &Psbt, network: Network, own: &[Address]) -> Result<PsbtSummary> {
    if psbt.unsigned_tx.input.len() > MAX_PSBT_IO || psbt.unsigned_tx.output.len() > MAX_PSBT_IO {
        return Err(Error::InvalidPsbt("too many inputs or outputs"));
    }
    let mut inputs = Vec::new();
    let mut known_total = Some(Sats(0));
    for i in 0..psbt.unsigned_tx.input.len() {
        match prevout(psbt, i) {
            Ok(po) => {
                let v = Sats(po.value.to_sat());
                known_total = known_total.and_then(|t| t.checked_add(v).ok());
                inputs.push(InputSummary {
                    index: i,
                    address: address_string(network, &po.script_pubkey),
                    value: Some(v),
                });
            }
            Err(_) => {
                known_total = None;
                inputs.push(InputSummary {
                    index: i,
                    address: None,
                    value: None,
                });
            }
        }
    }
    let mut outputs = Vec::new();
    for (i, o) in psbt.unsigned_tx.output.iter().enumerate() {
        let is_op_return = o.script_pubkey.as_bytes().first() == Some(&OP_RETURN.to_u8());
        let address = address_string(network, &o.script_pubkey);
        let is_change = own
            .iter()
            .any(|a| a.network() == network && a.script_pubkey() == o.script_pubkey.as_script());
        outputs.push(OutputSummary {
            index: i,
            address,
            value: Sats(o.value.to_sat()),
            is_change,
            is_op_return,
            op_return_text: if is_op_return {
                op_return_text(&o.script_pubkey)
            } else {
                None
            },
        });
    }
    let total_out = Sats::sum(outputs.iter().map(|o| o.value))?;
    let fee = match known_total {
        Some(t_in) => Some(
            t_in.checked_sub(total_out)
                .map_err(|_| Error::InvalidPsbt("outputs exceed inputs"))?,
        ),
        None => None,
    };
    Ok(PsbtSummary {
        network,
        inputs,
        outputs,
        total_in: known_total,
        total_out,
        fee,
    })
}

// ---------------------------------------------------------------- signing

#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Sign only these input indices (legacy `sellerFlag` signs input 0 only). `None` signs
    /// every input the account owns.
    pub only_indices: Option<Vec<usize>>,
    /// Finalize and extract (legacy buyer path). Fails if any input is not final.
    pub finalize: bool,
    /// Witness script supplied out-of-band (legacy `witnessScript` argument for input 0).
    /// Used only if the PSBT input lacks one, and only if it hashes to the input's existing
    /// `witness_utxo` script; the PSBT's prevout data is never rewritten.
    pub witness_script_input0: Option<ScriptBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    Final { raw_tx_hex: String, txid: String },
    Partial { psbt_hex: String },
}

pub(crate) fn parse_multisig(ws: &Script) -> Option<(usize, Vec<PublicKey>)> {
    let mut it = ws.instructions();
    let m = match it.next()?.ok()? {
        Instruction::Op(op) => pushnum(op)?,
        _ => return None,
    };
    let mut keys = Vec::new();
    let n;
    loop {
        match it.next()?.ok()? {
            Instruction::PushBytes(b) => keys.push(PublicKey::from_slice(b.as_bytes()).ok()?),
            Instruction::Op(op) => {
                n = pushnum(op)?;
                break;
            }
        }
    }
    match it.next()?.ok()? {
        Instruction::Op(op) if op == OP_CHECKMULTISIG => {}
        _ => return None,
    }
    if it.next().is_some() || n != keys.len() || m == 0 || m > n {
        return None;
    }
    Some((m, keys))
}

fn sign_hash(
    account: &Account,
    sk_owner: &crate::keys::DerivedKey,
    hash: [u8; 32],
) -> EcdsaSignature {
    let sig = account
        .secp()
        .sign_ecdsa(&Message::from_digest(hash), sk_owner.secret());
    EcdsaSignature {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    }
}

/// Sign inputs after authorization has succeeded. Crate-private by design.
pub(crate) fn sign_authorized(
    account: &Account,
    mut psbt: Psbt,
    opts: &SignOptions,
) -> Result<SignOutcome> {
    let n = psbt.unsigned_tx.input.len();
    if let Some(idx) = &opts.only_indices {
        if idx.iter().any(|i| *i >= n) {
            return Err(Error::InvalidPsbt("input index out of range"));
        }
    }
    for i in 0..n {
        let wanted = opts
            .only_indices
            .as_ref()
            .map(|v| v.contains(&i))
            .unwrap_or(true);
        if !wanted {
            continue;
        }
        let explicit = opts.only_indices.is_some();
        let ws_override = if i == 0 {
            opts.witness_script_input0.as_deref()
        } else {
            None
        };
        let signed = sign_one_input(account, &mut psbt, i, ws_override)?;
        if !signed && explicit {
            return Err(Error::InvalidPsbt(
                "requested input is not signable by this account",
            ));
        }
    }
    if opts.finalize {
        for i in 0..n {
            if !finalize_input(&mut psbt, i)? {
                return Err(Error::InvalidPsbt(
                    "cannot finalize: input lacks signatures",
                ));
            }
        }
        let tx = psbt.extract_tx_unchecked_fee_rate();
        let raw = bitcoin::consensus::encode::serialize(&tx);
        return Ok(SignOutcome::Final {
            raw_tx_hex: encode_hex(&raw),
            txid: tx.compute_txid().to_string(),
        });
    }
    Ok(SignOutcome::Partial {
        psbt_hex: psbt_to_hex(&psbt),
    })
}

fn is_final(psbt: &Psbt, i: usize) -> bool {
    psbt.inputs[i].final_script_witness.is_some() || psbt.inputs[i].final_script_sig.is_some()
}

/// Returns `Ok(true)` if a signature was added, `Ok(false)` if the input is not ours or is
/// already final.
fn sign_one_input(
    account: &Account,
    psbt: &mut Psbt,
    i: usize,
    ws_override: Option<&Script>,
) -> Result<bool> {
    if is_final(psbt, i) {
        return Ok(false);
    }
    if let Some(t) = psbt.inputs[i].sighash_type {
        if t.ecdsa_hash_ty().ok() != Some(EcdsaSighashType::All) {
            return Err(Error::InvalidPsbt("only SIGHASH_ALL is signed"));
        }
    }
    let po = prevout(psbt, i)?;
    let spk = po.script_pubkey.clone();
    let amount = po.value;

    if spk.is_p2wpkh() || spk.is_p2pkh() {
        let Some(key) = account.key_for_script(&spk) else {
            return Ok(false);
        };
        let hash: [u8; 32] = {
            let cache_tx = psbt.unsigned_tx.clone();
            let mut cache = SighashCache::new(&cache_tx);
            if spk.is_p2wpkh() {
                cache
                    .p2wpkh_signature_hash(i, &spk, amount, EcdsaSighashType::All)
                    .map_err(|_| Error::InvalidPsbt("sighash"))?
                    .to_byte_array()
            } else {
                if psbt.inputs[i].non_witness_utxo.is_none() {
                    return Err(Error::InvalidPsbt("p2pkh input requires non_witness_utxo"));
                }
                cache
                    .legacy_signature_hash(i, &spk, EcdsaSighashType::All.to_u32())
                    .map_err(|_| Error::InvalidPsbt("sighash"))?
                    .to_byte_array()
            }
        };
        let sig = sign_hash(account, key, hash);
        let pk = PublicKey::new(key.public_key().0);
        psbt.inputs[i].partial_sigs.insert(pk, sig);
        return Ok(true);
    }

    if spk.is_p2wsh() {
        let ws: ScriptBuf = match (&psbt.inputs[i].witness_script, ws_override) {
            (Some(w), _) => w.clone(),
            (None, Some(o)) => o.to_owned(),
            (None, None) => return Ok(false),
        };
        if ScriptBuf::new_p2wsh(&ws.wscript_hash()) != spk {
            return Err(Error::InvalidPsbt(
                "witness script does not match prevout script",
            ));
        }
        let (_, keys) =
            parse_multisig(&ws).ok_or(Error::InvalidPsbt("unsupported witness script"))?;
        let our = PublicKey::new(account.receive_key().public_key().0);
        if !keys.contains(&our) {
            return Ok(false);
        }
        let hash = {
            let cache_tx = psbt.unsigned_tx.clone();
            let mut cache = SighashCache::new(&cache_tx);
            cache
                .p2wsh_signature_hash(i, &ws, amount, EcdsaSighashType::All)
                .map_err(|_| Error::InvalidPsbt("sighash"))?
                .to_byte_array()
        };
        let sig = sign_hash(account, account.receive_key(), hash);
        psbt.inputs[i].witness_script = Some(ws);
        psbt.inputs[i].partial_sigs.insert(our, sig);
        return Ok(true);
    }
    Ok(false)
}

/// Returns whether the input is final afterwards.
fn finalize_input(psbt: &mut Psbt, i: usize) -> Result<bool> {
    if is_final(psbt, i) {
        return Ok(true);
    }
    let po = prevout(psbt, i)?;
    let spk = po.script_pubkey;
    let input = &mut psbt.inputs[i];
    if spk.is_p2wpkh() {
        let Some((pk, sig)) = input.partial_sigs.iter().next().map(|(k, v)| (*k, *v)) else {
            return Ok(false);
        };
        input.final_script_witness = Some(Witness::p2wpkh(&sig, &pk.inner));
    } else if spk.is_p2pkh() {
        let Some((pk, sig)) = input.partial_sigs.iter().next().map(|(k, v)| (*k, *v)) else {
            return Ok(false);
        };
        let sig_bytes = sig.serialize();
        input.final_script_sig = Some(
            bitcoin::script::Builder::new()
                .push_slice(sig_bytes)
                .push_key(&pk)
                .into_script(),
        );
    } else if spk.is_p2wsh() {
        let Some(ws) = input.witness_script.clone() else {
            return Ok(false);
        };
        let Some((m, keys)) = parse_multisig(&ws) else {
            return Ok(false);
        };
        let mut witness = Witness::new();
        witness.push(Vec::<u8>::new());
        let mut have = 0usize;
        for k in &keys {
            if have == m {
                break;
            }
            if let Some(sig) = input.partial_sigs.get(k) {
                witness.push(sig.serialize());
                have += 1;
            }
        }
        if have < m {
            return Ok(false);
        }
        witness.push(ws.as_bytes());
        input.final_script_witness = Some(witness);
    } else {
        return Ok(false);
    }
    input.partial_sigs.clear();
    input.witness_script = None;
    input.sighash_type = None;
    Ok(true)
}

/// Sighash of input `i` for the cross-language known-answer tests.
pub fn segwit_sighash_hex(
    tx: &Transaction,
    i: usize,
    script: &Script,
    value: Sats,
) -> Result<String> {
    let mut cache = SighashCache::new(tx);
    let h = cache
        .p2wpkh_signature_hash(i, script, Amount::from_sat(value.0), EcdsaSighashType::All)
        .map_err(|_| Error::InvalidPsbt("sighash"))?;
    Ok(encode_hex(&h.to_byte_array()))
}

/// Value of `OP_1`..`OP_16` (`0x51..=0x60`).
fn pushnum(op: bitcoin::Opcode) -> Option<usize> {
    let b = op.to_u8();
    if (0x51..=0x60).contains(&b) {
        Some(usize::from(b - 0x50))
    } else {
        None
    }
}
