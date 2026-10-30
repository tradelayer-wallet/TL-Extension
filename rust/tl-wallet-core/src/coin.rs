//! UTXO selection and fee/change accounting with checked satoshi arithmetic.
//!
//! Ported from the selection in `signTransaction` (largest-first, fixed 10 000 sat fee) with
//! the legacy accounting holes closed:
//!
//! * legacy only checked `total >= amount` (not `amount + fee`) and then computed a possibly
//!   negative `change`, silently emitting a transaction whose outputs exceed its inputs;
//! * legacy emitted dust change; here change below the network dust threshold is folded into
//!   the fee, and the resulting fee must still respect the explicit bound.
//!
//! The pure core is [`select_largest_first`]; `lean/TlWalletCore/Coin.lean` models it.

use crate::amount::Sats;
use crate::error::{Error, Result};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};

/// Upper bound on candidate/selected inputs (bounded work on untrusted lists).
pub const MAX_UTXOS: usize = 2_000;

/// Legacy fixed fee: `10000n` sats in `signTransaction`.
pub const LEGACY_FIXED_FEE: Sats = Sats(10_000);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: Sats,
    pub script_pubkey: ScriptBuf,
    /// Full previous transaction. Required for legacy `p2pkh` inputs (whose sighash does not
    /// commit to the input amount); ignored for segwit inputs.
    pub prev_tx: Option<Transaction>,
}

impl Utxo {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }
}

/// How the fee is computed from the number of selected inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePolicy {
    /// Constant fee (legacy default [`LEGACY_FIXED_FEE`]).
    Fixed(Sats),
    /// `sats_per_vb * (fixed_vbytes + inputs * input_vbytes)`, all checked.
    PerVbyte {
        sats_per_vb: u64,
        fixed_vbytes: u64,
        input_vbytes: u64,
    },
}

impl FeePolicy {
    pub fn fee_for_inputs(&self, n_inputs: usize) -> Result<Sats> {
        match *self {
            FeePolicy::Fixed(f) => Ok(f),
            FeePolicy::PerVbyte {
                sats_per_vb,
                fixed_vbytes,
                input_vbytes,
            } => {
                let n = u64::try_from(n_inputs).map_err(|_| Error::AmountOverflow)?;
                let vb = n
                    .checked_mul(input_vbytes)
                    .and_then(|x| x.checked_add(fixed_vbytes))
                    .ok_or(Error::AmountOverflow)?;
                sats_per_vb
                    .checked_mul(vb)
                    .map(Sats)
                    .ok_or(Error::AmountOverflow)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub selected: Vec<Utxo>,
    pub total_in: Sats,
    pub target: Sats,
    /// Change output value; zero means no change output is created.
    pub change: Sats,
    /// Fee actually paid, including any dust folded in from would-be change.
    pub fee: Sats,
}

/// Largest value first; ties broken by (txid bytes, vout) so the order is deterministic.
fn sort_largest_first(utxos: &[Utxo]) -> Vec<Utxo> {
    let mut v = utxos.to_vec();
    v.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.txid.as_raw_hash().cmp(b.txid.as_raw_hash()))
            .then_with(|| a.vout.cmp(&b.vout))
    });
    v
}

/// Select inputs so that `sum(inputs) = target + change + fee`, `fee <= max_fee`, and
/// `change` is zero or at least `dust`.
pub fn select_largest_first(
    utxos: &[Utxo],
    target: Sats,
    policy: &FeePolicy,
    max_fee: Sats,
    dust: Sats,
) -> Result<Selection> {
    if utxos.len() > MAX_UTXOS {
        return Err(Error::InvalidInput("too many candidate inputs"));
    }
    if target.0 == 0 {
        return Err(Error::InvalidAmount("amount must be positive"));
    }
    let sorted = sort_largest_first(utxos);
    for w in sorted.windows(2) {
        if w[0].outpoint() == w[1].outpoint() {
            return Err(Error::InvalidInput("duplicate outpoint"));
        }
    }
    let mut total = Sats(0);
    for (i, u) in sorted.iter().enumerate() {
        total = total.checked_add(u.value)?;
        let fee = policy.fee_for_inputs(i + 1)?;
        let need = target.checked_add(fee)?;
        if total >= need {
            let raw_change = total.checked_sub(need)?;
            let (change, fee_paid) = if raw_change >= dust {
                (raw_change, fee)
            } else {
                (Sats(0), fee.checked_add(raw_change)?)
            };
            if fee_paid > max_fee {
                return Err(Error::FeeAboveBound {
                    fee: fee_paid.0,
                    bound: max_fee.0,
                });
            }
            return Ok(Selection {
                selected: sorted[..=i].to_vec(),
                total_in: total,
                target,
                change,
                fee: fee_paid,
            });
        }
    }
    let fee_all = policy.fee_for_inputs(sorted.len())?;
    Err(Error::InsufficientFunds {
        needed: target.checked_add(fee_all)?.0,
        available: total.0,
    })
}
