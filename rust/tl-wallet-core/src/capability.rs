//! The signing capability: the only way to obtain a signature from an [`Account`].
//!
//! A capability binds one origin, one network, one account, the exact approved inputs and
//! outputs, and a fee bound. It is single-use (signing consumes it) and time-limited by an
//! injected clock. [`authorize_tx`] / [`authorize_message`] are the pure predicates that the
//! Lean model `TlWalletCore.Capability` proves correct.
//!
//! Granting a capability is the act of user approval; it must be called only by the code
//! that renders the request to the user and receives their decision, never from page input.

use crate::amount::Sats;
use crate::error::{Denied, Error, Result};
use crate::keys::{Account, AccountId};
use crate::message;
use crate::network::Network;
use crate::origin::Origin;
use crate::tx::{self, SignOptions, SignOutcome};
use bitcoin::psbt::Psbt;
use bitcoin::{OutPoint, ScriptBuf};

/// An approved input: outpoint and the amount the user was shown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputRef {
    pub outpoint: OutPoint,
    pub value: Sats,
}

/// An approved output: exact script and amount.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputRef {
    pub script: ScriptBuf,
    pub value: Sats,
}

/// Facts about the current request as established by the provider layer (sender origin,
/// resolved-and-approved network), not as claimed by the page body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester {
    pub origin: Origin,
    pub network: Network,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Message {
        message: Vec<u8>,
    },
    Transaction {
        inputs: Vec<InputRef>,
        outputs: Vec<OutputRef>,
        fee_bound: Sats,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct SigningCapability {
    origin: Origin,
    network: Network,
    account: AccountId,
    /// Exclusive expiry on the injected clock (any monotonic unit the caller chooses).
    expires_at: u64,
    scope: Scope,
}

impl SigningCapability {
    pub fn for_message(
        origin: Origin,
        account: AccountId,
        expires_at: u64,
        message: Vec<u8>,
    ) -> Self {
        SigningCapability {
            origin,
            network: account.network,
            account,
            expires_at,
            scope: Scope::Message { message },
        }
    }

    pub fn for_transaction(
        origin: Origin,
        account: AccountId,
        expires_at: u64,
        inputs: Vec<InputRef>,
        outputs: Vec<OutputRef>,
        fee_bound: Sats,
    ) -> Self {
        SigningCapability {
            origin,
            network: account.network,
            account,
            expires_at,
            scope: Scope::Transaction {
                inputs,
                outputs,
                fee_bound,
            },
        }
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

fn check_common(
    cap: &SigningCapability,
    req: &Requester,
    account: &AccountId,
    now: u64,
) -> core::result::Result<(), Denied> {
    if now >= cap.expires_at {
        return Err(Denied::Expired);
    }
    if req.origin != cap.origin {
        return Err(Denied::OriginMismatch);
    }
    if req.network != cap.network || account.network != cap.network {
        return Err(Denied::NetworkMismatch);
    }
    if *account != cap.account {
        return Err(Denied::AccountMismatch);
    }
    Ok(())
}

/// Authorization predicate for a transaction. On success returns the fee implied by the
/// presented inputs and outputs (`sum(inputs) - sum(outputs)`), which is `<= fee_bound`.
///
/// Succeeds only if origin, network and account all match, every presented input is an
/// approved input (same outpoint and amount, no repeats), the presented outputs are exactly
/// the approved outputs (as a multiset), and the fee is within the bound.
pub fn authorize_tx(
    cap: &SigningCapability,
    req: &Requester,
    account: &AccountId,
    now: u64,
    inputs: &[InputRef],
    outputs: &[OutputRef],
) -> core::result::Result<Sats, Denied> {
    check_common(cap, req, account, now)?;
    let (approved_in, approved_out, fee_bound) = match &cap.scope {
        Scope::Transaction {
            inputs,
            outputs,
            fee_bound,
        } => (inputs, outputs, *fee_bound),
        Scope::Message { .. } => return Err(Denied::WrongKind),
    };
    let mut seen: Vec<&OutPoint> = Vec::with_capacity(inputs.len());
    for inp in inputs {
        if seen.contains(&&inp.outpoint) {
            return Err(Denied::DuplicateInput);
        }
        seen.push(&inp.outpoint);
    }
    for (i, inp) in inputs.iter().enumerate() {
        if !approved_in.contains(inp) {
            return Err(Denied::UnapprovedInput(i));
        }
    }
    let mut a: Vec<&OutputRef> = approved_out.iter().collect();
    let mut b: Vec<&OutputRef> = outputs.iter().collect();
    a.sort();
    b.sort();
    if a != b {
        return Err(Denied::OutputsNotApproved);
    }
    let total_in = Sats::sum(inputs.iter().map(|i| i.value)).map_err(|_| Denied::InvalidAmounts)?;
    let total_out =
        Sats::sum(outputs.iter().map(|o| o.value)).map_err(|_| Denied::InvalidAmounts)?;
    let fee = total_in
        .checked_sub(total_out)
        .map_err(|_| Denied::InvalidAmounts)?;
    if fee > fee_bound {
        return Err(Denied::FeeAboveBound);
    }
    Ok(fee)
}

/// Authorization predicate for a message: same bindings, exact message bytes.
pub fn authorize_message(
    cap: &SigningCapability,
    req: &Requester,
    account: &AccountId,
    now: u64,
    msg: &[u8],
) -> core::result::Result<(), Denied> {
    check_common(cap, req, account, now)?;
    match &cap.scope {
        Scope::Message { message } if message.as_slice() == msg => Ok(()),
        Scope::Message { .. } => Err(Denied::MessageMismatch),
        Scope::Transaction { .. } => Err(Denied::WrongKind),
    }
}

/// BIP-137 sign `msg`. Consumes the capability.
pub fn sign_message(
    cap: SigningCapability,
    req: &Requester,
    account: &Account,
    now: u64,
    msg: &[u8],
) -> Result<String> {
    authorize_message(&cap, req, &account.id(), now, msg)?;
    message::sign_message_unchecked(account, msg)
}

/// Sign the owned inputs of `psbt`. Consumes the capability. The presented inputs, outputs
/// and fee are re-derived from the PSBT itself, never taken from request fields.
pub fn sign_psbt(
    cap: SigningCapability,
    req: &Requester,
    account: &Account,
    now: u64,
    psbt: Psbt,
    opts: &SignOptions,
) -> Result<SignOutcome> {
    let (inputs, outputs) = tx::presented(&psbt)?;
    authorize_tx(&cap, req, &account.id(), now, &inputs, &outputs).map_err(Error::Denied)?;
    tx::sign_authorized(account, psbt, opts)
}
