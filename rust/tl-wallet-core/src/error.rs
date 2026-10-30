//! Typed errors. Nothing in this crate panics on untrusted input.

use crate::network::Network;
use core::fmt;

/// Why a signing capability refused an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The requesting origin differs from the origin the user approved.
    OriginMismatch,
    /// The request targets a different network than the approved one.
    NetworkMismatch,
    /// The request is for a different account than the approved one.
    AccountMismatch,
    /// A transaction input (by index) was not part of the approved input set.
    UnapprovedInput(usize),
    /// The same outpoint appears twice in the request.
    DuplicateInput,
    /// The transaction outputs are not exactly the approved outputs.
    OutputsNotApproved,
    /// The implied fee exceeds the approved fee bound.
    FeeAboveBound,
    /// Outputs exceed inputs, or the total overflows.
    InvalidAmounts,
    /// The capability has expired (injected clock).
    Expired,
    /// The capability was granted for a different kind of operation.
    WrongKind,
    /// The message differs from the approved message.
    MessageMismatch,
}

/// Why a page request was refused before reaching any approval UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    MissingRequestId,
    UnsupportedMethod(String),
    OriginNotAllowed,
    OriginNotApproved,
    NetworkNotApproved,
    /// More than one network is approved and the page did not name one.
    NetworkRequired,
    NoAccounts,
    InvalidRequest(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnknownNetwork(String),
    NetworkMismatch { expected: Network, actual: Network },
    InvalidAddress(&'static str),
    UnsupportedAddress(&'static str),
    InvalidMnemonic(&'static str),
    InvalidAmount(&'static str),
    AmountOverflow,
    InsufficientFunds { needed: u64, available: u64 },
    FeeAboveBound { fee: u64, bound: u64 },
    DustOutput { value: u64, threshold: u64 },
    InvalidInput(&'static str),
    InvalidPsbt(&'static str),
    PayloadTooLarge { len: usize, max: usize },
    MessageTooLong { len: usize, max: usize },
    InvalidSignature(&'static str),
    InvalidMultisig(&'static str),
    Denied(Denied),
    Provider(ProviderError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

impl From<Denied> for Error {
    fn from(d: Denied) -> Self {
        Error::Denied(d)
    }
}

impl From<ProviderError> for Error {
    fn from(e: ProviderError) -> Self {
        Error::Provider(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
