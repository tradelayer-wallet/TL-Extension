//! `tl-wallet-core`: the pure, I/O-free wallet logic of the TradeLayer browser extension.
//!
//! No threads, no filesystem, no clock and no entropy are used: time (`now`) and randomness
//! (mnemonic entropy) are injected by the caller, which keeps the crate usable from
//! `wasm32` bindings. Vault encryption and browser storage are deliberately not here.
#![forbid(unsafe_code)]

pub mod address;
pub mod amount;
pub mod capability;
pub mod coin;
pub mod error;
pub mod keys;
pub mod message;
pub mod multisig;
pub mod network;
pub mod origin;
pub mod provider;
pub mod tx;

pub use address::{Address, AddressKind};
pub use amount::Sats;
pub use capability::{
    authorize_message, authorize_tx, sign_message, sign_psbt, InputRef, OutputRef, Requester,
    Scope, SigningCapability,
};
pub use error::{Denied, Error, ProviderError, Result};
pub use keys::{Account, AccountId, AccountInfo, ChangeMode, ImportedMnemonic};
pub use network::Network;
pub use origin::Origin;
