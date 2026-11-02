//! The extension vault: password-protected storage of the wallet seed.
//!
//! * [`legacy`] decrypts what the shipped extension wrote (CryptoJS passphrase encryption).
//!   Import only; nothing in this crate produces the legacy format.
//! * [`format`] is the versioned sealed format (scrypt or PBKDF2-SHA-256, then
//!   XChaCha20-Poly1305 with the header as associated data).
//! * [`store`] holds the storage and randomness traits plus in-memory implementations.
//! * [`manager`] is the migration state machine, unlock, password change and recovery.
//!
//! No filesystem, clock or ambient RNG is used: storage and randomness are injected.

pub mod format;
pub mod legacy;
pub mod manager;
pub mod store;

pub use format::{Header, Kdf, PayloadKind, CURRENT_VERSION};
pub use manager::{
    MigrationStep, Phase, Record, RecoverOutcome, Snapshot, UnlockSource, VaultManager,
};
pub use store::{CounterRandom, MemoryStore, Random, StoreError, VaultStore};

use crate::network::Network;
use zeroize::Zeroizing;

/// Why a vault operation failed. Nothing here carries secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// The empty password is refused everywhere (legacy `PasswordSetup` accepted it).
    EmptyPassword,
    /// Authentication failed: the password is wrong or the blob was modified. The two cannot be
    /// told apart, by design.
    WrongPasswordOrTampered,
    /// The blob is not a vault blob or is structurally invalid.
    Malformed(&'static str),
    /// A version this build does not know.
    UnsupportedVersion(u8),
    /// The blob is older than the recorded version floor.
    Downgrade { found: u8, floor: u8 },
    /// KDF identifier unknown.
    UnsupportedKdf(u8),
    /// KDF parameters outside the accepted window (guards against resource exhaustion).
    KdfParamsOutOfRange(&'static str),
    /// The blob was sealed for another network than the one the caller expects.
    NetworkMismatch { expected: Network, found: Network },
    /// The blob holds another kind of payload than the caller expects.
    KindMismatch,
    /// Legacy blob could not be decoded or decrypted.
    Legacy(legacy::LegacyError),
    /// Legacy plaintext decrypted but is a valid phrase only in a non-canonical spelling
    /// (extra spaces, upper case): migrating it would silently change the derived wallet.
    NonCanonicalLegacyPhrase,
    /// Storage failed.
    Store(StoreError),
    /// The injected randomness source failed.
    Random,
    /// Neither a vault nor a legacy seed exists.
    NoVault,
    /// A vault, a legacy seed, a backup or a migration record already exists.
    AlreadyExists,
    /// The legacy seed changed after the migration started (fingerprint differs).
    LegacyChanged,
    /// The backup record does not equal the legacy seed it was taken from.
    BackupMismatch,
    /// The new blob read back from storage does not decrypt to the legacy secret.
    VerifyFailed,
    /// The migration record is not in a phase that allows this operation.
    WrongPhase(Option<Phase>),
    /// The migration record is malformed.
    BadRecord,
    /// The sealed blob is missing but a backup exists: call recover.
    Unreadable,
    /// The unlocked secret does not derive the expected address.
    AddressMismatch,
    /// The secret is not a mnemonic accepted by the wallet.
    InvalidSecret,
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Store(e)
    }
}

impl From<legacy::LegacyError> for VaultError {
    fn from(e: legacy::LegacyError) -> Self {
        VaultError::Legacy(e)
    }
}

/// Secret bytes (a mnemonic phrase). Wiped on drop; `Debug` prints nothing.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Secret) -> bool {
        use subtle::ConstantTimeEq;
        self.0.len() == other.0.len() && bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
