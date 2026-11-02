//! Vault manager: create, unlock, migrate from the legacy blob, change password, recover.
//!
//! # Storage layout
//!
//! | key | holds |
//! | --- | --- |
//! | `encryptedSeed` | legacy CryptoJS blob (read; deleted only by the final migration step) |
//! | `vault.legacy_backup` | byte-for-byte copy of the legacy blob, written before anything else |
//! | `vault.v1` | the sealed blob ([`super::format`]) |
//! | `vault.record` | migration record: phase, version floor, legacy fingerprint |
//! | `encryptedKey`, `encryptedPrivateKey:*` | legacy derived-key caches, purged at retirement |
//!
//! # Migration state machine
//!
//! Every step changes exactly one key with a compare-and-swap, so an interruption between two
//! steps leaves a state the next call resumes from:
//!
//! ```text
//! (no record)  --1--> BackedUp --2--> Written --3--> Verified --4--> Retired
//!   1: decrypt+validate legacy, write backup, then the record
//!   2: seal a new blob, write it, then the record
//!   3: read the new blob back from storage, open it, compare with the legacy secret
//!   4: re-verify, delete the legacy key, purge key caches, then the record
//! ```
//!
//! The legacy key is deleted only in step 4, only when the record says `Verified`, the backup
//! equals the legacy blob, and a fresh read-back of the sealed blob decrypts to the legacy secret.
//! At every point at least one of {legacy blob, sealed blob, backup} decrypts to the seed.

use super::format::{self, Kdf, PayloadKind, CURRENT_VERSION};
use super::legacy::{self, LegacyError};
use super::store::{Random, VaultStore};
use super::{Secret, VaultError};
use crate::keys::{Account, ChangeMode, ImportedMnemonic};
use crate::network::Network;
use sha2::{Digest, Sha256};

pub const LEGACY_SEED_KEY: &str = "encryptedSeed";
pub const LEGACY_KEY_CACHE: &str = "encryptedKey";
pub const LEGACY_KEY_CACHE_PREFIX: &str = "encryptedPrivateKey";
pub const VAULT_KEY: &str = "vault.v1";
pub const BACKUP_KEY: &str = "vault.legacy_backup";
pub const RECORD_KEY: &str = "vault.record";

const RECORD_PREFIX: &str = "tlrec1";

/// Persisted migration phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Backup written; nothing else changed.
    BackedUp,
    /// Sealed blob written, not yet read back.
    Written,
    /// Sealed blob read back and matched the legacy secret; legacy blob still present.
    Verified,
    /// Legacy blob and key caches removed; the backup remains.
    Retired,
    /// Vault created natively, never had a legacy blob.
    Native,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::BackedUp => "backed_up",
            Phase::Written => "written",
            Phase::Verified => "verified",
            Phase::Retired => "retired",
            Phase::Native => "native",
        }
    }

    fn from_name(s: &str) -> Option<Phase> {
        Some(match s {
            "backed_up" => Phase::BackedUp,
            "written" => Phase::Written,
            "verified" => Phase::Verified,
            "retired" => Phase::Retired,
            "native" => Phase::Native,
            _ => return None,
        })
    }
}

/// The persisted migration record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub phase: Phase,
    /// Sealed blobs with a version below this are refused ([`VaultError::Downgrade`]).
    pub min_version: u8,
    /// SHA-256 of the legacy blob this migration started from.
    pub fingerprint: Option<[u8; 32]>,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

fn fingerprint(blob: &str) -> [u8; 32] {
    Sha256::digest(blob.as_bytes()).into()
}

impl Record {
    pub fn encode(&self) -> String {
        let fp = match &self.fingerprint {
            Some(f) => hex(f),
            None => "-".to_string(),
        };
        format!(
            "{RECORD_PREFIX};{};{};{fp}",
            self.phase.name(),
            self.min_version
        )
    }

    pub fn parse(text: &str) -> Result<Record, VaultError> {
        let mut it = text.split(';');
        if it.next() != Some(RECORD_PREFIX) {
            return Err(VaultError::BadRecord);
        }
        let phase = it
            .next()
            .and_then(Phase::from_name)
            .ok_or(VaultError::BadRecord)?;
        let min_version: u8 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(VaultError::BadRecord)?;
        let fp = it.next().ok_or(VaultError::BadRecord)?;
        if it.next().is_some() {
            return Err(VaultError::BadRecord);
        }
        let fingerprint = if fp == "-" {
            None
        } else {
            Some(unhex32(fp).ok_or(VaultError::BadRecord)?)
        };
        Ok(Record {
            phase,
            min_version,
            fingerprint,
        })
    }
}

/// What one call of [`VaultManager::migrate_step`] reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStep {
    Reached(Phase),
    /// Nothing to do: the migration is finished or the vault was created natively.
    AlreadyDone,
}

/// Which secret store [`VaultManager::unlock`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockSource {
    Legacy,
    Sealed,
}

/// Result of [`VaultManager::recover_from_backup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverOutcome {
    AlreadyHealthy,
    Restored,
}

/// Which pieces exist (booleans only; no secret). Mirrors the Lean model `St`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub legacy: bool,
    pub backup: bool,
    pub vault: bool,
    pub phase: Option<Phase>,
}

pub struct VaultManager<S: VaultStore, R: Random> {
    store: S,
    rng: R,
    network: Network,
    kdf: Kdf,
}

fn cas<S: VaultStore>(
    store: &mut S,
    key: &str,
    expected: Option<&str>,
    new: Option<&str>,
) -> Result<(), VaultError> {
    store
        .compare_and_swap(key, expected, new)
        .map_err(VaultError::from)
}

/// Decrypt a legacy blob and accept it only if it is a canonical 12-word BIP-39 phrase.
fn legacy_secret(blob: &str, password: &str) -> Result<Secret, VaultError> {
    let plain = legacy::decrypt_cryptojs_passphrase(blob, password).map_err(|e| match e {
        LegacyError::BadPadding | LegacyError::NotUtf8 => VaultError::WrongPasswordOrTampered,
        other => VaultError::Legacy(other),
    })?;
    // generateAddressFromSeed trims the phrase (walletUtils.js:262)
    let trimmed = plain
        .as_str()
        .ok_or(VaultError::WrongPasswordOrTampered)?
        .trim();
    let parsed = ImportedMnemonic::parse_phrase(trimmed).map_err(|_| VaultError::InvalidSecret)?;
    if parsed.phrase() != trimmed {
        // The legacy wallet derived keys from the raw string; a canonical re-spelling would give
        // another seed. Refuse rather than migrate to a different wallet.
        return Err(VaultError::NonCanonicalLegacyPhrase);
    }
    Ok(Secret::new(trimmed.as_bytes().to_vec()))
}

impl<S: VaultStore, R: Random> VaultManager<S, R> {
    pub fn new(store: S, rng: R, network: Network, kdf: Kdf) -> Result<Self, VaultError> {
        kdf.validate()?;
        Ok(VaultManager {
            store,
            rng,
            network,
            kdf,
        })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn read_record(&self) -> Result<Option<(String, Record)>, VaultError> {
        match self.store.get(RECORD_KEY)? {
            None => Ok(None),
            Some(text) => {
                let rec = Record::parse(&text)?;
                Ok(Some((text, rec)))
            }
        }
    }

    fn floor(&self) -> Result<u8, VaultError> {
        Ok(self.read_record()?.map_or(1, |(_, r)| r.min_version))
    }

    fn open_sealed(&self, blob: &str, password: &str) -> Result<Secret, VaultError> {
        format::open(
            blob,
            password,
            self.network,
            PayloadKind::MnemonicPhrase,
            self.floor()?,
        )
    }

    fn seal(&mut self, password: &str, secret: &Secret) -> Result<String, VaultError> {
        format::seal(
            &mut self.rng,
            password,
            secret.expose(),
            self.kdf,
            self.network,
            PayloadKind::MnemonicPhrase,
        )
    }

    fn record_after(&self, phase: Phase, fp: Option<[u8; 32]>) -> Result<Record, VaultError> {
        let floor = self.floor()?.max(CURRENT_VERSION);
        Ok(Record {
            phase,
            min_version: floor,
            fingerprint: fp,
        })
    }

    /// Which pieces currently exist.
    pub fn snapshot(&self) -> Result<Snapshot, VaultError> {
        Ok(Snapshot {
            legacy: self.store.get(LEGACY_SEED_KEY)?.is_some(),
            backup: self.store.get(BACKUP_KEY)?.is_some(),
            vault: self.store.get(VAULT_KEY)?.is_some(),
            phase: self.read_record()?.map(|(_, r)| r.phase),
        })
    }

    /// Which secret store [`Self::unlock`] reads: the legacy blob until the sealed blob has been
    /// verified, the sealed blob afterwards.
    pub fn unlock_source(&self) -> Result<UnlockSource, VaultError> {
        let legacy = self.store.get(LEGACY_SEED_KEY)?.is_some();
        let phase = self.read_record()?.map(|(_, r)| r.phase);
        Ok(
            if legacy && matches!(phase, None | Some(Phase::BackedUp) | Some(Phase::Written)) {
                UnlockSource::Legacy
            } else {
                UnlockSource::Sealed
            },
        )
    }

    /// Decrypt the seed phrase. Wrong password or damage is an error, never garbage.
    pub fn unlock(&self, password: &str) -> Result<Secret, VaultError> {
        match self.unlock_source()? {
            UnlockSource::Legacy => {
                let blob = self
                    .store
                    .get(LEGACY_SEED_KEY)?
                    .ok_or(VaultError::NoVault)?;
                legacy_secret(&blob, password)
            }
            UnlockSource::Sealed => match self.store.get(VAULT_KEY)? {
                Some(blob) => self.open_sealed(&blob, password),
                None if self.store.get(BACKUP_KEY)?.is_some() => Err(VaultError::Unreadable),
                None => Err(VaultError::NoVault),
            },
        }
    }

    /// Replacement for the legacy `checkPasswordMatch` stub (walletUtils.js:886, always `true`):
    /// the password must decrypt the vault.
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        self.unlock(password).map(|_| ())
    }

    /// What the legacy stub's signature intended: the password must decrypt the vault AND the
    /// seed must derive `expected_address` on `network`.
    pub fn check_password_match(
        &self,
        password: &str,
        network: Network,
        expected_address: &str,
    ) -> Result<(), VaultError> {
        let secret = self.unlock(password)?;
        let phrase = secret.as_str().ok_or(VaultError::InvalidSecret)?;
        let m = ImportedMnemonic::parse_phrase(phrase).map_err(|_| VaultError::InvalidSecret)?;
        let account = Account::from_mnemonic(&m, network, ChangeMode::SameAsReceive)
            .map_err(|_| VaultError::InvalidSecret)?;
        let derived = account
            .receive_address()
            .encode()
            .map_err(|_| VaultError::InvalidSecret)?;
        if derived == expected_address {
            Ok(())
        } else {
            Err(VaultError::AddressMismatch)
        }
    }

    /// Create a fresh vault. Refuses to run over an existing vault, legacy blob, backup or
    /// record (legacy `PasswordSetup.js:24-37` silently kept the old seed and dropped the new
    /// one when `encryptedSeed` already existed).
    pub fn create(
        &mut self,
        mnemonic: &ImportedMnemonic,
        password: &str,
    ) -> Result<(), VaultError> {
        if password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        for key in [LEGACY_SEED_KEY, VAULT_KEY, BACKUP_KEY, RECORD_KEY] {
            if self.store.get(key)?.is_some() {
                return Err(VaultError::AlreadyExists);
            }
        }
        let secret = Secret::new(mnemonic.phrase().into_bytes());
        let blob = self.seal(password, &secret)?;
        cas(&mut self.store, VAULT_KEY, None, Some(&blob))?;
        let back = self.store.get(VAULT_KEY)?.ok_or(VaultError::VerifyFailed)?;
        let got = self.open_sealed(&back, password)?;
        if !got.ct_eq(&secret) {
            return Err(VaultError::VerifyFailed);
        }
        let rec = self.record_after(Phase::Native, None)?;
        cas(&mut self.store, RECORD_KEY, None, Some(&rec.encode()))
    }

    /// The secret the migration must reproduce: the legacy blob if present (and unchanged since
    /// the migration started), else the backup.
    fn reference_secret(
        &self,
        old_password: &str,
        rec: &Record,
        legacy: Option<&str>,
    ) -> Result<Secret, VaultError> {
        match legacy {
            Some(l) => {
                if rec.fingerprint != Some(fingerprint(l)) {
                    return Err(VaultError::LegacyChanged);
                }
                legacy_secret(l, old_password)
            }
            None => {
                let b = self
                    .store
                    .get(BACKUP_KEY)?
                    .ok_or(VaultError::BackupMismatch)?;
                if rec.fingerprint != Some(fingerprint(&b)) {
                    return Err(VaultError::BackupMismatch);
                }
                legacy_secret(&b, old_password)
            }
        }
    }

    /// Read the sealed blob back from storage and require it to open to `expected`.
    fn read_back(&self, new_password: &str, expected: &Secret) -> Result<(), VaultError> {
        let blob = self.store.get(VAULT_KEY)?.ok_or(VaultError::VerifyFailed)?;
        let got = self
            .open_sealed(&blob, new_password)
            .map_err(|_| VaultError::VerifyFailed)?;
        if got.ct_eq(expected) {
            Ok(())
        } else {
            Err(VaultError::VerifyFailed)
        }
    }

    /// Perform exactly one transition of the migration (see the module docs). Call repeatedly,
    /// or use [`Self::migrate`]. Safe to call again after any failure.
    pub fn migrate_step(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<MigrationStep, VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        let legacy = self.store.get(LEGACY_SEED_KEY)?;
        let rec = self.read_record()?;
        let Some((rec_text, rec)) = rec else {
            // Step 1.
            let Some(l) = legacy else {
                return if self.store.get(VAULT_KEY)?.is_some() {
                    Ok(MigrationStep::AlreadyDone)
                } else {
                    Err(VaultError::NoVault)
                };
            };
            drop(legacy_secret(&l, old_password)?);
            let current = self.store.get(BACKUP_KEY)?;
            if current.as_deref() != Some(l.as_str()) {
                cas(&mut self.store, BACKUP_KEY, current.as_deref(), Some(&l))?;
            }
            if self.store.get(BACKUP_KEY)?.as_deref() != Some(l.as_str()) {
                return Err(VaultError::BackupMismatch);
            }
            let next = self.record_after(Phase::BackedUp, Some(fingerprint(&l)))?;
            cas(&mut self.store, RECORD_KEY, None, Some(&next.encode()))?;
            return Ok(MigrationStep::Reached(Phase::BackedUp));
        };
        match rec.phase {
            Phase::Native | Phase::Retired => Ok(MigrationStep::AlreadyDone),
            Phase::BackedUp => {
                // Step 2.
                let l = legacy.ok_or(VaultError::LegacyChanged)?;
                if rec.fingerprint != Some(fingerprint(&l)) {
                    return Err(VaultError::LegacyChanged);
                }
                if self.store.get(BACKUP_KEY)?.as_deref() != Some(l.as_str()) {
                    return Err(VaultError::BackupMismatch);
                }
                let secret = self.reference_secret(old_password, &rec, Some(&l))?;
                let current = self.store.get(VAULT_KEY)?;
                let already_good = match &current {
                    Some(c) => self
                        .open_sealed(c, new_password)
                        .map(|s| s.ct_eq(&secret))
                        .unwrap_or(false),
                    None => false,
                };
                if !already_good {
                    let blob = self.seal(new_password, &secret)?;
                    cas(&mut self.store, VAULT_KEY, current.as_deref(), Some(&blob))?;
                }
                let next = self.record_after(Phase::Written, rec.fingerprint)?;
                cas(
                    &mut self.store,
                    RECORD_KEY,
                    Some(&rec_text),
                    Some(&next.encode()),
                )?;
                Ok(MigrationStep::Reached(Phase::Written))
            }
            Phase::Written => {
                // Step 3.
                let secret = self.reference_secret(old_password, &rec, legacy.as_deref())?;
                self.read_back(new_password, &secret)?;
                let next = self.record_after(Phase::Verified, rec.fingerprint)?;
                cas(
                    &mut self.store,
                    RECORD_KEY,
                    Some(&rec_text),
                    Some(&next.encode()),
                )?;
                Ok(MigrationStep::Reached(Phase::Verified))
            }
            Phase::Verified => {
                // Step 4.
                let secret = self.reference_secret(old_password, &rec, legacy.as_deref())?;
                self.read_back(new_password, &secret)?;
                if let Some(l) = &legacy {
                    if self.store.get(BACKUP_KEY)?.as_deref() != Some(l.as_str()) {
                        return Err(VaultError::BackupMismatch);
                    }
                    cas(&mut self.store, LEGACY_SEED_KEY, Some(l), None)?;
                }
                for key in self.store.keys()? {
                    if key == LEGACY_KEY_CACHE || key.starts_with(LEGACY_KEY_CACHE_PREFIX) {
                        if let Some(cur) = self.store.get(&key)? {
                            cas(&mut self.store, &key, Some(&cur), None)?;
                        }
                    }
                }
                let next = self.record_after(Phase::Retired, rec.fingerprint)?;
                cas(
                    &mut self.store,
                    RECORD_KEY,
                    Some(&rec_text),
                    Some(&next.encode()),
                )?;
                Ok(MigrationStep::Reached(Phase::Retired))
            }
        }
    }

    /// Run the migration to completion (or to the first failure; call again to resume).
    pub fn migrate(&mut self, old_password: &str, new_password: &str) -> Result<Phase, VaultError> {
        loop {
            match self.migrate_step(old_password, new_password)? {
                MigrationStep::Reached(Phase::Retired) => return Ok(Phase::Retired),
                MigrationStep::Reached(_) => continue,
                MigrationStep::AlreadyDone => {
                    return Ok(self.read_record()?.map_or(Phase::Native, |(_, r)| r.phase));
                }
            }
        }
    }

    /// Abandon an unfinished migration while the legacy blob is still present: removes the
    /// record, the staged sealed blob and the backup. Nothing is lost: the legacy blob stays.
    pub fn abort_migration(&mut self) -> Result<(), VaultError> {
        let legacy = self.store.get(LEGACY_SEED_KEY)?;
        let rec = self.read_record()?;
        if legacy.is_none() {
            return Err(VaultError::WrongPhase(rec.map(|(_, r)| r.phase)));
        }
        if let Some((_, r)) = &rec {
            if matches!(r.phase, Phase::Retired | Phase::Native) {
                return Err(VaultError::WrongPhase(Some(r.phase)));
            }
        }
        if let Some((text, _)) = &rec {
            cas(&mut self.store, RECORD_KEY, Some(text), None)?;
        }
        for key in [VAULT_KEY, BACKUP_KEY] {
            if let Some(cur) = self.store.get(key)? {
                cas(&mut self.store, key, Some(&cur), None)?;
            }
        }
        Ok(())
    }

    /// Re-encrypt the vault under a new password in one atomic swap of the sealed blob.
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        if self.unlock_source()? != UnlockSource::Sealed {
            return Err(VaultError::WrongPhase(
                self.read_record()?.map(|(_, r)| r.phase),
            ));
        }
        let current = self.store.get(VAULT_KEY)?.ok_or(VaultError::NoVault)?;
        let secret = self.open_sealed(&current, old_password)?;
        let blob = self.seal(new_password, &secret)?;
        cas(&mut self.store, VAULT_KEY, Some(&current), Some(&blob))?;
        if let Err(e) = self.read_back(new_password, &secret) {
            // best effort: put the previous blob back
            let _ = cas(&mut self.store, VAULT_KEY, Some(&blob), Some(&current));
            return Err(e);
        }
        Ok(())
    }

    /// Rebuild the sealed blob from the backup record after the blob was lost or damaged.
    pub fn recover_from_backup(
        &mut self,
        backup_password: &str,
        new_password: &str,
    ) -> Result<RecoverOutcome, VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        let rec = self.read_record()?;
        if self.store.get(LEGACY_SEED_KEY)?.is_some() {
            // the legacy blob is still authoritative: use migrate
            return Err(VaultError::WrongPhase(rec.map(|(_, r)| r.phase)));
        }
        let backup = self.store.get(BACKUP_KEY)?.ok_or(VaultError::NoVault)?;
        let secret = legacy_secret(&backup, backup_password)?;
        let current = self.store.get(VAULT_KEY)?;
        if let Some(c) = &current {
            if let Ok(s) = self.open_sealed(c, new_password) {
                if s.ct_eq(&secret) {
                    return Ok(RecoverOutcome::AlreadyHealthy);
                }
            }
        }
        let blob = self.seal(new_password, &secret)?;
        cas(&mut self.store, VAULT_KEY, current.as_deref(), Some(&blob))?;
        self.read_back(new_password, &secret)?;
        Ok(RecoverOutcome::Restored)
    }

    /// Delete the backup record once the sealed blob is confirmed to hold the same secret. The
    /// backup is protected only by the legacy scheme, so keeping it indefinitely keeps the weak
    /// ciphertext around; this is the explicit, verified way to drop it.
    pub fn discard_backup(
        &mut self,
        backup_password: &str,
        vault_password: &str,
    ) -> Result<(), VaultError> {
        let rec = self.read_record()?;
        match rec {
            Some((_, r)) if r.phase == Phase::Retired => {}
            other => return Err(VaultError::WrongPhase(other.map(|(_, r)| r.phase))),
        }
        let backup = self.store.get(BACKUP_KEY)?.ok_or(VaultError::NoVault)?;
        let from_backup = legacy_secret(&backup, backup_password)?;
        self.read_back(vault_password, &from_backup)?;
        cas(&mut self.store, BACKUP_KEY, Some(&backup), None)
    }
}
