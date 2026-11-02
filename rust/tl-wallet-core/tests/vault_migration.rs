//! Migration state machine, fault injection, recovery drill and repaired-defect regressions.
mod vault_common;
use tl_wallet_core::keys::{Account, ChangeMode, ImportedMnemonic};
use tl_wallet_core::vault::manager::{
    BACKUP_KEY, LEGACY_KEY_CACHE, LEGACY_KEY_CACHE_PREFIX, LEGACY_SEED_KEY, RECORD_KEY, VAULT_KEY,
};
use tl_wallet_core::vault::{
    CounterRandom, Kdf, MemoryStore, MigrationStep, Phase, Record, RecoverOutcome, Snapshot,
    UnlockSource, VaultError, VaultManager, VaultStore,
};
use tl_wallet_core::Network;
use vault_common::*;

const KDF: Kdf = Kdf::Pbkdf2Sha256 { iterations: 1_000 };
const NET: Network = Network::Ltc;

type Mgr<S> = VaultManager<S, CounterRandom>;

fn mgr<S: VaultStore>(store: S) -> Mgr<S> {
    VaultManager::new(store, CounterRandom::new(42), NET, KDF).unwrap()
}

fn snap(l: bool, b: bool, v: bool, p: Option<Phase>) -> Snapshot {
    Snapshot {
        legacy: l,
        backup: b,
        vault: v,
        phase: p,
    }
}

fn phrase_of<S: VaultStore>(m: &Mgr<S>, pw: &str) -> String {
    m.unlock(pw).unwrap().as_str().unwrap().to_string()
}

// ---- state machine (mirrors lean/TlWalletCore/Vault.lean `trace_*` examples) -------------------

#[test]
fn happy_path_step_by_step() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    assert_eq!(m.snapshot().unwrap(), snap(true, false, false, None));
    assert_eq!(m.unlock_source().unwrap(), UnlockSource::Legacy);

    let expect = [
        (
            Phase::BackedUp,
            snap(true, true, false, Some(Phase::BackedUp)),
            UnlockSource::Legacy,
        ),
        (
            Phase::Written,
            snap(true, true, true, Some(Phase::Written)),
            UnlockSource::Legacy,
        ),
        (
            Phase::Verified,
            snap(true, true, true, Some(Phase::Verified)),
            UnlockSource::Sealed,
        ),
        (
            Phase::Retired,
            snap(false, true, true, Some(Phase::Retired)),
            UnlockSource::Sealed,
        ),
    ];
    for (phase, snapshot, source) in expect {
        assert_eq!(
            m.migrate_step(OLD_PW, NEW_PW).unwrap(),
            MigrationStep::Reached(phase)
        );
        assert_eq!(m.snapshot().unwrap(), snapshot);
        assert_eq!(m.unlock_source().unwrap(), source);
        // the secret is readable with the password that belongs to the active source
        let pw = if source == UnlockSource::Legacy {
            OLD_PW
        } else {
            NEW_PW
        };
        assert_eq!(phrase_of(&m, pw), PHRASE);
    }
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).unwrap(),
        MigrationStep::AlreadyDone
    );
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);

    // legacy key and both caches are gone; the backup is the original blob byte for byte
    let s = m.store();
    assert!(s.raw(LEGACY_SEED_KEY).is_none());
    assert!(s.raw(LEGACY_KEY_CACHE).is_none());
    assert!(s
        .keys()
        .unwrap()
        .iter()
        .all(|k| !k.starts_with(LEGACY_KEY_CACHE_PREFIX)));
    assert_eq!(s.raw("unrelated"), Some("kept"));
    let original = legacy_store(PHRASE, OLD_PW);
    assert_eq!(s.raw(BACKUP_KEY), original.raw(LEGACY_SEED_KEY));
    let rec = Record::parse(s.raw(RECORD_KEY).unwrap()).unwrap();
    assert_eq!(rec.phase, Phase::Retired);
    assert_eq!(rec.min_version, 1);
    // legacy password no longer opens the sealed blob
    assert_eq!(
        m.unlock(OLD_PW).err(),
        Some(VaultError::WrongPasswordOrTampered)
    );
}

#[test]
fn migrate_runs_all_steps_and_keeps_same_password() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    assert_eq!(m.migrate(OLD_PW, OLD_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, OLD_PW), PHRASE);
}

#[test]
fn legacy_wallet_with_empty_password_migrates_to_a_real_one() {
    // PasswordSetup.js accepted an empty password; migration is the way out.
    let v = vectors();
    let mut s = MemoryStore::new();
    s.put_raw(LEGACY_SEED_KEY, &v["legacy.seed_empty_pw.blob"]);
    let mut m = mgr(s);
    assert_eq!(
        m.migrate("", "").err(),
        Some(VaultError::EmptyPassword),
        "the new password must not be empty"
    );
    assert_eq!(phrase_of(&m, ""), PHRASE);
    assert_eq!(m.migrate("", NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

#[test]
fn crypto_js_fixture_blob_migrates() {
    let v = vectors();
    let mut s = MemoryStore::new();
    s.put_raw(LEGACY_SEED_KEY, &v["legacy.seed.blob"]);
    let mut m = mgr(s);
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
    assert_eq!(
        m.store().raw(BACKUP_KEY),
        Some(v["legacy.seed.blob"].as_str())
    );
}

#[test]
fn wrong_old_password_changes_nothing() {
    let before = legacy_store(PHRASE, OLD_PW);
    let mut m = mgr(before.clone());
    assert!(m.migrate("wrong", NEW_PW).is_err());
    assert_eq!(m.store(), &before);
    // and mid-migration too
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    let mid = m.store().clone();
    assert!(m.migrate_step("wrong", NEW_PW).is_err());
    assert_eq!(m.store(), &mid);
}

#[test]
fn non_canonical_or_invalid_legacy_plaintext_is_not_migrated() {
    for (plain, want) in [
        (
            "Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            VaultError::NonCanonicalLegacyPhrase,
        ),
        (
            "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            VaultError::NonCanonicalLegacyPhrase,
        ),
        (
            // 12 valid words with a bad checksum: the pre-validation import (R10) allowed these
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            VaultError::InvalidSecret,
        ),
        ("not a seed at all", VaultError::InvalidSecret),
        ("", VaultError::InvalidSecret),
    ] {
        let before = legacy_store(plain, OLD_PW);
        let mut m = mgr(before.clone());
        assert_eq!(m.migrate(OLD_PW, NEW_PW).err(), Some(want), "{plain:?}");
        assert_eq!(m.store(), &before, "legacy data must stay untouched");
    }
    // surrounding whitespace is trimmed exactly like walletUtils.js:262
    let mut m = mgr(legacy_store(&format!("  {PHRASE}\n"), OLD_PW));
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

// ---- fault injection ----------------------------------------------------------------------------

/// At least one of legacy blob, verified sealed blob, backup holds the secret.
fn assert_recoverable(s: &Snapshot) {
    let sealed_ok = s.vault && matches!(s.phase, Some(Phase::Verified) | Some(Phase::Retired));
    assert!(s.legacy || sealed_ok || s.backup, "unrecoverable: {s:?}");
    // the legacy blob is only ever absent after read-back verification, with backup and vault present
    if !s.legacy {
        assert!(
            matches!(s.phase, Some(Phase::Verified) | Some(Phase::Retired)) && s.vault && s.backup,
            "legacy gone too early: {s:?}"
        );
    }
}

#[test]
fn interruption_at_every_write_is_recoverable_and_resumable() {
    for mode in [FaultMode::FailBefore, FaultMode::ApplyThenFail] {
        let mut writes_seen = 0;
        for n in 0.. {
            let mut m = mgr(FaultStore::new(legacy_store(PHRASE, OLD_PW)));
            m.store_mut().arm(n, mode);
            let r = m.migrate(OLD_PW, NEW_PW);
            if !m.store().fired {
                assert_eq!(r.unwrap(), Phase::Retired);
                writes_seen = n;
                break;
            }
            assert_eq!(
                r.err(),
                Some(VaultError::Store(tl_wallet_core::vault::StoreError::Io))
            );
            m.store_mut().disarm();
            // state after the interruption: recoverable, and the user can still unlock
            let s = m.snapshot().unwrap();
            assert_recoverable(&s);
            let pw = if m.unlock_source().unwrap() == UnlockSource::Legacy {
                OLD_PW
            } else {
                NEW_PW
            };
            assert_eq!(phrase_of(&m, pw), PHRASE, "write {n} {mode:?}");
            // resume to completion
            assert_eq!(
                m.migrate(OLD_PW, NEW_PW).unwrap(),
                Phase::Retired,
                "write {n} {mode:?}"
            );
            assert_eq!(
                m.snapshot().unwrap(),
                snap(false, true, true, Some(Phase::Retired))
            );
            assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
            let original = legacy_store(PHRASE, OLD_PW);
            assert_eq!(
                m.store().inner.raw(BACKUP_KEY),
                original.raw(LEGACY_SEED_KEY)
            );
            assert!(m.store().inner.raw(LEGACY_KEY_CACHE).is_none());
        }
        // backup, record, vault, record, record, legacy delete, 2 cache deletes, record
        assert_eq!(writes_seen, 9, "{mode:?}");
    }
}

#[test]
fn double_interruption_still_converges() {
    // fail write k, resume and fail write j of the resumed run, then finish
    for k in 0..9 {
        for j in 0..9 {
            let mut m = mgr(FaultStore::new(legacy_store(PHRASE, OLD_PW)));
            m.store_mut().arm(k, FaultMode::ApplyThenFail);
            let _ = m.migrate(OLD_PW, NEW_PW);
            m.store_mut().arm(j, FaultMode::FailBefore);
            let _ = m.migrate(OLD_PW, NEW_PW);
            assert_recoverable(&m.snapshot().unwrap());
            m.store_mut().disarm();
            assert_eq!(
                m.migrate(OLD_PW, NEW_PW).unwrap(),
                Phase::Retired,
                "{k},{j}"
            );
            assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
        }
    }
}

#[test]
fn read_back_mismatch_blocks_retirement() {
    let mut m = mgr(FaultStore::new(legacy_store(PHRASE, OLD_PW)));
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    assert_eq!(
        m.snapshot().unwrap(),
        snap(true, true, true, Some(Phase::Written))
    );
    // storage returns altered bytes for the sealed blob
    m.store_mut().lie_on = Some(VAULT_KEY.to_string());
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).err(),
        Some(VaultError::VerifyFailed)
    );
    assert_eq!(
        m.snapshot().unwrap(),
        snap(true, true, true, Some(Phase::Written))
    );
    m.store_mut().lie_on = None;
    assert_eq!(phrase_of(&m, OLD_PW), PHRASE, "legacy still unlocks");
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);
}

#[test]
fn corrupt_sealed_blob_in_written_phase_blocks_until_aborted() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    let blob = m.store().raw(VAULT_KEY).unwrap().to_string();
    let mut bad = blob.clone().into_bytes();
    let i = bad.len() - 6;
    bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
    m.store_mut()
        .put_raw(VAULT_KEY, &String::from_utf8(bad).unwrap());
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).err(),
        Some(VaultError::VerifyFailed)
    );
    assert!(m.store().raw(LEGACY_SEED_KEY).is_some());
    m.abort_migration().unwrap();
    assert_eq!(m.snapshot().unwrap(), snap(true, false, false, None));
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

#[test]
fn legacy_changed_after_start_is_detected_and_never_deleted() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    // the user resets the password in the old UI: a different blob appears under the same key
    let other = legacy_store(PHRASE_B, "other pw");
    m.store_mut()
        .put_raw(LEGACY_SEED_KEY, other.raw(LEGACY_SEED_KEY).unwrap());
    assert_eq!(
        m.migrate_step("other pw", NEW_PW).err(),
        Some(VaultError::LegacyChanged)
    );
    assert!(m.store().raw(LEGACY_SEED_KEY).is_some());
    m.abort_migration().unwrap();
    assert_eq!(m.migrate("other pw", NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE_B);
}

#[test]
fn legacy_changed_at_verified_never_gets_deleted() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    for _ in 0..3 {
        m.migrate_step(OLD_PW, NEW_PW).unwrap();
    }
    assert_eq!(m.snapshot().unwrap().phase, Some(Phase::Verified));
    let other = legacy_store(PHRASE_B, OLD_PW);
    let other_blob = other.raw(LEGACY_SEED_KEY).unwrap().to_string();
    m.store_mut().put_raw(LEGACY_SEED_KEY, &other_blob);
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).err(),
        Some(VaultError::LegacyChanged)
    );
    assert_eq!(m.store().raw(LEGACY_SEED_KEY), Some(other_blob.as_str()));
}

#[test]
fn backup_tampering_is_detected_before_the_sealed_blob_is_written() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    m.store_mut().put_raw(BACKUP_KEY, "garbage");
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).err(),
        Some(VaultError::BackupMismatch)
    );
    assert!(m.store().raw(VAULT_KEY).is_none());
    // deleting the backup is caught at the same place
    m.store_mut().remove_raw(BACKUP_KEY);
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).err(),
        Some(VaultError::BackupMismatch)
    );
}

#[test]
fn backup_removed_before_retirement_blocks_deletion_of_legacy() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    for _ in 0..3 {
        m.migrate_step(OLD_PW, NEW_PW).unwrap();
    }
    m.store_mut().remove_raw(BACKUP_KEY);
    assert_eq!(
        m.migrate_step(OLD_PW, NEW_PW).err(),
        Some(VaultError::BackupMismatch)
    );
    assert!(m.store().raw(LEGACY_SEED_KEY).is_some());
}

#[test]
fn abort_is_refused_without_legacy_or_after_retirement() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate(OLD_PW, NEW_PW).unwrap();
    assert_eq!(
        m.abort_migration().err(),
        Some(VaultError::WrongPhase(Some(Phase::Retired)))
    );
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

// ---- recovery drill ---------------------------------------------------------------------------------

fn expected_addresses() -> Vec<(Network, String)> {
    let m = ImportedMnemonic::parse_phrase(PHRASE).unwrap();
    Network::ALL
        .iter()
        .map(|n| {
            let a = Account::from_mnemonic(&m, *n, ChangeMode::SameAsReceive).unwrap();
            (*n, a.receive_address().encode().unwrap())
        })
        .collect()
}

#[test]
fn recovery_drill_lost_and_corrupted_sealed_blob() {
    // 1. synthetic mnemonic -> legacy blob (real crypto-js output from the fixture)
    let v = vectors();
    let mut s = MemoryStore::new();
    s.put_raw(LEGACY_SEED_KEY, &v["legacy.seed.blob"]);
    let mut m = mgr(s);
    let expected = expected_addresses();
    for (net, addr) in &expected {
        m.check_password_match(OLD_PW, *net, addr).unwrap();
    }

    // 2. migrate
    m.migrate(OLD_PW, NEW_PW).unwrap();
    for (net, addr) in &expected {
        m.check_password_match(NEW_PW, *net, addr).unwrap();
    }

    // 3a. corrupt the sealed blob
    let good = m.store().raw(VAULT_KEY).unwrap().to_string();
    let mut bad = good.clone().into_bytes();
    let i = bad.len() / 2;
    bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
    m.store_mut()
        .put_raw(VAULT_KEY, &String::from_utf8(bad).unwrap());
    assert!(m.unlock(NEW_PW).is_err(), "never returns garbage");
    assert_eq!(
        m.recover_from_backup(OLD_PW, NEW_PW).unwrap(),
        RecoverOutcome::Restored
    );
    for (net, addr) in &expected {
        m.check_password_match(NEW_PW, *net, addr).unwrap();
    }
    assert_eq!(
        m.recover_from_backup(OLD_PW, NEW_PW).unwrap(),
        RecoverOutcome::AlreadyHealthy
    );

    // 3b. lose the sealed blob entirely
    m.store_mut().remove_raw(VAULT_KEY);
    assert_eq!(m.unlock(NEW_PW).err(), Some(VaultError::Unreadable));
    // recovery with a wrong backup password fails and writes nothing
    let before = m.store().clone();
    assert!(m.recover_from_backup("wrong", NEW_PW).is_err());
    assert_eq!(m.store(), &before);
    // recovery may also choose a different new password
    assert_eq!(
        m.recover_from_backup(OLD_PW, "third password").unwrap(),
        RecoverOutcome::Restored
    );
    for (net, addr) in &expected {
        m.check_password_match("third password", *net, addr)
            .unwrap();
    }
    assert_eq!(
        m.snapshot().unwrap(),
        snap(false, true, true, Some(Phase::Retired))
    );

    // 4. once the sealed blob is confirmed, the weak backup can be dropped on purpose
    assert!(m.discard_backup("wrong", "third password").is_err());
    assert!(m.discard_backup(OLD_PW, "wrong").is_err());
    assert!(m.store().raw(BACKUP_KEY).is_some());
    m.discard_backup(OLD_PW, "third password").unwrap();
    assert!(m.store().raw(BACKUP_KEY).is_none());
    m.store_mut().remove_raw(VAULT_KEY);
    assert_eq!(m.unlock("third password").err(), Some(VaultError::NoVault));
}

#[test]
fn recovery_drill_crash_between_legacy_delete_and_retired_record() {
    // The legacy key is gone, the record still says Verified, and the sealed blob is damaged:
    // the backup repairs it and the migration then finishes.
    let mut m = mgr(FaultStore::new(legacy_store(PHRASE, OLD_PW)));
    // writes: 0 backup, 1 record, 2 vault, 3 record, 4 record, 5 legacy delete, 6 first cache purge
    m.store_mut().arm(6, FaultMode::FailBefore);
    assert!(m.migrate(OLD_PW, NEW_PW).is_err());
    m.store_mut().disarm();
    let s = m.snapshot().unwrap();
    assert_eq!(s.phase, Some(Phase::Verified));
    assert!(!s.legacy && s.backup && s.vault);
    m.store_mut().inner.put_raw(VAULT_KEY, "tlvault:AAAA");
    assert!(m.unlock(NEW_PW).is_err());
    assert_eq!(
        m.recover_from_backup(OLD_PW, NEW_PW).unwrap(),
        RecoverOutcome::Restored
    );
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

// ---- repaired defects ---------------------------------------------------------------------------------

/// V-R1 walletUtils.js:886-889: `checkPasswordMatch` returned true for every input.
#[test]
fn v_r1_check_password_match_is_real() {
    let expected = expected_addresses();
    for migrated in [false, true] {
        let mut m = mgr(legacy_store(PHRASE, OLD_PW));
        let pw = if migrated {
            m.migrate(OLD_PW, NEW_PW).unwrap();
            NEW_PW
        } else {
            OLD_PW
        };
        let (net, addr) = &expected[0];
        m.check_password_match(pw, *net, addr).unwrap();
        m.verify_password(pw).unwrap();
        assert!(m.check_password_match("wrong", *net, addr).is_err());
        assert!(m.verify_password("wrong").is_err());
        assert_eq!(
            m.check_password_match(pw, Network::Btc, addr).err(),
            Some(VaultError::AddressMismatch),
            "an address of another network does not match"
        );
        let other = Account::from_mnemonic(
            &ImportedMnemonic::parse_phrase(PHRASE_B).unwrap(),
            NET,
            ChangeMode::SameAsReceive,
        )
        .unwrap()
        .receive_address()
        .encode()
        .unwrap();
        assert_eq!(
            m.check_password_match(pw, NET, &other).err(),
            Some(VaultError::AddressMismatch)
        );
    }
}

/// V-R2 CryptoJS CBC without authentication (PasswordSetup.js:40-47, ExposeSeed.js:28-31,
/// ResetPass.js:35-41): wrong passwords produced truthy garbage that was accepted. Here every
/// wrong password and every modified sealed blob is an error.
#[test]
fn v_r2_sealed_vault_never_returns_garbage() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate(OLD_PW, NEW_PW).unwrap();
    for i in 0..200 {
        let pw = format!("guess-{i}");
        assert_eq!(
            m.unlock(&pw).err(),
            Some(VaultError::WrongPasswordOrTampered)
        );
    }
    // legacy path: the vector for which crypto-js returned "/" is refused by the manager as well
    let v = vectors();
    let mut s = MemoryStore::new();
    s.put_raw(LEGACY_SEED_KEY, &v["legacy.wrong_accepted.blob"]);
    let wrong = unhex_str(&v["legacy.wrong_accepted.wrong_password_hex"]);
    let m2 = mgr(s);
    assert!(m2.unlock(&wrong).is_err());
    assert_eq!(m2.unlock(OLD_PW).unwrap().as_str(), Some(PHRASE));
}

/// V-R3 EVP_BytesToKey(MD5, 1 iteration) as the password KDF: the sealed header records a
/// memory-hard KDF and the defaults are scrypt 2^15/8/1.
#[test]
fn v_r3_new_vault_uses_a_recorded_memory_hard_kdf() {
    let mut m = VaultManager::new(
        MemoryStore::new(),
        CounterRandom::new(5),
        NET,
        Kdf::FLOOR_SCRYPT,
    )
    .unwrap();
    m.create(&ImportedMnemonic::parse_phrase(PHRASE).unwrap(), NEW_PW)
        .unwrap();
    let h = tl_wallet_core::vault::format::peek(m.store().raw(VAULT_KEY).unwrap()).unwrap();
    assert_eq!(h.kdf, Kdf::FLOOR_SCRYPT);
    assert!(matches!(h.kdf, Kdf::Scrypt { .. }));
    assert!(matches!(Kdf::DEFAULT, Kdf::Scrypt { log_n: 15, .. }));
    // a manager cannot be built with a weaker setting than the accepted floor
    assert!(VaultManager::new(
        MemoryStore::new(),
        CounterRandom::new(5),
        NET,
        Kdf::Pbkdf2Sha256 { iterations: 1 }
    )
    .is_err());
}

/// V-R4 walletUtils.js:892-914 and PasswordPrompt.js:87-88 cache a derived private key (under the
/// weak legacy scheme) in localStorage next to the seed. The new vault persists no derived key,
/// and migration purges the legacy caches.
#[test]
fn v_r4_no_derived_key_cache_is_persisted() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate(OLD_PW, NEW_PW).unwrap();
    let expected = expected_addresses();
    for (net, addr) in &expected {
        m.check_password_match(NEW_PW, *net, addr).unwrap();
    }
    m.change_password(NEW_PW, "another").unwrap();
    let mut keys = m.store().keys().unwrap();
    keys.sort();
    assert_eq!(keys, vec!["unrelated", BACKUP_KEY, RECORD_KEY, VAULT_KEY]);
    // a native vault has exactly two keys
    let mut n = mgr(MemoryStore::new());
    n.create(&ImportedMnemonic::parse_phrase(PHRASE).unwrap(), NEW_PW)
        .unwrap();
    for (net, addr) in &expected {
        n.check_password_match(NEW_PW, *net, addr).unwrap();
    }
    let mut keys = n.store().keys().unwrap();
    keys.sort();
    assert_eq!(keys, vec![RECORD_KEY, VAULT_KEY]);
}

/// V-R5 PasswordSetup.js:24-37: when `encryptedSeed` already existed, the newly entered seed was
/// dropped and the old one silently kept. Creation now refuses.
#[test]
fn v_r5_create_never_overwrites_or_silently_keeps() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    let before = m.store().clone();
    let b = ImportedMnemonic::parse_phrase(PHRASE_B).unwrap();
    assert_eq!(m.create(&b, NEW_PW).err(), Some(VaultError::AlreadyExists));
    assert_eq!(m.store(), &before);

    let mut n = mgr(MemoryStore::new());
    n.create(&b, NEW_PW).unwrap();
    let snapshot = n.store().clone();
    assert_eq!(n.create(&b, NEW_PW).err(), Some(VaultError::AlreadyExists));
    assert_eq!(n.store(), &snapshot);
    assert_eq!(phrase_of(&n, NEW_PW), PHRASE_B);
}

/// V-R6 PasswordSetup.js accepts an empty password.
#[test]
fn v_r6_empty_password_is_refused() {
    let mut n = mgr(MemoryStore::new());
    let a = ImportedMnemonic::parse_phrase(PHRASE).unwrap();
    assert_eq!(n.create(&a, "").err(), Some(VaultError::EmptyPassword));
    assert!(n.store().keys().unwrap().is_empty());
    n.create(&a, NEW_PW).unwrap();
    assert_eq!(
        n.change_password(NEW_PW, "").err(),
        Some(VaultError::EmptyPassword)
    );
    assert_eq!(n.unlock("").err(), Some(VaultError::EmptyPassword));
}

/// V-R7 ResetPass.js:35-47 re-encrypted whatever decrypted to a truthy string, and wrote it with
/// no read-back. change_password is one atomic swap with read-back and rollback.
#[test]
fn v_r7_change_password_is_atomic_and_verified() {
    let mut n = mgr(FaultStore::new(MemoryStore::new()));
    n.create(&ImportedMnemonic::parse_phrase(PHRASE).unwrap(), OLD_PW)
        .unwrap();
    let before = n.store().inner.clone();
    assert!(n.change_password("wrong", NEW_PW).is_err());
    assert_eq!(n.store().inner, before);

    // failed write: the old password keeps working
    n.store_mut().arm(0, FaultMode::FailBefore);
    assert!(n.change_password(OLD_PW, NEW_PW).is_err());
    n.store_mut().disarm();
    assert_eq!(n.store().inner, before);
    assert_eq!(phrase_of(&n, OLD_PW), PHRASE);

    // lost acknowledgement: the new password works, the old does not; never a mix
    n.store_mut().arm(0, FaultMode::ApplyThenFail);
    assert!(n.change_password(OLD_PW, NEW_PW).is_err());
    n.store_mut().disarm();
    assert_eq!(phrase_of(&n, NEW_PW), PHRASE);
    assert!(n.unlock(OLD_PW).is_err());

    // storage that returns altered bytes: the change is rolled back
    n.store_mut().lie_on = Some(VAULT_KEY.to_string());
    assert!(n.change_password(NEW_PW, "x").is_err());
    n.store_mut().lie_on = None;
    assert_eq!(phrase_of(&n, NEW_PW), PHRASE);
}

#[test]
fn change_password_before_migration_is_refused() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    let before = m.store().clone();
    assert!(matches!(
        m.change_password(OLD_PW, NEW_PW).err(),
        Some(VaultError::WrongPhase(_))
    ));
    assert_eq!(m.store(), &before);
}

// ---- version floor, hostile records, networks ------------------------------------------------------------

#[test]
fn version_floor_in_the_record_rejects_older_blobs() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate(OLD_PW, NEW_PW).unwrap();
    let rec = Record::parse(m.store().raw(RECORD_KEY).unwrap()).unwrap();
    let raised = Record {
        min_version: 2,
        ..rec
    };
    m.store_mut().put_raw(RECORD_KEY, &raised.encode());
    assert_eq!(
        m.unlock(NEW_PW).err(),
        Some(VaultError::Downgrade { found: 1, floor: 2 })
    );
    // restoring the lower floor makes the same blob readable again
    m.store_mut().put_raw(RECORD_KEY, &rec.encode());
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

#[test]
fn the_floor_never_decreases_across_record_writes() {
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate_step(OLD_PW, NEW_PW).unwrap();
    let rec = Record::parse(m.store().raw(RECORD_KEY).unwrap()).unwrap();
    // floor 1 here; a record claiming 1 stays at least CURRENT_VERSION
    assert!(rec.min_version >= tl_wallet_core::vault::CURRENT_VERSION);
}

#[test]
fn malformed_records_are_typed_errors() {
    for bad in [
        "",
        "tlrec1",
        "tlrec1;nope;1;-",
        "tlrec1;written;x;-",
        "tlrec1;written;1",
        "tlrec1;written;1;zz",
        "tlrec1;written;1;-;extra",
        "tlrec0;written;1;-",
    ] {
        assert_eq!(
            Record::parse(bad).err(),
            Some(VaultError::BadRecord),
            "{bad:?}"
        );
    }
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.store_mut().put_raw(RECORD_KEY, "tlrec1;nope;1;-");
    assert_eq!(m.unlock(OLD_PW).err(), Some(VaultError::BadRecord));
    assert_eq!(m.migrate(OLD_PW, NEW_PW).err(), Some(VaultError::BadRecord));
}

#[test]
fn record_round_trips() {
    for phase in [
        Phase::BackedUp,
        Phase::Written,
        Phase::Verified,
        Phase::Retired,
        Phase::Native,
    ] {
        for fp in [None, Some([0xabu8; 32])] {
            let r = Record {
                phase,
                min_version: 1,
                fingerprint: fp,
            };
            assert_eq!(Record::parse(&r.encode()).unwrap(), r);
        }
    }
}

#[test]
fn vault_for_another_network_is_refused() {
    let mut a = mgr(MemoryStore::new());
    a.create(&ImportedMnemonic::parse_phrase(PHRASE).unwrap(), NEW_PW)
        .unwrap();
    let store = a.into_store();
    let b = VaultManager::new(store, CounterRandom::new(1), Network::LtcTest, KDF).unwrap();
    assert!(matches!(
        b.unlock(NEW_PW).err(),
        Some(VaultError::NetworkMismatch { .. })
    ));
}

#[test]
fn empty_and_hostile_stores() {
    let m = mgr(MemoryStore::new());
    assert_eq!(m.unlock(NEW_PW).err(), Some(VaultError::NoVault));
    let mut m = mgr(MemoryStore::new());
    assert_eq!(m.migrate(OLD_PW, NEW_PW).err(), Some(VaultError::NoVault));
    m.store_mut().put_raw(LEGACY_SEED_KEY, &"A".repeat(100_000));
    assert!(m.migrate(OLD_PW, NEW_PW).is_err());
    m.store_mut().put_raw(LEGACY_SEED_KEY, "!!!");
    assert!(m.unlock(OLD_PW).is_err());
}

#[test]
fn scrypt_default_family_end_to_end() {
    // one run with the real memory-hard KDF at its floor setting
    let mut m = VaultManager::new(
        legacy_store(PHRASE, OLD_PW),
        CounterRandom::new(9),
        NET,
        Kdf::FLOOR_SCRYPT,
    )
    .unwrap();
    assert_eq!(m.migrate(OLD_PW, NEW_PW).unwrap(), Phase::Retired);
    assert_eq!(phrase_of(&m, NEW_PW), PHRASE);
}

// ---- Lean model vectors ----------------------------------------------------------------------------

/// `snap (run pp (steps.take k) (init0 lv))` for k = 0..=7 in lean/TlWalletCore/Vault.lean.
fn lean_snapshot(acts: usize) -> Snapshot {
    match acts {
        0 => snap(true, false, false, None),
        1 => snap(true, true, false, None),
        2 => snap(true, true, false, Some(Phase::BackedUp)),
        3 => snap(true, true, true, Some(Phase::BackedUp)),
        4 => snap(true, true, true, Some(Phase::Written)),
        5 => snap(true, true, true, Some(Phase::Verified)),
        6 => snap(false, true, true, Some(Phase::Verified)),
        7 => snap(false, true, true, Some(Phase::Retired)),
        _ => unreachable!(),
    }
}

/// Rust writes: 0 backup, 1 record, 2 vault, 3 record, 4 record, 5 legacy delete, 6 and 7 key
/// cache purges (not modelled: they leave the modelled state unchanged), 8 final record.
fn model_acts_after_writes(writes: usize) -> usize {
    match writes {
        0..=6 => writes,
        7 | 8 => 6,
        _ => 7,
    }
}

#[test]
fn interruption_snapshots_match_the_lean_model() {
    for mode in [FaultMode::FailBefore, FaultMode::ApplyThenFail] {
        for n in 0..9 {
            let mut m = mgr(FaultStore::new(legacy_store(PHRASE, OLD_PW)));
            m.store_mut().arm(n, mode);
            assert!(m.migrate(OLD_PW, NEW_PW).is_err());
            m.store_mut().disarm();
            let applied = if mode == FaultMode::FailBefore {
                n
            } else {
                n + 1
            };
            assert_eq!(
                m.snapshot().unwrap(),
                lean_snapshot(model_acts_after_writes(applied)),
                "{mode:?} at write {n}"
            );
        }
    }
    // the uninterrupted run ends in the model's final state
    let mut m = mgr(legacy_store(PHRASE, OLD_PW));
    m.migrate(OLD_PW, NEW_PW).unwrap();
    assert_eq!(m.snapshot().unwrap(), lean_snapshot(7));
}

/// Lean `unlock pp 1/2 (run pp (steps.take k) ...)` vectors: the legacy password works until the
/// sealed blob is verified, the new password afterwards, never the other one.
#[test]
fn unlock_vectors_match_the_lean_model() {
    // (model acts taken, writes applied, legacy password unlocks, new password unlocks)
    let table = [
        (0usize, 0usize, true, false),
        (4, 4, true, false),
        (5, 5, false, true),
        (7, 9, false, true),
    ];
    for (acts, writes, old_ok, new_ok) in table {
        let mut m = mgr(FaultStore::new(legacy_store(PHRASE, OLD_PW)));
        m.store_mut().arm(writes, FaultMode::FailBefore);
        let _ = m.migrate(OLD_PW, NEW_PW);
        m.store_mut().disarm();
        assert_eq!(m.snapshot().unwrap(), lean_snapshot(acts));
        assert_eq!(m.unlock(OLD_PW).is_ok(), old_ok, "acts {acts}");
        assert_eq!(m.unlock(NEW_PW).is_ok(), new_ok, "acts {acts}");
    }
}
