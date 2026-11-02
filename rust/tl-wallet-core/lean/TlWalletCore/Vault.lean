/-!
# Vault migration state machine

Models `src/vault/manager.rs` (`VaultManager::migrate_step`, `unlock`, `unlock_source`) and the
version policy of `src/vault/format.rs::open`.

The Rust step of "write backup, then record" is two compare-and-swap writes; the model keeps
each write as its own action (`Act`), so every interleaving, every prefix (an interruption after
any write, whether or not the failing write was applied) and every skipped action is covered by
`Reach`.

Abstractions: passwords are `Nat` keys, secrets are `Nat`, a blob is `(key, secret, version)`;
`openBlob` succeeds exactly when the key matches (AEAD authentication) and the version is
accepted. The cryptography is not modelled; authentication of every header field and bit is
tested in Rust (`tests/vault_format.rs`). The legacy blob is assumed not to change during the
migration (Rust: the SHA-256 fingerprint in the record refuses a changed blob with
`LegacyChanged`). The KDF, base64 envelope, the key-cache purge (it touches no modelled key) and
the version floor ratchet (a parameter `fl` here) are not modelled.
-/
namespace TlWalletCore.Vault

/-- `format::CURRENT_VERSION`. -/
def curVer : Nat := 1

structure Blob where
  key : Nat
  secret : Nat
  ver : Nat
  deriving DecidableEq, Repr

/-- `legacy::decrypt_cryptojs_passphrase` followed by the mnemonic validation in `legacy_secret`:
succeeds only with the matching key. -/
def legacyOpen (k : Nat) (b : Blob) : Option Nat :=
  if b.key = k then some b.secret else none

/-- `format::open`: version window and floor first, then authentication. -/
def openBlob (fl k : Nat) (b : Blob) : Option Nat :=
  if fl ≤ b.ver ∧ 1 ≤ b.ver ∧ b.ver ≤ curVer then
    (if b.key = k then some b.secret else none)
  else none

theorem openBlob_some {fl k : Nat} {b : Blob} {x : Nat} (h : openBlob fl k b = some x) :
    b.key = k ∧ x = b.secret ∧ fl ≤ b.ver ∧ 1 ≤ b.ver ∧ b.ver ≤ curVer := by
  unfold openBlob at h
  split at h
  · rename_i hv
    split at h
    · rename_i hk
      simp at h
      exact ⟨hk, h.symm, hv.1, hv.2.1, hv.2.2⟩
    · simp at h
  · simp at h

/-- Unlock succeeds only with the key the blob was sealed under. -/
theorem openBlob_wrong_key {fl k : Nat} {b : Blob} (h : b.key ≠ k) : openBlob fl k b = none := by
  unfold openBlob
  split
  · simp
  · rfl

/-- Downgrade: a blob older than the recorded floor is refused, whatever the key. -/
theorem downgrade_rejected {fl k : Nat} {b : Blob} (h : b.ver < fl) : openBlob fl k b = none := by
  unfold openBlob
  have : ¬ (fl ≤ b.ver ∧ 1 ≤ b.ver ∧ b.ver ≤ curVer) := by omega
  simp [this]

/-- A version this build does not know (newer) is refused. -/
theorem unknown_version_rejected {fl k : Nat} {b : Blob} (h : curVer < b.ver) :
    openBlob fl k b = none := by
  unfold openBlob
  have : ¬ (fl ≤ b.ver ∧ 1 ≤ b.ver ∧ b.ver ≤ curVer) := by omega
  simp [this]

/-- Version 0 is refused. -/
theorem version_zero_rejected {fl k : Nat} {b : Blob} (h : b.ver = 0) : openBlob fl k b = none := by
  unfold openBlob
  have : ¬ (fl ≤ b.ver ∧ 1 ≤ b.ver ∧ b.ver ≤ curVer) := by omega
  simp [this]

/-- A blob of the current version opens with its own key. -/
theorem right_key_opens {fl : Nat} {b : Blob} (h1 : fl ≤ b.ver) (h2 : 1 ≤ b.ver)
    (h3 : b.ver ≤ curVer) : openBlob fl b.key b = some b.secret := by
  unfold openBlob
  simp [h1, h2, h3]

/-! ## State -/

inductive Phase where
  | backedUp | written | verified | retired
  deriving DecidableEq, Repr

/-- The persisted pieces: legacy blob, backup record, sealed blob, migration record phase. -/
structure St where
  legacy : Option Blob
  backup : Option Blob
  vault : Option Blob
  phase : Option Phase
  deriving DecidableEq, Repr

/-- Passwords and the version floor. -/
structure Params where
  oldK : Nat
  newK : Nat
  fl : Nat

/-- The secret the migration must reproduce: legacy blob if present, else the backup
(`VaultManager::reference_secret`). -/
def refSecret (p : Params) (s : St) : Option Nat :=
  match s.legacy with
  | some l => legacyOpen p.oldK l
  | none => match s.backup with
    | some b => legacyOpen p.oldK b
    | none => none

/-- The sealed blob read back from storage opens to the reference secret
(`VaultManager::read_back` compared with `reference_secret`). -/
def readBack (p : Params) (s : St) : Prop :=
  (refSecret p s).isSome = true ∧ s.vault.bind (openBlob p.fl p.newK) = refSecret p s

instance (p : Params) (s : St) : Decidable (readBack p s) := by
  unfold readBack; infer_instance

/-- The individual writes of `migrate_step`. -/
inductive Act where
  | writeBackup | recBackedUp          -- step 1
  | writeVault | recWritten            -- step 2
  | recVerified                        -- step 3
  | deleteLegacy | recRetired          -- step 4
  deriving DecidableEq, Repr

/-- One write, applied only when its guard holds; otherwise nothing changes (an error return). -/
def act (p : Params) : Act → St → St
  | .writeBackup, s =>
      if s.phase = none ∧ s.legacy ≠ none ∧ (refSecret p s).isSome = true
      then { s with backup := s.legacy } else s
  | .recBackedUp, s =>
      if s.phase = none ∧ s.legacy ≠ none ∧ s.backup = s.legacy
      then { s with phase := some .backedUp } else s
  | .writeVault, s =>
      if s.phase = some .backedUp ∧ s.legacy ≠ none ∧ s.backup = s.legacy ∧
          (refSecret p s).isSome = true
      then { s with vault := (refSecret p s).map (fun sec => ⟨p.newK, sec, curVer⟩) } else s
  | .recWritten, s =>
      if s.phase = some .backedUp ∧ s.vault ≠ none
      then { s with phase := some .written } else s
  | .recVerified, s =>
      if s.phase = some .written ∧ readBack p s
      then { s with phase := some .verified } else s
  | .deleteLegacy, s =>
      if s.phase = some .verified ∧ s.legacy ≠ none ∧ s.backup = s.legacy ∧ readBack p s
      then { s with legacy := none } else s
  | .recRetired, s =>
      if s.phase = some .verified ∧ s.legacy = none ∧ readBack p s
      then { s with phase := some .retired } else s

def run (p : Params) : List Act → St → St
  | [], s => s
  | a :: as, s => run p as (act p a s)

/-- The state before any migration: a legacy blob, nothing else. -/
def init0 (l : Blob) : St := { legacy := some l, backup := none, vault := none, phase := none }

/-- Reachable by any sequence of actions (interruptions and skipped actions included). -/
inductive Reach (p : Params) (s0 : St) : St → Prop
  | start : Reach p s0 s0
  | step (a : Act) {s : St} : Reach p s0 s → Reach p s0 (act p a s)

/-- As `Reach`, plus the environment replacing, corrupting or deleting the sealed blob at any time. -/
inductive ReachEnv (p : Params) (s0 : St) : St → Prop
  | start : ReachEnv p s0 s0
  | step (a : Act) {s : St} : ReachEnv p s0 s → ReachEnv p s0 (act p a s)
  | corrupt (b : Option Blob) {s : St} : ReachEnv p s0 s → ReachEnv p s0 { s with vault := b }

/-! ## Invariants -/

/-- Facts that hold in every reachable state, with or without a damaged sealed blob. -/
structure Base (p : Params) (l0 : Blob) (s : St) : Prop where
  legacy_is : ∀ l, s.legacy = some l → l = l0
  backup_is : ∀ b, s.backup = some b → b = l0
  recorded_has_backup : s.phase ≠ none → s.backup = some l0
  legacy_gone_only_verified : s.legacy = none → s.phase = some .verified ∨ s.phase = some .retired

/-- `Base` plus the facts about the sealed blob that need it to be untouched by the environment. -/
structure Strong (p : Params) (l0 : Blob) (sec0 : Nat) (s : St) : Prop extends Base p l0 s where
  sealed_present : (s.phase = some .written ∨ s.phase = some .verified ∨ s.phase = some .retired) →
    s.vault ≠ none
  sealed_verified : (s.phase = some .verified ∨ s.phase = some .retired) →
    s.vault.bind (openBlob p.fl p.newK) = some sec0
  sealed_is_ours : ∀ v, s.vault = some v → v = ⟨p.newK, sec0, curVer⟩

theorem ref_eq {p : Params} {l0 : Blob} {sec0 : Nat} {s : St} (hb : Base p l0 s)
    (h0 : legacyOpen p.oldK l0 = some sec0) : refSecret p s = some sec0 := by
  unfold refSecret
  cases hl : s.legacy with
  | some l =>
    have := hb.legacy_is l hl
    subst this
    exact h0
  | none =>
    have hph := hb.legacy_gone_only_verified hl
    have hne : s.phase ≠ none := by
      rcases hph with h | h <;> simp [h]
    have hbk := hb.recorded_has_backup hne
    simp [hbk, h0]

theorem init_base (p : Params) (l0 : Blob) : Base p l0 (init0 l0) := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [init0]

theorem init_strong (p : Params) (l0 : Blob) (sec0 : Nat) : Strong p l0 sec0 (init0 l0) := by
  refine { init_base p l0 with sealed_present := ?_, sealed_verified := ?_, sealed_is_ours := ?_ }
  <;> simp [init0]

theorem act_base {p : Params} {l0 : Blob} (a : Act) {s : St} (hb : Base p l0 s) :
    Base p l0 (act p a s) := by
  cases a <;> simp only [act] <;> split
  · -- writeBackup
    rename_i hg
    refine ⟨hb.legacy_is, ?_, ?_, ?_⟩
    · intro b hbk
      simp only at hbk
      exact hb.legacy_is b hbk
    · intro hne
      have : s.phase ≠ none := hne
      exact absurd hg.1 this
    · intro hn
      exact hb.legacy_gone_only_verified hn
  · exact hb
  · -- recBackedUp
    rename_i hg
    refine ⟨hb.legacy_is, hb.backup_is, ?_, ?_⟩
    · intro _
      simp only
      obtain ⟨_, hl, hbk⟩ := hg
      cases hs : s.legacy with
      | none => exact absurd hs hl
      | some l => rw [hbk, hs, hb.legacy_is l hs]
    · intro hn
      exact absurd hg.1 (by
        have := hb.legacy_gone_only_verified hn
        rcases this with h | h <;> simp [h])
  · exact hb
  · -- writeVault
    rename_i hg
    exact ⟨hb.legacy_is, hb.backup_is, hb.recorded_has_backup, hb.legacy_gone_only_verified⟩
  · exact hb
  · -- recWritten
    rename_i hg
    refine ⟨hb.legacy_is, hb.backup_is, ?_, ?_⟩
    · intro _
      exact hb.recorded_has_backup (by rw [hg.1]; simp)
    · intro hn
      have := hb.legacy_gone_only_verified hn
      rw [hg.1] at this
      simp at this
  · exact hb
  · -- recVerified
    rename_i hg
    refine ⟨hb.legacy_is, hb.backup_is, ?_, ?_⟩
    · intro _
      exact hb.recorded_has_backup (by rw [hg.1]; simp)
    · intro _
      simp
  · exact hb
  · -- deleteLegacy
    rename_i hg
    refine ⟨?_, hb.backup_is, hb.recorded_has_backup, ?_⟩
    · intro l hl
      simp at hl
    · intro _
      left
      exact hg.1
  · exact hb
  · -- recRetired
    rename_i hg
    refine ⟨hb.legacy_is, hb.backup_is, ?_, ?_⟩
    · intro _
      exact hb.recorded_has_backup (by rw [hg.1]; simp)
    · intro _
      simp
  · exact hb


theorem act_strong {p : Params} {l0 : Blob} {sec0 : Nat} (h0 : legacyOpen p.oldK l0 = some sec0)
    (a : Act) {s : St} (hs : Strong p l0 sec0 s) : Strong p l0 sec0 (act p a s) := by
  have hr := ref_eq hs.toBase h0
  have hb := act_base a hs.toBase
  cases a <;> simp only [act] <;> split
  · -- writeBackup
    rename_i hg
    rw [act, if_pos hg] at hb
    exact { toBase := hb, sealed_present := hs.sealed_present,
            sealed_verified := hs.sealed_verified, sealed_is_ours := hs.sealed_is_ours }
  · exact hs
  · -- recBackedUp
    rename_i hg
    rw [act, if_pos hg] at hb
    refine { toBase := hb, sealed_present := ?_, sealed_verified := ?_,
             sealed_is_ours := hs.sealed_is_ours }
    · intro h; simp at h
    · intro h; simp at h
  · exact hs
  · -- writeVault
    rename_i hg
    rw [act, if_pos hg] at hb
    refine { toBase := hb, sealed_present := ?_, sealed_verified := ?_, sealed_is_ours := ?_ }
    · intro _; simp [hr]
    · intro h
      have := hg.1
      simp [this] at h
    · intro v hv
      simp [hr] at hv
      exact hv.symm
  · exact hs
  · -- recWritten
    rename_i hg
    rw [act, if_pos hg] at hb
    refine { toBase := hb, sealed_present := ?_, sealed_verified := ?_,
             sealed_is_ours := hs.sealed_is_ours }
    · intro _; exact hg.2
    · intro h; simp at h
  · exact hs
  · -- recVerified
    rename_i hg
    rw [act, if_pos hg] at hb
    refine { toBase := hb, sealed_present := ?_, sealed_verified := ?_,
             sealed_is_ours := hs.sealed_is_ours }
    · intro _; exact hs.sealed_present (Or.inl hg.1)
    · intro _
      have := hg.2.2
      rw [hr] at this
      exact this
  · exact hs
  · -- deleteLegacy
    rename_i hg
    rw [act, if_pos hg] at hb
    exact { toBase := hb, sealed_present := hs.sealed_present,
            sealed_verified := hs.sealed_verified, sealed_is_ours := hs.sealed_is_ours }
  · exact hs
  · -- recRetired
    rename_i hg
    rw [act, if_pos hg] at hb
    refine { toBase := hb, sealed_present := ?_, sealed_verified := ?_,
             sealed_is_ours := hs.sealed_is_ours }
    · intro _; exact hs.sealed_present (Or.inr (Or.inl hg.1))
    · intro _; exact hs.sealed_verified (Or.inl hg.1)
  · exact hs

theorem reach_strong {p : Params} {l0 : Blob} {sec0 : Nat} (h0 : legacyOpen p.oldK l0 = some sec0)
    {s0 s : St} (hs0 : Strong p l0 sec0 s0) (hr : Reach p s0 s) : Strong p l0 sec0 s := by
  induction hr with
  | start => exact hs0
  | step a _ ih => exact act_strong h0 a ih

theorem reachEnv_base {p : Params} {l0 : Blob} {s0 s : St} (hs0 : Base p l0 s0)
    (hr : ReachEnv p s0 s) : Base p l0 s := by
  induction hr with
  | start => exact hs0
  | step a _ ih => exact act_base a ih
  | corrupt b _ ih =>
    exact ⟨ih.legacy_is, ih.backup_is, ih.recorded_has_backup, ih.legacy_gone_only_verified⟩

/-! ## Headline theorems -/

/-- Something that still decrypts to the original secret under the legacy password:
the legacy blob or the backup. -/
def Recoverable (p : Params) (sec0 : Nat) (s : St) : Prop :=
  ∃ b, (s.legacy = some b ∨ s.backup = some b) ∧ legacyOpen p.oldK b = some sec0

/-- Every reachable state is recoverable, whatever was interrupted, skipped, replayed, and even
if the sealed blob is lost, replaced or corrupted at any point. -/
theorem every_reachable_state_recoverable {p : Params} {l0 : Blob} {sec0 : Nat}
    (h0 : legacyOpen p.oldK l0 = some sec0) {s : St} (hr : ReachEnv p (init0 l0) s) :
    Recoverable p sec0 s := by
  have hb := reachEnv_base (init_base p l0) hr
  cases hl : s.legacy with
  | some l =>
    have := hb.legacy_is l hl
    subst this
    exact ⟨l, Or.inl hl, h0⟩
  | none =>
    have hph := hb.legacy_gone_only_verified hl
    have hne : s.phase ≠ none := by rcases hph with h | h <;> simp [h]
    exact ⟨l0, Or.inr (hb.recorded_has_backup hne), h0⟩

/-- The legacy blob is removed only after the record says `verified`, the backup holds it, and
(when the sealed blob was not touched) the sealed blob read back opens to the original secret. -/
theorem legacy_removed_only_after_verified_readback {p : Params} {l0 : Blob} {sec0 : Nat}
    (h0 : legacyOpen p.oldK l0 = some sec0) {s : St} (hr : Reach p (init0 l0) s)
    (hl : s.legacy = none) :
    (s.phase = some .verified ∨ s.phase = some .retired) ∧ s.backup = some l0 ∧
      s.vault.bind (openBlob p.fl p.newK) = some sec0 := by
  have hs := reach_strong h0 (init_strong p l0 sec0) hr
  have hph := hs.legacy_gone_only_verified hl
  have hne : s.phase ≠ none := by rcases hph with h | h <;> simp [h]
  exact ⟨hph, hs.recorded_has_backup hne, hs.sealed_verified hph⟩

/-- Same without any assumption on the sealed blob: the legacy blob is never gone unless the
backup holds it and the record is past `written`. -/
theorem legacy_removed_implies_backup {p : Params} {l0 : Blob} {s : St}
    (hr : ReachEnv p (init0 l0) s) (hl : s.legacy = none) :
    (s.phase = some .verified ∨ s.phase = some .retired) ∧ s.backup = some l0 := by
  have hb := reachEnv_base (init_base p l0) hr
  have hph := hb.legacy_gone_only_verified hl
  have hne : s.phase ≠ none := by rcases hph with h | h <;> simp [h]
  exact ⟨hph, hb.recorded_has_backup hne⟩

/-- A migration record is only ever written after the backup exists. -/
theorem record_implies_backup {p : Params} {l0 : Blob} {s : St}
    (hr : ReachEnv p (init0 l0) s) (hne : s.phase ≠ none) : s.backup = some l0 :=
  (reachEnv_base (init_base p l0) hr).recorded_has_backup hne

/-! ## Unlock -/

/-- `VaultManager::unlock_source`: the legacy blob until the sealed blob is verified. -/
def useLegacy (s : St) : Prop :=
  s.legacy ≠ none ∧ (s.phase = none ∨ s.phase = some .backedUp ∨ s.phase = some .written)

instance (s : St) : Decidable (useLegacy s) := by unfold useLegacy; infer_instance

/-- `VaultManager::unlock` with the password key `k`. -/
def unlock (p : Params) (k : Nat) (s : St) : Option Nat :=
  if useLegacy s then s.legacy.bind (legacyOpen k) else s.vault.bind (openBlob p.fl k)

/-- Unlock returns a stored secret and only under the key the stored blob was sealed with. -/
theorem unlock_sound {p : Params} {k x : Nat} {s : St} (h : unlock p k s = some x) :
    (∃ l, s.legacy = some l ∧ l.key = k ∧ x = l.secret) ∨
    (∃ v, s.vault = some v ∧ v.key = k ∧ x = v.secret ∧ p.fl ≤ v.ver) := by
  unfold unlock at h
  split at h
  · left
    cases hl : s.legacy with
    | none => simp [hl] at h
    | some l =>
      simp [hl, legacyOpen] at h
      exact ⟨l, rfl, h.1, h.2.symm⟩
  · right
    cases hv : s.vault with
    | none => simp [hv] at h
    | some v =>
      simp only [hv, Option.bind_some] at h
      have := openBlob_some h
      exact ⟨v, rfl, this.1, this.2.1, this.2.2.1⟩

/-- A key that matches no stored blob unlocks nothing. -/
theorem unlock_wrong_key {p : Params} {k : Nat} {s : St}
    (hl : ∀ l, s.legacy = some l → l.key ≠ k) (hv : ∀ v, s.vault = some v → v.key ≠ k) :
    unlock p k s = none := by
  cases h : unlock p k s with
  | none => rfl
  | some x =>
    rcases unlock_sound h with ⟨l, h1, h2, _⟩ | ⟨v, h1, h2, _⟩
    · exact absurd h2 (hl l h1)
    · exact absurd h2 (hv v h1)

/-- In any state reachable by the migration, unlock can only return the original secret:
never anything else, whatever the key. -/
theorem unlock_returns_original {p : Params} {l0 : Blob} {sec0 : Nat}
    (h0 : legacyOpen p.oldK l0 = some sec0) {s : St} (hr : Reach p (init0 l0) s)
    {k x : Nat} (h : unlock p k s = some x) : x = sec0 := by
  have hs := reach_strong h0 (init_strong p l0 sec0) hr
  rcases unlock_sound h with ⟨l, h1, _, h3⟩ | ⟨v, h1, _, h3, _⟩
  · have := hs.legacy_is l h1
    subst this
    simp [legacyOpen] at h0
    rw [h3]; exact h0.2
  · have := hs.sealed_is_ours v h1
    subst this
    exact h3

/-- A sealed blob below the version floor is never unlocked by the sealed path. -/
theorem unlock_sealed_downgrade {p : Params} {k : Nat} {s : St} {v : Blob}
    (hu : ¬ useLegacy s) (hv : s.vault = some v) (hd : v.ver < p.fl) : unlock p k s = none := by
  unfold unlock
  rw [if_neg hu, hv]
  exact downgrade_rejected hd

/-! ## Concrete vectors (mirrored by `tests/vault_migration.rs`, `tests/vault_format.rs`) -/

/-- old password 1, new password 2, floor 1; legacy blob sealed under key 1 holding secret 77. -/
def pp : Params := ⟨1, 2, 1⟩
def lv : Blob := ⟨1, 77, 0⟩

/-- `(legacy, backup, vault, phase)`, the same four facts as `Snapshot` in Rust. -/
def snap (s : St) : Bool × Bool × Bool × Option Phase :=
  (s.legacy.isSome, s.backup.isSome, s.vault.isSome, s.phase)

def steps : List Act :=
  [.writeBackup, .recBackedUp, .writeVault, .recWritten, .recVerified, .deleteLegacy, .recRetired]

/-- Snapshot after the first `n` writes of the migration. The Rust writes 6 and 7 (key-cache
purges) leave the modelled state unchanged. Mirrored by
`tests/vault_migration.rs::interruption_snapshots_match_the_lean_model`. -/
example : snap (init0 lv) = (true, false, false, none) := rfl
example : snap (run pp (steps.take 1) (init0 lv)) = (true, true, false, none) := by decide
example : snap (run pp (steps.take 2) (init0 lv)) = (true, true, false, some .backedUp) := by decide
example : snap (run pp (steps.take 3) (init0 lv)) = (true, true, true, some .backedUp) := by decide
example : snap (run pp (steps.take 4) (init0 lv)) = (true, true, true, some .written) := by decide
example : snap (run pp (steps.take 5) (init0 lv)) = (true, true, true, some .verified) := by decide
example : snap (run pp (steps.take 6) (init0 lv)) = (false, true, true, some .verified) := by decide
example : snap (run pp steps (init0 lv)) = (false, true, true, some .retired) := by decide

/-- The fully migrated state: sealed blob under the new key, backup is the legacy blob. -/
example : run pp steps (init0 lv) =
    { legacy := none, backup := some lv, vault := some ⟨2, 77, 1⟩, phase := some .retired } := by
  decide

/-- Actions out of order change nothing: the legacy blob cannot be deleted early and a phase
cannot be skipped. -/
example : run pp [.deleteLegacy] (init0 lv) = init0 lv := by decide
example : run pp [.recRetired] (init0 lv) = init0 lv := by decide
example : run pp [.recWritten, .recVerified, .deleteLegacy] (init0 lv) = init0 lv := by decide
example : run pp [.writeBackup, .writeVault, .recVerified, .deleteLegacy] (init0 lv) =
    run pp [.writeBackup] (init0 lv) := by decide
/-- Replaying a finished migration is a no-op. -/
example : run pp (steps ++ steps) (init0 lv) = run pp steps (init0 lv) := by decide

/-- Unlock vectors: legacy password before verification, new password after, never the other. -/
example : unlock pp 1 (init0 lv) = some 77 := by decide
example : unlock pp 2 (init0 lv) = none := by decide
example : unlock pp 1 (run pp (steps.take 4) (init0 lv)) = some 77 := by decide
example : unlock pp 2 (run pp (steps.take 4) (init0 lv)) = none := by decide
example : unlock pp 2 (run pp (steps.take 5) (init0 lv)) = some 77 := by decide
example : unlock pp 1 (run pp steps (init0 lv)) = none := by decide
example : unlock pp 2 (run pp steps (init0 lv)) = some 77 := by decide

/-- Version vectors (`format::open`): floor 2 rejects a version-1 blob, versions 0 and 2 are
unknown to this build, a wrong key opens nothing. -/
example : openBlob 1 2 ⟨2, 77, 1⟩ = some 77 := by decide
example : openBlob 2 2 ⟨2, 77, 1⟩ = none := by decide
example : openBlob 1 2 ⟨2, 77, 0⟩ = none := by decide
example : openBlob 1 2 ⟨2, 77, 2⟩ = none := by decide
example : openBlob 1 3 ⟨2, 77, 1⟩ = none := by decide

end TlWalletCore.Vault
