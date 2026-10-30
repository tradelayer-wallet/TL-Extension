/-!
# Signing capability and network resolution

Models `src/capability.rs::authorize_tx` / `authorize_message` and
`src/provider.rs::resolve_network`.

Abstractions: origins, networks, accounts (script), outpoints and scripts are opaque `Nat`s;
amounts are `Nat` (the Rust side uses checked `u64` and refuses on overflow with
`Denied::InvalidAmounts`, a case the unbounded model does not have); the capability is the
transaction-kind variant (the `WrongKind` refusals are a Rust type-tag check).
-/
namespace TlWalletCore

structure In where
  op : Nat
  value : Nat
  deriving Repr, DecidableEq

structure TxOut where
  script : Nat
  value : Nat
  deriving Repr, DecidableEq

/-- Granted by the user-approval UI. -/
structure Cap where
  origin : Nat
  network : Nat
  acctScript : Nat
  expires : Nat
  ins : List In
  outs : List TxOut
  feeBound : Nat

/-- Facts of the request being signed. `reqNetwork` is the provider-resolved network;
`acctNetwork` and `acctScript` identify the signing account; `ins`/`outs` are read from the
PSBT itself. -/
structure Req where
  origin : Nat
  reqNetwork : Nat
  acctNetwork : Nat
  acctScript : Nat
  now : Nat
  ins : List In
  outs : List TxOut

inductive Denied where
  | expired | origin | network | account | duplicate | unapprovedInput | outputs
  | amounts | feeBound
  deriving Repr, DecidableEq

def inValues (l : List In) : Nat := (l.map (·.value)).sum
def outValues' (l : List TxOut) : Nat := (l.map (·.value)).sum

/-- Same check order as `authorize_tx`; returns the implied fee. -/
def authorize (c : Cap) (r : Req) : Except Denied Nat :=
  if c.expires ≤ r.now then .error .expired
  else if r.origin ≠ c.origin then .error .origin
  else if r.reqNetwork ≠ c.network ∨ r.acctNetwork ≠ c.network then .error .network
  else if r.acctScript ≠ c.acctScript then .error .account
  else if ¬ (r.ins.map (·.op)).Nodup then .error .duplicate
  else if ¬ (∀ i ∈ r.ins, i ∈ c.ins) then .error .unapprovedInput
  else if ¬ (r.outs.Perm c.outs) then .error .outputs
  else if outValues' r.outs ≤ inValues r.ins then
    if inValues r.ins - outValues' r.outs ≤ c.feeBound then
      .ok (inValues r.ins - outValues' r.outs)
    else .error .feeBound
  else .error .amounts

/-- Soundness: signing proceeds only when every binding holds. -/
theorem authorize_sound {c : Cap} {r : Req} {fee : Nat} (h : authorize c r = .ok fee) :
    r.now < c.expires ∧
    r.origin = c.origin ∧
    r.reqNetwork = c.network ∧ r.acctNetwork = c.network ∧
    r.acctScript = c.acctScript ∧
    (r.ins.map (·.op)).Nodup ∧
    (∀ i ∈ r.ins, i ∈ c.ins) ∧
    r.outs.Perm c.outs ∧
    inValues r.ins = outValues' r.outs + fee ∧
    fee ≤ c.feeBound := by
  unfold authorize at h
  split at h
  · simp at h
  rename_i h1
  split at h
  · simp at h
  rename_i h2
  split at h
  · simp at h
  rename_i h3
  split at h
  · simp at h
  rename_i h4
  split at h
  · simp at h
  rename_i h5
  split at h
  · simp at h
  rename_i h6
  split at h
  · simp at h
  rename_i h7
  split at h
  · rename_i h8
    split at h
    · rename_i h9
      simp only [Except.ok.injEq] at h
      subst h
      refine ⟨by omega, by simpa using h2, ?_, ?_, by simpa using h4, by simpa using h5,
        by simpa using h6, by simpa using h7, by omega, h9⟩
      · exact Classical.byContradiction fun hc => h3 (Or.inl hc)
      · exact Classical.byContradiction fun hc => h3 (Or.inr hc)
    · simp at h
  · simp at h

/-- Origin binding: a different origin never gets a signature. -/
theorem origin_mismatch_refused (c : Cap) (r : Req) (h : r.origin ≠ c.origin) (fee : Nat) :
    authorize c r ≠ .ok fee := by
  intro hok
  exact h (authorize_sound hok).2.1

/-- Network binding: neither the request network nor the account network may differ. -/
theorem network_mismatch_refused (c : Cap) (r : Req)
    (h : r.reqNetwork ≠ c.network ∨ r.acctNetwork ≠ c.network) (fee : Nat) :
    authorize c r ≠ .ok fee := by
  intro hok
  have s := authorize_sound hok
  rcases h with h | h
  · exact h s.2.2.1
  · exact h s.2.2.2.1

/-- Account binding. -/
theorem account_mismatch_refused (c : Cap) (r : Req) (h : r.acctScript ≠ c.acctScript)
    (fee : Nat) : authorize c r ≠ .ok fee := by
  intro hok
  exact h (authorize_sound hok).2.2.2.2.1

/-- Output binding: one unapproved output is enough to refuse. -/
theorem unapproved_output_refused (c : Cap) (r : Req) (o : TxOut) (ho : o ∈ r.outs)
    (hn : o ∉ c.outs) (fee : Nat) : authorize c r ≠ .ok fee := by
  intro hok
  have hp := (authorize_sound hok).2.2.2.2.2.2.2.1
  exact hn (hp.subset ho)

/-- Approved outputs are never dropped either: the output multiset is exactly the approved one. -/
theorem approved_output_not_dropped (c : Cap) (r : Req) (o : TxOut) (ho : o ∈ c.outs)
    (hn : o ∉ r.outs) (fee : Nat) : authorize c r ≠ .ok fee := by
  intro hok
  have hp := (authorize_sound hok).2.2.2.2.2.2.2.1
  exact hn (hp.symm.subset ho)

/-- Input binding. -/
theorem unapproved_input_refused (c : Cap) (r : Req) (i : In) (hi : i ∈ r.ins)
    (hn : i ∉ c.ins) (fee : Nat) : authorize c r ≠ .ok fee := by
  intro hok
  exact hn ((authorize_sound hok).2.2.2.2.2.2.1 i hi)

/-- Fee bound, stated on the accounting identity of the presented transaction. -/
theorem fee_bounded {c : Cap} {r : Req} {fee : Nat} (h : authorize c r = .ok fee) :
    inValues r.ins = outValues' r.outs + fee ∧ fee ≤ c.feeBound :=
  let s := authorize_sound h
  ⟨s.2.2.2.2.2.2.2.2.1, s.2.2.2.2.2.2.2.2.2⟩

/-- Time binding. -/
theorem expired_refused (c : Cap) (r : Req) (h : c.expires ≤ r.now) (fee : Nat) :
    authorize c r ≠ .ok fee := by
  intro hok
  have := (authorize_sound hok).1
  omega

/-- A capability signs a transaction whose presented outputs are all approved, and the
approved outputs are exactly the presented ones: every presented output pays an approved
destination for an approved amount. -/
theorem all_outputs_approved {c : Cap} {r : Req} {fee : Nat} (h : authorize c r = .ok fee) :
    ∀ o ∈ r.outs, o ∈ c.outs :=
  fun _ ho => ((authorize_sound h).2.2.2.2.2.2.2.1).subset ho

/-! ## Messages: exact bytes (modelled as a `Nat` digest id) -/

structure MsgCap where
  origin : Nat
  network : Nat
  acctScript : Nat
  expires : Nat
  msg : Nat

structure MsgReq where
  origin : Nat
  reqNetwork : Nat
  acctNetwork : Nat
  acctScript : Nat
  now : Nat
  msg : Nat

def authorizeMsg (c : MsgCap) (r : MsgReq) : Bool :=
  decide (r.now < c.expires) && decide (r.origin = c.origin) &&
  decide (r.reqNetwork = c.network) && decide (r.acctNetwork = c.network) &&
  decide (r.acctScript = c.acctScript) && decide (r.msg = c.msg)

theorem authorizeMsg_sound {c : MsgCap} {r : MsgReq} (h : authorizeMsg c r = true) :
    r.now < c.expires ∧ r.origin = c.origin ∧ r.reqNetwork = c.network ∧
    r.acctNetwork = c.network ∧ r.acctScript = c.acctScript ∧ r.msg = c.msg := by
  simp [authorizeMsg] at h
  omega

/-! ## Network resolution (`resolve_network`)

`requested` is the page-supplied (or legacy-bridge preferred) network after parsing; `approved`
is the origin's approval list. -/

inductive NetErr where
  | notApproved | required | originNotApproved
  deriving Repr, DecidableEq

def resolveNetwork (approved : List Nat) (requested : Option Nat) : Except NetErr Nat :=
  match requested with
  | some n => if n ∈ approved then .ok n else .error .notApproved
  | none =>
    match approved with
    | [] => .error .originNotApproved
    | [only] => .ok only
    | _ :: _ :: _ => .error .required

/-- The resolved network is always one the origin approved. -/
theorem resolve_approved {approved : List Nat} {req : Option Nat} {n : Nat}
    (h : resolveNetwork approved req = .ok n) : n ∈ approved := by
  cases req with
  | some m =>
    by_cases hm : m ∈ approved
    · simp [resolveNetwork, hm] at h
      subst h; exact hm
    · simp [resolveNetwork, hm] at h
  | none =>
    cases approved with
    | nil => simp [resolveNetwork] at h
    | cons a rest =>
      cases rest with
      | nil =>
        simp [resolveNetwork] at h
        subst h; simp
      | cons b r => simp [resolveNetwork] at h

/-- No silent switch: if the page named a network, the result is that network or an error. -/
theorem resolve_no_switch {approved : List Nat} {m n : Nat}
    (h : resolveNetwork approved (some m) = .ok n) : n = m := by
  by_cases hm : m ∈ approved
  · simp [resolveNetwork, hm] at h
    omega
  · simp [resolveNetwork, hm] at h

/-- Without a named network the origin must have approved exactly one; several is an error. -/
theorem resolve_none_unique {approved : List Nat} {n : Nat}
    (h : resolveNetwork approved none = .ok n) : approved = [n] := by
  cases approved with
  | nil => simp [resolveNetwork] at h
  | cons a rest =>
    cases rest with
    | nil =>
      simp [resolveNetwork] at h
      simp [h]
    | cons b r => simp [resolveNetwork] at h

/-! ## Concrete vectors mirroring `tests/capability.rs` and `tests/provider.rs` -/

private def cap0 : Cap :=
  { origin := 1, network := 7, acctScript := 42, expires := 1000,
    ins := [{ op := 1, value := 100000 }],
    outs := [{ script := 5, value := 30000 }, { script := 42, value := 60000 }],
    feeBound := 10000 }

private def req0 : Req :=
  { origin := 1, reqNetwork := 7, acctNetwork := 7, acctScript := 42, now := 1,
    ins := [{ op := 1, value := 100000 }],
    outs := [{ script := 42, value := 60000 }, { script := 5, value := 30000 }] }

/-- Same multiset in a different order is the same transaction; fee 10 000. -/
example : authorize cap0 req0 = .ok 10000 := rfl

example : authorize cap0 { req0 with now := 1000 } = .error .expired := rfl
example : authorize cap0 { req0 with origin := 2 } = .error .origin := rfl
example : authorize cap0 { req0 with reqNetwork := 8 } = .error .network := rfl
example : authorize cap0 { req0 with acctScript := 43 } = .error .account := rfl
example : authorize cap0 { req0 with outs := [{ script := 5, value := 30000 }] } =
    .error .outputs := rfl
example : authorize { cap0 with feeBound := 9999 } req0 = .error .feeBound := rfl

example : resolveNetwork [1, 2] none = .error .required := rfl
example : resolveNetwork [1, 2] (some 3) = .error .notApproved := rfl
example : resolveNetwork [1] none = .ok 1 := rfl
example : resolveNetwork [] none = .error .originNotApproved := rfl

end TlWalletCore
