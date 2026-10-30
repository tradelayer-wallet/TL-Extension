/-!
# Coin selection and fee/change accounting

Model of `src/coin.rs::select_largest_first` (after the deterministic sort) and of the output
layout produced by `src/tx.rs::build_payment`.

Abstractions: money is `Nat` (Rust uses checked `u64`, where overflow is an error, so the Rust
function only returns a value in the cases the model covers); inputs are represented by their
values; `feeFor n` is the fee as a function of the number of selected inputs (`FeePolicy`);
the sort itself is not modelled (selection starts from the already-sorted value list).
-/
namespace TlWalletCore

inductive SelErr where
  | insufficient
  | feeAboveBound
  deriving Repr, DecidableEq

structure Selection where
  selected : List Nat
  totalIn : Nat
  change : Nat
  fee : Nat
  deriving Repr, DecidableEq

/-- The branch taken once `taken` (summing to `total`) covers `target + fee`: keep the change if
it is at least `dust`, otherwise fold it into the fee; refuse if the fee would exceed the bound. -/
def finish (target maxFee dust fee total : Nat) (taken : List Nat) : Except SelErr Selection :=
  if dust ≤ total - (target + fee) then
    if fee ≤ maxFee then
      .ok { selected := taken, totalIn := total, change := total - (target + fee), fee := fee }
    else .error .feeAboveBound
  else
    if fee + (total - (target + fee)) ≤ maxFee then
      .ok { selected := taken, totalIn := total, change := 0,
            fee := fee + (total - (target + fee)) }
    else .error .feeAboveBound

/-- `taken` are the values chosen so far (in order), `total` their sum. Mirrors the Rust loop:
add the next value, recompute the fee for the new input count, stop when covered. -/
def selectAux (target maxFee dust : Nat) (feeFor : Nat → Nat) :
    List Nat → List Nat → Nat → Except SelErr Selection
  | [], _, _ => .error .insufficient
  | v :: rest, taken, total =>
    if target + feeFor (taken.length + 1) ≤ total + v then
      finish target maxFee dust (feeFor (taken.length + 1)) (total + v) (taken ++ [v])
    else selectAux target maxFee dust feeFor rest (taken ++ [v]) (total + v)

/-- `select_largest_first` on an already sorted (descending) list of values. -/
def select (target maxFee dust : Nat) (feeFor : Nat → Nat) (sorted : List Nat) :
    Except SelErr Selection :=
  selectAux target maxFee dust feeFor sorted [] 0

theorem finish_spec {target maxFee dust fee total : Nat} {taken : List Nat} {s : Selection}
    (hcov : target + fee ≤ total) (h : finish target maxFee dust fee total taken = .ok s) :
    s.selected = taken ∧ s.totalIn = total ∧ s.totalIn = target + s.change + s.fee ∧
    s.fee ≤ maxFee ∧ (s.change = 0 ∨ dust ≤ s.change) ∧ fee ≤ s.fee := by
  unfold finish at h
  split at h
  · rename_i hd
    split at h
    · rename_i hf
      simp only [Except.ok.injEq] at h
      subst h
      refine ⟨rfl, rfl, ?_, hf, Or.inr hd, Nat.le_refl _⟩
      show total = target + (total - (target + fee)) + fee
      omega
    · simp at h
  · rename_i hd
    split at h
    · rename_i hf
      simp only [Except.ok.injEq] at h
      subst h
      refine ⟨rfl, rfl, ?_, hf, Or.inl rfl, ?_⟩
      · show total = target + 0 + (fee + (total - (target + fee)))
        omega
      · show fee ≤ fee + (total - (target + fee))
        omega
    · simp at h

/-- Every success of `selectAux` satisfies the accounting invariants, given that the running
total really is the sum of `taken`. -/
theorem selectAux_spec (target maxFee dust : Nat) (feeFor : Nat → Nat) :
    ∀ (l taken : List Nat) (total : Nat) (s : Selection),
      total = taken.sum →
      selectAux target maxFee dust feeFor l taken total = .ok s →
      s.selected.sum = s.totalIn ∧
      s.totalIn = target + s.change + s.fee ∧
      s.fee ≤ maxFee ∧
      (s.change = 0 ∨ dust ≤ s.change) ∧
      feeFor s.selected.length ≤ s.fee ∧
      s.selected <+: taken ++ l := by
  intro l
  induction l with
  | nil =>
    intro taken total s _ h
    simp [selectAux] at h
  | cons v rest ih =>
    intro taken total s htot h
    simp only [selectAux] at h
    split at h
    · rename_i hcov
      obtain ⟨e1, e2, e3, e4, e5, e6⟩ := finish_spec hcov h
      have hsum : (taken ++ [v]).sum = total + v := by
        simp [List.sum_append, htot]
      have hlen : s.selected.length = taken.length + 1 := by
        rw [e1]; simp
      refine ⟨?_, e3, e4, e5, ?_, ?_⟩
      · rw [e1, e2]; exact hsum
      · rw [hlen]; exact e6
      · rw [e1]; exact ⟨rest, by simp⟩
    · have hsum : total + v = (taken ++ [v]).sum := by
        simp [List.sum_append, htot]
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ih (taken ++ [v]) (total + v) s hsum h
      refine ⟨h1, h2, h3, h4, h5, ?_⟩
      simpa [List.append_assoc] using h6

/-- Value conservation: `sum(inputs) = target + change + fee`. -/
theorem select_conserves {target maxFee dust : Nat} {feeFor : Nat → Nat}
    {sorted : List Nat} {s : Selection}
    (h : select target maxFee dust feeFor sorted = .ok s) :
    s.totalIn = target + s.change + s.fee ∧ s.selected.sum = s.totalIn :=
  let r := selectAux_spec target maxFee dust feeFor sorted [] 0 s (by simp) h
  ⟨r.2.1, r.1⟩

/-- The fee never exceeds the explicit bound. -/
theorem select_fee_bounded {target maxFee dust : Nat} {feeFor : Nat → Nat}
    {sorted : List Nat} {s : Selection}
    (h : select target maxFee dust feeFor sorted = .ok s) : s.fee ≤ maxFee :=
  (selectAux_spec target maxFee dust feeFor sorted [] 0 s (by simp) h).2.2.1

/-- No dust change: the change is zero or at least the dust threshold. -/
theorem select_no_dust_change {target maxFee dust : Nat} {feeFor : Nat → Nat}
    {sorted : List Nat} {s : Selection}
    (h : select target maxFee dust feeFor sorted = .ok s) :
    s.change = 0 ∨ dust ≤ s.change :=
  (selectAux_spec target maxFee dust feeFor sorted [] 0 s (by simp) h).2.2.2.1

/-- The fee covers at least the policy fee for the chosen inputs (it can only grow by absorbing
sub-dust change). -/
theorem select_fee_floor {target maxFee dust : Nat} {feeFor : Nat → Nat}
    {sorted : List Nat} {s : Selection}
    (h : select target maxFee dust feeFor sorted = .ok s) :
    feeFor s.selected.length ≤ s.fee :=
  (selectAux_spec target maxFee dust feeFor sorted [] 0 s (by simp) h).2.2.2.2.1

/-- The chosen inputs are a prefix of the sorted candidates (largest first, nothing skipped). -/
theorem select_prefix {target maxFee dust : Nat} {feeFor : Nat → Nat}
    {sorted : List Nat} {s : Selection}
    (h : select target maxFee dust feeFor sorted = .ok s) : s.selected <+: sorted := by
  have r := (selectAux_spec target maxFee dust feeFor sorted [] 0 s (by simp) h).2.2.2.2.2
  simpa using r

/-- The selection pays at least `target + policy fee`. -/
theorem select_covers {target maxFee dust : Nat} {feeFor : Nat → Nat}
    {sorted : List Nat} {s : Selection}
    (h : select target maxFee dust feeFor sorted = .ok s) :
    target + feeFor s.selected.length ≤ s.totalIn := by
  have c := select_conserves h
  have f := select_fee_floor h
  omega

/-! ## Output layout of `build_payment`

Outputs are `recipient`, then the wallet-owned change output when the change is positive, then
the optional zero-value payload output. The change script is a field of the *wallet account*;
the request type carries no source address, so nothing a page sends can redirect change.
-/

structure Out where
  script : Nat
  value : Nat
  deriving Repr, DecidableEq

structure AccountModel where
  changeScript : Nat

structure PayRequest where
  toScript : Nat
  amount : Nat
  payloadScript : Option Nat

def planOutputs (acct : AccountModel) (req : PayRequest) (change : Nat) : List Out :=
  [{ script := req.toScript, value := req.amount }]
    ++ (if 0 < change then [{ script := acct.changeScript, value := change }] else [])
    ++ (match req.payloadScript with
        | some p => [{ script := p, value := 0 }]
        | none => [])

def outValues (os : List Out) : Nat := (os.map (·.value)).sum

/-- Output values add up to `amount + change`; together with `select_conserves` this gives
`sum(inputs) = sum(outputs) + fee`. -/
theorem planOutputs_sum (acct : AccountModel) (req : PayRequest) (change : Nat) :
    outValues (planOutputs acct req change) = req.amount + change := by
  unfold planOutputs outValues
  cases hp : req.payloadScript <;> by_cases hc : 0 < change <;> simp [hc] <;> omega

/-- Change safety: every output is either the recipient output, the payload output, or pays
the wallet-owned change script. No other destination can appear. -/
theorem planOutputs_destinations (acct : AccountModel) (req : PayRequest) (change : Nat) :
    ∀ o ∈ planOutputs acct req change,
      o.script = req.toScript ∨ o.script = acct.changeScript ∨
        req.payloadScript = some o.script := by
  intro o ho
  unfold planOutputs at ho
  cases hp : req.payloadScript with
  | none =>
    by_cases hc : 0 < change
    · simp [hc, hp] at ho
      rcases ho with ho | ho <;> subst ho <;> simp
    · simp [hc, hp] at ho
      subst ho; simp
  | some p =>
    by_cases hc : 0 < change
    · simp [hc, hp] at ho
      rcases ho with ho | ho | ho <;> subst ho <;> simp
    · simp [hc, hp] at ho
      rcases ho with ho | ho <;> subst ho <;> simp

/-- Combined accounting for a built payment: inputs equal outputs plus fee. -/
theorem payment_balances {maxFee dust : Nat} {feeFor : Nat → Nat} {sorted : List Nat}
    {s : Selection} (acct : AccountModel) (req : PayRequest)
    (h : select req.amount maxFee dust feeFor sorted = .ok s) :
    s.totalIn = outValues (planOutputs acct req s.change) + s.fee := by
  have c := select_conserves h
  rw [planOutputs_sum]
  omega

/-! ## Concrete vectors (the same cases asserted by `tests/coin.rs` and `tests/capability.rs`) -/

/-- Two inputs 60 000 and 50 000, target 80 000, fixed fee 10 000: both inputs, change 20 000. -/
example : select 80000 10000 5460 (fun _ => 10000) [60000, 50000] =
    .ok { selected := [60000, 50000], totalIn := 110000, change := 20000, fee := 10000 } := rfl

/-- Exactly amount + fee: no change. -/
example : select 30000 100000 5460 (fun _ => 10000) [40000] =
    .ok { selected := [40000], totalIn := 40000, change := 0, fee := 10000 } := rfl

/-- One satoshi short: insufficient. -/
example : select 30000 100000 5460 (fun _ => 10000) [39999] = .error .insufficient := rfl

/-- Change exactly at the dust threshold is kept. -/
example : select 30000 100000 5460 (fun _ => 10000) [45460] =
    .ok { selected := [45460], totalIn := 45460, change := 5460, fee := 10000 } := rfl

/-- One below the dust threshold: folded into the fee. -/
example : select 30000 100000 5460 (fun _ => 10000) [45459] =
    .ok { selected := [45459], totalIn := 45459, change := 0, fee := 15459 } := rfl

/-- Folding that exceeds the fee bound is refused. -/
example : select 30000 12000 5460 (fun _ => 10000) [45459] = .error .feeAboveBound := rfl

end TlWalletCore
