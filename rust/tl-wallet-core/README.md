# tl-wallet-core

Pure, I/O-free wallet logic of the TradeLayer browser extension, ported to Rust with Lean 4
models of the accounting and authorization rules. Part of the Rust migration charter row
"TL-Extension: share pure wallet operations through WASM after vault/network migration review".

Status: offline scaffold. It is not wired into the extension, nothing was signed with a real key,
nothing was broadcast, no endpoint was contacted. Vault encryption and browser storage remain in
JavaScript (see "Not ported").

## Baseline and provenance

| Item | Value |
| --- | --- |
| Repository / branch | `tradelayer-wallet/TL-Extension`, work on `feat/rust-port` |
| Baseline (`main`) | `e16cb4ebabd742cf4dcf47de7ad9f0186adb53cc` (live `main` re-checked, unchanged) |
| `lib/walletUtils.js` | git blob `f72101b4fdb97783c598e1d9899dcad615b4d584` (1,481 lines; vendored `lib/bitcoinjs-lib.js` ignored) |
| `background/background.js` | blob `dadd958b055ad2b663d940b50588d5d4934f63eb` (769 lines) |
| `contentScript.js` | blob `cf4ba6cc876622fbff4e82103669ec1671af7be9` (212 lines) |
| Also read | `components/SeedPhraseImport.js`, `components/SignTransaction.js`, `popup/popup.js` (consumers) |
| Open PR #3 | "Harden seed/key encryption (C1), password checks (M1), network-correct signing (H2), BIP39 import validation (M5)" (open, not merged, not part of the baseline; vault migration is separate work) |

## What is ported

| Rust module | Legacy source | Notes |
| --- | --- | --- |
| `network` | `litecoinNetwork` ... `dogecoinTestnet`, `networkAliases`, `networkPaths` (walletUtils 28-153), `normalizeNetworkId` (background 83) | Explicit `Network` enum; constants copied; per-network dust threshold added |
| `amount` | float `Math.round(amount * 1e8)` | `Sats(u64)`, checked ops, exact decimal parse |
| `address` | `payments.p2wpkh/p2pkh/p2sh/p2wsh`, `address.fromOutputScript` | Encode/validate per explicit network; LTC/DOGE prefixes on top of `bitcoin::base58` and `bech32` |
| `keys` | `generateAddressFromSeed`, `generateMnemonic`, `SeedPhraseImport` | BIP39 import validation, BIP32/84/44 derivation, injected entropy, redacted `Debug`, key erased on drop |
| `coin` | selection in `signTransaction` (989-1002) | Largest-first, checked, fee/dust/bound accounting |
| `tx` | `signTransaction` (build), `buildUnsignedPSBT`, `signInputsInPsbt`, `summarizePsbtForDisplay` | PSBT build, summary, signing p2wpkh / p2pkh (Dogecoin) / p2wsh multisig, finalize/extract |
| `multisig` | `addMultisigAddress`, `getExistingMultisig` | Record computation only (persistence stays in JS) |
| `message` | `signMessage` / `signString` | BIP-137 (see R4) |
| `capability` | none (new) | Signing capability and its authorization predicates |
| `provider`, `origin` | `contentScript.js` gate, `background.js` `PAGE_METHODS`, `isAllowedOrigin`, permissions, account selection, pending registry | Decisions only; no browser APIs |

`signMessage` keeps the page-visible call shape (message in, signature out) but the encoding
changes (BIP-137 base64 65-byte recoverable signature instead of a DER-ish hex of
`sha256(message)`); see R4 and the "versioned protocol change" row.

## Dependencies

* `bitcoin = "0.32"` (resolved in the lockfile: 0.32.102, secp256k1 0.29.1): transaction/PSBT types,
  segwit v0 and legacy sighash, ECDSA/recoverable signing through `secp256k1`, `base58`, `bech32`,
  BIP32. Chosen so no cryptography or consensus encoding is reimplemented.
* `bip39 = "2.2"` (`std` only): word list, checksum and PBKDF2 seed derivation. Cached offline.
* No JSON, HTTP, RNG, clock or threading crates. `tests/hygiene.rs` asserts the library sources
  contain no `std::fs/net/env/thread/process`, clock, RNG, `unsafe`, `unwrap`, `expect` or `panic!`.
* Build is `--locked --offline` from the local cargo cache. Whether those exact registry versions
  resolve on crates.io in CI was not checked from here.

## Compatibility and difference table

Legend: **P** preserved contract, **R** repaired defect, **V** versioned protocol change,
**U** unresolved question. "Already fixed in JS on main?" is for the repaired defects.

| # | Kind | Legacy behaviour (file:line at baseline) | Already fixed in JS on main? | New behaviour | Test |
| --- | --- | --- | --- | --- | --- |
| R1 | R | `signTransaction` pays change to the page-supplied `fromKeyPair.address` (walletUtils.js:1068-1078) | No | Change goes to `Account::change_address()`; `PaymentRequest` has no source-address field. `ChangeMode::SameAsReceive` keeps the legacy intent (own receive address); `InternalChain` uses `.../1/0` | `regression::r1_*`, Lean `planOutputs_destinations` |
| R2 | R | Only `total >= amount` is checked (1000); the fee of 10 000 is subtracted afterwards, so `change` can be negative: no change output is made and the real fee is below the intended 10 000 (down to zero), giving an underfunded or non-relayable transaction (1032-1078) | No | `amount + fee` must be covered, else `InsufficientFunds` | `regression::r2_*`, Lean `select_covers` |
| R3 | R | Missing/NaN `amount` silently becomes 0.0000546 (958-960) | No | Amount is mandatory and must be at least the network dust | `regression::r3_*` |
| R4 | R | `signMessage` signs `sha256(message)` with no prefix (225-229, 860-883): a page can obtain a signature over a chosen 32-byte hash, i.e. a transaction-signing oracle | No | BIP-137: `sha256d(varint(len(magic)) magic varint(len(msg)) msg)`, recoverable compact signature, header 39..42 (p2wpkh) / 31..34 (p2pkh), base64. Per-network magic from the legacy `messagePrefix`. Only via a message capability bound to the exact bytes. Known answer cross-checked with Bitcoin Core 31.1 `signmessagewithprivkey`/`verifymessage` | `regression::r4_*`, `address_message::bip137_known_answer_against_bitcoin_core` |
| R5 | R | Network silently switches: `normalizeNetwork` falls back to LTC (176-188), `resolveNetwork(undefined)` to LTCTEST (123-126), `tryPayment` retries an address on an alternate network (1036-1046), `normalizeNetworkId(null)` returns LTC (background 83-93), `approvedNetworks[0]` when the page names none (background 256-260), `getPreferredLegacyNetwork` ends in `'LTC'` (289-310), `connect` defaults a missing network to LTC (467-468) | Partly: `resolveApprovedNetwork` checks that a *named* network was approved | `Network` is always passed explicitly; unknown labels are errors; an address is valid only for the network the caller names; with several approved networks the page must name one; the signing capability binds origin, network and account and refuses on any mismatch | `regression::r5_*`, `provider::*`, `capability::every_mismatch_is_denied`, Lean `network_mismatch_refused`, `resolve_no_switch` |
| R5b | U | Base58 prefixes collide across chains (BTCTEST/LTCTEST p2pkh `0x6f`, BTCTEST/DOGETEST p2sh `0xc4`) so a string cannot identify its network | n/a | Documented and tested: network is never inferred from an address | `regression::r5b_*` |
| R6 | R | Page-supplied UTXOs (script and amount) are added to the PSBT with no ownership check; a foreign script only fails late inside bitcoinjs signing, and the page-chosen amounts drive the selection (1008-1026) | No | Candidate UTXOs must be the account's own scripts, refused up front; signing signs only owned inputs | `regression::r6_*` |
| R7 | R | Dust change is emitted (1076) | No | Change below the network dust threshold is folded into the fee and the result must still respect the explicit fee bound | `regression::r7_*`, Lean `select_no_dust_change`, `select_fee_bounded` |
| R8 | R | `patchPsbtForMultisig` overwrites `witnessUtxo.script` of a supplied PSBT (1377-1392) and the relayer witness script is trusted | No | Prevout data is never rewritten; a witness script is used only if it hashes to the existing prevout script | `regression::r8_*` |
| R9 | R | Display fee `Math.max(in - out, 0)` and unknown input values count as 0 (1468-1480) | No | Unknown input amount gives `fee: None`; outputs above inputs is an error | `regression::r9_*` |
| R10 | R | Seed import joins 12 free-text boxes with no word-list or checksum check (SeedPhraseImport.js; `bip39.mnemonicToSeedSync` does not validate) | Only in open PR #3 | Exactly 12 single-token words, English list, valid checksum | `regression::r10_*` |
| R11 | R | Float arithmetic on amounts (`Math.round(x * 1e8)`) | No | Exact decimal strings to `u64` sats, 8 decimals max | `regression::r11_*` |
| R12 | R | OP_RETURN payload length unbounded (1081-1085) | No | At most 80 bytes; empty payload means no output (legacy falsy check) | `regression::r12_*` |
| P4 | P | bitcoinjs `signInput` defaults to `SIGHASH_ALL` only | n/a | Only `SIGHASH_ALL` is signed; a PSBT input asking for another flag is refused | `capability::non_all_sighash_requests_are_refused` |
| R14 | R | Account lists infer a network from the address prefix (`inferNetworkFromAddress`, background 197-205; popup.js 56-63), defaulting unknowns to LTC | No | Only explicitly labelled records are used and each address must validate for that network | `provider::account_selection_uses_explicit_labels_only` |
| R15 | R | `signTransaction` builds p2wpkh payments and `witnessUtxo` inputs for every network, which cannot work for Dogecoin p2pkh (and legacy sighash does not commit to amounts) | No | Dogecoin spends are supported: p2pkh inputs require the full previous transaction, checked against txid, script and value | `capability::dogecoin_*` |
| P1 | P | Method allow-list, `signPSBT` alias, id rules (string or number for the legacy bridge, string otherwise), exact origin allow-list (3 https origins; loopback http only with the development flag), per-origin approved networks, popup-only message names, bounded pending registry | n/a | Same decisions, with typed errors and size bounds (message 64 KiB, PSBT hex 4 MiB, 15 multisig keys, 32 pending, id 128 chars) | `provider::*` |
| P2 | P | Derivation paths `m/84'/{2,1,0,1}'/0'/0/0`, `m/44'/{3,1}'/0'/0/0`; p2wpkh for BTC/LTC, p2pkh for DOGE; network constants | n/a | Identical; checked against `walletUtils.js` constants and bitcoinjs output | `legacy_parity::*` |
| P3 | P | Output order recipient, change, OP_RETURN; tx version 2; sequence `0xffffffff`; locktime 0; SIGHASH_ALL; fixed 10 000 sat fee as the default policy | n/a | Same bytes for the same inputs (unsigned tx and BIP143 sighash equal bitcoinjs) | `legacy_parity::unsigned_tx_and_sighash_match_bitcoinjs` |
| V1 | V | `signMessage` result format | n/a | BIP-137 base64 signatures replace the legacy encoding; consumers must adopt the new format (activation is a JS/UI decision) | |
| V2 | V | Multisig keys must be 33-byte compressed, distinct, `1 <= m <= n <= 15` (legacy only checked `n >= m`) | n/a | Stricter | `address_message::multisig_record_validation` |
| U1 | U | Dust thresholds: LTC 5 460 (the legacy default amount), BTC 546, DOGE 100 000 000 are choices of this port, not copied from a node policy | | Per-network constant in `NetworkParams` | |
| U2 | U | Dogecoin transactions use version 2 as legacy bitcoinjs did; standardness on Dogecoin Core was not checked | | Unchanged | |
| U3 | U | `MAINNET`/`TESTNET` mean LTC/LTCTEST in legacy; they are ambiguous in a multi-chain wallet | | Accepted only for the legacy bridge (`Network::parse_legacy_generic`) | `provider::connect_*` |
| U4 | U | Taproot / witness v1 destinations and multisig other than P2WSH bare m-of-n are not supported | | Typed `UnsupportedAddress` | |

Already fixed on `main` before this port (no action, noted for the record): the provider layer
requires an approved origin and an approved network for named networks, `ALLOW_DEVELOPMENT_ORIGINS`
is off, popup-only messages are sender-checked (commit `e16cb4e`).

## Signing capability

`SigningCapability` binds: origin, network, account (`AccountId` = network + receive script), an
expiry on an injected clock, and either the exact message bytes or the exact approved inputs
(outpoint + amount), approved outputs (script + amount, compared as a multiset) and a fee bound.
`sign_psbt` and `sign_message` take the capability by value (single use), re-derive inputs,
outputs and the fee from the PSBT itself, call `authorize_tx` / `authorize_message`, and only then
reach the crate-private signing code. The Rust predicates and their Lean model:

`authorize_tx` succeeds only if `now < expires`, origin equal, request network equal and account
network equal to the approved network, account equal, no duplicate outpoints, every input
approved, output multiset equal to the approved multiset, `sum(inputs) >= sum(outputs)`, and
`fee = sum(inputs) - sum(outputs) <= fee_bound`.

Granting a capability is the act of user approval: only the approval UI may call
`SigningCapability::for_*`. The crate cannot enforce that boundary by type; the JS/WASM binding
must expose only "approve request id N" and never the constructor to page-reachable code.

## Commands

From a Git Bash with WSL (paths as in the shared tooling):

```
TOOLS=/mnt/c/Users/patri/Documents/Codex/2026-10-30/new-chat/work/tools
C=C:/Users/patri/Documents/Codex/2026-10-30/new-chat/work/repos/TL-Extension/rust/tl-wallet-core
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash $TOOLS/rust.sh $C test --locked --offline
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash $TOOLS/rust.sh $C clippy --locked --offline --all-targets -- -D warnings
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash $TOOLS/rust.sh $C fmt --all -- --check
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash $TOOLS/lean.sh $C/lean       # prints LEAN_CHECK_OK
```

Plain cargo: `cd rust/tl-wallet-core && cargo test --locked`.

Legacy parity vectors (Node, no npm install; reads `lib/walletUtils.js` as text and `require`s only
the committed `dist/bitcoinjs.js` bundle):

```
node scripts/compare-legacy.cjs           # rewrite tests/fixtures/legacy_vectors.txt
node scripts/compare-legacy.cjs --check   # fail if the legacy code no longer produces the committed vectors
```

The script refuses to run if `lib/walletUtils.js` is not the pinned blob. Fixtures use only
public test keys (the BIP39 `abandon ... about` mnemonic, the secp256k1 generator multiples).

`examples/probe.rs` prints the inputs used for the Bitcoin Core known-answer check.

## Lean 4 (`lean/`, Lean v4.34.1, core only, no Mathlib)

`TlWalletCore/Coin.lean` models `coin::select_largest_first` (after sorting) as `select` and the
output layout of `tx::build_payment` as `planOutputs`. `TlWalletCore/Capability.lean` models
`capability::authorize_tx` as `authorize`, `authorize_message` as `authorizeMsg`, and
`provider::resolve_network` as `resolveNetwork`.

Theorems (all checked, axioms limited to `propext`, `Classical.choice`, `Quot.sound` by `AxiomCheck.lean`):

* Coin: `finish_spec`, `selectAux_spec`, `select_conserves` (`sum(inputs) = target + change + fee`),
  `select_fee_bounded` (`fee <= max_fee`), `select_no_dust_change` (`change = 0 or dust <= change`),
  `select_fee_floor`, `select_covers` (`target + policy fee <= inputs`), `select_prefix` (largest-first,
  nothing skipped), `planOutputs_sum`, `planOutputs_destinations` (every output is the recipient,
  the payload, or the wallet-owned change script), `payment_balances` (`inputs = outputs + fee`).
* Capability: `authorize_sound` (success implies every binding holds), `origin_mismatch_refused`,
  `network_mismatch_refused`, `account_mismatch_refused`, `unapproved_output_refused`,
  `approved_output_not_dropped`, `unapproved_input_refused`, `fee_bounded`, `expired_refused`,
  `all_outputs_approved`, `authorizeMsg_sound`.
* Network: `resolve_approved`, `resolve_no_switch`, `resolve_none_unique`.

Concrete `example ... := rfl` vectors in both files are the same cases that `tests/coin.rs`
(`lean_model_vectors`, `boundaries`), `tests/capability.rs` (`every_mismatch_is_denied`) and
`tests/provider.rs` assert in Rust.

Where the model abstracts: money is `Nat` (Rust uses checked `u64`; overflow is an error in Rust
and absent in the model); the stable sort and the outpoint/script bytes are not modelled
(opaque `Nat`s); the PSBT parsing that produces the presented inputs/outputs is outside the model;
signing itself (ECDSA, sighash) is not modelled. The proofs are about the decision logic, not about
the cryptography.

## Not ported (and why)

* Vault: CryptoJS AES encryption of seed and keys, password prompts and `checkPasswordMatch`
  (a stub returning `true` in legacy), `getOrDeriveKeyPair` caching in `localStorage`,
  `clearPrivateKeyCaches`. Vault migration needs backup, atomic writes, wrong-password/tamper tests
  and a recovery drill with synthetic keys; open PR #3 touches this.
* Browser storage and messaging: `chrome.storage`, `localStorage`, popup windows, runtime messages,
  `window.js`, React components.
* Network I/O: `fetchUTXOs`, `broadcastTransaction`, `sendBTC` (BlockCypher), `buildPsbtLocally`
  (dead code in legacy; its fee check is the same defect as R2 and the new path replaces it).
* `generateLitecoinAddress`, `encodeSignature`, `signString` (replaced by BIP-137), the commented
  `generateAddressesFromSeed` multi-address scan, `decryptPrivateKey`, `hashMessage`.
* Taproot, witness versions above 0, non-P2WSH scripts, BIP32 xpub/xprv serialization with the
  per-network version bytes (the constants are carried in `NetworkParams` but unused).

## Remaining gaps (honest list)

* `wasm32-unknown-unknown` build was **not** run: the target is not installed in the offline
  toolchain. The library avoids std I/O/clock/thread/RNG (`tests/hygiene.rs`), but `secp256k1-sys`
  needs a C toolchain for wasm32 and that was not exercised. No `wasm-bindgen` layer exists.
* CI workflow `.github/workflows/rust-tl-wallet-core.yml` has not run (nothing was pushed). Its Node
  parity step and the Lean job are untested in GitHub's environment.
* Multisig finalize assumes bare m-of-n P2WSH with keys in script order; signatures from the
  account's receive key only. Hardware/other signer shapes, SIGHASH variants, RBF/locktime policy and
  fee estimation from real vsizes beyond the `FeePolicy::PerVbyte` helper are not covered.
* No fuzzing. Property coverage is the deterministic sweep in `tests/coin.rs` (3 000 cases) and the
  Lean theorems; parity covers the vectors in `tests/fixtures/legacy_vectors.txt` only.
* The Lean model proves decision logic, not equivalence of the Rust code to the model; the
  correspondence is by construction plus the shared vectors.
* No consumer was changed: wiring into `background.js` / `walletUtils.js` is a later task and
  depends on the vault migration and on adopting the BIP-137 format (V1).

## WASM

Verified 2026-10-30 (Rust 1.90.0, `wasm32-unknown-unknown`, clang 18 for libsecp256k1):
`cargo build --locked --lib --target wasm32-unknown-unknown` succeeds, and
`wasm-smoke/` (a raw-ABI `cdylib`, 208,343 bytes in release) runs under Node's
WebAssembly host: `node wasm-smoke/scripts/wasm-smoke.mjs <wasm>` prints
`WASM_SMOKE_OK` after checking address validation (valid, uppercase, mixed case, bad
checksum, wrong network, unknown network) and BIP-39 phrases for zero and `0xff`
entropy against the native test vectors. The smoke ABI is for verification only; an
extension binding still needs a reviewed generator and secret-zeroizing buffers.
