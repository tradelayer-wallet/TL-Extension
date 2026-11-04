# tl-wallet-core

Pure, I/O-free wallet logic of the TradeLayer browser extension, ported to Rust with Lean 4
models of the accounting and authorization rules. Part of the Rust migration charter row
"TL-Extension: share pure wallet operations through WASM after vault/network migration review".

Status: library and test suite; `../tl-extension-app` wires the vault, unlock and signing into the
extension's original popup through WebAssembly (milestone 1). Nothing was signed with a real key,
nothing was broadcast, no endpoint was contacted. The vault (legacy import, sealed format,
migration state machine) is ported behind storage and randomness traits; the browser storage
adapter and the UI stay in JavaScript (see "Vault" and "Not ported").

## Baseline and provenance

| Item | Value |
| --- | --- |
| Repository / branch | `tradelayer-wallet/TL-Extension`, work on `feat/rust-port` |
| Baseline (`main`) | `e16cb4ebabd742cf4dcf47de7ad9f0186adb53cc` (live `main` re-checked, unchanged) |
| `lib/walletUtils.js` | git blob `f72101b4fdb97783c598e1d9899dcad615b4d584` (1,481 lines; vendored `lib/bitcoinjs-lib.js` ignored) |
| `background/background.js` | blob `dadd958b055ad2b663d940b50588d5d4934f63eb` (769 lines) |
| `contentScript.js` | blob `cf4ba6cc876622fbff4e82103669ec1671af7be9` (212 lines) |
| Also read | `components/SeedPhraseImport.js`, `components/SignTransaction.js`, `popup/popup.js` (consumers) |
| Vault sources (same baseline content at `c8c2da4`) | `components/PasswordSetup.js` blob `52d4b5566119fb6af602e738efb5e5d48e7d8192`, `PasswordPrompt.js` `8877959cd214574bc1517d9eef8ee2225ec8dca4`, `ExposeSeed.js` `406e876680a9181cf6812836145dad04c7d6844c`, `ResetPass.js` `9ef7cb17ad0b198a23952ba18ff8039612f9545a`, `DelegatedSigner.js` `384fa100b103cb75e156b5f228bbb945c145656e`; `lib/walletUtils.js` as above; `components/Send.js` (caller of `checkPasswordMatch`) |
| Legacy cipher library | `crypto-js` 4.2.0 (`package-lock.json`, integrity `sha512-KALDyEYg...`); parity ciphertexts come from that exact version |
| Open PR #3 | "Harden seed/key encryption (C1), password checks (M1), network-correct signing (H2), BIP39 import validation (M5)" (open, not merged, not part of the baseline; vault migration is separate work) |

## What is ported

| Rust module | Legacy source | Notes |
| --- | --- | --- |
| `network` | `litecoinNetwork` ... `dogecoinTestnet`, `networkAliases`, `networkPaths` (walletUtils 28-153), `normalizeNetworkId` (background 83) | Explicit `Network` enum; constants copied; per-network dust threshold added. Two non-legacy ids, `BTCREGTEST` (`bcrt`) and `LTCREGTEST` (`rltc`), reuse the testnet key versions and paths for local regtest chains; they are outside `Network::ALL` (`Network::REGTEST`), tested in `tests/regtest_network.rs` |
| `amount` | float `Math.round(amount * 1e8)` | `Sats(u64)`, checked ops, exact decimal parse |
| `address` | `payments.p2wpkh/p2pkh/p2sh/p2wsh`, `address.fromOutputScript` | Encode/validate per explicit network; LTC/DOGE prefixes on top of `bitcoin::base58` and `bech32` |
| `keys` | `generateAddressFromSeed`, `generateMnemonic`, `SeedPhraseImport` | BIP39 import validation, BIP32/84/44 derivation, injected entropy, redacted `Debug`, key erased on drop |
| `coin` | selection in `signTransaction` (989-1002) | Largest-first, checked, fee/dust/bound accounting |
| `tx` | `signTransaction` (build), `buildUnsignedPSBT`, `signInputsInPsbt`, `summarizePsbtForDisplay` | PSBT build, summary, signing p2wpkh / p2pkh (Dogecoin) / p2wsh multisig, finalize/extract |
| `multisig` | `addMultisigAddress`, `getExistingMultisig` | Record computation only (persistence stays in JS) |
| `message` | `signMessage` / `signString` | BIP-137 (see R4) |
| `capability` | none (new) | Signing capability and its authorization predicates |
| `provider`, `origin` | `contentScript.js` gate, `background.js` `PAGE_METHODS`, `isAllowedOrigin`, permissions, account selection, pending registry | Decisions only; no browser APIs |
| `vault::legacy` | `CryptoJS.AES.encrypt(text, password)` in `PasswordSetup.js:34`, `ResetPass.js:44`, `walletUtils.js:332`; decrypts in `generateAddressFromSeed` (261), `ExposeSeed.js:28`, `ResetPass.js:35`, `walletUtils.js:869,963,1175`; DelegatedSigner PBKDF2 key | Import only: OpenSSL `Salted__` + EVP_BytesToKey(MD5, 1 iteration) + AES-256-CBC, byte-exact against crypto-js 4.2.0 |
| `vault::format` | none (new) | Versioned sealed blob: scrypt or PBKDF2-SHA256, XChaCha20-Poly1305, header as AAD |
| `vault::manager` | `PasswordSetup`, `PasswordPrompt` (unlock part), `ExposeSeed`, `ResetPass`, `checkPasswordMatch`, `getOrDeriveKeyPair`, `clearPrivateKeyCaches` | Create, unlock, migrate legacy -> sealed (state machine), change password, recover from backup, real password check |
| `vault::store` | `localStorage` / `chrome.storage.local` use | `VaultStore` (get / compare-and-swap / keys) and `Random` traits, `MemoryStore`, test-only `CounterRandom` |

`signMessage` keeps the page-visible call shape (message in, signature out) but the encoding
changes (BIP-137 base64 65-byte recoverable signature instead of a DER-ish hex of
`sha256(message)`); see R4 and the "versioned protocol change" row.

## Dependencies

* `bitcoin = "0.32"` (resolved in the lockfile: 0.32.102, secp256k1 0.29.1): transaction/PSBT types,
  segwit v0 and legacy sighash, ECDSA/recoverable signing through `secp256k1`, `base58`, `bech32`,
  BIP32. Chosen so no cryptography or consensus encoding is reimplemented.
* `bip39 = "2.2"` (`std` only): word list, checksum and PBKDF2 seed derivation. Cached offline.
* Vault dependencies, all RustCrypto, all already in the offline cargo cache (`--locked --offline`
  works), none hand-rolled:
  * `aes 0.8` + `cbc 0.1`: AES-256-CBC with checked PKCS#7 unpadding, needed only to read legacy blobs.
  * `md-5 0.10`: the MD5 inside OpenSSL `EVP_BytesToKey`, needed only to read legacy blobs (MD5 is
    never used for anything new).
  * `sha2 0.10` + `pbkdf2 0.12` (feature `hmac` only): PBKDF2-HMAC-SHA256 for the sealed format
    option and for the DelegatedSigner key derivation check; SHA-256 for the migration fingerprint.
  * `scrypt 0.11` (no default features, raw `scrypt()` function): the default memory-hard KDF.
  * `chacha20poly1305 0.10` (`alloc`): XChaCha20-Poly1305 AEAD (24-byte nonce, pure software,
    constant time, no AES-NI dependency in WASM).
  * `zeroize 1`: `Zeroizing` buffers for derived keys and decrypted secrets.
  * `subtle 2`: constant-time comparison of secrets (`Secret::ct_eq`).
  * `base64 0.22` (`alloc`): the legacy and sealed text envelopes.
  The lockfile grows from 28 to 57 packages; none pulls `getrandom`/`rand_core` (asserted by
  `tests/hygiene.rs::lockfile_has_no_ambient_entropy_crates`, which keeps `wasm32` linking without
  a `js` shim). `cargo deny` (rust/deny.toml unchanged: all new crates are MIT / Apache-2.0) and
  `cargo audit` pass on this crate and on `wasm-smoke` against the locally cached advisory database
  (not freshly fetched).
* No JSON, HTTP, RNG, clock or threading crates. `tests/hygiene.rs` asserts the library sources
  (including `src/vault/`) contain no `std::fs/net/env/thread/process`, clock, RNG, `unsafe`,
  `unwrap`, `expect` or `panic!`.
* Dev profile: the crypto crates above are built with `opt-level = 3` (`[profile.dev.package.*]`)
  so the scrypt-based tests run in seconds; release builds are unaffected.
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
| R16 | R | `checkPasswordMatch` returns `true` for every input (walletUtils.js:886-889); its caller `Send.js:25` also passes four arguments to a three-parameter function | Not on main; open PR #3 is titled as hardening password checks (M1), its diff was not reviewed here | `verify_password` must decrypt the vault; `check_password_match` also requires the seed to derive the expected address on the named network | `vault_migration::v_r1_check_password_match_is_real` |
| R17 | R | Unauthenticated AES-CBC and no padding check in crypto-js: a wrong password usually yields an empty or malformed string but sometimes a short non-empty one, which the `if (decrypted)` checks accept (PasswordSetup.js:40-47, ExposeSeed.js:28-37, ResetPass.js:35-41, walletUtils.js:261-266 feeds any non-empty string to `mnemonicToSeedSync`, deriving a different wallet silently). crypto-js 4.2.0 returned `"/"` for the wrong password `wrong-28` on a seed blob (fixture `legacy.wrong_accepted.*`) | No | Sealed format is AEAD with the whole header authenticated: wrong password and any modified byte are `WrongPasswordOrTampered`. Legacy blobs are read with checked PKCS#7 and must decrypt to a canonical BIP-39 phrase | `vault_legacy::regression_wrong_password_that_crypto_js_accepted_is_refused`, `vault_format::every_bit_flip_is_rejected`, `vault_migration::v_r2_sealed_vault_never_returns_garbage` |
| R18 | R | Password KDF is OpenSSL `EVP_BytesToKey` with MD5 and one iteration (PasswordSetup.js:34, ResetPass.js:44, walletUtils.js:332): a fast offline guess rate against any copy of the localStorage blob | No | scrypt N=2^15, r=8, p=1 by default (PBKDF2-SHA256 600 000 iterations as the alternative), parameters recorded in the authenticated header and bounded on read | `vault_migration::v_r3_new_vault_uses_a_recorded_memory_hard_kdf`, `vault_format::hostile_kdf_parameters_are_refused_before_any_work` |
| R19 | R | `getOrDeriveKeyPair` caches `address.privateKey` per network under `encryptedPrivateKey:<net>:<path>` (walletUtils.js:892-914) and PasswordPrompt stores it as `encryptedKey` (PasswordPrompt.js:87-88). The cached value is not plaintext: it is `CryptoJS.AES.encrypt(base64(privateKey), password)` (walletUtils.js:331-332), i.e. a second ciphertext under the same weak scheme with a recognisable plaintext shape (44 base64 characters ending in `=`), which doubles the offline attack surface and outlives a password change until `clearPrivateKeyCaches` runs | Partly: `clearPrivateKeyCaches` is called on setup and reset | No derived key is ever persisted; keys are derived in memory from the unlocked seed; migration retirement deletes the legacy caches | `vault_migration::v_r4_no_derived_key_cache_is_persisted` |
| R20 | R | `PasswordSetup` keeps an existing `encryptedSeed` and silently drops the seed phrase just entered (PasswordSetup.js:24-37): the user believes the new wallet exists while the old one is unlocked | No | `create` refuses with `AlreadyExists` when a legacy blob, vault, backup or record exists | `vault_migration::v_r5_create_never_overwrites_or_silently_keeps` |
| R21 | R | An empty password is accepted at setup (PasswordSetup.js:17-35) although the unlock prompt rejects it (PasswordPrompt.js:24-27), leaving an unusable wallet | No | Empty password is `EmptyPassword` for create, seal, open and change; a legacy empty-password wallet can still be read once and migrated to a real password | `vault_migration::v_r6_empty_password_is_refused`, `legacy_wallet_with_empty_password_migrates_to_a_real_one` |
| R22 | R | `ResetPass` re-encrypts whatever decrypted to a truthy string (ResetPass.js:35-47): with R17 a wrong "current password" can overwrite the seed with an encryption of garbage, with no backup and no read-back | No | `change_password` opens with the old password, seals, swaps the single key with compare-and-swap, reads it back and restores the previous blob if the read-back fails | `vault_migration::v_r7_change_password_is_atomic_and_verified` |
| P5 | P | Legacy blob format: `base64("Salted__" ‖ salt8 ‖ AES-256-CBC(PKCS#7))`, key and IV from `EVP_BytesToKey(MD5, 1)` over the UTF-8 password; plaintext is the phrase, trimmed before use (walletUtils.js:262) | n/a | Read byte-exactly; stricter only in that PKCS#7 padding is verified (no honest blob is refused). Never written | `vault_legacy::fixtures_decrypt_byte_exact`, `test_encryptor_reproduces_crypto_js_blobs` |
| V3 | V | New storage format: `tlvault:` + base64 of `TLVT` header (version, payload kind, network, KDF id and three parameters, salt, nonce) + XChaCha20-Poly1305 ciphertext; keys `vault.v1`, `vault.legacy_backup`, `vault.record`; `encryptedSeed` is removed at the end of a migration (popup.js:310-314 routes on its presence, so the JS side must read `vault.v1` / `vault.record` instead) | n/a | Versioned; unknown versions refused, versions below the recorded floor refused (`Downgrade`) | `vault_format::version_policy_rejects_downgrade_and_unknown_versions`, `vault_migration::version_floor_in_the_record_rejects_older_blobs` |
| U5 | U | DelegatedSigner (DelegatedSigner.js:36-70) passes the PBKDF2 output, a `WordArray`, as the AES key. crypto-js then skips key derivation and supplies no IV, and throws `TypeError` in CBC before returning (verified with crypto-js 4.2.0 for both `encrypt` and `decrypt`; fixture `delegated.*`). `initialize()` therefore never reaches `saveEncryptedKey`, and no file in the repository imports the class. Its PBKDF2 parameters are SHA-256, 10 000 iterations, 32 bytes, salt = UTF-8 of the 32-character hex string | n/a | No second legacy format exists to import; `delegated_signer_key` documents the derivation and is parity-checked. Not repaired, because nothing it would protect exists | `vault_legacy::delegated_signer_key_matches_crypto_js_and_its_ciphertext_cannot_exist` |
| U6 | U | Legacy phrases that are not canonical BIP-39 (checksum-less typos accepted by the old import, R10; extra spaces or capitals) | n/a | Not migrated: `InvalidSecret` / `NonCanonicalLegacyPhrase`, legacy data untouched, wallet keeps working through the legacy path. Canonicalising would derive a different seed (`mnemonicToSeedSync` uses the raw string), so the port refuses instead of guessing; the JS side needs a separate "export seed" path for these users | `vault_migration::non_canonical_or_invalid_legacy_plaintext_is_not_migrated` |
| U7 | U | The migration record and version floor live in the same store as the blob. Anyone who can write the store can delete the record and lower the floor | n/a | AEAD still protects confidentiality and integrity of the seed; the floor only stops older or accidental writers. Deleting the sealed blob is an availability attack that the backup record recovers from | |
| U8 | U | The backup record is the legacy ciphertext byte for byte, so it keeps the MD5/1-iteration protection for as long as it exists | n/a | Kept so a lost or damaged sealed blob can be rebuilt (`recover_from_backup`); `discard_backup` deletes it after proving the sealed blob holds the same secret. The extension binding (`../tl-extension-app/wasm`, `drop_legacy_backup`) calls it at the first unlock after the migration finished, before a password change, and right after a migration under a new password; a failed check keeps the backup | `vault_migration::recovery_drill_lost_and_corrupted_sealed_blob` |
| U9 | U | scrypt N=2^15 (32 MiB, a few hundred ms natively) was not timed inside an extension service worker or popup; PBKDF2 is available for hosts without the memory | | Parameters are data in the header, so the default can change without a format change | |
| U10 | U | Passwords are used as typed (UTF-8 bytes, no Unicode normalisation), exactly as crypto-js did | | Unchanged, so legacy passwords keep working (fixture `seed_unicode_pw`) | |

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

## Vault (`src/vault/`)

Storage and randomness are injected (`VaultStore`, `Random`); there is no filesystem, clock or
ambient RNG, so the module builds for `wasm32-unknown-unknown` and runs in a WASM host (see
"WASM"). The caller owns the real adapters: a `chrome.storage.local` / `localStorage` store whose
`compare_and_swap` is a read-compare-write inside one task, and a `Random` backed by
`crypto.getRandomValues`. `CounterRandom` is a deterministic LCG for tests only.

Storage keys:

| Key | Holds |
| --- | --- |
| `encryptedSeed` | legacy CryptoJS blob (deleted only by the last migration step) |
| `vault.legacy_backup` | byte-for-byte copy of the legacy blob, written before anything else |
| `vault.v1` | sealed blob: `tlvault:` + base64(`TLVT` header 60 bytes ‖ XChaCha20-Poly1305 ciphertext ‖ tag) |
| `vault.record` | `tlrec1;<phase>;<min_version>;<sha256 of the legacy blob or ->` |
| `encryptedKey`, `encryptedPrivateKey:*` | legacy derived-key caches, deleted at retirement |

Header (all authenticated as AAD): magic, version, payload kind, network, KDF id (1 scrypt,
2 PBKDF2-SHA256), three KDF parameters, 16-byte salt, 24-byte nonce. Reads refuse, before any KDF
work: bad envelope, version 0 or newer than this build, version below the record floor
(`Downgrade`), unknown KDF, parameters outside the window (scrypt log N 10..20, r 1..16, p 1..4,
at most 256 MiB; PBKDF2 1 000..4 000 000), another network or payload kind. The network is the
"vault slot" label (the wallet derives every network from one seed), so a blob sealed for one
network is not accepted in another network's slot.

Migration (`VaultManager::migrate_step`, one transition per call, `migrate` loops):

```
(no record) --1--> BackedUp --2--> Written --3--> Verified --4--> Retired
 1  decrypt + validate legacy (canonical 12-word BIP-39), write backup, write record
 2  seal a new blob (reusing a staged blob that already opens), write it, write record
 3  read the sealed blob back from storage, open it, compare with the legacy secret, write record
 4  re-verify, delete the legacy key, delete the key caches, write record
```

Each storage write is one compare-and-swap on one key. The tests interrupt a full migration at
each of its 9 writes, both before the write (`FailBefore`) and after it was applied but reported
as failed (`ApplyThenFail`), and then after two interruptions in a row (81 combinations). In every
case the state is recoverable (legacy blob, verified sealed blob or backup decrypts to the seed),
`unlock` works with the password that belongs to the active source, and resuming reaches
`Retired` with the backup equal to the original legacy blob. The legacy key is deleted only when
the record says `Verified`, the backup equals it, and a fresh read of the sealed blob opens to the
legacy secret. Other operations: `create` (refuses over anything existing), `unlock`,
`verify_password`, `check_password_match(password, network, address)`, `change_password` (one
swap, read-back, rollback), `abort_migration` (only while the legacy blob still exists),
`recover_from_backup`, `discard_backup`.

Recovery drill (`vault_migration::recovery_drill_lost_and_corrupted_sealed_blob`): the
crypto-js-generated blob for the public `abandon ... about` mnemonic is migrated, the sealed blob
is corrupted (unlock fails with a typed error), recovered from the backup, deleted outright
(`Unreadable`), recovered again with a different new password, and every network's address is
checked against `Account::from_mnemonic` after each stage.

## Vault parity with crypto-js

`scripts/vault-legacy-vectors.cjs` runs the real crypto-js 4.2.0 through the extension's exact
calls (`CryptoJS.AES.encrypt(text, password).toString()`, and the DelegatedSigner PBKDF2 +
`AES.encrypt(text, key)` pair) and writes `tests/fixtures/vault_legacy_vectors.txt`: eight
synthetic blobs (the public BIP-39 mnemonic with ASCII, non-ASCII and empty passwords, a
`base64(0x11 * 32)` key-cache blob, padding-boundary plaintexts of 0, 15 and 16 bytes, UTF-8),
one wrong-password case crypto-js accepts, and the DelegatedSigner key and failure outcome. The one
random input (the OpenSSL salt) is replaced by a deterministic stream so `--check` reproduces the
file byte for byte; everything else is unmodified crypto-js. The script verifies the installed
version and the SHA-256 of `crypto-js.js` (`ee02257f...9bbe`, from the tarball whose sha512
integrity is in the repository's `package-lock.json`). crypto-js is not a dependency of the crate:

```
mkdir /tmp/legacy && cd /tmp/legacy && printf '{"private":true}' > package.json
npm install --ignore-scripts crypto-js@4.2.0
LEGACY_CRYPTOJS_DIR=/tmp/legacy node scripts/vault-legacy-vectors.cjs --check   # VAULT_VECTORS_OK
```

For this port the vectors were produced in a scratch folder outside the repository
(`legacy-run/TL-Extension`, `npm ci --ignore-scripts` against a lockfile reduced to the one
pinned package with the same integrity); `--check` printed `VAULT_VECTORS_OK` under Windows Node and
under Node 18 in WSL.

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

`cargo test --locked` runs 112 tests (56 before the vault module: `vault_legacy` 7, `vault_format` 14,
`vault_migration` 34, plus one new hygiene test). Vault crypto-js vectors: see "Vault parity with
crypto-js"; the WASM host run is `wasm-smoke/scripts/wasm-smoke.mjs` (see "WASM").

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

### Vault model (`TlWalletCore/Vault.lean`)

Models `VaultManager::migrate_step` / `unlock` / `unlock_source` and `format::open`'s version
policy. Each storage write of a step is its own action (`Act`: `writeBackup`, `recBackedUp`,
`writeVault`, `recWritten`, `recVerified`, `deleteLegacy`, `recRetired`), applied only when its
guard holds, so `Reach` covers every interleaving, interruption and skipped action; `ReachEnv`
adds the environment replacing, corrupting or deleting the sealed blob at any time.

Theorems (axioms limited to `propext` and `Quot.sound` by `AxiomCheck.lean`):

* `every_reachable_state_recoverable`: in every state reachable by any sequence of migration
  actions and sealed-blob damage, the legacy blob or the backup still decrypts to the original secret.
* `legacy_removed_only_after_verified_readback`: the legacy blob is absent only if the record is
  `verified` or `retired`, the backup equals it, and the sealed blob read back opens to the original
  secret. `legacy_removed_implies_backup` is the same without trusting the sealed blob.
  `record_implies_backup`: no record exists before the backup does.
* `unlock_sound`, `unlock_wrong_key`: unlock returns a stored secret, only under the key its blob
  was sealed with; a key matching no stored blob unlocks nothing.
  `unlock_returns_original`: in any migration-reachable state unlock can only return the original
  secret (no garbage, no other value), whatever key is tried.
* `openBlob_some`, `openBlob_wrong_key`, `right_key_opens`, `downgrade_rejected`,
  `unknown_version_rejected`, `version_zero_rejected`, `unlock_sealed_downgrade`: opening needs
  the matching key and a version in `[floor, current]` and at least 1; older-than-floor, newer and
  zero versions are refused.
* Support lemmas: `ref_eq`, `act_base`, `act_strong`, `reach_strong`, `reachEnv_base`.

Concrete `example ... := by decide` vectors cover the snapshot after each prefix of the seven
actions, the finished state, out-of-order actions being no-ops, replaying a finished migration,
unlock before/after verification and the version cases. Rust mirrors: 
`vault_migration::interruption_snapshots_match_the_lean_model` (interrupt at each of the 9 writes,
both failure modes, compare `Snapshot` with the model; writes 6 and 7, the key-cache purges, are
the two writes the model leaves out), `unlock_vectors_match_the_lean_model`,
`happy_path_step_by_step`, `vault_format::version_policy_rejects_downgrade_and_unknown_versions`.

Where the vault model abstracts: passwords and secrets are `Nat`s and a blob is
`(key, secret, version)`; authentication is "the key matches", so cipher strength, the KDF, header
AAD coverage (tested exhaustively in Rust by flipping every bit) and base64 are not modelled; the
legacy blob is assumed not to change mid-migration (Rust refuses a changed blob via the SHA-256
fingerprint, `LegacyChanged`); the version floor is a fixed parameter (its ratchet is tested in
Rust); `discard_backup` and `change_password` are not modelled.

## Not ported (and why)

* Vault, the parts that are not logic: the `chrome.storage` / `localStorage` adapter implementing
  `VaultStore`, the `crypto.getRandomValues` adapter implementing `Random`, the password
  prompts and the React components. `getOrDeriveKeyPair`'s caching is deliberately not ported
  (R19), `clearPrivateKeyCaches` survives only as the purge inside migration step 4, and
  `lib/walletUtils.js`'s exported `decryptPrivateKey` (817-835, explicit-IV CryptoJS call shape,
  called nowhere in the repository) is not imported. Open PR #3 also touches the vault; this port
  is independent of it and was not rebased onto it.
* Browser storage and messaging: `chrome.storage`, `localStorage`, popup windows, runtime messages,
  `window.js`, React components.
* Network I/O: `fetchUTXOs`, `broadcastTransaction`, `sendBTC` (BlockCypher), `buildPsbtLocally`
  (dead code in legacy; its fee check is the same defect as R2 and the new path replaces it).
* `generateLitecoinAddress`, `encodeSignature`, `signString` (replaced by BIP-137), the commented
  `generateAddressesFromSeed` multi-address scan, `decryptPrivateKey`, `hashMessage`.
* Taproot, witness versions above 0, non-P2WSH scripts, BIP32 xpub/xprv serialization with the
  per-network version bytes (the constants are carried in `NetworkParams` but unused).

## Remaining gaps (honest list)

* The `wasm32-unknown-unknown` library build and the WASM smoke run pass with the vault included
  (see "WASM"). No `wasm-bindgen` layer exists; the smoke ABI passes no secrets, the extension
  binding in `../tl-extension-app/wasm` does (JSON requests that it zeroes after use).
* Vault: the extension binding (`../tl-extension-app`) implements `VaultStore` over the popup's
  `localStorage` (a synchronous read-compare-write in one task) and `Random` over
  `crypto.getRandomValues`, and a browser run opens a legacy crypto-js vault and migrates it. There
  is no `chrome.storage.local` adapter, so the service worker and several popup windows writing
  at once are not covered; the popup (`popup.js` routing, unlock, sign) now goes through the module.
* Vault: timing of scrypt N=2^15 on target browsers (U9), password strength policy (only
  "non-empty" is enforced), padding of the sealed plaintext (the ciphertext length reveals the
  phrase length), and secret-zeroizing across a WASM boundary are open.
* Vault: only legacy blobs that decrypt to a canonical 12-word BIP-39 phrase migrate (U6).
  The legacy blob is assumed not to change while a migration is in flight; if it does the
  migration stops with `LegacyChanged` and must be aborted explicitly.
* CI workflow `.github/workflows/rust-tl-wallet-core.yml` has not run (nothing was pushed). Its Node
  parity step, the new vault-vector step (it runs `npm install crypto-js@4.2.0` there) and the Lean job are untested in GitHub's environment.
* Multisig finalize assumes bare m-of-n P2WSH with keys in script order; signatures from the
  account's receive key only. Hardware/other signer shapes, SIGHASH variants, RBF/locktime policy and
  fee estimation from real vsizes beyond the `FeePolicy::PerVbyte` helper are not covered.
* No fuzzing. Property coverage is the deterministic sweep in `tests/coin.rs` (3 000 cases) and the
  Lean theorems; parity covers the vectors in `tests/fixtures/legacy_vectors.txt` only.
* The Lean model proves decision logic, not equivalence of the Rust code to the model; the
  correspondence is by construction plus the shared vectors.
* Consumer: `../tl-extension-app` replaces `lib/walletUtils.js` key functions and the inline vault
  code in the popup (see its `PORT_PLAN.md`); `background.js` still does its own provider
  decisions (the `provider` and `origin` modules are not wired). BIP-137 (V1) is adopted by that
  build. `tx::presented` is `pub` so the binding can build capabilities from a PSBT.

## WASM

Verified 2026-10-30 (Rust 1.90.0, `wasm32-unknown-unknown`, clang 18 for libsecp256k1):
`cargo build --locked --lib --target wasm32-unknown-unknown` succeeds, and
`wasm-smoke/` (a raw-ABI `cdylib`, 338,009 bytes in release (208,343 before the vault)) runs under Node's
WebAssembly host: `node wasm-smoke/scripts/wasm-smoke.mjs <wasm>` prints
`WASM_SMOKE_OK` after checking address validation (valid, uppercase, mixed case, bad
checksum, wrong network, unknown network) and BIP-39 phrases for zero and `0xff`
entropy against the native test vectors, then `tlw_vault_selftest()` runs the vault inside the host
(crypto-js blob decrypt, scrypt + XChaCha20-Poly1305 seal/open with wrong-password and tamper
refusal, and a full legacy-to-sealed migration over `MemoryStore`) and must return 1. Re-verified
2026-11-02 with the vault in: `wasm-smoke.sh` printed `WASM_SMOKE_OK 338009 bytes`. The smoke ABI is for verification only; an
extension binding still needs a reviewed generator and secret-zeroizing buffers.
