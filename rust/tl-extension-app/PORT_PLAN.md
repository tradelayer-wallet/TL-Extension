# TL-Extension port plan: original UI on the Rust core

Goal: the MV3 extension runs its original popup UI and behaviour unchanged, with key handling,
the vault and signing in `tl-wallet-core` compiled to WebAssembly. Baseline: `feat/rust-port`
at `0f296d6` (contains `origin/main` `e16cb4e`). Milestone 1 (this document, `build.mjs`, `shim/`,
`wasm/`, `scripts/`) is built and driven in a browser; section 6 says what ran.

## 1. Where keys live (read from the code, not assumed)

The background service worker never touches a key. `background/background.js` (769 lines) only
validates page requests, keeps the per-origin network approvals and the pending-request registry,
and opens the approval popup window. It has no `crypto-js`, `bitcoinjs`, `localStorage` or
signing call. Everything that creates, stores, unlocks or uses a key runs in the popup page
(`popup/popup.html` -> `dist/bundle.js`), which is a normal extension page with a synchronous
`localStorage`:

| Operation | Legacy location | Storage touched |
| --- | --- | --- |
| Generate mnemonic | `SeedPhraseGeneration.js` `handleGenerateSeed` -> `walletUtils.generateMnemonic` (802, `bip39.generateMnemonic`) | none (Redux `seedPhrase`) |
| Import mnemonic | `SeedPhraseImport.js` (12 text boxes joined by spaces, no word-list or checksum check) | Redux `seedPhrase` |
| Create vault | `PasswordSetup.js` (`CryptoJS.AES.encrypt(seed, password)`, then `localStorage.encryptedSeed`) | `localStorage.encryptedSeed` |
| Unlock + address | `PasswordPrompt.js` -> `walletUtils.generateAddressFromSeed` (259: decrypt, derive, address, public key, and the private key re-encrypted under the password) | writes `localStorage.encryptedKey` (that ciphertext) and `chrome.storage.local.addresses`, `activeAccountsV1` |
| Key cache | `walletUtils.getOrDeriveKeyPair` (892) | `localStorage.encryptedPrivateKey:<net>:<path>` |
| Password check | `walletUtils.checkPasswordMatch` (886, always `true`); callers `SignTransaction.js`, `signPSBT.js` | none |
| Sign message | `SignTransaction.js` -> `walletUtils.signMessage` (860, decrypts `encryptedKey`, signs `sha256(message)`) | reads `encryptedKey` |
| Sign transaction (legacy payload) | `SignTransaction.js`, `Send.js` -> `walletUtils.signTransaction` (919) | reads `encryptedKey` / caches |
| Sign PSBT | `signPSBT.js` -> `walletUtils.signInputsInPsbt` (1149) | reads caches; reads `localStorage.multisigs` through `getMultisigData` |
| Expose seed | `ExposeSeed.js` | reads `encryptedSeed` |
| Change password | `ResetPass.js` | rewrites `encryptedSeed` |
| "Is there a wallet" routing | `popup.js:310-314` | reads `encryptedSeed` |
| Delegated signer | `DelegatedSigner.js` | `chrome.storage` salt/key; imported nowhere, cannot run (core README U5) |

There is no vault in `chrome.storage`. The legacy vault is the crypto-js blob in the popup
origin's `localStorage.encryptedSeed`; that is what an existing user has and what must open.
`chrome.storage.local` holds `addresses`, `activeAccountsV1`, `sitePermissionsV1` and a copy of
`multisigs` (also in `localStorage.multisigs`); none is secret.

## 2. Message types (every one in the repository)

Page <-> content script (`window.postMessage`, `contentScript.js`, `window.js`):

| Type | Direction | Payload |
| --- | --- | --- |
| `{type:'request'}` (legacy bridge, no `channel`) | page -> cs | `data:{id (string or number), method, params}` |
| `{type:'response'}` (legacy) | cs -> page | `data:{id, success, result, accounts, error, payload}` |
| `tradelayerBridgePing` / `tradelayerBridgeReady` | page -> cs / cs -> page | `data:{providerId, sessionId}` |
| `{channel:'tradelayer-provider', type:'request'}` | page -> cs | `sessionId`, `data:{id (string), method, params}` |
| `{channel, type:'response'}` | cs -> page | `data:{id, success, result, accounts, error}` |
| `{channel, type:'event'}` | cs -> page | `data:{event, payload}` (`accountsChanged`, `networkChanged`) |

Provider methods: `connect`, `requestAccounts`, `signMessage`, `signPsbt` (alias `signPSBT`),
`signTransaction`, `addMultisig`, `fetchUserIP`, `keepAlive`.

Content script <-> background (`chrome.runtime.sendMessage` / `chrome.tabs.sendMessage`):

| Type | Direction | Payload / reply |
| --- | --- | --- |
| `{channel, type:'providerRequest'}` | cs -> bg | `data:{id, method, params(+__legacyBridge)}`; reply `{success, result}` or `{success:false, error}` |
| `{channel, type:'providerEvent'}` | bg -> cs | `event`, `payload` |

Background <-> popup (`chrome.runtime.sendMessage`, selector is `method`, no channel):

| `method` | Direction | Payload |
| --- | --- | --- |
| `popupReady` (popup-only) | popup -> bg | `{requestId}`; bg answers by sending the matching request below |
| `connectApprovalRequest` | bg -> popup | `{requestId, origin, network}` |
| `signMessageRequest` | bg -> popup | `{requestId, origin, network, messageToSign}` |
| `signTxRequest` | bg -> popup | `{requestId, origin, network, txToSign}` |
| `signPsbtRequest` | bg -> popup | `{requestId, origin, network, sellerFlag, redeemScript, txToSign}` |
| `addMultisigRequest` | bg -> popup | `{requestId, origin, network, m, pubkeys}` |
| `approvalDecision` (popup-only) | popup -> bg | `{requestId, approved}` |
| `signMessageResponse` (popup-only) | popup -> bg | `{requestId, signedMessage}` |
| `signTxResponse` (popup-only) | popup -> bg | `{requestId, signedTx}` (bg unwraps `signedTx.data`) |
| `addMultisigResponse` (popup-only) | popup -> bg | `{requestId, result}` |
| `rejectPendingRequest` (popup-only) | popup -> bg | `{requestId, reason}` |
| `getAccount`, `buildUTXOTrade`, `addMultisigToWallet` | any extension context -> popup | handled by `popup.js:170-217`; nothing in this repository sends them and the popup does not check the sender (a latent surface: `addMultisigToWallet` and `buildUTXOTrade` run with page-supplied key pairs) |

Popup-only names are sender-checked in the background (`isPopupSender`).

## 3. Disposition

| Function | Now |
| --- | --- |
| generateMnemonic, create, import validation, unlock, address derivation, check password, expose seed, change password, sign message, sign payment, sign PSBT | **Rust core in wasm** (`wasm/src/ops.rs`), reached through `shim/walletUtils.js` and `shim/vault.js` |
| Legacy vault read + migration to the sealed format | **Rust core** (`VaultManager::migrate`), triggered by a correct unlock of a legacy vault |
| `clearPrivateKeyCaches`, `addMultisigAddress`, `buildUnsignedPSBT`, `summarizePsbtForDisplay`, `fetchUTXOs`, `sendBTC`, UTXO and balance fetches (production endpoints) | legacy JS, unchanged |
| Provider gate, origin allow-list, approvals, pending registry (`background.js`, `contentScript.js`, `window.js`) | legacy JS, unchanged; the Rust `provider` and `origin` modules exist and are not wired (section 7) |
| React/Redux UI | legacy JS, unchanged except the edits in section 5 |

## 4. Wiring

`build.mjs` bundles `popup/popup.js` with esbuild like `build.js`, with a resolver plugin that
swaps two modules for the shims. The legacy tree is read and never written; `npm run build`
still produces the crypto-js build.

```
lib/walletUtils.js -> shim/walletUtils.js   re-exports the legacy module, overrides the key functions
lib/vault.js       -> shim/vault.js         vaultExists, createVault, exposeSeed, changePassword
shim/core.js                                 top-level await: fetch + instantiate wasm (popup only)
shim/core-factory.mjs                        ABI host: localStorage store, getRandomValues, JSON call()
wasm/                                        crate tl-extension-wasm (cdylib, raw ABI, 11 native tests)
```

The vault operations run against the popup's real `localStorage` through host imports
(`store_get`, `store_cas`, `store_keys`, `random_fill`), so `encryptedSeed` opens in place and the
core's compare-and-swap is a synchronous read-compare-write in one task. A password and any
phrase cross the boundary inside a request buffer that the module zeroes before returning
(`tlx_call`) and when freed (`tlx_free`); the JS strings that held them are not wiped (JS cannot).

MV3 requirements: `content_security_policy.extension_pages` gets `wasm-unsafe-eval`
(`script-src 'self' 'wasm-unsafe-eval'; object-src 'self';`, written by `build.mjs`; the legacy
`manifest.json` is untouched). The module is not listed in `web_accessible_resources`; only extension pages load it.
The service worker does not load wasm because it holds no key; when the `provider` module is
wired later it can `WebAssembly.instantiateStreaming` inside the existing module worker with the
same CSP, and must re-instantiate after each idle shutdown.

Why the vault stays in the popup: the worker has no `localStorage`, and `chrome.storage` is
asynchronous while `VaultStore` is synchronous. Moving vault calls to the worker needs an async
store design (preload the five keys, run the op, commit the diff by compare-and-swap) and is not
needed while only the popup signs.

## 5. Legacy files edited (all behaviour-preserving in the legacy build)

1. `lib/vault.js` (new): the crypto-js implementation of `vaultExists`, `createVault`,
   `exposeSeed`, `changePassword`, moved out of the components unchanged in behaviour.
2. `components/PasswordSetup.js`: inline AES encrypt/store/decrypt block replaced by
   `createVault(password, seedPhrase)`; the CryptoJS import removed.
3. `components/ExposeSeed.js`: inline decrypt replaced by `exposeSeed(password)`.
4. `components/ResetPass.js`: inline decrypt/encrypt/store replaced by `changePassword(...)`.
5. `popup/popup.js`: the `localStorage.getItem('encryptedSeed')` routing read (310) replaced by
   `vaultExists()` (the Rust vault deletes `encryptedSeed` once migrated, so the old read would
   route a migrated user to "create wallet").

No other legacy file is edited. `PasswordPrompt.js`, `SignTransaction.js`, `signPSBT.js`,
`Send.js`, `balance.js`, `SiteApproval.js`, the background worker, content script and provider
are byte-identical; they reach Rust only through the `lib/walletUtils` swap.

Observable differences in the Rust build (each is a repaired defect or versioned change in
`rust/tl-wallet-core/README.md`): `generateAddressFromSeed` ignores its first argument and
returns `privateKey: ''`, so `PasswordPrompt` stores an empty `encryptedKey` (R19);
`checkPasswordMatch` really checks (R16); `signMessage` returns a BIP-137 base64 signature (R4,
V1); `signTransaction` pays change to the wallet's own address and refuses foreign UTXOs (R1,
R6); `signInputsInPsbt` no longer rewrites PSBTs from `localStorage` multisig records (R8); an
invalid BIP-39 phrase is refused at password setup (R10); wrong passwords never yield a wallet
(R17).

## 6. Milestone 1 results

See `README.md` for commands. Native: 11 tests (`wasm/tests/ops.rs`); core crate unchanged apart
from `tx::presented` becoming `pub`. Node: `scripts/core-node-test.mjs` (the ABI host with an
in-memory Storage). Browser: `scripts/e2e-browser.mjs` in Chrome for Testing 157 over CDP.

## 7. Next steps

1. Wire the Rust `provider`/`origin` modules into the worker (decisions only; closes R5/R14 in
   `background.js`) with wasm loaded in the service worker.
2. Dogecoin spends: the legacy UTXO payload has no previous transaction; `sign_payment` returns
   `InvalidInput("p2pkh utxo requires prev_tx")` until the UTXO source supplies it.
3. `addMultisig` (`addMultisigAddress`) and `buildUnsignedPSBT` use only public data or
   page-supplied key pairs; port `multisig` into the shim and remove the unauthenticated
   `buildUTXOTrade` / `addMultisigToWallet` popup handlers (section 2).
4. Legacy phrases that are not canonical BIP-39 (core README U6) cannot be opened by the Rust
   vault; add an export path before enabling the Rust build for existing users.
5. `summarizePsbtForDisplay` -> `tx::summarize_psbt` (same numbers, `fee: None` on unknown input).
6. Release build: `build.mjs --mode=release` stages the release match patterns; it still needs
   the legacy `release-build-smoke` equivalent and a CI job that builds the wasm
   (`scripts/build-wasm.sh`) and runs `core-node-test.mjs` and the native tests.
7. Measure scrypt N=2^15 on a low-end device (U9); the only timing so far is the headless Chrome run in `README.md`.
