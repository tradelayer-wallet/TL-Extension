# tl-extension-app

The TradeLayer MV3 extension with its original React/Redux popup, content script, provider and
background worker, running key handling, the vault and signing on `tl-wallet-core` compiled to
WebAssembly. `PORT_PLAN.md` maps the legacy code and lists the shims and the next steps.

```
wasm/      tl-extension-wasm: raw-ABI cdylib over tl-wallet-core (vault, unlock, sign message / PSBT / payment)
shim/      JS that replaces lib/walletUtils.js and lib/vault.js in the Rust build; ABI host
build.mjs  stages the unpacked extension (legacy tree read-only) and bundles the popup with the shims
scripts/   build-wasm.sh, core-node-test.mjs (ABI under Node), e2e-browser.mjs (Chrome over CDP)
```

## Commands

From Git Bash on Windows with the shared WSL tooling (`MSYS_NO_PATHCONV=1`); `W` is the `work`
folder; npm is installed only in a copy outside the clone (`npm ci --ignore-scripts` in
`legacy-run/TL-Extension/build-full`, from the repository's own `package.json` and lockfile).

```
# native tests, lints (13 tests; run through the shared rust.sh)
rust.sh $C/tl-extension-app/wasm test --locked --offline
rust.sh $C/tl-extension-app/wasm clippy --locked --offline --all-targets -- -D warnings
rust.sh $C/tl-extension-app/wasm clippy --locked --offline --lib --target wasm32-unknown-unknown -- -D warnings
rust.sh $C/tl-extension-app/wasm fmt --all -- --check

# wasm module (988,350 bytes, release)
wsl.exe -d Ubuntu-24.04 -- bash scripts/build-wasm.sh $W/ext-scratch/wasm

# ABI under Node
node scripts/core-node-test.mjs $W/ext-scratch/wasm/tl_extension_wasm.wasm      # CORE_NODE_TEST_OK

# unpacked extension in a scratch folder (outside the repository)
node build.mjs --out $W/ext-scratch/unpacked --node-modules $W/legacy-run/TL-Extension/build-full/node_modules \
     --wasm $W/ext-scratch/wasm/tl_extension_wasm.wasm                              # EXTENSION_BUILD_OK

# browser run: Chrome for Testing 157.0.8103.38 (branded Chrome ignores --load-extension)
node scripts/e2e-browser.mjs --chrome <chrome-win64/chrome.exe> --ext $W/ext-scratch/unpacked \
     --node-modules $W/legacy-run/TL-Extension/build-full/node_modules --profile <scratch profile>   # E2E_OK
```

`build.mjs --mode=development` (default) adds `http://localhost/*` and `http://127.0.0.1/*` to the
content-script matches and enables the loopback origin in the staged `background.js`, as
`build.js --mode=development` does; `--mode=release` stages the three layerwallet.com origins only.

## What the browser run covers (2026-11-04, headless Chrome for Testing 157, Windows)

The browser resolves nothing except loopback (`--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE
localhost, EXCLUDE 127.0.0.1"`), so the balance screen's calls to the production API fail
locally and no packet leaves the machine. All keys and phrases are synthetic or the public
`abandon ... about` phrase.

| Step | Result |
| --- | --- |
| Create wallet through the original screens (generate, show, confirm, password, prompt on LTCTEST) | testnet address view; storage holds `vault.v1` (`tlvault:` sealed blob), `vault.record`, empty `encryptedKey`; no seed word, 32-byte hex or base64 key in `localStorage` or `chrome.storage.local` |
| Unlock with a wrong password | legacy alert "Incorrect password or corrupted data", no wallet |
| Import the `abandon ... about` phrase | address `tltc1q6rz28...pesrjxk`, the address in `tl-wallet-core/tests/fixtures/legacy_vectors.txt` |
| Import a phrase with a bad checksum | refused at password setup, nothing stored |
| Legacy crypto-js blob in `localStorage.encryptedSeed` (fixture from crypto-js 4.2.0) | popup routes to the unlock prompt, opens to the same address, migrates in place (`encryptedSeed` removed, `vault.legacy_backup` equals the old blob, record `retired`); the next unlock drops `vault.legacy_backup` |
| Provider on a local page: `connect` | approval popup (step 17) shows the page origin; Approve returns the account |
| `signMessage` | approval popup (step 13) shows the message; the BIP-137 signature recovers the account public key; a wrong password is refused and Reject reaches the page |
| `signPsbt` | step 16 with the legacy fee summary; the returned final transaction passes an independent BIP143 ECDSA check (Node + `@noble/curves`) and its txid matches |
| `signTransaction` (legacy payload) | step 13; returns a signed segwit transaction with a txid |
| Settings: expose seed, reset password | wrong password refused; right password shows the phrase; reset re-seals the vault, old password refused, new password opens it |

Timing in that run: creating a vault (two scrypt N=2^15 passes) 286 ms, unlocking 128 ms.

## Not covered

* Branded Chrome/Edge (they ignore `--load-extension`), a headed browser, Firefox.
* `--mode=release` was staged by neither the run nor a test.
* Two popup windows writing the vault at once (the store's compare-and-swap is single-task; no
  multi-window race was run), and scrypt timing on a slow device.
* `addMultisig`, `buildUnsignedPSBT`, Dogecoin spends, BTC (the legacy popup does not offer BTC),
  the Send screen's network calls, balance fetches.
* The wasm module is not signed or reproducibly built beyond `--locked --offline`.
* The service worker does not load the module (it holds no key); see `PORT_PLAN.md` section 4.
