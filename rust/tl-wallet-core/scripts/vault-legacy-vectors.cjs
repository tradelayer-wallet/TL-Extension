#!/usr/bin/env node
// Legacy vault parity harness for tl-wallet-core (`vault::legacy`).
//
// Generates ciphertexts with the real crypto-js 4.2.0 (the version pinned by the repository's
// package-lock.json) through the exact calls the extension makes:
//   * CryptoJS.AES.encrypt(text, password).toString()       components/PasswordSetup.js:34,
//                                                          components/ResetPass.js:44,
//                                                          lib/walletUtils.js:332
//   * CryptoJS.PBKDF2(password, salt, {keySize: 8, iterations: 10000}) then
//     CryptoJS.AES.encrypt(privateKey, key)                 components/DelegatedSigner.js:39-43
// and writes `key=value` vectors (synthetic passwords and keys only) to
// tests/fixtures/vault_legacy_vectors.txt. The only random input of the legacy encrypt path is the
// 8-byte OpenSSL salt, drawn from CryptoJS.lib.WordArray.random; the harness replaces that one
// function with a deterministic stream so the fixture is reproducible. Everything else is the
// unmodified crypto-js code.
//
//   node scripts/vault-legacy-vectors.cjs            # rewrite the fixture
//   node scripts/vault-legacy-vectors.cjs --check    # fail if crypto-js no longer yields the fixture
//
// crypto-js is not a dependency of this crate. Install it outside the repository:
//   mkdir /tmp/legacy && cd /tmp/legacy && npm init -y >/dev/null \
//     && npm install --ignore-scripts crypto-js@4.2.0
//   LEGACY_CRYPTOJS_DIR=/tmp/legacy node scripts/vault-legacy-vectors.cjs --check
// (a plain `require('crypto-js')` is tried first).

'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const fixturePath = path.resolve(__dirname, '..', 'tests', 'fixtures', 'vault_legacy_vectors.txt');
const PINNED_VERSION = '4.2.0';
// sha256 of node_modules/crypto-js/crypto-js.js from the registry tarball whose integrity the
// repository lockfile records (sha512-KALDyEYgpY+Rlob/...).
const PINNED_BUNDLE_SHA256 = 'ee02257ffbaf0a9b481c7039b0f3bb20c360c9674fe4be8b38ae709b2ea59bbe';

function loadCryptoJs() {
  const candidates = [];
  if (process.env.LEGACY_CRYPTOJS_DIR) {
    candidates.push(path.join(process.env.LEGACY_CRYPTOJS_DIR, 'node_modules', 'crypto-js'));
  }
  candidates.push('crypto-js');
  let lastErr;
  for (const c of candidates) {
    try {
      const pkgPath = c === 'crypto-js' ? require.resolve('crypto-js/package.json') : path.join(c, 'package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.version !== PINNED_VERSION) {
        throw new Error(`crypto-js ${pkg.version} found, ${PINNED_VERSION} required`);
      }
      const bundle = fs.readFileSync(path.join(path.dirname(pkgPath), 'crypto-js.js'));
      const digest = crypto.createHash('sha256').update(bundle).digest('hex');
      if (PINNED_BUNDLE_SHA256 !== 'unpinned' && digest !== PINNED_BUNDLE_SHA256) {
        throw new Error(`crypto-js.js sha256 ${digest} differs from the pinned ${PINNED_BUNDLE_SHA256}`);
      }
      return { CryptoJS: require(c === 'crypto-js' ? c : c), digest };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`cannot load pinned crypto-js: ${lastErr && lastErr.message}`);
}

const { CryptoJS, digest: bundleDigest } = loadCryptoJs();

// Deterministic replacement for the salt source only.
let saltCounter = 0;
function deterministicRandom(nBytes) {
  const out = [];
  while (out.length < nBytes) {
    const h = crypto.createHash('sha256').update(`tl-wallet-core vault vectors ${saltCounter++}`).digest();
    for (const b of h) out.push(b);
  }
  return CryptoJS.lib.WordArray.create(Buffer.from(out.slice(0, nBytes)));
}
CryptoJS.lib.WordArray.random = deterministicRandom;

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// Synthetic 32-byte "private key" (0x11 repeated) in the base64 form walletUtils.js:331 stores.
const KEY_B64 = Buffer.alloc(32, 0x11).toString('base64');

const out = [];
const emit = (k, v) => out.push(`${k}=${v}`);

emit('crypto_js.version', PINNED_VERSION);
emit('crypto_js.bundle_sha256', bundleDigest);

// name, password, plaintext
const cases = [
  ['seed', 'correct horse battery staple', MNEMONIC],
  ['seed_unicode_pw', 'pässwörd-Δ✓', MNEMONIC],
  ['seed_empty_pw', '', MNEMONIC],
  ['key_cache', 'correct horse battery staple', KEY_B64],
  ['pad_full_block', 'pw16', '0123456789abcdef'],
  ['pad_fifteen', 'pw15', '0123456789abcde'],
  ['pad_empty', 'pw0', ''],
  ['utf8_plain', 'pw-utf8', 'café ✓'],
];
for (const [name, pw, plain] of cases) {
  const blob = CryptoJS.AES.encrypt(plain, pw).toString();
  // self-check with the legacy decrypt path
  const back = CryptoJS.AES.decrypt(blob, pw).toString(CryptoJS.enc.Utf8);
  if (back !== plain) throw new Error(`crypto-js round trip failed for ${name}`);
  emit(`legacy.${name}.password_hex`, Buffer.from(pw, 'utf8').toString('hex'));
  emit(`legacy.${name}.plaintext_hex`, Buffer.from(plain, 'utf8').toString('hex'));
  emit(`legacy.${name}.blob`, blob);
}

// Unauthenticated CBC: search for a wrong password for which the legacy code returns a
// non-empty string instead of failing (CryptoJS never validates the PKCS#7 padding).
{
  const pw = 'correct horse battery staple';
  const blob = CryptoJS.AES.encrypt(MNEMONIC, pw).toString();
  let found = null;
  for (let i = 0; i < 200000 && !found; i++) {
    const wrong = `wrong-${i}`;
    try {
      const got = CryptoJS.AES.decrypt(blob, wrong).toString(CryptoJS.enc.Utf8);
      if (got.length > 0) found = { wrong, got };
    } catch (_) {
      /* Malformed UTF-8 data */
    }
  }
  if (!found) throw new Error('no accepted wrong password found in the search window');
  emit('legacy.wrong_accepted.blob', blob);
  emit('legacy.wrong_accepted.password_hex', Buffer.from(pw, 'utf8').toString('hex'));
  emit('legacy.wrong_accepted.wrong_password_hex', Buffer.from(found.wrong, 'utf8').toString('hex'));
  emit('legacy.wrong_accepted.legacy_output_hex', Buffer.from(found.got, 'utf8').toString('hex'));
}

// DelegatedSigner (components/DelegatedSigner.js:36-44, 61-70).
{
  const salt = '00112233445566778899aabbccddeeff'; // generateSalt() returns a 32-char hex STRING
  const pw = 'delegated-pw';
  const key = CryptoJS.PBKDF2(pw, salt, { keySize: 256 / 32, iterations: 10000 });
  emit('delegated.salt', salt);
  emit('delegated.password_hex', Buffer.from(pw, 'utf8').toString('hex'));
  emit('delegated.key_hex', key.toString(CryptoJS.enc.Hex));
  // Cross-check the parameters crypto-js 4.2.0 actually used (hasher SHA-256, salt = UTF-8 of the
  // hex string) against Node's PBKDF2.
  const nodeKey = crypto.pbkdf2Sync(Buffer.from(pw, 'utf8'), Buffer.from(salt, 'utf8'), 10000, 32, 'sha256').toString('hex');
  if (nodeKey !== key.toString(CryptoJS.enc.Hex)) throw new Error('PBKDF2 parameters differ from SHA-256/10000/utf8-salt');
  let encryptOutcome;
  try {
    CryptoJS.AES.encrypt('11'.repeat(32), key).toString();
    encryptOutcome = 'ok';
  } catch (e) {
    encryptOutcome = e.name;
  }
  let decryptOutcome;
  try {
    // any well-formed OpenSSL-shaped input: the decrypt side needs an IV too
    CryptoJS.AES.decrypt(CryptoJS.AES.encrypt('x', 'pw').toString(), key).toString(CryptoJS.enc.Utf8);
    decryptOutcome = 'ok';
  } catch (e) {
    decryptOutcome = e.name;
  }
  emit('delegated.encrypt_with_wordarray_key', encryptOutcome);
  emit('delegated.decrypt_with_wordarray_key', decryptOutcome);
}

const text = out.join('\n') + '\n';
if (process.argv.includes('--check')) {
  const have = fs.readFileSync(fixturePath, 'utf8').replace(/\r\n/g, '\n');
  if (have !== text) {
    console.error('vault_legacy_vectors.txt differs from the output of crypto-js');
    process.exit(1);
  }
  console.log('VAULT_VECTORS_OK');
} else {
  fs.writeFileSync(fixturePath, text);
  console.log(`wrote ${out.length} vectors to ${fixturePath}`);
}
