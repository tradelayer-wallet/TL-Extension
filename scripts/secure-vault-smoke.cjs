// Sanity smoke test for lib/secureVault.js (runs offline under plain Node):
//   - v2 vault (PBKDF2-SHA256 600k + AES-256-GCM) round-trip and format checks
//   - v2 parameter hardening: only PBKDF2_ITERATIONS is accepted, so KDF
//     downgrade / DoS iteration counts are rejected before any derivation
//   - legacy CryptoJS blob detection + decrypt fallback (transparent migration)
//   - legacy plaintext validation: wrong-password garbage must never be
//     accepted nor migrated over the real ciphertext (seed-loss fix)
//   - empty-password handling (legacy read path only)
//   - wrong-password / tamper handling for both formats
// The vault module is ESM for the extension bundle, so it is bundled to CJS
// with esbuild (a devDependency already required by build.js) before testing.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const esbuild = require('esbuild');

const ROOT = path.resolve(__dirname, '..');

const bundleVault = () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-vault-smoke-'));
  const outfile = path.join(outDir, 'secureVault.cjs');
  esbuild.buildSync({
    entryPoints: [path.join(ROOT, 'lib', 'secureVault.js')],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    outfile,
    logLevel: 'silent',
  });
  return { outDir, outfile };
};

const b64Json = (blob) =>
  JSON.parse(Buffer.from(blob, 'base64').toString('utf8'));

// Build a v2 envelope with an arbitrary iteration count (the vault module only
// ever writes PBKDF2_ITERATIONS, so crafted values must be built by hand).
const buildEnvelopeWithIter = async (text, password, iter) => {
  const enc = new TextEncoder();
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const baseKey = await webcrypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  const payload = {
    v: 2,
    kdf: 'pbkdf2-sha256',
    iter,
    salt: Buffer.from(salt).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    ct: Buffer.from(new Uint8Array(ct)).toString('base64'),
  };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
};

(async () => {
  const { outDir, outfile } = bundleVault();
  try {
    const vault = require(outfile);
    const CryptoJS = require('crypto-js');

    const {
      encryptWithPassword,
      decryptWithPassword,
      decryptWithPasswordInfo,
      isLegacyVaultBlob,
      maybeUpgradeStoredBlob,
      validateSeedPlaintext,
      validatePrivateKeyPlaintext,
      checkNewPasswordPolicy,
      PLAINTEXT_KIND,
      VAULT_VERSION,
      KDF_NAME,
      PBKDF2_ITERATIONS,
    } = vault;

    // A real BIP39 mnemonic: legacy seed decryptions are only accepted when
    // they validate as one.
    const plaintext = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    assert.equal(validateSeedPlaintext(plaintext), true);
    const blob = await encryptWithPassword(plaintext, 'correct horse battery staple');

    // --- v2 round trip ---
    assert.equal(typeof blob, 'string');
    assert.equal(isLegacyVaultBlob(blob), false);

    const payload = b64Json(blob);
    assert.equal(payload.v, VAULT_VERSION);
    assert.equal(payload.v, 2);
    assert.equal(payload.kdf, KDF_NAME);
    assert.equal(payload.kdf, 'pbkdf2-sha256');
    assert.equal(payload.iter, PBKDF2_ITERATIONS);
    assert.equal(payload.iter, 600000);
    assert.equal(Buffer.from(payload.salt, 'base64').length, 16, 'salt must be 16 bytes');
    assert.equal(Buffer.from(payload.iv, 'base64').length, 12, 'iv must be 12 bytes');
    assert.ok(payload.ct.length > 0);

    assert.equal(await decryptWithPassword(blob, 'correct horse battery staple'), plaintext);
    const info = await decryptWithPasswordInfo(blob, 'correct horse battery staple', PLAINTEXT_KIND.SEED);
    assert.equal(info.plaintext, plaintext);
    assert.equal(info.legacy, false);

    // Unicode + empty-string round trips (v2 is authenticated; no expect needed).
    const unicode = 'seed 🌱 phrase ✓';
    assert.equal(await decryptWithPassword(await encryptWithPassword(unicode, 'pw-1'), 'pw-1'), unicode);
    assert.equal(await decryptWithPassword(await encryptWithPassword('', 'pw-1'), 'pw-1'), '');

    // Per-item salt/IV: identical plaintexts must not produce identical blobs.
    const blobAgain = await encryptWithPassword(plaintext, 'correct horse battery staple');
    assert.notEqual(blobAgain, blob, 'fresh salt/IV must be used per encryption');

    // --- v2 failure modes ---
    await assert.rejects(
      () => decryptWithPassword(blob, 'wrong password'),
      /Failed to decrypt/,
      'v2 wrong password must throw'
    );
    const tamperedPayload = b64Json(blob);
    tamperedPayload.ct = tamperedPayload.ct.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
    const tamperedBlob = Buffer.from(JSON.stringify(tamperedPayload), 'utf8').toString('base64');
    await assert.rejects(
      () => decryptWithPassword(tamperedBlob, 'correct horse battery staple'),
      /Failed to decrypt/,
      'v2 tampered ciphertext must fail GCM authentication'
    );
    await assert.rejects(
      () => decryptWithPassword('not-a-vault-blob', 'pw', PLAINTEXT_KIND.SEED),
      /Failed to decrypt/,
      'garbage blobs must throw'
    );
    await assert.rejects(
      () => decryptWithPassword('not-a-vault-blob', 'pw'),
      /without an expected plaintext kind/,
      'legacy-path decryptions without an expected kind must refuse'
    );

    // --- fix 3: KDF downgrade / popup-DoS iteration counts must be rejected
    //     before any derivation happens (and never fall back to legacy) ---
    const weakKdfBlob = await buildEnvelopeWithIter(plaintext, 'pw-1', 1000);
    const weakStart = Date.now();
    await assert.rejects(
      () => decryptWithPasswordInfo(weakKdfBlob, 'pw-1', PLAINTEXT_KIND.SEED),
      /unsupported vault parameters/,
      'iter: 1000 (KDF downgrade) must be rejected'
    );
    assert.ok(Date.now() - weakStart < 500, 'iter rejection must not run the KDF');

    const dosKdfBlob = await buildEnvelopeWithIter(plaintext, 'pw-1', 10000000);
    const dosStart = Date.now();
    await assert.rejects(
      () => decryptWithPasswordInfo(dosKdfBlob, 'pw-1', PLAINTEXT_KIND.SEED),
      /unsupported vault parameters/,
      'iter: 10,000,000 (popup DoS) must be rejected'
    );
    assert.ok(Date.now() - dosStart < 500, 'a 10M-iteration KDF must never be run');

    // Exact-match policy: no build ever wrote any count but PBKDF2_ITERATIONS,
    // so even an in-band count (400k) is rejected rather than tolerated.
    const inBandBlob = await buildEnvelopeWithIter(plaintext, 'pw-1', 400000);
    await assert.rejects(
      () => decryptWithPasswordInfo(inBandBlob, 'pw-1', PLAINTEXT_KIND.SEED),
      /unsupported vault parameters/,
      'iter: 400000 (not PBKDF2_ITERATIONS) must be rejected'
    );

    // --- plaintext-shape validators (fix 1 foundation) ---
    assert.equal(validateSeedPlaintext(plaintext), true);
    assert.equal(validateSeedPlaintext(`  ${plaintext}  `), true);
    assert.equal(validateSeedPlaintext('not a valid mnemonic at all'), false);
    assert.equal(validateSeedPlaintext('67Tt83Uf4PqVj2cXwZ9rNq1LkM'), false);

    const keyB64 = Buffer.alloc(32, 7).toString('base64');
    assert.equal(validatePrivateKeyPlaintext(keyB64), true);
    assert.equal(validatePrivateKeyPlaintext(Buffer.alloc(31, 7).toString('base64')), false);
    assert.equal(validatePrivateKeyPlaintext(Buffer.alloc(33, 7).toString('base64')), false);
    assert.equal(validatePrivateKeyPlaintext('!!! not base64 !!!'), false);
    assert.equal(validatePrivateKeyPlaintext(Buffer.alloc(32, 7).toString('hex')), false);
    assert.equal(validatePrivateKeyPlaintext(plaintext), false, 'mnemonics are not key caches');
    // Same 32 bytes, but the final character carries non-zero pad bits: not
    // the canonical encoding, so it must be rejected.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const nonCanonicalKeyB64 = keyB64.slice(0, 42) + alphabet[alphabet.indexOf(keyB64[42]) | 1] + '=';
    assert.equal(
      Buffer.from(nonCanonicalKeyB64, 'base64').equals(Buffer.from(keyB64, 'base64')),
      true,
      'fixture must decode to the same 32 bytes'
    );
    assert.equal(validatePrivateKeyPlaintext(nonCanonicalKeyB64), false, 'non-canonical base64 must be rejected');

    // --- new-password policy (fix 5) ---
    assert.equal(checkNewPasswordPolicy('long enough password'), null);
    assert.match(checkNewPasswordPolicy(''), /empty/);
    assert.match(checkNewPasswordPolicy('short'), /at least 8/);

    // --- legacy CryptoJS fallback + detection ---
    const legacyBlob = CryptoJS.AES.encrypt(plaintext, 'old password').toString();
    assert.equal(isLegacyVaultBlob(legacyBlob), true, 'legacy blobs start with base64 "Salted__"');
    assert.ok(legacyBlob.startsWith('U2FsdGVkX1'));

    const legacyInfo = await decryptWithPasswordInfo(legacyBlob, 'old password', PLAINTEXT_KIND.SEED);
    assert.equal(legacyInfo.plaintext, plaintext);
    assert.equal(legacyInfo.legacy, true, 'legacy decrypts must be reported for migration');
    assert.equal(await decryptWithPassword(legacyBlob, 'old password', PLAINTEXT_KIND.SEED), plaintext);

    // Legacy decryptions are unauthenticated: never run them without a
    // plaintext shape to validate against.
    await assert.rejects(
      () => decryptWithPasswordInfo(legacyBlob, 'old password'),
      /without an expected plaintext kind/,
      'legacy decryptions must require an expected plaintext kind'
    );

    await assert.rejects(
      () => decryptWithPassword(legacyBlob, 'wrong password', PLAINTEXT_KIND.SEED),
      /Failed to decrypt/,
      'legacy wrong password must throw'
    );

    // --- fix 1: legacy decrypt garbage must NOT validate or migrate ---
    // Deterministic half: a legacy blob whose CORRECT decryption is not a
    // mnemonic must be rejected exactly like a wrong password.
    const nonMnemonicBlob = CryptoJS.AES.encrypt('definitely not a mnemonic', 'pw-x').toString();
    await assert.rejects(
      () => decryptWithPasswordInfo(nonMnemonicBlob, 'pw-x', PLAINTEXT_KIND.SEED),
      /Failed to decrypt/,
      'legacy decrypts that are not a valid mnemonic must be treated as wrong password'
    );

    // Real half: find a wrong password whose legacy decrypt yields non-empty
    // garbage (the red team's measured ~0.5% false-positive class) and prove
    // it is neither accepted nor migrated.
    let garbagePassword = null;
    let garbagePlaintext = null;
    for (let i = 0; i < 20000 && !garbagePassword; i += 1) {
      const candidate = `typo-${i}-password`;
      let out = null;
      try {
        out = CryptoJS.AES.decrypt(legacyBlob, candidate).toString(CryptoJS.enc.Utf8);
      } catch (_) {
        out = null;
      }
      if (out) {
        garbagePassword = candidate;
        garbagePlaintext = out;
      }
    }
    assert.ok(garbagePassword, 'expected a wrong password with a non-empty garbage decrypt (~0.5% measured)');
    assert.notEqual(garbagePlaintext, plaintext);
    assert.equal(validateSeedPlaintext(garbagePlaintext), false, 'garbage must not validate as a seed');

    await assert.rejects(
      () => decryptWithPasswordInfo(legacyBlob, garbagePassword, PLAINTEXT_KIND.SEED),
      /Failed to decrypt/,
      'wrong-password garbage must never be accepted'
    );

    // --- transparent migration helper (localStorage-backed) ---
    const store = new Map();
    globalThis.localStorage = {
      getItem: (key) => (store.has(key) ? store.get(key) : null),
      setItem: (key, value) => store.set(key, String(value)),
      removeItem: (key) => store.delete(key),
    };

    // Garbage must never be written over the real ciphertext (the original
    // seed-loss exploit).
    store.set('encryptedSeed', legacyBlob);
    const garbageUpgrade = await maybeUpgradeStoredBlob(
      'encryptedSeed', legacyBlob, garbagePlaintext, garbagePassword, PLAINTEXT_KIND.SEED
    );
    assert.equal(garbageUpgrade, null, 'garbage must not migrate');
    assert.equal(store.get('encryptedSeed'), legacyBlob, 'stored ciphertext must be untouched');
    assert.equal(store.has('encryptedSeed.bak'), false, 'no migration means no write at all');

    // A migration without an expected kind must also be refused.
    assert.equal(
      await maybeUpgradeStoredBlob('encryptedSeed', legacyBlob, garbagePlaintext, garbagePassword),
      null,
      'migration without a plaintext kind must be refused'
    );
    assert.equal(store.get('encryptedSeed'), legacyBlob);

    // The correct password still migrates — and a one-time .bak of the old
    // blob is kept before the first overwrite.
    const upgraded = await maybeUpgradeStoredBlob('encryptedSeed', legacyBlob, plaintext, 'old password', PLAINTEXT_KIND.SEED);
    assert.ok(upgraded, 'upgrade should produce a new blob');
    assert.equal(store.get('encryptedSeed'), upgraded, 'stored blob must be rewritten');
    assert.equal(b64Json(upgraded).v, 2, 'upgraded blob must be v2');
    assert.equal(await decryptWithPassword(store.get('encryptedSeed'), 'old password', PLAINTEXT_KIND.SEED), plaintext);
    assert.equal(store.get('encryptedSeed.bak'), legacyBlob, 'one-time backup of the pre-migration blob');

    // The backup is one-time: later migrations never clobber the original.
    const secondMnemonic = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    assert.equal(validateSeedPlaintext(secondMnemonic), true);
    const secondLegacyBlob = CryptoJS.AES.encrypt(secondMnemonic, 'old password 2').toString();
    store.set('encryptedSeed', secondLegacyBlob);
    const secondUpgrade = await maybeUpgradeStoredBlob('encryptedSeed', secondLegacyBlob, secondMnemonic, 'old password 2', PLAINTEXT_KIND.SEED);
    assert.ok(secondUpgrade);
    assert.equal(store.get('encryptedSeed.bak'), legacyBlob, '.bak must keep the FIRST pre-migration blob');

    // Stale writes must not clobber concurrent updates.
    store.set('encryptedSeed', legacyBlob);
    const stale = await maybeUpgradeStoredBlob('encryptedSeed', 'some-other-blob', plaintext, 'old password', PLAINTEXT_KIND.SEED);
    assert.equal(stale, null);
    assert.equal(store.get('encryptedSeed'), legacyBlob, 'stale upgrade must not write');

    // --- key-cache plaintexts must be base64 of exactly 32 bytes ---
    const legacyKeyBlob = CryptoJS.AES.encrypt(keyB64, 'old password').toString();
    const keyInfo = await decryptWithPasswordInfo(legacyKeyBlob, 'old password', PLAINTEXT_KIND.PRIVATE_KEY);
    assert.equal(keyInfo.plaintext, keyB64);
    assert.equal(keyInfo.legacy, true);
    await assert.rejects(
      () => decryptWithPasswordInfo(legacyKeyBlob, 'old password', PLAINTEXT_KIND.SEED),
      /Failed to decrypt/,
      'a key cache must not validate as a seed'
    );

    const badKeyBlob = CryptoJS.AES.encrypt('not-a-32-byte-key', 'old password').toString();
    await assert.rejects(
      () => decryptWithPasswordInfo(badKeyBlob, 'old password', PLAINTEXT_KIND.PRIVATE_KEY),
      /Failed to decrypt/,
      'legacy key caches must decode to exactly 32 bytes'
    );

    // --- fix 2: empty-password legacy wallets stay readable; v2 still
    //     refuses empty passwords for reading and writing ---
    const emptyPwBlob = CryptoJS.AES.encrypt(plaintext, '').toString();
    const emptyInfo = await decryptWithPasswordInfo(emptyPwBlob, '', PLAINTEXT_KIND.SEED);
    assert.equal(emptyInfo.plaintext, plaintext, 'legacy empty-password blobs must decrypt');
    assert.equal(emptyInfo.legacy, true);

    await assert.rejects(
      () => decryptWithPassword(blob, '', PLAINTEXT_KIND.SEED),
      /Failed to decrypt/,
      'v2 blobs must reject empty passwords'
    );
    await assert.rejects(
      () => encryptWithPassword(plaintext, ''),
      /non-empty/,
      'new v2 encryption must still reject empty passwords'
    );

    // Migration with an empty password must not write a v2 blob.
    store.set('encryptedSeed', emptyPwBlob);
    assert.equal(
      await maybeUpgradeStoredBlob('encryptedSeed', emptyPwBlob, plaintext, '', PLAINTEXT_KIND.SEED),
      null,
      'no v2 write is possible without a password'
    );
    assert.equal(store.get('encryptedSeed'), emptyPwBlob, 'the legacy blob must stay in place');

    console.log('[unit] secure vault smoke test passed');
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
