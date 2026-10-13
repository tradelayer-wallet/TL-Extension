// Sanity smoke test for lib/secureVault.js (runs offline under plain Node):
//   - v2 vault (PBKDF2-SHA256 600k + AES-256-GCM) round-trip and format checks
//   - legacy CryptoJS blob detection + decrypt fallback (transparent migration)
//   - wrong-password / tamper handling for both formats
// The vault module is ESM for the extension bundle, so it is bundled to CJS
// with esbuild (a devDependency already required by build.js) before testing.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
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
      VAULT_VERSION,
      KDF_NAME,
      PBKDF2_ITERATIONS,
    } = vault;

    // --- v2 round trip ---
    const plaintext = 'abandon ability able about above absent absorb abstract absurd abuse';
    const blob = await encryptWithPassword(plaintext, 'correct horse battery staple');

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
    const info = await decryptWithPasswordInfo(blob, 'correct horse battery staple');
    assert.equal(info.plaintext, plaintext);
    assert.equal(info.legacy, false);

    // Unicode + empty-string round trips.
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
      () => decryptWithPassword('not-a-vault-blob', 'pw'),
      /Failed to decrypt/,
      'garbage blobs must throw'
    );

    // --- legacy CryptoJS fallback + detection ---
    const legacyBlob = CryptoJS.AES.encrypt(plaintext, 'old password').toString();
    assert.equal(isLegacyVaultBlob(legacyBlob), true, 'legacy blobs start with base64 "Salted__"');
    assert.ok(legacyBlob.startsWith('U2FsdGVkX1'));

    const legacyInfo = await decryptWithPasswordInfo(legacyBlob, 'old password');
    assert.equal(legacyInfo.plaintext, plaintext);
    assert.equal(legacyInfo.legacy, true, 'legacy decrypts must be reported for migration');
    assert.equal(await decryptWithPassword(legacyBlob, 'old password'), plaintext);

    await assert.rejects(
      () => decryptWithPassword(legacyBlob, 'wrong password'),
      /Failed to decrypt/,
      'legacy wrong password must throw'
    );

    // --- transparent migration helper ---
    const store = new Map();
    globalThis.localStorage = {
      getItem: (key) => (store.has(key) ? store.get(key) : null),
      setItem: (key, value) => store.set(key, String(value)),
      removeItem: (key) => store.delete(key),
    };

    store.set('encryptedSeed', legacyBlob);
    const upgraded = await maybeUpgradeStoredBlob('encryptedSeed', legacyBlob, plaintext, 'old password');
    assert.ok(upgraded, 'upgrade should produce a new blob');
    assert.equal(store.get('encryptedSeed'), upgraded, 'stored blob must be rewritten');
    assert.equal(b64Json(upgraded).v, 2, 'upgraded blob must be v2');
    assert.equal(await decryptWithPassword(store.get('encryptedSeed'), 'old password'), plaintext);

    // Stale writes must not clobber concurrent updates.
    store.set('encryptedSeed', legacyBlob);
    const stale = await maybeUpgradeStoredBlob('encryptedSeed', 'some-other-blob', plaintext, 'old password');
    assert.equal(stale, null);
    assert.equal(store.get('encryptedSeed'), legacyBlob, 'stale upgrade must not write');

    console.log('[unit] secure vault smoke test passed');
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
