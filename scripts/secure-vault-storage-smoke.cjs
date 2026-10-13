// Storage-layer regression tests for lib/secureVault.js and the key-cache sweep
// in lib/walletUtils.js (runs offline under plain Node):
//   - a write superseded by another page is never overwritten and is reported
//     as a failed migration instead of a success
//   - a failed verification rolls our write back and leaves the prior blob
//     intact, both in the live key and in the backup slots
//   - password changes keep the displaced blob; stale writers are refused
//   - restoreFromBackup verifies the backup before writing and keeps what it
//     displaces
//   - the key-cache sweep removes key caches but never their backups
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const esbuild = require('esbuild');
const CryptoJS = require('crypto-js');

const ROOT = path.resolve(__dirname, '..');
const SEED = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const OLD_PASSWORD = 'old password';
const SEED_KIND = 'seed';

// Minimal localStorage with a hook that runs right after every setItem, so a
// test can make another page's write land at an exact point in our sequence.
const makeStorage = () => {
  const map = new Map();
  const hooks = { afterSet: null };
  const store = {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => {
      map.set(key, String(value));
      if (hooks.afterSet) hooks.afterSet(key, String(value));
    },
    removeItem: (key) => {
      map.delete(key);
    },
    key: (index) => (index < map.size ? [...map.keys()][index] : null),
    get length() {
      return map.size;
    },
  };
  return { store, map, hooks };
};

(async () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-vault-storage-smoke-'));
  try {
    const vaultFile = path.join(outDir, 'secureVault.cjs');
    esbuild.buildSync({
      entryPoints: [path.join(ROOT, 'lib', 'secureVault.js')],
      bundle: true,
      platform: 'node',
      format: 'cjs',
      outfile: vaultFile,
      logLevel: 'silent',
    });
    const vault = require(vaultFile);

    // walletUtils pulls in bitcoinjs-lib, whose ESM entry does not bundle for
    // Node; alias it to the CJS build, as the round-2 probes do.
    const walletFile = path.join(outDir, 'walletUtils.cjs');
    await esbuild.build({
      entryPoints: [path.join(ROOT, 'lib', 'walletUtils.js')],
      bundle: true,
      platform: 'node',
      format: 'cjs',
      outfile: walletFile,
      logLevel: 'silent',
      plugins: [{
        name: 'bitcoinjs-cjs',
        setup(build) {
          build.onResolve({ filter: /^bitcoinjs-lib$/ }, () => ({
            path: path.join(ROOT, 'node_modules', 'bitcoinjs-lib', 'src', 'cjs', 'index.cjs'),
          }));
        },
      }],
    });
    globalThis.chrome = { storage: { local: { get: (_, cb) => cb && cb({}), set: (_, cb) => cb && cb() } }, runtime: {} };
    const wallet = require(walletFile);

    const useStorage = () => {
      const storage = makeStorage();
      globalThis.localStorage = storage.store;
      return storage;
    };
    const legacySeed = CryptoJS.AES.encrypt(SEED, OLD_PASSWORD).toString();

    // --- 1. another page writes right after our migration write ---
    {
      const { map, hooks } = useStorage();
      map.set('encryptedSeed', legacySeed);
      const foreign = await vault.encryptWithPassword(SEED, 'reset in other tab');
      hooks.afterSet = (key, value) => {
        if (key === 'encryptedSeed' && value !== legacySeed) {
          hooks.afterSet = null;
          map.set('encryptedSeed', foreign);
        }
      };
      const result = await vault.maybeUpgradeStoredBlob('encryptedSeed', legacySeed, SEED, OLD_PASSWORD, SEED_KIND);
      assert.equal(result, null, 'a migration superseded by another page must report failure');
      assert.equal(map.get('encryptedSeed'), foreign, 'the newer foreign blob must not be overwritten');
      assert.equal(map.get('encryptedSeed.prev'), legacySeed, 'the displaced blob stays recoverable');
      assert.equal(
        await vault.decryptWithPassword(map.get('encryptedSeed'), 'reset in other tab', SEED_KIND),
        SEED
      );
    }

    // --- 2. verification failure rolls back our write, prior blob intact ---
    {
      const { map } = useStorage();
      map.set('encryptedSeed', legacySeed);
      // The next decrypt is the verify step of the write; fail it once.
      const subtle = globalThis.crypto.subtle;
      subtle.decrypt = async () => {
        delete subtle.decrypt;
        throw new Error('injected verify failure');
      };
      await assert.rejects(
        () => vault.replaceStoredBlob('encryptedSeed', legacySeed, SEED, 'fresh password 1', SEED_KIND),
        /Failed to decrypt/
      );
      assert.equal(map.get('encryptedSeed'), legacySeed, 'prior blob must be restored byte-for-byte');
      assert.equal(map.get('encryptedSeed.bak'), legacySeed, 'one-time backup holds the prior blob');
      assert.equal(map.get('encryptedSeed.prev'), legacySeed, 'displaced blob kept in .prev');
    }

    // --- 3. password change keeps the displaced blob; stale writers refused ---
    {
      const { map } = useStorage();
      map.set('encryptedSeed', legacySeed);
      const upgraded = await vault.maybeUpgradeStoredBlob('encryptedSeed', legacySeed, SEED, OLD_PASSWORD, SEED_KIND);
      assert.ok(upgraded, 'the correct password must migrate');
      const reset = await vault.replaceStoredBlob('encryptedSeed', upgraded, SEED, 'brand new password', SEED_KIND);
      assert.equal(map.get('encryptedSeed'), reset);
      assert.equal(map.get('encryptedSeed.bak'), legacySeed, '.bak stays the first blob ever displaced');
      assert.equal(map.get('encryptedSeed.prev'), upgraded, '.prev holds the blob this reset displaced');
      assert.equal(await vault.decryptWithPassword(reset, 'brand new password', SEED_KIND), SEED);

      // A writer that validated against the pre-reset blob must not overwrite the reset.
      await assert.rejects(
        () => vault.replaceStoredBlob('encryptedSeed', upgraded, SEED, 'stale password', SEED_KIND),
        /changed concurrently/
      );
      assert.equal(map.get('encryptedSeed'), reset);

      // Invalid input is refused before anything is written.
      await assert.rejects(
        () => vault.replaceStoredBlob('encryptedSeed', reset, 'not a mnemonic', 'brand new password', SEED_KIND),
        /fails plaintext validation/
      );
      await assert.rejects(
        () => vault.replaceStoredBlob('encryptedSeed', reset, SEED, 'brand new password'),
        /expected plaintext kind/
      );
      assert.equal(map.get('encryptedSeed'), reset);

      // The migration helper never throws, even for an unknown kind.
      assert.equal(
        await vault.maybeUpgradeStoredBlob('encryptedSeed', legacySeed, SEED, OLD_PASSWORD, 'bogus'),
        null
      );
    }

    // --- 4. restoreFromBackup: verify first, keep what it displaces ---
    {
      const { map } = useStorage();
      const current = await vault.encryptWithPassword(SEED, 'password of current blob');
      map.set('encryptedSeed', current);
      map.set('encryptedSeed.bak', legacySeed);
      await assert.rejects(
        () => vault.restoreFromBackup('encryptedSeed', 'wrong password'),
        /Failed to decrypt/
      );
      assert.equal(map.get('encryptedSeed'), current, 'a failed restore must change nothing');
      assert.equal(map.has('encryptedSeed.prev'), false, 'a failed restore must write no backup');

      assert.equal(await vault.restoreFromBackup('encryptedSeed', OLD_PASSWORD), legacySeed);
      assert.equal(map.get('encryptedSeed'), legacySeed);
      assert.equal(map.get('encryptedSeed.prev'), current, 'the blob the restore displaced is kept');
      assert.equal(map.get('encryptedSeed.bak'), legacySeed);
      assert.equal(await vault.restoreFromBackup('encryptedSeed', OLD_PASSWORD), legacySeed, 'restore is idempotent');

      map.delete('encryptedSeed.bak');
      assert.equal(await vault.restoreFromBackup('encryptedSeed', OLD_PASSWORD), null, 'no backup, nothing to restore');
    }

    // --- 5. seed writes serialize on the origin-wide Web Lock when present ---
    {
      const { map } = useStorage();
      const requested = [];
      let queue = Promise.resolve();
      const locks = {
        request(name, callback) {
          requested.push(name);
          const run = queue.then(() => callback());
          queue = run.catch(() => {});
          return run;
        },
      };
      const realNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
      Object.defineProperty(globalThis, 'navigator', { value: { locks }, configurable: true });
      try {
        map.set('encryptedSeed', legacySeed);
        const upgraded = await vault.maybeUpgradeStoredBlob('encryptedSeed', legacySeed, SEED, OLD_PASSWORD, SEED_KIND);
        assert.ok(upgraded, 'the write must still succeed under the lock');
        assert.deepEqual(requested, ['tl-extension:vault-writes'], 'every seed write takes the vault lock');
        await assert.rejects(
          () => vault.replaceStoredBlob('encryptedSeed', legacySeed, SEED, 'stale password', SEED_KIND),
          /changed concurrently/
        );
        assert.equal(map.get('encryptedSeed'), upgraded);
      } finally {
        if (realNavigator) {
          Object.defineProperty(globalThis, 'navigator', realNavigator);
        } else {
          delete globalThis.navigator;
        }
      }
    }

    // --- 6. key-cache namespace and sweep ---
    const cacheKey = 'encryptedPrivateKey:LTC:m_44_2_0_0_0';
    assert.equal(vault.isPrivateKeyCacheKey(cacheKey), true);
    assert.equal(vault.isPrivateKeyCacheKey(`${cacheKey}.bak`), false);
    assert.equal(vault.isPrivateKeyCacheKey(`${cacheKey}.prev`), false);
    assert.equal(vault.isPrivateKeyCacheKey('encryptedSeed'), false);
    assert.equal(vault.isPrivateKeyCacheKey('encryptedKey'), false);
    assert.equal(vault.isPrivateKeyCacheKey(null), false);
    assert.equal(vault.isVaultBackupKey('encryptedSeed.bak'), true);
    assert.equal(vault.isVaultBackupKey('encryptedSeed.prev'), true);
    assert.equal(vault.isVaultBackupKey('encryptedSeed'), false);

    {
      const { map } = useStorage();
      map.set('encryptedSeed', legacySeed);
      map.set('encryptedSeed.bak', legacySeed);
      map.set(cacheKey, 'cache-blob');
      map.set(`${cacheKey}.bak`, 'cache-backup');
      map.set(`${cacheKey}.prev`, 'cache-prev');
      map.set('encryptedKey', 'legacy-key');
      wallet.clearPrivateKeyCaches();
      assert.equal(map.has(cacheKey), false, 'key caches are swept');
      assert.equal(map.has('encryptedKey'), false, 'legacy key entry is swept');
      assert.equal(map.get(`${cacheKey}.bak`), 'cache-backup', 'key-cache backups must survive the sweep');
      assert.equal(map.get(`${cacheKey}.prev`), 'cache-prev', 'key-cache .prev must survive the sweep');
      assert.equal(map.get('encryptedSeed'), legacySeed, 'seed is never swept');
      assert.equal(map.get('encryptedSeed.bak'), legacySeed);
    }

    console.log('[unit] secure vault storage smoke test passed');
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
