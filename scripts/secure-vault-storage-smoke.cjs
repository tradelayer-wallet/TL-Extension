// Storage-layer regression tests for lib/secureVault.js and the key-cache sweep
// in lib/walletUtils.js (runs offline under plain Node):
//   - a write superseded by another page is never overwritten and is reported
//     as a failed migration instead of a success
//   - a failed verification rolls our write back and leaves the prior blob
//     intact, both in the live key and in the backup slots
//   - password changes keep the displaced blob; stale writers are refused
//   - restoreFromBackup verifies the backup before writing and keeps what it
//     displaces; it can recover from the .bak or the .prev slot
//   - a completed write leaves no displaced copy behind (.prev is dropped)
//   - derived key caches are never backed up
//   - the only localStorage writes outside lib/secureVault.js are non-vault keys
//   - the key-cache sweep removes key caches but never their backups
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const esbuild = require('esbuild');
const CryptoJS = require('crypto-js');
// Vault writes need navigator.locks. Node 24 has it natively; older Node does
// not, so give these single-process tests a FIFO lock with the same semantics.
if (!globalThis.navigator || !globalThis.navigator.locks) {
  let lockTail = Promise.resolve();
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: {
      locks: {
        request(_name, callback) {
          const run = lockTail.then(() => callback());
          lockTail = run.catch(() => {});
          return run;
        },
      },
    },
  });
}

const ROOT = path.resolve(__dirname, '..');
const SEED = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const OLD_PASSWORD = 'old password';
const SEED_KIND = 'seed';

// Minimal localStorage with hooks around every setItem: beforeSet can throw to
// simulate an interruption before a write lands, afterSet runs once it has
// landed, so a test can make another page's write land at an exact point.
const makeStorage = () => {
  const map = new Map();
  const hooks = { beforeSet: null, afterSet: null };
  const store = {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => {
      if (hooks.beforeSet) hooks.beforeSet(key, String(value));
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
      const v2Prior = await vault.encryptWithPassword(SEED, 'pw-prior-2');
      map.set('encryptedSeed', v2Prior);
      // The next decrypt is the verify step of the write; fail it once.
      const subtle = globalThis.crypto.subtle;
      subtle.decrypt = async () => {
        delete subtle.decrypt;
        throw new Error('injected verify failure');
      };
      await assert.rejects(
        () => vault.replaceStoredBlob('encryptedSeed', v2Prior, SEED, 'fresh password 1', SEED_KIND),
        /Failed to decrypt/
      );
      assert.equal(map.get('encryptedSeed'), v2Prior, 'prior blob must be restored byte-for-byte');
      assert.equal(map.get('encryptedSeed.bak'), v2Prior, 'one-time backup holds the first v2 blob displaced');
      assert.equal(map.has('encryptedSeed.prev'), false, 'a completed rollback leaves no displaced copy behind');
    }

    // --- 3. password change keeps the displaced blob; stale writers refused ---
    {
      const { map } = useStorage();
      map.set('encryptedSeed', legacySeed);
      const upgraded = await vault.maybeUpgradeStoredBlob('encryptedSeed', legacySeed, SEED, OLD_PASSWORD, SEED_KIND);
      assert.ok(upgraded, 'the correct password must migrate');
      const reset = await vault.replaceStoredBlob('encryptedSeed', upgraded, SEED, 'brand new password', SEED_KIND);
      assert.equal(map.get('encryptedSeed'), reset);
      assert.equal(map.get('encryptedSeed.bak'), upgraded, '.bak holds the first v2 blob ever displaced');
      assert.equal(map.has('encryptedSeed.prev'), false, 'a verified reset drops the displaced blob from .prev');
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

    // --- 4b. an interrupted write is recoverable from .prev ---
    {
      const { map, hooks } = useStorage();
      const priorBlob = await vault.encryptWithPassword(SEED, 'pw-prior-1');
      map.set('encryptedSeed', priorBlob);
      map.set('encryptedSeed.bak', legacySeed);
      // The verify step of the new write fails, and the rollback write is
      // interrupted before it lands (a crash or quota error at that point).
      const subtle = globalThis.crypto.subtle;
      subtle.decrypt = async () => {
        delete subtle.decrypt;
        throw new Error('injected verify failure');
      };
      hooks.beforeSet = (key, value) => {
        if (key === 'encryptedSeed' && value === priorBlob) {
          hooks.beforeSet = null;
          throw new Error('interrupted before the rollback landed');
        }
      };
      await assert.rejects(
        () => vault.replaceStoredBlob('encryptedSeed', priorBlob, SEED, 'pw-new-2', SEED_KIND),
        /interrupted before the rollback landed/
      );
      const unverified = map.get('encryptedSeed');
      assert.notEqual(unverified, priorBlob, 'the interrupted write left the new blob in the live key');
      assert.equal(map.get('encryptedSeed.prev'), priorBlob, 'the displaced blob is kept in .prev for recovery');

      // The .bak slot holds an older password, so it cannot restore this seed.
      await assert.rejects(
        () => vault.restoreFromBackup('encryptedSeed', 'pw-prior-1', SEED_KIND, 'bak'),
        /Failed to decrypt/
      );
      assert.equal(map.get('encryptedSeed'), unverified, 'a failed restore changes nothing');

      assert.equal(
        await vault.restoreFromBackup('encryptedSeed', 'pw-prior-1', SEED_KIND, 'prev'),
        priorBlob,
        'restore must be able to recover from .prev'
      );
      assert.equal(map.get('encryptedSeed'), priorBlob);
      // .prev already held the good copy that is now live. The unverified value
      // that was live is not allowed to replace it.
      assert.equal(map.get('encryptedSeed.prev'), priorBlob, 'the restore keeps the existing recovery copy in .prev');
      assert.equal(await vault.decryptWithPassword(map.get('encryptedSeed'), 'pw-prior-1', SEED_KIND), SEED);

      await assert.rejects(
        () => vault.restoreFromBackup('encryptedSeed', 'pw-prior-1', SEED_KIND, 'main'),
        /Unknown backup slot/
      );
      await assert.rejects(
        () => vault.restoreFromBackup('encryptedPrivateKey:LTC:m_44_2_0_0_0', 'pw-prior-1', SEED_KIND, 'bak'),
        /Only the seed/
      );
      hooks.beforeSet = null;
    }

    // --- 4c. a failed cleanup of .prev never turns a verified write into a failure ---
    {
      const { map } = useStorage();
      map.set('encryptedSeed', legacySeed);
      const store = globalThis.localStorage;
      const realRemove = store.removeItem;
      store.removeItem = (key) => {
        if (key === 'encryptedSeed.prev') throw new Error('quota: cleanup failed');
        realRemove(key);
      };
      try {
        const reset = await vault.replaceStoredBlob('encryptedSeed', legacySeed, SEED, 'pw-cleanup-3', SEED_KIND);
        assert.equal(map.get('encryptedSeed'), reset, 'the verified write must stand');
        assert.equal(await vault.decryptWithPassword(reset, 'pw-cleanup-3', SEED_KIND), SEED);
      } finally {
        store.removeItem = realRemove;
      }
    }

    // --- 4d. derived key caches are re-derivable, so they never get backups ---
    const cacheKey = 'encryptedPrivateKey:LTC:m_44_2_0_0_0';
    {
      const { map } = useStorage();
      const keyB64 = Buffer.alloc(32, 9).toString('base64');
      const legacyKey = CryptoJS.AES.encrypt(keyB64, OLD_PASSWORD).toString();
      map.set(cacheKey, legacyKey);
      // A cache is only written while the live seed opens under its password.
      const orphan = await vault.maybeUpgradeStoredBlob(cacheKey, legacyKey, keyB64, OLD_PASSWORD, 'privateKey');
      assert.equal(orphan, null, 'a cache with no live seed must not be migrated');
      assert.equal(map.get(cacheKey), legacyKey, 'a refused migration changes nothing');
      map.set('encryptedSeed', await vault.encryptWithPassword(SEED, OLD_PASSWORD));
      const upgraded = await vault.maybeUpgradeStoredBlob(cacheKey, legacyKey, keyB64, OLD_PASSWORD, 'privateKey');
      assert.ok(upgraded, 'the legacy key cache must upgrade');
      assert.equal(map.get(cacheKey), upgraded);
      assert.equal(map.has(`${cacheKey}.bak`), false, 'key caches keep no .bak copy');
      assert.equal(map.has(`${cacheKey}.prev`), false, 'key caches keep no .prev copy');
    }

    // --- 4e. storeKeyCacheBlob: the only door for an already-encrypted key cache ---
    {
      const { map } = useStorage();
      const keyB64 = Buffer.alloc(32, 9).toString('base64');
      const seedBlob = await vault.encryptWithPassword(SEED, 'pw-key-4');
      map.set('encryptedSeed', seedBlob);
      const notAKey = await vault.encryptWithPassword(SEED, 'pw-key-4');
      await assert.rejects(
        () => vault.storeKeyCacheBlob(cacheKey, notAKey, 'pw-key-4'),
        /Failed to decrypt/
      );
      assert.equal(map.has(cacheKey), false, 'a blob of the wrong kind is never stored');
      const keyBlob = await vault.encryptWithPassword(keyB64, 'pw-key-4');
      await assert.rejects(
        () => vault.storeKeyCacheBlob(cacheKey, keyBlob, 'wrong password'),
        /does not open under the password/
      );
      assert.equal(map.has(cacheKey), false, 'a key that the live seed does not open under is never stored');
      await assert.rejects(
        () => vault.storeKeyCacheBlob('encryptedSeed', keyBlob, 'pw-key-4'),
        /outside the private-key cache namespace/
      );
      assert.equal(await vault.storeKeyCacheBlob(cacheKey, keyBlob, 'pw-key-4'), keyBlob);
      assert.equal(map.get(cacheKey), keyBlob);

      // Guard: once the seed has moved to another password, a key derived under
      // the old one is never stored (it would outlive its password).
      map.delete(cacheKey);
      const newSeed = await vault.encryptWithPassword(SEED, 'pw-key-4b');
      map.set('encryptedSeed', newSeed);
      await assert.rejects(
        () => vault.storeKeyCacheBlob(cacheKey, keyBlob, 'pw-key-4'),
        /does not open under the password/
      );
      assert.equal(map.has(cacheKey), false, 'a stale key cache (old password) is never stored');
      assert.equal(map.get('encryptedSeed'), newSeed);

      // A migration keeps the password, so a key derived under it is still stored.
      const sameSeedNewBlob = await vault.encryptWithPassword(SEED, 'pw-key-4b');
      map.set('encryptedSeed', sameSeedNewBlob);
      const keyBlobB = await vault.encryptWithPassword(keyB64, 'pw-key-4b');
      assert.equal(await vault.storeKeyCacheBlob(cacheKey, keyBlobB, 'pw-key-4b'), keyBlobB, 'same password, new blob: stored');
    }

    // --- 4f. signing derives and caches the key without any backup copy ---
    {
      const { map } = useStorage();
      map.set('encryptedSeed', await vault.encryptWithPassword(SEED, 'pw-derive-5'));
      const ltcCacheKey = 'encryptedPrivateKey:LTC:m_84_2_0_0_0'; // DERIVATION_PATHS.LTC
      const cached = await wallet.getOrDeriveKeyPair('pw-derive-5', 'LTC');
      assert.equal(map.get(ltcCacheKey), cached, 'the derived key is cached under the network label');
      const keyBytes = Buffer.from(await vault.decryptWithPassword(cached, 'pw-derive-5', 'privateKey'), 'base64');
      assert.equal(keyBytes.length, 32);
      assert.equal(map.has(`${ltcCacheKey}.bak`), false, 'the derived key cache keeps no backup');
      assert.equal(map.has(`${ltcCacheKey}.prev`), false);
    }

    // --- 4g. every localStorage write outside lib/secureVault.js is a non-vault key ---
    {
      const offenders = [];
      const walk = (dir) => {
        if (!fs.existsSync(dir)) return;
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(full);
          } else if (entry.name.endsWith('.js') && entry.name !== 'bitcoinjs-lib.js') {
            fs.readFileSync(full, 'utf8')
              .split('\n')
              .forEach((line, index) => {
                // Vault data is written only by secureVault. Any other
                // encryption of key material (a second scheme) is an offender too.
                const writesVault = line.includes('localStorage.setItem(') && !line.includes("'multisigs'");
                if (writesVault || line.includes('CryptoJS.AES.encrypt(')) {
                  offenders.push(`${path.relative(ROOT, full)}:${index + 1}`);
                }
              });
          }
        }
      };
      for (const dir of ['lib', 'components', 'popup', 'background', 'store']) {
        walk(path.join(ROOT, dir));
      }
      assert.deepEqual(
        offenders.filter((line) => !line.startsWith('lib/secureVault.js:')),
        [],
        'vault data must only be written through lib/secureVault.js'
      );
    }

    // --- 4g1. derivation paths are written once, in lib/networks.js ---
    {
      const pathLiterals = [];
      const walkPaths = (dir) => {
        if (!fs.existsSync(dir)) return;
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walkPaths(full);
          } else if (entry.name.endsWith('.js') && entry.name !== 'bitcoinjs-lib.js') {
            fs.readFileSync(full, 'utf8')
              .split('\n')
              .forEach((line, index) => {
                if (/m\/(44|84)'\//.test(line)) pathLiterals.push(`${path.relative(ROOT, full)}:${index + 1}`);
              });
          }
        }
      };
      for (const dir of ['lib', 'components', 'popup', 'background', 'store']) {
        walkPaths(path.join(ROOT, dir));
      }
      assert.deepEqual(
        pathLiterals.filter((line) => !line.startsWith('lib/networks.js:')),
        [],
        'derivation paths must come only from DERIVATION_PATHS in lib/networks.js'
      );
    }

    // --- 4g2. the send form checks the password exactly as setup and unlock stored it ---
    {
      const sendSource = fs.readFileSync(path.join(ROOT, 'components', 'Send.js'), 'utf8');
      assert.equal(
        /\.trim\(\)/.test(sendSource),
        false,
        'Send.js must not trim the password: setup and unlock keep it as typed'
      );
      assert.ok(
        /^\s*const isValidPassword = await liveSeedOpensUnder\(password\);/m.test(sendSource),
        'Send.js must check the password before it signs'
      );
    }

    // --- 4h. a restore from .bak never overwrites the only good copy in .prev ---
    {
      // State left by an interrupted rollback: the live seed is unreadable and
      // .prev holds the last decryptable copy.
      const { map } = useStorage();
      const goodPrev = await vault.encryptWithPassword(SEED, 'pw-prev-6');
      const bak = await vault.encryptWithPassword(SEED, 'pw-bak-6');
      map.set('encryptedSeed', 'unreadable live value');
      map.set('encryptedSeed.bak', bak);
      map.set('encryptedSeed.prev', goodPrev);
      assert.equal(
        await vault.restoreFromBackup('encryptedSeed', 'pw-bak-6', SEED_KIND, 'bak'),
        bak,
        'the .bak blob opens and becomes the live seed'
      );
      assert.equal(map.get('encryptedSeed'), bak);
      assert.equal(
        map.get('encryptedSeed.prev'),
        goodPrev,
        'a restore must not replace the decryptable .prev copy with the unreadable live value'
      );
      assert.equal(await vault.decryptWithPassword(goodPrev, 'pw-prev-6', SEED_KIND), SEED);
    }

    // --- 4i. a restore from .prev never creates .bak ---
    {
      const { map } = useStorage();
      const goodPrev = await vault.encryptWithPassword(SEED, 'pw-prev-7');
      map.set('encryptedSeed', 'unreadable live value');
      map.set('encryptedSeed.prev', goodPrev);
      assert.equal(await vault.restoreFromBackup('encryptedSeed', 'pw-prev-7', SEED_KIND, 'prev'), goodPrev);
      assert.equal(map.has('encryptedSeed.bak'), false, 'a restore must never create the one-time .bak');
      assert.equal(map.get('encryptedSeed.prev'), goodPrev, 'the restore source stays in .prev');
    }

    // --- 4j. a password change sweeps key caches, and aborts if it cannot ---
    {
      const { map } = useStorage();
      const oldBlob = await vault.encryptWithPassword(SEED, 'pw-sweep-8');
      map.set('encryptedSeed', oldBlob);
      map.set(cacheKey, await vault.encryptWithPassword(Buffer.alloc(32, 7).toString('base64'), 'pw-sweep-8'));
      const store = globalThis.localStorage;
      const realRemove = store.removeItem;
      store.removeItem = (key) => {
        if (key === cacheKey) throw new Error('quota: cache removal failed');
        realRemove(key);
      };
      try {
        await assert.rejects(
          () => vault.replaceStoredBlob('encryptedSeed', oldBlob, SEED, 'pw-sweep-9', SEED_KIND),
          /Could not remove 1 key cache entry/
        );
      } finally {
        store.removeItem = realRemove;
      }
      assert.equal(map.get('encryptedSeed'), oldBlob, 'a failed sweep aborts the password change');
      assert.equal(map.has('encryptedSeed.bak'), false, 'nothing is backed up by an aborted change');
      assert.ok(map.has(cacheKey), 'the cache that could not be removed is still there (and still matches the live seed)');

      const reset = await vault.replaceStoredBlob('encryptedSeed', oldBlob, SEED, 'pw-sweep-9', SEED_KIND);
      assert.equal(map.get('encryptedSeed'), reset);
      assert.equal(map.has(cacheKey), false, 'a completed password change leaves no key cache behind');
      assert.equal(map.get('encryptedSeed.bak'), oldBlob, 'the old password blob is kept as the first v2 backup');
    }

    // --- 4k. a legacy encryptedKey entry that cannot be removed also fails the sweep ---
    {
      const { map } = useStorage();
      const oldBlob = await vault.encryptWithPassword(SEED, 'pw-sweep-10');
      map.set('encryptedSeed', oldBlob);
      map.set('encryptedKey', 'legacy-key');
      const store = globalThis.localStorage;
      const realRemove = store.removeItem;
      store.removeItem = (key) => {
        if (key === 'encryptedKey') throw new Error('quota: legacy removal failed');
        realRemove(key);
      };
      try {
        await assert.rejects(
          () => vault.replaceStoredBlob('encryptedSeed', oldBlob, SEED, 'pw-sweep-11', SEED_KIND),
          /Could not remove 1 key cache entry/
        );
      } finally {
        store.removeItem = realRemove;
      }
      assert.equal(map.get('encryptedSeed'), oldBlob, 'the seed is unchanged when the legacy entry cannot be removed');
    }

    // --- 4l. without Web Locks, every write is refused and nothing changes ---
    {
      const { map } = useStorage();
      const seed = await vault.encryptWithPassword(SEED, 'pw-nolock-12');
      map.set('encryptedSeed', await vault.encryptWithPassword(SEED, 'pw-nolock-14'));
      map.set('encryptedSeed.bak', seed);
      const realNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
      Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true });
      try {
        const before = new Map(map);
        await assert.rejects(
          () => vault.replaceStoredBlob('encryptedSeed', seed, SEED, 'pw-nolock-13', SEED_KIND),
          /Web Locks/
        );
        await assert.rejects(
          () => vault.restoreFromBackup('encryptedSeed', 'pw-nolock-12', SEED_KIND, 'bak'),
          /Web Locks/
        );
        const keyBlob = await vault.encryptWithPassword(Buffer.alloc(32, 3).toString('base64'), 'pw-nolock-12');
        await assert.rejects(
          () => vault.storeKeyCacheBlob(cacheKey, keyBlob, 'pw-nolock-12'),
          /Web Locks/
        );
        assert.equal(await vault.maybeUpgradeStoredBlob('encryptedSeed', seed, SEED, 'pw-nolock-12', SEED_KIND), null);
        assert.deepEqual(new Map(map), before, 'no write happens without the lock');
      } finally {
        if (realNavigator) {
          Object.defineProperty(globalThis, 'navigator', realNavigator);
        } else {
          delete globalThis.navigator;
        }
      }
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
