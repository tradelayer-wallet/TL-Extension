// Model checker for the seed storage state machine (lib/secureVault.js and the
// flows that call it). Runs offline under plain Node.
//
// Operations mirror the component code paths call for call:
//   setup(X)       PasswordSetup.js: no seed yet -> replaceStoredBlob; otherwise a
//                  read-only decrypt check
//   unlock(X)      PasswordPrompt.js: generateAddressFromSeed (migrates a legacy
//                  seed), then clearPrivateKeyCaches, after success only
//   expose(X)      ExposeSeed.js: decrypt, then maybeUpgradeStoredBlob if legacy
//   sign(X)        the signing UI: checkPasswordMatch, then getSigningKeyBase64
//                  (reads, derives, stores and migrates the key cache)
//   sign-raw(X)    getSigningKeyBase64 without the UI's password gate
//   reset(X->Y)    ResetPass.js: decrypt with X, replaceStoredBlob(seed, ..., Y)
//   restore(s,X)   popup.js restoreSeedFromBackup -> restoreFromBackup(s)
//   sweep          any other clearPrivateKeyCaches caller
// Key-cache slots: the LTC and DOGE cache entries and the legacy 'encryptedKey'.
//
// Start states: an empty store; a legacy seed (under A, and under the empty
// password); a v2 seed; a legacy seed with legacy key caches; and a state an
// older build could leave behind (v2 seed under B, key cache still under A).
//
// Faults: at each localStorage call an operation makes, one fault per run:
//   reject      a set/remove throws before writing (quota)
//   land-throw  a set/remove lands, then throws (interruption)
//   read-throw  a getItem throws
// Opt-in classes (MODEL_CHECK_FAULTS), outside localStorage's contract and
// reported, not asserted, by default:
//   corrupt     a set silently stores a truncated value
//   foreign     another writer that does not use the primitive lands a value in
//               the live slot just before a call
//
// Invariants, checked after every transition unless noted:
//   I1 no lost copy: if some seed slot opened under a password before, one
//      still does after.
//   I2 success means openable: an operation that succeeds leaves the live seed
//      openable under the password it was given.
//   I3 no silent change: an operation that fails with no injected fault leaves
//      the store unchanged, except that signing may discard a stale key cache
//      it has just refused to use.
//   I4 no stale key cache: a key cache opens only under the password that opens
//      the live seed. A transition may not create a stale cache, and a signing
//      operation may not succeed while one remains (it would have signed with
//      a key that the live seed no longer goes with).
//   I5 competing password changes from the same password: exactly one wins.
//   I6 no legacy blob newly written into .bak.
//   I7 liveness: with no fault, an operation given the password that opens the
//      live seed succeeds (a stale cache must not block signing).
//   I8 a verified migration (no fault) leaves no .prev.
//   I10 a restore never creates .bak (only a normal write does, once).
//
// Passwords the user knows are the ones in PASSWORDS (plus the empty password,
// which legacy wallets may use). Crypto is the real code; only the PBKDF2 round
// count is set to 1 by a wrapper around subtle.deriveKey, so the explorer runs
// in seconds. PBKDF2_ITERATIONS and the parameter check are covered by the
// other smoke tests, which use the real count.
//
// Not modelled: passwords the user has forgotten (a copy under one reads as
// "garbage"), Web Locks outside the in-process FIFO stand-in, and browser
// behaviour such as a popup closing between two awaits (interleaving is only
// explored at the await points of two operations started together).
//
// Environment:
//   MODEL_CHECK_DEPTH   operation-sequence length (default 3)
//   MODEL_CHECK_FAULTS  fault classes: write,read (default), corrupt, foreign
//   MODEL_CHECK_SHOW    print every violation whose kind starts with this prefix
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const esbuild = require('esbuild');
const CryptoJS = require('crypto-js');

const ROOT = path.resolve(__dirname, '..');
const SEED = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const SEED_KIND = 'seed';
const KEY_PLAIN = Buffer.alloc(32, 7).toString('base64');
const PASSWORDS = {
  A: 'model-password-one',
  B: 'model-password-two',
  C: 'model-password-three',
  D: 'model-password-four',
  empty: '',
};
const SEED_KEY = 'encryptedSeed';
const BAK = 'encryptedSeed.bak';
const PREV = 'encryptedSeed.prev';
const SEED_SLOTS = [SEED_KEY, BAK, PREV];
const KEY_CACHE_LTC = 'encryptedPrivateKey:LTC:m_84_2_0_0_0';
const KEY_CACHE_DOGE = 'encryptedPrivateKey:DOGE:m_44_3_0_0_0';
const LEGACY_KEY = 'encryptedKey';
const CACHE_SLOTS = [KEY_CACHE_LTC, KEY_CACHE_DOGE, LEGACY_KEY];
const MAX_DEPTH = Number(process.env.MODEL_CHECK_DEPTH || 3);
const FAULT_CLASSES = new Set((process.env.MODEL_CHECK_FAULTS || 'write,read').split(',').map((c) => c.trim()));
const READ_FAULTS = FAULT_CLASSES.has('read');
const FOREIGN_WRITERS = FAULT_CLASSES.has('foreign');
const CORRUPT_WRITES = FAULT_CLASSES.has('corrupt');

// Microtask turns each key derivation waits before it starts. The fast KDF
// finishes in about the same time for every operation, so the concurrency runs
// vary this per run to reach interleavings a uniform schedule would miss.
let kdfTurns = () => 0;
// Seeded PRNG (mulberry32) so a failing schedule can be replayed.
const seededTurns = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) % 6;
  };
};

// Fast KDF for the explorer only (see header). Everything else is real.
const installFastKdf = () => {
  const realCrypto = globalThis.crypto;
  const realSubtle = realCrypto.subtle;
  const subtle = {
    importKey: (...args) => realSubtle.importKey(...args),
    encrypt: (...args) => realSubtle.encrypt(...args),
    decrypt: (...args) => realSubtle.decrypt(...args),
    deriveKey: async (params, ...rest) => {
      for (let turns = kdfTurns(); turns > 0; turns -= 1) await null;
      return realSubtle.deriveKey({ ...params, iterations: 1 }, ...rest);
    },
  };
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: { getRandomValues: (bytes) => realCrypto.getRandomValues(bytes), subtle },
  });
};

// Lock manager with FIFO ordering, standing in for navigator.locks.
const makeLockManager = () => {
  let tail = Promise.resolve();
  return {
    request(_name, fn) {
      const run = tail.then(() => fn());
      tail = run.catch(() => {});
      return run;
    },
  };
};

const setNavigator = (locks) => {
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    writable: true,
    value: locks ? { locks } : {},
  });
};

(async () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-vault-model-'));
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
    const vault = require(vaultFile);
    const wallet = require(walletFile);
    installFastKdf();

    // maybeUpgradeStoredBlob logs each refused migration; the explorer expects
    // many of them, so count them instead of printing each one.
    const logError = console.error;
    let quietedErrors = 0;
    console.error = () => { quietedErrors += 1; };
    let result;
    try {
      result = await explore({ vault, wallet });
    } finally {
      console.error = logError;
    }
    result.quietedErrors = quietedErrors;
    report(result);
    if (result.violations.length > 0) {
      process.exitCode = 1;
    }
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

// ---------------------------------------------------------------------------
// Explorer
// ---------------------------------------------------------------------------

async function explore({ vault, wallet }) {
  // ---- Fake localStorage with one injected fault per run -----------------
  let map = new Map();
  let log = [];
  let fault = null;
  let foreignValid = null;
  const GARBAGE = 'Zm9vYmFyZ2FyYmFnZQ==';

  const applyForeign = (mode) => {
    if (mode === 'foreign-remove') map.delete(SEED_KEY);
    else map.set(SEED_KEY, mode === 'foreign-garbage' ? GARBAGE : foreignValid);
  };

  const call = (kind, key, apply, value) => {
    const index = log.length;
    log.push({ kind, key });
    const here = fault && fault.at === index ? fault.mode : null;
    if (here && here.startsWith('foreign')) applyForeign(here);
    const hit = here && !here.startsWith('foreign') ? here : null;
    if (hit === 'reject' && (kind === 'set' || kind === 'remove')) {
      throw new Error('injected: write rejected (quota exceeded)');
    }
    if (hit === 'read-throw' && kind === 'get') {
      throw new Error('injected: storage read failed');
    }
    if (hit === 'corrupt' && kind === 'set') {
      map.set(key, value.slice(0, Math.floor(value.length / 2)));
      return undefined;
    }
    const out = apply();
    if (hit === 'land-throw' && (kind === 'set' || kind === 'remove')) {
      throw new Error('injected: interrupted after the write landed');
    }
    return out;
  };

  const store = {
    getItem: (key) => call('get', key, () => (map.has(key) ? map.get(key) : null)),
    setItem: (key, value) => call('set', key, () => { map.set(key, String(value)); }, String(value)),
    removeItem: (key) => call('remove', key, () => { map.delete(key); }),
    key: (index) => [...map.keys()][index] ?? null,
    get length() { return map.size; },
  };
  globalThis.localStorage = store;

  const locks = makeLockManager();
  setNavigator(locks);

  // A valid v2 blob of the seed under password D: the "other writer" value.
  foreignValid = await vault.encryptWithPassword(SEED, PASSWORDS.D);

  // ---- Labels: which known password opens a blob (memoized by value) -----
  const labelCache = new Map();
  const labelOf = async (blob, kind = SEED_KIND) => {
    if (blob === null || blob === undefined) return 'absent';
    const cacheKey = `${kind}:${blob}`;
    if (labelCache.has(cacheKey)) return labelCache.get(cacheKey);
    let label = 'garbage';
    for (const [name, password] of Object.entries(PASSWORDS)) {
      try {
        const { plaintext } = await vault.decryptWithPasswordInfo(blob, password, kind);
        // Seeds must open to the seed; key caches to a canonical 32-byte key.
        const ok = kind === SEED_KIND ? plaintext === SEED : vault.validatePrivateKeyPlaintext(plaintext);
        if (ok) {
          label = name;
          break;
        }
      } catch (_) {
        // not this password
      }
    }
    labelCache.set(cacheKey, label);
    return label;
  };
  const valueOf = (snapshot, slot) => (snapshot.has(slot) ? snapshot.get(slot) : null);
  const formatOf = (value) => {
    if (value === null) return '-';
    return vault.isLegacyVaultBlob(value) ? 'L' : 'V';
  };

  const summarize = async (snapshot) => {
    const labels = {};
    const parts = [];
    const ids = new Map();
    for (const slot of SEED_SLOTS) {
      const value = valueOf(snapshot, slot);
      labels[slot] = await labelOf(value, SEED_KIND);
      if (value !== null && !ids.has(value)) ids.set(value, ids.size);
      parts.push(`${slot}=${value === null ? '-' : `#${ids.get(value)}:${labels[slot]}:${formatOf(value)}`}`);
    }
    const seedPart = parts.join('|');
    const caches = {};
    for (const slot of CACHE_SLOTS) {
      const value = valueOf(snapshot, slot);
      caches[slot] = await labelOf(value, 'privateKey');
      parts.push(`${slot}=${caches[slot]}:${formatOf(value)}`);
    }
    const liveLabel = labels[SEED_KEY];
    const known = (label) => label !== 'garbage' && label !== 'absent';
    const stale = CACHE_SLOTS.find((slot) => known(caches[slot]) && caches[slot] !== liveLabel) || null;
    return {
      fingerprint: parts.join('|'),
      seedPart,
      copies: SEED_SLOTS.filter((slot) => known(labels[slot])).length,
      decryptable: new Set(SEED_SLOTS.map((slot) => labels[slot]).filter(known)),
      liveLabel,
      liveFormat: formatOf(valueOf(snapshot, SEED_KEY)),
      bakFormat: formatOf(valueOf(snapshot, BAK)),
      prevPresent: valueOf(snapshot, PREV) !== null,
      bakPresent: valueOf(snapshot, BAK) !== null,
      stale,
    };
  };

  // ---- Operations: mirror the component code paths -----------------------
  const setupFlow = async (password) => {
    const enc = localStorage.getItem(SEED_KEY);
    if (!enc) {
      await vault.replaceStoredBlob(SEED_KEY, null, SEED, password, SEED_KIND);
      return 'ok';
    }
    await vault.decryptWithPasswordInfo(enc, password, SEED_KIND);
    return 'checked';
  };
  // PasswordPrompt.js: unlock, then the best-effort sweep on success.
  const unlockFlow = async (password) => {
    await wallet.generateAddressFromSeed(localStorage.getItem(SEED_KEY), 'LTC', password);
    wallet.clearPrivateKeyCaches();
    return 'ok';
  };
  // ExposeSeed.js: decrypt, migrate a legacy blob.
  const exposeFlow = async (password) => {
    const enc = localStorage.getItem(SEED_KEY);
    const { plaintext, legacy } = await vault.decryptWithPasswordInfo(enc, password, SEED_KIND);
    if (legacy) {
      await vault.maybeUpgradeStoredBlob(SEED_KEY, enc, plaintext, password, SEED_KIND);
    }
    return 'ok';
  };
  // The signing UI checks the password against the live seed first.
  const signFlow = async (password, network = 'LTC') => {
    if (!(await wallet.checkPasswordMatch(password))) {
      throw new Error('Incorrect password.');
    }
    await wallet.getSigningKeyBase64(password, network);
    return 'ok';
  };
  const signRawFlow = async (password, network = 'LTC') => {
    await wallet.getSigningKeyBase64(password, network);
    return 'ok';
  };
  // ResetPass.js
  const resetFlow = async (from, to) => {
    const enc = localStorage.getItem(SEED_KEY);
    if (!enc) throw new Error('Encrypted seed not found.');
    let decrypted;
    try {
      decrypted = (await vault.decryptWithPasswordInfo(enc, from, SEED_KIND)).plaintext;
    } catch (_) {
      throw new Error('Incorrect current password.');
    }
    await vault.replaceStoredBlob(SEED_KEY, enc, decrypted, to, SEED_KIND);
    decrypted = null;
    return 'ok';
  };
  // popup.js restoreSeedFromBackup -> restoreFromBackup
  const restoreFlow = async (source, password) => {
    const restored = await vault.restoreFromBackup(SEED_KEY, password, undefined, source);
    return restored === null ? 'noop' : 'ok';
  };
  const sweepFlow = async () => {
    wallet.clearPrivateKeyCaches();
    return 'ok';
  };

  // openableWith: the password the live seed must open under after success.
  // liveFor: the password the user types; with no fault it must succeed when the
  // live seed opens under it (I7). resetFrom: for the competing-change check.
  const op = (name, run, meta = {}) => ({ name, run, ...meta });
  const ops = [
    op('setup(A)', () => setupFlow(PASSWORDS.A), { openableWith: 'A' }),
    op('unlock(A)', () => unlockFlow(PASSWORDS.A), { openableWith: 'A', liveFor: 'A' }),
    op('unlock(B)', () => unlockFlow(PASSWORDS.B), { openableWith: 'B', liveFor: 'B' }),
    op('unlock(empty)', () => unlockFlow(PASSWORDS.empty), { openableWith: 'empty', liveFor: 'empty' }),
    op('expose(A)', () => exposeFlow(PASSWORDS.A), { openableWith: 'A', liveFor: 'A' }),
    op('sign(A)', () => signFlow(PASSWORDS.A), { liveFor: 'A', signs: true }),
    op('sign(B)', () => signFlow(PASSWORDS.B), { liveFor: 'B', signs: true }),
    op('sign(A,DOGE)', () => signFlow(PASSWORDS.A, 'DOGE'), { liveFor: 'A', signs: true }),
    op('sign-raw(A)', () => signRawFlow(PASSWORDS.A), { liveFor: 'A', signs: true }),
    op('reset(A->B)', () => resetFlow(PASSWORDS.A, PASSWORDS.B), { openableWith: 'B', liveFor: 'A', resetFrom: 'A' }),
    op('reset(A->C)', () => resetFlow(PASSWORDS.A, PASSWORDS.C), { openableWith: 'C', liveFor: 'A', resetFrom: 'A' }),
    op('reset(B->C)', () => resetFlow(PASSWORDS.B, PASSWORDS.C), { openableWith: 'C', liveFor: 'B', resetFrom: 'B' }),
    op('reset(C->A)', () => resetFlow(PASSWORDS.C, PASSWORDS.A), { openableWith: 'A', liveFor: 'C', resetFrom: 'C' }),
    op('restore(bak,A)', () => restoreFlow('bak', PASSWORDS.A), { openableWith: 'A', restores: true }),
    op('restore(bak,B)', () => restoreFlow('bak', PASSWORDS.B), { openableWith: 'B', restores: true }),
    op('restore(prev,A)', () => restoreFlow('prev', PASSWORDS.A), { openableWith: 'A', restores: true }),
    op('restore(prev,B)', () => restoreFlow('prev', PASSWORDS.B), { openableWith: 'B', restores: true }),
    op('sweep', () => sweepFlow(), {}),
  ];

  // Run one operation from `start` with at most one injected fault.
  const execute = async (start, operation, injected) => {
    map = new Map(start);
    log = [];
    fault = injected;
    let outcome;
    let error = null;
    try {
      outcome = await operation.run();
    } catch (e) {
      outcome = 'error';
      error = e;
    }
    fault = null;
    return { map, log: log.slice(), outcome, error };
  };

  const faultPlansFor = (calls) => {
    const plans = [];
    calls.forEach((c, index) => {
      if (c.kind === 'set' || c.kind === 'remove') {
        plans.push({ at: index, mode: 'reject' });
        plans.push({ at: index, mode: 'land-throw' });
      }
      if (c.kind === 'get' && READ_FAULTS) plans.push({ at: index, mode: 'read-throw' });
      if (c.kind === 'set' && CORRUPT_WRITES) plans.push({ at: index, mode: 'corrupt' });
      if (FOREIGN_WRITERS) {
        plans.push({ at: index, mode: 'foreign-garbage' });
        plans.push({ at: index, mode: 'foreign-valid' });
        plans.push({ at: index, mode: 'foreign-remove' });
      }
    });
    return plans;
  };

  // ---- Start states -------------------------------------------------------
  const seedMap = (...entries) => new Map(entries);
  const starts = [
    { name: 'empty', map: new Map() },
    { name: 'legacy(A)', map: seedMap([SEED_KEY, CryptoJS.AES.encrypt(SEED, PASSWORDS.A).toString()]) },
    { name: 'legacy(empty)', map: seedMap([SEED_KEY, CryptoJS.AES.encrypt(SEED, PASSWORDS.empty).toString()]) },
    { name: 'v2(A)', map: seedMap([SEED_KEY, await vault.encryptWithPassword(SEED, PASSWORDS.A)]) },
    {
      name: 'legacy(A)+legacy caches(A)',
      map: seedMap(
        [SEED_KEY, CryptoJS.AES.encrypt(SEED, PASSWORDS.A).toString()],
        [KEY_CACHE_LTC, CryptoJS.AES.encrypt(KEY_PLAIN, PASSWORDS.A).toString()],
        [LEGACY_KEY, CryptoJS.AES.encrypt(KEY_PLAIN, PASSWORDS.A).toString()]
      ),
    },
    {
      name: 'v2(B)+stale cache(A)',
      map: seedMap(
        [SEED_KEY, await vault.encryptWithPassword(SEED, PASSWORDS.B)],
        [KEY_CACHE_LTC, await vault.encryptWithPassword(KEY_PLAIN, PASSWORDS.A)]
      ),
    },
    {
      name: 'v2(B)+legacy stale cache(A)',
      map: seedMap(
        [SEED_KEY, await vault.encryptWithPassword(SEED, PASSWORDS.B)],
        [KEY_CACHE_LTC, CryptoJS.AES.encrypt(KEY_PLAIN, PASSWORDS.A).toString()]
      ),
    },
  ];

  // ---- Checks ------------------------------------------------------------
  // Invariant checks for one transition. `before` and `after` are summaries.
  const checkTransition = (before, after, run, operation, injected, trace) => {
    const found = [];
    const add = (kind) => found.push({ kind, trace, after: after.fingerprint });
    const clean = injected === null;
    if (before.copies >= 1 && after.copies === 0) add('I1 lost last copy');
    if (run.outcome === 'ok' && operation.openableWith && after.liveLabel !== operation.openableWith) {
      add('I2 success but live seed not openable');
    }
    const discardedStale = before.stale && !after.stale && after.seedPart === before.seedPart;
    if (clean && run.outcome === 'error' && after.fingerprint !== before.fingerprint && !discardedStale) {
      add('I3 failed operation changed the store');
    }
    // I4: a stale cache may persist through a failed or no-op transition, but a
    // transition may not create one or report success while one remains.
    if (after.stale && (!before.stale || (operation.signs && run.outcome === 'ok'))) {
      add(`I4 key cache outlives its password (${after.stale})`);
    }
    if (after.bakFormat === 'L' && before.bakFormat !== 'L') add('I6 legacy blob newly written to .bak');
    if (clean && before.liveFormat === 'L' && after.liveFormat === 'V' && after.prevPresent) {
      add('I8 verified migration left a .prev');
    }
    if (operation.restores && !before.bakPresent && after.bakPresent) add('I10 restore created a .bak');
    if (clean && operation.liveFor && before.liveLabel === operation.liveFor && run.outcome !== 'ok') {
      add('I7 liveness: the live password is refused');
    }
    return found;
  };

  // ---- Breadth-first exploration -----------------------------------------
  const seen = new Set();
  const violations = [];
  const observations = new Map();
  let transitions = 0;
  const pathOf = (node, extra) => [...node.path, extra].join(' ; ');
  const describeFault = (f) => (f ? `${f.mode}@${f.at}` : 'none');

  let frontier = [];
  for (const start of starts) {
    const summary = await summarize(start.map);
    if (!seen.has(summary.fingerprint)) {
      seen.add(summary.fingerprint);
      frontier.push({ map: start.map, path: [start.name], summary });
    }
  }
  const initialCount = frontier.length;

  for (let depth = 0; depth < MAX_DEPTH; depth += 1) {
    const next = [];
    for (const node of frontier) {
      for (const operation of ops) {
        const base = await execute(node.map, operation, null);
        const plans = [null, ...faultPlansFor(base.log)];
        for (const injected of plans) {
          const run = injected === null ? base : await execute(node.map, operation, injected);
          transitions += 1;
          const after = await summarize(run.map);
          const trace = pathOf(node, `${operation.name}[${describeFault(injected)}]`);
          violations.push(...checkTransition(node.summary, after, run, operation, injected, trace));

          // Observation (policy, not a violation): passwords that no longer open any copy.
          const lost = [...node.summary.decryptable].filter((p) => !after.decryptable.has(p));
          if (lost.length > 0 && injected === null) {
            const key = `${operation.name} loses access under ${lost.join(',')}`;
            observations.set(key, (observations.get(key) || 0) + 1);
          }

          if (!seen.has(after.fingerprint)) {
            seen.add(after.fingerprint);
            next.push({ map: run.map, path: [...node.path, `${operation.name}[${describeFault(injected)}]`], summary: after });
          }
        }
      }
    }
    frontier = next;
    if (frontier.length === 0) break;
  }

  // ---- Two operations at once (two extension contexts) -------------------
  // Both start from the same store and run concurrently through the lock, with
  // the awaits of each interleaved. Every ordered pair of operations is tried
  // from every start state.
  const concurrent = [];
  let concurrentRuns = 0;
  const SCHEDULES = [1, 2, 3];
  for (const start of starts) {
    const before = await summarize(start.map);
    for (const first of ops) {
      for (const second of ops) for (const seed of SCHEDULES) {
        map = new Map(start.map);
        log = [];
        fault = null;
        kdfTurns = seededTurns(seed * 7919 + concurrentRuns);
        const outcomes = await Promise.allSettled([first.run(), second.run()]);
        kdfTurns = () => 0;
        const after = await summarize(map);
        concurrentRuns += 1;
        const failed = outcomes.filter((o) => o.status === 'rejected').length;
        const trace = `concurrent from ${start.name}: ${first.name} || ${second.name}`;
        // Only the state-level invariants apply to a pair (no single outcome).
        if (before.copies >= 1 && after.copies === 0) {
          violations.push({ kind: 'I1 lost last copy', trace, after: after.fingerprint });
        }
        // I4, as in checkTransition: created by the pair, or left by a signing
        // operation that succeeded.
        const signedOk = [first, second].some((o, i) => o.signs && outcomes[i].status === 'fulfilled');
        if (after.stale && (!before.stale || signedOk)) {
          violations.push({ kind: `I4 key cache outlives its password (${after.stale})`, trace, after: after.fingerprint });
        }
        // I5: two password changes from the same password, with the live seed
        // under it: exactly one may win.
        // A normal seed write may create .bak; only a pair without one can be blamed on a restore.
        const writesSeed = (o) => o.name.startsWith('reset(') || o.name.startsWith('setup(');
        if ((first.restores || second.restores) && !writesSeed(first) && !writesSeed(second)
          && !before.bakPresent && after.bakPresent) {
          violations.push({ kind: 'I10 restore created a .bak', trace, after: after.fingerprint });
        }
        if (first.resetFrom && first.resetFrom === second.resetFrom && before.liveLabel === first.resetFrom && failed !== 1) {
          violations.push({ kind: 'I5 competing password changes: expected exactly one winner', trace, after: after.fingerprint });
        }
        if (first.name === 'reset(A->B)' && second.name === 'reset(A->C)' && start.name === 'v2(A)') {
          concurrent.push({ name: trace, failed, after });
        }
      }
    }
  }

  return {
    concurrent,
    concurrentRuns,
    depth: MAX_DEPTH,
    faults: [...FAULT_CLASSES].join(','),
    initialCount,
    states: seen.size,
    transitions,
    violations,
    observations,
  };
}

function report(result) {
  console.log(
    `[model] faults=${result.faults} depth=${result.depth} states=${result.states} transitions=${result.transitions} concurrent-pairs=${result.concurrentRuns} violations=${result.violations.length} refused-migrations=${result.quietedErrors}`
  );
  const byKind = new Map();
  for (const v of result.violations) byKind.set(v.kind, (byKind.get(v.kind) || 0) + 1);
  for (const [kind, count] of byKind) {
    const withBak = result.violations.filter((v) => v.kind === kind && !v.after.includes('encryptedSeed.bak=-')).length;
    console.log(`[model]   ${kind}: ${count} (with .bak present: ${withBak})`);
  }
  const shown = process.env.MODEL_CHECK_SHOW || '';
  const selected = shown ? result.violations.filter((v) => v.kind.startsWith(shown)) : result.violations;
  for (const v of selected.slice(0, shown ? 60 : 8)) {
    console.log(`[model]   e.g. ${v.kind}: ${v.trace}`);
    console.log(`[model]        after: ${v.after}`);
  }
  for (const c of result.concurrent) {
    console.log(`[model] concurrent ${c.name}: rejected=${c.failed} live=${c.after.liveLabel} stale=${c.after.stale || 'none'}`);
  }
  for (const [key, count] of result.observations) {
    console.log(`[model] observation (policy, not a violation): ${key} (${count} states)`);
  }
  if (result.violations.length === 0) {
    console.log('[model] all invariants held on every explored transition');
  }
}
