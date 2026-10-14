// Model checker for the seed storage state machine (lib/secureVault.js and the
// flows that call it: PasswordSetup, ResetPass, PasswordPrompt/unlock, signing
// key caches, popup restore helper). Runs offline under plain Node.
//
// Model:
//   - slots: encryptedSeed (live), encryptedSeed.bak, encryptedSeed.prev, and
//     one key-cache entry (encryptedPrivateKey:LTC:...).
//   - operations: setup, unlock, sign, reset (password change), restore from
//     .bak or .prev, sweep of key caches.
//   - faults: at every localStorage write an operation makes, the write can be
//     rejected (quota) or land and then throw (interruption). Opt-in classes
//     (MODEL_CHECK_FAULTS) add a silently truncated write (corrupt) and a write
//     by another writer that does not use the primitive (foreign). Both are
//     outside localStorage's contract and are reported, not asserted, by default.
//   - concurrency: competing operations from two contexts, run through the lock.
//   - exploration: breadth-first over reachable stores, deduplicated by an
//     abstract fingerprint (which slots are equal, which password opens each).
//
// Invariants, checked after every transition:
//   I1 no lost copy: if some seed slot opened under a password the user knows
//      before a transition, one still does after it.
//   I2 success means openable: a successful operation leaves the live seed
//      openable under the password the user supplied to it.
//   I3 no silent change: an operation that fails without any injected fault
//      leaves the store unchanged (wrong password, refused write).
//   I4 no stale key cache: a key cache opens only under the password that opens
//      the live seed (a password change retires the old cache).
//
// Passwords the user knows are the ones in PASSWORDS (plus the empty password,
// which legacy wallets may use). Crypto is the real code; only the PBKDF2 round
// count is set to 1 by a wrapper around subtle.deriveKey, so the explorer runs
// in seconds. PBKDF2_ITERATIONS and the parameter check are covered by the
// other smoke tests, which use the real count.
//
// Environment:
//   MODEL_CHECK_DEPTH   operation-sequence length (default 3)
//   MODEL_CHECK_FAULTS  fault classes to explore: write (default), corrupt, foreign
//   MODEL_CHECK_SHOW    print every violation whose kind starts with this prefix
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const esbuild = require('esbuild');
const CryptoJS = require('crypto-js');

const ROOT = path.resolve(__dirname, '..');
const SEED = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const SEED_KIND = 'seed';
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
const KEY_CACHE = 'encryptedPrivateKey:LTC:m_84_2_0_0_0';
const MAX_DEPTH = Number(process.env.MODEL_CHECK_DEPTH || 3);
// Fault classes (comma separated):
//   write    storage write rejected (quota) or landed-then-interrupted (default)
//   corrupt  a set silently stores a truncated value (outside localStorage's
//            contract, which is all-or-throw; explored separately)
//   foreign  another writer that does not use the vault primitive lands a value
//            in the live slot just before a call (outside the primitive's
//            contract; every writer in this extension goes through it)
const FAULT_CLASSES = new Set((process.env.MODEL_CHECK_FAULTS || 'write').split(',').map((c) => c.trim()));
const FOREIGN_WRITERS = FAULT_CLASSES.has('foreign');
const CORRUPT_WRITES = FAULT_CLASSES.has('corrupt');

// Fast KDF for the explorer only (see header). Everything else is real.
const installFastKdf = () => {
  const realCrypto = globalThis.crypto;
  const realSubtle = realCrypto.subtle;
  const subtle = {
    importKey: (...args) => realSubtle.importKey(...args),
    encrypt: (...args) => realSubtle.encrypt(...args),
    decrypt: (...args) => realSubtle.decrypt(...args),
    deriveKey: (params, ...rest) => realSubtle.deriveKey({ ...params, iterations: 1 }, ...rest),
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
  // kind: SEED_KIND for seed slots, 'privateKey' for key caches.
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

  const summarize = async (snapshot) => {
    const labels = {};
    const parts = [];
    const ids = new Map();
    for (const slot of SEED_SLOTS) {
      const value = snapshot.has(slot) ? snapshot.get(slot) : null;
      labels[slot] = await labelOf(value);
      if (value !== null && !ids.has(value)) ids.set(value, ids.size);
      parts.push(`${slot}=${value === null ? '-' : `#${ids.get(value)}:${labels[slot]}`}`);
    }
    const cacheLabel = await labelOf(snapshot.has(KEY_CACHE) ? snapshot.get(KEY_CACHE) : null, 'privateKey');
    parts.push(`cache=${cacheLabel}`);
    const decryptable = new Set(
      SEED_SLOTS.map((slot) => labels[slot]).filter((l) => l !== 'garbage' && l !== 'absent')
    );
    return {
      fingerprint: parts.join('|'),
      copies: SEED_SLOTS.filter((slot) => labels[slot] !== 'garbage' && labels[slot] !== 'absent').length,
      decryptable,
      liveLabel: labels[SEED_KEY],
      cacheLabel,
    };
  };

  // ---- Operations: mirror the app code paths -----------------------------
  // PasswordSetup.js (no seed yet: store; seed present: verify the password).
  const setupFlow = async (password) => {
    const enc = localStorage.getItem(SEED_KEY);
    if (!enc) {
      await vault.replaceStoredBlob(SEED_KEY, null, SEED, password, SEED_KIND);
      wallet.clearPrivateKeyCaches();
    } else {
      await vault.decryptWithPasswordInfo(enc, password, SEED_KIND);
    }
    return 'wrote';
  };
  // PasswordPrompt.js -> walletUtils.generateAddressFromSeed (unlock; migrates legacy).
  const unlockFlow = async (password) => {
    await wallet.generateAddressFromSeed(localStorage.getItem(SEED_KEY), 'LTC', password);
    return 'wrote';
  };
  // Signing: walletUtils.getSigningKeyBase64 (fills and migrates key caches).
  const signFlow = async (password) => {
    await wallet.getSigningKeyBase64(password, 'LTC');
    return 'wrote';
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
    wallet.clearPrivateKeyCaches();
    return 'wrote';
  };
  // popup.js restoreSeedFromBackup -> restoreFromBackup
  const restoreFlow = async (source, password) => {
    const restored = await vault.restoreFromBackup(SEED_KEY, password, undefined, source);
    return restored === null ? 'noop' : 'wrote';
  };
  const sweepFlow = async () => {
    wallet.clearPrivateKeyCaches();
    return 'wrote';
  };

  const op = (name, run, openableWith) => ({ name, run, openableWith });
  const ops = [
    op('setup(A)', () => setupFlow(PASSWORDS.A), 'A'),
    op('unlock(A)', () => unlockFlow(PASSWORDS.A), 'A'),
    op('unlock(B)', () => unlockFlow(PASSWORDS.B), 'B'),
    op('sign(A)', () => signFlow(PASSWORDS.A), 'A'),
    op('reset(A->B)', () => resetFlow(PASSWORDS.A, PASSWORDS.B), 'B'),
    op('reset(B->C)', () => resetFlow(PASSWORDS.B, PASSWORDS.C), 'C'),
    op('reset(C->A)', () => resetFlow(PASSWORDS.C, PASSWORDS.A), 'A'),
    op('restore(bak,A)', () => restoreFlow('bak', PASSWORDS.A), 'A'),
    op('restore(bak,B)', () => restoreFlow('bak', PASSWORDS.B), 'B'),
    op('restore(prev,A)', () => restoreFlow('prev', PASSWORDS.A), 'A'),
    op('restore(prev,B)', () => restoreFlow('prev', PASSWORDS.B), 'B'),
    op('sweep', () => sweepFlow(), null),
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
  const starts = [];
  starts.push({ name: 'empty', map: new Map() });
  {
    const m = new Map();
    m.set(SEED_KEY, CryptoJS.AES.encrypt(SEED, PASSWORDS.A).toString());
    starts.push({ name: 'legacy(A)', map: m });
  }
  {
    const m = new Map();
    m.set(SEED_KEY, CryptoJS.AES.encrypt(SEED, PASSWORDS.empty).toString());
    starts.push({ name: 'legacy(empty)', map: m });
  }
  {
    const m = new Map();
    m.set(SEED_KEY, await vault.encryptWithPassword(SEED, PASSWORDS.A));
    starts.push({ name: 'v2(A)', map: m });
  }

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
          const label = pathOf(node, `${operation.name}[${describeFault(injected)}]`);

          // I1: no operation leaves the wallet without an openable copy.
          if (node.summary.copies >= 1 && after.copies === 0) {
            violations.push({ kind: 'I1 lost last copy', trace: label, after: after.fingerprint });
          }
          // I2: a successful operation leaves the live seed openable under the password it was given.
          if (run.outcome === 'wrote' && operation.openableWith && after.liveLabel !== operation.openableWith) {
            violations.push({ kind: 'I2 success but live seed not openable', trace: label, after: after.fingerprint });
          }
          // I3: a failure without an injected fault changes nothing.
          if (injected === null && run.outcome === 'error' && after.fingerprint !== node.summary.fingerprint) {
            violations.push({ kind: 'I3 failed operation changed the store', trace: label, after: after.fingerprint });
          }
          // I4: a key cache opens only under the password that opens the live seed
          // (a cache outliving a password change is a retired password still working).
          if (
            after.cacheLabel !== 'absent' &&
            after.cacheLabel !== 'garbage' &&
            after.liveLabel !== 'garbage' &&
            after.cacheLabel !== after.liveLabel
          ) {
            violations.push({ kind: 'I4 key cache outlives its password', trace: label, after: after.fingerprint });
          }
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

  // ---- Two writers at once (two extension contexts) ----------------------
  // Both start from the same store and run concurrently through the lock. Each
  // operation reads before the other writes, so the lock and the compare-and-
  // swap decide the outcome. Afterwards the invariants must still hold.
  const concurrent = [];
  const runPair = async (name, start, first, second, competing = false) => {
    map = new Map(start.map);
    log = [];
    fault = null;
    const outcomes = await Promise.allSettled([first.run(), second.run()]);
    const after = await summarize(map);
    const failed = outcomes.filter((o) => o.status === 'rejected').length;
    concurrent.push({ name, failed, after });
    if (after.copies === 0) {
      violations.push({ kind: 'I1 lost last copy', trace: `concurrent: ${name}`, after: after.fingerprint });
    }
    if (
      after.cacheLabel !== 'absent' &&
      after.cacheLabel !== 'garbage' &&
      after.liveLabel !== 'garbage' &&
      after.cacheLabel !== after.liveLabel
    ) {
      violations.push({ kind: 'I4 key cache outlives its password', trace: `concurrent: ${name}`, after: after.fingerprint });
    }
    // Two password changes from the same starting password: exactly one may win.
    if (competing && failed !== 1) {
      violations.push({ kind: 'I5 competing password changes: expected exactly one winner', trace: `concurrent: ${name}`, after: after.fingerprint });
    }
  };
  const legacyA = starts.find((st) => st.name === 'v2(A)');
  await runPair(
    'reset(A->B) || reset(A->C)',
    legacyA,
    ops[4],
    op('reset(A->C)', () => resetFlow(PASSWORDS.A, PASSWORDS.C), 'C'),
    true
  );
  await runPair('reset(A->B) || sign(A)', legacyA, ops[4], ops[3]);
  await runPair('reset(A->B) || unlock(A)', legacyA, ops[4], ops[1]);

  return {
    concurrent,
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
    `[model] faults=${result.faults} depth=${result.depth} states=${result.states} transitions=${result.transitions} violations=${result.violations.length} refused-migrations=${result.quietedErrors}`
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
    console.log(`[model] concurrent ${c.name}: rejected=${c.failed} live=${c.after.liveLabel} cache=${c.after.cacheLabel}`);
  }
  for (const [key, count] of result.observations) {
    console.log(`[model] observation (policy, not a violation): ${key} (${count} states)`);
  }
  if (result.violations.length === 0) {
    console.log('[model] all invariants held on every explored transition');
  }
}
