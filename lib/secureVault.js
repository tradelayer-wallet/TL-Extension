// Secure vault for encrypting seed phrases and private keys at rest.
//
// Format v2 (written from now on):
//   base64(JSON { v: 2, kdf: 'pbkdf2-sha256', iter, salt, iv, ct })
//   - KDF:    PBKDF2-SHA256, 600,000 iterations, 16-byte random per-item salt
//   - Cipher: AES-256-GCM, 12-byte random IV (WebCrypto via globalThis.crypto,
//     so the module works in the extension popup and under Node 18+)
//
// Format v1 (legacy, read-only): CryptoJS passphrase-AES ("Salted__" / OpenSSL
//   EVP_BytesToKey with MD5 and 1 iteration). Existing users' encrypted seeds
//   MUST remain decryptable, so decryptWithPasswordInfo auto-detects the
//   legacy format and falls back to CryptoJS. Callers re-encrypt successful
//   legacy decryptions to v2 (transparent upgrade-on-unlock); the legacy
//   writer is never used again. CryptoJS is imported only for this fallback.
//
// Legacy decryption is UNAUTHENTICATED: a wrong password frequently yields
// garbage that survives a plain non-empty check (measured: ~0.5% of wrong
// passwords "succeed" deterministically). Accepting such garbage and then
// migrating it would re-encrypt the garbage over the real ciphertext —
// irreversible seed loss. Therefore:
//   - a legacy decrypt is ONLY returned when the caller states what the
//     plaintext must look like (`expect`, see PLAINTEXT_KIND) and the
//     decrypted data passes that validation; anything else is "wrong
//     password";
//   - every write of vault data goes through one primitive (commitStoredBlob),
//     reached via replaceStoredBlob (encrypt + store), storeKeyCacheBlob (store
//     a derived key cache), restoreFromBackup, or discardKeyCacheBlob (remove a
//     stale key cache). Each validates what it stores, keeps the displaced seed
//     for recovery, and keeps the new value only once it decrypts back
//     correctly. Writes run under the Web Lock and fail closed when
//     navigator.locks is unavailable.
import CryptoJS from 'crypto-js'; // legacy fallback path only
import * as bip39 from 'bip39'; // plaintext validation for legacy seed decrypts

export const VAULT_VERSION = 2;
export const KDF_NAME = 'pbkdf2-sha256';
// The single source of truth for the v2 KDF: encryptWithPassword writes these
// values and decryptWithPasswordInfo derives with them. A blob declaring any
// other iteration count is rejected before anything is derived (attacker-chosen
// counts are both a KDF downgrade and a popup DoS). Changing either value needs
// a new VAULT_VERSION, because existing blobs would no longer open.
export const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';
const SALT_BYTES = 16;
const IV_BYTES = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const getSubtle = () => {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) {
    throw new Error('WebCrypto (globalThis.crypto.subtle) is unavailable.');
  }
  return subtle;
};

const randomBytes = (length) => {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
};

const bytesToBase64 = (bytes) => {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const base64ToBytes = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const wipeBytes = (bytes) => {
  if (bytes && typeof bytes.fill === 'function') {
    bytes.fill(0);
  }
};

const deriveAesKey = async (password, salt) => {
  const baseKey = await getSubtle().importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return getSubtle().deriveKey(
    { name: 'PBKDF2', hash: PBKDF2_HASH, salt, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

// Decode a vault envelope (any version). Returns the parsed object when the
// blob is vault-shaped, null otherwise (e.g. a legacy CryptoJS blob).
const decodeVaultEnvelope = (blob) => {
  if (typeof blob !== 'string' || blob.length === 0) return null;
  try {
    const parsed = JSON.parse(decoder.decode(base64ToBytes(blob)));
    if (
      parsed &&
      typeof parsed === 'object' &&
      typeof parsed.v === 'number'
    ) {
      return parsed;
    }
    return null;
  } catch (_) {
    return null;
  }
};

// Strict parameter check for v2 envelopes. Anything vault-shaped that fails
// this check is REJECTED outright (never sent down the legacy path).
const hasValidVaultParams = (parsed) =>
  parsed.v === VAULT_VERSION &&
  parsed.kdf === KDF_NAME &&
  parsed.iter === PBKDF2_ITERATIONS &&
  typeof parsed.salt === 'string' &&
  typeof parsed.iv === 'string' &&
  typeof parsed.ct === 'string';

// Legacy CryptoJS passphrase-AES blobs are OpenSSL "Salted__" data, i.e. their
// base64 form starts with "U2FsdGVkX1".
export const isLegacyVaultBlob = (blob) =>
  typeof blob === 'string' && blob.startsWith('U2FsdGVkX1');

const decryptionError = () =>
  new Error('Failed to decrypt vault data: wrong password or corrupted data.');

const unsupportedVaultError = () =>
  new Error('Failed to decrypt vault data: unsupported vault parameters.');

// ---------------------------------------------------------------------------
// Plaintext-shape validation. Legacy (CryptoJS) decryptions cannot be
// authenticated, so a decrypt is only accepted when its plaintext matches the
// shape the caller expects. Wrong-password garbage essentially never does.
// ---------------------------------------------------------------------------

export const PLAINTEXT_KIND = {
  SEED: 'seed',
  PRIVATE_KEY: 'privateKey',
};

/**
 * Seed blobs must decrypt to a bare seed phrase, with no wrapper or metadata.
 * Current writers store a valid lowercase BIP39 mnemonic: bip39.generateMnemonic()
 * output, or an import that SeedPhraseImport checks against the wordlist and
 * checksum. The released import before the vault rework did neither: it stored
 * the 12 words as typed (each trimmed, joined by single spaces, case kept, no
 * wordlist or checksum check), and keys were derived from that exact string. Those
 * wallets must keep opening and keep deriving the same keys, so a seed is also
 * accepted when it has the shape that import produced: 12 to 24 words of ASCII
 * letters separated by spaces. The shape is what tells an unauthenticated legacy
 * decryption under a wrong password from a seed: random bytes take that form with
 * probability below 2^-160 even for the shortest phrase.
 * @param {string} plaintext
 * @returns {boolean}
 */
const LEGACY_IMPORT_SEED_PHRASE = /^[A-Za-z]{1,16}(?: +[A-Za-z]{1,16}){11,23}$/;

export function validateSeedPlaintext(plaintext) {
  if (typeof plaintext !== 'string') return false;
  return bip39.validateMnemonic(plaintext.trim()) || LEGACY_IMPORT_SEED_PHRASE.test(plaintext);
}

/**
 * Private-key caches must decrypt to the CANONICAL base64 encoding of exactly
 * 32 raw key bytes (the same shape walletUtils.signTransaction /
 * signInputsInPsbt check with `keyBuffer.length !== 32`). Canonicality is
 * enforced by a decode/re-encode round-trip over the exact string: a string
 * whose final character carries non-zero pad bits decodes to the same 32 bytes
 * but does not round-trip, so it is rejected. Surrounding whitespace is not
 * part of the canonical form and is rejected too. Every writer in this
 * codebase (btoa and Buffer base64) emits the canonical form.
 * @param {string} plaintext
 * @returns {boolean}
 */
export function validatePrivateKeyPlaintext(plaintext) {
  if (typeof plaintext !== 'string') return false;
  // 32 bytes -> 44 base64 chars: 43 chars from the alphabet plus one '=' pad.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(plaintext)) return false;
  try {
    const bytes = base64ToBytes(plaintext);
    const canonical = bytesToBase64(bytes);
    wipeBytes(bytes);
    return canonical === plaintext;
  } catch (_) {
    return false;
  }
}

const validatorFor = (expect) => {
  if (expect === PLAINTEXT_KIND.SEED) return validateSeedPlaintext;
  if (expect === PLAINTEXT_KIND.PRIVATE_KEY) return validatePrivateKeyPlaintext;
  if (expect === undefined || expect === null) return null;
  throw new Error(`Unknown expected vault plaintext kind: ${expect}`);
};

// ---------------------------------------------------------------------------
// Password policy for NEW v2 encryption. (Existing passwords — including
// legacy empty ones — must keep working on the read path; the policy only
// applies when a new password is chosen.)
// ---------------------------------------------------------------------------

export const NEW_PASSWORD_MIN_LENGTH = 8;

/**
 * Minimal policy for newly chosen passwords.
 * @param {string} password
 * @returns {string|null} an error message, or null when acceptable
 */
export function checkNewPasswordPolicy(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return 'Password must not be empty.';
  }
  if (password.length < NEW_PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${NEW_PASSWORD_MIN_LENGTH} characters long.`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt `plaintext` under `password` and return the serialized v2 vault blob.
 * New v2 encryption always requires a non-empty password (empty passwords were
 * only ever possible with the legacy writer and stay readable on its path).
 * @param {string} plaintext
 * @param {string} password
 * @returns {Promise<string>}
 */
export async function encryptWithPassword(plaintext, password) {
  if (typeof plaintext !== 'string') {
    throw new Error('Vault plaintext must be a string.');
  }
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Vault password must be a non-empty string.');
  }

  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);

  let blob = null;
  try {
    const key = await deriveAesKey(password, salt);
    const ciphertext = await getSubtle().encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(plaintext)
    );
    const payload = {
      v: VAULT_VERSION,
      kdf: KDF_NAME,
      iter: PBKDF2_ITERATIONS,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ct: bytesToBase64(new Uint8Array(ciphertext)),
    };
    blob = bytesToBase64(encoder.encode(JSON.stringify(payload)));
  } finally {
    wipeBytes(salt);
    wipeBytes(iv);
  }
  return blob;
}

/**
 * Decrypt a vault blob with `password`, auto-detecting the format:
 * v2 blobs are decrypted with AES-256-GCM; anything else falls back to the
 * legacy CryptoJS passphrase-AES format. Throws on wrong password/corruption.
 * @param {string} blob
 * @param {string} password
 * @param {string} [expect] PLAINTEXT_KIND the plaintext must satisfy (required
 *   for legacy blobs; strongly recommended everywhere)
 * @returns {Promise<string>} the plaintext
 */
export async function decryptWithPassword(blob, password, expect) {
  const { plaintext } = await decryptWithPasswordInfo(blob, password, expect);
  return plaintext;
}

/**
 * Same as decryptWithPassword but reports which format the blob was in, so
 * callers can transparently re-encrypt legacy blobs to the v2 format.
 *
 * Never accepts a legacy decrypt without validating it against `expect`
 * (a wrong password can otherwise "succeed" with garbage). Empty passwords are
 * accepted ONLY on the legacy read path (legacy CryptoJS blobs may have been
 * created with an empty password).
 * @param {string} blob
 * @param {string} password
 * @param {string} [expect] PLAINTEXT_KIND the plaintext must satisfy (required
 *   for legacy blobs; strongly recommended everywhere)
 * @returns {Promise<{plaintext: string, legacy: boolean}>}
 */
export async function decryptWithPasswordInfo(blob, password, expect) {
  if (typeof blob !== 'string' || blob.length === 0) {
    throw decryptionError();
  }
  if (typeof password !== 'string') {
    throw decryptionError();
  }
  const validate = validatorFor(expect);

  const envelope = decodeVaultEnvelope(blob);

  if (!envelope) {
    // Legacy CryptoJS passphrase-AES format (kept decryptable for migration).
    // Its decryptions are unauthenticated, so refuse to run without a
    // plaintext shape to validate against, and never return plaintext that
    // fails validation: both are indistinguishable from a wrong password.
    if (!validate) {
      throw new Error(
        'Refusing to decrypt a legacy vault blob without an expected plaintext kind. ' +
        'Pass PLAINTEXT_KIND.SEED or PLAINTEXT_KIND.PRIVATE_KEY.'
      );
    }
    let wordArray = null;
    try {
      wordArray = CryptoJS.AES.decrypt(blob, password);
      const plaintext = wordArray.toString(CryptoJS.enc.Utf8);
      if (!plaintext || !validate(plaintext)) {
        throw decryptionError();
      }
      return { plaintext, legacy: true };
    } catch (_) {
      throw decryptionError();
    } finally {
      if (wordArray && Array.isArray(wordArray.words)) {
        for (let i = 0; i < wordArray.words.length; i += 1) {
          wordArray.words[i] = 0;
        }
        wordArray.sigBytes = 0;
      }
    }
  }

  // Vault envelope (v2). Empty passwords are impossible here (the v2 writer
  // requires a non-empty password), so reject them outright.
  if (password.length === 0) {
    throw decryptionError();
  }
  if (!hasValidVaultParams(envelope)) {
    // Reject before deriving anything: an attacker-supplied envelope must not
    // be able to downgrade the KDF (iter: 1000) or stall the popup for
    // seconds per decrypt (iter: 10_000_000). Never falls back to the legacy
    // path for vault-shaped data.
    throw unsupportedVaultError();
  }

  let plaintextBytes = null;
  try {
    const key = await deriveAesKey(password, base64ToBytes(envelope.salt));
    plaintextBytes = new Uint8Array(
      await getSubtle().decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(envelope.iv) },
        key,
        base64ToBytes(envelope.ct)
      )
    );
    const plaintext = decoder.decode(plaintextBytes);
    if (validate && !validate(plaintext)) {
      throw decryptionError();
    }
    return { plaintext, legacy: false };
  } catch (_) {
    throw decryptionError();
  } finally {
    wipeBytes(plaintextBytes);
  }
}

// ---------------------------------------------------------------------------
// Stored blobs: key namespace, backup slots and the single write primitive
// ---------------------------------------------------------------------------

// The seed key, the private-key cache namespace and the backup slots are
// defined here only, so writers, recovery and sweeps share one answer.
export const SEED_STORAGE_KEY = 'encryptedSeed';
export const PRIVATE_KEY_CACHE_PREFIX = 'encryptedPrivateKey';
// Single-key entry written by the pre-vault wallet; swept, never read.
export const LEGACY_KEY_CACHE_ENTRY = 'encryptedKey';
// `.bak`: the first v2 seed blob ever displaced by a write (one-time, never
//   replaced). A legacy CryptoJS blob is never kept here: the legacy format is
//   cheap to brute-force, so keeping it would weaken the v2 copy of the same
//   seed under the same password. A verified migration leaves the v2 copy.
// `.prev`: the seed blob displaced by the write in progress. A completed write
//   or rollback removes it, so it only exists during a write, after an
//   interrupted one, or after a restore (which keeps what it displaces).
const BACKUP_SUFFIX = '.bak';
const PREVIOUS_SUFFIX = '.prev';

const backupKeyFor = (storageKey) => `${storageKey}${BACKUP_SUFFIX}`;
const previousKeyFor = (storageKey) => `${storageKey}${PREVIOUS_SUFFIX}`;

// Only the seed has backup slots. Key caches are derived from the seed and
// re-created on demand (walletUtils.getOrDeriveKeyPair); their old ciphertext
// has no recovery value, so they are never backed up.
const isBackedUpKey = (storageKey) => storageKey === SEED_STORAGE_KEY;

/**
 * True for backup slots (`<key>.bak`, `<key>.prev`). Backups are recovery
 * copies and must survive cache sweeps.
 * @param {string} key
 * @returns {boolean}
 */
export const isVaultBackupKey = (key) =>
  typeof key === 'string' && (key.endsWith(BACKUP_SUFFIX) || key.endsWith(PREVIOUS_SUFFIX));

/**
 * True for live private-key cache entries (not their backups).
 * @param {string} key
 * @returns {boolean}
 */
export const isPrivateKeyCacheKey = (key) =>
  typeof key === 'string' &&
  key.startsWith(PRIVATE_KEY_CACHE_PREFIX) &&
  !isVaultBackupKey(key);

/**
 * Removes every private-key cache entry and the legacy single-key entry. Every
 * removal is attempted; if any fails, an error is thrown after the others, so a
 * partial sweep is never reported as complete. Backup slots are never removed.
 * @param {Storage} store
 */
export function removeKeyCaches(store) {
  const keys = [];
  for (let i = 0; i < store.length; i += 1) {
    const key = store.key(i);
    if (isPrivateKeyCacheKey(key)) keys.push(key);
  }
  keys.push(LEGACY_KEY_CACHE_ENTRY);
  let failed = 0;
  for (const key of keys) {
    try {
      store.removeItem(key);
    } catch (_) {
      failed += 1;
    }
  }
  if (failed > 0) {
    throw new Error(`Could not remove ${failed} key cache entr${failed === 1 ? 'y' : 'ies'}.`);
  }
}

class StoredBlobConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StoredBlobConflictError';
  }
}

/**
 * True when a write was refused or reverted because another writer changed
 * the stored value. Nothing of ours was left in place in that case.
 * @param {unknown} error
 * @returns {boolean}
 */
export const isStoredBlobConflictError = (error) =>
  error instanceof StoredBlobConflictError;

const requireStore = () => {
  const store = globalThis.localStorage;
  if (!store) {
    throw new Error('localStorage is unavailable; vault data was not written.');
  }
  return store;
};

// Write a backup slot and confirm it persisted before anything it protects is
// overwritten.
const persistBackup = (store, key, value) => {
  store.setItem(key, value);
  if (store.getItem(key) !== value) {
    throw new Error(`Backup ${key} did not persist; nothing was overwritten.`);
  }
};

// Remove the displaced copy once the write it protected is complete. Best
// effort: the write has already succeeded, so a failure here must not be
// reported as a failed write. A leftover .prev only costs retention, and the
// next write overwrites it.
const dropPrevious = (store, storageKey, displaced) => {
  try {
    if (store.getItem(previousKeyFor(storageKey)) === displaced) {
      store.removeItem(previousKeyFor(storageKey));
    }
  } catch (_) {
    // see above: cleanup is not part of the write's outcome
  }
};

const VAULT_WRITE_LOCK = 'tl-extension:vault-writes';

/**
 * THE write primitive. Every write of vault data (seed or key cache) goes
 * through here; nothing else calls localStorage.setItem for a vault key.
 *
 * Steps, with the crash-safety argument for each:
 *   0. the write lock is held (see Concurrency); without Web Locks nothing is
 *      written at all;
 *   1. pre-check: the stored value must still equal `previousValue`, otherwise
 *      nothing is written (compare-and-swap against the caller's read). A
 *      `guard` (key cache writes) must also still hold its value;
 *   2. seed only: key caches are swept first, because they are encrypted under
 *      the seed's password and a seed write retires that password. A failed
 *      sweep aborts the write, so nothing is written;
 *   3. seed only, when there is a displaced v2 value: `<key>.bak` is written if
 *      it does not exist yet (never by a restore), and `<key>.prev` is written,
 *      both confirmed by read-back, before the live key is touched;
 *   4. `newValue` is written and read back; a different stored value means
 *      another writer got in, and it is left in place (StoredBlobConflictError);
 *   5. `verify(stored)` runs on the value read back from storage. If it fails
 *      and the live key still holds our value, `previousValue` is restored;
 *   6. on success, or after a completed rollback, `.prev` is dropped (seed
 *      only). A restore (`options.restore`) keeps `.prev` instead.
 *
 * Interruption: the seed's displaced value is in `.prev` from step 3 until
 * step 6, so it survives a crash at any point. A crash after step 4 leaves the
 * new value in the live key; if verification did not run to completion, that
 * value is unverified. Recovery is restoreFromBackup(..., 'prev'), which
 * decrypts `.prev` before writing it back.
 *
 * Concurrency: steps 1 to 6 run under one Web Lock named VAULT_WRITE_LOCK. Only
 * same-origin contexts that use this primitive take it, and every writer of
 * vault data in this extension does. Without navigator.locks the write is
 * refused (fail closed): a read-back alone cannot stop a writer that lands
 * between our check and our write, and the lock is what makes the check and
 * the write one step.
 * @param {string} storageKey
 * @param {string|null} previousValue the value this write must replace
 * @param {string} newValue
 * @param {(stored: string) => Promise<void>} verify throws unless `stored` is good
 * @param {{restore?: boolean, guard?: (store: Storage) => Promise<void>|void}} [options]
 *   restore: keep `.prev` after success, never replace a different `.prev`, and
 *   never create `.bak` (see restoreFromBackup); guard: throws to refuse the
 *   write (checked under the lock, before anything is written)
 * @returns {Promise<string>} `newValue`
 */
const commitStoredBlob = (storageKey, previousValue, newValue, verify, options = {}) =>
  withVaultLock(() => commitStoredBlobLocked(storageKey, previousValue, newValue, verify, options));

// Runs `run` holding the vault write lock. Fails closed without Web Locks.
// Never nest: the lock is not re-entrant.
const withVaultLock = (run) => {
  const locks = globalThis.navigator && globalThis.navigator.locks;
  if (!locks) {
    throw new Error('Web Locks (navigator.locks) are unavailable; vault data was not written.');
  }
  return locks.request(VAULT_WRITE_LOCK, run);
};

async function commitStoredBlobLocked(
  storageKey,
  previousValue,
  newValue,
  verify,
  { restore = false, guard = null } = {}
) {
  const store = requireStore();
  const prior = previousValue ?? null;
  if (typeof newValue !== 'string' || newValue.length === 0) {
    throw new Error('Refusing to write an empty vault blob.');
  }
  if ((store.getItem(storageKey) ?? null) !== prior) {
    throw new StoredBlobConflictError('Stored vault data changed concurrently; nothing was overwritten.');
  }
  if (guard) {
    await guard(store);
  }
  if (storageKey === SEED_STORAGE_KEY) {
    removeKeyCaches(store);
  }
  const backedUp = isBackedUpKey(storageKey) && prior !== null;
  if (backedUp) {
    // Only a v2 blob is kept as the long-term copy (see the BACKUP comments).
    if (!restore && decodeVaultEnvelope(prior) && !store.getItem(backupKeyFor(storageKey))) {
      persistBackup(store, backupKeyFor(storageKey), prior);
    }
    // A normal write displaces a value its caller has just decrypted, so it
    // may replace .prev. A restore does not decrypt the live value it displaces
    // (that value may be the unreadable result of an interrupted rollback), so
    // it must not replace a different .prev, which may be the only good copy.
    const existingPrevious = store.getItem(previousKeyFor(storageKey));
    const keepsExistingPrevious = restore && existingPrevious !== null && existingPrevious !== prior;
    if (!keepsExistingPrevious) {
      persistBackup(store, previousKeyFor(storageKey), prior);
    }
  }
  store.setItem(storageKey, newValue);
  const stored = store.getItem(storageKey);
  if (stored !== newValue) {
    throw new StoredBlobConflictError(
      'Stored vault data changed concurrently during the write; the newer value was left in place.'
    );
  }
  try {
    await verify(stored);
  } catch (error) {
    // Roll back only our own write. A foreign value is never touched.
    if (store.getItem(storageKey) === newValue) {
      if (prior === null) {
        store.removeItem(storageKey);
      } else {
        store.setItem(storageKey, prior);
      }
      if (backedUp && !restore) dropPrevious(store, storageKey, prior);
    }
    throw error;
  }
  if (backedUp && !restore) dropPrevious(store, storageKey, prior);
  return newValue;
}

// Verifier for a blob just written: it must open under `password` as `expect`
// and yield exactly `expected`.
const verifyDecryptsTo = (password, expect, expected) => async (stored) => {
  const { plaintext } = await decryptWithPasswordInfo(stored, password, expect);
  if (plaintext !== expected) {
    throw new Error('Stored vault data does not decrypt to the expected plaintext.');
  }
};

/**
 * Encrypt `plaintext` as v2 under `password` and replace `previousValue` at
 * `storageKey` through commitStoredBlob. Plaintext that fails `expect` is
 * refused before encryption, and the new blob is kept only once it decrypts
 * back to `plaintext`.
 * @param {string} storageKey
 * @param {string|null} previousValue the stored value this write replaces (null for none)
 * @param {string} plaintext
 * @param {string} password
 * @param {string} expect PLAINTEXT_KIND the plaintext must satisfy
 * @returns {Promise<string>} the stored blob
 * @throws {Error} on invalid input, a concurrent change, or failed verification
 */
export async function replaceStoredBlob(storageKey, previousValue, plaintext, password, expect) {
  const validate = validatorFor(expect);
  if (!validate) {
    throw new Error('Refusing to store vault data without an expected plaintext kind.');
  }
  if (!validate(plaintext)) {
    throw new Error('Refusing to store vault data that fails plaintext validation.');
  }
  const blob = await encryptWithPassword(plaintext, password);
  return commitStoredBlob(storageKey, previousValue, blob, verifyDecryptsTo(password, expect, plaintext), {
    guard: keyCacheGuard(storageKey, password),
  });
}

// The one password check for the seed: the stored seed must open under
// `password` and decrypt to a BIP39 mnemonic. Read-only.
const openStoredSeed = async (store, password) => {
  const blob = store.getItem(SEED_STORAGE_KEY);
  if (!blob) throw decryptionError();
  const { plaintext, legacy } = await decryptWithPasswordInfo(blob, password, PLAINTEXT_KIND.SEED);
  return { blob, plaintext, legacy };
};

/**
 * Opens the stored seed under `password` as typed. Throws when it does not
 * open. Returns the stored blob (for a compare-and-swap write), its plaintext,
 * and whether the blob is in the legacy format and should be upgraded.
 * @param {string} password
 * @returns {Promise<{blob: string, plaintext: string, legacy: boolean}>}
 */
export const openLiveSeed = (password) => openStoredSeed(requireStore(), password);

/**
 * Does the live seed open under `password`? Read-only; no lock needed.
 * @param {string} password
 * @returns {Promise<boolean>}
 */
export async function liveSeedOpensUnder(password) {
  const store = requireStore();
  return openStoredSeed(store, password).then(() => true, () => false);
}

// A private-key cache entry may be written (or migrated) only while the live
// seed still opens under the password the key was derived with. A password
// change makes the live seed refuse the old password, so a cache from before
// the change is refused after it. A migration (same password, new blob) is not
// blocked. Checked under the write lock, inside commitStoredBlob.
const keyCacheGuard = (storageKey, password) => {
  if (!isPrivateKeyCacheKey(storageKey)) return null;
  return async (store) => {
    await openStoredSeed(store, password).catch(() => {
      throw new StoredBlobConflictError(
        'The live seed does not open under the password this key was derived with; nothing was stored.'
      );
    });
  };
};

/**
 * Store a derived private-key cache entry (an already-encrypted v2 blob that
 * walletUtils has just produced) through the primitive. It is stored only when
 * it opens under `password` as a 32-byte private key and the live seed opens
 * under that same password (see keyCacheGuard).
 * @param {string} cacheKey a private-key cache key (see isPrivateKeyCacheKey)
 * @param {string} blob v2 blob produced by encryptWithPassword
 * @param {string} password the password the key was derived with
 * @returns {Promise<string>} the stored blob
 */
export async function storeKeyCacheBlob(cacheKey, blob, password) {
  if (!isPrivateKeyCacheKey(cacheKey)) {
    throw new Error('Refusing to store a value outside the private-key cache namespace.');
  }
  // decryptWithPasswordInfo validates the plaintext as a private key, so a
  // blob of any other kind fails here exactly like a wrong password.
  return commitStoredBlob(
    cacheKey,
    null,
    blob,
    async (stored) => {
      await decryptWithPasswordInfo(stored, password, PLAINTEXT_KIND.PRIVATE_KEY);
    },
    { guard: keyCacheGuard(cacheKey, password) }
  );
}

/**
 * Removes a private-key cache entry, but only while it still holds
 * `staleValue` (compare-and-swap under the write lock). A cache entry is
 * derived data, so removing one never loses access: the seed still opens and
 * the key is derived again on demand.
 * @param {string} cacheKey a private-key cache key (see isPrivateKeyCacheKey)
 * @param {string} staleValue the value the caller has just rejected
 * @returns {Promise<void>}
 */
export function discardKeyCacheBlob(cacheKey, staleValue) {
  if (!isPrivateKeyCacheKey(cacheKey)) {
    throw new Error('Refusing to remove a value outside the private-key cache namespace.');
  }
  return withVaultLock(() => {
    const store = requireStore();
    if (store.getItem(cacheKey) === staleValue) {
      store.removeItem(cacheKey);
    }
  });
}

/**
 * Transparent migration helper: re-encrypts a legacy blob (just decrypted to
 * `plaintext`) to v2 via replaceStoredBlob. The write only happens while
 * `blob` is still the stored value and the plaintext validates as `expect`.
 * Returns the upgraded blob, or null when nothing was migrated. Never throws,
 * because a migration must not break the unlock flow that triggered it.
 * @param {string} storageKey
 * @param {string} blob
 * @param {string} plaintext
 * @param {string} password
 * @param {string} expect
 * @returns {Promise<string|null>}
 */
export async function maybeUpgradeStoredBlob(storageKey, blob, plaintext, password, expect) {
  try {
    return await replaceStoredBlob(storageKey, blob, plaintext, password, expect);
  } catch (error) {
    if (isStoredBlobConflictError(error)) {
      console.error('secureVault: migration refused:', error.message);
    }
    return null;
  }
}

/**
 * Recovery: restores the seed from one of its backup slots. The slot's blob
 * must open under `password` as `expect` before anything is written, and the
 * key caches are swept first (as for any seed write).
 *   - source 'bak': the one-time first v2 blob (survives every later write)
 *   - source 'prev': the blob displaced by the last write, which is what an
 *     interrupted write leaves behind
 * Returns the restored blob, or null when that slot is empty. Throws when the
 * slot does not open under `password`, or the write cannot be verified.
 *
 * What a restore keeps, precisely: the live value it displaces goes to `.prev`
 * only when `.prev` is empty or already holds that same value. When `.prev`
 * holds a different value, that value is kept and the live value is NOT kept:
 * it is discarded, even if it still opens under another password. A restore
 * never creates `.bak`. The seed itself is never lost by a restore, because the
 * restored blob is verified and the chosen backup slot is left in place.
 * @param {string} [storageKey] must be the seed key
 * @param {string} password password that opens the chosen backup blob (may be
 *   '' for legacy empty-password wallets)
 * @param {string} [expect] PLAINTEXT_KIND (default PLAINTEXT_KIND.SEED)
 * @param {'bak'|'prev'} [source] backup slot to restore from (default 'bak')
 * @returns {Promise<string|null>}
 */
export async function restoreFromBackup(
  storageKey = SEED_STORAGE_KEY,
  password,
  expect = PLAINTEXT_KIND.SEED,
  source = 'bak'
) {
  if (!isBackedUpKey(storageKey)) {
    throw new Error('Only the seed has backup slots.');
  }
  let slotKey;
  if (source === 'bak') {
    slotKey = backupKeyFor(storageKey);
  } else if (source === 'prev') {
    slotKey = previousKeyFor(storageKey);
  } else {
    throw new Error(`Unknown backup slot: ${source}`);
  }
  // The slot is read and decrypted under the lock too, so the blob that is
  // written is the one that was checked (a writer cannot replace the slot in
  // between).
  return withVaultLock(async () => {
    const store = requireStore();
    const backup = store.getItem(slotKey);
    if (!backup) return null;
    const { plaintext } = await decryptWithPasswordInfo(backup, password, expect);
    const current = store.getItem(storageKey);
    if (current === backup) return backup;
    return commitStoredBlobLocked(storageKey, current, backup, verifyDecryptsTo(password, expect, plaintext), {
      restore: true,
    });
  });
}
