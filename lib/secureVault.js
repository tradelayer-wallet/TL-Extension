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
//   - every write of the encrypted seed goes through replaceStoredBlob, which
//     validates the plaintext first, keeps the displaced blob in a backup
//     slot, and only keeps the new blob once it decrypts back correctly.
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
 * Seed blobs must decrypt to a bare BIP39 mnemonic string. (Verified against
 * every historical writer: pre-PR PasswordSetup.js encrypted `seedPhrase`
 * directly — `bip39.generateMnemonic()` output or the validated lowercase
 * import — with no wrapper or extra metadata, and current PasswordSetup.js /
 * ResetPass.js write the same plaintext.)
 * @param {string} plaintext
 * @returns {boolean}
 */
export function validateSeedPlaintext(plaintext) {
  if (typeof plaintext !== 'string') return false;
  return bip39.validateMnemonic(plaintext.trim());
}

/**
 * Private-key caches must decrypt to the CANONICAL base64 encoding of exactly
 * 32 raw key bytes (the same shape walletUtils.signTransaction /
 * signInputsInPsbt check with `keyBuffer.length !== 32`). Canonicality is
 * enforced by a decode/re-encode round-trip: a string whose final character
 * carries non-zero pad bits decodes to the same 32 bytes but does not
 * round-trip, so it is rejected. Every writer in this codebase (btoa and
 * Buffer base64) emits the canonical form.
 * @param {string} plaintext
 * @returns {boolean}
 */
export function validatePrivateKeyPlaintext(plaintext) {
  if (typeof plaintext !== 'string') return false;
  const trimmed = plaintext.trim();
  // 32 bytes -> 44 base64 chars: 43 chars from the alphabet plus one '=' pad.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) return false;
  try {
    const bytes = base64ToBytes(trimmed);
    const canonical = bytesToBase64(bytes);
    wipeBytes(bytes);
    return canonical === trimmed;
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
// Stored blobs: key namespace, backup slots and transactional replacement
// ---------------------------------------------------------------------------

// The private-key cache namespace and the backup slots are defined here only,
// so writers and sweeps share one answer to "is this a key cache or a backup".
export const PRIVATE_KEY_CACHE_PREFIX = 'encryptedPrivateKey';
// `.bak`: the first blob ever displaced by a write (one-time, never replaced).
// `.prev`: the blob displaced by the most recent write.
const BACKUP_SUFFIX = '.bak';
const PREVIOUS_SUFFIX = '.prev';

const backupKeyFor = (storageKey) => `${storageKey}${BACKUP_SUFFIX}`;
const previousKeyFor = (storageKey) => `${storageKey}${PREVIOUS_SUFFIX}`;

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

class StoredBlobConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StoredBlobConflictError';
  }
}

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

const VAULT_WRITE_LOCK = 'tl-extension:vault-writes';

/**
 * Transactional replacement of a stored blob. The ordering guarantees that the
 * only copy of the seed is never removed before its replacement is verified:
 *   1. pre-check: the stored value must still equal `previousValue` (the value
 *      the caller read and validated against); otherwise nothing is written;
 *   2. the displaced value is persisted to `<key>.prev` (and to `<key>.bak` when
 *      no one-time backup exists yet) before the main key is touched;
 *   3. `newValue` is written and read back. A different stored value means
 *      another page wrote after us; it is left in place, never overwritten;
 *   4. `verify(newValue)` runs. If it fails and the stored value is still ours,
 *      `previousValue` is restored.
 * Where the Web Locks API exists, the steps run under a lock shared by all
 * extension pages of this origin, so seed writers cannot interleave. Where it
 * does not, the read-back in step 3 is the only guard: it catches a foreign
 * write that lands after ours, but a foreign write landing just before ours is
 * overwritten and cannot be detected with plain localStorage.
 * @param {string} storageKey
 * @param {string|null} previousValue the value this write must replace
 * @param {string} newValue
 * @param {(stored: string) => Promise<void>} verify throws unless `stored` is good
 * @returns {Promise<string>} `newValue`
 */
const commitStoredBlob = (storageKey, previousValue, newValue, verify) => {
  const locks = globalThis.navigator && globalThis.navigator.locks;
  const run = () => commitStoredBlobLocked(storageKey, previousValue, newValue, verify);
  return locks ? locks.request(VAULT_WRITE_LOCK, run) : run();
};

async function commitStoredBlobLocked(storageKey, previousValue, newValue, verify) {
  const store = requireStore();
  const prior = previousValue ?? null;
  if (typeof newValue !== 'string' || newValue.length === 0) {
    throw new Error('Refusing to write an empty vault blob.');
  }
  if ((store.getItem(storageKey) ?? null) !== prior) {
    throw new StoredBlobConflictError('Stored vault data changed concurrently; nothing was overwritten.');
  }
  if (prior !== null) {
    if (!store.getItem(backupKeyFor(storageKey))) {
      persistBackup(store, backupKeyFor(storageKey), prior);
    }
    persistBackup(store, previousKeyFor(storageKey), prior);
  }
  store.setItem(storageKey, newValue);
  if (store.getItem(storageKey) !== newValue) {
    throw new StoredBlobConflictError(
      'Stored vault data changed concurrently during the write; the newer value was left in place.'
    );
  }
  try {
    await verify(newValue);
  } catch (error) {
    // Roll back only our own write. A foreign value is never touched.
    if (store.getItem(storageKey) === newValue) {
      if (prior === null) {
        store.removeItem(storageKey);
      } else {
        store.setItem(storageKey, prior);
      }
    }
    throw error;
  }
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
 * Encrypt `plaintext` as v2 under `password` and transactionally replace
 * `previousValue` at `storageKey` (see commitStoredBlob). Every write of the
 * encrypted seed goes through here: plaintext that fails `expect` is refused
 * before encryption, and the new blob is kept only once it decrypts back to
 * `plaintext`.
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
  return commitStoredBlob(storageKey, previousValue, blob, verifyDecryptsTo(password, expect, plaintext));
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
 * @param {string} [expect] PLAINTEXT_KIND the plaintext must satisfy (required)
 * @returns {Promise<string|null>}
 */
export async function maybeUpgradeStoredBlob(storageKey, blob, plaintext, password, expect) {
  try {
    return await replaceStoredBlob(storageKey, blob, plaintext, password, expect);
  } catch (error) {
    if (error instanceof StoredBlobConflictError) {
      console.error('secureVault: migration aborted, stored data changed concurrently:', error.message);
    }
    return null;
  }
}

/**
 * Recovery: promotes the one-time `<key>.bak` blob to the current blob. The
 * backup must open under `password` as `expect` before anything is written,
 * and the blob it displaces is kept in `<key>.prev`, so the restore itself
 * never destroys a copy that still works. Returns the restored blob, or null
 * when there is no backup. Throws when the backup does not open (for example
 * a wrong password) or the write cannot be verified.
 * @param {string} [storageKey]
 * @param {string} password password that opens the BACKUP blob (may be ''
 *   for legacy empty-password wallets)
 * @param {string} [expect] PLAINTEXT_KIND (default PLAINTEXT_KIND.SEED)
 * @returns {Promise<string|null>}
 */
export async function restoreFromBackup(storageKey = 'encryptedSeed', password, expect = PLAINTEXT_KIND.SEED) {
  const store = requireStore();
  const backup = store.getItem(backupKeyFor(storageKey));
  if (!backup) return null;
  const { plaintext } = await decryptWithPasswordInfo(backup, password, expect);
  const current = store.getItem(storageKey);
  if (current === backup) return backup;
  return commitStoredBlob(storageKey, current, backup, verifyDecryptsTo(password, expect, plaintext));
}
