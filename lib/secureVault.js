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
//   - maybeUpgradeStoredBlob refuses to migrate any plaintext that does not
//     validate, and keeps a one-time backup of the pre-migration blob.
import CryptoJS from 'crypto-js'; // legacy fallback path only
import * as bip39 from 'bip39'; // plaintext validation for legacy seed decrypts

export const VAULT_VERSION = 2;
export const KDF_NAME = 'pbkdf2-sha256';
export const PBKDF2_ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
// v2 blobs must declare a PBKDF2 iteration count inside this tolerance band
// around PBKDF2_ITERATIONS. 600,000 is the only value we write; the band
// admits previously written builds while rejecting KDF downgrades
// (iter: 1000 is cheap to brute-force) and DoS upgrades (iter: 10,000,000
// costs seconds per decrypt in the approval popup).
const MIN_ACCEPTED_ITERATIONS = 100000;
const MAX_ACCEPTED_ITERATIONS = 1000000;

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

const deriveAesKey = async (password, salt, iterations) => {
  const baseKey = await getSubtle().importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return getSubtle().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
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
  typeof parsed.iter === 'number' &&
  Number.isInteger(parsed.iter) &&
  parsed.iter >= MIN_ACCEPTED_ITERATIONS &&
  parsed.iter <= MAX_ACCEPTED_ITERATIONS &&
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
 * Private-key caches must decrypt to canonical base64 of exactly 32 raw key
 * bytes (the same shape walletUtils.signTransaction / signInputsInPsbt check
 * with `keyBuffer.length !== 32`).
 * @param {string} plaintext
 * @returns {boolean}
 */
export function validatePrivateKeyPlaintext(plaintext) {
  if (typeof plaintext !== 'string') return false;
  const trimmed = plaintext.trim();
  // 32 bytes -> 44 base64 chars: 43 chars from the alphabet plus one '=' pad.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) return false;
  try {
    return base64ToBytes(trimmed).length === 32;
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
    const key = await deriveAesKey(password, salt, PBKDF2_ITERATIONS);
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
 * (a wrong password can otherwise "succeed" with garbage). Empty passwords
 * are accepted ONLY on the legacy read path (legacy CryptoJS blobs may have
 * been created with an empty password).
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

  // Vault envelope: v2 (or newer) data. Empty passwords are impossible here
  // (the v2 writer requires a non-empty password), so reject them outright.
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
    const key = await deriveAesKey(
      password,
      base64ToBytes(envelope.salt),
      envelope.iter
    );
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
// Migration
// ---------------------------------------------------------------------------

/**
 * One-time backup of a stored blob before it is first overwritten by an
 * upgrade/re-encrypt. The first backup wins, so later migrations or password
 * changes never clobber the original ciphertext.
 * @param {string} storageKey
 * @param {string} blob the current (soon to be replaced) stored value
 */
export function backupStoredBlobOnce(storageKey, blob) {
  const store = globalThis.localStorage;
  if (!store) return;
  const backupKey = `${storageKey}.bak`;
  if (!store.getItem(backupKey)) {
    store.setItem(backupKey, blob);
  }
}

/**
 * Transparent migration helper: if `blob` (a legacy blob just decrypted to
 * `plaintext`) is still the value stored under `storageKey`, re-encrypt the
 * plaintext to the v2 format and write it back. No-op when the stored value
 * changed in the meantime.
 *
 * Refuses to migrate unless `expect` is given AND `plaintext` validates as
 * that kind — garbage from a wrong-password legacy decrypt must never be
 * written over the real ciphertext. Keeps a one-time `.bak` of the old blob
 * before the first overwrite. Returns the upgraded blob, or null when
 * unchanged/not migrated.
 * @param {string} storageKey
 * @param {string} blob
 * @param {string} plaintext
 * @param {string} password
 * @param {string} [expect] PLAINTEXT_KIND the plaintext must satisfy (required)
 * @returns {Promise<string|null>}
 */
export async function maybeUpgradeStoredBlob(storageKey, blob, plaintext, password, expect) {
  const validate = validatorFor(expect);
  try {
    // Never migrate an unvalidated (or invalid) plaintext: this is the exact
    // path that previously turned a wrong-password false positive into
    // permanent seed loss.
    if (!validate || !validate(plaintext)) {
      return null;
    }
    // v2 encryption requires a non-empty password; empty-password legacy
    // users keep their blob until they set one.
    if (typeof password !== 'string' || password.length === 0) {
      return null;
    }
    const store = globalThis.localStorage;
    if (!store || store.getItem(storageKey) !== blob) {
      return null;
    }
    const upgraded = await encryptWithPassword(plaintext, password);
    if (store.getItem(storageKey) !== blob) {
      return null;
    }
    backupStoredBlobOnce(storageKey, blob);
    store.setItem(storageKey, upgraded);
    return upgraded;
  } catch (_) {
    // Migration must never break the calling flow.
    return null;
  }
}
