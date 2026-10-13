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
//   MUST remain decryptable, so decryptWithPassword auto-detects the legacy
//   format and falls back to CryptoJS. Callers re-encrypt successful legacy
//   decryptions to v2 (transparent upgrade-on-unlock); the legacy writer is
//   never used again. CryptoJS is imported only for this fallback path.
import CryptoJS from 'crypto-js'; // legacy fallback path only

export const VAULT_VERSION = 2;
export const KDF_NAME = 'pbkdf2-sha256';
export const PBKDF2_ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MIN_ACCEPTED_ITERATIONS = 1000;
const MAX_ACCEPTED_ITERATIONS = 10000000;

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

// Parse a v2 vault blob. Returns the decoded payload or null when the blob is
// not in the v2 format (e.g. a legacy CryptoJS blob).
const parseVaultBlob = (blob) => {
  if (typeof blob !== 'string' || blob.length === 0) return null;
  try {
    const parsed = JSON.parse(decoder.decode(base64ToBytes(blob)));
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      parsed.v !== VAULT_VERSION ||
      parsed.kdf !== KDF_NAME ||
      typeof parsed.iter !== 'number' ||
      !Number.isInteger(parsed.iter) ||
      parsed.iter < MIN_ACCEPTED_ITERATIONS ||
      parsed.iter > MAX_ACCEPTED_ITERATIONS ||
      typeof parsed.salt !== 'string' ||
      typeof parsed.iv !== 'string' ||
      typeof parsed.ct !== 'string'
    ) {
      return null;
    }
    return parsed;
  } catch (_) {
    return null;
  }
};

// Legacy CryptoJS passphrase-AES blobs are OpenSSL "Salted__" data, i.e. their
// base64 form starts with "U2FsdGVkX1".
export const isLegacyVaultBlob = (blob) =>
  typeof blob === 'string' && blob.startsWith('U2FsdGVkX1');

const decryptionError = () =>
  new Error('Failed to decrypt vault data: wrong password or corrupted data.');

/**
 * Encrypt `plaintext` under `password` and return the serialized v2 vault blob.
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
 * @returns {Promise<string>} the plaintext
 */
export async function decryptWithPassword(blob, password) {
  const { plaintext } = await decryptWithPasswordInfo(blob, password);
  return plaintext;
}

/**
 * Same as decryptWithPassword but reports which format the blob was in, so
 * callers can transparently re-encrypt legacy blobs to the v2 format.
 * @param {string} blob
 * @param {string} password
 * @returns {Promise<{plaintext: string, legacy: boolean}>}
 */
export async function decryptWithPasswordInfo(blob, password) {
  if (typeof blob !== 'string' || blob.length === 0) {
    throw decryptionError();
  }
  if (typeof password !== 'string' || password.length === 0) {
    throw decryptionError();
  }

  const parsed = parseVaultBlob(blob);
  if (parsed) {
    // v2 vault blob. AES-GCM authentication failure means wrong password or
    // tampered data; do not fall back to the legacy path for v2 blobs.
    let plaintextBytes = null;
    try {
      const key = await deriveAesKey(
        password,
        base64ToBytes(parsed.salt),
        parsed.iter
      );
      plaintextBytes = new Uint8Array(
        await getSubtle().decrypt(
          { name: 'AES-GCM', iv: base64ToBytes(parsed.iv) },
          key,
          base64ToBytes(parsed.ct)
        )
      );
      return { plaintext: decoder.decode(plaintextBytes), legacy: false };
    } catch (_) {
      throw decryptionError();
    } finally {
      wipeBytes(plaintextBytes);
    }
  }

  // Legacy CryptoJS passphrase-AES format (kept decryptable for migration).
  let wordArray = null;
  try {
    wordArray = CryptoJS.AES.decrypt(blob, password);
    const plaintext = wordArray.toString(CryptoJS.enc.Utf8);
    if (!plaintext) {
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

/**
 * Transparent migration helper: if `blob` (a legacy blob just decrypted to
 * `plaintext`) is still the value stored under `storageKey`, re-encrypt the
 * plaintext to the v2 format and write it back. No-op when the stored value
 * changed in the meantime. Returns the upgraded blob, or null when unchanged.
 * @param {string} storageKey
 * @param {string} blob
 * @param {string} plaintext
 * @param {string} password
 * @returns {Promise<string|null>}
 */
export async function maybeUpgradeStoredBlob(storageKey, blob, plaintext, password) {
  try {
    const store = globalThis.localStorage;
    if (!store || store.getItem(storageKey) !== blob) {
      return null;
    }
    const upgraded = await encryptWithPassword(plaintext, password);
    if (store.getItem(storageKey) === blob) {
      store.setItem(storageKey, upgraded);
      return upgraded;
    }
    return null;
  } catch (_) {
    // Migration must never break the calling flow.
    return null;
  }
}
