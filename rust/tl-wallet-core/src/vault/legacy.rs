//! Import-only decryption of what the shipped extension wrote.
//!
//! Legacy call sites (`TL-Extension` @ e16cb4e): `CryptoJS.AES.encrypt(text, password)` with a
//! STRING password in `components/PasswordSetup.js:34`, `components/ResetPass.js:44` and
//! `lib/walletUtils.js:332`. crypto-js 4.2.0 then uses its `PasswordBasedCipher`:
//!
//! * 8 random salt bytes;
//! * OpenSSL `EVP_BytesToKey` with MD5 and ONE iteration: `D1 = MD5(pw || salt)`,
//!   `Dn = MD5(Dn-1 || pw || salt)`, key = `D1 || D2` (32 bytes), IV = `D3` (16 bytes); the
//!   password is its UTF-8 encoding;
//! * AES-256-CBC with PKCS#7 padding;
//! * output `base64("Salted__" || salt || ciphertext)`.
//!
//! `components/DelegatedSigner.js:36-44` passes a `WordArray` KEY (the PBKDF2 output) instead of a
//! string. crypto-js then takes the `SerializableCipher` path, which does no key derivation and
//! gets no IV, and throws `TypeError` inside CBC before returning anything. The decrypt side
//! fails the same way. No ciphertext in that format can exist, so there is nothing to import;
//! [`delegated_signer_key`] documents the key derivation only (parity-checked against crypto-js).

use aes::Aes256;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

use super::Secret;

const MAGIC: &[u8; 8] = b"Salted__";
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const BLOCK: usize = 16;
/// Upper bound on a legacy blob (a seed or a cached key is a few hundred bytes).
pub const MAX_LEGACY_BASE64: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyError {
    /// Not standard padded base64, or longer than [`MAX_LEGACY_BASE64`].
    NotBase64,
    /// Does not start with the OpenSSL `Salted__` header. (crypto-js can parse unsalted input,
    /// but its encrypt path with a string password always salts, so no such data exists.)
    NoSaltHeader,
    /// No ciphertext, or not a multiple of the AES block size.
    BadLength,
    /// PKCS#7 padding invalid: wrong password, or the blob is damaged. crypto-js does not
    /// check padding and would have returned garbage here.
    BadPadding,
    /// Plaintext is not UTF-8 (crypto-js throws `Malformed UTF-8 data`).
    NotUtf8,
}

/// `EVP_BytesToKey(MD5, count = 1)` as used by crypto-js `OpenSSL` KDF: 32-byte key, 16-byte IV.
#[allow(clippy::type_complexity)]
pub fn evp_bytes_to_key(
    password: &[u8],
    salt: &[u8; 8],
) -> (Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; IV_LEN]>) {
    let mut material = Zeroizing::new([0u8; 48]);
    let mut prev = Zeroizing::new([0u8; 16]);
    for i in 0..3 {
        let mut h = Md5::new();
        if i > 0 {
            h.update(prev.as_slice());
        }
        h.update(password);
        h.update(salt);
        let d = h.finalize();
        prev.copy_from_slice(&d);
        material[i * 16..(i + 1) * 16].copy_from_slice(&d);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let mut iv = Zeroizing::new([0u8; IV_LEN]);
    key.copy_from_slice(&material[..KEY_LEN]);
    iv.copy_from_slice(&material[KEY_LEN..]);
    (key, iv)
}

/// Decrypt a blob written by `CryptoJS.AES.encrypt(text, password).toString()`.
///
/// Stricter than crypto-js in one way: the PKCS#7 padding is verified. Every legacy ciphertext
/// has valid padding, so no honest blob is refused; a wrong password is refused with
/// probability 255/256 instead of returning garbage.
pub fn decrypt_cryptojs_passphrase(blob: &str, password: &str) -> Result<Secret, LegacyError> {
    if blob.len() > MAX_LEGACY_BASE64 {
        return Err(LegacyError::NotBase64);
    }
    let raw = STANDARD
        .decode(blob.as_bytes())
        .map_err(|_| LegacyError::NotBase64)?;
    if raw.len() < MAGIC.len() + 8 || &raw[..MAGIC.len()] != MAGIC {
        return Err(LegacyError::NoSaltHeader);
    }
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&raw[8..16]);
    let body = &raw[16..];
    if body.is_empty() || body.len() % BLOCK != 0 {
        return Err(LegacyError::BadLength);
    }
    let (key, iv) = evp_bytes_to_key(password.as_bytes(), &salt);
    let mut buf = Zeroizing::new(body.to_vec());
    let dec = cbc::Decryptor::<Aes256>::new_from_slices(key.as_slice(), iv.as_slice())
        .map_err(|_| LegacyError::BadLength)?;
    let n = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| LegacyError::BadPadding)?
        .len();
    let plain = buf[..n].to_vec();
    if core::str::from_utf8(&plain).is_err() {
        return Err(LegacyError::NotUtf8);
    }
    Ok(Secret::new(plain))
}

/// The AES key `DelegatedSigner` derives: `CryptoJS.PBKDF2(password, salt, {keySize: 8,
/// iterations: 10000})`. crypto-js 4.2.0 defaults the hasher to SHA-256 and treats `salt` as the
/// UTF-8 bytes of the string (DelegatedSigner passes its 32-character hex STRING, not 16 bytes).
pub fn delegated_signer_key(password: &str, salt: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        10_000,
        out.as_mut_slice(),
    );
    out
}
