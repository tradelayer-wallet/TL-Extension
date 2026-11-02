#![allow(dead_code)]
//! Shared helpers for the vault tests: fixture parsing, a CryptoJS-compatible test encryptor,
//! and a fault-injecting store.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use std::collections::BTreeMap;
use tl_wallet_core::vault::legacy::evp_bytes_to_key;
use tl_wallet_core::vault::manager::{LEGACY_KEY_CACHE, LEGACY_KEY_CACHE_PREFIX, LEGACY_SEED_KEY};
use tl_wallet_core::vault::{MemoryStore, StoreError, VaultStore};

pub const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const PHRASE_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
pub const OLD_PW: &str = "correct horse battery staple";
pub const NEW_PW: &str = "new synthetic passphrase";

pub fn vectors() -> BTreeMap<String, String> {
    include_str!("../fixtures/vault_legacy_vectors.txt")
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.trim_end_matches('\r').to_string()))
        .collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

pub fn unhex_str(s: &str) -> String {
    String::from_utf8(unhex(s)).unwrap()
}

/// `CryptoJS.AES.encrypt(plain, password).toString()` with a caller-chosen salt, built from the
/// same primitives; the legacy parity test proves it reproduces crypto-js output byte for byte.
pub fn cryptojs_encrypt(plain: &str, password: &str, salt: [u8; 8]) -> String {
    let (key, iv) = evp_bytes_to_key(password.as_bytes(), &salt);
    let mut buf = plain.as_bytes().to_vec();
    let n = buf.len();
    buf.resize(n + 16, 0);
    let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key[..], &iv[..])
        .unwrap()
        .encrypt_padded_mut::<Pkcs7>(&mut buf, n)
        .unwrap()
        .to_vec();
    let mut raw = b"Salted__".to_vec();
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&ct);
    STANDARD.encode(raw)
}

/// A store holding a legacy wallet: encrypted seed plus two derived-key caches.
pub fn legacy_store(phrase: &str, password: &str) -> MemoryStore {
    let mut s = MemoryStore::new();
    s.put_raw(
        LEGACY_SEED_KEY,
        &cryptojs_encrypt(phrase, password, [1, 2, 3, 4, 5, 6, 7, 8]),
    );
    let cache = cryptojs_encrypt(
        &STANDARD.encode([0x11u8; 32]),
        password,
        [8, 7, 6, 5, 4, 3, 2, 1],
    );
    s.put_raw(LEGACY_KEY_CACHE, &cache);
    s.put_raw(
        &format!("{LEGACY_KEY_CACHE_PREFIX}:LTC:m/84'/2'/0'/0/0"),
        &cache,
    );
    s.put_raw("unrelated", "kept");
    s
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultMode {
    /// The failing write is not applied.
    FailBefore,
    /// The failing write is applied, then the call reports an I/O error (lost acknowledgement).
    ApplyThenFail,
}

/// A store that fails the `fail_at`-th compare-and-swap once, and can lie about reads.
pub struct FaultStore {
    pub inner: MemoryStore,
    pub calls: usize,
    pub fail_at: Option<usize>,
    pub mode: FaultMode,
    pub fired: bool,
    /// Return a one-character-altered value for reads of this key.
    pub lie_on: Option<String>,
}

impl FaultStore {
    pub fn new(inner: MemoryStore) -> Self {
        FaultStore {
            inner,
            calls: 0,
            fail_at: None,
            mode: FaultMode::FailBefore,
            fired: false,
            lie_on: None,
        }
    }

    pub fn arm(&mut self, fail_at: usize, mode: FaultMode) {
        self.calls = 0;
        self.fail_at = Some(fail_at);
        self.mode = mode;
        self.fired = false;
    }

    pub fn disarm(&mut self) {
        self.fail_at = None;
    }
}

impl VaultStore for FaultStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let v = self.inner.get(key)?;
        if self.lie_on.as_deref() == Some(key) {
            return Ok(v.map(|s| {
                let mut b = s.into_bytes();
                let i = b.len() / 2;
                b[i] = if b[i] == b'A' { b'B' } else { b'A' };
                String::from_utf8(b).unwrap()
            }));
        }
        Ok(v)
    }

    fn compare_and_swap(
        &mut self,
        key: &str,
        expected: Option<&str>,
        new: Option<&str>,
    ) -> Result<(), StoreError> {
        let n = self.calls;
        self.calls += 1;
        if self.fail_at == Some(n) {
            self.fired = true;
            if self.mode == FaultMode::ApplyThenFail {
                self.inner.compare_and_swap(key, expected, new)?;
            }
            return Err(StoreError::Io);
        }
        self.inner.compare_and_swap(key, expected, new)
    }

    fn keys(&self) -> Result<Vec<String>, StoreError> {
        self.inner.keys()
    }
}
