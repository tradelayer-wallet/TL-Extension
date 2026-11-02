//! Legacy CryptoJS import, checked against ciphertexts produced by the real crypto-js 4.2.0
//! (`scripts/vault-legacy-vectors.cjs`, fixture `tests/fixtures/vault_legacy_vectors.txt`).
mod vault_common;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tl_wallet_core::vault::legacy::{
    decrypt_cryptojs_passphrase, delegated_signer_key, LegacyError, MAX_LEGACY_BASE64,
};
use vault_common::*;

const CASES: [&str; 8] = [
    "seed",
    "seed_unicode_pw",
    "seed_empty_pw",
    "key_cache",
    "pad_full_block",
    "pad_fifteen",
    "pad_empty",
    "utf8_plain",
];

#[test]
fn fixtures_decrypt_byte_exact() {
    let v = vectors();
    assert_eq!(v["crypto_js.version"], "4.2.0");
    for name in CASES {
        let pw = unhex_str(&v[&format!("legacy.{name}.password_hex")]);
        let want = unhex(&v[&format!("legacy.{name}.plaintext_hex")]);
        let blob = &v[&format!("legacy.{name}.blob")];
        let got =
            decrypt_cryptojs_passphrase(blob, &pw).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(got.expose(), &want[..], "{name}");
    }
}

#[test]
fn test_encryptor_reproduces_crypto_js_blobs() {
    // The helper used by the other vault tests is byte-identical to crypto-js for the same salt.
    let v = vectors();
    for name in CASES {
        let pw = unhex_str(&v[&format!("legacy.{name}.password_hex")]);
        let plain = unhex_str(&v[&format!("legacy.{name}.plaintext_hex")]);
        let blob = &v[&format!("legacy.{name}.blob")];
        let raw = STANDARD.decode(blob).unwrap();
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&raw[8..16]);
        assert_eq!(&cryptojs_encrypt(&plain, &pw, salt), blob, "{name}");
    }
}

#[test]
fn wrong_password_is_an_error_for_every_fixture() {
    let v = vectors();
    for name in CASES {
        let blob = &v[&format!("legacy.{name}.blob")];
        let r = decrypt_cryptojs_passphrase(blob, "definitely not the password");
        assert!(
            matches!(r, Err(LegacyError::BadPadding) | Err(LegacyError::NotUtf8)),
            "{name}: {r:?}"
        );
    }
}

/// Regression for the unauthenticated-CBC defect: crypto-js returned "/" (non-empty, so the
/// legacy truthiness checks passed) for this wrong password.
#[test]
fn regression_wrong_password_that_crypto_js_accepted_is_refused() {
    let v = vectors();
    let blob = &v["legacy.wrong_accepted.blob"];
    let wrong = unhex_str(&v["legacy.wrong_accepted.wrong_password_hex"]);
    assert_eq!(v["legacy.wrong_accepted.legacy_output_hex"], "2f");
    assert_eq!(
        decrypt_cryptojs_passphrase(blob, &wrong).err(),
        Some(LegacyError::BadPadding)
    );
    let right = unhex_str(&v["legacy.wrong_accepted.password_hex"]);
    assert_eq!(
        decrypt_cryptojs_passphrase(blob, &right).unwrap().as_str(),
        Some(PHRASE)
    );
}

#[test]
fn malformed_blobs_are_typed_errors() {
    let v = vectors();
    let good = &v["legacy.seed.blob"];
    assert_eq!(
        decrypt_cryptojs_passphrase("not base64 !!", "x").err(),
        Some(LegacyError::NotBase64)
    );
    assert_eq!(
        decrypt_cryptojs_passphrase("", "x").err(),
        Some(LegacyError::NoSaltHeader)
    );
    // valid base64, wrong header
    let mut raw = STANDARD.decode(good).unwrap();
    raw[0] = b'X';
    assert_eq!(
        decrypt_cryptojs_passphrase(&STANDARD.encode(&raw), "x").err(),
        Some(LegacyError::NoSaltHeader)
    );
    // header only
    let hdr = STANDARD.encode(&STANDARD.decode(good).unwrap()[..16]);
    assert_eq!(
        decrypt_cryptojs_passphrase(&hdr, "x").err(),
        Some(LegacyError::BadLength)
    );
    // ciphertext not a multiple of 16
    let raw = STANDARD.decode(good).unwrap();
    let cut = STANDARD.encode(&raw[..raw.len() - 1]);
    assert_eq!(
        decrypt_cryptojs_passphrase(&cut, "x").err(),
        Some(LegacyError::BadLength)
    );
    // oversize
    let big = "A".repeat(MAX_LEGACY_BASE64 + 4);
    assert_eq!(
        decrypt_cryptojs_passphrase(&big, "x").err(),
        Some(LegacyError::NotBase64)
    );
}

#[test]
fn flipped_ciphertext_bits_never_return_the_plaintext() {
    // CBC is unauthenticated: a flip may decrypt to garbage (and is then caught by the
    // padding/UTF-8/mnemonic checks of the caller) but it never yields the original text.
    let v = vectors();
    let blob = &v["legacy.seed.blob"];
    let raw = STANDARD.decode(blob).unwrap();
    for i in 16..raw.len() {
        let mut t = raw.clone();
        t[i] ^= 1;
        if let Ok(s) = decrypt_cryptojs_passphrase(&STANDARD.encode(&t), OLD_PW) {
            assert_ne!(s.as_str(), Some(PHRASE), "byte {i}");
        }
    }
}

#[test]
fn delegated_signer_key_matches_crypto_js_and_its_ciphertext_cannot_exist() {
    let v = vectors();
    let pw = unhex_str(&v["delegated.password_hex"]);
    let key = delegated_signer_key(&pw, &v["delegated.salt"]);
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, v["delegated.key_hex"]);
    // crypto-js throws on both directions when handed the WordArray key, so DelegatedSigner
    // never stored a ciphertext: there is no second legacy format to import.
    assert_eq!(v["delegated.encrypt_with_wordarray_key"], "TypeError");
    assert_eq!(v["delegated.decrypt_with_wordarray_key"], "TypeError");
}
