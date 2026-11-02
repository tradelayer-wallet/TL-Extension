//! The sealed vault format: round trips, wrong passwords, tampering, version policy, hostile headers.
mod vault_common;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tl_wallet_core::vault::format::{open, peek, seal, HEADER_LEN, MAX_PLAINTEXT, TEXT_PREFIX};
use tl_wallet_core::vault::{CounterRandom, Kdf, PayloadKind, VaultError, CURRENT_VERSION};
use tl_wallet_core::Network;
use vault_common::*;

const KIND: PayloadKind = PayloadKind::MnemonicPhrase;
const PBKDF2_FAST: Kdf = Kdf::Pbkdf2Sha256 { iterations: 1_000 };

fn sealed(kdf: Kdf, net: Network) -> String {
    seal(
        &mut CounterRandom::new(7),
        NEW_PW,
        PHRASE.as_bytes(),
        kdf,
        net,
        KIND,
    )
    .unwrap()
}

fn raw(text: &str) -> Vec<u8> {
    STANDARD
        .decode(text.strip_prefix(TEXT_PREFIX).unwrap())
        .unwrap()
}

fn text(raw: &[u8]) -> String {
    format!("{TEXT_PREFIX}{}", STANDARD.encode(raw))
}

#[test]
fn round_trip_for_both_kdfs() {
    for kdf in [Kdf::FLOOR_SCRYPT, PBKDF2_FAST] {
        let blob = sealed(kdf, Network::Ltc);
        assert!(blob.starts_with("tlvault:"));
        let got = open(&blob, NEW_PW, Network::Ltc, KIND, 1).unwrap();
        assert_eq!(got.as_str(), Some(PHRASE));
        let h = peek(&blob).unwrap();
        assert_eq!(h.version, CURRENT_VERSION);
        assert_eq!(h.kdf, kdf);
        assert_eq!(h.network, Network::Ltc);
        // the plaintext never appears in the blob
        assert!(!blob.contains("abandon"));
        assert!(!String::from_utf8_lossy(&raw(&blob)).contains("abandon"));
    }
}

#[test]
fn default_parameters_are_the_documented_ones_and_work() {
    assert_eq!(
        Kdf::DEFAULT,
        Kdf::Scrypt {
            log_n: 15,
            r: 8,
            p: 1
        }
    );
    let blob = sealed(Kdf::DEFAULT, Network::Btc);
    assert!(open(&blob, NEW_PW, Network::Btc, KIND, 1).is_ok());
    assert_eq!(
        Kdf::PBKDF2_DEFAULT,
        Kdf::Pbkdf2Sha256 {
            iterations: 600_000
        }
    );
}

#[test]
fn fresh_salt_and_nonce_per_seal() {
    let mut rng = CounterRandom::new(1);
    let a = seal(&mut rng, NEW_PW, b"x", PBKDF2_FAST, Network::Ltc, KIND).unwrap();
    let b = seal(&mut rng, NEW_PW, b"x", PBKDF2_FAST, Network::Ltc, KIND).unwrap();
    assert_ne!(a, b);
}

#[test]
fn wrong_password_is_a_typed_error() {
    for kdf in [Kdf::FLOOR_SCRYPT, PBKDF2_FAST] {
        let blob = sealed(kdf, Network::Ltc);
        for pw in [
            "wrong",
            "new synthetic passphrase ",
            "NEW synthetic passphrase",
        ] {
            assert_eq!(
                open(&blob, pw, Network::Ltc, KIND, 1).err(),
                Some(VaultError::WrongPasswordOrTampered)
            );
        }
    }
}

#[test]
fn empty_password_refused_both_ways() {
    assert_eq!(
        seal(
            &mut CounterRandom::new(1),
            "",
            b"x",
            PBKDF2_FAST,
            Network::Ltc,
            KIND
        )
        .err(),
        Some(VaultError::EmptyPassword)
    );
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    assert_eq!(
        open(&blob, "", Network::Ltc, KIND, 1).err(),
        Some(VaultError::EmptyPassword)
    );
}

/// Every single-bit flip of every byte of the blob (header and ciphertext and tag) fails.
#[test]
fn every_bit_flip_is_rejected() {
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    let base = raw(&blob);
    assert_eq!(base.len(), HEADER_LEN + PHRASE.len() + 16);
    let mut cases = 0;
    for i in 0..base.len() {
        for bit in 0..8 {
            let mut t = base.clone();
            t[i] ^= 1 << bit;
            let r = open(&text(&t), NEW_PW, Network::Ltc, KIND, 1);
            assert!(r.is_err(), "byte {i} bit {bit} was accepted");
            cases += 1;
        }
    }
    assert_eq!(cases, base.len() * 8);
}

#[test]
fn every_truncation_and_extension_is_rejected() {
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    let base = raw(&blob);
    for n in 0..base.len() {
        assert!(
            open(&text(&base[..n]), NEW_PW, Network::Ltc, KIND, 1).is_err(),
            "len {n}"
        );
    }
    let mut longer = base.clone();
    longer.push(0);
    assert!(open(&text(&longer), NEW_PW, Network::Ltc, KIND, 1).is_err());
}

#[test]
fn text_level_substitutions_are_rejected() {
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    let body = blob.strip_prefix(TEXT_PREFIX).unwrap().to_string();
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .chars()
        .collect();
    for i in 0..body.len() {
        let orig = body.as_bytes()[i] as char;
        if orig == '=' {
            continue;
        }
        // two substitutes per position keeps the test fast while covering every position
        for sub in alphabet.iter().filter(|c| **c != orig).step_by(31) {
            let mut b = body.clone().into_bytes();
            b[i] = *sub as u8;
            let t = format!("{TEXT_PREFIX}{}", String::from_utf8(b).unwrap());
            assert!(
                open(&t, NEW_PW, Network::Ltc, KIND, 1).is_err(),
                "position {i} -> {sub}"
            );
        }
    }
    assert!(open("tlvault:", NEW_PW, Network::Ltc, KIND, 1).is_err());
    assert!(open("", NEW_PW, Network::Ltc, KIND, 1).is_err());
    assert!(open(&blob[1..], NEW_PW, Network::Ltc, KIND, 1).is_err());
}

#[test]
fn header_fields_are_authenticated_not_just_checked() {
    // Re-encode the header with a different (still valid) network tag: the network check would
    // pass for the new tag, so only authentication can reject it.
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    let mut t = raw(&blob);
    t[6] = 3; // Btc
    assert_eq!(
        open(&text(&t), NEW_PW, Network::Btc, KIND, 1).err(),
        Some(VaultError::WrongPasswordOrTampered)
    );
    // same for the KDF iteration count (valid window)
    let mut t = raw(&blob);
    t[8..12].copy_from_slice(&1_001u32.to_be_bytes());
    assert_eq!(
        open(&text(&t), NEW_PW, Network::Ltc, KIND, 1).err(),
        Some(VaultError::WrongPasswordOrTampered)
    );
}

#[test]
fn wrong_network_is_a_typed_error() {
    let blob = sealed(PBKDF2_FAST, Network::LtcTest);
    assert_eq!(
        open(&blob, NEW_PW, Network::Ltc, KIND, 1).err(),
        Some(VaultError::NetworkMismatch {
            expected: Network::Ltc,
            found: Network::LtcTest
        })
    );
}

#[test]
fn version_policy_rejects_downgrade_and_unknown_versions() {
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    // floor above the blob's version: downgrade, rejected before any KDF work
    assert_eq!(
        open(&blob, NEW_PW, Network::Ltc, KIND, 2).err(),
        Some(VaultError::Downgrade { found: 1, floor: 2 })
    );
    // equal floor passes
    assert!(open(&blob, NEW_PW, Network::Ltc, KIND, 1).is_ok());
    for v in [0u8, 2, 3, 255] {
        let mut t = raw(&blob);
        t[4] = v;
        assert_eq!(
            open(&text(&t), NEW_PW, Network::Ltc, KIND, 1).err(),
            Some(VaultError::UnsupportedVersion(v))
        );
    }
}

#[test]
fn hostile_kdf_parameters_are_refused_before_any_work() {
    let blob = sealed(Kdf::FLOOR_SCRYPT, Network::Ltc);
    let base = raw(&blob);
    let patch = |off: usize, v: u32| {
        let mut t = base.clone();
        t[off..off + 4].copy_from_slice(&v.to_be_bytes());
        open(&text(&t), NEW_PW, Network::Ltc, KIND, 1).err()
    };
    assert!(matches!(
        patch(8, 31),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    assert!(matches!(
        patch(8, 9),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    assert!(matches!(
        patch(8, 1 << 20),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    assert!(matches!(
        patch(12, 0),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    assert!(matches!(
        patch(12, 1 << 30),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    assert!(matches!(
        patch(16, 0),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    assert!(matches!(
        patch(16, 1000),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    // memory cap: log_n 20 with r 16 is 2 GiB
    let mut t = base.clone();
    t[8..12].copy_from_slice(&20u32.to_be_bytes());
    t[12..16].copy_from_slice(&16u32.to_be_bytes());
    assert!(matches!(
        open(&text(&t), NEW_PW, Network::Ltc, KIND, 1).err(),
        Some(VaultError::KdfParamsOutOfRange(_))
    ));
    // unknown kdf id
    let mut t = base.clone();
    t[7] = 9;
    assert_eq!(
        open(&text(&t), NEW_PW, Network::Ltc, KIND, 1).err(),
        Some(VaultError::UnsupportedKdf(9))
    );
    // pbkdf2 with absurd iteration count
    let pb = raw(&sealed(PBKDF2_FAST, Network::Ltc));
    for it in [0u32, 999, 4_000_001, u32::MAX] {
        let mut t = pb.clone();
        t[8..12].copy_from_slice(&it.to_be_bytes());
        assert!(matches!(
            open(&text(&t), NEW_PW, Network::Ltc, KIND, 1).err(),
            Some(VaultError::KdfParamsOutOfRange(_))
        ));
    }
}

#[test]
fn seal_validates_parameters_and_size() {
    let mut rng = CounterRandom::new(3);
    for bad in [
        Kdf::Scrypt {
            log_n: 9,
            r: 8,
            p: 1,
        },
        Kdf::Scrypt {
            log_n: 21,
            r: 1,
            p: 1,
        },
        Kdf::Scrypt {
            log_n: 15,
            r: 0,
            p: 1,
        },
        Kdf::Scrypt {
            log_n: 15,
            r: 8,
            p: 5,
        },
        Kdf::Pbkdf2Sha256 { iterations: 10 },
    ] {
        assert!(matches!(
            seal(&mut rng, NEW_PW, b"x", bad, Network::Ltc, KIND).err(),
            Some(VaultError::KdfParamsOutOfRange(_))
        ));
    }
    let big = vec![0u8; MAX_PLAINTEXT + 1];
    assert!(matches!(
        seal(&mut rng, NEW_PW, &big, PBKDF2_FAST, Network::Ltc, KIND).err(),
        Some(VaultError::Malformed(_))
    ));
    let edge = vec![7u8; MAX_PLAINTEXT];
    let b = seal(&mut rng, NEW_PW, &edge, PBKDF2_FAST, Network::Ltc, KIND).unwrap();
    assert_eq!(
        open(&b, NEW_PW, Network::Ltc, KIND, 1).unwrap().expose(),
        &edge[..]
    );
}

#[test]
fn secret_debug_is_redacted() {
    let blob = sealed(PBKDF2_FAST, Network::Ltc);
    let s = open(&blob, NEW_PW, Network::Ltc, KIND, 1).unwrap();
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("abandon"));
    assert!(dbg.contains("redacted"));
}
