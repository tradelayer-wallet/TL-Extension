//! Address validation, mnemonic derivation vectors and BIP-137 known answers.
mod common;
use common::*;
use tl_wallet_core::message::{message_digest, verify_message};
use tl_wallet_core::multisig::{find_existing, multisig_record};
use tl_wallet_core::*;

#[test]
fn bip84_and_bip44_vectors() {
    let expect = [
        (Network::Btc, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
        (
            Network::BtcTest,
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
        ),
        (Network::Ltc, "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"),
        (
            Network::LtcTest,
            "tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk",
        ),
        (Network::Doge, "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"),
        (Network::DogeTest, "nZVmfmUtKPmskB9Ds4P9GUJy9eYFqPKHqH"),
    ];
    for (n, addr) in expect {
        let a = account(n);
        let info = a.info().unwrap();
        assert_eq!(info.address, addr, "{n:?}");
        assert_eq!(info.derivation_path, n.default_path());
        assert_eq!(info.network, n);
    }
}

#[test]
fn change_modes_are_wallet_owned_and_distinct() {
    let m = mnemonic(PHRASE);
    let same = Account::from_mnemonic(&m, Network::Btc, ChangeMode::SameAsReceive).unwrap();
    assert_eq!(same.change_address(), same.receive_address());
    let internal = Account::from_mnemonic(&m, Network::Btc, ChangeMode::InternalChain).unwrap();
    assert_eq!(internal.receive_address(), same.receive_address());
    assert_ne!(internal.change_address(), internal.receive_address());
    // BIP84 m/84'/0'/0'/1/0 for the abandon mnemonic
    assert_eq!(
        internal.change_address().encode().unwrap(),
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
    );
    assert_eq!(internal.id(), same.id());
}

#[test]
fn generated_mnemonic_uses_injected_entropy() {
    let zero = tl_wallet_core::keys::generate_mnemonic(&[0u8; 16]).unwrap();
    assert_eq!(zero, PHRASE);
    let ff = tl_wallet_core::keys::generate_mnemonic(&[0xff; 16]).unwrap();
    assert_eq!(ff, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    assert!(ImportedMnemonic::parse_phrase(&ff).is_ok());
}

#[test]
fn address_validation_negative_cases() {
    let good = "tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk";
    assert!(Address::parse(Network::LtcTest, good).is_ok());
    // uppercase bech32 is canonical-equivalent; mixed case is not valid
    assert!(Address::parse(Network::LtcTest, &good.to_uppercase()).is_ok());
    let mut mixed = good.to_string();
    mixed.replace_range(0..1, "T");
    assert!(Address::parse(Network::LtcTest, &mixed).is_err());
    // flipped checksum character
    let mut bad = good.to_string();
    bad.pop();
    bad.push('q');
    assert!(Address::parse(Network::LtcTest, &bad).is_err());
    // wrong hrp / network
    assert!(Address::parse(Network::Ltc, good).is_err());
    assert!(Address::parse(Network::BtcTest, good).is_err());
    assert!(Address::parse(Network::DogeTest, good).is_err());
    // taproot (witness v1) is not a supported destination
    assert!(Address::parse(
        Network::Btc,
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    )
    .is_err());
    // junk and bounds
    for s in [
        "",
        " ",
        "1",
        "bc1",
        "tltc1",
        "\u{1F600}",
        "tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk ",
        &"1".repeat(101),
        &"q".repeat(40),
    ] {
        assert!(Address::parse(Network::LtcTest, s).is_err(), "{s:?}");
    }
    // base58: wrong checksum, wrong version byte for the network
    let doge = "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC";
    assert!(Address::parse(Network::Doge, doge).is_ok());
    assert!(Address::parse(Network::DogeTest, doge).is_err());
    assert!(Address::parse(Network::Btc, doge).is_err());
    let mut tampered = doge.to_string();
    tampered.replace_range(5..6, "z");
    assert!(Address::parse(Network::Doge, &tampered).is_err());
    // no segwit on Dogecoin
    assert!(Address::parse(Network::Doge, good).is_err());
}

#[test]
fn encode_parse_round_trip_all_kinds() {
    use bitcoin::hashes::Hash;
    for n in Network::ALL {
        let h20 = [7u8; 20];
        let scripts = [
            bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(h20)),
            bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(h20)),
            bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(h20)),
            bitcoin::ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([9u8; 32])),
        ];
        for s in scripts {
            let seg = s.is_p2wpkh() || s.is_p2wsh();
            match Address::from_script(n, &s) {
                Ok(a) => {
                    assert!(!(seg && n.params().bech32_hrp.is_none()));
                    let enc = a.encode().unwrap();
                    assert_eq!(Address::parse(n, &enc).unwrap(), a);
                }
                Err(_) => assert!(seg && n.params().bech32_hrp.is_none()),
            }
        }
    }
    // non-standard script
    assert!(Address::from_script(Network::Btc, bitcoin::Script::from_bytes(&[0x6a])).is_err());
}

// BIP-137 known answer. The expected signature was produced by Bitcoin Core 31.1
// `signmessagewithprivkey` (regtest, throwaway node) for the private key of
// m/84'/0'/0'/0/0 of the public "abandon ... about" mnemonic; Core prints header 32
// (compressed p2pkh, recovery id 1). Our p2wpkh account uses header 40 (= 39 + 1) over the
// identical 64 compact bytes, because RFC6979 signing is deterministic.
const KAT_MESSAGE: &[u8] = b"TradeLayer BIP-137 known answer";
const KAT_CORE_P2PKH_SIG: &str =
    "IBZzZwXOlaOiY6XpdS9sMg4WU8KeUrf7YTMtwkt1ZbSOe1qxMR5/iahzEGIxOivBfQfjBFD1ssjWVjbGYC28kDI=";
const KAT_P2WPKH_SIG: &str =
    "KBZzZwXOlaOiY6XpdS9sMg4WU8KeUrf7YTMtwkt1ZbSOe1qxMR5/iahzEGIxOivBfQfjBFD1ssjWVjbGYC28kDI=";
// Same key as a regtest/testnet p2pkh address, from Core `deriveaddresses pkh(...)`.
const KAT_P2PKH_ADDRESS: &str = "my6RhGaMEf8v9yyQKqiuUYniJLfyU4gzqe";

#[test]
fn bip137_known_answer_against_bitcoin_core() {
    let a = account(Network::Btc);
    let r = Requester {
        origin: origin(),
        network: Network::Btc,
    };
    let cap = SigningCapability::for_message(origin(), a.id(), 10, KAT_MESSAGE.to_vec());
    let sig = sign_message(cap, &r, &a, 1, KAT_MESSAGE).unwrap();
    assert_eq!(sig, KAT_P2WPKH_SIG);
    // our p2wpkh signature verifies for the p2wpkh address and not as p2pkh
    let wpkh = a.receive_address();
    assert!(verify_message(&wpkh, KAT_MESSAGE, &sig).unwrap());
    assert!(!verify_message(&wpkh, b"another message", &sig).unwrap());
    // Core's p2pkh signature verifies for the p2pkh address (Core also said `true`)
    let p2pkh = Address::parse(Network::BtcTest, KAT_P2PKH_ADDRESS).unwrap();
    assert!(verify_message(&p2pkh, KAT_MESSAGE, KAT_CORE_P2PKH_SIG).unwrap());
    assert!(!verify_message(&p2pkh, b"something else", KAT_CORE_P2PKH_SIG).unwrap());
    // header range must match the address type (strict BIP-137)
    assert!(!verify_message(&wpkh, KAT_MESSAGE, KAT_CORE_P2PKH_SIG).unwrap());
    assert!(!verify_message(&p2pkh, KAT_MESSAGE, KAT_P2WPKH_SIG).unwrap());
}

#[test]
fn doge_messages_use_p2pkh_headers_and_network_magic() {
    let a = account(Network::Doge);
    let r = Requester {
        origin: origin(),
        network: Network::Doge,
    };
    let msg = b"hello doge";
    let cap = SigningCapability::for_message(origin(), a.id(), 10, msg.to_vec());
    let sig = sign_message(cap, &r, &a, 1, msg).unwrap();
    let raw = b64(&sig);
    assert!((31..=34).contains(&raw[0]));
    assert!(verify_message(&a.receive_address(), msg, &sig).unwrap());
    // magic differs per network
    let digests: Vec<[u8; 32]> = Network::ALL
        .iter()
        .map(|n| message_digest(*n, msg))
        .collect();
    // Testnets share the magic of their chain, so only chains are pairwise distinct.
    assert_eq!(digests[0], digests[1]);
    assert_ne!(digests[0], digests[2]);
    assert_ne!(digests[2], digests[4]);
}

#[test]
fn verify_rejects_malformed_signatures() {
    let a = account(Network::Btc).receive_address();
    for s in ["", "AAAA", "!!!!", &"A".repeat(88), "KBZz", &"=".repeat(88)] {
        assert!(verify_message(&a, b"m", s).is_err() || !verify_message(&a, b"m", s).unwrap());
    }
    // 65 bytes with an out-of-range header
    let mut raw = b64(KAT_P2WPKH_SIG);
    raw[0] = 27;
    let enc = b64_encode(&raw);
    assert!(!verify_message(&a, KAT_MESSAGE, &enc).unwrap());
    raw[0] = 43;
    assert!(!verify_message(&a, KAT_MESSAGE, &b64_encode(&raw)).unwrap());
    // zero r/s
    let mut z = vec![40u8];
    z.extend_from_slice(&[0u8; 64]);
    assert!(!verify_message(&a, KAT_MESSAGE, &b64_encode(&z)).unwrap_or(false));
    // oversized message
    let big = vec![0u8; 64 * 1024 + 1];
    assert!(matches!(
        verify_message(&a, &big, KAT_P2WPKH_SIG),
        Err(Error::MessageTooLong { .. })
    ));
}

fn b64(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | T.iter().position(|x| *x == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = (u32::from(ch[0]) << 16)
            | (u32::from(*ch.get(1).unwrap_or(&0)) << 8)
            | u32::from(*ch.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if ch.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn multisig_record_validation() {
    let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string();
    let g2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".to_string();
    let n = Network::LtcTest;
    let rec = multisig_record(n, 2, &[g.clone(), g2.clone()]).unwrap();
    assert!(rec.address.starts_with("tltc1q"));
    assert_eq!(rec.m, 2);
    assert_eq!(rec.network, n);
    // invalid thresholds / counts
    assert!(multisig_record(n, 0, std::slice::from_ref(&g)).is_err());
    assert!(multisig_record(n, 3, &[g.clone(), g2.clone()]).is_err());
    assert!(multisig_record(n, 1, &[]).is_err());
    // invalid keys: uncompressed, short, non-hex, off-curve, duplicates
    let uncompressed = format!(
        "04{}{}",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );
    for bad in [
        uncompressed.as_str(),
        "02",
        "zz",
        &format!("02{}", "00".repeat(32)),
    ] {
        assert!(multisig_record(n, 1, &[bad.to_string()]).is_err(), "{bad}");
    }
    assert_eq!(
        multisig_record(n, 1, &[g.clone(), g.clone()]).unwrap_err(),
        Error::InvalidMultisig("duplicate pubkey")
    );
    // segwit-less network
    assert!(multisig_record(Network::Doge, 1, std::slice::from_ref(&g)).is_err());
    // 16 keys exceed the bound
    let many: Vec<String> = vec![g.clone(); 16];
    assert!(multisig_record(n, 1, &many).is_err());
    // lookup: same m, same ordered keys, same explicit network
    let store = vec![rec.clone()];
    assert!(find_existing(&store, n, 2, &[g.clone(), g2.clone()]).is_some());
    assert!(find_existing(&store, n, 1, &[g.clone(), g2.clone()]).is_none());
    assert!(find_existing(&store, n, 2, &[g2.clone(), g.clone()]).is_none());
    assert!(find_existing(&store, Network::Ltc, 2, &[g, g2]).is_none());
}
