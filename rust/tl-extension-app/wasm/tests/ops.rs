//! The binding's operations against `MemoryStore`, with synthetic keys only.
use serde_json::{json, Value};
use std::cell::RefCell;
use std::rc::Rc;
use tl_extension_wasm::ops::handle;
use tl_wallet_core::vault::{CounterRandom, MemoryStore, StoreError, VaultStore};

const LEGACY_BLOB: &str = "U2FsdGVkX18Ilk95oR6SPnbycD/2lt2Q+gAe116q0xvdvgurgmnQNJUR0Jt4+nSgpl4u98r/Eopm8PC4O/b37e77jw0PIcP0lWE7OLUjHrO35Dd1SmwlaCyhZAoTkypm2KISXsIAFEgVH9w3s1g3sQ==";
const LEGACY_PASSWORD: &str = "correct horse battery staple";
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ORIGIN: &str = "http://localhost:8080";

#[derive(Clone, Default)]
struct Shared(Rc<RefCell<MemoryStore>>);

impl VaultStore for Shared {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.0.borrow().get(key)
    }
    fn compare_and_swap(
        &mut self,
        key: &str,
        expected: Option<&str>,
        new: Option<&str>,
    ) -> Result<(), StoreError> {
        self.0.borrow_mut().compare_and_swap(key, expected, new)
    }
    fn keys(&self) -> Result<Vec<String>, StoreError> {
        self.0.borrow().keys()
    }
}

fn call(store: &Shared, req: Value) -> Value {
    let out = handle(
        store.clone(),
        CounterRandom::new(7),
        req.to_string().as_bytes(),
    );
    serde_json::from_slice(&out).expect("response is JSON")
}

fn ok(v: &Value) -> bool {
    v["ok"] == json!(true)
}

#[test]
fn create_unlock_status_roundtrip() {
    let s = Shared::default();
    assert_eq!(call(&s, json!({"op": "status"}))["exists"], json!(false));
    let r = call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "pw-1"}),
    );
    assert!(ok(&r), "{r}");
    let st = call(&s, json!({"op": "status"}));
    assert_eq!(st["exists"], json!(true));
    assert_eq!(st["source"], json!("sealed"));
    assert_eq!(st["phase"], json!("Native"));
    let u = call(
        &s,
        json!({"op": "unlock", "password": "pw-1", "network": "LTCTEST"}),
    );
    assert!(ok(&u), "{u}");
    assert!(u["address"].as_str().unwrap().starts_with("tltc1q"));
    assert_eq!(u["derivation_path"], json!("m/84'/1'/0'/0/0"));
    assert_eq!(u["network"], json!("LTCTEST"));
    let bad = call(
        &s,
        json!({"op": "unlock", "password": "nope", "network": "LTCTEST"}),
    );
    assert_eq!(bad["ok"], json!(false));
    assert_eq!(bad["code"], json!("WrongPasswordOrTampered"));
}

#[test]
fn create_refuses_to_overwrite_and_invalid_phrases() {
    let s = Shared::default();
    let bad = call(
        &s,
        json!({"op": "create", "phrase": "abandon abandon", "password": "x"}),
    );
    assert_eq!(bad["ok"], json!(false));
    assert!(ok(&call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "x"})
    )));
    let again = call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "y"}),
    );
    assert_eq!(again["code"], json!("AlreadyExists"));
    let empty = call(
        &Shared::default(),
        json!({"op": "create", "phrase": ABANDON, "password": ""}),
    );
    assert_eq!(empty["code"], json!("EmptyPassword"));
}

#[test]
fn generated_phrase_is_valid_and_creates_a_vault() {
    let s = Shared::default();
    let g = call(&s, json!({"op": "generate_mnemonic"}));
    assert!(ok(&g));
    let phrase = g["phrase"].as_str().unwrap();
    assert_eq!(phrase.split(' ').count(), 12);
    assert!(ok(&call(
        &s,
        json!({"op": "create", "phrase": phrase, "password": "p"})
    )));
}

#[test]
fn legacy_vault_opens_and_is_migrated_on_unlock() {
    let s = Shared::default();
    s.0.borrow_mut().put_raw("encryptedSeed", LEGACY_BLOB);
    let st = call(&s, json!({"op": "status"}));
    assert_eq!(st["source"], json!("legacy"));
    let u = call(
        &s,
        json!({"op": "unlock", "password": LEGACY_PASSWORD, "network": "LTCTEST"}),
    );
    assert!(ok(&u), "{u}");
    assert_eq!(u["migration"]["phase"], json!("Retired"));
    // same address as a fresh vault built from the plaintext phrase
    let fresh = Shared::default();
    assert!(ok(&call(
        &fresh,
        json!({"op": "create", "phrase": ABANDON, "password": "q"})
    )));
    let f = call(
        &fresh,
        json!({"op": "unlock", "password": "q", "network": "LTCTEST"}),
    );
    assert_eq!(u["address"], f["address"]);
    // legacy key gone, sealed vault and backup present, unlock still works
    assert!(s.0.borrow().raw("encryptedSeed").is_none());
    assert!(s.0.borrow().raw("vault.v1").is_some());
    assert_eq!(s.0.borrow().raw("vault.legacy_backup"), Some(LEGACY_BLOB));
    let again = call(
        &s,
        json!({"op": "unlock", "password": LEGACY_PASSWORD, "network": "LTCTEST"}),
    );
    assert!(ok(&again));
    assert!(again.get("migration").is_none());
    // that later unlock confirmed the sealed vault and dropped the crypto-js backup
    assert_eq!(again["backup_discarded"], json!(true));
    assert!(s.0.borrow().raw("vault.legacy_backup").is_none());
    let third = call(
        &s,
        json!({"op": "unlock", "password": LEGACY_PASSWORD, "network": "LTCTEST"}),
    );
    assert_eq!(third["address"], u["address"]);
    assert!(third.get("backup_discarded").is_none());
}

#[test]
fn a_backup_that_does_not_match_the_vault_is_kept() {
    let s = Shared::default();
    s.0.borrow_mut().put_raw("encryptedSeed", LEGACY_BLOB);
    let u = call(
        &s,
        json!({"op": "unlock", "password": LEGACY_PASSWORD, "network": "LTCTEST"}),
    );
    assert_eq!(u["migration"]["phase"], json!("Retired"));
    // a damaged backup no longer decrypts: unlock works, the backup stays for inspection
    let mut damaged = LEGACY_BLOB.to_string();
    damaged.replace_range(20..24, "AAAA");
    s.0.borrow_mut().put_raw("vault.legacy_backup", &damaged);
    let again = call(
        &s,
        json!({"op": "unlock", "password": LEGACY_PASSWORD, "network": "LTCTEST"}),
    );
    assert!(ok(&again), "{again}");
    assert_eq!(again["backup_discarded"], json!(false));
    assert_eq!(
        s.0.borrow().raw("vault.legacy_backup"),
        Some(damaged.as_str())
    );
}

#[test]
fn a_password_change_after_migration_drops_the_backup_first() {
    let s = Shared::default();
    s.0.borrow_mut().put_raw("encryptedSeed", LEGACY_BLOB);
    let u = call(
        &s,
        json!({"op": "unlock", "password": LEGACY_PASSWORD, "network": "LTCTEST"}),
    );
    assert_eq!(u["migration"]["phase"], json!("Retired"));
    let wrong = call(
        &s,
        json!({"op": "change_password", "old_password": "bad", "new_password": "next"}),
    );
    assert_eq!(wrong["ok"], json!(false));
    assert!(s.0.borrow().raw("vault.legacy_backup").is_some());
    let r = call(
        &s,
        json!({"op": "change_password", "old_password": LEGACY_PASSWORD, "new_password": "next"}),
    );
    assert!(ok(&r), "{r}");
    assert_eq!(r["backup_discarded"], json!(true));
    assert!(s.0.borrow().raw("vault.legacy_backup").is_none());
    assert_eq!(
        call(&s, json!({"op": "expose_seed", "password": "next"}))["phrase"],
        json!(ABANDON)
    );
}

#[test]
fn legacy_wrong_password_is_refused_and_leaves_the_blob() {
    let s = Shared::default();
    s.0.borrow_mut().put_raw("encryptedSeed", LEGACY_BLOB);
    let r = call(
        &s,
        json!({"op": "unlock", "password": "wrong-28", "network": "LTC"}),
    );
    assert_eq!(r["ok"], json!(false));
    assert_eq!(s.0.borrow().raw("encryptedSeed"), Some(LEGACY_BLOB));
    assert!(s.0.borrow().raw("vault.v1").is_none());
}

#[test]
fn change_password_and_expose_seed() {
    let s = Shared::default();
    assert!(ok(&call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "old"})
    )));
    let wrong = call(
        &s,
        json!({"op": "change_password", "old_password": "bad", "new_password": "new"}),
    );
    assert_eq!(wrong["ok"], json!(false));
    assert!(ok(&call(
        &s,
        json!({"op": "change_password", "old_password": "old", "new_password": "new"})
    )));
    assert_eq!(
        call(&s, json!({"op": "expose_seed", "password": "old"}))["ok"],
        json!(false)
    );
    assert_eq!(
        call(&s, json!({"op": "expose_seed", "password": "new"}))["phrase"],
        json!(ABANDON)
    );
}

#[test]
fn legacy_change_password_migrates_under_the_new_password() {
    let s = Shared::default();
    s.0.borrow_mut().put_raw("encryptedSeed", LEGACY_BLOB);
    let r = call(
        &s,
        json!({"op": "change_password", "old_password": LEGACY_PASSWORD, "new_password": "fresh"}),
    );
    assert!(ok(&r), "{r}");
    assert_eq!(
        call(&s, json!({"op": "expose_seed", "password": "fresh"}))["phrase"],
        json!(ABANDON)
    );
    assert_eq!(
        call(
            &s,
            json!({"op": "expose_seed", "password": LEGACY_PASSWORD})
        )["ok"],
        json!(false)
    );
    // the backup is under the old password, which is never presented again: dropped here
    assert_eq!(r["backup_discarded"], json!(true));
    assert!(s.0.borrow().raw("vault.legacy_backup").is_none());
    assert!(s.0.borrow().raw("encryptedSeed").is_none());
}

#[test]
fn check_password_requires_the_matching_address() {
    let s = Shared::default();
    assert!(ok(&call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "pw"})
    )));
    let u = call(
        &s,
        json!({"op": "unlock", "password": "pw", "network": "LTCTEST"}),
    );
    let addr = u["address"].as_str().unwrap().to_string();
    assert!(ok(&call(
        &s,
        json!({"op": "check_password", "password": "pw", "network": "LTCTEST", "address": addr})
    )));
    let wrong_pw = call(
        &s,
        json!({"op": "check_password", "password": "x", "network": "LTCTEST", "address": addr}),
    );
    assert_eq!(wrong_pw["ok"], json!(false));
    let wrong_addr = call(
        &s,
        json!({"op": "check_password", "password": "pw", "network": "LTC", "address": addr}),
    );
    assert_eq!(wrong_addr["code"], json!("AddressMismatch"));
}

#[test]
fn sign_message_is_bip137_and_verifies() {
    let s = Shared::default();
    assert!(ok(&call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "pw"})
    )));
    let r = call(
        &s,
        json!({"op": "sign_message", "password": "pw", "network": "LTCTEST",
               "origin": ORIGIN, "message": "hello tradelayer", "now": 100}),
    );
    assert!(ok(&r), "{r}");
    let sig = r["signature"].as_str().unwrap();
    let addr = tl_wallet_core::Address::parse(
        tl_wallet_core::Network::LtcTest,
        r["address"].as_str().unwrap(),
    )
    .unwrap();
    assert!(tl_wallet_core::message::verify_message(&addr, b"hello tradelayer", sig).unwrap());
    assert!(!tl_wallet_core::message::verify_message(&addr, b"other", sig).unwrap());
    // wrong password never signs
    let bad = call(
        &s,
        json!({"op": "sign_message", "password": "x", "network": "LTCTEST", "origin": ORIGIN, "message": "m"}),
    );
    assert_eq!(bad["ok"], json!(false));
    // a non-http origin is refused before any key is derived
    let o = call(
        &s,
        json!({"op": "sign_message", "password": "pw", "network": "LTCTEST", "origin": "chrome-extension://abc", "message": "m"}),
    );
    assert_eq!(o["code"], json!("InvalidOrigin"));
    // unknown networks are errors, not a silent LTC
    let n = call(
        &s,
        json!({"op": "sign_message", "password": "pw", "network": "NOPE", "message": "m"}),
    );
    assert_eq!(n["code"], json!("UnknownNetwork"));
}

#[test]
fn sign_payment_signs_owned_utxo_and_refuses_foreign_script() {
    let s = Shared::default();
    assert!(ok(&call(
        &s,
        json!({"op": "create", "phrase": ABANDON, "password": "pw"})
    )));
    let u = call(
        &s,
        json!({"op": "unlock", "password": "pw", "network": "LTCTEST"}),
    );
    let addr = u["address"].as_str().unwrap();
    let own = tl_wallet_core::Address::parse(tl_wallet_core::Network::LtcTest, addr).unwrap();
    let spk = own.script_pubkey().to_hex_string();
    let utxo =
        json!({"txid": "11".repeat(32), "vout": 0, "amount": "1.00000000", "script_pubkey": spk});
    // pay the wallet's own address (a synthetic recipient) from a synthetic UTXO
    let r = call(
        &s,
        json!({"op": "sign_payment", "password": "pw", "network": "LTCTEST", "to": addr,
               "amount": "0.10000000", "utxos": [utxo], "now": 5}),
    );
    assert!(ok(&r), "{r}");
    assert_eq!(r["fee_sats"], json!(10000));
    assert_eq!(r["txid"].as_str().unwrap().len(), 64);
    // a foreign script is refused up front
    let foreign = json!({"txid": "22".repeat(32), "vout": 1, "amount": "1.0",
                         "script_pubkey": format!("0014{}", "ab".repeat(20))});
    let bad = call(
        &s,
        json!({"op": "sign_payment", "password": "pw", "network": "LTCTEST", "to": addr,
               "amount": "0.1", "utxos": [foreign]}),
    );
    assert_eq!(bad["ok"], json!(false));
    // an exponent is not a decimal amount
    let exp = call(
        &s,
        json!({"op": "sign_payment", "password": "pw", "network": "LTCTEST", "to": addr,
               "amount": "1e-3", "utxos": []}),
    );
    assert_eq!(exp["ok"], json!(false));
}

#[test]
fn malformed_requests_are_typed_errors() {
    let s = Shared::default();
    for req in [
        json!({}),
        json!({"op": 3}),
        json!({"op": "nope"}),
        json!({"op": "create"}),
    ] {
        let r = call(&s, req);
        assert_eq!(r["ok"], json!(false));
    }
    let out = handle(s.clone(), CounterRandom::new(1), b"not json");
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["code"], json!("BadRequest"));
}
