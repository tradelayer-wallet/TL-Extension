//! Raw wasm32 ABI over a few pure `tl-wallet-core` functions, used only to show that
//! the library runs inside a WASM host (`scripts/wasm-smoke.mjs`). Not an API for the
//! extension: a real binding would use a reviewed generator and never pass secrets
//! through linear memory without zeroizing. `unsafe` is confined to pointer handling.
use tl_wallet_core::address::Address;
use tl_wallet_core::keys::generate_mnemonic;
use tl_wallet_core::network::Network;

const MAX_INPUT: usize = 1024;

/// Allocate `len` bytes the host can write into.
#[no_mangle]
pub extern "C" fn tlw_alloc(len: usize) -> *mut u8 {
    if len == 0 || len > MAX_INPUT {
        return std::ptr::null_mut();
    }
    let mut v = vec![0u8; len];
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Free a buffer returned by `tlw_alloc` with the same `len`.
///
/// # Safety
/// `ptr`/`len` must come from one `tlw_alloc` call and be freed once.
#[no_mangle]
pub unsafe extern "C" fn tlw_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 && len <= MAX_INPUT {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

fn network(code: u32) -> Option<Network> {
    Some(match code {
        0 => Network::Ltc,
        1 => Network::LtcTest,
        2 => Network::Btc,
        3 => Network::BtcTest,
        4 => Network::Doge,
        5 => Network::DogeTest,
        _ => return None,
    })
}

/// 1 = valid address for the network, 0 = invalid, -1 = bad arguments.
///
/// # Safety
/// `ptr..ptr+len` must be readable.
#[no_mangle]
pub unsafe extern "C" fn tlw_validate_address(net: u32, ptr: *const u8, len: usize) -> i32 {
    let Some(net) = network(net) else { return -1 };
    if ptr.is_null() || len == 0 || len > MAX_INPUT {
        return -1;
    }
    let bytes = std::slice::from_raw_parts(ptr, len);
    let Ok(s) = std::str::from_utf8(bytes) else {
        return -1;
    };
    i32::from(Address::parse(net, s).is_ok())
}

/// Write the BIP-39 mnemonic for 16 bytes of entropy at `entropy` into `out`
/// (capacity `cap`). Returns the byte length written, or -1.
///
/// # Safety
/// `entropy` must point to 16 readable bytes and `out..out+cap` must be writable.
#[no_mangle]
pub unsafe extern "C" fn tlw_mnemonic(entropy: *const u8, out: *mut u8, cap: usize) -> i32 {
    if entropy.is_null() || out.is_null() {
        return -1;
    }
    let mut e = [0u8; 16];
    e.copy_from_slice(std::slice::from_raw_parts(entropy, 16));
    let Ok(phrase) = generate_mnemonic(&e) else {
        return -1;
    };
    if phrase.len() > cap {
        return -1;
    }
    std::ptr::copy_nonoverlapping(phrase.as_ptr(), out, phrase.len());
    phrase.len() as i32
}

const FIXTURE: &str = include_str!("../../tests/fixtures/vault_legacy_vectors.txt");
const FIXTURE_PASSWORD: &str = "correct horse battery staple";
const FIXTURE_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn fixture_blob() -> Option<&'static str> {
    FIXTURE
        .lines()
        .find_map(|l| l.strip_prefix("legacy.seed.blob="))
        .map(str::trim_end)
}

/// Runs the vault end to end inside the WASM host: legacy CryptoJS decrypt of a crypto-js
/// generated blob, scrypt + XChaCha20-Poly1305 seal/open (wrong password and a flipped byte are
/// refused), then the full legacy-to-sealed migration over the in-memory store. Returns 1 when
/// every stage passes, otherwise the negative number of the failing stage.
#[no_mangle]
pub extern "C" fn tlw_vault_selftest() -> i32 {
    use tl_wallet_core::vault::format::{open, seal};
    use tl_wallet_core::vault::manager::LEGACY_SEED_KEY;
    use tl_wallet_core::vault::{
        CounterRandom, Kdf, MemoryStore, PayloadKind, Phase, VaultManager,
    };
    let Some(blob) = fixture_blob() else {
        return -1;
    };
    let kind = PayloadKind::MnemonicPhrase;
    match tl_wallet_core::vault::legacy::decrypt_cryptojs_passphrase(blob, FIXTURE_PASSWORD) {
        Ok(s) if s.as_str() == Some(FIXTURE_PHRASE) => {}
        _ => return -2,
    }
    let Ok(sealed) = seal(
        &mut CounterRandom::new(1),
        "wasm pw",
        FIXTURE_PHRASE.as_bytes(),
        Kdf::FLOOR_SCRYPT,
        Network::Ltc,
        kind,
    ) else {
        return -3;
    };
    match open(&sealed, "wasm pw", Network::Ltc, kind, 1) {
        Ok(s) if s.as_str() == Some(FIXTURE_PHRASE) => {}
        _ => return -4,
    }
    if open(&sealed, "other", Network::Ltc, kind, 1).is_ok() {
        return -5;
    }
    let mut bytes = sealed.clone().into_bytes();
    let last = bytes.len() - 5;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    if let Ok(t) = String::from_utf8(bytes) {
        if open(&t, "wasm pw", Network::Ltc, kind, 1).is_ok() {
            return -6;
        }
    }
    let mut store = MemoryStore::new();
    store.put_raw(LEGACY_SEED_KEY, blob);
    let Ok(mut m) = VaultManager::new(
        store,
        CounterRandom::new(2),
        Network::Ltc,
        Kdf::FLOOR_SCRYPT,
    ) else {
        return -7;
    };
    if m.migrate(FIXTURE_PASSWORD, "wasm pw") != Ok(Phase::Retired) {
        return -8;
    }
    match m.unlock("wasm pw") {
        Ok(s) if s.as_str() == Some(FIXTURE_PHRASE) => 1,
        _ => -9,
    }
}
