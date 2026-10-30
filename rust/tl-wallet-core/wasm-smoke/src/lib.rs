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
