//! Raw-ABI WebAssembly binding of `tl-wallet-core` for the TradeLayer MV3 extension.
//!
//! The extension page (popup) loads this module, passes one JSON request per call and reads one
//! JSON response (see [`ops`] for the operations). Storage (`localStorage` in the popup, where
//! the legacy vault lives) and entropy (`crypto.getRandomValues`) are host imports, so the
//! vault's compare-and-swap runs against the real store and a legacy `encryptedSeed` opens
//! in place. `unsafe` exists only in the pointer glue below; the core crate forbids it.
//!
//! ABI (module `tlx`):
//! * exports `tlx_alloc(len) -> ptr`, `tlx_free(ptr, len)` (zeroes the buffer first),
//!   `tlx_call(req_ptr, req_len) -> ptr` where the result is `[len: u32 LE][json bytes]`;
//!   the request buffer is zeroed before `tlx_call` returns.
//! * imports `store_get`, `store_cas`, `store_keys`, `random_fill` (see `abi`).

pub mod ops;

#[cfg(target_arch = "wasm32")]
mod abi {
    use crate::ops;
    use tl_wallet_core::vault::{Random, StoreError, VaultError, VaultStore};

    #[link(wasm_import_module = "tlx")]
    extern "C" {
        /// Copy the value of `key` into `out` (capacity `cap`) and return its byte length, or
        /// -1 when absent. A length above `cap` means nothing was copied: retry with more room.
        fn store_get(key: *const u8, key_len: usize, out: *mut u8, cap: usize) -> i32;
        /// Atomically replace `key` iff its current value equals `expected` (when
        /// `has_expected != 0`, else iff absent). `has_new == 0` deletes. 0 ok, 1 conflict, 2 io.
        fn store_cas(
            key: *const u8,
            key_len: usize,
            has_expected: i32,
            expected: *const u8,
            expected_len: usize,
            has_new: i32,
            new: *const u8,
            new_len: usize,
        ) -> i32;
        /// Newline-separated list of keys, same length protocol as `store_get`.
        fn store_keys(out: *mut u8, cap: usize) -> i32;
        /// Fill from `crypto.getRandomValues`; 0 ok.
        fn random_fill(out: *mut u8, len: usize) -> i32;
    }

    const MAX_VALUE: usize = 1 << 20;

    fn read_into(
        mut call: impl FnMut(*mut u8, usize) -> i32,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut buf = vec![0u8; 4096];
        for _ in 0..2 {
            let n = call(buf.as_mut_ptr(), buf.len());
            if n < 0 {
                return Ok(None);
            }
            let n = n as usize;
            if n > MAX_VALUE {
                return Err(StoreError::Io);
            }
            if n <= buf.len() {
                buf.truncate(n);
                return Ok(Some(buf));
            }
            buf = vec![0u8; n];
        }
        Err(StoreError::Io)
    }

    pub struct HostStore;

    impl VaultStore for HostStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            // SAFETY: `key` and the scratch buffer are valid for the lengths passed; the host
            // writes at most `cap` bytes.
            let raw =
                read_into(|out, cap| unsafe { store_get(key.as_ptr(), key.len(), out, cap) })?;
            match raw {
                None => Ok(None),
                Some(bytes) => String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_| StoreError::Io),
            }
        }

        fn compare_and_swap(
            &mut self,
            key: &str,
            expected: Option<&str>,
            new: Option<&str>,
        ) -> Result<(), StoreError> {
            let (he, ep, el) = match expected {
                Some(s) => (1, s.as_ptr(), s.len()),
                None => (0, key.as_ptr(), 0),
            };
            let (hn, np, nl) = match new {
                Some(s) => (1, s.as_ptr(), s.len()),
                None => (0, key.as_ptr(), 0),
            };
            // SAFETY: all pointers are valid for the lengths passed and only read by the host.
            let rc = unsafe { store_cas(key.as_ptr(), key.len(), he, ep, el, hn, np, nl) };
            match rc {
                0 => Ok(()),
                1 => Err(StoreError::Conflict),
                _ => Err(StoreError::Io),
            }
        }

        fn keys(&self) -> Result<Vec<String>, StoreError> {
            // SAFETY: the scratch buffer is valid for `cap` bytes.
            let raw = read_into(|out, cap| unsafe { store_keys(out, cap) })?.unwrap_or_default();
            let text = String::from_utf8(raw).map_err(|_| StoreError::Io)?;
            Ok(text
                .split('\n')
                .filter(|k| !k.is_empty())
                .map(str::to_string)
                .collect())
        }
    }

    pub struct HostRandom;

    impl Random for HostRandom {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), VaultError> {
            // SAFETY: `buf` is valid for `buf.len()` bytes and written only by the host.
            let rc = unsafe { random_fill(buf.as_mut_ptr(), buf.len()) };
            if rc == 0 {
                Ok(())
            } else {
                Err(VaultError::Random)
            }
        }
    }

    /// Largest request the host may pass.
    const MAX_ALLOC: usize = 16 * 1024 * 1024;

    #[no_mangle]
    pub extern "C" fn tlx_alloc(len: usize) -> *mut u8 {
        if len == 0 || len > MAX_ALLOC {
            return core::ptr::null_mut();
        }
        Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
    }

    /// Zero and release a buffer from `tlx_alloc` or `tlx_call`.
    ///
    /// # Safety
    /// `ptr`/`len` must be exactly what one earlier call returned/was given, freed once.
    #[no_mangle]
    pub unsafe extern "C" fn tlx_free(ptr: *mut u8, len: usize) {
        if ptr.is_null() || len == 0 || len > MAX_ALLOC + 4 {
            return;
        }
        let mut b = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len));
        b.fill(0);
        drop(b);
    }

    /// Run one request. Returns `[len: u32 LE][json]` (free with `tlx_free(ptr, 4 + len)`), or
    /// null when the arguments are invalid. The request buffer is zeroed.
    ///
    /// # Safety
    /// `ptr..ptr+len` must be a live `tlx_alloc` buffer.
    #[no_mangle]
    pub unsafe extern "C" fn tlx_call(ptr: *mut u8, len: usize) -> *mut u8 {
        if ptr.is_null() || len == 0 || len > MAX_ALLOC {
            return core::ptr::null_mut();
        }
        let request = core::slice::from_raw_parts_mut(ptr, len);
        let mut response = ops::handle(HostStore, HostRandom, request);
        request.fill(0);
        let mut framed = Vec::with_capacity(4 + response.len());
        framed.extend_from_slice(&(response.len() as u32).to_le_bytes());
        framed.extend_from_slice(&response);
        response.fill(0);
        Box::into_raw(framed.into_boxed_slice()) as *mut u8
    }
}
