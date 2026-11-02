//! Storage and randomness behind traits, with in-memory implementations.

use super::VaultError;
use std::collections::BTreeMap;

/// Storage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// `compare_and_swap` found a value other than the expected one; nothing was written.
    Conflict,
    /// The backend failed; the write may or may not have been applied.
    Io,
}

/// A string-valued key/value store with single-key atomic compare-and-swap, which is what
/// `chrome.storage.local` and `localStorage` adapters can offer. Multi-key atomicity is NOT
/// assumed: the migration state machine only ever changes one key per step.
pub trait VaultStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Atomically replace the value of `key` with `new` (`None` deletes) iff the current value is
    /// `expected` (`None` means absent). On `Err(Conflict)` nothing changed.
    fn compare_and_swap(
        &mut self,
        key: &str,
        expected: Option<&str>,
        new: Option<&str>,
    ) -> Result<(), StoreError>;

    /// All keys currently present.
    fn keys(&self) -> Result<Vec<String>, StoreError>;
}

/// Randomness source. The crate never reads ambient entropy; the caller supplies this.
pub trait Random {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), VaultError>;
}

/// In-memory store for tests and examples.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemoryStore {
    map: BTreeMap<String, String>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct write that bypasses CAS (test fixtures: seed a legacy value, corrupt a blob).
    pub fn put_raw(&mut self, key: &str, value: &str) {
        self.map.insert(key.to_string(), value.to_string());
    }

    pub fn remove_raw(&mut self, key: &str) {
        self.map.remove(key);
    }

    pub fn raw(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    pub fn values(&self) -> impl Iterator<Item = &String> {
        self.map.values()
    }
}

impl VaultStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.map.get(key).cloned())
    }

    fn compare_and_swap(
        &mut self,
        key: &str,
        expected: Option<&str>,
        new: Option<&str>,
    ) -> Result<(), StoreError> {
        if self.map.get(key).map(String::as_str) != expected {
            return Err(StoreError::Conflict);
        }
        match new {
            Some(v) => {
                self.map.insert(key.to_string(), v.to_string());
            }
            None => {
                self.map.remove(key);
            }
        }
        Ok(())
    }

    fn keys(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.map.keys().cloned().collect())
    }
}

/// Deterministic byte stream for tests (a linear congruential generator). Not random:
/// production code must pass an entropy-backed [`Random`].
#[derive(Debug, Clone)]
pub struct CounterRandom {
    next: u64,
}

impl CounterRandom {
    pub fn new(seed: u64) -> Self {
        CounterRandom { next: seed }
    }
}

impl Random for CounterRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), VaultError> {
        for b in buf.iter_mut() {
            self.next = self
                .next
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.next >> 33) as u8;
        }
        Ok(())
    }
}
