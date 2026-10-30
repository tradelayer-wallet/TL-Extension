//! BIP39 import validation and BIP32 account derivation.
//!
//! Ported from `generateAddressFromSeed`, `generateMnemonic` and the 12-box
//! `SeedPhraseImport` component. Entropy is injected by the caller (no RNG in this crate).
//! Encryption of keys at rest (the legacy CryptoJS vault) is NOT ported: it stays in JS.

use crate::address::Address;
use crate::error::{Error, Result};
use crate::network::Network;
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::NetworkKind;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use bitcoin::{CompressedPublicKey, ScriptBuf};
use std::str::FromStr;

/// The legacy import UI offers exactly twelve boxes.
pub const LEGACY_WORD_COUNT: usize = 12;

/// A mnemonic that passed shape, wordlist and checksum validation.
pub struct ImportedMnemonic(Mnemonic);

impl core::fmt::Debug for ImportedMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ImportedMnemonic(<redacted>)")
    }
}

fn map_bip39(e: bip39::Error) -> Error {
    match e {
        bip39::Error::BadWordCount(_) => Error::InvalidMnemonic("bad word count"),
        bip39::Error::UnknownWord(_) => Error::InvalidMnemonic("word not in the English list"),
        bip39::Error::InvalidChecksum => Error::InvalidMnemonic("checksum mismatch"),
        _ => Error::InvalidMnemonic("invalid mnemonic"),
    }
}

impl ImportedMnemonic {
    /// Legacy shape: twelve non-empty boxes, each trimmed, joined by single spaces. A box
    /// containing whitespace is rejected (legacy joined it silently into a longer phrase).
    /// Unlike legacy (`bip39.mnemonicToSeedSync` never checks the checksum) the wordlist and
    /// checksum are validated, so a typo cannot silently create a different wallet.
    pub fn from_words(words: &[&str]) -> Result<Self> {
        if words.len() != LEGACY_WORD_COUNT {
            return Err(Error::InvalidMnemonic("expected exactly 12 words"));
        }
        let mut cleaned = Vec::with_capacity(LEGACY_WORD_COUNT);
        for w in words {
            let w = w.trim();
            if w.is_empty() {
                return Err(Error::InvalidMnemonic("empty word box"));
            }
            if !w.is_ascii() || w.chars().any(char::is_whitespace) {
                return Err(Error::InvalidMnemonic("word must be one ASCII token"));
            }
            cleaned.push(w.to_ascii_lowercase());
        }
        Self::parse_normalized(&cleaned.join(" "))
    }

    /// Whitespace-separated phrase form of [`ImportedMnemonic::from_words`].
    pub fn parse_phrase(phrase: &str) -> Result<Self> {
        if phrase.len() > 512 {
            return Err(Error::InvalidMnemonic("phrase too long"));
        }
        let words: Vec<&str> = phrase.split_whitespace().collect();
        Self::from_words(&words)
    }

    fn parse_normalized(s: &str) -> Result<Self> {
        Mnemonic::parse_in_normalized(Language::English, s)
            .map(ImportedMnemonic)
            .map_err(map_bip39)
    }

    pub fn to_seed(&self) -> [u8; 64] {
        self.0.to_seed("")
    }

    pub fn phrase(&self) -> String {
        self.0.to_string()
    }
}

/// Legacy `generateMnemonic()` (12 words) with caller-supplied entropy.
pub fn generate_mnemonic(entropy: &[u8; 16]) -> Result<String> {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .map(|m| m.to_string())
        .map_err(map_bip39)
}

/// A derived secp256k1 key. The secret never leaves this type except to sign.
pub struct DerivedKey {
    secret: SecretKey,
    public: CompressedPublicKey,
    path: String,
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DerivedKey({}, <redacted>)", self.path)
    }
}

impl DerivedKey {
    pub fn public_key(&self) -> &CompressedPublicKey {
        &self.public
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

/// Where change goes. Both options are wallet-owned; the page never chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeMode {
    /// Change returns to the receive address (the legacy intent of "change to from-address").
    SameAsReceive,
    /// Change goes to a fresh internal-chain address `.../1/0`.
    InternalChain,
}

/// Identity of an account as bound into approvals: the network plus the receive script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountId {
    pub network: Network,
    pub script: ScriptBuf,
}

/// Public view of a derived account (legacy `generateAddressFromSeed` return, minus the
/// encrypted private key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub address: String,
    pub public_key_hex: String,
    pub derivation_path: String,
    pub network: Network,
}

pub struct Account {
    network: Network,
    secp: Secp256k1<All>,
    receive: DerivedKey,
    internal: Option<DerivedKey>,
}

impl core::fmt::Debug for Account {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Account({:?}, <redacted>)", self.network)
    }
}

fn derive(secp: &Secp256k1<All>, seed: &[u8; 64], path: &str) -> Result<DerivedKey> {
    let master = Xpriv::new_master(NetworkKind::Main, seed)
        .map_err(|_| Error::InvalidMnemonic("seed rejected"))?;
    let dp = DerivationPath::from_str(path).map_err(|_| Error::InvalidInput("derivation path"))?;
    let child = master
        .derive_priv(secp, &dp)
        .map_err(|_| Error::InvalidInput("derivation failed"))?;
    let public = PublicKey::from_secret_key(secp, &child.private_key);
    Ok(DerivedKey {
        secret: child.private_key,
        public: CompressedPublicKey(public),
        path: path.to_string(),
    })
}

impl Account {
    pub fn from_mnemonic(m: &ImportedMnemonic, network: Network, change: ChangeMode) -> Result<Self> {
        let secp = Secp256k1::new();
        let mut seed = m.to_seed();
        let receive = derive(&secp, &seed, &network.default_path());
        let internal = match change {
            ChangeMode::SameAsReceive => Ok(None),
            ChangeMode::InternalChain => derive(&secp, &seed, &network.internal_path()).map(Some),
        };
        seed.fill(0);
        Ok(Account {
            network,
            secp,
            receive: receive?,
            internal: internal?,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    pub fn receive_address(&self) -> Address {
        Address::for_account_key(self.network, self.receive.public_key())
    }

    /// The wallet-owned change destination. Independent of any request field.
    pub fn change_address(&self) -> Address {
        match &self.internal {
            Some(k) => Address::for_account_key(self.network, k.public_key()),
            None => self.receive_address(),
        }
    }

    pub fn id(&self) -> AccountId {
        AccountId {
            network: self.network,
            script: self.receive_address().script_pubkey().to_owned(),
        }
    }

    pub fn info(&self) -> Result<AccountInfo> {
        Ok(AccountInfo {
            address: self.receive_address().encode()?,
            public_key_hex: self.receive.public.to_string(),
            derivation_path: self.receive.path.clone(),
            network: self.network,
        })
    }

    /// The key controlling `script`, if it is one of this account's own scripts.
    pub(crate) fn key_for_script(&self, script: &bitcoin::Script) -> Option<&DerivedKey> {
        if self.receive_address().script_pubkey() == script {
            return Some(&self.receive);
        }
        if let Some(k) = &self.internal {
            if Address::for_account_key(self.network, k.public_key()).script_pubkey() == script {
                return Some(k);
            }
        }
        None
    }

    /// Whether `script` pays this wallet (receive or internal change).
    pub fn owns_script(&self, script: &bitcoin::Script) -> bool {
        self.key_for_script(script).is_some()
    }

    pub(crate) fn receive_key(&self) -> &DerivedKey {
        &self.receive
    }
}
