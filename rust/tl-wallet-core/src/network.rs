//! Explicit chain identity. A [`Network`] is always passed in; it is never guessed from
//! an address prefix, a key, or a default (legacy `walletUtils.js` defaulted to LTC/LTCTEST).

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    Ltc,
    LtcTest,
    Btc,
    BtcTest,
    Doge,
    DogeTest,
}

/// Which single-key address type the wallet derives for the network (legacy `generateAddressFromSeed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    /// Native segwit v0 (`p2wpkh`), BIP84.
    P2wpkh,
    /// Legacy `p2pkh`, BIP44 (Dogecoin has no segwit).
    P2pkh,
}

/// Constants copied from the legacy `litecoinNetwork`/`bitcoinMainnet`/... objects.
#[derive(Debug, Clone, Copy)]
pub struct NetworkParams {
    pub id: &'static str,
    pub bech32_hrp: Option<&'static str>,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub wif_prefix: u8,
    /// Message magic text without its leading length byte (legacy `messagePrefix`).
    pub message_magic: &'static str,
    pub bip32_public: u32,
    pub bip32_private: u32,
    pub purpose: u32,
    pub coin_type: u32,
    pub account_kind: AccountKind,
    /// Smallest change/recipient value this port will create (see README, unresolved question).
    pub dust_sats: u64,
    pub is_test: bool,
}

const LTC: NetworkParams = NetworkParams {
    id: "LTC",
    bech32_hrp: Some("ltc"),
    p2pkh_prefix: 0x30,
    p2sh_prefix: 0x32,
    wif_prefix: 0xb0,
    message_magic: "Litecoin Signed Message:\n",
    bip32_public: 0x019d_a462,
    bip32_private: 0x019d_9cfe,
    purpose: 84,
    coin_type: 2,
    account_kind: AccountKind::P2wpkh,
    dust_sats: 5_460,
    is_test: false,
};
const LTC_TEST: NetworkParams = NetworkParams {
    id: "LTCTEST",
    bech32_hrp: Some("tltc"),
    p2pkh_prefix: 0x6f,
    p2sh_prefix: 0x3a,
    wif_prefix: 0xef,
    message_magic: "Litecoin Signed Message:\n",
    bip32_public: 0x0435_87cf,
    bip32_private: 0x0435_8394,
    purpose: 84,
    coin_type: 1,
    account_kind: AccountKind::P2wpkh,
    dust_sats: 5_460,
    is_test: true,
};
const BTC: NetworkParams = NetworkParams {
    id: "BTC",
    bech32_hrp: Some("bc"),
    p2pkh_prefix: 0x00,
    p2sh_prefix: 0x05,
    wif_prefix: 0x80,
    message_magic: "Bitcoin Signed Message:\n",
    bip32_public: 0x0488_b21e,
    bip32_private: 0x0488_ade4,
    purpose: 84,
    coin_type: 0,
    account_kind: AccountKind::P2wpkh,
    dust_sats: 546,
    is_test: false,
};
const BTC_TEST: NetworkParams = NetworkParams {
    id: "BTCTEST",
    bech32_hrp: Some("tb"),
    p2pkh_prefix: 0x6f,
    p2sh_prefix: 0xc4,
    wif_prefix: 0xef,
    message_magic: "Bitcoin Signed Message:\n",
    bip32_public: 0x0435_87cf,
    bip32_private: 0x0435_8394,
    purpose: 84,
    coin_type: 1,
    account_kind: AccountKind::P2wpkh,
    dust_sats: 546,
    is_test: true,
};
const DOGE: NetworkParams = NetworkParams {
    id: "DOGE",
    bech32_hrp: None,
    p2pkh_prefix: 0x1e,
    p2sh_prefix: 0x16,
    wif_prefix: 0x9e,
    message_magic: "Dogecoin Signed Message:\n",
    bip32_public: 0x02fa_cafd,
    bip32_private: 0x02fa_c398,
    purpose: 44,
    coin_type: 3,
    account_kind: AccountKind::P2pkh,
    dust_sats: 100_000_000,
    is_test: false,
};
const DOGE_TEST: NetworkParams = NetworkParams {
    id: "DOGETEST",
    bech32_hrp: None,
    p2pkh_prefix: 0x71,
    p2sh_prefix: 0xc4,
    wif_prefix: 0xf1,
    message_magic: "Dogecoin Signed Message:\n",
    bip32_public: 0x0435_87cf,
    bip32_private: 0x0435_8394,
    purpose: 44,
    coin_type: 1,
    account_kind: AccountKind::P2pkh,
    dust_sats: 100_000_000,
    is_test: true,
};

impl Network {
    pub const ALL: [Network; 6] = [
        Network::Ltc,
        Network::LtcTest,
        Network::Btc,
        Network::BtcTest,
        Network::Doge,
        Network::DogeTest,
    ];

    pub fn params(self) -> &'static NetworkParams {
        match self {
            Network::Ltc => &LTC,
            Network::LtcTest => &LTC_TEST,
            Network::Btc => &BTC,
            Network::BtcTest => &BTC_TEST,
            Network::Doge => &DOGE,
            Network::DogeTest => &DOGE_TEST,
        }
    }

    /// Canonical id, the key used in storage namespaces and approvals (`"LTCTEST"`, ...).
    pub fn id(self) -> &'static str {
        self.params().id
    }

    /// Strict parse of a network label. Accepts the canonical ids and the unambiguous
    /// aliases of legacy `networkAliases` / `normalizeNetworkId`. Unknown labels are an
    /// error (legacy `normalizeNetwork` silently fell back to LTC).
    pub fn parse(label: &str) -> Result<Network> {
        let up = label.trim().to_ascii_uppercase();
        let n = match up.as_str() {
            "LTC" | "LITECOIN" | "LTCMAINNET" => Network::Ltc,
            "LTCTEST" | "LITECOIN-TESTNET" | "LITECOIN_TESTNET" | "TLTC" | "TLTCTEST" => {
                Network::LtcTest
            }
            "BTC" | "BITCOIN" => Network::Btc,
            "BTCTEST" | "BITCOIN-TESTNET" => Network::BtcTest,
            "DOGE" | "DOGECOIN" => Network::Doge,
            "DOGETEST" | "DOGECOIN-TESTNET" => Network::DogeTest,
            _ => return Err(Error::UnknownNetwork(label.chars().take(32).collect())),
        };
        Ok(n)
    }

    /// Legacy generic aliases `MAINNET` -> LTC and `TESTNET` -> LTCTEST. They are ambiguous
    /// (the wallet is multi-chain) and are accepted only through this explicit entry point,
    /// used by the legacy-bridge path.
    pub fn parse_legacy_generic(label: &str) -> Result<Network> {
        match label.trim().to_ascii_uppercase().as_str() {
            "MAINNET" => Ok(Network::Ltc),
            "TESTNET" => Ok(Network::LtcTest),
            _ => Network::parse(label),
        }
    }

    /// BIP32/BIP44/BIP84 receive path for account 0, index 0 (legacy `networkPaths`).
    pub fn default_path(self) -> String {
        let p = self.params();
        format!("m/{}'/{}'/0'/0/0", p.purpose, p.coin_type)
    }

    /// Internal (change) chain path, account 0, index 0.
    pub fn internal_path(self) -> String {
        let p = self.params();
        format!("m/{}'/{}'/0'/1/0", p.purpose, p.coin_type)
    }
}
