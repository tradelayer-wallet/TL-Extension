//! Address encoding and validation, always relative to an explicit [`Network`].
//!
//! Supported kinds are the ones the legacy wallet produces or pays: `p2pkh`, `p2sh`,
//! `p2wpkh` and `p2wsh` (witness v0). Taproot and other witness versions are rejected with
//! a typed error rather than being guessed at (legacy chose `p2wsh` vs `p2wpkh` from the
//! string length of the address).
//!
//! Litecoin and Dogecoin addresses use the same script types as Bitcoin with different
//! prefixes, so the encoding is done here from the per-network constants, on top of the
//! `base58` and `bech32` implementations re-exported by the `bitcoin` crate.

use crate::error::{Error, Result};
use crate::network::Network;
use bitcoin::bech32::{self, Hrp};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::{CompressedPublicKey, Script, ScriptBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    network: Network,
    kind: AddressKind,
    script: ScriptBuf,
}

fn hash_160_bytes(script: &Script, offset: usize) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&script.as_bytes()[offset..offset + 20]);
    out
}

impl Address {
    pub fn network(&self) -> Network {
        self.network
    }

    pub fn kind(&self) -> AddressKind {
        self.kind
    }

    pub fn script_pubkey(&self) -> &Script {
        &self.script
    }

    /// Classify an output script and bind it to `network`.
    pub fn from_script(network: Network, script: &Script) -> Result<Address> {
        let kind = if script.is_p2pkh() {
            AddressKind::P2pkh
        } else if script.is_p2sh() {
            AddressKind::P2sh
        } else if script.is_p2wpkh() {
            AddressKind::P2wpkh
        } else if script.is_p2wsh() {
            AddressKind::P2wsh
        } else {
            return Err(Error::UnsupportedAddress("script is not p2pkh/p2sh/p2wpkh/p2wsh"));
        };
        if matches!(kind, AddressKind::P2wpkh | AddressKind::P2wsh)
            && network.params().bech32_hrp.is_none()
        {
            return Err(Error::UnsupportedAddress("network has no segwit addresses"));
        }
        Ok(Address {
            network,
            kind,
            script: script.to_owned(),
        })
    }

    /// The single-key address the wallet derives for this network (legacy: p2wpkh for
    /// BTC/LTC, p2pkh for DOGE).
    pub fn for_account_key(network: Network, key: &CompressedPublicKey) -> Address {
        use crate::network::AccountKind;
        let script = match network.params().account_kind {
            AccountKind::P2wpkh => ScriptBuf::new_p2wpkh(&key.wpubkey_hash()),
            AccountKind::P2pkh => ScriptBuf::new_p2pkh(&key.pubkey_hash()),
        };
        let kind = match network.params().account_kind {
            AccountKind::P2wpkh => AddressKind::P2wpkh,
            AccountKind::P2pkh => AddressKind::P2pkh,
        };
        Address {
            network,
            kind,
            script,
        }
    }

    /// `p2wsh` address of a witness script (multisig).
    pub fn p2wsh(network: Network, witness_script: &Script) -> Result<Address> {
        if network.params().bech32_hrp.is_none() {
            return Err(Error::UnsupportedAddress("network has no segwit addresses"));
        }
        Ok(Address {
            network,
            kind: AddressKind::P2wsh,
            script: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        })
    }

    /// Parse and validate `s` for exactly `network`. A string valid on a different network
    /// (even with an identical base58 prefix byte, e.g. BTCTEST/LTCTEST p2pkh `0x6f`) is
    /// accepted only because the caller named that network; the caller must therefore
    /// never choose the network from the string.
    pub fn parse(network: Network, s: &str) -> Result<Address> {
        let p = network.params();
        if s.is_empty() || s.len() > 100 || !s.is_ascii() {
            return Err(Error::InvalidAddress("length or charset"));
        }
        if let Some(hrp) = p.bech32_hrp {
            let lower = s.to_ascii_lowercase();
            if lower.starts_with(hrp) && lower.as_bytes().get(hrp.len()) == Some(&b'1') {
                let (got_hrp, version, program) = bech32::segwit::decode(s)
                    .map_err(|_| Error::InvalidAddress("bech32 checksum or structure"))?;
                if got_hrp.to_lowercase() != hrp {
                    return Err(Error::InvalidAddress("bech32 prefix"));
                }
                if version.to_u8() != 0 {
                    return Err(Error::UnsupportedAddress("witness version above 0"));
                }
                return match program.len() {
                    20 => {
                        let mut h = [0u8; 20];
                        h.copy_from_slice(&program);
                        Ok(Address {
                            network,
                            kind: AddressKind::P2wpkh,
                            script: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                                h,
                            )),
                        })
                    }
                    32 => {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&program);
                        Ok(Address {
                            network,
                            kind: AddressKind::P2wsh,
                            script: ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array(h)),
                        })
                    }
                    _ => Err(Error::InvalidAddress("witness program length")),
                };
            }
        }
        let data = bitcoin::base58::decode_check(s)
            .map_err(|_| Error::InvalidAddress("base58check"))?;
        if data.len() != 21 {
            return Err(Error::InvalidAddress("base58 payload length"));
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&data[1..]);
        if data[0] == p.p2pkh_prefix {
            Ok(Address {
                network,
                kind: AddressKind::P2pkh,
                script: ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(h)),
            })
        } else if data[0] == p.p2sh_prefix {
            Ok(Address {
                network,
                kind: AddressKind::P2sh,
                script: ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(h)),
            })
        } else {
            Err(Error::InvalidAddress("version byte not valid for this network"))
        }
    }

    /// Canonical string form.
    pub fn encode(&self) -> Result<String> {
        let p = self.network.params();
        match self.kind {
            AddressKind::P2pkh | AddressKind::P2sh => {
                let (prefix, off) = if self.kind == AddressKind::P2pkh {
                    (p.p2pkh_prefix, 3)
                } else {
                    (p.p2sh_prefix, 2)
                };
                let mut payload = vec![prefix];
                payload.extend_from_slice(&hash_160_bytes(&self.script, off));
                Ok(bitcoin::base58::encode_check(&payload))
            }
            AddressKind::P2wpkh | AddressKind::P2wsh => {
                let hrp_str = p
                    .bech32_hrp
                    .ok_or(Error::UnsupportedAddress("network has no segwit addresses"))?;
                let hrp = Hrp::parse(hrp_str).map_err(|_| Error::InvalidAddress("hrp"))?;
                bech32::segwit::encode_v0(hrp, &self.script.as_bytes()[2..])
                    .map_err(|_| Error::InvalidAddress("bech32 encode"))
            }
        }
    }
}

/// hash160 helper used by tests and the message verifier.
pub fn hash160_of(bytes: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(bytes).to_byte_array()
}
