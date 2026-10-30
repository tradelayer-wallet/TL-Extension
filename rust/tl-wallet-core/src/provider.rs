//! What a web page may ask for. Ported from `contentScript.js` (`ALLOWED_METHODS`, id checks)
//! and `background/background.js` (`PAGE_METHODS`, `isAllowedOrigin`, site permissions,
//! network resolution, account selection, pending-request registry).
//!
//! This module decides; it performs no I/O. Browser storage, popup windows and messaging
//! stay in JS and call into it.

use crate::address::Address;
use crate::error::ProviderError;
use crate::network::Network;
use crate::origin::Origin;
use std::collections::BTreeMap;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_PSBT_HEX_CHARS: usize = 4 * 1024 * 1024;
pub const MAX_MULTISIG_KEYS: usize = 15;
pub const MAX_PENDING_REQUESTS: usize = 32;
pub const MAX_REQUEST_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderMethod {
    Connect,
    RequestAccounts,
    SignMessage,
    SignPsbt,
    SignTransaction,
    AddMultisig,
    FetchUserIp,
    KeepAlive,
}

impl ProviderMethod {
    /// Exact-match allow-list. `signPSBT` is the legacy spelling of `signPsbt`.
    pub fn parse(name: &str) -> Result<ProviderMethod, ProviderError> {
        Ok(match name {
            "connect" => ProviderMethod::Connect,
            "requestAccounts" => ProviderMethod::RequestAccounts,
            "signMessage" => ProviderMethod::SignMessage,
            "signPsbt" | "signPSBT" => ProviderMethod::SignPsbt,
            "signTransaction" => ProviderMethod::SignTransaction,
            "addMultisig" => ProviderMethod::AddMultisig,
            "fetchUserIP" => ProviderMethod::FetchUserIp,
            "keepAlive" => ProviderMethod::KeepAlive,
            other => {
                return Err(ProviderError::UnsupportedMethod(
                    other.chars().take(64).collect(),
                ))
            }
        })
    }

    /// Methods that need a signing capability (explicit user approval per request).
    pub fn needs_signing_approval(self) -> bool {
        matches!(
            self,
            ProviderMethod::SignMessage
                | ProviderMethod::SignPsbt
                | ProviderMethod::SignTransaction
        )
    }
}

/// `id` as received from the page, before validation.
#[derive(Debug, Clone, PartialEq)]
pub enum PageId {
    Str(String),
    Num(f64),
    Other,
}

/// `contentScript.js` gate: legacy-bridge requests accept string or number ids, current
/// provider requests require a string id; the method must be on the allow-list.
pub fn content_gate(
    legacy: bool,
    id: &PageId,
    method: &str,
) -> Result<ProviderMethod, ProviderError> {
    let id_ok = match id {
        PageId::Str(s) => !s.is_empty() && s.len() <= MAX_REQUEST_ID_LEN,
        PageId::Num(n) => legacy && n.is_finite(),
        PageId::Other => false,
    };
    if !id_ok {
        return Err(ProviderError::MissingRequestId);
    }
    ProviderMethod::parse(method)
}

/// Origins that may talk to the wallet (`APPROVED_HTTPS_ORIGINS`, `ALLOW_DEVELOPMENT_ORIGINS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPolicy {
    approved_https: Vec<Origin>,
    allow_development: bool,
}

impl OriginPolicy {
    pub fn new(approved_https: &[&str], allow_development: bool) -> Result<Self, ProviderError> {
        let mut v = Vec::new();
        for o in approved_https {
            let origin = Origin::from_url(o)?;
            if !origin.is_https() {
                return Err(ProviderError::InvalidRequest(
                    "approved origin must be https",
                ));
            }
            v.push(origin);
        }
        Ok(OriginPolicy {
            approved_https: v,
            allow_development,
        })
    }

    /// The origins shipped in the legacy background script. Development origins disabled.
    pub fn legacy_defaults() -> Self {
        OriginPolicy::new(
            &[
                "https://layerwallet.com",
                "https://www.layerwallet.com",
                "https://testnet.layerwallet.com",
            ],
            false,
        )
        .unwrap_or(OriginPolicy {
            approved_https: Vec::new(),
            allow_development: false,
        })
    }

    pub fn is_allowed(&self, origin: &Origin) -> bool {
        if origin.is_https() {
            return self.approved_https.contains(origin);
        }
        self.allow_development
            && origin.as_str().starts_with("http://")
            && matches!(origin.host(), "localhost" | "127.0.0.1")
    }
}

/// Per-origin approved networks (`sitePermissionsV1`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SitePermissions {
    map: BTreeMap<Origin, Vec<Network>>,
}

impl SitePermissions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn approved(&self, origin: &Origin) -> &[Network] {
        self.map.get(origin).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn is_approved(&self, origin: &Origin, network: Network) -> bool {
        self.approved(origin).contains(&network)
    }

    /// Idempotent grant; returns the origin's approved list afterwards.
    pub fn grant(&mut self, origin: &Origin, network: Network) -> &[Network] {
        let list = self.map.entry(origin.clone()).or_default();
        if !list.contains(&network) {
            list.push(network);
        }
        list.as_slice()
    }

    pub fn revoke(&mut self, origin: &Origin, network: Network) {
        if let Some(l) = self.map.get_mut(origin) {
            l.retain(|n| *n != network);
            if l.is_empty() {
                self.map.remove(origin);
            }
        }
    }
}

/// A stored account record. `network` is the explicit stored label; it is never inferred
/// from the address prefix (legacy `inferNetworkFromAddress` only knew `ltc`/`tltc` and
/// the normalizer then defaulted everything else to LTC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAccount {
    pub address: String,
    pub network: Option<Network>,
    pub pubkey: Option<String>,
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSelection {
    pub accounts: Vec<StoredAccount>,
    /// Records for this network that failed address validation, plus records with no
    /// explicit network label (never matched).
    pub rejected: usize,
}

/// `getAddressesForNetwork`: only records explicitly labelled with `network` whose address
/// validates for it; the active account (if any) is moved first.
pub fn select_accounts(
    network: Network,
    records: &[StoredAccount],
    active_address: Option<&str>,
) -> Result<AccountSelection, ProviderError> {
    let mut accounts = Vec::new();
    let mut rejected = 0usize;
    for r in records {
        match r.network {
            None => rejected += 1,
            Some(n) if n == network => {
                if Address::parse(network, &r.address).is_ok() {
                    accounts.push(r.clone());
                } else {
                    rejected += 1;
                }
            }
            Some(_) => {}
        }
    }
    if accounts.is_empty() {
        return Err(ProviderError::NoAccounts);
    }
    if let Some(active) = active_address {
        if let Some(i) = accounts.iter().position(|a| a.address == active) {
            if i > 0 {
                let a = accounts.remove(i);
                accounts.insert(0, a);
            }
        }
    }
    Ok(AccountSelection { accounts, rejected })
}

/// `getPreferredLegacyNetwork` without the silent "LTC" fallback: the single account's
/// network; else LTCTEST if present; else LTC if present; else no accounts.
pub fn preferred_legacy_network(records: &[StoredAccount]) -> Result<Network, ProviderError> {
    let labelled: Vec<Network> = records.iter().filter_map(|r| r.network).collect();
    if labelled.len() == 1 {
        return Ok(labelled[0]);
    }
    if labelled.contains(&Network::LtcTest) {
        return Ok(Network::LtcTest);
    }
    if labelled.contains(&Network::Ltc) {
        return Ok(Network::Ltc);
    }
    Err(ProviderError::NoAccounts)
}

/// Sender facts supplied by the browser adapter.
#[derive(Debug, Clone)]
pub struct SenderContext {
    /// First available of `sender.origin`, `sender.url`, `sender.documentUrl`, `sender.tab.url`.
    pub origin_or_url: Option<String>,
    pub has_tab: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProviderRequest {
    pub id: Option<String>,
    pub method: String,
    /// Page-supplied network label. A hint to be checked against approvals, never a switch.
    pub network: Option<String>,
    pub legacy_bridge: bool,
    pub message: Option<String>,
    pub psbt_hex: Option<String>,
    pub transaction: Option<String>,
    pub multisig_m: Option<i64>,
    pub multisig_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalKind {
    Connect,
    SignMessage,
    SignPsbt,
    SignTransaction,
    AddMultisig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// `keepAlive`.
    Ok,
    /// `fetchUserIP` stub (`ip: null`, `isVpn: false`, `countryCode: "Unknown"`).
    UserIpStub,
    /// Return the accounts for `network` now.
    Accounts { origin: Origin, network: Network },
    /// Open the approval popup; no signing happens before the user decides.
    NeedsApproval {
        origin: Origin,
        network: Network,
        kind: ApprovalKind,
    },
}

fn resolve_network(
    perms: &SitePermissions,
    origin: &Origin,
    req: &ProviderRequest,
    stored: &[StoredAccount],
) -> Result<Network, ProviderError> {
    let approved = perms.approved(origin);
    let requested: Option<Network> = match &req.network {
        Some(label) => {
            let parsed = if req.legacy_bridge {
                Network::parse_legacy_generic(label)
            } else {
                Network::parse(label)
            };
            Some(parsed.map_err(|_| ProviderError::InvalidRequest("unknown network"))?)
        }
        None if req.legacy_bridge => Some(preferred_legacy_network(stored)?),
        None => None,
    };
    match requested {
        Some(n) if approved.contains(&n) => Ok(n),
        Some(_) => Err(ProviderError::NetworkNotApproved),
        None => match approved {
            [] => Err(ProviderError::OriginNotApproved),
            [only] => Ok(*only),
            _ => Err(ProviderError::NetworkRequired),
        },
    }
}

/// Decide what to do with one page request. Mirrors `handleProviderRequest`, with the
/// network defaults removed: `connect` requires an explicit network, and an origin with
/// several approved networks must name one.
pub fn evaluate(
    policy: &OriginPolicy,
    perms: &SitePermissions,
    sender: &SenderContext,
    req: &ProviderRequest,
    stored: &[StoredAccount],
) -> Result<Decision, ProviderError> {
    match &req.id {
        Some(id) if !id.is_empty() && id.len() <= MAX_REQUEST_ID_LEN => {}
        _ => return Err(ProviderError::MissingRequestId),
    }
    let method = ProviderMethod::parse(&req.method)?;

    let origin = match (&sender.origin_or_url, sender.has_tab) {
        (Some(u), true) => Origin::from_url(u).map_err(|_| ProviderError::OriginNotAllowed)?,
        _ => return Err(ProviderError::OriginNotAllowed),
    };
    if !policy.is_allowed(&origin) {
        return Err(ProviderError::OriginNotAllowed);
    }

    match method {
        ProviderMethod::KeepAlive => Ok(Decision::Ok),
        ProviderMethod::FetchUserIp => Ok(Decision::UserIpStub),
        ProviderMethod::Connect => {
            let label = req
                .network
                .as_deref()
                .ok_or(ProviderError::NetworkRequired)?;
            let parsed = if req.legacy_bridge {
                Network::parse_legacy_generic(label)
            } else {
                Network::parse(label)
            };
            let network = parsed.map_err(|_| ProviderError::InvalidRequest("unknown network"))?;
            if perms.is_approved(&origin, network) {
                Ok(Decision::Accounts { origin, network })
            } else {
                Ok(Decision::NeedsApproval {
                    origin,
                    network,
                    kind: ApprovalKind::Connect,
                })
            }
        }
        ProviderMethod::RequestAccounts => {
            let network = resolve_network(perms, &origin, req, stored)?;
            Ok(Decision::Accounts { origin, network })
        }
        ProviderMethod::SignMessage => {
            let network = resolve_network(perms, &origin, req, stored)?;
            match req.message.as_deref() {
                Some(m) if !m.is_empty() && m.len() <= MAX_MESSAGE_BYTES => {}
                _ => {
                    return Err(ProviderError::InvalidRequest(
                        "message required (<= 64 KiB)",
                    ))
                }
            }
            Ok(Decision::NeedsApproval {
                origin,
                network,
                kind: ApprovalKind::SignMessage,
            })
        }
        ProviderMethod::SignPsbt => {
            let network = resolve_network(perms, &origin, req, stored)?;
            let payload = req.psbt_hex.as_deref().or(req.transaction.as_deref());
            match payload {
                Some(h) if !h.is_empty() && h.len() <= MAX_PSBT_HEX_CHARS => {}
                _ => return Err(ProviderError::InvalidRequest("psbtHex required")),
            }
            Ok(Decision::NeedsApproval {
                origin,
                network,
                kind: ApprovalKind::SignPsbt,
            })
        }
        ProviderMethod::SignTransaction => {
            let network = resolve_network(perms, &origin, req, stored)?;
            match req.transaction.as_deref() {
                Some(t) if !t.is_empty() && t.len() <= MAX_PSBT_HEX_CHARS => {}
                _ => return Err(ProviderError::InvalidRequest("transaction required")),
            }
            Ok(Decision::NeedsApproval {
                origin,
                network,
                kind: ApprovalKind::SignTransaction,
            })
        }
        ProviderMethod::AddMultisig => {
            let network = resolve_network(perms, &origin, req, stored)?;
            let m = req
                .multisig_m
                .filter(|m| *m > 0)
                .ok_or(ProviderError::InvalidRequest("positive threshold required"))?;
            let n = req.multisig_pubkeys.len();
            if n == 0 || n > MAX_MULTISIG_KEYS || (m as u64) > n as u64 {
                return Err(ProviderError::InvalidRequest("pubkey count or threshold"));
            }
            Ok(Decision::NeedsApproval {
                origin,
                network,
                kind: ApprovalKind::AddMultisig,
            })
        }
    }
}

/// `chrome.runtime.onMessage` methods that only the extension popup may call.
pub fn is_popup_only_method(method: &str) -> bool {
    matches!(
        method,
        "popupReady"
            | "approvalDecision"
            | "signMessageResponse"
            | "signTxResponse"
            | "addMultisigResponse"
            | "rejectPendingRequest"
    )
}

/// Registry of requests waiting for the user: unique ids, bounded size, single settlement.
#[derive(Debug, Clone)]
pub struct PendingRequests<T> {
    map: BTreeMap<String, T>,
}

impl<T> Default for PendingRequests<T> {
    fn default() -> Self {
        PendingRequests {
            map: BTreeMap::new(),
        }
    }
}

impl<T> PendingRequests<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Duplicate ids and a full registry are refused.
    pub fn create(&mut self, id: &str, item: T) -> Result<(), ProviderError> {
        if id.is_empty() || id.len() > MAX_REQUEST_ID_LEN {
            return Err(ProviderError::MissingRequestId);
        }
        if self.map.contains_key(id) {
            return Err(ProviderError::InvalidRequest("duplicate request id"));
        }
        if self.map.len() >= MAX_PENDING_REQUESTS {
            return Err(ProviderError::InvalidRequest("too many pending requests"));
        }
        self.map.insert(id.to_string(), item);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&T> {
        self.map.get(id)
    }

    /// Remove and return; a second settle of the same id fails (no double responses).
    pub fn settle(&mut self, id: &str) -> Result<T, ProviderError> {
        self.map
            .remove(id)
            .ok_or(ProviderError::InvalidRequest("no pending request"))
    }
}
