//! Request handlers of the extension binding. Pure with respect to the host: storage and
//! randomness come in as `tl-wallet-core` traits, so the same code runs natively in tests
//! (with `MemoryStore`) and inside the browser (with the host-import store in `lib.rs`).
//!
//! Wire format: one JSON object in (`{"op": "...", ...}`), one JSON object out
//! (`{"ok": true, ...}` or `{"ok": false, "code": "...", "message": "..."}`). Secrets that
//! leave this module: the seed phrase from `generate_mnemonic` and `expose_seed` (both are
//! explicit user actions in the legacy UI); no private key is ever returned.

use bitcoin::{ScriptBuf, Txid};
use serde_json::{json, Value};
use std::str::FromStr;
use tl_wallet_core::capability::{self, Requester, SigningCapability};
use tl_wallet_core::coin::{FeePolicy, Utxo, LEGACY_FIXED_FEE};
use tl_wallet_core::keys::{generate_mnemonic, Account, ChangeMode, ImportedMnemonic};
use tl_wallet_core::tx::{self, PaymentRequest, SignOptions, SignOutcome};
use tl_wallet_core::vault::{
    Kdf, Phase, Random, Secret, UnlockSource, VaultError, VaultManager, VaultStore,
};
use tl_wallet_core::{Address, Error, Network, Origin, Sats};

/// The vault keeps one seed for every network; this is the "slot" label sealed into the header.
pub const VAULT_SLOT: Network = Network::Ltc;
/// Origin used for approvals the wallet UI itself initiates (Send), where no page is involved.
pub const WALLET_ORIGIN: &str = "https://tl-extension.invalid";
/// A capability is granted at the moment of approval and consumed in the same call.
const CAPABILITY_TTL_SECS: u64 = 60;
/// Hard bounds on request sizes (the host also bounds the buffer it passes).
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_UTXOS: usize = 2_000;

pub struct OpError {
    pub code: String,
    pub message: String,
}

impl OpError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        OpError {
            code: code.to_string(),
            message: message.into(),
        }
    }
    fn bad(message: &str) -> Self {
        OpError::new("BadRequest", message)
    }
}

/// First identifier of a `Debug` rendering: `Legacy(BadPadding)` -> `Legacy`.
fn variant_name(debug: &str) -> String {
    debug
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

impl From<VaultError> for OpError {
    fn from(e: VaultError) -> Self {
        let text = format!("{e:?}");
        OpError::new(&variant_name(&text), text)
    }
}

impl From<Error> for OpError {
    fn from(e: Error) -> Self {
        let text = format!("{e:?}");
        OpError::new(&variant_name(&text), text)
    }
}

type Res<T> = Result<T, OpError>;

fn str_field<'a>(req: &'a Value, name: &str) -> Res<&'a str> {
    req.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| OpError::bad(&format!("field `{name}` must be a string")))
}

fn opt_str_field<'a>(req: &'a Value, name: &str) -> Option<&'a str> {
    req.get(name).and_then(Value::as_str)
}

fn network_field(req: &Value) -> Res<Network> {
    Ok(Network::parse_legacy_generic(str_field(req, "network")?)?)
}

fn now_field(req: &Value) -> u64 {
    req.get("now").and_then(Value::as_u64).unwrap_or(0)
}

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::BackedUp => "BackedUp",
        Phase::Written => "Written",
        Phase::Verified => "Verified",
        Phase::Retired => "Retired",
        Phase::Native => "Native",
    }
}

fn account_from_secret(secret: &Secret, network: Network) -> Res<Account> {
    let phrase = secret
        .as_str()
        .ok_or_else(|| OpError::new("InvalidSecret", "vault secret is not text"))?;
    let m = ImportedMnemonic::parse_phrase(phrase.trim())?;
    Ok(Account::from_mnemonic(
        &m,
        network,
        ChangeMode::SameAsReceive,
    )?)
}

fn requester(req: &Value, network: Network) -> Res<Requester> {
    let origin = opt_str_field(req, "origin").unwrap_or(WALLET_ORIGIN);
    let origin = Origin::from_url(origin)
        .map_err(|_| OpError::new("InvalidOrigin", "origin is not an http(s) origin"))?;
    Ok(Requester { origin, network })
}

/// Run one request. `now` is seconds on any monotonic clock the host chooses.
pub fn handle<S: VaultStore, R: Random>(store: S, rng: R, request: &[u8]) -> Vec<u8> {
    let out = match run(store, rng, request) {
        Ok(mut v) => {
            if let Value::Object(m) = &mut v {
                m.insert("ok".into(), Value::Bool(true));
            }
            v
        }
        Err(e) => json!({"ok": false, "code": e.code, "message": e.message}),
    };
    serde_json::to_vec(&out).unwrap_or_else(|_| b"{\"ok\":false,\"code\":\"Encode\"}".to_vec())
}

fn run<S: VaultStore, R: Random>(store: S, mut rng: R, request: &[u8]) -> Res<Value> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(OpError::bad("request too large"));
    }
    let req: Value =
        serde_json::from_slice(request).map_err(|_| OpError::bad("request is not JSON"))?;
    let op = str_field(&req, "op")?.to_string();
    if op == "generate_mnemonic" {
        return generate(&mut rng);
    }
    let mut mgr = VaultManager::new(store, rng, VAULT_SLOT, Kdf::DEFAULT)?;
    match op.as_str() {
        "status" => status(&mgr),
        "create" => create(&mut mgr, &req),
        "unlock" => unlock(&mut mgr, &req),
        "check_password" => check_password(&mgr, &req),
        "expose_seed" => expose_seed(&mgr, &req),
        "change_password" => change_password(&mut mgr, &req),
        "sign_message" => sign_message(&mgr, &req),
        "sign_psbt" => sign_psbt(&mgr, &req),
        "sign_payment" => sign_payment(&mgr, &req),
        other => Err(OpError::new("UnknownOp", format!("unknown op `{other}`"))),
    }
}

fn status<S: VaultStore, R: Random>(mgr: &VaultManager<S, R>) -> Res<Value> {
    let snap = mgr.snapshot()?;
    let source = if snap.legacy || snap.vault {
        Some(match mgr.unlock_source()? {
            UnlockSource::Legacy => "legacy",
            UnlockSource::Sealed => "sealed",
        })
    } else {
        None
    };
    Ok(json!({
        "exists": snap.legacy || snap.vault,
        "legacy": snap.legacy,
        "vault": snap.vault,
        "backup": snap.backup,
        "phase": snap.phase.map(phase_name),
        "source": source,
    }))
}

fn generate<R: Random>(rng: &mut R) -> Res<Value> {
    let mut entropy = [0u8; 16];
    rng.fill(&mut entropy)?;
    let phrase = generate_mnemonic(&entropy)?;
    entropy.fill(0);
    Ok(json!({ "phrase": phrase }))
}

fn create<S: VaultStore, R: Random>(mgr: &mut VaultManager<S, R>, req: &Value) -> Res<Value> {
    let phrase = str_field(req, "phrase")?;
    let password = str_field(req, "password")?;
    let m = ImportedMnemonic::parse_phrase(phrase)?;
    mgr.create(&m, password)?;
    Ok(json!({}))
}

fn account_info(account: &Account) -> Res<Value> {
    let info = account.info()?;
    Ok(json!({
        "address": info.address,
        "public_key": info.public_key_hex,
        "derivation_path": info.derivation_path,
        "network": info.network.id(),
    }))
}

fn unlock<S: VaultStore, R: Random>(mgr: &mut VaultManager<S, R>, req: &Value) -> Res<Value> {
    let password = str_field(req, "password")?;
    let network = network_field(req)?;
    let source = mgr.unlock_source();
    let secret = mgr.unlock(password)?;
    let mut out = account_info(&account_from_secret(&secret, network)?)?;
    // A correct password on a legacy (crypto-js) vault is the moment to upgrade it: the
    // legacy blob stays as `vault.legacy_backup` and the wallet keeps working if any step fails.
    if matches!(source, Ok(UnlockSource::Legacy)) {
        let migration = match mgr.migrate(password, password) {
            Ok(phase) => json!({"phase": phase_name(phase)}),
            Err(e) => json!({"error": OpError::from(e).code}),
        };
        if let Value::Object(m) = &mut out {
            m.insert("migration".into(), migration);
        }
    } else if let Some(discarded) = drop_legacy_backup(mgr, password, password) {
        if let Value::Object(m) = &mut out {
            m.insert("backup_discarded".into(), json!(discarded));
        }
    }
    Ok(out)
}

/// The legacy backup is encrypted with crypto-js's single-round MD5 key derivation, so keeping
/// it keeps the weak ciphertext on disk. It is dropped at the first call after a completed
/// migration that opens the sealed vault (the confirmation that the sealed vault works);
/// `discard_backup` re-checks that the backup and the sealed vault hold the same seed before it
/// deletes. Returns `None` when there is no backup to drop, otherwise whether it was dropped; a
/// failure keeps the backup and never fails the calling operation.
fn drop_legacy_backup<S: VaultStore, R: Random>(
    mgr: &mut VaultManager<S, R>,
    backup_password: &str,
    vault_password: &str,
) -> Option<bool> {
    let snap = mgr.snapshot().ok()?;
    if !snap.backup || snap.phase != Some(Phase::Retired) {
        return None;
    }
    Some(mgr.discard_backup(backup_password, vault_password).is_ok())
}

fn check_password<S: VaultStore, R: Random>(mgr: &VaultManager<S, R>, req: &Value) -> Res<Value> {
    let password = str_field(req, "password")?;
    let network = network_field(req)?;
    let address = str_field(req, "address")?;
    mgr.check_password_match(password, network, address)?;
    Ok(json!({}))
}

fn expose_seed<S: VaultStore, R: Random>(mgr: &VaultManager<S, R>, req: &Value) -> Res<Value> {
    let secret = mgr.unlock(str_field(req, "password")?)?;
    let phrase = secret
        .as_str()
        .ok_or_else(|| OpError::new("InvalidSecret", "vault secret is not text"))?;
    Ok(json!({ "phrase": phrase }))
}

fn change_password<S: VaultStore, R: Random>(
    mgr: &mut VaultManager<S, R>,
    req: &Value,
) -> Res<Value> {
    let old = str_field(req, "old_password")?;
    let new = str_field(req, "new_password")?;
    // The backup is under the password the migration started from. Drop it while that password
    // is known: before a sealed change, and right after a migration under a new password.
    let discarded = match mgr.unlock_source()? {
        UnlockSource::Legacy => {
            mgr.migrate(old, new)?;
            drop_legacy_backup(mgr, old, new)
        }
        UnlockSource::Sealed => {
            mgr.unlock(old)?;
            let discarded = drop_legacy_backup(mgr, old, old);
            mgr.change_password(old, new)?;
            discarded
        }
    };
    Ok(match discarded {
        Some(d) => json!({ "backup_discarded": d }),
        None => json!({}),
    })
}

/// Unlock and derive the account for `network`, the first step of every signing op.
fn unlocked_account<S: VaultStore, R: Random>(
    mgr: &VaultManager<S, R>,
    req: &Value,
    network: Network,
) -> Res<Account> {
    let secret = mgr.unlock(str_field(req, "password")?)?;
    account_from_secret(&secret, network)
}

fn sign_message<S: VaultStore, R: Random>(mgr: &VaultManager<S, R>, req: &Value) -> Res<Value> {
    let network = network_field(req)?;
    let message = str_field(req, "message")?;
    let now = now_field(req);
    let requester = requester(req, network)?;
    let account = unlocked_account(mgr, req, network)?;
    let cap = SigningCapability::for_message(
        requester.origin.clone(),
        account.id(),
        now.saturating_add(CAPABILITY_TTL_SECS),
        message.as_bytes().to_vec(),
    );
    let signature = capability::sign_message(cap, &requester, &account, now, message.as_bytes())?;
    Ok(json!({ "signature": signature, "address": account.receive_address().encode()? }))
}

fn outcome_json(outcome: SignOutcome) -> Value {
    match outcome {
        SignOutcome::Final { raw_tx_hex, txid } => json!({"raw_tx": raw_tx_hex, "txid": txid}),
        SignOutcome::Partial { psbt_hex } => json!({"psbt_hex": psbt_hex}),
    }
}

fn sign_psbt<S: VaultStore, R: Random>(mgr: &VaultManager<S, R>, req: &Value) -> Res<Value> {
    let network = network_field(req)?;
    let psbt = tx::parse_psbt_hex(str_field(req, "psbt_hex")?)?;
    let seller = req
        .get("seller_flag")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let witness_script = match opt_str_field(req, "witness_script") {
        Some(h) if !h.is_empty() => {
            Some(ScriptBuf::from_hex(h).map_err(|_| OpError::bad("witness_script is not hex"))?)
        }
        _ => None,
    };
    let now = now_field(req);
    let requester = requester(req, network)?;
    let account = unlocked_account(mgr, req, network)?;
    // Approval = the user pressing Approve on the PSBT shown by the popup. The approved
    // inputs, outputs and fee are those of the PSBT the popup displayed, which this call
    // re-derives from the same bytes; signing re-checks them against the PSBT again.
    let (inputs, outputs) = tx::presented(&psbt)?;
    let total_in = Sats::sum(inputs.iter().map(|i| i.value))?;
    let total_out = Sats::sum(outputs.iter().map(|o| o.value))?;
    let fee = total_in.checked_sub(total_out)?;
    let cap = SigningCapability::for_transaction(
        requester.origin.clone(),
        account.id(),
        now.saturating_add(CAPABILITY_TTL_SECS),
        inputs,
        outputs,
        fee,
    );
    let opts = SignOptions {
        only_indices: if seller { Some(vec![0]) } else { None },
        finalize: !seller,
        witness_script_input0: witness_script,
    };
    let outcome = capability::sign_psbt(cap, &requester, &account, now, psbt, &opts)?;
    Ok(outcome_json(outcome))
}

fn parse_utxo(v: &Value) -> Res<Utxo> {
    let txid = v
        .get("txid")
        .and_then(Value::as_str)
        .and_then(|s| Txid::from_str(s).ok())
        .ok_or_else(|| OpError::bad("utxo.txid"))?;
    let vout = v
        .get("vout")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| OpError::bad("utxo.vout"))?;
    let value = Sats::from_coin_str(
        v.get("amount")
            .and_then(Value::as_str)
            .ok_or_else(|| OpError::bad("utxo.amount must be a decimal string"))?,
    )?;
    let script_pubkey = v
        .get("script_pubkey")
        .and_then(Value::as_str)
        .and_then(|s| ScriptBuf::from_hex(s).ok())
        .ok_or_else(|| OpError::bad("utxo.script_pubkey"))?;
    Ok(Utxo {
        txid,
        vout,
        value,
        script_pubkey,
        prev_tx: None,
    })
}

fn sign_payment<S: VaultStore, R: Random>(mgr: &VaultManager<S, R>, req: &Value) -> Res<Value> {
    let network = network_field(req)?;
    let to = Address::parse(network, str_field(req, "to")?)?;
    let amount = Sats::from_coin_str(str_field(req, "amount")?)?;
    let utxos: Vec<Utxo> = req
        .get("utxos")
        .and_then(Value::as_array)
        .ok_or_else(|| OpError::bad("utxos must be an array"))?
        .iter()
        .take(MAX_UTXOS + 1)
        .map(parse_utxo)
        .collect::<Res<_>>()?;
    if utxos.len() > MAX_UTXOS {
        return Err(OpError::bad("too many utxos"));
    }
    let payload = opt_str_field(req, "payload").map(str::as_bytes);
    let now = now_field(req);
    let requester = requester(req, network)?;
    let account = unlocked_account(mgr, req, network)?;
    let plan = tx::build_payment(
        &account,
        &PaymentRequest {
            to: &to,
            amount,
            utxos: &utxos,
            fee: FeePolicy::Fixed(LEGACY_FIXED_FEE),
            max_fee: LEGACY_FIXED_FEE,
            payload,
        },
    )?;
    let cap = SigningCapability::for_transaction(
        requester.origin.clone(),
        account.id(),
        now.saturating_add(CAPABILITY_TTL_SECS),
        plan.inputs.clone(),
        plan.outputs.clone(),
        plan.fee,
    );
    let outcome = capability::sign_psbt(
        cap,
        &requester,
        &account,
        now,
        plan.psbt,
        &SignOptions {
            only_indices: None,
            finalize: true,
            witness_script_input0: None,
        },
    )?;
    let mut out = outcome_json(outcome);
    if let Value::Object(m) = &mut out {
        m.insert("fee_sats".into(), json!(plan.fee.0));
    }
    Ok(out)
}
