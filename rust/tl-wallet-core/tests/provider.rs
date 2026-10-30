//! What a web page may ask for: method allow-list, origin approval, network/account selection.
mod common;
use common::*;
use tl_wallet_core::provider::*;
use tl_wallet_core::*;

fn sender(url: &str) -> SenderContext {
    SenderContext {
        origin_or_url: Some(url.to_string()),
        has_tab: true,
    }
}

fn request(method: &str) -> ProviderRequest {
    ProviderRequest {
        id: Some("req-1".to_string()),
        method: method.to_string(),
        ..Default::default()
    }
}

fn perms(networks: &[Network]) -> SitePermissions {
    let mut p = SitePermissions::new();
    for n in networks {
        p.grant(&origin(), *n);
    }
    p
}

fn stored(network: Option<Network>, a: &Account) -> StoredAccount {
    StoredAccount {
        address: a.receive_address().encode().unwrap(),
        network,
        pubkey: None,
        derivation_path: None,
    }
}

#[test]
fn method_allow_list_is_exact() {
    for (name, m) in [
        ("connect", ProviderMethod::Connect),
        ("requestAccounts", ProviderMethod::RequestAccounts),
        ("signMessage", ProviderMethod::SignMessage),
        ("signPsbt", ProviderMethod::SignPsbt),
        ("signPSBT", ProviderMethod::SignPsbt),
        ("signTransaction", ProviderMethod::SignTransaction),
        ("addMultisig", ProviderMethod::AddMultisig),
        ("fetchUserIP", ProviderMethod::FetchUserIp),
        ("keepAlive", ProviderMethod::KeepAlive),
    ] {
        assert_eq!(ProviderMethod::parse(name).unwrap(), m);
    }
    for bad in [
        "",
        "SignMessage",
        "signmessage",
        "sign",
        "eth_sign",
        "__proto__",
        "constructor",
        "connect ",
        "signTx",
        "personal_sign",
        "wallet_switchEthereumChain",
    ] {
        assert!(
            matches!(
                ProviderMethod::parse(bad),
                Err(ProviderError::UnsupportedMethod(_))
            ),
            "{bad:?}"
        );
    }
    assert!(ProviderMethod::SignMessage.needs_signing_approval());
    assert!(!ProviderMethod::RequestAccounts.needs_signing_approval());
    // unsupported method names are echoed truncated, never unbounded
    let long = "x".repeat(10_000);
    match ProviderMethod::parse(&long) {
        Err(ProviderError::UnsupportedMethod(s)) => assert_eq!(s.len(), 64),
        other => panic!("{other:?}"),
    }
}

#[test]
fn content_script_gate() {
    let s = PageId::Str("abc".into());
    assert_eq!(
        content_gate(false, &s, "signPSBT"),
        Ok(ProviderMethod::SignPsbt)
    );
    assert_eq!(
        content_gate(false, &PageId::Num(1.0), "connect"),
        Err(ProviderError::MissingRequestId)
    );
    assert_eq!(
        content_gate(true, &PageId::Num(1.0), "connect"),
        Ok(ProviderMethod::Connect)
    );
    assert_eq!(
        content_gate(true, &PageId::Num(f64::NAN), "connect"),
        Err(ProviderError::MissingRequestId)
    );
    assert_eq!(
        content_gate(true, &PageId::Other, "connect"),
        Err(ProviderError::MissingRequestId)
    );
    assert_eq!(
        content_gate(false, &PageId::Str(String::new()), "connect"),
        Err(ProviderError::MissingRequestId)
    );
    assert_eq!(
        content_gate(false, &PageId::Str("x".repeat(129)), "connect"),
        Err(ProviderError::MissingRequestId)
    );
    assert!(matches!(
        content_gate(false, &s, "evil"),
        Err(ProviderError::UnsupportedMethod(_))
    ));
}

#[test]
fn origin_parsing_canonicalizes_and_rejects_tricks() {
    assert_eq!(
        Origin::from_url("HTTPS://LayerWallet.com:443/path?q=1#f")
            .unwrap()
            .as_str(),
        "https://layerwallet.com"
    );
    assert_eq!(
        Origin::from_url("http://localhost:8080/").unwrap().as_str(),
        "http://localhost:8080"
    );
    for bad in [
        "",
        "layerwallet.com",
        "https://",
        "https://user:pw@layerwallet.com",
        "https://layerwallet.com@evil.com",
        "ftp://layerwallet.com",
        "javascript://layerwallet.com",
        "https://layerwallet.com:99999",
        "https://layerwallet.com:",
        "https://[::1]/",
        "https://l\u{e4}yerwallet.com",
        "https://..",
        "https://a..b",
        "null",
        "chrome-extension://abcdef",
    ] {
        assert!(Origin::from_url(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn origin_policy_only_admits_exact_https_origins() {
    let p = OriginPolicy::legacy_defaults();
    let ok = |u: &str| p.is_allowed(&Origin::from_url(u).unwrap());
    assert!(ok("https://layerwallet.com"));
    assert!(ok("https://www.layerwallet.com/page"));
    assert!(ok("https://testnet.layerwallet.com"));
    // look-alikes and scheme/port downgrades
    assert!(!ok("http://layerwallet.com"));
    assert!(!ok("https://layerwallet.com:8443"));
    assert!(!ok("https://evil-layerwallet.com"));
    assert!(!ok("https://layerwallet.com.evil.com"));
    assert!(!ok("https://sub.layerwallet.com"));
    assert!(!ok("http://localhost:3000"));
    assert!(!ok("http://127.0.0.1"));
    // development origins only when the flag is set, and only loopback http
    let dev = OriginPolicy::new(&["https://layerwallet.com"], true).unwrap();
    let okd = |u: &str| dev.is_allowed(&Origin::from_url(u).unwrap());
    assert!(okd("http://localhost:3000"));
    assert!(okd("http://127.0.0.1:8080"));
    assert!(!okd("http://localhost.evil.com"));
    assert!(!okd("https://localhost"));
    assert!(!okd("http://192.168.0.2"));
    assert!(OriginPolicy::new(&["http://layerwallet.com"], false).is_err());
}

#[test]
fn request_pipeline_order_and_defaults() {
    let policy = OriginPolicy::legacy_defaults();
    let ok_sender = sender("https://layerwallet.com/app");
    let p = perms(&[Network::LtcTest]);

    // missing id
    let mut r = request("requestAccounts");
    r.id = None;
    assert_eq!(
        evaluate(&policy, &p, &ok_sender, &r, &[]),
        Err(ProviderError::MissingRequestId)
    );
    // unsupported method is reported before the origin check (legacy order)
    assert!(matches!(
        evaluate(
            &policy,
            &p,
            &sender("https://evil.com"),
            &request("nope"),
            &[]
        ),
        Err(ProviderError::UnsupportedMethod(_))
    ));
    // origin not allowed / no tab / no origin
    assert_eq!(
        evaluate(
            &policy,
            &p,
            &sender("https://evil.com"),
            &request("keepAlive"),
            &[]
        ),
        Err(ProviderError::OriginNotAllowed)
    );
    let no_tab = SenderContext {
        origin_or_url: Some("https://layerwallet.com".into()),
        has_tab: false,
    };
    assert_eq!(
        evaluate(&policy, &p, &no_tab, &request("keepAlive"), &[]),
        Err(ProviderError::OriginNotAllowed)
    );
    let no_origin = SenderContext {
        origin_or_url: None,
        has_tab: true,
    };
    assert_eq!(
        evaluate(&policy, &p, &no_origin, &request("keepAlive"), &[]),
        Err(ProviderError::OriginNotAllowed)
    );
    // trivial methods
    assert_eq!(
        evaluate(&policy, &p, &ok_sender, &request("keepAlive"), &[]),
        Ok(Decision::Ok)
    );
    assert_eq!(
        evaluate(&policy, &p, &ok_sender, &request("fetchUserIP"), &[]),
        Ok(Decision::UserIpStub)
    );
}

#[test]
fn connect_requires_an_explicit_network_and_approval() {
    let policy = OriginPolicy::legacy_defaults();
    let s = sender("https://layerwallet.com");
    let empty = SitePermissions::new();
    // legacy defaulted a missing network to LTC
    assert_eq!(
        evaluate(&policy, &empty, &s, &request("connect"), &[]),
        Err(ProviderError::NetworkRequired)
    );
    let mut r = request("connect");
    r.network = Some("LTCTEST".into());
    assert_eq!(
        evaluate(&policy, &empty, &s, &r, &[]),
        Ok(Decision::NeedsApproval {
            origin: origin(),
            network: Network::LtcTest,
            kind: ApprovalKind::Connect
        })
    );
    // approval for LTCTEST does not carry to BTCTEST
    let p = perms(&[Network::LtcTest]);
    assert_eq!(
        evaluate(&policy, &p, &s, &r, &[]),
        Ok(Decision::Accounts {
            origin: origin(),
            network: Network::LtcTest
        })
    );
    r.network = Some("BTCTEST".into());
    assert_eq!(
        evaluate(&policy, &p, &s, &r, &[]),
        Ok(Decision::NeedsApproval {
            origin: origin(),
            network: Network::BtcTest,
            kind: ApprovalKind::Connect
        })
    );
    r.network = Some("moonbase".into());
    assert!(matches!(
        evaluate(&policy, &p, &s, &r, &[]),
        Err(ProviderError::InvalidRequest(_))
    ));
    // generic aliases only through the legacy bridge
    r.network = Some("TESTNET".into());
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.legacy_bridge = true;
    assert!(matches!(
        evaluate(&policy, &p, &s, &r, &[]),
        Ok(Decision::Accounts {
            network: Network::LtcTest,
            ..
        })
    ));
}

#[test]
fn page_cannot_switch_to_an_unapproved_or_ambiguous_network() {
    let policy = OriginPolicy::legacy_defaults();
    let s = sender("https://layerwallet.com");
    let one = perms(&[Network::LtcTest]);
    let two = perms(&[Network::LtcTest, Network::Ltc]);
    let none = SitePermissions::new();

    // no network named
    assert_eq!(
        evaluate(&policy, &one, &s, &request("requestAccounts"), &[]),
        Ok(Decision::Accounts {
            origin: origin(),
            network: Network::LtcTest
        })
    );
    // two approved networks, none named: legacy took approved[0]; now the page must say
    assert_eq!(
        evaluate(&policy, &two, &s, &request("requestAccounts"), &[]),
        Err(ProviderError::NetworkRequired)
    );
    assert_eq!(
        evaluate(&policy, &none, &s, &request("requestAccounts"), &[]),
        Err(ProviderError::OriginNotApproved)
    );
    // naming an unapproved network is refused for every method
    let mut r = request("signMessage");
    r.network = Some("BTC".into());
    r.message = Some("hi".into());
    assert_eq!(
        evaluate(&policy, &two, &s, &r, &[]),
        Err(ProviderError::NetworkNotApproved)
    );
    r.network = Some("LTC".into());
    assert_eq!(
        evaluate(&policy, &two, &s, &r, &[]),
        Ok(Decision::NeedsApproval {
            origin: origin(),
            network: Network::Ltc,
            kind: ApprovalKind::SignMessage
        })
    );
    // a different origin shares nothing
    let other = sender("https://www.layerwallet.com");
    assert_eq!(
        evaluate(&policy, &two, &other, &request("requestAccounts"), &[]),
        Err(ProviderError::OriginNotApproved)
    );
}

#[test]
fn legacy_bridge_preferred_network_has_no_silent_default() {
    let a = account(Network::LtcTest);
    let b = account(Network::Btc);
    let policy = OriginPolicy::legacy_defaults();
    let s = sender("https://layerwallet.com");
    let p = perms(&[Network::LtcTest, Network::Btc]);
    let mut r = request("requestAccounts");
    r.legacy_bridge = true;
    // single stored account decides
    assert_eq!(
        evaluate(&policy, &p, &s, &r, &[stored(Some(Network::Btc), &b)]),
        Ok(Decision::Accounts {
            origin: origin(),
            network: Network::Btc
        })
    );
    // several: LTCTEST first
    let both = [
        stored(Some(Network::Btc), &b),
        stored(Some(Network::LtcTest), &a),
    ];
    assert_eq!(preferred_legacy_network(&both), Ok(Network::LtcTest));
    // nothing stored: legacy fell back to LTC; now an error
    assert_eq!(
        evaluate(&policy, &p, &s, &r, &[]),
        Err(ProviderError::NoAccounts)
    );
    // unlabelled records are not guessed from the address prefix
    assert_eq!(
        preferred_legacy_network(&[stored(None, &a), stored(None, &b)]),
        Err(ProviderError::NoAccounts)
    );
    // preferred network still has to be approved
    let only_ltc = perms(&[Network::Ltc]);
    assert_eq!(
        evaluate(
            &policy,
            &only_ltc,
            &s,
            &r,
            &[stored(Some(Network::Btc), &b)]
        ),
        Err(ProviderError::NetworkNotApproved)
    );
}

#[test]
fn method_payload_validation() {
    let policy = OriginPolicy::legacy_defaults();
    let s = sender("https://layerwallet.com");
    let p = perms(&[Network::LtcTest]);
    // signMessage
    let mut r = request("signMessage");
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.message = Some(String::new());
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.message = Some("x".repeat(MAX_MESSAGE_BYTES + 1));
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.message = Some("x".repeat(MAX_MESSAGE_BYTES));
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_ok());
    // signPsbt accepts psbtHex or transaction
    let mut r = request("signPSBT");
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.transaction = Some("70736274ff".into());
    assert!(matches!(
        evaluate(&policy, &p, &s, &r, &[]),
        Ok(Decision::NeedsApproval {
            kind: ApprovalKind::SignPsbt,
            ..
        })
    ));
    // signTransaction
    let mut r = request("signTransaction");
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.transaction = Some("00".into());
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_ok());
    // addMultisig
    let mut r = request("addMultisig");
    r.multisig_pubkeys = vec!["02".into(), "03".into()];
    for bad_m in [None, Some(0), Some(-1), Some(3)] {
        r.multisig_m = bad_m;
        assert!(evaluate(&policy, &p, &s, &r, &[]).is_err(), "{bad_m:?}");
    }
    r.multisig_m = Some(2);
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_ok());
    r.multisig_pubkeys = vec!["02".into(); MAX_MULTISIG_KEYS + 1];
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
    r.multisig_pubkeys = vec![];
    assert!(evaluate(&policy, &p, &s, &r, &[]).is_err());
}

#[test]
fn site_permissions_are_idempotent_and_per_origin() {
    let mut p = SitePermissions::new();
    assert!(p.approved(&origin()).is_empty());
    assert_eq!(p.grant(&origin(), Network::Ltc), &[Network::Ltc]);
    assert_eq!(p.grant(&origin(), Network::Ltc), &[Network::Ltc]);
    assert_eq!(
        p.grant(&origin(), Network::Btc),
        &[Network::Ltc, Network::Btc]
    );
    assert!(p.approved(&other_origin()).is_empty());
    p.revoke(&origin(), Network::Ltc);
    assert_eq!(p.approved(&origin()), &[Network::Btc]);
    p.revoke(&origin(), Network::Btc);
    assert!(p.approved(&origin()).is_empty());
}

#[test]
fn account_selection_uses_explicit_labels_only() {
    let a = account(Network::LtcTest);
    let b = account(Network::Btc);
    let a2 = account_b(Network::LtcTest);
    let recs = vec![
        stored(Some(Network::LtcTest), &a),
        stored(Some(Network::Btc), &b),
        stored(Some(Network::LtcTest), &a2),
        stored(None, &a),
        // labelled LTCTEST but the address is a BTC address: rejected, not trusted
        StoredAccount {
            address: b.receive_address().encode().unwrap(),
            network: Some(Network::LtcTest),
            pubkey: None,
            derivation_path: None,
        },
    ];
    let sel = select_accounts(Network::LtcTest, &recs, None).unwrap();
    assert_eq!(sel.accounts.len(), 2);
    assert_eq!(sel.rejected, 2);
    assert_eq!(
        sel.accounts[0].address,
        a.receive_address().encode().unwrap()
    );
    // active account moves to the front
    let active = a2.receive_address().encode().unwrap();
    let sel = select_accounts(Network::LtcTest, &recs, Some(&active)).unwrap();
    assert_eq!(sel.accounts[0].address, active);
    // an unknown active address changes nothing
    let sel = select_accounts(Network::LtcTest, &recs, Some("nope")).unwrap();
    assert_eq!(sel.accounts.len(), 2);
    // nothing for DOGE
    assert_eq!(
        select_accounts(Network::Doge, &recs, None),
        Err(ProviderError::NoAccounts)
    );
}

#[test]
fn pending_registry_is_bounded_unique_and_single_settle() {
    let mut reg: PendingRequests<u32> = PendingRequests::new();
    assert!(reg.is_empty());
    reg.create("a", 1).unwrap();
    assert_eq!(
        reg.create("a", 2),
        Err(ProviderError::InvalidRequest("duplicate request id"))
    );
    assert_eq!(reg.get("a"), Some(&1));
    assert_eq!(reg.settle("a"), Ok(1));
    assert!(reg.settle("a").is_err());
    assert_eq!(reg.create("", 1), Err(ProviderError::MissingRequestId));
    for i in 0..MAX_PENDING_REQUESTS {
        reg.create(&format!("id{i}"), i as u32).unwrap();
    }
    assert_eq!(reg.len(), MAX_PENDING_REQUESTS);
    assert!(reg.create("one-too-many", 0).is_err());
    reg.settle("id0").unwrap();
    assert!(reg.create("one-too-many", 0).is_ok());
}

#[test]
fn popup_only_methods() {
    for m in [
        "popupReady",
        "approvalDecision",
        "signMessageResponse",
        "signTxResponse",
        "addMultisigResponse",
        "rejectPendingRequest",
    ] {
        assert!(is_popup_only_method(m));
    }
    assert!(!is_popup_only_method("providerRequest"));
    assert!(!is_popup_only_method("connect"));
}
