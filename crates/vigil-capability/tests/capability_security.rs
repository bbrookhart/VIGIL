//! Adversarial tests for capability issuance and redemption.
//!
//! Each test corresponds to a line in the red-team matrix (spec §48, "Identity" and
//! "Approval") and to a GA blocker. They exercise the real issuer and verifier — no mocks in
//! the crypto path — so a regression here fails the build rather than a report.

use std::sync::Arc;
use vigil_capability::{
    CapabilityClaims, CapabilityIssuer, CapabilityVerifier, InMemoryNonceStore, PresentedAction,
    SigningKeyMaterial,
};
use vigil_common::ids::{
    AgentId, AgentInstanceId, CapabilityId, EnvironmentId, PolicyBundleId, PrincipalId, SessionId,
    TenantId, ToolId,
};
use vigil_common::{ContentHash, FixedClock};

const TTL: i64 = 60;

struct Fixture {
    issuer: CapabilityIssuer,
    verifier: CapabilityVerifier,
    clock: Arc<FixedClock>,
}

fn fixture() -> Fixture {
    let clock = Arc::new(FixedClock::at_epoch());
    let signing = SigningKeyMaterial::generate("k1");
    let public = signing.verifying_key();
    let issuer = CapabilityIssuer::new(signing, clock.clone());
    let verifier = CapabilityVerifier::new(clock.clone(), Arc::new(InMemoryNonceStore::new()))
        .trust_key("k1", public);
    Fixture {
        issuer,
        verifier,
        clock,
    }
}

fn id<T: std::str::FromStr>(s: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    s.parse().expect("valid test identifier")
}

fn action_hash(recipient: &str) -> ContentHash {
    ContentHash::canonical_json(&serde_json::json!({
        "kind": "tool_call",
        "name": "send_email",
        "arguments": {"to": recipient, "body": "quarterly report"},
    }))
    .expect("hashable")
}

fn claims(recipient: &str) -> CapabilityClaims {
    CapabilityClaims {
        version: String::new(),
        capability_id: CapabilityId::generate(),
        tenant_id: id::<TenantId>("acme"),
        environment_id: id::<EnvironmentId>("prod"),
        agent_id: id::<AgentId>("support-assistant"),
        agent_instance_id: id::<AgentInstanceId>("inst-1"),
        session_id: id::<SessionId>("sess-1"),
        principal_id: id::<PrincipalId>("user-1"),
        action_kind: "tool_call".to_string(),
        tool_id: Some(id::<ToolId>("send_email")),
        operation: "send".to_string(),
        target_resource: None,
        action_hash: action_hash(recipient),
        remit_version: "support@3".to_string(),
        policy_bundle_version: id::<PolicyBundleId>("bundle-7"),
        approval_id: None,
        constraints: vec![],
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now(),
        nonce: String::new(),
        max_uses: 1,
    }
}

fn presented(recipient: &str) -> PresentedAction {
    let c = claims(recipient);
    PresentedAction {
        tenant_id: c.tenant_id,
        environment_id: c.environment_id,
        agent_id: c.agent_id,
        agent_instance_id: c.agent_instance_id,
        session_id: c.session_id,
        principal_id: c.principal_id,
        action_kind: c.action_kind,
        tool_id: c.tool_id,
        operation: c.operation,
        target_resource: c.target_resource,
        action_hash: action_hash(recipient),
    }
}

#[test]
fn a_freshly_issued_capability_redeems_for_the_action_it_authorized() {
    let f = fixture();
    let (token, issued) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let verified = f
        .verifier
        .verify_and_consume(&token, &presented("cfo@acme.example"))
        .expect("the authorized action must succeed");
    assert_eq!(verified.use_number, 1);
    assert_eq!(verified.claims.capability_id, issued.capability_id);
}

#[test]
fn replaying_a_capability_fails() {
    // Red-team matrix: Identity → replayed capability. GA blocker if this regresses.
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    assert!(f
        .verifier
        .verify_and_consume(&token, &presented("cfo@acme.example"))
        .is_ok());
    let err = f
        .verifier
        .verify_and_consume(&token, &presented("cfo@acme.example"))
        .expect_err("a second redemption must fail");
    assert!(err.to_string().contains("already redeemed"), "{err}");
}

#[test]
fn an_expired_capability_never_executes() {
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    f.clock.advance(chrono::Duration::seconds(TTL + 1));
    let err = f
        .verifier
        .verify_and_consume(&token, &presented("cfo@acme.example"))
        .expect_err("an expired capability must fail");
    assert!(err.to_string().contains("expired"), "{err}");
}

#[test]
fn mutating_the_action_after_issuance_invalidates_the_capability() {
    // The core of Invariant 5. A capability for one recipient must not send to another.
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let err = f
        .verifier
        .verify_and_consume(&token, &presented("attacker@evil.example"))
        .expect_err("a mutated action must fail");
    assert!(
        err.to_string()
            .contains("does not match the authorized action"),
        "{err}"
    );
}

#[test]
fn a_rejected_redemption_does_not_consume_a_use_of_a_live_capability() {
    // Otherwise an attacker who cannot forge a capability can still destroy one, by
    // replaying it against a wrong action until its uses are exhausted.
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    for _ in 0..5 {
        assert!(f
            .verifier
            .verify_and_consume(&token, &presented("attacker@evil.example"))
            .is_err());
    }
    assert!(
        f.verifier
            .verify_and_consume(&token, &presented("cfo@acme.example"))
            .is_ok(),
        "the legitimate redemption must still succeed"
    );
}

#[test]
fn a_capability_cannot_be_redeemed_by_a_different_agent() {
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let mut other = presented("cfo@acme.example");
    other.agent_id = id::<AgentId>("finance-agent");
    let err = f.verifier.verify_and_consume(&token, &other).unwrap_err();
    assert!(err.to_string().contains("agent binding"), "{err}");
}

#[test]
fn a_capability_cannot_be_redeemed_across_tenants() {
    // GA blocker: cross-tenant isolation.
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let mut other = presented("cfo@acme.example");
    other.tenant_id = id::<TenantId>("other-corp");
    let err = f.verifier.verify_and_consume(&token, &other).unwrap_err();
    assert!(err.to_string().contains("tenant binding"), "{err}");
}

#[test]
fn a_capability_cannot_be_redeemed_in_a_different_session_or_instance() {
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();

    let mut other_session = presented("cfo@acme.example");
    other_session.session_id = id::<SessionId>("sess-2");
    assert!(f
        .verifier
        .verify_and_consume(&token, &other_session)
        .is_err());

    let mut other_instance = presented("cfo@acme.example");
    other_instance.agent_instance_id = id::<AgentInstanceId>("inst-2");
    assert!(f
        .verifier
        .verify_and_consume(&token, &other_instance)
        .is_err());
}

#[test]
fn a_capability_signed_by_an_untrusted_key_is_rejected() {
    // An attacker who compromises a non-Core component and mints their own capabilities.
    let f = fixture();
    let rogue_signing = SigningKeyMaterial::generate("k1"); // same key id, different key
    let rogue = CapabilityIssuer::new(rogue_signing, f.clock.clone());
    let (token, _) = rogue.issue(claims("attacker@evil.example"), TTL).unwrap();
    let err = f
        .verifier
        .verify_and_consume(&token, &presented("attacker@evil.example"))
        .unwrap_err();
    assert!(err.to_string().contains("signature is invalid"), "{err}");
}

#[test]
fn tampering_with_the_claims_breaks_the_signature() {
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let parts: Vec<&str> = token.split('.').collect();

    // Re-encode the claims with a different recipient hash and reuse the original signature.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let mut claims_value: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    claims_value["action_hash"] =
        serde_json::json!(action_hash("attacker@evil.example").to_string());
    let forged = format!(
        "{}.{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_value).unwrap()),
        parts[3]
    );

    let err = f
        .verifier
        .verify_and_consume(&forged, &presented("attacker@evil.example"))
        .unwrap_err();
    assert!(err.to_string().contains("signature is invalid"), "{err}");
}

#[test]
fn an_unsigned_or_none_algorithm_token_is_rejected() {
    // The `alg: none` class of attack, which broke many JWT implementations.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let f = fixture();
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"k1"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims("x@y.example")).unwrap());
    let token = format!(
        "vcap1.{header}.{body}.{}",
        URL_SAFE_NO_PAD.encode([0u8; 64])
    );
    let err = f
        .verifier
        .verify_and_consume(&token, &presented("x@y.example"))
        .unwrap_err();
    assert!(err.to_string().contains("unsupported"), "{err}");
}

#[test]
fn issuance_clamps_an_over_long_ttl_rather_than_honouring_it() {
    let f = fixture();
    let (_token, issued) = f.issuer.issue(claims("cfo@acme.example"), 86_400).unwrap();
    let lifetime = (issued.expires_at - issued.issued_at).num_seconds();
    assert_eq!(lifetime, vigil_capability::MAX_CAPABILITY_TTL_SECONDS);
}

#[test]
fn every_issued_capability_gets_a_distinct_nonce() {
    let f = fixture();
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..200 {
        let (_t, c) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
        assert!(nonces.insert(c.nonce.clone()), "nonce reuse: {}", c.nonce);
    }
}

#[test]
fn inspection_does_not_consume_a_use() {
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let inspected = f.verifier.inspect(&token).unwrap();
    assert_eq!(inspected.operation, "send");
    assert!(
        f.verifier
            .verify_and_consume(&token, &presented("cfo@acme.example"))
            .is_ok(),
        "inspection must not burn the capability"
    );
}

#[test]
fn a_capability_whose_nonce_store_is_unavailable_fails_closed() {
    // Chaos scenario: the replay-prevention backend is down. Execution must stop, not
    // proceed unchecked.
    #[derive(Debug)]
    struct BrokenStore;
    impl vigil_capability::NonceStore for BrokenStore {
        fn consume(
            &self,
            _nonce: &str,
            _max_uses: u32,
            _expires_at: vigil_common::Timestamp,
        ) -> vigil_common::Result<vigil_capability::NonceVerdict> {
            Err(vigil_common::VigilError::Unavailable {
                component: "nonce_store",
                reason: "simulated outage".to_string(),
            })
        }
        fn purge_expired(&self, _now: vigil_common::Timestamp) -> vigil_common::Result<usize> {
            Ok(0)
        }
    }

    let clock = Arc::new(FixedClock::at_epoch());
    let signing = SigningKeyMaterial::generate("k1");
    let public = signing.verifying_key();
    let issuer = CapabilityIssuer::new(signing, clock.clone());
    let verifier =
        CapabilityVerifier::new(clock.clone(), Arc::new(BrokenStore)).trust_key("k1", public);

    let (token, _) = issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    let err = verifier
        .verify_and_consume(&token, &presented("cfo@acme.example"))
        .expect_err("an unavailable replay check must reject");
    assert!(err.to_string().contains("nonce_store"), "{err}");
}

#[test]
fn clock_skew_leeway_applies_to_validity_start_but_never_extends_expiry() {
    let f = fixture();
    let (token, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();

    // A verifier running slightly behind the issuer still accepts.
    f.clock.advance(chrono::Duration::seconds(
        -(vigil_capability::CLOCK_SKEW_LEEWAY_SECONDS - 5),
    ));
    assert!(f
        .verifier
        .verify_and_consume(&token, &presented("cfo@acme.example"))
        .is_ok());

    // But a verifier running ahead does not get extra life out of the leeway.
    let (token2, _) = f.issuer.issue(claims("cfo@acme.example"), TTL).unwrap();
    f.clock.advance(chrono::Duration::seconds(TTL + 1));
    assert!(f
        .verifier
        .verify_and_consume(&token2, &presented("cfo@acme.example"))
        .is_err());
}
