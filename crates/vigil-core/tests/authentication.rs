//! Regression tests for three authentication defects found in the shipped code.
//!
//! Each test names the defect it guards. All three were real: they held in-process, where the
//! only caller was trusted code, and failed over HTTP, where the caller is whoever can reach
//! the port.
//!
//! 1. `workload_identity.verified` was a `bool` deserialized from the request body, so
//!    Protected Mode's identity requirement was satisfiable by asserting it.
//! 2. `POST /v1/approvals/{id}/grant` took the approver's `Principal` from the body, so
//!    self-approval was a matter of typing a different name.
//! 3. Nothing authenticated any route, and no listener existed to authenticate on.

use std::collections::HashMap;
use std::sync::Arc;
use vigil_common::ids::*;
use vigil_common::{Clock, FixedClock};
use vigil_core::auth::CoreAuthenticator;
use vigil_core::{
    AuthenticatedRequest, Authenticator, CallerKind, CoreConfig, MtlsSpiffeAuthenticator,
    SharedSecretAuthenticator, ToolManifestRegistry, VerifiedIdentity, VigilCore,
};
use vigil_policy::DeterministicPolicyEngine;
use vigil_protocol::action::*;
use vigil_protocol::principal::{Principal, PrincipalKind, WorkloadIdentity};
use vigil_protocol::ActionRequest;
use vigil_remit::RemitRegistry;

const SUPPORT_SVID: &str = "spiffe://vigil.test/ns/agents/sa/support";

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("workspace root")
}

/// A Core configured exactly as production would be: Protected Mode, workload identity
/// required. The point of these tests is what happens at that setting.
fn protected_core() -> Arc<VigilCore> {
    let root = repo_root();
    let mut rules = Vec::new();
    for dir in ["policies/base", "policies/agents"] {
        let engine = DeterministicPolicyEngine::from_directory(
            &root.join(dir),
            PolicyBundleId::new("t").expect("id"),
        )
        .expect("shipped bundles load");
        rules.extend(engine.bundle().rules.clone());
    }
    let policy = Arc::new(DeterministicPolicyEngine::new(vigil_policy::PolicyBundle {
        version: PolicyBundleId::new("auth-test").expect("id"),
        description: "shipped rules".to_string(),
        default_effect: vigil_policy::PolicyEffect::Deny,
        rules,
    }));

    Arc::new(
        VigilCore::builder()
            .config(CoreConfig {
                // Not `development()` — these tests exist to exercise the production setting.
                require_workload_identity: true,
                allow_unregistered_agents: true,
                ..CoreConfig::default()
            })
            .policy(policy)
            .remits(RemitRegistry::load_directory(&root.join("policies/remits")).expect("remits"))
            .manifests(
                ToolManifestRegistry::load_file(&root.join("policies/tools/manifests.yaml"))
                    .expect("manifests"),
            )
            .clock(Arc::new(FixedClock::at_epoch()))
            .tenant(TenantId::new("acme").expect("id"))
            .ephemeral_keys()
            .build()
            .expect("core builds"),
    )
}

fn spiffe_authenticator() -> MtlsSpiffeAuthenticator {
    MtlsSpiffeAuthenticator::new().register_agent(
        SUPPORT_SVID,
        TenantId::new("acme").expect("id"),
        AgentId::new("customer-support-assistant").expect("id"),
    )
}

fn request_claiming(workload_identity: Option<WorkloadIdentity>) -> ActionRequest {
    ActionRequest {
        schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
        request_id: EventId::new_random(),
        occurred_at: FixedClock::at_epoch().now(),
        tenant_id: TenantId::new("acme").expect("id"),
        environment_id: EnvironmentId::new("prod").expect("id"),
        session_id: SessionId::new("sess-1").expect("id"),
        agent_id: AgentId::new("customer-support-assistant").expect("id"),
        agent_instance_id: AgentInstanceId::new("inst-1").expect("id"),
        principal: Principal::new(
            PrincipalId::new("user-1").expect("id"),
            PrincipalKind::Human,
            TenantId::new("acme").expect("id"),
        ),
        workload_identity,
        trace: Default::default(),
        action: Action::ToolCall(ToolCall {
            protocol: ToolProtocol::Native,
            server: None,
            tool_id: ToolId::new("read_customer_record").expect("id"),
            name: "read_customer_record".to_string(),
            version: None,
            operation: Some("read".to_string()),
            arguments: serde_json::json!({"customer_id": "C-1"}),
            target_resource: None,
            declared_side_effect: None,
        }),
        context: Default::default(),
    }
}

// ------------------------------------------------------- defect 1: forged `verified`

#[test]
fn defect_1_a_request_body_cannot_assert_that_it_is_verified() {
    // The exact payload that used to satisfy Protected Mode.
    let body = serde_json::json!({
        "id": "spiffe://vigil.example/ns/agents/sa/admin",
        "attestation_method": "mtls",
        "verified": true
    });
    let parsed: WorkloadIdentity = serde_json::from_value(body).expect("parses");
    assert!(
        !parsed.verified,
        "a body-supplied `verified` flag must not survive deserialization"
    );
}

#[tokio::test]
async fn defect_1_a_forged_identity_cannot_reach_a_decision() {
    // End-to-end: build the request an attacker would send, hand it to the authenticator the
    // API layer uses, and confirm it never becomes an AuthenticatedRequest.
    let forged: WorkloadIdentity = serde_json::from_value(serde_json::json!({
        "id": SUPPORT_SVID,
        "attestation_method": "mtls",
        "verified": true
    }))
    .expect("parses");

    let result = spiffe_authenticator()
        .authenticate_request(
            request_claiming(Some(forged)),
            &HashMap::new(),
            &[], // no client certificate — the attacker has only the body
        )
        .await;

    assert!(
        result.is_err(),
        "a request with no certificate must not authenticate, whatever its body claims"
    );
}

#[tokio::test]
async fn defect_1_protected_mode_rejects_an_unverified_caller() {
    let core = protected_core();

    // Construct an AuthenticatedRequest whose identity is *not* verified, which is what a
    // misconfigured or degraded authenticator would produce.
    #[derive(Debug)]
    struct UnverifyingAuthenticator;

    #[async_trait::async_trait]
    impl Authenticator for UnverifyingAuthenticator {
        async fn authenticate(
            &self,
            _headers: &HashMap<String, String>,
            _peer: &[String],
        ) -> vigil_common::Result<VerifiedIdentity> {
            Ok(VerifiedIdentity {
                // `unverified` rather than `attested`: the flag is false.
                workload: WorkloadIdentity::unverified("spiffe://unproven"),
                tenant_id: TenantId::new("acme").expect("id"),
                agent_id: Some(AgentId::new("customer-support-assistant").expect("id")),
                principal_id: None,
                roles: vec![],
                kind: CallerKind::Agent,
            })
        }
        fn method(&self) -> &'static str {
            "test_unverifying"
        }
    }

    let authenticated = UnverifyingAuthenticator
        .authenticate_request(request_claiming(None), &HashMap::new(), &[])
        .await
        .expect("binding succeeds; the identity is simply not verified");

    let error = core
        .decide(&authenticated)
        .await
        .expect_err("protected mode must reject an unverified workload identity");
    assert!(
        error.to_string().contains("verified workload identity"),
        "{error}"
    );
}

#[tokio::test]
async fn a_properly_attested_caller_is_accepted() {
    // The other half: the control must not simply reject everything.
    let core = protected_core();
    let authenticated = spiffe_authenticator()
        .authenticate_request(
            request_claiming(None),
            &HashMap::new(),
            &[SUPPORT_SVID.to_string()],
        )
        .await
        .expect("a registered SVID authenticates");

    let outcome = core.decide(&authenticated).await.expect("decision");
    assert!(
        outcome.response.permits_execution(),
        "got {:?} because {:?}",
        outcome.response.decision,
        outcome.response.reason_codes
    );
}

#[tokio::test]
async fn the_audit_record_shows_the_proven_identity_not_the_claimed_one() {
    let core = protected_core();
    let claimed = WorkloadIdentity::unverified("spiffe://evil/ns/admin");
    let authenticated = spiffe_authenticator()
        .authenticate_request(
            request_claiming(Some(claimed)),
            &HashMap::new(),
            &[SUPPORT_SVID.to_string()],
        )
        .await
        .expect("authenticates");

    core.decide(&authenticated).await.expect("decision");

    let bundle = core.audit().export().expect("export");
    let recorded = bundle
        .entries
        .last()
        .and_then(|e| e.event.workload_identity.clone())
        .expect("the event carries a workload identity");
    assert_eq!(
        recorded.id, SUPPORT_SVID,
        "the proven identity must be recorded"
    );
    assert!(recorded.verified);
}

// ------------------------------------------------------- defect 2: self-approval

#[test]
fn defect_2_the_grant_route_accepts_no_body_naming_an_approver() {
    // Structural. Read from disk rather than `include_str!` of this file: a test that greps
    // its own source can never fail, because the needle is the string it contains.
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/api.rs"),
    )
    .expect("api.rs is readable");

    assert!(
        !source.contains("struct GrantApprovalRequest"),
        "reintroducing a request body that names the approver restores the self-approval hole"
    );
    assert!(
        source.contains("only an authenticated human principal may grant an approval"),
        "the grant route must derive the approver from the authenticated caller"
    );
}

#[test]
fn defect_3_no_handler_uses_the_in_process_authentication_bypass() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/api.rs"),
    )
    .expect("api.rs is readable");

    assert!(
        !source.contains("for_trusted_in_process_caller"),
        "the API layer must authenticate, never bypass"
    );
    assert!(
        source.contains("auth_middleware"),
        "every non-probe route must sit behind authentication"
    );
}

#[tokio::test]
async fn an_agent_workload_cannot_grant_an_approval() {
    // Authorization, not just authentication: a valid agent identity is the wrong *kind* of
    // caller for the approval route. The check lives in the handler, but the service
    // independently refuses a non-human approver too.
    let core = protected_core();
    let requester = Principal::new(
        PrincipalId::new("user-1").expect("id"),
        PrincipalKind::Human,
        TenantId::new("acme").expect("id"),
    );

    let approval = core
        .approvals()
        .request(
            TenantId::new("acme").expect("id"),
            AgentId::new("customer-support-assistant").expect("id"),
            SessionId::new("sess-1").expect("id"),
            requester.id.clone(),
            vigil_common::ContentHash::sha256(b"an action"),
            vigil_core::TransactionPreview {
                action_descriptor: "tool_call:send_email".to_string(),
                target: None,
                parameters: vec![],
                sensitive_data_crossing_boundary: vec![],
                rationale: None,
                triggering_policies: vec![],
                risk_score: 0.5,
                irreversible: true,
                reason_codes: vec![],
            },
            vec!["SupportLead".to_string()],
            900,
        )
        .expect("approval raised");

    let mut agent_principal = Principal::new(
        PrincipalId::new("agent-1").expect("id"),
        PrincipalKind::Agent,
        TenantId::new("acme").expect("id"),
    )
    .with_roles(["SupportLead".to_string()]);
    agent_principal.kind = PrincipalKind::Agent;

    let error = core
        .approvals()
        .grant(&approval.approval_id, &agent_principal)
        .expect_err("an agent must never grant an approval");
    assert!(error.to_string().contains("accountable human"), "{error}");
}

// ------------------------------------------------------- impersonation

#[tokio::test]
async fn an_authenticated_agent_cannot_submit_actions_as_another_agent() {
    let mut impersonating = request_claiming(None);
    impersonating.agent_id = AgentId::new("finance-agent").expect("id");

    let error = spiffe_authenticator()
        .authenticate_request(impersonating, &HashMap::new(), &[SUPPORT_SVID.to_string()])
        .await
        .expect_err("proving you are one agent must not let you act as another");
    assert!(error.to_string().contains("as another agent"), "{error}");
}

#[tokio::test]
async fn an_authenticated_agent_cannot_submit_actions_for_another_tenant() {
    let mut cross_tenant = request_claiming(None);
    cross_tenant.tenant_id = TenantId::new("other-corp").expect("id");
    cross_tenant.principal = Principal::new(
        PrincipalId::new("user-1").expect("id"),
        PrincipalKind::Human,
        TenantId::new("other-corp").expect("id"),
    );

    let error = spiffe_authenticator()
        .authenticate_request(cross_tenant, &HashMap::new(), &[SUPPORT_SVID.to_string()])
        .await
        .expect_err("cross-tenant submission must be refused");
    assert!(error.to_string().contains("another"), "{error}");
}

// ------------------------------------------------------- configuration safety

#[test]
fn the_development_authenticator_cannot_be_used_for_protected_mode_in_release() {
    // The control that stops a development shortcut becoming production authentication.
    let result = SharedSecretAuthenticator::new(true);
    if cfg!(debug_assertions) {
        assert!(result.is_ok(), "development builds may use it");
    } else {
        assert!(result.is_err(), "release builds must refuse it");
    }
}

#[test]
fn an_authenticated_request_can_only_be_built_through_an_authenticator_or_the_named_bypass() {
    // Documents the type-level property. `AuthenticatedRequest` has private fields and no
    // public constructor other than `for_trusted_in_process_caller`; everything else goes
    // through `CoreAuthenticator`. If someone adds a public constructor, this comment is the
    // reminder that it defeats the whole module.
    let request = request_claiming(None);
    let authenticated = AuthenticatedRequest::for_trusted_in_process_caller(request);
    assert_eq!(
        authenticated.identity().workload.attestation_method,
        "in_process_trusted_caller"
    );
}
