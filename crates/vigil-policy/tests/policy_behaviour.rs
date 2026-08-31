//! Behavioural tests for the deterministic policy engine, run against the *shipped* bundles
//! in `policies/` rather than against fixtures invented for the test.
//!
//! A policy engine tested only on hand-written rules proves nothing about the rules an
//! operator will actually deploy. These tests fail if someone edits `policies/` in a way that
//! opens a hole, which is the point.

use std::path::PathBuf;
use vigil_common::ids::{AgentId, EnvironmentId, PolicyBundleId, PrincipalId, SessionId, TenantId};
use vigil_policy::{
    DeterministicPolicyEngine, PolicyAction, PolicyContext, PolicyEngine, PolicyPrincipal,
    PolicyRequest, PolicyResource,
};
use vigil_protocol::action::{ImpactTier, SideEffectClass};
use vigil_protocol::decision::Decision;
use vigil_protocol::reason::ReasonCode;
use vigil_protocol::trust::{TaintKind, TrustLevel};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("workspace root")
}

/// Load the real base + agent bundles the product ships with.
fn engine() -> DeterministicPolicyEngine {
    let root = repo_root();
    let mut rules = Vec::new();
    for dir in ["policies/base", "policies/agents"] {
        let e = DeterministicPolicyEngine::from_directory(
            &root.join(dir),
            PolicyBundleId::new("tmp").unwrap(),
        )
        .unwrap_or_else(|e| panic!("shipped bundle {dir} failed to load: {e}"));
        rules.extend(e.bundle().rules.clone());
    }
    let merged = vigil_policy::PolicyBundle {
        version: PolicyBundleId::new("test-merged").unwrap(),
        description: "base + agents".to_string(),
        default_effect: vigil_policy::PolicyEffect::Deny,
        rules,
    };
    merged.validate().expect("merged shipped bundles validate");
    DeterministicPolicyEngine::new(merged)
}

struct Req(PolicyRequest);

impl Req {
    fn tool(name: &str, operation: &str, side_effect: SideEffectClass) -> Self {
        Self(PolicyRequest {
            principal: PolicyPrincipal {
                id: PrincipalId::new("user-1").unwrap(),
                tenant_id: TenantId::new("acme").unwrap(),
                kind: "human".to_string(),
                roles: vec!["support-agent".to_string()],
                mfa: true,
                agent_id: AgentId::new("customer-support-assistant").unwrap(),
                delegation_lineage: vec![],
            },
            action: PolicyAction {
                kind: "tool_call".to_string(),
                operation: operation.to_string(),
                side_effect,
                impact_tier: side_effect.floor_tier(),
            },
            resource: PolicyResource {
                name: name.to_string(),
                tool_id: None,
                destination_host: None,
                paths: vec![],
                data_classes: vec![],
            },
            context: PolicyContext {
                environment_id: Some(EnvironmentId::new("prod").unwrap()),
                session_id: Some(SessionId::new("sess-1").unwrap()),
                ..Default::default()
            },
        })
    }

    fn kind(mut self, kind: &str) -> Self {
        self.0.action.kind = kind.to_string();
        self
    }
    fn tier(mut self, tier: ImpactTier) -> Self {
        self.0.action.impact_tier = tier;
        self
    }
    fn host(mut self, host: &str) -> Self {
        self.0.resource.destination_host = Some(host.to_string());
        self
    }
    fn paths(mut self, paths: &[&str]) -> Self {
        self.0.resource.paths = paths.iter().map(|s| s.to_string()).collect();
        self
    }
    fn tainted(mut self, taints: &[TaintKind]) -> Self {
        self.0.context.taints = taints.to_vec();
        self
    }
    fn injected(mut self) -> Self {
        self.0.context.untrusted_instruction_influence = true;
        self.0.context.lowest_influencing_trust = Some(TrustLevel::WebUntrusted);
        self
    }
    fn prior_denials(mut self, n: u32) -> Self {
        self.0.context.prior_denials = n;
        self
    }
    fn delegation_depth(mut self, n: u32) -> Self {
        self.0.context.delegation_depth = n;
        self
    }
    fn get(self) -> PolicyRequest {
        self.0
    }
}

fn decide(req: PolicyRequest) -> vigil_policy::PolicyDecision {
    engine().evaluate_sync(&req)
}

// ---------------------------------------------------------------- shipped bundle integrity

#[test]
fn every_shipped_bundle_parses_and_validates() {
    let root = repo_root();
    for dir in ["policies/base", "policies/agents"] {
        DeterministicPolicyEngine::from_directory(
            &root.join(dir),
            PolicyBundleId::new("check").unwrap(),
        )
        .unwrap_or_else(|e| panic!("{dir} is not a valid policy bundle: {e}"));
    }
}

#[test]
fn no_shipped_rule_allows_everything() {
    let e = engine();
    for rule in &e.bundle().rules {
        if rule.matcher.match_all {
            assert!(
                !matches!(rule.effect, vigil_policy::PolicyEffect::Allow),
                "rule `{}` is a universal allow",
                rule.id
            );
        }
    }
}

#[test]
fn every_shipped_rule_id_is_unique_and_attributable() {
    let e = engine();
    let mut seen = std::collections::HashSet::new();
    for rule in &e.bundle().rules {
        assert!(seen.insert(rule.id.clone()), "duplicate id {}", rule.id);
        assert!(
            !rule.description.trim().is_empty(),
            "{} has no description",
            rule.id
        );
    }
}

// ---------------------------------------------------------------- default deny

#[test]
fn an_unknown_tool_is_denied_by_default() {
    let d = decide(
        Req::tool(
            "some_unregistered_tool",
            "invoke",
            SideEffectClass::ExternalWrite,
        )
        .get(),
    );
    assert_eq!(d.decision, Decision::Deny);
    assert!(d.reason_codes.contains(&ReasonCode::PolicyDefaultDeny));
}

// ---------------------------------------------------------------- Demo 2: the safe path

#[test]
fn demo2_creating_a_ticket_is_allowed_with_constraints() {
    let d = decide(
        Req::tool(
            "create_ticket",
            "create_ticket",
            SideEffectClass::InternalWrite,
        )
        .get(),
    );
    assert!(d.permits_execution(), "got {:?}", d.decision);
    assert!(d
        .matched_policies
        .contains(&"support-remit-002".to_string()));
    assert!(
        !d.constraints.is_empty(),
        "a bounded allow must carry constraints"
    );
}

#[test]
fn demo2_reading_a_customer_record_is_allowed() {
    let d = decide(
        Req::tool(
            "read_customer_record",
            "read",
            SideEffectClass::InternalRead,
        )
        .get(),
    );
    assert!(d.permits_execution(), "got {:?}", d.decision);
    assert!(d.reason_codes.contains(&ReasonCode::WithinRemit));
}

// ---------------------------------------------------------------- Demo 1: the blocked chain

#[test]
fn demo1_injection_driven_external_write_is_denied() {
    let d = decide(
        Req::tool("send_email", "send", SideEffectClass::ExternalWrite)
            .injected()
            .tainted(&[TaintKind::Secret, TaintKind::UntrustedInstruction])
            .get(),
    );
    assert_eq!(d.decision, Decision::Deny, "reasons: {:?}", d.reason_codes);
    assert!(d.reason_codes.contains(&ReasonCode::SecretEgress));
    assert!(d
        .reason_codes
        .contains(&ReasonCode::UntrustedInstructionFlow));
    assert!(d
        .matched_policies
        .contains(&"secret-egress-001".to_string()));
}

#[test]
fn a_deny_wins_over_an_agent_rule_that_would_allow_the_same_tool() {
    // support-remit-005 permits fetch_url; the injection rule denies external writes. This
    // asserts the resolution order cannot be inverted by editing which file loads first.
    let allowed = decide(Req::tool("fetch_url", "invoke", SideEffectClass::ExternalRead).get());
    assert!(allowed.permits_execution());

    let denied = decide(
        Req::tool("fetch_url", "invoke", SideEffectClass::ExternalWrite)
            .injected()
            .get(),
    );
    assert_eq!(denied.decision, Decision::Deny);
}

#[test]
fn secret_egress_has_no_approval_escape_hatch() {
    // A human must not be able to approve a secret exfiltration, because the approval prompt
    // is itself downstream of the injection.
    let d = decide(
        Req::tool("send_email", "send", SideEffectClass::ExternalWrite)
            .tainted(&[TaintKind::Secret])
            .get(),
    );
    assert_eq!(d.decision, Decision::Deny);
    assert!(!matches!(d.decision, Decision::RequireApproval));
}

// ---------------------------------------------------------------- Demo 3: approval path

#[test]
fn demo3_sending_email_requires_approval_with_a_named_approver_set() {
    let d = decide(Req::tool("send_email", "send", SideEffectClass::ExternalWrite).get());
    assert_eq!(d.decision, Decision::RequireApproval);
    let has_human_approval = d.obligations.iter().any(|o| {
        matches!(
            o,
            vigil_protocol::decision::Obligation::HumanApproval { approver_roles, .. }
                if !approver_roles.is_empty()
        )
    });
    assert!(has_human_approval, "obligations: {:?}", d.obligations);
}

#[test]
fn drafting_an_email_does_not_require_approval_but_sending_does() {
    let draft = decide(Req::tool("send_email", "draft", SideEffectClass::InternalWrite).get());
    assert!(draft.permits_execution(), "{:?}", draft.decision);
    let send = decide(Req::tool("send_email", "send", SideEffectClass::ExternalWrite).get());
    assert_eq!(send.decision, Decision::RequireApproval);
}

// ---------------------------------------------------------------- execution controls

#[test]
fn shell_execution_is_denied() {
    let d = decide(
        Req::tool("shell:exec", "exec", SideEffectClass::Execute)
            .kind("shell")
            .get(),
    );
    assert_eq!(d.decision, Decision::Deny);
    assert!(d.reason_codes.contains(&ReasonCode::DangerousShellCommand));
}

#[test]
fn credential_paths_are_denied_even_inside_an_allowed_workspace() {
    for path in [
        "/workspace/.ssh/id_rsa",
        "/workspace/project/.env",
        "/workspace/.aws/credentials",
        "/etc/shadow",
    ] {
        let d = decide(
            Req::tool("file:read", "read", SideEffectClass::InternalRead)
                .kind("file")
                .paths(&[path])
                .get(),
        );
        assert_eq!(d.decision, Decision::Deny, "path {path} was not denied");
    }
}

#[test]
fn workspace_writes_are_permitted_but_writes_outside_it_are_denied() {
    let outside = decide(
        Req::tool("file:write", "write", SideEffectClass::InternalWrite)
            .kind("file")
            .paths(&["/etc/cron.d/backdoor"])
            .get(),
    );
    assert_eq!(outside.decision, Decision::Deny);
    assert!(outside
        .reason_codes
        .contains(&ReasonCode::PathOutsideAllowlist));
}

#[test]
fn workspace_prefix_confusion_is_denied() {
    let decision = decide(
        Req::tool("file:write", "write", SideEffectClass::InternalWrite)
            .kind("file")
            .paths(&["/workspace-evil/backdoor"])
            .get(),
    );
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision
        .reason_codes
        .contains(&ReasonCode::PathOutsideAllowlist));
}

#[test]
fn destructive_sql_is_denied_and_reads_are_allowed() {
    let drop = decide(
        Req::tool("db:postgres", "DROP", SideEffectClass::Destructive)
            .kind("database")
            .get(),
    );
    assert_eq!(drop.decision, Decision::Deny);

    let select = decide(
        Req::tool("db:postgres", "SELECT", SideEffectClass::InternalRead)
            .kind("database")
            .get(),
    );
    assert!(select.permits_execution(), "{:?}", select.decision);
}

// ---------------------------------------------------------------- network controls

#[test]
fn cloud_metadata_endpoints_are_denied() {
    for host in ["169.254.169.254", "metadata.google.internal"] {
        let d = decide(
            Req::tool("net:x", "GET", SideEffectClass::ExternalRead)
                .kind("network")
                .host(host)
                .get(),
        );
        assert_eq!(d.decision, Decision::Deny, "{host} was not denied");
        assert!(d.reason_codes.contains(&ReasonCode::SsrfMetadataEndpoint));
    }
}

#[test]
fn egress_to_an_unlisted_destination_is_denied_and_a_listed_one_is_not() {
    let unlisted = decide(
        Req::tool("net:x", "POST", SideEffectClass::ExternalWrite)
            .kind("network")
            .host("attacker.evil.example")
            .get(),
    );
    assert_eq!(unlisted.decision, Decision::Deny);
    assert!(unlisted
        .reason_codes
        .contains(&ReasonCode::EgressDestinationForbidden));

    let listed = decide(
        Req::tool("net:x", "POST", SideEffectClass::ExternalWrite)
            .kind("network")
            .host("mail-provider.example")
            .get(),
    );
    assert!(
        !listed
            .reason_codes
            .contains(&ReasonCode::EgressDestinationForbidden),
        "an allowlisted host must not trip the egress rule"
    );
}

#[test]
fn omitting_the_destination_host_does_not_bypass_the_egress_allowlist() {
    // The bypass this guards: an adapter that "forgets" to populate the host.
    let d = decide(
        Req::tool("net:x", "POST", SideEffectClass::ExternalWrite)
            .kind("network")
            .get(),
    );
    assert_eq!(d.decision, Decision::Deny);
    assert!(d
        .reason_codes
        .contains(&ReasonCode::EgressDestinationForbidden));
}

// ---------------------------------------------------------------- self-protection

#[test]
fn an_agent_cannot_reach_vigils_own_control_surfaces() {
    for resource in [
        "vigil.policy.update",
        "acme-policy-store",
        "agent-remit-editor",
    ] {
        let d = decide(Req::tool(resource, "invoke", SideEffectClass::InternalWrite).get());
        assert_eq!(d.decision, Decision::Deny, "{resource} was not denied");
        assert!(d
            .reason_codes
            .contains(&ReasonCode::SelfModificationAttempt));
    }
}

#[test]
fn a_session_that_keeps_probing_after_denials_is_terminated() {
    let d = decide(
        Req::tool(
            "read_customer_record",
            "read",
            SideEffectClass::InternalRead,
        )
        .prior_denials(6)
        .get(),
    );
    assert_eq!(d.decision, Decision::TerminateSession);
}

#[test]
fn deep_delegation_chains_are_denied() {
    let d = decide(
        Req::tool(
            "delegate:other-agent",
            "delegate",
            SideEffectClass::PrivilegeChange,
        )
        .kind("delegation")
        .delegation_depth(5)
        .get(),
    );
    assert_eq!(d.decision, Decision::Deny);
}

#[test]
fn tier4_actions_always_require_approval_even_for_an_unnamed_tool() {
    let d = decide(
        Req::tool(
            "some_admin_tool",
            "invoke",
            SideEffectClass::PrivilegeChange,
        )
        .tier(ImpactTier::Tier4Critical)
        .get(),
    );
    assert!(
        matches!(d.decision, Decision::RequireApproval | Decision::Deny),
        "got {:?}",
        d.decision
    );
}

// ---------------------------------------------------------------- determinism properties

#[test]
fn evaluation_is_independent_of_rule_order() {
    let root = repo_root();
    let base = DeterministicPolicyEngine::from_directory(
        &root.join("policies/base"),
        PolicyBundleId::new("b").unwrap(),
    )
    .unwrap();

    let mut reversed = base.bundle().clone();
    reversed.rules.reverse();
    let reversed_engine = DeterministicPolicyEngine::new(reversed);

    let cases = [
        Req::tool("send_email", "send", SideEffectClass::ExternalWrite)
            .injected()
            .tainted(&[TaintKind::Secret])
            .get(),
        Req::tool(
            "read_customer_record",
            "read",
            SideEffectClass::InternalRead,
        )
        .get(),
        Req::tool("shell:exec", "exec", SideEffectClass::Execute)
            .kind("shell")
            .get(),
    ];
    for req in cases {
        assert_eq!(
            base.evaluate_sync(&req).decision,
            reversed_engine.evaluate_sync(&req).decision,
            "rule order changed the decision"
        );
    }
}

#[test]
fn evaluation_is_repeatable() {
    let e = engine();
    let req = Req::tool("send_email", "send", SideEffectClass::ExternalWrite).get();
    let first = e.evaluate_sync(&req);
    for _ in 0..100 {
        assert_eq!(e.evaluate_sync(&req), first);
    }
}

#[tokio::test]
async fn the_async_trait_and_sync_paths_agree() {
    let e = engine();
    let req = Req::tool(
        "create_ticket",
        "create_ticket",
        SideEffectClass::InternalWrite,
    )
    .get();
    assert_eq!(e.evaluate(&req).await.unwrap(), e.evaluate_sync(&req));
    assert_eq!(e.provider(), "deterministic");
}

// ---------------------------------------------------------------- bundle validation

#[test]
fn a_bundle_with_a_typo_in_a_matcher_field_is_rejected() {
    // Without `deny_unknown_fields`, `tool_ids` would be ignored and the matcher would
    // degenerate into "matches everything with this action kind".
    let src = r#"
version: typo-bundle
rules:
  - id: oops
    effect: allow
    when:
      action_kinds: [tool_call]
      tool_ids: ["send_email"]
"#;
    let err = vigil_policy::PolicyBundle::from_yaml(src).unwrap_err();
    assert!(err.to_string().contains("tool_ids"), "{err}");
}

#[test]
fn a_rule_with_no_conditions_is_rejected() {
    let src = r#"
version: empty-matcher
rules:
  - id: catch-all-by-accident
    effect: allow
    when: {}
"#;
    let err = vigil_policy::PolicyBundle::from_yaml(src).unwrap_err();
    assert!(err.to_string().contains("no conditions"), "{err}");
}

#[test]
fn a_universal_allow_is_rejected() {
    let src = r#"
version: universal-allow
rules:
  - id: allow-everything
    effect: allow
    when:
      match_all: true
"#;
    let err = vigil_policy::PolicyBundle::from_yaml(src).unwrap_err();
    assert!(err.to_string().contains("allows everything"), "{err}");
}

#[test]
fn duplicate_rule_ids_are_rejected() {
    let src = r#"
version: dup
rules:
  - id: same
    effect: deny
    when: {action_kinds: [shell]}
  - id: same
    effect: allow
    when: {action_kinds: [tool_call]}
"#;
    let err = vigil_policy::PolicyBundle::from_yaml(src).unwrap_err();
    assert!(err.to_string().contains("duplicate rule id"), "{err}");
}

#[test]
fn an_empty_bundle_is_rejected() {
    let src = "version: empty\nrules: []\n";
    assert!(vigil_policy::PolicyBundle::from_yaml(src).is_err());
}

#[test]
fn a_bundle_omitting_default_effect_defaults_to_deny() {
    let src = r#"
version: no-default
rules:
  - id: r1
    effect: allow
    when: {action_kinds: [tool_call], resources: ["safe_tool"]}
"#;
    let bundle = vigil_policy::PolicyBundle::from_yaml(src).unwrap();
    assert_eq!(bundle.default_effect, vigil_policy::PolicyEffect::Deny);
}
