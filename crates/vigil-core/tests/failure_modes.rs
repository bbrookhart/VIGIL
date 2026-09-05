//! Failure-injection tests for the documented fail-closed matrix.
//!
//! `docs/architecture/README.md` contains a table stating what happens when each dependency
//! fails, split by impact tier. Until now that table was prose: nothing checked that the code
//! agreed with it. A fail-closed guarantee nobody exercises is a guess.
//!
//! Each test drives one dependency into failure through the trait seam it already has —
//! `PolicyEngine`, `SemanticDetector`, `NonceStore`, `AuditSink` — and asserts the documented
//! behaviour. Policy outages deny reads as well as mutations: impact is not authority.

use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vigil_common::ids::*;
use vigil_common::{Clock, FixedClock, Result, VigilError};
use vigil_core::{AuthenticatedRequest, CoreConfig, ToolManifestRegistry, VigilCore};
use vigil_detect::{DetectionContext, DetectorRegistry, SemanticDetector};
use vigil_policy::{DeterministicPolicyEngine, PolicyDecision, PolicyEngine, PolicyRequest};
use vigil_protocol::action::*;
use vigil_protocol::detector::{DetectorId, DetectorOutcome, DetectorResult};
use vigil_protocol::principal::{Principal, PrincipalKind};
use vigil_protocol::reason::ReasonCode;
use vigil_protocol::ActionRequest;
use vigil_remit::RemitRegistry;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("workspace root")
}

fn shipped_policy() -> DeterministicPolicyEngine {
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
    DeterministicPolicyEngine::new(vigil_policy::PolicyBundle {
        version: PolicyBundleId::new("failure-tests").expect("id"),
        description: "shipped rules".to_string(),
        default_effect: vigil_policy::PolicyEffect::Deny,
        rules,
    })
}

/// Build a Core with specific dependencies replaced by failing ones.
fn core_with(policy: Arc<dyn PolicyEngine>, detectors: DetectorRegistry) -> Arc<VigilCore> {
    let root = repo_root();
    Arc::new(
        VigilCore::builder()
            .config(CoreConfig::development())
            .policy(policy)
            .remits(RemitRegistry::load_directory(&root.join("policies/remits")).expect("remits"))
            .manifests(
                ToolManifestRegistry::load_file(&root.join("policies/tools/manifests.yaml"))
                    .expect("manifests"),
            )
            .detectors(detectors)
            .clock(Arc::new(FixedClock::at_epoch()))
            .tenant(TenantId::new("acme").expect("id"))
            .ephemeral_keys()
            .build()
            .expect("core builds"),
    )
}

fn request(action: Action) -> AuthenticatedRequest {
    AuthenticatedRequest::for_trusted_in_process_caller(ActionRequest {
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
        workload_identity: None,
        trace: Default::default(),
        action,
        context: Default::default(),
    })
}

fn tool(name: &str, operation: &str) -> Action {
    Action::ToolCall(ToolCall {
        protocol: ToolProtocol::Native,
        server: None,
        tool_id: ToolId::new(name).expect("id"),
        name: name.to_string(),
        version: None,
        operation: Some(operation.to_string()),
        arguments: serde_json::json!({"customer_id": "C-1"}),
        target_resource: None,
        declared_side_effect: None,
    })
}

/// A Tier 1 read: `read_customer_record` is `internal_read` in the shipped manifest.
fn low_impact_read() -> AuthenticatedRequest {
    request(tool("read_customer_record", "read"))
}

/// A Tier 3 external write: `send_email` leaves the trust boundary.
fn high_impact_write() -> AuthenticatedRequest {
    request(tool("send_email", "send"))
}

// ---------------------------------------------------------------- policy engine outage

#[derive(Debug)]
struct UnavailablePolicyEngine;

#[async_trait]
impl PolicyEngine for UnavailablePolicyEngine {
    async fn evaluate(&self, _request: &PolicyRequest) -> Result<PolicyDecision> {
        Err(VigilError::Unavailable {
            component: "policy",
            reason: "simulated outage".to_string(),
        })
    }
    fn bundle_version(&self) -> PolicyBundleId {
        PolicyBundleId::new("unavailable").expect("id")
    }
    fn provider(&self) -> &'static str {
        "unavailable"
    }
}

#[tokio::test]
async fn policy_outage_fails_closed_for_a_high_impact_action() {
    let core = core_with(
        Arc::new(UnavailablePolicyEngine),
        DetectorRegistry::with_builtins(),
    );
    let outcome = core.decide(&high_impact_write()).await.expect("decision");

    assert!(
        !outcome.response.permits_execution(),
        "a policy outage must not permit an external write, got {:?}",
        outcome.response.decision
    );
    assert!(outcome.response.capability.is_none());
    let reasons = &outcome.response.reason_codes;
    assert!(
        reasons.contains(&ReasonCode::PolicyEngineUnavailable),
        "{reasons:?}"
    );
    assert!(reasons.contains(&ReasonCode::FailClosed), "{reasons:?}");
}

#[tokio::test]
async fn policy_outage_denies_low_impact_reads_without_minting_authority() {
    let core = core_with(
        Arc::new(UnavailablePolicyEngine),
        DetectorRegistry::with_builtins(),
    );
    // A customer-record read has low impact classification but can disclose private data.
    let outcome = core.decide(&low_impact_read()).await.expect("decision");
    assert!(!outcome.response.permits_execution());
    assert!(outcome.response.capability.is_none());
    let reasons = &outcome.response.reason_codes;
    assert!(reasons.contains(&ReasonCode::PolicyEngineUnavailable));
    assert!(reasons.contains(&ReasonCode::FailClosed));
    assert!(!reasons.contains(&ReasonCode::DegradedModeAllow));
}

// ---------------------------------------------------------------- detector failure

#[derive(Debug)]
struct HangingDetector {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SemanticDetector for HangingDetector {
    fn id(&self) -> DetectorId {
        DetectorId::new("test.hanging")
    }
    fn version(&self) -> String {
        "1".to_string()
    }
    fn deadline(&self) -> Duration {
        Duration::from_millis(5)
    }
    async fn analyze(&self, _context: &DetectionContext) -> Result<DetectorResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(DetectorResult::clean(self.id(), "1"))
    }
}

#[derive(Debug)]
struct ErroringDetector;

#[async_trait]
impl SemanticDetector for ErroringDetector {
    fn id(&self) -> DetectorId {
        DetectorId::new("test.erroring")
    }
    fn version(&self) -> String {
        "1".to_string()
    }
    async fn analyze(&self, _context: &DetectionContext) -> Result<DetectorResult> {
        Err(VigilError::Detector {
            detector: "test.erroring".to_string(),
            reason: "simulated failure".to_string(),
        })
    }
}

#[tokio::test]
async fn a_hanging_detector_is_cut_off_and_the_decision_still_returns() {
    // An agent blocked forever on VIGIL is an availability incident that operators resolve
    // by removing VIGIL, so the deadline is a security control too.
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = DetectorRegistry::new().register(Arc::new(HangingDetector {
        calls: calls.clone(),
    }));
    let core = core_with(Arc::new(shipped_policy()), registry);

    let outcome = tokio::time::timeout(Duration::from_secs(5), core.decide(&low_impact_read()))
        .await
        .expect("the decision must not hang")
        .expect("decision");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the detector should have run"
    );
    let result = outcome
        .response
        .detector_results
        .iter()
        .find(|r| r.detector_id.as_str() == "test.hanging")
        .expect("the timed-out detector is still reported");
    assert_eq!(result.outcome, DetectorOutcome::TimedOut);
    assert!(result.risk > 0.0, "a timeout must not read as clean");
}

#[tokio::test]
async fn a_failed_detector_lowers_confidence_and_is_recorded() {
    let registry = DetectorRegistry::new().register(Arc::new(ErroringDetector));
    let core = core_with(Arc::new(shipped_policy()), registry);
    let outcome = core.decide(&low_impact_read()).await.expect("decision");

    let result = outcome
        .response
        .detector_results
        .iter()
        .find(|r| r.detector_id.as_str() == "test.erroring")
        .expect("the failed detector is reported");
    assert_eq!(result.outcome, DetectorOutcome::Errored);
    assert!(result.reason_codes.contains(&ReasonCode::DetectorDegraded));
    // The error text may embed attacker-influenced content and must not propagate.
    assert!(!format!("{result:?}").contains("simulated failure"));
}

#[tokio::test]
async fn a_broken_detector_cannot_turn_a_denial_into_an_allow() {
    // Invariant 1 under failure conditions: whatever a detector does or fails to do, a
    // deterministic denial stands.
    let registry = DetectorRegistry::new()
        .register(Arc::new(ErroringDetector))
        .register(Arc::new(HangingDetector {
            calls: Arc::new(AtomicUsize::new(0)),
        }));
    let core = core_with(Arc::new(shipped_policy()), registry);

    // Shell execution is denied outright by `shell-execution-001`.
    let outcome = core
        .decide(&request(Action::Shell(ShellExecution {
            command: "rm -rf /".to_string(),
            argv: vec![],
            cwd: None,
            uses_shell: true,
        })))
        .await
        .expect("decision");

    assert!(!outcome.response.permits_execution());
    assert!(outcome.response.capability.is_none());
}

// ---------------------------------------------------------------- audit failure

#[tokio::test]
async fn an_unwritable_audit_chain_fails_the_decision() {
    // A system that keeps enforcing while silently losing its evidence is worse than one
    // that stops. `vigil-audit` proves the append fails; this proves Core propagates it
    // rather than swallowing it and returning a decision nobody can later account for.
    use vigil_audit::{AuditEntry, AuditSink, Checkpoint};

    #[derive(Debug)]
    struct BrokenSink;
    impl AuditSink for BrokenSink {
        fn append(&self, _entry: &AuditEntry) -> Result<()> {
            Err(VigilError::Io("simulated disk failure".to_string()))
        }
        fn append_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<()> {
            Ok(())
        }
        fn load(&self) -> Result<(Vec<AuditEntry>, Vec<Checkpoint>)> {
            Ok((Vec::new(), Vec::new()))
        }
    }

    let root = repo_root();
    let core = VigilCore::builder()
        .config(CoreConfig::development())
        .policy(Arc::new(shipped_policy()))
        .remits(RemitRegistry::load_directory(&root.join("policies/remits")).expect("remits"))
        .manifests(
            ToolManifestRegistry::load_file(&root.join("policies/tools/manifests.yaml"))
                .expect("manifests"),
        )
        .clock(Arc::new(FixedClock::at_epoch()))
        .tenant(TenantId::new("acme").expect("id"))
        .ephemeral_keys()
        .audit_sink(Arc::new(BrokenSink))
        .build()
        .expect("core builds");

    let error = core
        .decide(&low_impact_read())
        .await
        .expect_err("an unauditable decision must fail");
    assert!(
        matches!(error, VigilError::Io(_) | VigilError::AuditIntegrity(_)),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------- combined degradation

#[tokio::test]
async fn simultaneous_policy_and_detector_failure_still_fails_closed() {
    // Chaos rarely arrives one dependency at a time.
    let registry = DetectorRegistry::new().register(Arc::new(ErroringDetector));
    let core = core_with(Arc::new(UnavailablePolicyEngine), registry);

    let outcome = core.decide(&high_impact_write()).await.expect("decision");
    assert!(
        !outcome.response.permits_execution(),
        "got {:?} because {:?}",
        outcome.response.decision,
        outcome.response.reason_codes
    );
    assert!(
        outcome.response.confidence < 1.0,
        "a degraded detector must reduce confidence, got {}",
        outcome.response.confidence
    );
}

#[tokio::test]
async fn the_decision_record_is_coherent_even_when_everything_is_failing() {
    // A malformed response under stress would hide the failure from whatever consumes it.
    let registry = DetectorRegistry::new().register(Arc::new(ErroringDetector));
    let core = core_with(Arc::new(UnavailablePolicyEngine), registry);

    for candidate in [low_impact_read(), high_impact_write()] {
        let outcome = core.decide(&candidate).await.expect("decision");
        assert!(
            outcome.response.is_coherent(),
            "incoherent response: {:?}",
            outcome.response
        );
        assert!(
            !outcome.response.reason_codes.is_empty(),
            "a decision with no reason is not auditable"
        );
    }
}
