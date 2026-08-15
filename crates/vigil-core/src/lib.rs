//! VIGIL Core: the runtime decision engine.
//!
//! # Why
//!
//! Everything else in VIGIL produces evidence or enforces an outcome. This crate is where the
//! outcome is decided, which makes it the component the whole product promise rests on:
//!
//! > No high-impact agent action reaches the real world without passing through an
//! > independently enforceable, attributable, policy-aware VIGIL decision.
//!
//! # What
//!
//! [`VigilCore`] wires the subsystems together and exposes two operations:
//!
//! * [`VigilCore::ingest_content`] — record content entering a session, with its provenance
//! * [`VigilCore::decide`] — evaluate one candidate action
//!
//! # Assumptions
//!
//! Core decides; it does not execute. The separation is the point: Core holds the signing key
//! and no tool credentials, the Gateway holds tool credentials and only public keys. Neither
//! alone can both authorize and perform an action (spec §57).
//!
//! # Failure mode
//!
//! See [`pipeline`] for the per-stage behaviour. In summary: dependency failures resolve
//! against the action's impact tier, with Tier 2 and above failing closed.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod api;
pub mod approval;
pub mod auth;
pub mod config;
pub mod manifest;
pub mod pipeline;
pub mod risk;
pub mod server;
pub mod session;

pub use approval::{ApprovalGrant, ApprovalRequest, ApprovalService, TransactionPreview};
pub use auth::{
    AuthenticatedRequest, Authenticator, CallerKind, CoreAuthenticator, MtlsSpiffeAuthenticator,
    SharedSecretAuthenticator, VerifiedIdentity,
};
pub use config::{CoreConfig, EnforcementMode};
pub use manifest::{ToolManifest, ToolManifestRegistry};
pub use pipeline::{DecisionOutcome, DecisionPipeline};
pub use risk::{RiskAssessment, RiskInputs};
pub use server::{AuthConfig, PeerIdentitySource, ServerConfig};
pub use session::{SessionKey, SessionStore};

use std::sync::Arc;
use vigil_audit::{AuditChain, CheckpointSigner};
use vigil_capability::{CapabilityIssuer, SigningKeyMaterial};
use vigil_common::ids::{ProvenanceNodeId, TenantId};
use vigil_common::{Clock, Result, SystemClock};
use vigil_detect::DetectorRegistry;
use vigil_policy::PolicyEngine;
use vigil_protocol::event::{
    DataClassification, Enforcement, EventType, TaintSummary, VigilSecurityEvent,
};
use vigil_protocol::trust::{TaintKind, TrustLevel};
use vigil_protocol::ActionRequest;
use vigil_remit::RemitRegistry;

/// The assembled runtime.
#[derive(Debug)]
pub struct VigilCore {
    pipeline: DecisionPipeline,
    audit: Arc<AuditChain>,
    sessions: Arc<SessionStore>,
    approvals: Arc<ApprovalService>,
    clock: Arc<dyn Clock>,
}

/// Builder for [`VigilCore`].
///
/// Every security-relevant dependency is injected. There is no hidden default that silently
/// constructs a permissive policy engine or an unsigned capability issuer — a Core that
/// cannot be fully constructed fails to start rather than starting degraded.
pub struct VigilCoreBuilder {
    config: CoreConfig,
    policy: Option<Arc<dyn PolicyEngine>>,
    remits: Arc<RemitRegistry>,
    manifests: Arc<ToolManifestRegistry>,
    detectors: Arc<DetectorRegistry>,
    clock: Arc<dyn Clock>,
    tenant_id: Option<TenantId>,
    audit_sink: Option<Arc<dyn vigil_audit::AuditSink>>,
    capability_seed: Option<[u8; 32]>,
    approval_seed: Option<[u8; 32]>,
    audit_seed: Option<[u8; 32]>,
}

impl VigilCoreBuilder {
    pub fn new() -> Self {
        Self {
            config: CoreConfig::default(),
            policy: None,
            remits: Arc::new(RemitRegistry::new()),
            manifests: Arc::new(ToolManifestRegistry::new()),
            detectors: Arc::new(DetectorRegistry::with_builtins()),
            clock: Arc::new(SystemClock),
            tenant_id: None,
            audit_sink: None,
            capability_seed: None,
            approval_seed: None,
            audit_seed: None,
        }
    }

    pub fn config(mut self, config: CoreConfig) -> Self {
        self.config = config;
        self
    }

    pub fn policy(mut self, policy: Arc<dyn PolicyEngine>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn remits(mut self, remits: RemitRegistry) -> Self {
        self.remits = Arc::new(remits);
        self
    }

    pub fn manifests(mut self, manifests: ToolManifestRegistry) -> Self {
        self.manifests = Arc::new(manifests);
        self
    }

    pub fn detectors(mut self, detectors: DetectorRegistry) -> Self {
        self.detectors = Arc::new(detectors);
        self
    }

    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Persist audit evidence, resuming an existing chain if one is present.
    ///
    /// Without this, the chain lives only in memory: it verifies while the process runs and
    /// vanishes on restart. Worse than vanishing, a restart would begin a *second* chain at
    /// sequence 0, making a legitimate reboot indistinguishable from an attacker truncating
    /// the old one. `FileAuditSink` recovers the head so the chain continues.
    pub fn audit_sink(mut self, sink: Arc<dyn vigil_audit::AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Provide the capability, approval and audit signing seeds.
    ///
    /// Three distinct seeds, deliberately: compromise of the audit key must not let an
    /// attacker mint capabilities, and compromise of the approval key must not let them
    /// forge audit checkpoints.
    pub fn signing_seeds(
        mut self,
        capability: [u8; 32],
        approval: [u8; 32],
        audit: [u8; 32],
    ) -> Self {
        self.capability_seed = Some(capability);
        self.approval_seed = Some(approval);
        self.audit_seed = Some(audit);
        self
    }

    /// Generate ephemeral signing keys. Development and tests only: capabilities and audit
    /// checkpoints do not survive a restart.
    pub fn ephemeral_keys(mut self) -> Self {
        let mut seeds = [[0u8; 32]; 3];
        for seed in seeds.iter_mut() {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed);
        }
        self.capability_seed = Some(seeds[0]);
        self.approval_seed = Some(seeds[1]);
        self.audit_seed = Some(seeds[2]);
        self
    }

    pub fn build(self) -> Result<VigilCore> {
        self.config.validate()?;

        let policy = self.policy.ok_or_else(|| {
            vigil_common::VigilError::Config(
                "no policy engine configured; VIGIL Core will not start without one".to_string(),
            )
        })?;
        let tenant_id = self
            .tenant_id
            .ok_or_else(|| vigil_common::VigilError::Config("no tenant configured".to_string()))?;
        let (capability_seed, approval_seed, audit_seed) =
            match (self.capability_seed, self.approval_seed, self.audit_seed) {
                (Some(c), Some(a), Some(u)) => (c, a, u),
                _ => {
                    return Err(vigil_common::VigilError::Config(
                        "no signing keys configured; call signing_seeds or ephemeral_keys"
                            .to_string(),
                    ))
                }
            };

        let sessions = Arc::new(SessionStore::new());
        let issuer = Arc::new(CapabilityIssuer::new(
            SigningKeyMaterial::from_seed("cap-k1", &capability_seed)?,
            self.clock.clone(),
        ));
        let approvals = Arc::new(ApprovalService::new(
            &approval_seed,
            "approval-k1",
            self.clock.clone(),
        )?);
        let chain = AuditChain::new(
            tenant_id,
            CheckpointSigner::from_seed("audit-k1", &audit_seed)?,
            self.clock.clone(),
        );
        let audit = Arc::new(match self.audit_sink {
            Some(sink) => chain.with_sink(sink)?,
            None => chain,
        });

        let pipeline = DecisionPipeline {
            config: self.config,
            policy,
            remits: self.remits,
            manifests: self.manifests,
            detectors: self.detectors,
            sessions: sessions.clone(),
            issuer,
            approvals: approvals.clone(),
            clock: self.clock.clone(),
        };

        Ok(VigilCore {
            pipeline,
            audit,
            sessions,
            approvals,
            clock: self.clock,
        })
    }
}

impl Default for VigilCoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Content entering a session, with where it came from.
#[derive(Debug, Clone)]
pub struct ContentIngest {
    pub origin: String,
    pub trust: TrustLevel,
    pub content: Option<String>,
    pub taints: Vec<TaintKind>,
    pub derived_from: Vec<ProvenanceNodeId>,
    /// Values to watch as they move through the session (a secret read from a vault).
    pub tracked_values: Vec<String>,
}

impl VigilCore {
    pub fn builder() -> VigilCoreBuilder {
        VigilCoreBuilder::new()
    }

    pub fn sessions(&self) -> &Arc<SessionStore> {
        &self.sessions
    }

    pub fn approvals(&self) -> &Arc<ApprovalService> {
        &self.approvals
    }

    pub fn audit(&self) -> &Arc<AuditChain> {
        &self.audit
    }

    pub fn capability_verifying_key(&self) -> ed25519_dalek_reexport::VerifyingKey {
        self.pipeline.issuer.verifying_key()
    }

    pub fn capability_key_id(&self) -> String {
        self.pipeline.issuer.key_id().to_string()
    }

    /// Record content entering a session.
    ///
    /// Called by the SDK whenever the agent receives anything: a user message, a tool result,
    /// a fetched page, a retrieved document. Content that is never ingested has no
    /// provenance, and actions with no provenance are treated as maximally influenced, so
    /// under-reporting makes VIGIL stricter rather than blind.
    pub fn ingest_content(
        &self,
        key: &SessionKey,
        ingest: ContentIngest,
    ) -> Result<ProvenanceNodeId> {
        let now = self.clock.now();
        let node_id = self.sessions.with_session(key, now, |state| {
            let node_id = state.trace.ingest(
                ingest.origin.clone(),
                ingest.trust,
                ingest.content.as_deref(),
                ingest.taints.iter().copied(),
                &ingest.derived_from,
                now,
            );
            for value in &ingest.tracked_values {
                state.trace.track_value(&node_id, value);
            }
            node_id
        })?;
        Ok(node_id)
    }

    /// Evaluate one action and commit the decision to the audit chain.
    ///
    /// Accepts only an [`AuthenticatedRequest`]. Obtaining one requires an
    /// [`Authenticator`], so there is no way to reach the pipeline without having
    /// established who the caller is.
    pub async fn decide(&self, authenticated: &AuthenticatedRequest) -> Result<DecisionOutcome> {
        let outcome = self.pipeline.decide(authenticated).await?;
        self.record_decision(authenticated.request(), &outcome)?;
        Ok(outcome)
    }

    /// Write the decision event. An unauditable decision is a failed decision: if the chain
    /// cannot accept the record, the caller learns about it rather than the event vanishing.
    fn record_decision(&self, request: &ActionRequest, outcome: &DecisionOutcome) -> Result<()> {
        let event = VigilSecurityEvent {
            schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
            event_id: vigil_common::ids::EventId::new_random(),
            timestamp: outcome.response.evaluated_at,
            event_type: EventType::DecisionRendered,
            trace: request.trace.clone(),
            tenant_id: request.tenant_id.clone(),
            environment_id: request.environment_id.clone(),
            session_id: request.session_id.clone(),
            agent_id: request.agent_id.clone(),
            agent_instance_id: request.agent_instance_id.clone(),
            principal: request.principal.clone(),
            workload_identity: request.workload_identity.clone(),
            source: "core".to_string(),
            trust_level: outcome
                .causal_chain
                .iter()
                .map(|r| r.trust_level)
                .min_by_key(|t| t.rank()),
            provenance: outcome.causal_chain.clone(),
            action: Some(request.action.clone()),
            action_hash: Some(outcome.action_hash.clone()),
            data_classification: DataClassification {
                classes: outcome.taints.iter().map(|t| format!("{t:?}")).collect(),
                crosses_trust_boundary: request.action.intrinsic_side_effect().is_egress(),
                fingerprints: vec![],
            },
            taint: TaintSummary {
                kinds: outcome.taints.clone(),
                chain: outcome.causal_chain.clone(),
                untrusted_instruction_influence: outcome
                    .causal_chain
                    .iter()
                    .any(|r| !r.trust_level.carries_instruction_authority()),
            },
            remit_version: outcome.response.provenance.remit_version.clone(),
            policy_bundle_version: outcome.response.provenance.policy_bundle_version.clone(),
            detector_results: outcome.response.detector_results.clone(),
            decision: Some(outcome.response.decision),
            reason_codes: outcome.response.reason_codes.clone(),
            risk_score: Some(outcome.response.risk_score),
            enforcement: Some(Enforcement {
                // Core decides; it does not execute. Whether the action actually happened is
                // reported later by the Gateway, and conflating the two would let a minted
                // capability read as a completed action.
                executed: false,
                capability_id: None,
                stopped_at_gateway: false,
                obligations_met: vec![],
                error: None,
            }),
            approval_id: outcome.response.approval_id.clone(),
            incident_id: None,
            integrity: None,
            extensions: Default::default(),
        };
        self.audit.append(&event)?;
        Ok(())
    }

    /// End a session, releasing its provenance graph and any tracked secret values.
    pub fn end_session(&self, key: &SessionKey) -> Result<bool> {
        self.sessions.end(key)
    }

    /// Evict sessions past their maximum lifetime. Called periodically by the server.
    pub fn evict_stale_sessions(&self) -> Result<usize> {
        let cutoff = self.clock.now()
            - chrono::Duration::minutes(self.pipeline.config.session_max_lifetime_minutes);
        self.sessions.evict_older_than(cutoff)
    }

    pub fn mode(&self) -> EnforcementMode {
        self.pipeline.config.mode
    }
}

/// Re-export so downstream crates can hold a verifying key without depending on the
/// signature crate directly.
pub mod ed25519_dalek_reexport {
    pub use ed25519_dalek::VerifyingKey;
}
