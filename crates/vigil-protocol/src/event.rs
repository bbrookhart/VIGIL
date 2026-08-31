//! The canonical security event.
//!
//! # Why
//!
//! Invariant 9: every enforcement decision must be attributable. Reconstructing "why did
//! VIGIL allow this in March" requires the principal, agent, policy, remit, detector
//! versions, action, provenance, approval and result — all of it, in one record, in a form
//! whose meaning has not drifted. That is this type.
//!
//! # What
//!
//! One envelope for every event class. Class-specific detail hangs off optional sub-objects
//! rather than living in separate top-level schemas, so a query for "everything in session X"
//! is one scan and not a join across ten shapes.
//!
//! # Assumptions
//!
//! Events are append-only and hash-chained by `vigil-audit`. This type carries the
//! [`IntegrityEnvelope`] that chain populates; it does not itself guarantee anything about
//! tampering.

use serde::{Deserialize, Serialize};
use vigil_common::ids::{
    AgentId, AgentInstanceId, ApprovalId, CapabilityId, EnvironmentId, EventId, IncidentId,
    PolicyBundleId, SessionId, TenantId,
};
use vigil_common::{ContentHash, Timestamp};

use crate::action::Action;
use crate::decision::{Decision, Obligation};
use crate::detector::DetectorResult;
use crate::principal::{Principal, TraceContext, WorkloadIdentity};
use crate::reason::ReasonCode;
use crate::trust::{ProvenanceRef, TaintKind, TrustLevel};

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// A session began.
    SessionStart,
    /// A session ended, normally or by termination.
    SessionEnd,
    /// Content entered the session with a provenance label.
    ContentIngested,
    /// A model was invoked.
    ModelInvocation,
    /// An action was submitted for a decision.
    ActionRequested,
    /// VIGIL reached a decision.
    DecisionRendered,
    /// A capability was minted.
    CapabilityIssued,
    /// A capability was presented at the gateway.
    CapabilityPresented,
    /// A capability was rejected at the gateway.
    CapabilityRejected,
    /// A protected tool actually executed.
    ActionExecuted,
    /// A protected tool returned, and the result was inspected.
    ActionResultObserved,
    /// A human approval was requested.
    ApprovalRequested,
    /// A human approval was granted.
    ApprovalGranted,
    /// A human approval was denied or expired.
    ApprovalRejected,
    /// Memory was written.
    MemoryWritten,
    /// Work was delegated to another agent.
    DelegationRequested,
    /// A budget threshold was crossed.
    BudgetEvent,
    /// An administrative mutation occurred in the control plane.
    AdminMutation,
    /// A detector or correlation raised a security finding.
    SecurityFinding,
    /// A VIGIL component reported degraded operation.
    ComponentDegraded,
}

impl EventType {
    /// Whether this event class is required to be retained for the full audit period,
    /// regardless of sampling configuration.
    ///
    /// Sampling a decision away would create gaps an attacker could hide in, so enforcement
    /// and identity events are never sampled; high-volume observational events may be.
    pub fn is_audit_mandatory(&self) -> bool {
        matches!(
            self,
            Self::DecisionRendered
                | Self::CapabilityIssued
                | Self::CapabilityRejected
                | Self::ActionExecuted
                | Self::ApprovalRequested
                | Self::ApprovalGranted
                | Self::ApprovalRejected
                | Self::AdminMutation
                | Self::SessionEnd
                | Self::ComponentDegraded
        )
    }
}

/// Data-classification summary for an event.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DataClassification {
    /// Classes observed in this action's content.
    #[serde(default)]
    pub classes: Vec<String>,
    /// Whether any classified data would cross the trust boundary.
    #[serde(default)]
    pub crosses_trust_boundary: bool,
    /// Fingerprints (never values) of sensitive items, so an analyst can correlate.
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

/// Taint summary for an event.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaintSummary {
    #[serde(default)]
    pub kinds: Vec<TaintKind>,
    /// Provenance nodes that contributed taint, oldest first — the causal chain.
    #[serde(default)]
    pub chain: Vec<ProvenanceRef>,
    /// Whether untrusted instruction content is among the influences.
    #[serde(default)]
    pub untrusted_instruction_influence: bool,
}

/// The enforcement outcome, as distinct from the decision.
///
/// A decision is what VIGIL concluded; enforcement is what actually happened. They can
/// differ — a capability can be minted and then never presented — and conflating them hides
/// exactly the failures an operator most needs to see.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enforcement {
    /// Whether the protected side effect actually occurred.
    pub executed: bool,
    /// The capability involved, if any.
    #[serde(default)]
    pub capability_id: Option<CapabilityId>,
    /// Whether the gateway, rather than Core, was the component that stopped it.
    #[serde(default)]
    pub stopped_at_gateway: bool,
    /// Obligations that were discharged.
    #[serde(default)]
    pub obligations_met: Vec<Obligation>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Tamper-evidence fields populated by `vigil-audit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrityEnvelope {
    /// Position in the per-tenant chain. Gaps mean missing events.
    pub sequence: u64,
    /// Hash of this event's canonical bytes.
    pub event_hash: ContentHash,
    /// Hash of the previous event in the chain, linking the log together.
    pub previous_hash: Option<ContentHash>,
    /// Signature over the most recent checkpoint covering this event, if one exists yet.
    #[serde(default)]
    pub checkpoint_signature: Option<String>,
}

/// The canonical VIGIL security event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VigilSecurityEvent {
    #[serde(default = "crate::action_schema_version")]
    pub schema_version: String,
    pub event_id: EventId,
    pub timestamp: Timestamp,
    pub event_type: EventType,

    #[serde(default)]
    pub trace: TraceContext,

    pub tenant_id: TenantId,
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub agent_instance_id: AgentInstanceId,
    pub principal: Principal,
    #[serde(default)]
    pub workload_identity: Option<WorkloadIdentity>,

    /// Which component emitted this: `sdk.python`, `core`, `gateway`, `control`.
    pub source: String,
    /// Trust label of the content this event concerns.
    #[serde(default)]
    pub trust_level: Option<TrustLevel>,
    #[serde(default)]
    pub provenance: Vec<ProvenanceRef>,

    /// The normalized action, for events that concern one.
    #[serde(default)]
    pub action: Option<Action>,
    /// Hash of the action, present whenever `action` is.
    #[serde(default)]
    pub action_hash: Option<ContentHash>,

    #[serde(default)]
    pub data_classification: DataClassification,
    #[serde(default)]
    pub taint: TaintSummary,

    #[serde(default)]
    pub remit_version: Option<String>,
    #[serde(default)]
    pub policy_bundle_version: Option<PolicyBundleId>,

    #[serde(default)]
    pub detector_results: Vec<DetectorResult>,
    #[serde(default)]
    pub decision: Option<Decision>,
    #[serde(default)]
    pub reason_codes: Vec<ReasonCode>,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
    #[serde(default)]
    pub approval_id: Option<ApprovalId>,
    #[serde(default)]
    pub incident_id: Option<IncidentId>,

    /// Populated by the audit chain when the event is committed.
    #[serde(default)]
    pub integrity: Option<IntegrityEnvelope>,

    /// Fields written by a newer producer than this reader understands.
    ///
    /// Captured rather than dropped so a rolling upgrade cannot silently destroy evidence,
    /// and so the audit hash — computed over the whole event — still verifies.
    #[serde(flatten, default)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl VigilSecurityEvent {
    /// The bytes the audit chain hashes.
    ///
    /// Excludes the integrity envelope itself, since that contains the hash being computed.
    pub fn integrity_payload(&self) -> vigil_common::Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("integrity");
        }
        Ok(value)
    }

    /// Hash of this event's content, excluding the chain fields.
    pub fn content_hash(&self) -> vigil_common::Result<ContentHash> {
        ContentHash::canonical_json(&self.integrity_payload()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::PrincipalKind;
    use std::str::FromStr;

    fn event() -> VigilSecurityEvent {
        VigilSecurityEvent {
            schema_version: crate::SCHEMA_VERSION.to_string(),
            event_id: EventId::from_str("e-1").unwrap(),
            timestamp: {
                use vigil_common::Clock as _;
                vigil_common::FixedClock::at_epoch().now()
            },
            event_type: EventType::DecisionRendered,
            trace: TraceContext::default(),
            tenant_id: TenantId::from_str("acme").unwrap(),
            environment_id: EnvironmentId::from_str("prod").unwrap(),
            session_id: SessionId::from_str("s-1").unwrap(),
            agent_id: AgentId::from_str("support").unwrap(),
            agent_instance_id: AgentInstanceId::from_str("i-1").unwrap(),
            principal: Principal::new(
                vigil_common::ids::PrincipalId::from_str("u-1").unwrap(),
                PrincipalKind::Human,
                TenantId::from_str("acme").unwrap(),
            ),
            workload_identity: None,
            source: "core".to_string(),
            trust_level: None,
            provenance: vec![],
            action: None,
            action_hash: None,
            data_classification: DataClassification::default(),
            taint: TaintSummary::default(),
            remit_version: None,
            policy_bundle_version: None,
            detector_results: vec![],
            decision: Some(Decision::Deny),
            reason_codes: vec![ReasonCode::SecretEgress],
            risk_score: Some(0.97),
            enforcement: None,
            approval_id: None,
            incident_id: None,
            integrity: None,
            extensions: serde_json::Map::new(),
        }
    }

    #[test]
    fn enforcement_events_are_never_sampled_away() {
        assert!(EventType::DecisionRendered.is_audit_mandatory());
        assert!(EventType::ActionExecuted.is_audit_mandatory());
        assert!(EventType::AdminMutation.is_audit_mandatory());
        assert!(!EventType::ModelInvocation.is_audit_mandatory());
    }

    #[test]
    fn content_hash_excludes_the_integrity_envelope() {
        let mut e = event();
        let h1 = e.content_hash().unwrap();
        e.integrity = Some(IntegrityEnvelope {
            sequence: 7,
            event_hash: h1.clone(),
            previous_hash: None,
            checkpoint_signature: None,
        });
        assert!(e.content_hash().unwrap().ct_eq(&h1));
    }

    #[test]
    fn content_hash_changes_when_the_decision_changes() {
        let e1 = event();
        let mut e2 = event();
        e2.decision = Some(Decision::Allow);
        assert!(!e1
            .content_hash()
            .unwrap()
            .ct_eq(&e2.content_hash().unwrap()));
    }

    #[test]
    fn unknown_fields_from_a_newer_producer_survive_a_round_trip() {
        let mut raw = serde_json::to_value(event()).unwrap();
        if let Some(o) = raw.as_object_mut() {
            o.insert("future_field".into(), serde_json::json!({"a": 1}));
        }
        let parsed: VigilSecurityEvent = serde_json::from_value(raw.clone()).unwrap();
        assert!(parsed.extensions.contains_key("future_field"));
        let reserialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(reserialized.get("future_field"), raw.get("future_field"));
    }
}
