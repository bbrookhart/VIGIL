//! The seam where a profile decision meets the session that made the request.
//!
//! Brokers ask one question here and get back everything that follows from it: the decision
//! after risk and leases have had their say, the lease that was spent if one was, the
//! approval request that was raised if the answer was "ask a human", and the risk signal that
//! a detection-bearing denial loaded.
//!
//! Keeping this in one place is deliberate. Three brokers each re-deriving "consult risk,
//! then try a lease, then maybe raise an approval" is three chances to get the order wrong,
//! and the order is what makes the whole thing sound.

use crate::approval::{ApprovalOutcome, CapabilityAsk};
use crate::detection::{rule_for_label, Severity};
use crate::lease::CapabilityLease;
use crate::{
    evaluate, DecisionOutcome, LeaseStatus, LocalAction, LocalDecision, LocalProfile, LocalStore,
    RiskState,
};
use std::path::Path;
use vigil_common::Result;

/// Everything that happened while answering one authorization question.
#[derive(Debug)]
pub struct LocalAuthorization {
    pub decision: LocalDecision,
    /// The lease that was spent, if spending one is what produced an `ALLOW`.
    pub lease: Option<CapabilityLease>,
    /// The approval raised, if the answer was `REQUIRE_APPROVAL`.
    pub approval: Option<ApprovalOutcome>,
    /// The session's risk state after any signal this request loaded.
    pub risk_state: RiskState,
}

impl LocalAuthorization {
    pub fn permits_execution(&self) -> bool {
        self.decision.permits_execution()
    }
}

/// Record a detection for a decision that named one, and load the risk it implies.
///
/// Only decisions that already carry a detection label produce a detection. A routine denial —
/// a path outside the workspace, a typo — is not evidence of anything and must not creep a
/// session toward containment.
///
/// Weights live in the rule catalogue so severity, confidence, and risk contribution are
/// stated together in one place rather than drifting apart across modules.
fn fire_detection(
    store: &LocalStore,
    session_id: &str,
    decision: &LocalDecision,
) -> Result<Option<RiskState>> {
    let Some(label) = decision.detection.as_deref() else {
        return Ok(None);
    };
    let Some(rule) = rule_for_label(label) else {
        return Ok(None);
    };
    let detection = store.record_detection(
        session_id,
        rule,
        // Metadata only. The resolved resource is a path VIGIL already decided about; no file
        // content, argument value, or secret material reaches an evidence record.
        serde_json::json!({
            "action": decision.action,
            "resolved_resource": decision.resolved_resource,
            "determining_policy": decision.determining_policy,
            "label": label,
        }),
        None,
    )?;
    let risk_state = store.record_risk_signal(
        session_id,
        rule.dimension,
        rule.weight,
        None,
        rule.description,
    )?;
    // A critical detection, or a session that has just been contained, is an incident.
    if rule.severity >= Severity::Critical || risk_state.revokes_leases() {
        let incident = store.open_incident(
            session_id,
            rule.severity,
            &format!("{} ({})", rule.name, detection.detection_id),
        )?;
        store.attach_detections(&incident.incident_id, session_id)?;
    }
    Ok(Some(risk_state))
}

impl LocalStore {
    /// Authorize one path-bearing capability for a session.
    pub fn authorize_local(
        &self,
        session_id: &str,
        profile: LocalProfile,
        workspace: &Path,
        action: LocalAction,
        requested_resource: &str,
    ) -> Result<LocalAuthorization> {
        let base = evaluate(profile, workspace, action, requested_resource);
        self.authorize_decision(session_id, action, requested_resource, base, |decision| {
            decision.resolved_resource.clone()
        })
    }

    /// Apply session state to a decision produced by a specialised evaluator.
    ///
    /// The process and network brokers reach their base decision through their own evaluators
    /// — an executable identity check, a destination preflight — and then join the same path
    /// here. `resource_key` extracts the value a lease and an approval bind to, which is the
    /// resolved path for a file, the canonical executable for a process, and the validated
    /// `host:port` for a destination.
    pub fn authorize_decision(
        &self,
        session_id: &str,
        action: LocalAction,
        requested_resource: &str,
        base: LocalDecision,
        resource_key: impl FnOnce(&LocalDecision) -> Option<String>,
    ) -> Result<LocalAuthorization> {
        // Monotone time: an expired lease must stay expired even if the system clock moves
        // backwards. A material regression is reported against this session.
        let now = self.observe_now_reporting(session_id)?.now;
        let risk = self.session_risk_state(session_id)?;
        let key = resource_key(&base);

        // Spend a lease only when spending it changes the answer. Establish the ceiling risk
        // would allow *if* a lease existed; if that ceiling is not `ALLOW`, the lease would be
        // burned for a request that gets refused anyway, so it is left alone.
        let lease = match (&key, base.outcome) {
            (Some(key), DecisionOutcome::RequireApproval)
                if apply(&base, action, risk, LeaseStatus::Present).outcome
                    == DecisionOutcome::Allow =>
            {
                self.consume_lease(session_id, action, key, now)?
            }
            _ => None,
        };
        let lease_status = if lease.is_some() {
            LeaseStatus::Present
        } else {
            LeaseStatus::Absent
        };

        let decision = apply(&base, action, risk, lease_status);

        // Touching bait is information regardless of whether policy permitted it: a canary is
        // inside the workspace, so an ordinary read of one is *allowed* and is exactly the
        // event worth knowing about. Checking only denials would miss every canary hit.
        let mut risk_state = risk;
        if let Some(key) = &key {
            if let Some(canary) = self.canary_at(session_id, key)? {
                if let Some(rule) = rule_for_label(crate::canary::DETECTION_CANARY_ACCESS) {
                    self.record_detection(
                        session_id,
                        rule,
                        serde_json::json!({
                            "canary_id": canary.canary_id,
                            "kind": canary.kind.as_str(),
                            "path": canary.path,
                            "action": decision.action,
                            "outcome": decision.outcome,
                        }),
                        None,
                    )?;
                    risk_state = self.record_risk_signal(
                        session_id,
                        rule.dimension,
                        rule.weight,
                        None,
                        rule.description,
                    )?;
                    if risk_state.revokes_leases() {
                        let incident = self.open_incident(
                            session_id,
                            rule.severity,
                            &format!("{} ({})", rule.name, canary.canary_id),
                        )?;
                        self.attach_detections(&incident.incident_id, session_id)?;
                    }
                }
            }
        }

        // A denial that named a detection is evidence. A denial that named none is routine.
        if decision.outcome == DecisionOutcome::Deny {
            if let Some(after) = fire_detection(self, session_id, &decision)? {
                risk_state = after;
            }
        }

        // Only `REQUIRE_APPROVAL` is approvable. A `DENY` is never routed to a human, because
        // an approval that could overturn a denial would be exactly the path from Deny to
        // Allow that the decision algebra exists to forbid.
        let approval = match (&key, decision.outcome) {
            (Some(key), DecisionOutcome::RequireApproval) => Some(self.request_approval(
                &CapabilityAsk {
                    session_id,
                    action,
                    requested_resource,
                    resolved_resource: key,
                    determining_policy: &decision.determining_policy,
                    reason: &decision.reason,
                },
                now,
            )?),
            _ => None,
        };
        // Asking again for something already refused loads risk, so take the state the
        // request itself produced rather than the one read before it.
        if let Some(ApprovalOutcome::PreviouslyDenied {
            risk_state: after, ..
        }) = &approval
        {
            risk_state = *after;
        }

        Ok(LocalAuthorization {
            decision,
            lease,
            approval,
            risk_state,
        })
    }
}

/// Re-run the lease and degradation steps against a base decision.
///
/// `evaluate_in_context` re-derives the base ladder from scratch, which the specialised
/// evaluators cannot do. This applies the same two steps, in the same order, to a base
/// decision that is already in hand.
fn apply(
    base: &LocalDecision,
    action: LocalAction,
    risk: RiskState,
    lease: LeaseStatus,
) -> LocalDecision {
    crate::policy::apply_session_state(base.clone(), action, risk, lease)
}
