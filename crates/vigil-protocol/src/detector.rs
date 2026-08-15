//! Detector results.
//!
//! # Why
//!
//! Invariant 2: security models are not trusted principals. A detector — whether a regex, a
//! local classifier or a remote LLM — produces *evidence*, not authority. This type is
//! shaped so a detector literally cannot express "allow this": it can raise risk and it can
//! propose escalation, and the pipeline folds that proposal through
//! [`crate::Decision::combine`], which only ever moves toward restriction.
//!
//! # What
//!
//! Every detector returns its id, version, a bounded risk and confidence, machine-readable
//! reason codes, and references to evidence — not copies of the attacker's payload
//! (spec §58).
//!
//! # Failure mode
//!
//! A detector that times out or errors returns [`DetectorOutcome::TimedOut`] or
//! [`DetectorOutcome::Errored`] with a *non-zero* risk floor and the `DETECTOR_DEGRADED`
//! reason code. A failed detector never reads as "found nothing".

use serde::{Deserialize, Serialize};
use vigil_common::ids::ProvenanceNodeId;

use crate::decision::Decision;
use crate::reason::ReasonCode;

/// Stable identifier for a detector, e.g. `injection.heuristic`, `dlp.secrets`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DetectorId(String);

impl DetectorId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DetectorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a detector actually ran to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorOutcome {
    /// The detector ran and its result is meaningful.
    Completed,
    /// The detector exceeded its deadline.
    TimedOut,
    /// The detector failed.
    Errored,
    /// The detector was not applicable to this action, or was gated off by risk routing.
    Skipped,
}

impl DetectorOutcome {
    /// Whether the risk value in this result reflects actual analysis.
    pub fn is_conclusive(&self) -> bool {
        matches!(self, Self::Completed | Self::Skipped)
    }

    /// Whether this outcome indicates a degraded dependency the operator should see.
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::TimedOut | Self::Errored)
    }
}

/// A pointer to stored evidence rather than a copy of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// The provenance node the evidence lives in.
    pub node_id: ProvenanceNodeId,
    /// Where inside that content, as a character range.
    #[serde(default)]
    pub span: Option<(u32, u32)>,
    /// A short, control-character-stripped excerpt for triage. Bounded by the producer.
    #[serde(default)]
    pub excerpt: Option<String>,
}

/// What one detector concluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectorResult {
    pub detector_id: DetectorId,
    /// Version of the detector *and its ruleset*, so a historical score can be reproduced.
    pub detector_version: String,
    pub outcome: DetectorOutcome,
    /// Risk contributed, 0.0–1.0. Clamped on construction.
    pub risk: f64,
    /// How reliable this detector considers its own verdict, 0.0–1.0.
    pub confidence: f64,
    #[serde(default)]
    pub reason_codes: Vec<ReasonCode>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    /// The most restrictive decision this detector believes is warranted.
    ///
    /// A *proposal*. The pipeline combines it, so it can tighten the outcome and can never
    /// loosen it — a compromised or prompt-injected detector returning `Allow` changes
    /// nothing.
    #[serde(default)]
    pub proposed_escalation: Option<Decision>,
    pub duration_ms: u64,
}

impl DetectorResult {
    /// A completed result. Risk and confidence are clamped rather than trusted, because a
    /// detector returning `risk: 1e9` must not be able to dominate the risk engine.
    pub fn completed(
        detector_id: DetectorId,
        detector_version: impl Into<String>,
        risk: f64,
        confidence: f64,
    ) -> Self {
        Self {
            detector_id,
            detector_version: detector_version.into(),
            outcome: DetectorOutcome::Completed,
            risk: clamp_unit(risk),
            confidence: clamp_unit(confidence),
            reason_codes: Vec::new(),
            evidence: Vec::new(),
            proposed_escalation: None,
            duration_ms: 0,
        }
    }

    /// A clean result: the detector ran and found nothing.
    pub fn clean(detector_id: DetectorId, detector_version: impl Into<String>) -> Self {
        Self::completed(detector_id, detector_version, 0.0, 1.0)
    }

    /// A detector that did not produce an answer.
    ///
    /// The risk floor is deliberately non-zero: "we could not check" is not "it is fine".
    /// The pipeline additionally applies the action's fail-closed policy; this floor is what
    /// keeps a degraded detector visible in the risk score even for actions that may proceed.
    pub fn degraded(
        detector_id: DetectorId,
        detector_version: impl Into<String>,
        outcome: DetectorOutcome,
        duration_ms: u64,
    ) -> Self {
        debug_assert!(outcome.is_degraded());
        Self {
            detector_id,
            detector_version: detector_version.into(),
            outcome,
            risk: DEGRADED_RISK_FLOOR,
            confidence: 0.0,
            reason_codes: vec![ReasonCode::DetectorDegraded],
            evidence: Vec::new(),
            proposed_escalation: None,
            duration_ms,
        }
    }

    /// A detector that did not apply to this action.
    pub fn skipped(detector_id: DetectorId, detector_version: impl Into<String>) -> Self {
        Self {
            detector_id,
            detector_version: detector_version.into(),
            outcome: DetectorOutcome::Skipped,
            risk: 0.0,
            confidence: 1.0,
            reason_codes: Vec::new(),
            evidence: Vec::new(),
            proposed_escalation: None,
            duration_ms: 0,
        }
    }

    pub fn with_reasons(mut self, codes: impl IntoIterator<Item = ReasonCode>) -> Self {
        self.reason_codes.extend(codes);
        self
    }

    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = EvidenceRef>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Propose an escalation. Attempts to propose something *less* restrictive than
    /// [`Decision::RequireApproval`] are recorded as no proposal at all: a detector has no
    /// business asking for an allow, and silently accepting such a value would make the
    /// combine step depend on detector goodwill.
    pub fn proposing(mut self, decision: Decision) -> Self {
        self.proposed_escalation = if decision.permits_execution() {
            None
        } else {
            Some(decision)
        };
        self
    }

    pub fn with_duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }

    /// This result's contribution to the composite score: risk weighted by confidence.
    pub fn weighted_risk(&self) -> f64 {
        match self.outcome {
            // A degraded detector contributes its floor at full weight; discounting it by
            // its (zero) confidence would erase the signal that checking failed.
            DetectorOutcome::TimedOut | DetectorOutcome::Errored => self.risk,
            _ => self.risk * self.confidence,
        }
    }
}

/// Risk assigned when a detector could not produce an answer.
pub const DEGRADED_RISK_FLOOR: f64 = 0.35;

fn clamp_unit(v: f64) -> f64 {
    if v.is_nan() {
        // A NaN risk would silently win or lose every comparison depending on operand order.
        return 1.0;
    }
    // Rounded to four decimals for the same reason risk scores are: these values are
    // serialized into audit events, which are canonicalized and hashed, and VCJ/1 refuses
    // floats that do not survive a JSON round trip. Detector confidence is a heuristic
    // weight, so the lost precision is imaginary.
    (v.clamp(0.0, 1.0) * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> DetectorId {
        DetectorId::new("test.detector")
    }

    #[test]
    fn a_detector_cannot_propose_an_allow() {
        let r = DetectorResult::clean(id(), "1").proposing(Decision::Allow);
        assert_eq!(r.proposed_escalation, None);
        let r = DetectorResult::clean(id(), "1").proposing(Decision::AllowWithConstraints);
        assert_eq!(r.proposed_escalation, None);
    }

    #[test]
    fn a_detector_can_propose_restriction() {
        let r = DetectorResult::clean(id(), "1").proposing(Decision::Deny);
        assert_eq!(r.proposed_escalation, Some(Decision::Deny));
    }

    #[test]
    fn out_of_range_and_nan_risks_are_clamped() {
        assert_eq!(DetectorResult::completed(id(), "1", 9.0, 1.0).risk, 1.0);
        assert_eq!(DetectorResult::completed(id(), "1", -3.0, 1.0).risk, 0.0);
        assert_eq!(
            DetectorResult::completed(id(), "1", f64::NAN, 1.0).risk,
            1.0
        );
        assert_eq!(
            DetectorResult::completed(id(), "1", 0.5, f64::NAN).confidence,
            1.0
        );
    }

    #[test]
    fn a_failed_detector_never_reads_as_clean() {
        let r = DetectorResult::degraded(id(), "1", DetectorOutcome::TimedOut, 250);
        assert!(r.risk > 0.0);
        assert!(r.weighted_risk() > 0.0, "zero confidence must not erase it");
        assert!(r.reason_codes.contains(&ReasonCode::DetectorDegraded));
        assert!(!r.outcome.is_conclusive());
    }

    #[test]
    fn a_clean_result_contributes_no_risk() {
        assert_eq!(DetectorResult::clean(id(), "1").weighted_risk(), 0.0);
        assert_eq!(DetectorResult::skipped(id(), "1").weighted_risk(), 0.0);
    }

    #[test]
    fn low_confidence_discounts_a_completed_finding() {
        let r = DetectorResult::completed(id(), "1", 1.0, 0.25);
        assert!((r.weighted_risk() - 0.25).abs() < f64::EPSILON);
    }
}
