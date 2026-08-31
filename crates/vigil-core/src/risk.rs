//! The composite risk engine.
//!
//! # Why
//!
//! Spec §22 is explicit: no single weak classifier may determine an outcome. Risk here is a
//! *bounded aggregation* over many independent signals, and it is deliberately not the thing
//! that decides. Policy decides. Risk orders the queue, routes the alert, chooses whether to
//! spend money on a deep detector, and — only within the band policy leaves open — tips a
//! borderline action toward approval.
//!
//! # What
//!
//! Two numbers, tracked separately and never multiplied into one:
//!
//! * **risk** — how bad it would be if this action is what it looks like
//! * **confidence** — how sure the signals are
//!
//! Keeping them separate is what lets a high-risk/low-confidence action route to human review
//! instead of being auto-blocked (which would make VIGIL noisy) or auto-allowed (which would
//! make it useless).
//!
//! # Assumptions
//!
//! Weights are a starting posture, not a claim of calibration. They are versioned
//! ([`RISK_MODEL_VERSION`]) and recorded on every decision so a historical score stays
//! interpretable after they change. The benchmark methodology for tuning them lives in
//! `docs/operations/detection-quality.md`; no accuracy figure is claimed here that the
//! evaluation suite has not produced.

use vigil_protocol::action::ImpactTier;
use vigil_protocol::detector::DetectorResult;
use vigil_protocol::trust::{TaintKind, TrustLevel};

/// Version of the weighting model, recorded on every decision.
pub const RISK_MODEL_VERSION: &str = "composite/1";

/// The signals feeding a risk score.
#[derive(Debug, Clone, Default)]
pub struct RiskInputs {
    pub impact_tier: Option<ImpactTier>,
    /// Whether the operation can be undone.
    pub reversible: bool,
    /// Whether the action crosses the trust boundary outward.
    pub egress: bool,
    /// Least-trusted influence on this action.
    pub lowest_influencing_trust: Option<TrustLevel>,
    /// Whether untrusted instruction-like content steered this action.
    pub untrusted_instruction_influence: bool,
    /// Taints the action carries.
    pub taints: Vec<TaintKind>,
    /// Whether a sensitive value was found flowing in an evasive encoding.
    pub evasive_encoding: bool,
    /// Whether the remit permits this.
    pub out_of_remit: bool,
    /// Prior distinct denials in this session.
    pub prior_distinct_denials: u32,
    /// Whether this exact action was already denied once.
    pub retry_of_denied_action: bool,
    /// Whether a valid approval already covers this action.
    pub approval_satisfied: bool,
    /// Delegation hops behind this request.
    pub delegation_depth: u32,
    /// Results from every detector that ran.
    pub detector_results: Vec<DetectorResult>,
}

/// The computed score.
#[derive(Debug, Clone, PartialEq)]
pub struct RiskAssessment {
    pub risk: f64,
    pub confidence: f64,
    /// Per-signal contributions, for the decision inspector. Ordered by contribution.
    pub contributions: Vec<(String, f64)>,
    pub model_version: &'static str,
}

impl RiskAssessment {
    /// Whether the score is high enough to warrant a human look, within whatever latitude
    /// policy has left. Never consulted when policy already denied.
    pub fn warrants_review(&self) -> bool {
        self.risk >= REVIEW_THRESHOLD
    }

    /// Whether the signals are strong *and* consistent enough to act on automatically.
    pub fn is_confident_high_risk(&self) -> bool {
        self.risk >= HIGH_RISK_THRESHOLD && self.confidence >= CONFIDENT_THRESHOLD
    }
}

/// Risk at or above which an otherwise-permitted action is escalated to approval.
pub const REVIEW_THRESHOLD: f64 = 0.6;
/// Risk at or above which an action is considered high risk.
pub const HIGH_RISK_THRESHOLD: f64 = 0.8;
/// Confidence at or above which automatic action on a high score is appropriate.
pub const CONFIDENT_THRESHOLD: f64 = 0.7;

/// Compute the composite risk.
///
/// The aggregation is **saturating**, not additive: each signal claims a fraction of the
/// remaining headroom toward 1.0. Two consequences, both deliberate:
///
/// * no single signal can reach 1.0 alone, so a misfiring detector cannot dominate
/// * many independent weak signals still accumulate, which is exactly the multi-step attack
///   shape a purely max-based score would miss
pub fn assess(inputs: &RiskInputs) -> RiskAssessment {
    let mut contributions: Vec<(String, f64)> = Vec::new();

    if let Some(tier) = inputs.impact_tier {
        push(&mut contributions, "impact_tier", tier.risk_weight() * 0.6);
    }
    if !inputs.reversible {
        push(&mut contributions, "irreversible_operation", 0.3);
    }
    if inputs.egress {
        push(&mut contributions, "crosses_trust_boundary", 0.25);
    }

    if let Some(trust) = inputs.lowest_influencing_trust {
        if !trust.carries_instruction_authority() {
            // Scaled by how far below the authority line the source sits.
            let distance = (TrustLevel::UserAuthenticated.rank() as f64 - trust.rank() as f64)
                / TrustLevel::UserAuthenticated.rank() as f64;
            push(&mut contributions, "low_trust_influence", 0.35 * distance);
        }
    }
    if inputs.untrusted_instruction_influence {
        push(&mut contributions, "untrusted_instruction_influence", 0.55);
    }

    for taint in &inputs.taints {
        push(
            &mut contributions,
            &format!("taint:{}", taint_label(*taint)),
            taint.risk_weight() * 0.5,
        );
    }
    if inputs.evasive_encoding {
        push(&mut contributions, "evasive_encoding", 0.4);
    }

    if inputs.out_of_remit {
        push(&mut contributions, "out_of_remit", 0.5);
    }
    if inputs.retry_of_denied_action {
        push(&mut contributions, "retry_of_denied_action", 0.45);
    }
    if inputs.prior_distinct_denials > 0 {
        // Probing for a gap escalates faster than a single mistake.
        let scaled = (inputs.prior_distinct_denials as f64 * 0.12).min(0.5);
        push(&mut contributions, "prior_distinct_denials", scaled);
    }
    if inputs.delegation_depth > 0 {
        push(
            &mut contributions,
            "delegation_depth",
            (inputs.delegation_depth as f64 * 0.08).min(0.3),
        );
    }

    for result in &inputs.detector_results {
        let weighted = result.weighted_risk();
        if weighted > 0.0 {
            push(
                &mut contributions,
                &format!("detector:{}", result.detector_id),
                weighted * 0.5,
            );
        }
    }

    // A satisfied approval reduces residual risk but never to zero: the approval covers this
    // exact action, not the possibility that the approver was misled.
    let approval_discount = if inputs.approval_satisfied { 0.4 } else { 0.0 };

    let mut risk = 0.0f64;
    for (_, weight) in &contributions {
        risk += (1.0 - risk) * weight.clamp(0.0, 1.0);
    }
    risk *= 1.0 - approval_discount;

    contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    RiskAssessment {
        risk: round_score(risk.clamp(0.0, 1.0)),
        confidence: round_score(confidence_of(inputs)),
        contributions,
        model_version: RISK_MODEL_VERSION,
    }
}

/// Round a score to four decimal places.
///
/// Two reasons, one cosmetic and one load-bearing.
///
/// A risk score is a weighted aggregation of heuristics; reporting it as
/// `0.9278124999999999` claims seventeen significant digits of precision that the model does
/// not have, and makes two runs that agree to within a rounding error look different in the
/// console.
///
/// The load-bearing reason: scores are serialized into audit events, and audit events are
/// canonicalized and hashed. VCJ/1 refuses to render floats that do not survive a JSON round
/// trip, because a canonical form that is not idempotent cannot be used for signature
/// binding. An unrounded score can land on exactly such a value — which surfaced as a failed
/// audit append, i.e. a failed decision. Four decimals keeps every score in the domain that
/// renders deterministically.
fn round_score(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

/// How much to trust the score.
///
/// Deterministic signals (impact tier, remit, taint from tracked value flow) are facts, so
/// they raise confidence. Probabilistic detector output raises it only in proportion to its
/// own self-reported confidence, and a *degraded* detector lowers it — "we could not check"
/// should make the system less sure, not more.
fn confidence_of(inputs: &RiskInputs) -> f64 {
    let mut confidence: f64 = 0.5;

    if inputs.impact_tier.is_some() {
        confidence += 0.15;
    }
    if inputs.out_of_remit || inputs.untrusted_instruction_influence {
        confidence += 0.15;
    }
    if !inputs.taints.is_empty() {
        confidence += 0.1;
    }

    let degraded = inputs
        .detector_results
        .iter()
        .filter(|r| r.outcome.is_degraded())
        .count();
    let conclusive = inputs
        .detector_results
        .iter()
        .filter(|r| r.outcome.is_conclusive())
        .count();

    if conclusive > 0 {
        let mean: f64 = inputs
            .detector_results
            .iter()
            .filter(|r| r.outcome.is_conclusive())
            .map(|r| r.confidence)
            .sum::<f64>()
            / conclusive as f64;
        confidence += 0.1 * mean;
    }
    confidence -= 0.2 * degraded as f64;

    confidence.clamp(0.0, 1.0)
}

fn push(into: &mut Vec<(String, f64)>, label: &str, weight: f64) {
    if weight > 0.0 {
        into.push((label.to_string(), weight));
    }
}

fn taint_label(taint: TaintKind) -> String {
    serde_json::to_string(&taint)
        .unwrap_or_else(|_| "\"UNKNOWN\"".to_string())
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_protocol::detector::{DetectorId, DetectorOutcome};

    #[test]
    fn a_benign_low_impact_action_scores_near_zero() {
        let a = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier1LowRiskRead),
            reversible: true,
            ..Default::default()
        });
        assert!(a.risk < 0.2, "risk was {}", a.risk);
        assert!(!a.warrants_review());
    }

    #[test]
    fn the_demo1_signal_combination_scores_high_with_high_confidence() {
        let a = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier3HighImpact),
            reversible: false,
            egress: true,
            lowest_influencing_trust: Some(TrustLevel::WebUntrusted),
            untrusted_instruction_influence: true,
            taints: vec![TaintKind::Secret, TaintKind::UntrustedInstruction],
            evasive_encoding: true,
            ..Default::default()
        });
        assert!(a.risk > 0.9, "risk was {}", a.risk);
        assert!(a.is_confident_high_risk());
        assert_eq!(a.contributions[0].0, "untrusted_instruction_influence");
    }

    #[test]
    fn no_single_signal_can_reach_certainty_alone() {
        // A misfiring detector claiming maximum risk must not produce a 1.0 composite.
        // `reversible: true` isolates the detector: the default is `false`, because an action
        // whose reversibility is unknown is treated as irreversible, which would otherwise
        // contribute a second signal to this test.
        let a = assess(&RiskInputs {
            reversible: true,
            detector_results: vec![DetectorResult::completed(
                DetectorId::new("rogue"),
                "1",
                1.0,
                1.0,
            )],
            ..Default::default()
        });
        assert!(a.risk < 0.6, "one detector alone reached {}", a.risk);
        assert!(
            !a.is_confident_high_risk(),
            "a single detector must not be able to trigger automatic action"
        );
    }

    #[test]
    fn unknown_reversibility_is_treated_as_irreversible() {
        // Documents the default: omitting the field makes the score more cautious, not less.
        let unknown = assess(&RiskInputs::default());
        let known_safe = assess(&RiskInputs {
            reversible: true,
            ..Default::default()
        });
        assert!(unknown.risk > known_safe.risk);
    }

    #[test]
    fn many_weak_signals_still_accumulate() {
        // The multi-step attack shape: nothing individually alarming.
        let a = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier2ControlledMutation),
            reversible: true,
            lowest_influencing_trust: Some(TrustLevel::RagUntrusted),
            prior_distinct_denials: 3,
            delegation_depth: 2,
            taints: vec![TaintKind::ExternalUrl],
            ..Default::default()
        });
        assert!(a.risk > 0.5, "risk was {}", a.risk);
    }

    #[test]
    fn risk_is_always_in_range_for_extreme_inputs() {
        let a = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier4Critical),
            reversible: false,
            egress: true,
            lowest_influencing_trust: Some(TrustLevel::ExternalUntrusted),
            untrusted_instruction_influence: true,
            taints: vec![
                TaintKind::Secret,
                TaintKind::Credential,
                TaintKind::Pii,
                TaintKind::FinancialData,
            ],
            evasive_encoding: true,
            out_of_remit: true,
            prior_distinct_denials: 1000,
            retry_of_denied_action: true,
            delegation_depth: 1000,
            approval_satisfied: false,
            detector_results: vec![DetectorResult::completed(
                DetectorId::new("d"),
                "1",
                1.0,
                1.0,
            )],
        });
        assert!((0.0..=1.0).contains(&a.risk));
        assert!((0.0..=1.0).contains(&a.confidence));
    }

    #[test]
    fn a_degraded_detector_lowers_confidence_rather_than_raising_it() {
        let base = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier3HighImpact),
            ..Default::default()
        });
        let degraded = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier3HighImpact),
            detector_results: vec![DetectorResult::degraded(
                DetectorId::new("d"),
                "1",
                DetectorOutcome::TimedOut,
                100,
            )],
            ..Default::default()
        });
        assert!(
            degraded.confidence < base.confidence,
            "{} vs {}",
            degraded.confidence,
            base.confidence
        );
        // But it must still raise risk: an unchecked action is riskier than a checked one.
        assert!(degraded.risk > base.risk);
    }

    #[test]
    fn an_approval_reduces_residual_risk_but_never_to_zero() {
        let inputs = RiskInputs {
            impact_tier: Some(ImpactTier::Tier3HighImpact),
            egress: true,
            taints: vec![TaintKind::Pii],
            ..Default::default()
        };
        let without = assess(&inputs);
        let with = assess(&RiskInputs {
            approval_satisfied: true,
            ..inputs
        });
        assert!(with.risk < without.risk);
        assert!(with.risk > 0.0, "an approval must not zero out risk");
    }

    #[test]
    fn scoring_is_deterministic() {
        let inputs = RiskInputs {
            impact_tier: Some(ImpactTier::Tier3HighImpact),
            taints: vec![TaintKind::Secret, TaintKind::Pii],
            untrusted_instruction_influence: true,
            ..Default::default()
        };
        let first = assess(&inputs);
        for _ in 0..100 {
            assert_eq!(assess(&inputs), first);
        }
    }

    #[test]
    fn contributions_are_ordered_so_the_inspector_shows_the_driver_first() {
        let a = assess(&RiskInputs {
            impact_tier: Some(ImpactTier::Tier1LowRiskRead),
            untrusted_instruction_influence: true,
            ..Default::default()
        });
        assert!(a.contributions.len() >= 2);
        assert!(a.contributions[0].1 >= a.contributions[1].1);
    }
}
