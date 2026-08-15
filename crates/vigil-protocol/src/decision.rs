//! Decisions, and the arithmetic that makes Invariant 1 structural.
//!
//! # Why
//!
//! Invariant 1 says deterministic policy always wins: a detector may raise the stakes but
//! may never lower them. Encoding that as a review rule ("remember not to downgrade a DENY")
//! guarantees it will eventually be violated. Encoding it as the *only available operation*
//! makes the violation unwriteable.
//!
//! # What
//!
//! [`Decision`] is totally ordered by restrictiveness, and the sole way to merge two
//! decisions is [`Decision::combine`], which returns the more restrictive of the two. There
//! is deliberately no `set_decision`, no `override_with`, and no path from `Deny` back to
//! `Allow` anywhere in this crate.
//!
//! # Evidence
//!
//! `tests/property/` exhaustively checks that no sequence of combines starting from `Deny`
//! ever yields anything less restrictive, and the red-team suite drives detector outputs
//! that attempt exactly that.

use serde::{Deserialize, Serialize};
use vigil_common::ids::{ApprovalId, PolicyBundleId};
use vigil_common::{ContentHash, Timestamp};

use crate::detector::DetectorResult;
use crate::reason::ReasonCode;

/// What VIGIL decided to do about an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    /// Proceed. A capability is minted.
    Allow,
    /// Proceed, but the capability carries constraints the gateway enforces.
    AllowWithConstraints,
    /// Proceed with specified content redacted before execution.
    AllowWithRedaction,
    /// Do not proceed until a qualified human approves this exact action.
    RequireApproval,
    /// Do not proceed; hold the action and its context for analyst review.
    Quarantine,
    /// Do not proceed.
    Deny,
    /// Do not proceed, and end the session: continuing is itself the risk.
    TerminateSession,
}

impl Decision {
    /// Position on the restrictiveness scale. Higher is more restrictive.
    pub fn restrictiveness(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::AllowWithConstraints => 1,
            Self::AllowWithRedaction => 2,
            Self::RequireApproval => 3,
            Self::Quarantine => 4,
            Self::Deny => 5,
            Self::TerminateSession => 6,
        }
    }

    /// Merge two decisions, keeping the more restrictive.
    ///
    /// This is the only merge operation in VIGIL. Every stage of the pipeline folds its
    /// result in through here, which is why a detector cannot undo a policy `Deny` no
    /// matter what it returns.
    pub fn combine(self, other: Self) -> Self {
        if other.restrictiveness() > self.restrictiveness() {
            other
        } else {
            self
        }
    }

    /// Whether execution may proceed at all.
    pub fn permits_execution(&self) -> bool {
        matches!(
            self,
            Self::Allow | Self::AllowWithConstraints | Self::AllowWithRedaction
        )
    }

    /// Whether a capability should be minted for this decision.
    pub fn mints_capability(&self) -> bool {
        self.permits_execution()
    }

    /// Whether this decision should terminate the whole session, not just the action.
    pub fn terminates_session(&self) -> bool {
        matches!(self, Self::TerminateSession)
    }

    /// The decision to return when a dependency in the enforcement path fails and the
    /// action class is configured to fail closed (Invariant 7).
    pub const fn fail_closed() -> Self {
        Self::Deny
    }
}

/// A restriction attached to a minted capability, enforced at the gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Constraint {
    /// The request may only reach these hosts.
    AllowedHosts { hosts: Vec<String> },
    /// The response body must not exceed this size.
    MaxResponseBytes { bytes: u64 },
    /// The tool call must complete within this budget.
    TimeoutMs { ms: u64 },
    /// Only these argument paths may be present.
    ArgumentAllowlist { paths: Vec<String> },
    /// The capability may be exercised at most this many times (normally 1).
    MaxUses { uses: u32 },
    /// Only these SQL operations are permitted.
    SqlOperations { operations: Vec<String> },
    /// Filesystem access is confined to these roots.
    PathRoots { roots: Vec<String> },
}

/// A rewrite applied to the action before execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactionDirective {
    /// Dotted path into the action's material projection, e.g. `arguments.body`.
    pub path: String,
    /// What was found there.
    pub reason: ReasonCode,
    /// How to handle it.
    pub method: RedactionMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMethod {
    /// Replace with a fixed placeholder.
    Mask,
    /// Replace with a reversible token the broker can re-substitute at execution time.
    Tokenize,
    /// Replace with a non-reversible fingerprint.
    Hash,
    /// Remove the field entirely.
    Drop,
}

/// Something that must happen alongside or before execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Obligation {
    /// A qualified human must approve this exact action hash first.
    HumanApproval {
        /// Roles that may approve. The requester's own principal is always excluded.
        approver_roles: Vec<String>,
        /// How long an approval, once granted, stays valid.
        ttl_seconds: u64,
    },
    /// Credentials must come from the broker, never from the agent's own context.
    BrokeredCredentials { credential_ref: String },
    /// The action must be logged to a specific evidence stream.
    EvidenceCapture { stream: String },
    /// An alert must be raised at this severity.
    Alert { severity: String },
}

/// Where a decision came from, in a form an auditor can reconstruct years later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionProvenance {
    pub policy_bundle_version: Option<PolicyBundleId>,
    pub remit_version: Option<String>,
    /// Identifiers of the rules that matched, in evaluation order.
    #[serde(default)]
    pub matched_policies: Vec<String>,
    /// Which pipeline stage produced the final, most restrictive verdict.
    pub deciding_stage: String,
    /// Versions of every detector consulted, so a historical score is interpretable.
    #[serde(default)]
    pub detector_versions: Vec<(String, String)>,
}

/// The response to an [`crate::ActionRequest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionResponse {
    #[serde(default = "crate::action_schema_version")]
    pub schema_version: String,
    pub decision_id: vigil_common::ids::EventId,
    pub decision: Decision,
    /// Hash of the exact action this decision covers. A client that mutates the action must
    /// obtain a new decision; the gateway recomputes and compares this.
    pub action_hash: ContentHash,
    /// Composite risk in 0.0–1.0.
    pub risk_score: f64,
    /// How much confidence the pipeline has in that score, tracked separately so a
    /// high-risk/low-confidence result can be routed to review rather than auto-blocked.
    pub confidence: f64,
    #[serde(default)]
    pub reason_codes: Vec<ReasonCode>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
    #[serde(default)]
    pub redactions: Vec<RedactionDirective>,
    #[serde(default)]
    pub detector_results: Vec<DetectorResult>,
    pub provenance: DecisionProvenance,
    /// The capability token, present only when the decision permits execution.
    #[serde(default)]
    pub capability: Option<String>,
    /// When approval is required, the identifier the caller polls or presents.
    #[serde(default)]
    pub approval_id: Option<ApprovalId>,
    pub evaluated_at: Timestamp,
    pub latency_ms: u64,
}

impl DecisionResponse {
    /// Whether the caller may execute.
    pub fn permits_execution(&self) -> bool {
        self.decision.permits_execution()
    }

    /// Structural check that the response is internally consistent.
    ///
    /// A `DENY` carrying a capability, or an `ALLOW` with no capability, means a bug in the
    /// pipeline. Callers assert this so that bug surfaces as a loud failure rather than as
    /// an unauthorized execution.
    pub fn is_coherent(&self) -> bool {
        let cap_matches = self.capability.is_some() == self.decision.mints_capability();
        let risk_in_range = (0.0..=1.0).contains(&self.risk_score);
        let confidence_in_range = (0.0..=1.0).contains(&self.confidence);
        let reasons_present = !self.reason_codes.is_empty();
        cap_matches && risk_in_range && confidence_in_range && reasons_present
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Decision; 7] = [
        Decision::Allow,
        Decision::AllowWithConstraints,
        Decision::AllowWithRedaction,
        Decision::RequireApproval,
        Decision::Quarantine,
        Decision::Deny,
        Decision::TerminateSession,
    ];

    #[test]
    fn combine_never_makes_a_decision_less_restrictive() {
        for a in ALL {
            for b in ALL {
                let c = a.combine(b);
                assert!(
                    c.restrictiveness() >= a.restrictiveness()
                        && c.restrictiveness() >= b.restrictiveness(),
                    "{a:?} combined with {b:?} produced {c:?}"
                );
            }
        }
    }

    #[test]
    fn a_deny_cannot_be_argued_back_to_allow_by_any_sequence() {
        // Invariant 1, exhaustively over every ordering of every decision value.
        let mut current = Decision::Deny;
        for _round in 0..3 {
            for d in ALL {
                current = current.combine(d);
                assert!(!current.permits_execution(), "escaped to {current:?}");
            }
        }
    }

    #[test]
    fn combine_is_commutative_and_associative() {
        for a in ALL {
            for b in ALL {
                assert_eq!(a.combine(b), b.combine(a));
                for c in ALL {
                    assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
                }
            }
        }
    }

    #[test]
    fn only_execution_permitting_decisions_mint_capabilities() {
        for d in ALL {
            assert_eq!(d.mints_capability(), d.permits_execution());
        }
        assert!(!Decision::RequireApproval.mints_capability());
        assert!(!Decision::Quarantine.mints_capability());
    }

    #[test]
    fn the_fail_closed_decision_denies() {
        assert_eq!(Decision::fail_closed(), Decision::Deny);
        assert!(!Decision::fail_closed().permits_execution());
    }

    #[test]
    fn decisions_serialize_as_the_documented_wire_strings() {
        assert_eq!(
            serde_json::to_string(&Decision::RequireApproval).unwrap(),
            "\"REQUIRE_APPROVAL\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::TerminateSession).unwrap(),
            "\"TERMINATE_SESSION\""
        );
    }
}
