//! Property tests for the invariants the security model rests on.
//!
//! The existing unit tests prove these by example — every pair and triple of decision values,
//! a handful of trust combinations. That is enough to catch a regression but not enough to
//! state the property. These generate arbitrary inputs and assert the algebraic laws, so a
//! future refactor that satisfies the examples but breaks the law still fails.

use proptest::prelude::*;
use vigil_protocol::decision::Decision;
use vigil_protocol::trust::TrustLevel;

const DECISIONS: [Decision; 7] = [
    Decision::Allow,
    Decision::AllowWithConstraints,
    Decision::AllowWithRedaction,
    Decision::RequireApproval,
    Decision::Quarantine,
    Decision::Deny,
    Decision::TerminateSession,
];

const TRUST_LEVELS: [TrustLevel; 14] = [
    TrustLevel::SystemTrusted,
    TrustLevel::AdminTrusted,
    TrustLevel::ToolSigned,
    TrustLevel::MemoryValidated,
    TrustLevel::UserAuthenticated,
    TrustLevel::UserUntrusted,
    TrustLevel::ToolUnverified,
    TrustLevel::MemoryUntrusted,
    TrustLevel::AgentUntrusted,
    TrustLevel::McpUntrusted,
    TrustLevel::RagUntrusted,
    TrustLevel::EmailUntrusted,
    TrustLevel::WebUntrusted,
    TrustLevel::ExternalUntrusted,
];

fn any_decision() -> impl Strategy<Value = Decision> {
    prop::sample::select(DECISIONS.as_slice())
}

fn any_trust() -> impl Strategy<Value = TrustLevel> {
    prop::sample::select(TRUST_LEVELS.as_slice())
}

proptest! {
    /// Invariant 1, stated as a law rather than a table.
    ///
    /// Folding *any* sequence of decisions can only move toward restriction. This is what
    /// makes pipeline stage order irrelevant to the outcome, which in turn is what allowed
    /// provenance analysis to move ahead of policy evaluation without weakening anything.
    #[test]
    fn combine_is_monotone_over_arbitrary_sequences(
        start in any_decision(),
        sequence in prop::collection::vec(any_decision(), 0..40),
    ) {
        let mut current = start;
        for next in sequence {
            let combined = current.combine(next);
            prop_assert!(
                combined.restrictiveness() >= current.restrictiveness(),
                "combining {current:?} with {next:?} produced the less restrictive {combined:?}"
            );
            current = combined;
        }
        prop_assert!(current.restrictiveness() >= start.restrictiveness());
    }

    /// Once denied, never permitted — regardless of what a detector proposes afterwards.
    #[test]
    fn a_denial_survives_any_subsequent_sequence(
        sequence in prop::collection::vec(any_decision(), 0..40),
    ) {
        let mut current = Decision::Deny;
        for next in sequence {
            current = current.combine(next);
            prop_assert!(!current.permits_execution(), "escaped to {current:?}");
        }
    }

    /// Order cannot change an outcome, so a merge conflict or a directory listing cannot
    /// either.
    #[test]
    fn combine_is_commutative(a in any_decision(), b in any_decision()) {
        prop_assert_eq!(a.combine(b), b.combine(a));
    }

    #[test]
    fn combine_is_associative(a in any_decision(), b in any_decision(), c in any_decision()) {
        prop_assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
    }

    #[test]
    fn combine_is_idempotent(a in any_decision()) {
        prop_assert_eq!(a.combine(a), a);
    }

    /// Allow is the identity: combining with it never changes anything. If this ever fails,
    /// some decision has been given a lower restrictiveness than Allow.
    #[test]
    fn allow_is_the_identity_element(a in any_decision()) {
        prop_assert_eq!(a.combine(Decision::Allow), a);
    }

    /// A capability is only ever minted for a decision that permits execution.
    #[test]
    fn capabilities_are_minted_exactly_when_execution_is_permitted(a in any_decision()) {
        prop_assert_eq!(a.mints_capability(), a.permits_execution());
    }

    // ------------------------------------------------------------------ trust

    /// Invariant 4, as a law: trust only ever flows downward.
    #[test]
    fn combining_trust_never_raises_it(a in any_trust(), b in any_trust()) {
        let combined = a.combine(b);
        prop_assert!(combined.rank() <= a.rank());
        prop_assert!(combined.rank() <= b.rank());
    }

    /// The combination is exactly the minimum — not merely bounded by it.
    #[test]
    fn combining_trust_yields_the_minimum(a in any_trust(), b in any_trust()) {
        let expected = if a.rank() <= b.rank() { a } else { b };
        prop_assert_eq!(a.combine(b), expected);
    }

    #[test]
    fn trust_combination_is_commutative_and_associative(
        a in any_trust(), b in any_trust(), c in any_trust(),
    ) {
        prop_assert_eq!(a.combine(b), b.combine(a));
        prop_assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
    }

    /// No sequence of combinations can produce content that may command the agent unless
    /// every input already could. This is the property that stops a model laundering an
    /// untrusted web page into an authoritative instruction.
    #[test]
    fn authority_cannot_be_manufactured_by_combination(
        levels in prop::collection::vec(any_trust(), 1..20),
    ) {
        let combined = levels.iter().copied().reduce(TrustLevel::combine)
            .expect("non-empty by construction");
        if combined.carries_instruction_authority() {
            prop_assert!(
                levels.iter().all(|l| l.carries_instruction_authority()),
                "a combination gained authority no input had"
            );
        }
    }

    /// The conservative default is a lower bound on every label.
    #[test]
    fn the_conservative_default_is_the_floor(level in any_trust()) {
        prop_assert!(TrustLevel::conservative_default().rank() <= level.rank());
    }
}
