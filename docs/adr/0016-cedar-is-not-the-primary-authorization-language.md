# ADR 0016 — Cedar is not the primary authorization language

**Status:** Accepted  
**Date:** 2026-08-30

## Context

VIGIL's design brief specifies Cedar as the primary deterministic authorization policy language,
"unless implementation research establishes a material incompatibility", and requires an ADR if it
is replaced. This record is that ADR.

What the repository actually has is `DeterministicPolicyEngine` (`crates/vigil-policy`), a
set-based rules engine reached through the `PolicyEngine` trait. Two earlier decisions already
constrain what any policy language may do here:

- **ADR 0002** makes `Decision` totally ordered by restrictiveness, with `combine` — the only merge
  — returning the more restrictive of two decisions. There is deliberately no `set_decision` and no
  override; a detector result cannot express an allow.
- **ADR 0004** makes a bundle an unordered *set*. Every matching rule folds through `combine`, the
  default effect is `deny`, and adding a rule can therefore only ever restrict. Approver sets
  intersect and the shortest TTL wins.

ADR 0005 already anticipated Cedar as a *second* provider behind the same trait, not as a
replacement.

## Decision

Keep `DeterministicPolicyEngine` as the primary authorization engine. Do not adopt Cedar now.

Cedar remains a documented, unimplemented future `PolicyEngine` provider. If it is added, its
permits must feed into the existing `Decision::combine` fold, where a forbid from any source still
dominates.

## Consequences

The reasoning, so that a future reader can disagree with it on the merits:

**Cedar's evaluation model would have to be wrapped regardless.** Cedar answers `Allow`/`Deny` for
one request against one policy set. VIGIL's authorization is a fold across a remit verdict, budget
state, detector results, risk state, and the policy bundle, in which any participant may restrict
and none may permit unilaterally. A Cedar decision would enter that fold as one more input that can
only restrict. That is exactly the position the deterministic engine already occupies, so the
substitution buys no new security property — it changes the syntax rules are written in, not what
the system can conclude.

**The properties we depend on are ours, not Cedar's.** Order independence, forbid dominance, the
rejection of `match_all + allow`, the intersection of approver sets, and the linear-time
non-regex glob matcher are all enforced by `PolicyBundle::validate` and exercised by
`policy_behaviour`. Cedar has its own analogous guarantees, but adopting them means re-deriving our
validation rules in a foreign model and re-earning confidence in 30 shipped rules across 6 bundles
that are currently covered by behavioural tests.

**The cost lands on the security core.** Cedar is a substantial dependency in the crate that makes
every authorization decision. VIGIL's own threat model names supply-chain compromise of a
dependency as threat T4. That is not a veto — the trade is worth making for a real capability — but
it is not worth making for equivalent expressiveness.

**What we give up.** Cedar brings a well-specified schema language, a validator, and analysis
tooling that can answer questions about a policy set without executing it. VIGIL's engine has a
narrower matcher vocabulary and no such analyzer. If policy authoring grows beyond what the current
matcher fields express, or if third parties need to reason about VIGIL policy with external tools,
that is the trigger to revisit this decision — and the `PolicyEngine` trait exists so that revisit
is an addition rather than a rewrite.

**This ADR does not apply to `vigil-local`.** The local macOS profiles (`crates/vigil-local/src/policy.rs`)
are a separate, compiled-in evaluator that does not go through `PolicyEngine` at all. Making local
profiles data-driven is an open question and is not settled here.
