# ADR 0004 — Order-independent policy evaluation

**Status:** Accepted
**Date:** 2026-08-14

## Context

Most policy engines evaluate rules in order and stop at the first match. That makes the
outcome depend on file order, which means a merge conflict, a directory listing on a
different filesystem, or an innocuous reordering can silently change what is permitted.

For a system whose decisions must be reproducible years later in an incident review, that is
disqualifying.

## Decision

A policy bundle is an unordered **set**. Evaluation matches every rule, then folds the matched
effects through `Decision::combine`, which is commutative and associative.

Consequences that follow directly:

- rule order in a file is irrelevant
- adding a rule can only make the system more restrictive, never less
- an operator cannot shadow a `deny` with an earlier `allow`
- merging bundles from `base/`, `tools/`, `agents/` and `tenants/` is a set union

The default effect is `deny`. A bundle wanting anything else must say so in a reviewed file.

Validation rejects the ways a well-meaning author disables enforcement by accident:

| Rejected | Because |
|---|---|
| unknown matcher fields (`deny_unknown_fields`) | `tool_ids:` instead of `tools:` would match everything |
| a rule with no conditions | an empty matcher is a universal rule |
| `match_all: true` with `effect: allow` | a universal allow disables enforcement |
| duplicate rule ids | decisions must be attributable to one rule |
| `*` as a host pattern | reads as "anywhere"; never what an operator means |

Matching is linear-time by construction — `*`/`?` globbing with a two-pointer algorithm, no
regex. A policy author's typo cannot become an availability incident through catastrophic
backtracking.

## Consequences

**Good.** Decisions are reproducible, attributable and safe to merge. Tested by evaluating
the shipped bundles, reversing rule order, and asserting identical outcomes.

**Cost.** "Allow this one exception to a broad deny" cannot be expressed by placing a rule
earlier. It must be expressed by narrowing the deny. This is more work and produces policy
that says what it means.

**Interaction discovered in testing.** When several rules each require approval, taking the
first rule's approver list would reintroduce order-dependence through the back door. The
pipeline instead **intersects** the approver sets and takes the shortest TTL. If the
intersection is empty, that is a policy authoring error and is raised loudly rather than
producing an approval request nobody can grant — which is how the shipped bundles were found
to be incoherent and fixed.

## Alternatives rejected

**Cedar / OPA as the only engine.** Both are supported through the `PolicyEngine` trait, and
VIGIL Core depends only on the trait. Neither is required, because the built-in engine needs
no external process on the synchronous enforcement path.

**First-match-wins with explicit priorities.** Priority is data, and whoever sets the highest
number wins.
