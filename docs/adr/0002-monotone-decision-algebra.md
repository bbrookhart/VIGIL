# ADR 0002 — Decisions form a monotone algebra

**Status:** Accepted
**Date:** 2026-08-14

## Context

Invariant 1 says deterministic policy always wins: a detector may raise the stakes but never
lower them. Invariant 2 says security models are not trusted principals.

Both are usually implemented as review conventions — "remember not to downgrade a DENY" —
which means they hold until the first person who forgets. Worse, an LLM-based detector sees
attacker-controlled input by definition, so "the detector returned allow" is a value an
attacker can sometimes cause.

## Decision

`Decision` is totally ordered by restrictiveness, and the **only** operation that merges two
decisions returns the more restrictive one:

```rust
pub fn combine(self, other: Self) -> Self {
    if other.restrictiveness() > self.restrictiveness() { other } else { self }
}
```

There is no `set_decision`, no `override_with`, and no path from `Deny` back to `Allow`
anywhere in the crate. Every pipeline stage folds through `combine`.

`DetectorResult` reinforces this from the other side: it has no field capable of expressing
an allow. Its `proposing()` constructor silently discards any permissive value, so a detector
returning `Decision::Allow` contributes nothing rather than something harmful.

## Consequences

**Good.** The invariant is unwriteable-around rather than merely documented. `combine` is
commutative, associative and monotone, which has a second payoff: **stage order cannot change
an outcome**. That is what let the pipeline reorder provenance analysis before policy
evaluation (so policy can match on taint) without weakening the guarantee — a freedom a
convention-based implementation would not have had.

Proved by exhaustive test over every pair and triple of decision values, plus a test that
starts from `Deny` and applies every value repeatedly, asserting it never escapes.

**Cost.** A legitimate "this is actually fine, allow it" override is impossible by
construction. Exceptions must be expressed as policy rules that participate in evaluation,
not as post-hoc overrides. This is more work for operators and is the correct trade: a
mechanism that can turn a denial into an allow is exactly the mechanism an attacker wants.

## Alternatives rejected

**Priority/precedence fields.** Reintroduces the problem — whoever sets the highest priority
wins, and priority is data.

**Separate "advisory" and "binding" channels.** Two channels means two code paths, and the
bug is always in the one nobody tested.
