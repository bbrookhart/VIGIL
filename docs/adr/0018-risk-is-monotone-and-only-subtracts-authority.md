# ADR 0018 — Risk is monotone and only subtracts authority

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Invariant 9 says risk may remove capabilities without the agent's consent. Locally it did nothing:
`policy::evaluate` was a pure function of `(profile, workspace, action, resource)`, and the
`risk_state` column on a session was written but never read back into a decision. A session that
had just been caught reaching for `~/.ssh` retained exactly the authority it started with.

Adding risk to the decision introduces two ways to get it wrong. Risk could accidentally *grant*
something, and a lease issued before things went wrong could keep working after.

## Decision

### Risk is a vector, and the aggregate is a documented threshold function

Twelve dimensions (`crates/vigil-local/src/risk.rs`), each loaded by named signals carrying a
weight, a note, and their source. The aggregate state is derived by a rule small enough to state in
full:

- any dimension ≥ 80 → `QUARANTINED`
- any ≥ 60, or two ≥ 40 → `CONTAINED`
- any ≥ 40, or three ≥ 20 → `RESTRICTED`
- any ≥ 20 → `ELEVATED`
- otherwise `NORMAL`

Scores are **not** summed across dimensions. One dimension going far is treated as worse than
several moving slightly, because a session doing one alarming thing repeatedly is a clearer signal
than a session doing many ordinary things. There is no model here that cannot be explained, and
`vigil risk <session>` prints the dimensions behind the state.

### Only detection-bearing denials load risk

A denial that named a detection is evidence. A denial that named none — a path outside the
workspace, a typo — is routine, and must not creep a session toward containment. The discriminator
is the `detection` label the policy ladder already sets.

### Risk is monotone within a session

The state never decreases. This costs something real: a session that trips one signal stays
degraded until it ends, and a false positive cannot be walked back without starting a new session.
It is taken because the alternative — any mechanism that lowers risk — is a mechanism an agent has
an incentive to trigger, and this codebase already treats monotonicity as the property that makes
ordering irrelevant (ADR 0002, ADR 0004).

### Evaluation order, which is load-bearing

1. the profile ladder, unchanged;
2. the **lease upgrade**, which may raise `REQUIRE_APPROVAL` to `ALLOW` and may never touch a
   `DENY`;
3. **risk degradation**, which is purely subtractive.

Degradation running last is what makes a lease issued before containment worthless afterwards.
Reaching a containing state *also* revokes the session's leases outright, in the same transaction
that records the transition — but the ordering means correctness does not depend on that revocation
having happened yet.

The ladder itself:

| State | Effect |
|---|---|
| `ELEVATED` | workspace mutation needs approval; secret use and metadata denied |
| `RESTRICTED` | only reads survive; leases are **not** revoked |
| `CONTAINED` | only reads survive; outstanding leases revoked |
| `QUARANTINED` | everything denied; outstanding leases revoked |

`RESTRICTED` and `CONTAINED` coincide in what they permit — a read outside the workspace was
already denied by the ladder — and differ in whether they revoke.

### The observe profile is exempt

The observe profile's contract is that it does not enforce. Degrading it would silently turn it into
a profile that does, so an `OBSERVE` outcome passes through untouched at every risk state.

## Consequences

Two exhaustive tests carry this ADR rather than sampled cases: over every action, resource shape and
lease state, raising risk never relaxes an outcome, and holding a lease never restricts one. Both
enumerate the full cross-product rather than a chosen handful, because "risk accidentally granted
something" is the failure a sampled test is most likely to miss.

Prompt Demo 2 and the credential-access chain now work: a first protected-credential attempt
elevates, a second restricts, a third contains and revokes leases, a fourth quarantines — with a
recorded transition and a named signal at each step.

`RiskState` gained `Contained` and `Quarantined`. Existing stored values still parse; the enum is
ordered by declaration so `Normal < Elevated < Restricted < Contained < Quarantined`.

### What this does not do

Nothing here terminates a process, blocks a network flow at the OS, or stops a process that bypasses
the brokers. Degradation withholds authority from *brokered* requests. Containment of an already
running process needs the process-tree termination that the provenance graph is a prerequisite for,
and real containment needs the entitled half of the product.
