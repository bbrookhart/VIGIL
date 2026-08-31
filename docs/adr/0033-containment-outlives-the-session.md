# ADR 0033 — Containment outlives the session

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Risk, budgets, capability leases, and denial history are all per-session. That is the right
scoping — a session is a bounded task, and a new task should get a fresh budget.

It also made containment escapable in the most obvious way available. A quarantined session's
agent could run `vigil session start` on the same workspace and immediately have `NORMAL` risk, a
full budget, no denial history, and unrestricted write authority. Measured directly before this
change: session A quarantined, session B on the same workspace `NORMAL` and writing freely.

Containment that lasts until the next command is not containment.

## Decision

A session created on a workspace where another session reached `CONTAINED` or `QUARANTINED` within
the last hour starts at `ELEVATED`, with `VIGIL-L034` recorded naming the prior session.

### Elevated, not contained

Inheriting full containment would let one bad session render a workspace unusable for an hour.
That is a denial of service against the *user*, not a control on the agent, and a control that
punishes the wrong party gets switched off.

`ELEVATED` means workspace mutations need a scoped human approval while reads still work. The
agent can continue investigating and reading; it cannot quietly resume changing things. A human is
in the loop for exactly the operations that have consequences.

### Scoped to the workspace, not the machine

An unrelated workspace is unaffected. The signal is "something went wrong *here*", and widening it
to every session on the host would make one incident a global penalty.

An agent can of course start a session on a different workspace — but then it does not have access
to the files it wanted, so it gains nothing for the workspace it was contained on.

### An hour

Long enough that restarting immediately gains nothing; short enough that a workspace is not marked
for the rest of the day by a single incident. The finding is `MEDIUM`/`HIGH` at weight 10, which is
below the elevation threshold: the authority consequence is carried by the inherited standing, not
by the detection's weight. Starting a session after an incident is also what a person does when
they are trying to get work done, and the operator should get to see which it was.

## Consequences

The adversarial harness quarantines a session, starts a new one on the same workspace, and asserts
it does not start `NORMAL`, that a write is refused pending approval, that a read still succeeds,
and that an unrelated workspace is untouched.

### What this does not close

The underlying gap is that an agent running as the user can start sessions at all — which is
invariant 3, which needs `vigild` and authenticated IPC. This does not fix that and does not claim
to. What it removes is the *free* reset: shedding containment now costs a human approval for every
mutation, and leaves a record naming the session it came from.

A determined agent can still wait an hour, or work in a different workspace. Both are visible in
the evidence, and neither is the one-command escape that existed before.
