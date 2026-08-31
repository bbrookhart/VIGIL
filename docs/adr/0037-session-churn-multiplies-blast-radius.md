# ADR 0037 — Session churn multiplies blast radius

**Status:** Accepted  
**Date:** 2026-08-30

## Context

ADR 0033 closed the containment escape: a new session on a recently contained workspace no longer
starts clean. The same shape has a quieter variant that it did not close.

Blast-radius budgets are per-session. An agent that never trips a detection at all can exhaust its
budget, start a new session, and continue. Measured directly: three sessions on one workspace
performed **75 writes against a 25-write limit**, with each session ending merely `ELEVATED` from
budget exhaustion and nothing connecting them.

The per-session model is not the bug. §13 scopes budgets to a task, and a new task legitimately
gets a new budget. The bug is that nothing noticed the pattern that abuses it.

## Decision

Five or more sessions on one workspace inside ten minutes records `VIGIL-L035` and raises the new
session to `ELEVATED`.

### The evidence carries what was spent

The abstract fact that several sessions exist is not actionable. The finding sums the consumed
budget across those sessions per dimension, so an operator reads "five sessions, 120 file writes"
rather than "five sessions". That is the difference between a number and a reason.

### Weight 20, confidence medium

Weight 20 elevates on its own, because the pattern it names is specifically an attempt to obtain
more authority than one session is allowed. It is not weighted higher because a person iterating on
a hard problem also starts sessions — and the cumulative consumption in the evidence is what lets
an operator tell the two apart.

### Thresholds

Five in ten minutes sits well above ordinary iteration and well below what farming requires. Both
are constants with the reasoning beside them rather than configuration, because a tunable threshold
on a control like this is a tunable way to disable it.

## Consequences

Three controls now apply when a session is created, and they compose deliberately: containment
inheritance (ADR 0033) catches restarting after an incident, churn detection catches restarting
*without* one, and per-session budgets still bound each individual task. None of them changes the
per-task model.

### What this does not do

It does not bound cumulative blast radius. An agent that waits eleven minutes between sessions, or
spreads work across workspaces, still accumulates unbounded total effect — it just does so slowly
and visibly. Making budgets workspace-cumulative would bound it, and would also mean a developer's
second task of the morning inherits the first one's spend, which is the wrong trade.

The underlying gap remains the one ADR 0033 names: an agent running as the user can start sessions
at all. That is invariant 3 and it needs `vigild`.
