# ADR 0024 — Intent–execution reconciliation, and what an empty result means

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Every other control in `vigil-local` answers one question: *should this request be permitted?*
`ARCHITECTURE.md` has named a second question since the first local slice — *did what happened
match what was asked for?* — and called the subsystem that would answer it the Intent–Execution
Reconciliation Engine. Nothing implemented it.

That question is the reason VIGIL has two enforcement points at all. A semantic broker knows the
tool, the argument, and the intent, but sees only requests routed through it. An OS observer knows
the executable, the file, and the flow, but not why. Neither view alone catches an agent that
declares a benign intent and performs a different operation: the declaration looks fine, and the
operation looks like ordinary process activity.

## Decision

### Reconciliation is a pure function over stored evidence

`reconcile(session, workspace, declared, observed)` takes no database and returns the same
findings in the same order for the same inputs. Declarations are read back from the hash-chained
event log rather than accumulated in memory, so a reconciliation can be run long after a session
ended, against a log whose integrity is independently checkable, and replayed by a reviewer who
was not there.

### Five classes, ordered by what they prove

| Class | What it means |
|---|---|
| `DENIED_OPERATION_OBSERVED` | VIGIL refused it and the OS saw it happen. The broker was **bypassed**. |
| `RESOURCE_MISMATCH` | A resource outside the workspace that was never declared. |
| `UNDECLARED_SIDE_EFFECT` | Declared for reading; observed being modified. |
| `CHILD_PROCESS_MISMATCH` | An execution nothing declared. |
| `SCOPE_EXPANSION` | Extra resources inside the workspace, beyond the declared set. |

The first is categorically different from the rest. Every other class means the semantic layer was
*incomplete* — it did not see something. `DENIED_OPERATION_OBSERVED` means it was *defeated*: the
answer was no, and the operation occurred regardless. It carries weight 80 and quarantines a
session on its own, joining `VIGIL-L003` and `VIGIL-L011` as the third and last rule permitted to
do that. A test pins that list so a fourth cannot be added without deliberation.

Separating scope expansion from resource mismatch is deliberate. An agent reading an extra file in
its own workspace and an agent reading `/etc/passwd` are different events, and collapsing them
would make the severe one unactionable inside the noise of the mild one.

### An operation the OS refused is not a mismatch

Only operations that took effect are reconciled. Counting a *blocked* operation as a divergence
would report the system working correctly as a failure, and would train an operator to ignore the
finding that matters.

### The load-bearing decision: absence of observations is not consistency

This is the one way an engine like this becomes actively harmful. With no installed Endpoint
Security extension, an empty observation set means *nothing was watching* — not *nothing
happened*. A design that reported "0 mismatches — consistent" would hand an operator a green
result manufactured entirely out of blindness.

So `Reconciliation::coverage` distinguishes `Observed` from `NoObserver`, `consistent()` is
**always false** when there was no observer, the CLI prints an explicit `NO OBSERVER` block saying
Endpoint Security is not installed, and `vigil reconcile` exits non-zero in that case. A script
cannot mistake an unwatched session for a clean one without ignoring an exit code.

### Findings are grouped by class, not emitted per instance

A session that touched forty undeclared files produces one detection with forty examples (capped
at 32 in evidence), not forty detections. An alert queue that scales with the size of the incident
is one nobody reads.

## Consequences

Prompt Demo 8 works end to end: a session declares one read of `package.json`, the observer
reports a shell execution, a credential read, a write to the file declared only for reading, and
an extra workspace file — and each is named as its own class with its own explanation.

`ObservedOperation` is deliberately not tied to Endpoint Security; it is the shape an OS observer
reports. Today the producers are `vigil-endpoint`'s deterministic simulator and hand-written
fixtures. When an entitled System Extension exists it becomes a third producer and **nothing in
this engine changes**.

### What this does not do

It does not observe anything. This engine compares two records; producing the second one requires
an installed, signed, entitled System Extension that this build does not have. Until then every
reconciliation on a real session reports `NO_OBSERVER`, which is the honest answer and is
deliberately not a passing one.
