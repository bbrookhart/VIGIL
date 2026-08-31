# ADR 0012 — Treat Endpoint policy expiry as a runtime lease

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Verifying expiry only when a snapshot is installed lets an extension continue authorizing from
stale state indefinitely after `vigild` stops refreshing policy. Clearing all state at expiry
would be unsafe because attribution distinguishes managed agents from unrelated host processes,
and a control-plane outage must not become a machine-wide denial of service.

## Decision

Carry the signed snapshot's exclusive expiry into immutable native fast-path state. Before every
authorization for an attributed process, read the local wall clock using bounded public Darwin
APIs. Deny when the clock is unavailable or the expiry has been reached. Refuse new root
attribution under an expired lease and report control health as unready while retaining the
installed generation for diagnosis.

Continue processing fork/exit notifications for attribution cleanup. Continue allowing untracked
processes because VIGIL has no policy principal to constrain for them; surface attribution loss as
degraded health instead of treating the entire host as managed.

## Consequences

A daemon outage has a bounded authorization lifetime for already attributed agents. Expiry checks
remain constant-time and perform no IPC, filesystem, database, allocation-heavy, or network work
inside the Endpoint Security callback. Wall-clock rollback resistance is not yet provided; signed
generation persistence, protected clock/boot continuity state, and listener heartbeat lifecycle
remain production work.

Entitlement-free native checks cover the exclusive boundary, clock failure, expired root binding,
health degradation, and the unmanaged-host exception.
