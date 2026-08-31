# ADR 0023 — Native Endpoint health is bounded and non-authoritative

**Status:** Accepted  
**Date:** 2026-08-30

## Context

The portable simulator measures authorization latency, deadline denials, and sequence gaps, while
the real Endpoint Security callback previously exposed none of them. That made an installed client
unable to report whether it was nearing authorization deadlines, failing to submit responses, or
losing kernel events. Logging every callback would add I/O and unbounded work to the path whose
latency must be controlled.

Telemetry must also never become authorization input. A counter reset, scrape failure, or health
consumer outage cannot safely change whether an OS operation is permitted.

## Decision

`NativeAuthorizationMetrics` holds a fixed set of saturating counters, seven preallocated per-event
sequence slots, and maximum/minimum timing observations behind one short critical section. Callback
recording performs no logging, I/O, JSON encoding, collection growth, or IPC. Mach ticks are
converted to nanoseconds only when the control path takes a snapshot.

The native source records authorization and notification counts, allow/deny results, deadline-guard
denials, responses completed at or after their deadline, malformed denials, Endpoint Security
response failures, global and per-event sequence gaps, sequence regressions, maximum authorization
latency, and minimum deadline headroom. Global sequence gaps supply the aggregate dropped-event
count when version 4 fields exist; per-event gaps are diagnostic and are not added a second time.

The callback checks its deadline both before projection and after deterministic policy evaluation.
If evaluation consumes the safety margin, a prospective allow is replaced with a denial before the
response. The result returned by `es_respond_*` is counted rather than discarded.

The control protocol's authenticated `health` reply includes one `authorization_metrics` object.
The production composition must pass the control service's accumulator into
`MacOSEndpointSecuritySource`; the source initializer intentionally has no independent default.
Metrics are process-lifetime health signals, not durable audit evidence and not policy inputs.

## Consequences

Operators and `vigild` can distinguish an idle healthy client from deadline pressure, late or
failed responses, and event loss without adding callback logging. Counters saturate rather than
wrapping. They reset when the extension process restarts, so durable incident evidence must consume
and separately record health snapshots. An entitled-device test is still required to characterize
real callback latency and alert thresholds under load.
