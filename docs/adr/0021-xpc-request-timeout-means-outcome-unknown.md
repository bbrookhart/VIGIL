# ADR 0021 — An XPC request timeout means the outcome is unknown

**Status:** Accepted  
**Date:** 2026-08-30

## Context

ADR 0015 bounds how long an idle peer may occupy a listener slot. It does not bound how long
`vigild` may wait for a reply to an individual policy install, root binding, or health request.
Using a semaphore without a deadline would let a wedged extension pin daemon work indefinitely.
Treating a timeout as a clean failure would be worse: XPC cannot prove the extension did not apply a
mutation immediately before its reply was delayed or lost, so automatic replay could duplicate or
conflict with an operation whose outcome is merely unknown.

## Decision

`NativeXPCControlClient` is asynchronous and gives every request one dispatch timer. Production
timeouts default to two seconds and must remain between 50 milliseconds and 30 seconds; anonymous
tests may use 10 milliseconds or greater. Requests and responses are capped at 2 MiB and no more
than 64 requests may be outstanding.

A reply or deadline removes the request and invokes its completion exactly once. Deadline expiry
returns `deadlineExceededOutcomeUnknown` and invalidates the whole connection. Other requests on
that connection fail as invalidated. The caller must establish a new authenticated connection and
issue `health` to reconcile installed generation/readiness before deciding whether a mutation may
be retried. The API deliberately has no automatic retry.

Timers are activated before a request becomes visible to any cancellation path. This is
load-bearing on Dispatch: releasing or cancelling a suspended source can trap the process.

## Consequences

A silent or slow extension cannot hold daemon request work indefinitely, late replies cannot cause
a second completion, and uncertain mutations are not silently replayed. The native executable check
uses real anonymous XPC endpoints to prove a successful request, a deliberately late reply, channel
invalidation, and exactly-once completion.

This does not create the production trust boundary. A signed `vigild`, registered Mach service,
launchd lifecycle, production code requirement, and entitled device tests are still required.
