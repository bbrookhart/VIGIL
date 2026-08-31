# ADR 0015 — Refresh XPC idle timeouts only after authentication

**Status:** Accepted  
**Date:** 2026-08-30

## Context

A hard peer-count bound limits memory growth but does not prevent slot exhaustion if clients can
connect and remain idle forever. Refreshing an idle timer before sender verification would let an
untrusted local process pin all slots by repeatedly sending malformed dictionaries.

## Decision

Give every accepted peer one refreshable dispatch timer. Production configuration defaults to 30
seconds and must remain between 1 and 300 seconds. The explicitly named anonymous test constructor
may use 10 milliseconds or greater to keep integration checks fast.

Refresh the timer only after `SecCodeCreateWithXPCMessage` and `SecCodeCheckValidity` authenticate
the individual message sender. Send a wrong-identity peer the fixed `unauthenticated_peer` response
and immediately cancel its connection. Cancel the timer on idle expiry, malformed-message teardown,
XPC error, explicit stop, peer rejection, and listener deinitialization.

## Consequences

Idle or unauthenticated clients cannot permanently consume the listener's 64 connection slots, and
chatty valid daemon connections remain alive. The anonymous integration check proves both timed
eviction of an authenticated idle client and immediate removal of a real wrong-identity client.

This is a connection-resource timeout, not an end-to-end request deadline. ADR 0021 adds the
separate bounded client deadline and outcome-unknown timeout posture.
