# ADR 0013 — Bind managed roots by full audit token

**Status:** Accepted  
**Date:** 2026-08-30

## Context

VIGIL must connect a launched agent session to the process identity observed by Endpoint Security.
A PID is caller-claimable and reusable, so an authenticated daemon message carrying only a PID can
still race process exit and bind authority to the wrong execution. Root binding must also remain
coherent with concurrent policy installation and daemon retries.

## Decision

Add `bind_root` to `vigil.endpoint-control/v1`. Require the exact session ID, current installed
generation as a canonical decimal string, and the complete nonzero 32-byte audit token encoded as
strict unpadded base64url. Reject unknown fields, including PID. Serialize generation validation
and binding with policy installation.

Treat an identical token/session/generation replay as idempotent. Never allow an existing token to
be reassigned to a different session. Reject missing or expired policy, generation mismatch,
unknown sessions, malformed tokens, and attribution-capacity failures without partial mutation.
Expose production registration only through the authenticated control service; retain an
explicitly named direct method solely for entitlement-free checks.

## Consequences

The future daemon/extension channel has a race-resistant registration contract and can safely retry
after a lost acknowledgement. The repository still lacks a signed `vigild`, registered Mach
service, and a verified supported path by which that daemon obtains the launched process's audit
token. Until those exist, the successful cross-process path is not claimed.

Portable Rust and native Swift checks prove idempotency, immutable binding, malformed and zero
token rejection, stale-generation refusal, expired-policy refusal, and absence of PID trust.
