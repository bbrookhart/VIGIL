# ADR 0017 — Approvals mint bounded capability leases

**Status:** Accepted  
**Date:** 2026-08-30

## Context

`crates/vigil-local/src/policy.rs` produced `REQUIRE_APPROVAL` from seven named policies —
workspace execution, `process.exec`, new network destinations, brokered secret use and metadata,
untrusted-agent deletion — and nothing in the system could satisfy one. There was no approval
record, no human decision path, no capability lease, and no CLI command. Every approval-bound
capability was therefore a permanent denial wearing a more optimistic label, which is worse than an
honest denial: it tells an operator that a path exists when it does not.

Invariants 5, 6 and 7 (explicit bounded delegation, expiring leases, use-bounded leases) were
documented but unenforced locally, and invariant 8 (specific approval) had nothing to constrain.

## Decision

A `REQUIRE_APPROVAL` decision records an approval request. A human grants it. Granting mints
exactly one capability lease, and a lease is the only thing that can satisfy a `REQUIRE_APPROVAL`.

**Approvals are specific.** An approval binds to the canonical-JSON SHA-256 of
`(session_id, action, resolved_resource)`. The lease inherits that triple from the approval; the
grant command chooses only *how many uses* and *for how long*. An operator decides whether, never
what. There is no API shape expressing "allow everything for N minutes".

**Leases bind to the resolved resource**, the path policy actually decided about, never the string
the caller typed. `~/w/../.ssh` cannot be laundered past authority granted for `~/w`.

**Expiry is a predicate, not a status.** Every statement that could act on a lease or an approval
compares `expires_at` inline. An expired lease is inert the instant it expires; no sweeper needs to
have run for that to be true, and the stored row may still read `active` with uses remaining.

**Two properties are database constraints, not code conventions.** `delegable` carries
`CHECK(delegable = 0)`, so a delegable lease cannot be stored. `uses_remaining` is bounded by
`max_uses` and by zero, so no accounting bug can inflate it.

**Consumption is one statement.** `consume_lease` performs its check-and-decrement as a single
`UPDATE ... WHERE status='active' AND uses_remaining > 0 AND expires_at > :now` inside
`BEGIN IMMEDIATE`, the same discipline as the budget reservations in ADR 0006. Concurrent callers
cannot both spend the last use.

**A grant longer than the ceiling is refused, not clamped.** An operator who believes they granted
eight hours must not discover later that they granted fifteen minutes.

**A denial is never routed to a human.** Only `REQUIRE_APPROVAL` raises an approval. An approval
able to overturn a `DENY` would be precisely the Deny-to-Allow path ADR 0002 exists to forbid.

**Re-asking is not free.** An identical pending request returns the existing row rather than
creating a second. Re-asking for something already refused creates no new row and loads the
policy-evasion risk dimension; four attempts reach quarantine. Generating requests faster than an
operator can answer loads the capability-anomaly dimension. Approval fatigue is treated as an
attack on the human rather than as noise.

## Consequences

Prompt Demo 7 — an agent needs legitimate exceptional access and receives one action, one resource,
one use, a short TTL — is now demonstrable end to end through the CLI. Invariants 5, 6, 7 and 8 are
enforced for brokered requests.

### What this does not claim

`grant_approval` and `deny_approval` require an `ApproverIdentity`, whose only constructor is
`from_cli_operator`. No broker module can build one, and a test asserts that no broker source
references the grant path at all. **That is defence in depth, not a trust boundary.**

On a host with no `vigild` and no authenticated IPC, the agent and the operator hold the same
ambient authority. An agent that can execute arbitrary code can run the `vigil` binary and approve
its own request. **Invariant 3 — no self-authorization — is not satisfied at the operating-system
level and must not be described as satisfied** until an entitled, signed daemon owns the approval
store and authenticates its callers. The structural control means a bug or a refactor cannot open
that path accidentally; it does not mean a deliberate attacker is stopped.

This is the same boundary `docs/security/TRUST_BOUNDARIES.md` already draws for local session IDs:
they are lookup keys, not bearer capabilities, and the launcher is not a containment boundary.
