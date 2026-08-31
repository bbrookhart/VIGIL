# ADR 0035 — Network flow authority is hostname plus pinned address

**Status:** Accepted  
**Date:** 2026-08-30

## Context

A hostname allowlist alone is not a flow authorization. DNS can change between policy compilation
and connection, return mixed public/private answers, or be bypassed with an IP literal. Conversely,
an IP allowlist alone loses the operator-reviewed destination identity and can grant unrelated
services hosted at the same address.

Network Extension callbacks also cannot wait for DNS, a database, UI, or daemon round trip. They
need bounded state that already answers the question.

## Decision

The Phase 4 fast-path contract binds a permitted destination to:

```text
session + complete process audit token + hostname + protocol + port
        + approved public IP set + exclusive resolution expiry
```

Policy is a strict, versioned snapshot. Attribution is transported as a list because a binary
audit token is not a valid JSON object key, then compiled into a bounded ordered lookup during an
atomic, monotonically increasing installation. The callback performs exact hostname comparison,
requires the native flow's remote address to be in the approved set, rejects direct IPs and all
private/local/special-use destinations, and fails closed if resolution time is unavailable or
expired.

The whole signed snapshot is itself an exclusive runtime lease. Missing clock or policy expiry is
forced to `ENFORCE` semantics for a managed process, regardless of the last installed mode; an
expired `OFF` policy is not enduring permission.

The four policy modes have explicit semantics. `OFF` permits managed traffic without evaluation;
`OBSERVE` permits a would-deny flow but reports its determining reason; `PROMPT` withholds an
unlisted flow for future supported mediation; `ENFORCE` denies it. An already allowlisted flow does
not prompt. Unattributed host processes remain unaffected in every mode.

Per-session total-flow and distinct-destination counters are part of the installed fast-path
state. A policy refresh preserves spent authority for surviving sessions; changing a generation
cannot replenish a budget.

## Consequences

The deterministic core can be exercised by a simulator without Network Extension entitlements.
The native Swift package now contains a public `NEFilterDataProvider` subclass and verifies the
exact domain-separated, instance-bound Ed25519 snapshot produced by Rust. Tests cover exact host
allow, unknown host, port and protocol mismatch, direct IP, loopback, IPv4/IPv6, resolution and
whole-policy expiry, modes, budgets, malformed/tampered snapshots, source failure, and rollback.

This is still not an installed firewall. The later protected publisher, bundle, and activation
coordinator do not replace the remaining signed/entitled-device proof; byte budgets and flow
telemetry persistence also do not exist. The macOS SDK makes a filter control provider unavailable,
so ADR 0036 defines distribution. Hostname metadata exposed by
Network Extension is not claimed to be authenticated application-layer SNI, and encrypted payload
inspection is outside this decision contract.

## Alternatives rejected

- **Hostname only.** Rebinding turns a name into authority for an unreviewed address.
- **IP only.** Shared and changing hosting makes address identity too broad and brittle.
- **Resolve inside the callback.** DNS is unbounded external work and does not belong on the
  enforcement path.
- **Reset counters on policy refresh.** Generation churn would mint new network authority.
- **Filter the entire host when policy is absent.** VIGIL constrains attributed agents; an outage
  must not become a machine-wide denial of service.
