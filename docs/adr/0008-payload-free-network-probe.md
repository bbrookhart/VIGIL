# ADR 0008 — Establish destination integrity with a payload-free network probe

**Status:** Accepted  
**Date:** 2026-08-29

## Context

Phase 2 calls for a basic network broker, but returning a raw socket would permit unbounded data
transfer before byte budgets, taint checks, protocol mediation, and Network Extension attribution
exist. Positive network tests must also remain deterministic and must not depend on Internet
access or a privileged Apple entitlement.

## Decision

Implement a payload-free TCP probe over a `NetworkEventSource` abstraction. The system source
performs bounded caller-visible resolution and connect attempts. The simulated source supplies
deterministic resolution/connect outcomes for security tests.

Enforced profiles use exact hostname/port allowlists and deny direct IPs before DNS. After
resolution, VIGIL rejects empty/oversized sets, port substitution, and any non-public IPv4/IPv6
answer. A connected peer must appear in the validated set. The broker then closes immediately,
records zero payload bytes, and never calls this a firewall or Network Extension enforcement.

SQLite schema v3 adds one first-use claim per session and normalized hostname/port. Reservation,
claim creation, and both connection/destination limits share `BEGIN IMMEDIATE`. Commit preserves
the claim so later probes spend only connection units. Failure refunds the reservation and removes
a pending first-use claim. An unreconciled pending claim blocks concurrent reuse fail-closed.

## Consequences

VIGIL now has testable hostname, port, direct-IP, rebinding, address-family, destination-novelty,
and network failure semantics without enabling application-data egress. The system resolver cannot
cancel an OS lookup after caller timeout, and direct sockets remain bypassable. General network
brokering, byte budgets, TLS/application identity, and non-bypassability remain Phase 4 Network
Extension work.
