# ADR 0047 — Network enforcement health requires four current signals

**Status:** Accepted

## Context

macOS exposes several independent facts around a content filter. A System Extension may be active
while its `NEFilterManager` preference is absent or drifted. Preferences may be enabled while the
provider failed startup or holds expired policy. Both can look healthy while traffic does not
actually receive the expected allow and deny outcomes. Treating any one fact as enforcement would
create a silent downgrade.

## Decision

VIGIL derives network posture from four ordered evidence planes:

1. confirmed System Extension activation;
2. an exact, enabled `NEFilterManager` configuration;
3. fresh authenticated provider readiness carrying a live policy generation; and
4. fresh entitled-device observations proving an allowlisted destination succeeds and a denied
   destination is blocked under that same generation.

Only agreement across all four yields `FULLY ENFORCED`. Missing downstream evidence yields
`DEGRADED`; an absent or transitional extension remains `OBSERVE ONLY`; explicit failures,
configuration drift, stale/future evidence, expired policy, generation mismatch, or an incorrect
probe outcome yield `BROKEN`.

The evaluator accepts no error descriptions or arbitrary strings. Provider-ready and flow-observed
values cannot be constructed through its public API; their future authenticated verifiers must
mint them inside `VigilMacSupport`. Until those producers exist, the Control Center supplies
unavailable evidence and therefore cannot display `FULLY ENFORCED`.

## Consequences

The health decision is deterministic and entitlement-free tests cover every downgrade boundary.
An OS activation success can no longer become a product-level protection claim. The remaining
Phase 4 device work is sharply defined: build the authenticated provider-health channel and the
privileged allow/deny probe that mint the two unavailable evidence types, then validate them on an
entitled machine.
