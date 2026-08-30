# Network Extension model

**Status:** native data-provider boundary compiles; no installable or activated extension  
**Deployment floor:** macOS 15 for the public `remoteFlowEndpoint` API

VIGIL constrains network flows only for processes attributed to a managed session. Unattributed
host traffic remains unaffected, including when VIGIL policy is missing or unhealthy.

## Bounded flow authority

```text
Rust policy compiler/signing key
        │ strict, instance-bound Ed25519 envelope
        ▼
protected out-of-band publisher                 [not built]
        │ atomic shared-container/configuration update
        ▼
Swift verifier + monotonic in-memory state      [built and checked]
        │ no callback I/O
        ▼
NEFilterDataProvider.handleNewFlow              [public subclass compiles]
        │ allow / drop / pause
        ▼
macOS flow                                      [not installed or activated]
```

The fast-path identity is:

```text
session + full process audit token + hostname + protocol + port
        + approved public IP set + exclusive resolution expiry
```

The native provider projects `sourceProcessAuditToken` (with `sourceAppAuditToken` only as a
compatibility fallback), socket protocol, direction, native hostname, numeric remote endpoint,
and callback time. It never accepts a PID or synthesizes a hostname from an address. Direct IP,
missing/malformed hostname, private or special-use address, rebinding, stale resolution, inbound
flow, protocol/port mismatch, and exhausted flow/destination budgets all fail closed for managed
`PROMPT` or `ENFORCE` sessions.

`OFF` permits a managed flow and `OBSERVE` records a would-deny result without blocking only while
their signed snapshot is live. Missing clock or whole-policy expiry is an authority failure and is
forced to `ENFORCE` semantics. `PROMPT` returns a pause verdict for future supported mediation;
there is no UI round trip in the callback. Budget state is not replenished by generation refresh.

## Policy authenticity and distribution

`vigil-network` emits a strict `vigil.network-policy/v1` payload inside a bounded,
domain-separated Ed25519 envelope. Swift authenticates the envelope before decoding the payload,
requires a preprovisioned key, expected installation instance, live issuance window, and strictly
newer generation, then installs atomically. The Rust-produced fixture is verified by the native
check and regenerated/freshness-checked in CI.

The public macOS SDK marks `NEFilterControlProvider`, `needRulesVerdict`, and
`notifyRulesChanged` unavailable on macOS. Consequently VIGIL does not model a control provider.
The future containing application or daemon must publish the envelope out of band through an
Apple-supported protected shared-container or configuration mechanism. The data callback consumes
only verified in-memory state and performs no DNS, network, filesystem, database, IPC, UI, model,
or logging work. See ADR 0036.

## What the simulator and native check prove

The entitlement-free Rust source replays ordered flows and injected source failure. Tests cover
exact allow, IPv4/IPv6, unknown/direct/private destinations, rebinding, protocol/port/direction,
resolution and whole-policy expiry, missing clock, four modes, bounded budgets, malformed policy,
generation rollback, signature tamper, wrong instance, and unknown key. The Swift check verifies
the exact Rust fixture, exercises the corresponding native state, and references the real public
provider subclass so SDK drift fails compilation.

## Remaining Phase 4 work

- protected atomic shared-container/configuration publisher and reader;
- durable generation high-water state across extension restarts;
- installable Xcode System Extension target and containing-app configuration;
- activation, upgrade, rollback, signing, notarization, and entitlement provisioning;
- flow telemetry persistence and supported prompt resumption/cancellation;
- byte-budget accounting at a layer with trustworthy byte visibility;
- entitled-device tests proving allowlisted reachability and denied-destination prevention.

Until those exist, `vigil status` continues to report `Network Extension: NOT INSTALLED` and
direct sockets remain outside VIGIL enforcement.
