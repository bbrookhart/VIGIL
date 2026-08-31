# Network Extension model

**Status:** unsigned containing-app/System Extension graph builds; no signed or activated extension
**Deployment floor:** macOS 15 for the public `remoteFlowEndpoint` API

VIGIL constrains network flows only for processes attributed to a managed session. Unattributed
host traffic remains unaffected, including when VIGIL policy is missing or unhealthy.

## Bounded flow authority

```text
Rust policy compiler/signing key
        │ strict, instance-bound Ed25519 envelope
        ▼
protected atomic envelope publisher             [built; provisioning pending]
        │ atomic shared-container/configuration update
        ▼
read-only Swift startup verifier + state         [built and checked]
        │ no callback I/O
        ▼
NEFilterDataProvider.handleNewFlow              [embedded in unsigned SYSX]
        │ allow / drop / pause
        ▼
macOS flow                                      [not signed, installed, or activated]
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
The containing application or daemon verifies and publishes exact envelope bytes out of band
through the atomic shared-container store, then commits the matching durable `(generation,
envelope digest)` replay record. One cross-process lock covers that complete write transaction.
The provider's App Group view is read-only: `startFilter` parses an exact vendor-configuration
schema, resolves the group, double-reads the durable record around the envelope read, verifies the
signature and exact generation/digest match, and only then activates policy. A restart may restore
only the exact envelope at the durable generation; different bytes at the same generation are
equivocation. The data callback consumes only verified in-memory state and performs no DNS,
network, filesystem, database, IPC, UI, model, or logging work. See ADRs 0036 and 0043.

The containing-app preference controller uses public `NEFilterManager` load/save/remove APIs. It
serializes complete operations, bounds every OS call, and reloads to verify exact provider bundle,
App Group, instance, key set, socket/packet flags, firewall grade, description, and enabled state.
Configuration drift is distinct from enabled VIGIL preferences. A timeout invalidates the
controller because the mutation's outcome is unknown. Even an exact enabled preference is not
reported as active enforcement; see ADR 0044.

## What the simulator and native check prove

The entitlement-free Rust source replays ordered flows and injected source failure. Tests cover
exact allow, IPv4/IPv6, unknown/direct/private destinations, rebinding, protocol/port/direction,
resolution and whole-policy expiry, missing clock, four modes, bounded budgets, malformed policy,
generation rollback, signature tamper, wrong instance, and unknown key. The Swift check verifies
the exact Rust fixture, exercises the corresponding native state, and references the real public
provider subclass so SDK drift fails compilation.

## Remaining Phase 4 work

- provision the factory's exact configuration, trusted keys, and App Group in signed targets;
- System Extension activation, upgrade, rollback, signing, notarization, and entitlement provisioning;
- flow telemetry persistence and supported prompt resumption/cancellation;
- byte-budget accounting at a layer with trustworthy byte visibility;
- entitled-device tests proving allowlisted reachability and denied-destination prevention.

Until those exist, `vigil status` continues to report `Network Extension: NOT INSTALLED` and
direct sockets remain outside VIGIL enforcement.
