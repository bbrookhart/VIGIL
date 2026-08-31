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
protected atomic envelope publisher             [built; conditional renewal]
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

The SwiftUI host uses a separate `SystemExtensions` lifecycle coordinator to inspect, activate,
replace, and deactivate the embedded provider. It serializes requests, surfaces user-approval and
reboot-required states, ignores stale callbacks, redacts OS failures into stable categories, and
refuses identity mismatch, malformed versions, or downgrade replacement. An active extension is
still labelled enforcement-unverified until preferences and provider health corroborate it; see
ADR 0046.

Product-level health is a four-way conjunction: confirmed extension activation, exact enabled
filter preferences, fresh authenticated provider readiness with a live generation, and fresh
entitled allow/deny flow observations naming that same generation. Missing evidence cannot become
healthy; stale/future evidence, drift, expiry, mismatched generations, or an incorrect probe result
is explicit. The current host verifies signed provider evidence but has no privileged flow-proof
producer and therefore renders `OBSERVE ONLY` or `DEGRADED`, never `FULLY ENFORCED`; see ADR 0047.

Provider readiness now has a dedicated short-lived, domain-separated Ed25519 attestation contract.
It binds the installation instance, provider bundle, policy generation/expiry, observation time,
and internally consistent allow/drop/pause counters. Verification precedes strict decoding and is
the only public bridge into ready health evidence. Production signing-key custody and the bounded
publisher/reader path remain; no signing occurs inside `handleNewFlow`. See ADR 0048.

The attestation transport is also built: provider-side publication uses an owner-only temporary
file, fsync, atomic rename, directory fsync, and cross-process advisory lock; containing-app reads
are bounded, owner/mode checked, symlink-safe, and create no state. Bytes pass through signature
verification before the verified wrapper is returned. The provider now holds its device-only key
in its non-shared Keychain namespace and publishes from a bounded serial lifecycle timer. Flow
callbacks only increment constant-space counters. The provider also publishes an untrusted public
identity; after OS-confirmed activation, the host requires that candidate to verify fresh bound
health before pinning it insert-only in the host Keychain. The host now owns a durable installation
UUID and polls this path outside the UI thread. The explicit Configure Filter path now publishes a
signed zero-authority bootstrap policy before saving and exactly verifying filter preferences. The
host conditionally renews near-expiry bootstrap leases, and the running provider pulls, verifies,
and atomically installs newer durable generations on a bounded serial timer outside flow callbacks.
An unsigned app still cannot activate this path, and flow proof remains absent. See ADRs 0049–0054.

## What the simulator and native check prove

The entitlement-free Rust source replays ordered flows and injected source failure. Tests cover
exact allow, IPv4/IPv6, unknown/direct/private destinations, rebinding, protocol/port/direction,
resolution and whole-policy expiry, missing clock, four modes, bounded budgets, malformed policy,
generation rollback, signature tamper, wrong instance, and unknown key. The Swift check verifies
the exact Rust fixture, exercises the corresponding native state, and references the real public
provider subclass so SDK drift fails compilation.

## Remaining Phase 4 work

- provision the factory's exact configuration, trusted keys, and App Group in signed targets;
- signed activation/upgrade/deactivation validation, notarization, and entitlement provisioning;
- the real managed-session policy feed;
- entitled allow/deny evidence producer;
- flow telemetry persistence and supported prompt resumption/cancellation;
- byte-budget accounting at a layer with trustworthy byte visibility;
- entitled-device tests proving allowlisted reachability and denied-destination prevention.

Until those exist, `vigil status` continues to report `Network Extension: NOT INSTALLED` and
direct sockets remain outside VIGIL enforcement.
