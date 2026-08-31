# ADR 0036 — macOS network policy arrives out of band

**Status:** Accepted  
**Date:** 2026-08-30

## Context

The compact network fast path needs authenticated policy without performing daemon calls, file
reads, or unbounded work in `handleNewFlow`. An earlier design assumed a filter control provider
could supply rules to the data provider.

The installed public macOS SDK marks `NEFilterControlProvider`, `needRulesVerdict`, and
`notifyRulesChanged` unavailable on macOS. Inventing a control-provider target would therefore
encode an API the target platform cannot activate.

## Decision

VIGIL has one native macOS filter boundary: `NEFilterDataProvider`. The containing application or
daemon will publish a compact snapshot out of band through an Apple-supported, protected
shared-container/configuration path. The callback consumes only already-verified in-memory state.

Each snapshot is a strict `vigil.network-policy/v1` payload in a domain-separated Ed25519 envelope.
It is bound to a preprovisioned key ID and installation instance, has an exclusive signed expiry,
and must increase generation monotonically. Signature and envelope bounds are checked before
payload parsing; installation is atomic; spent budgets survive refresh. Missing clock and expired
policy fail closed for attributed processes even when the last policy mode was `OFF` or `OBSERVE`.
Unattributed host processes remain unaffected.

## Consequences

The Rust signer and Swift verifier share a generated fixture and CI parity gate. The public data
provider compiles and the package includes entitlement/Info.plist templates, but the protected
publisher, atomic shared-container file or configuration transport, durable generation high-water
mark, installable Xcode target, signing, activation, and entitled-device tests remain required.

No Network Extension callback waits for IPC, performs DNS, or trusts an agent-provided PID.
