# ADR 0050 — Provider health keys remain in the extension Keychain

**Status:** Accepted

## Context

The provider-health signature is meaningful only if shared-container writers cannot obtain or
replace its private key. Persisting raw Ed25519 material in the App Group would let the containing
app or any process with that group entitlement forge provider readiness. Generating a new key on
every launch would also destroy stable trust identity.

Health signing and file publication must not add Keychain, cryptographic, or file work to
`handleNewFlow`. Startup races and corrupt persisted values must not silently rotate identity.

## Decision

The Network System Extension stores one 32-byte Ed25519 private key as a generic-password item in
its default Keychain access group, with `AfterFirstUnlockThisDeviceOnly` accessibility and iCloud
synchronization disabled. Neither extension nor host entitlement requests a shared Keychain
group. The App Group carries only short-lived signed health envelopes.

The provider loads or creates the key during `startFilter`. Creation uses insert-only semantics:
if another creator wins, the loser reloads that item and never overwrites it. Wrong-size or
unusable stored material is a hard error, not an invitation to rotate. Callers receive the public
key, its SHA-256-derived identifier, and an opaque signing capability; the API does not expose the
private bytes.

After verified policy startup, a dedicated serial timer publishes at a bounded 1–30 second
interval. Flow callbacks perform only constant-space saturating counter increments. The timer
takes a coherent policy lease and counter snapshot, signs it, and atomically publishes it. Missing
policy, clock, Keychain, or transport state cannot produce a successful health record. Provider
startup itself fails if the health runtime cannot be established.

## Consequences

Provider health now has production key custody and lifecycle scheduling without putting signing or
I/O in the verdict path. Unit tests cover stable creation, concurrent-create recovery, corrupt-key
refusal, exact counters, absent clock/policy, interval bounds, and idempotent start/stop.

ADR 0051 adds a reviewed first-install live-proof and immutable-pinning path. The containing app
still needs durable installation-instance provisioning and runtime orchestration before it may
turn the resulting signed bytes into visible ready evidence. Entitled-device tests also remain.
