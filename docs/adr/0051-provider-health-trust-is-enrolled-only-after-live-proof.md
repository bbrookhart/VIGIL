# ADR 0051 — Provider health trust is enrolled only after live proof

**Status:** Accepted

## Context

The provider holds its health-signing private key in the System Extension's non-shared Keychain
namespace. The containing app therefore needs a way to learn and persist the corresponding public
key without treating arbitrary App Group bytes as trusted provider evidence.

A self-signed public-key record would prove possession but not freshness, installation identity,
or live policy state. Automatically replacing an existing pin would also let changed shared state
silently redefine the provider identity.

## Decision

At successful startup the provider atomically publishes a strict, bounded public enrollment record
containing its installation instance, provider bundle identifier, key identifier, and public key.
The record is explicitly untrusted. The containing-app enrollment verifier uses that candidate to
verify the current short-lived provider-health envelope, including its signature, instance,
provider, timestamp, and policy lease. Only that combined proof can construct the opaque verified
enrollment type accepted by the trust store.

The macOS support controller additionally requires the System Extension lifecycle to report the
expected extension active before it attempts verification. It stores the first verified identity
as a device-only, non-synchronizing, insert-only item in the containing app's default Keychain
namespace. A matching identity is idempotent. A different identity, malformed pin, insertion race,
missing enrollment, or invalid health proof is refused and never produces ready evidence.

Key rotation is deliberately not automatic. A future recovery workflow must authenticate and make
rotation explicit rather than interpreting a changed App Group file as authority.

## Consequences

The repository now contains the complete provider-publication, live-proof, activation-gate, and
immutable-pinning primitives. Tests cover missing and unknown-field records, wrong instance,
candidate/signature mismatch, stable restart, changed identity, corrupt trust state, and inactive
extension states.

ADR 0052 adds durable installation identity and containing-app orchestration that invokes this
controller after activation. The host still needs policy-key provisioning and exact filter
preference orchestration before the provider can start on a provisioned device. Entitled-device
tests remain mandatory.
