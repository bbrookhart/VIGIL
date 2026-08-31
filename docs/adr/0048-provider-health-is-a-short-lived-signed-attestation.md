# ADR 0048 — Provider health is a short-lived signed attestation

**Status:** Accepted

## Context

The four-plane health model requires provider readiness, but a boolean written by the containing
application would merely restate desired configuration. Provider evidence must identify the exact
installation and provider, bind to the currently loaded policy generation and lease, carry bounded
decision counters, and expire quickly enough that a dead provider cannot remain healthy.

The provider callback cannot perform signing, filesystem, IPC, or other unbounded work. Health
publication therefore belongs on a separate lifecycle/timer path.

## Decision

Provider readiness uses `vigil.network-provider-health/v1` inside a bounded Ed25519 envelope with
the dedicated `VIGIL_NETWORK_PROVIDER_HEALTH_V1` signing domain. Verification authenticates the
exact payload bytes before strict decoding and requires:

- a preprovisioned trusted health key;
- the expected installation instance and provider bundle identifier;
- a nonzero policy generation and an unexpired policy lease;
- an observation no more than 30 seconds old, with at most 30 seconds of forward clock skew; and
- overflow-safe counters where total equals allow + drop + pause.

Unknown fields, noncanonical base64url, oversized envelopes, signature failure, identity mismatch,
staleness, future dating, expiry, and inconsistent counters are rejected. Only the verifier can
construct `VerifiedNativeNetworkProviderHealth`; that wrapper is the public path into
`NetworkProviderHealthEvidence`.

## Consequences

The cryptographic producer/verifier contract and health-model bridge are reviewable and tested
without entitlements. The production provider still needs isolated signing-key custody and a
bounded publisher invoked outside `handleNewFlow`; the containing app needs the corresponding
protected reader. Until those exist, it supplies unavailable provider evidence and cannot reach
`FULLY ENFORCED`.
