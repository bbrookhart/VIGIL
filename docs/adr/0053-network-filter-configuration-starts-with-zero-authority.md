# ADR 0053 — Network filter configuration starts with zero authority

**Status:** Accepted

## Context

The provider requires a signed policy and trusted public key before `startFilter` may succeed. The
containing app previously had a verifier and exact preference controller but no production policy
signer. Embedding a private seed or enabling preferences before a durable policy exists would make
the install path either forgeable or availability-unsafe.

An initial policy must not invent managed sessions, process attribution, destinations, or proof of
enforcement merely to make the provider start.

## Decision

The containing app owns a distinct Ed25519 network-policy key in its default device-only,
non-synchronizing Keychain namespace. Creation is insert-only; corrupt existing material is refused.
The provider receives only the SHA-256-fingerprinted key identifier and public key through the exact
`vigil.network-provider/v1` vendor configuration.

Before enabling filter preferences, the host publishes a short-lived signed bootstrap snapshot for
the durable installation instance. It has a monotonic generation and deliberately empty `sessions`
and `attributions` maps. It therefore grants no managed process network authority. A current policy
with more than five minutes remaining is reused; a near-expiry policy advances generation. Durable
generation and envelope identity retain the existing rollback/equivocation protections.

Only after policy publication succeeds does the main-actor orchestration save the public
`NEFilterManager` configuration, reload it, and require the exact bundle, App Group, instance,
trusted key, socket/packet flags, firewall grade, description, and enabled state to match. The UI
offers this as an explicit **Configure Filter** action and refuses it unless OS lifecycle evidence
reports the System Extension active.

## Consequences

The reviewable containing app can provision the provider's policy trust and exact preferences
without embedded secrets or fabricated process authority. Tests prove stable key identity,
corruption refusal, signature/instance binding, generation reuse/renewal, zero attribution, active
extension gating, and exact preference-state propagation.

ADR 0054 adds containing-app maintenance and provider-side reload outside the flow callback. The
real managed-session policy feed must replace the empty snapshot when the control plane is
connected. Entitled allow/deny flow proof and provisioned-device validation remain mandatory.
