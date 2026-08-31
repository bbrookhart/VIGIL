# ADR 0052 — Network installation identity is durable and host-owned

**Status:** Accepted

## Context

Network policy, provider-health signatures, enrollment records, and trust pins are bound to a
target installation instance. A compiled constant would collapse every installation into one
identity; an in-memory UUID would make restart look like a different installation. The containing
app also needs to refresh provider evidence without blocking its UI or weakening the separate
preference and flow-proof requirements.

## Decision

The containing app owns one canonical lowercase UUID in its default Keychain namespace. Creation
is device-only, non-synchronizing, and insert-only. A racing creator reloads the winner; malformed
existing bytes are refused and never silently replaced. The resulting identifier keys the
provider-health trust pin and is the exact instance expected by enrollment verification.

The reviewed host Info.plist now carries the provisioned App Group identifier. At launch, the host
runtime resolves that container, loads the durable instance, composes the enrollment/health stores
and immutable trust store, and exposes the instance for the filter-preference configuration path.
The SwiftUI host refreshes enrollment on a bounded five-second cadence using detached work. Only
verified enrollment states contribute provider evidence to the four-plane health evaluator.
Missing configuration, inactive extension state, invalid evidence, or runtime construction failure
remains unavailable and cannot become `FULLY ENFORCED`.

## Consequences

Installation identity and provider-health enrollment now survive restart and are wired into the
reviewable containing-app product. Tests cover canonical stability, creation races, corruption,
configuration validation, activation gating, and the rule that refusals expose no ready evidence.

ADR 0053 adds policy-signing public-key provisioning and exact `NEFilterManager` preference
orchestration using this instance. Automatic policy-lease renewal, a managed-session policy feed,
entitled flow proof, and provisioned-device validation remain before Phase 4 can ship.
