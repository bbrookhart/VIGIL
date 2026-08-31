# ADR 0054 — Network policy renewal is conditional and provider-pulled

**Status:** Accepted

## Context

Network authority is leased. The zero-authority bootstrap expires after one hour and the provider
must reject an expired snapshot for every attributed process. Publishing a new signed generation
alone is insufficient: the running data provider must also verify and install it without doing
filesystem, signature, or coordination work in `handleNewFlow`.

Renewal must not keep a disabled, drifted, or inactive filter configuration artificially alive.
It also cannot depend on unavailable macOS control-provider APIs.

## Decision

While the containing app is running, it attempts maintenance at most once per minute. Maintenance
requires OS-observed active System Extension state and an exact enabled preference round trip.
Only then may the host-side provisioner inspect the durable policy. A policy with more than five
minutes remaining is reused without generation churn; otherwise a new one-hour, empty-session,
empty-attribution snapshot is signed and atomically published at the next durable generation.

The Network data provider owns a separate serial reload timer bounded to 1–30 seconds. It reads the
durable record and envelope, requires two coherent generation reads, verifies signature, instance,
expiry, generation, and digest, and atomically installs only a newer snapshot. This work remains
outside the flow callback. Reload failure retains the last verified state; its exclusive expiry
continues to deny managed traffic instead of silently extending authority.

Provider health reads the same atomic policy state, so its next signed attestation naturally names
the newly installed generation. The existing four-plane health evaluator still requires matching
preference, provider, and privileged flow evidence before it can report full enforcement.

## Consequences

Bootstrap configuration no longer expires merely because a user leaves the Control Center open.
Tests prove host activation/preference gates, generation propagation into a running provider,
bounded/idempotent timers, missing-clock refusal, and failure retention. The renewal path grants no
managed process authority and does not claim entitled-device enforcement.

Renewal currently belongs to the running containing app rather than a launchd daemon. The real
managed-session policy feed, privileged allow/deny flow proof, signed provisioning, and device
validation remain release requirements.
