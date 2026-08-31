# ADR 0046 — System Extension activation is observed, not inferred

**Status:** Accepted

## Context

The unsigned containing-app product graph proves that VIGIL packages a real Network System
Extension, but it does not exercise macOS installation policy. The containing application must
submit supported activation, inspection, replacement, and deactivation requests while keeping OS
approval distinct from content-filter preference state and provider health.

Replacement is also a rollback boundary. Automatically accepting a candidate with a lower bundle
version would permit an older signed build to displace a repaired provider.

## Decision

`VigilMacSupport` owns the containing-app lifecycle coordinator. It uses public
`SystemExtensions` requests on a bounded main-queue state machine and exposes explicit states for:

- request submission;
- required user approval;
- active, inactive, and uninstalling status;
- completion requiring reboot; and
- stable, redacted failure categories.

Only one request may be outstanding. Stale callbacks are ignored. Status is obtained with a
properties request rather than inferred from a successful submission. Replacement requires both
the installed and candidate bundle identifiers to equal the configured identifier, strictly
numeric bounded versions, and a candidate version that is not older. Ambiguity and malformed
versions cancel replacement.

An OS result that says the System Extension is active is displayed as **enforcement unverified**.
It does not establish that `NEFilterManager` preferences match, the provider loaded authenticated
policy, callbacks are healthy, or denied traffic is actually stopped.

## Consequences

The activation/upgrade/deactivation control path is now reviewable and entitlement-free tests
cover its security decisions. Actual activation remains externally gated by signing,
provisioning, user approval, and an entitled device. The next health slice must combine extension
status, exact filter preferences, and authenticated provider evidence before VIGIL can report
network enforcement.
