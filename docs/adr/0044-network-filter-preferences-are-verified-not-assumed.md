# 0044 — Network filter preferences are verified, not assumed

Status: accepted
Date: 2026-08-30

## Context

The native data provider and its exact configuration factory compiled, but no containing-app code
managed `NEFilterManager`. Saving a preference is an asynchronous privileged operation: the caller
must first load current preferences, a save may fail or time out with an unknown outcome, and an
enabled preference does not prove that the System Extension is installed, running, or healthy.
Concurrent load/change/save sequences can also overwrite one another with stale state.

## Decision

The containing-app boundary uses a main-actor preference controller over the public
`NEFilterManager` API. Desired configuration is validated against the same strict
`vigil.network-provider/v1` contract consumed by provider startup.

Install/enable performs load, exact mutation, save, reload, and exact verification. Status
distinguishes absent, disabled, enabled, and configuration drift. Disable and removal also reload
and verify their postcondition. All public sequences are serialized; an overlapping request is
refused rather than interleaved. Each OS preference call has a bounded deadline. A timeout is
reported as outcome-unknown and permanently invalidates that controller instance so the caller
cannot blindly retry a mutation whose result may arrive later.

Preference status is deliberately named and scoped as preference status. It is not System
Extension activation or enforcement health; the activation coordinator in ADR 0046 and an
entitled-device health check remain separate evidence.

## Consequences

The production adapter compiles against the installed public SDK, while entitlement-free fakes
exercise success, drift, failure, timeout, concurrency, disable, and removal. Invalid identifiers,
keys, descriptions, or deadline bounds fail before preferences are touched.

An installable containing-app target, `OSSystemExtensionRequest` lifecycle, signing, entitlement
provisioning, user approval, and device-observed enforcement remain required. `vigil status`
continues to report the Network Extension as not installed.
