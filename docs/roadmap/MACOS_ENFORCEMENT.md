# Roadmap to demonstrated macOS enforcement

The native code is a serious implementation path, but code and entitlement-free tests are not the
same evidence as an active operating-system boundary. This roadmap defines the promotion criteria.

## Stage 1 — Isolate control-plane ownership

- Introduce `vigild` under a distinct, least-privileged identity.
- Move policy generations, capability keys, approvals and event storage behind authenticated IPC.
- Bind requests to audit-token identity and validate code requirements.
- Store private keys in restricted Keychain access groups.
- Prove an agent running as the user cannot grant approval or rewrite/delete current evidence.

**Exit evidence:** negative same-user attack suite, IPC peer matrix, store/key ACL inspection, daemon
restart/upgrade tests.

## Stage 2 — Sign and entitle the product graph

- Obtain Apple Endpoint Security and Network Extension entitlements for final bundle identifiers.
- Sign the containing app and embedded System Extensions without development-only exceptions.
- Validate hardened runtime, notarization path, entitlements and designated requirements.
- Keep SIP, Gatekeeper and TCC enabled.

**Exit evidence:** `codesign`/notarization inspection, archived build manifest and independent
identifier/entitlement review.

## Stage 3 — Activate on dedicated devices

- Exercise clean install, user/MDM approval, enable, restart, sleep/wake, fast-user switch, upgrade,
  disable, removal and failed-upgrade recovery.
- Test each supported macOS release and hardware class.
- Record explicit absent, disabled, degraded, broken and active states.

**Exit evidence:** device matrix and signed logs linked to exact commit/build.

## Stage 4 — Prove event and flow coverage

- Generate permitted and denied process, file, local IPC and network cases outside the brokers.
- Verify expected Endpoint Security authorization events and Network Extension callbacks.
- Measure drops, mute behavior, deadline misses, provider restarts and policy-generation staleness.
- Demonstrate DNS rebinding, direct-IP and stale-resolution behavior on real flows.

**Exit evidence:** coverage matrix by event/flow/API/OS version and reproducible fault-injection pack.

## Stage 5 — Close reconciliation and containment

- Correlate every semantic intent with live observed execution.
- Detect undeclared children, resource mismatch, unmediated effects and denied operations observed.
- Terminate process trees only after identity continuity is confirmed.
- Prove containment persists across session churn and component restart.

**Exit evidence:** end-to-end bypass suite and incident bundles showing intent, observation, decision,
response and residual gap.

## Stage 6 — Publish a bounded claim

Commission an independent security review, remediate critical/high findings, publish limitations and
reproduction instructions, and update [canonical enforcement status](../security/ENFORCEMENT_STATUS.md)
one row at a time. Never promote the whole system based on one successful adapter path.

## Explicit non-goals

The final claim will still exclude root/kernel compromise, deliberate administrator disablement,
unsupported macOS versions and side channels outside the documented event/flow coverage.
