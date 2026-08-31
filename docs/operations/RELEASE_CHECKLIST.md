# Release checklist

## The gates that are mechanical

§89 lists the conditions under which a release candidate fails. Each is a test:

```bash
cargo test -p vigil-cli --test release_gates
```

| Gate | Test |
|---|---|
| Policy validation can fail open | `gate_policy_validation_cannot_fail_open` |
| Entitlement-dependent functionality falsely reported as active | `gate_entitlement_dependent_functionality_is_never_reported_as_active` |
| An agent can directly alter policy | `gate_an_agent_cannot_reach_the_control_plane` |
| An agent can alter audit data without detection | `gate_altering_audit_data_is_detected` |
| A budget race permits overrun | `gate_a_budget_race_cannot_overrun` |
| Path traversal escapes the workspace | `gate_path_traversal_cannot_escape_the_workspace` |
| Sensitive values appear in logs | `gate_sensitive_values_never_reach_evidence` |
| Network policy silently falls back to unrestricted | `gate_network_policy_never_falls_back_to_unrestricted` |
| Privilege escalation without explicit policy | `gate_privilege_and_persistence_are_never_granted` |
| Process termination can kill unrelated processes | `gate_containment_does_not_terminate_processes` |
| Authorization callbacks miss Endpoint Security deadlines | `gate_endpoint_deadlines_are_not_applicable_yet` |

The last is recorded as **not applicable** rather than passing: there is no installed Endpoint
Security client, so there are no callbacks to miss deadlines. The test asserts that remains true,
so the moment a client exists the gate fails and must be replaced with a real deadline check.

Two §89 gates have no mechanical form here:

- **"critical IPC trusts caller-supplied identity"** — the XPC path refuses PID claims and
  authenticates by audit token (ADR 0011, 0013), but there is no registered Mach service to
  exercise. It is checked by the native adapter's own check executable.
- **"high-severity fuzz crashes remain unresolved"** — enforced by CI replaying every committed
  artifact in `fuzz/artifacts/`. A crash that still reproduces fails that job.

## Getting the external dependencies

`docs/development/UNBLOCKING.md` records the dependency order, what each unlocks, and the
disposable-VM path that validates the Endpoint Security exit criteria before any Apple approval.

## The gates that are not mechanical

Before a release that claims OS enforcement, all of these must be true and none can be tested from
this repository:

- [ ] Apple has granted `com.apple.developer.endpoint-security.client`
- [ ] A Developer ID certificate and Team ID are provisioned
- [ ] The System Extension bundle activates on a clean machine and survives upgrade
- [ ] Full Disk Access is granted and its absence is reported, not assumed
- [ ] The build is signed, hardened-runtime, and notarized
- [ ] Entitled-device tests prove pre-execution denial, deadline behaviour, event-drop handling,
      and cache invalidation
- [ ] `vigil doctor` reports `FULLY ENFORCED` only when every one of the above is true

## Before every release

- [ ] `make verify` — fmt, clippy, full suite
- [ ] `make verify-macos` — plus both native data-path adapters
- [ ] `cargo test -p vigil-cli --test release_gates`
- [ ] `cargo test -p vigil-cli --test adversarial`
- [ ] `cargo audit` and a secret scan
- [ ] Fuzz artifacts replay clean; a sustained campaign has run since the last release
- [ ] The maturity table in `README.md` still matches reality — nothing simulated labelled
      enforced, nothing entitlement-blocked labelled available
- [ ] Every new claim in the README has a CI job behind it
