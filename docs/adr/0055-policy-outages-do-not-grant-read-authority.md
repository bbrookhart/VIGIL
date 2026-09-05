# ADR 0055: Policy outages do not grant read authority

## Context

The core previously permitted constrained tier 0–1 reads when its policy engine
failed. A customer-record read can still disclose private information. Impact
classification is not evidence of permission, and a failed evaluation cannot
establish resource- or task-scoped authority.

## Decision

Any policy evaluation error contributes `DENY` with `POLICY_ENGINE_UNAVAILABLE`
and `FAIL_CLOSED`, regardless of impact tier. Restrictive decision composition
preserves this result, and no execution capability is minted. Optional detector
failure behavior is unchanged; detectors are not authorization authorities.

## Alternatives

- Retain degraded reads: rejected because their authorization has not succeeded.
- Cache grants: deferred until independently verified scope, expiry, revocation and
  outage semantics can be enforced; no cache is added in this change.

## Consequences and compatibility

Read-only agents lose availability during a policy outage. This is an intentional
security behavior change. Healthy authorized reads and exact-action approvals
retain their existing paths. This change does not establish host confinement,
human authentication, or persistent revocation across service restarts.

## Evidence

The failure-injection suite exercises low-impact customer-record reads and
high-impact writes against an unavailable policy engine, asserting refusal and
absence of a capability. Existing end-to-end tests cover healthy authorized actions.

## Reconsideration

Revisit only with a separately reviewed cached-authority design and fault tests
showing that policy unavailability cannot expand authority.
