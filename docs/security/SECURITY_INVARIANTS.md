# Security invariants

These invariants are the review contract for VIGIL. Each statement names its mechanism, evidence,
current boundary, known bypass, and the work required to strengthen it. “Held” below applies to
mediated requests unless the boundary explicitly says OS-enforced.

## Summary

| # | Invariant | Brokered boundary | Current OS boundary |
|---:|---|---|---|
| 1 | Default deny | Held | Partial; direct calls bypass brokers |
| 2 | Least authority | Held | Partial |
| 3 | No self-authorization | Structurally held | **Not held** for same-user CLI/storage |
| 4 | Non-transitive authority | Held in provenance/leases | Partial |
| 5 | Explicit bounded delegation | Held | Partial |
| 6 | Expiring, use-bounded leases | Held | Partial |
| 7 | Specific approval | Held | Approval identity not OS-authenticated |
| 8 | Budgets never self-increase or go negative | Held | Partial |
| 9 | Risk only reduces authority | Held | Partial |
| 10 | Deterministic final authority | Held | Held for decisions; bypass remains |
| 11 | Control-plane integrity | Structural checks only | **Not held** against same user |
| 12 | Evidence survives agent failure | Held for normal failure | Tamper-evident, not tamper-proof |
| 13 | Policy failure is safe | Held | Native unmanaged traffic unaffected |
| 14 | No silent downgrade | Held | Native activation not yet present |
| 15 | Identity is verified | Partial | Native design tested, not activated |
| 16 | Combination is monotone | Held | Held wherever policy runs |

## 1. Default deny

- **Rationale:** absence of an authorization must not become ambient user authority.
- **Mechanism/code:** explicit action parsing and the policy ladder in `vigil-policy` and
  `vigil-local`; protected/out-of-workspace resources deny before execution.
- **Tests:** policy behavior, local control-plane, release-gate, and adversarial suites.
- **Boundary:** held when Core/Gateway or a semantic broker is in the execution path.
- **Bypass/limitation:** a process can call the OS directly while native interception is inactive.
- **Hardening:** activate and validate Endpoint Security and Network Extension enforcement.

## 2. Least authority

- **Rationale:** a permit for one task must not become a reusable credential for another.
- **Mechanism/code:** action/resource hashes, principal/session binding, expiry, use count,
  destination scope, remit, risk and quantitative budgets.
- **Tests:** capability mismatch/replay/exhaustion tests and broker budget tests.
- **Boundary:** held at capability verification and each semantic broker.
- **Bypass/limitation:** inherited user permissions remain available outside those paths.
- **Hardening:** authenticated daemon custody and OS-level mediation of all relevant effects.

## 3. No self-authorization

- **Rationale:** the untrusted principal cannot be the authority that expands its own power.
- **Mechanism/code:** broker modules cannot construct `ApproverIdentity`; grants are exact and
  create bounded leases. A source-boundary test prevents accidental grant-path imports.
- **Tests:** approval architecture, grant binding, and release-gate tests.
- **Boundary:** structurally held inside the codebase only.
- **Bypass/limitation:** an agent running as the same user can invoke the approval CLI or edit the
  local store. This invariant is **not satisfied at the host boundary**.
- **Hardening:** a separately owned daemon, authenticated UI/IPC and operator authentication.

## 4. Non-transitive authority

- **Rationale:** spawning a child or calling a tool must not copy every capability implicitly.
- **Mechanism/code:** provenance propagates across process/tool nodes; leases remain bound to their
  recorded principal, session, action and resource.
- **Tests:** process lineage, MCP binding and capability mismatch tests.
- **Boundary:** held in recorded semantics.
- **Bypass/limitation:** an unconfined child inherits OS descriptors and same-user access.
- **Hardening:** close inherited descriptors, enforce child identity in native policy, reconcile
  undeclared children, and terminate by verified process identity.

## 5. Explicit, bounded delegation

- **Rationale:** delegation must be an auditable transfer, not a side effect of composition.
- **Mechanism/code:** current local leases have a database `CHECK(delegable = 0)`; the portable
  capability model carries scope, expiry, uses, depth, principals and reason.
- **Tests:** schema constraints and capability validation tests.
- **Boundary:** local delegation is disabled, which is safer than an incomplete delegate path.
- **Bypass/limitation:** OS resources can still be shared outside VIGIL.
- **Hardening:** introduce delegation only with authenticated principals and end-to-end negative tests.

## 6. Expiring and use-bounded leases

- **Rationale:** standing authority compounds blast radius.
- **Mechanism/code:** expiry is evaluated at use time; nonce/use consumption is atomic; revocation
  and exhaustion are immediate.
- **Tests:** expired, exhausted, revoked, replayed and concurrent-use cases.
- **Boundary:** held by Gateway and local authorization.
- **Bypass/limitation:** a lease cannot bound activity that never presents it.
- **Hardening:** protect time/key/nonce state in a daemon and anchor revocation externally.

## 7. Specific approval

- **Rationale:** “allow for ten minutes” is too broad for an autonomous actor.
- **Mechanism/code:** approval binds `sha256(session, action, resolved_resource)`; the operator may
  select only bounded TTL and use count.
- **Tests:** substitution, reuse and one-use approval tests.
- **Boundary:** the binding is held; the approver identity boundary is not yet host-authenticated.
- **Bypass/limitation:** same-user invocation can impersonate the human operator.
- **Hardening:** authenticated UI, reason display, anti-fatigue controls and daemon-only grant API.

## 8. Budgets never self-increase or go negative

- **Rationale:** individually valid actions can be dangerous in aggregate.
- **Mechanism/code:** SQLite `BEGIN IMMEDIATE` reservation plus constraints on consumed, reserved
  and limit values; execution commits or refunds explicitly.
- **Tests:** concurrency, exhaustion, refund, failed-I/O and session-churn tests.
- **Boundary:** held for brokered dimensions.
- **Bypass/limitation:** direct effects are not charged without an observer.
- **Hardening:** reconcile live OS observations and make store ownership independent of the agent.

## 9. Risk can only reduce authority

- **Rationale:** uncertain or hostile evidence must never unlock a more permissive path.
- **Mechanism/code:** fixed dimensions and monotone transitions run after any lease upgrade;
  containment revokes leases and persists workspace standing.
- **Tests:** transition, restart/churn, containment and monotonicity tests.
- **Boundary:** held inside local authorization and incident response.
- **Bypass/limitation:** unseen direct activity produces no risk signal.
- **Hardening:** native observation, authenticated telemetry and explicit recovery ceremonies.

## 10. Deterministic final authority

- **Rationale:** probabilistic detectors are useful evidence but unsafe final authorization.
- **Mechanism/code:** policy/remit/capability code alone returns the final lattice value; detectors
  may add taint, risk or a restriction, never a permit.
- **Tests:** order-independence, short-circuit and detector/decision monotonicity tests.
- **Boundary:** held wherever the VIGIL decision pipeline is called.
- **Bypass/limitation:** determinism does not make an uninvoked decision enforce itself.
- **Hardening:** keep native adapters on signed, precompiled deterministic snapshots.

## 11. Control-plane integrity

- **Rationale:** an agent that can rewrite policy, keys or evidence owns the control plane.
- **Mechanism/code:** protected-path registry, owner-only files, signed policy envelopes,
  generation checks, XPC peer design and tamper-evident event chains.
- **Tests:** protected-resource, policy rollback, signature, generation and peer-verification tests.
- **Boundary:** strong structural protection, but **not held against malicious same-user code**.
- **Bypass/limitation:** the current agent and CLI/store can share the same Unix user.
- **Hardening:** daemon/system-extension ownership, authenticated IPC, Keychain access groups and
  external checkpoint anchoring.

## 12. Evidence survives agent failure

- **Rationale:** incident evidence must outlive the process that caused it.
- **Mechanism/code:** durable SQLite/WAL events, hash chaining and signed checkpoints; ended
  sessions remain queryable.
- **Tests:** restart, chain verification, deletion/edit detection and checkpoint tests.
- **Boundary:** held for crashes and normal same-host failure.
- **Bypass/limitation:** same-user deletion can destroy availability even when modification is
  detectable; local media loss is out of scope.
- **Hardening:** daemon-owned store, remote append-only export and externally witnessed checkpoints.

## 13. Policy failure is safe

- **Rationale:** parser, store or policy failure cannot mean “allow all.”
- **Mechanism/code:** invalid profiles refuse session start; high-impact Core failures deny;
  native policy leases expire toward managed-process denial.
- **Tests:** invalid/stale/missing policy, store failure, deadline and restart cases.
- **Boundary:** held for managed sessions; unmanaged host activity stays outside VIGIL.
- **Bypass/limitation:** fail-closed policy does not imply fail-closed deployment routing.
- **Hardening:** prove deployment path ownership and test fault injection on activated devices.

## 14. No silent downgrade

- **Rationale:** “configured” must not be displayed as “enforced.”
- **Mechanism/code:** separate observe, degraded, broken and fully enforced states; network health
  requires activation, exact preferences, authenticated provider readiness and current flow proof.
- **Tests:** status/doctor, configuration drift, stale health and activation-state tests.
- **Boundary:** held in status computation and product design.
- **Bypass/limitation:** no activated-device evidence exists yet, so current status remains below
  full enforcement.
- **Hardening:** publish signed device evidence and keep state transitions fail-closed.

## 15. Identity is verified

- **Rationale:** PID, path and environment variables are identifiers, not authenticated identity.
- **Mechanism/code:** object/hash checks for executable and filesystem objects, full audit-token
  policy keys, code-requirement and XPC peer-verification designs.
- **Tests:** PID reuse, executable replacement, path swap, audit-token and peer tests.
- **Boundary:** partial locally; stronger native mechanisms are tested but not activated.
- **Bypass/limitation:** local session IDs are lookup keys and same-user callers are not separated.
- **Hardening:** authenticate the caller at IPC, use kernel event identity, and bind device evidence.

## 16. Monotone combination

- **Rationale:** no late-stage signal may accidentally weaken a prior restriction.
- **Mechanism/code:** `Decision::combine`, local restrictiveness ordering, lease upgrade limited to
  `REQUIRE_APPROVAL`, and risk degradation last.
- **Tests:** exhaustive pair/order properties and integration tests.
- **Boundary:** held in both portable and local decision composition.
- **Bypass/limitation:** it governs decisions, not deployment routing.
- **Hardening:** preserve the same algebra in every future native snapshot and protocol version.

## Review rule

A change that weakens one invariant must update this file, the relevant ADR, threat model, tests,
and [canonical enforcement status](ENFORCEMENT_STATUS.md) in the same pull request. Unsupported
security language is a release failure even when the code compiles.
