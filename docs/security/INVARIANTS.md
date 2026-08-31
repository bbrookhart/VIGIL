# Security invariants

These invariants apply to every VIGIL component and require negative tests.

1. **Default deny.** No matching authorization is a denial.
2. **Least authority.** Authority is scoped by action, resource, task, duration, use count, and
   destination where applicable.
3. **No self-authorization.** Agents cannot approve escalation, enlarge budgets, alter policy,
   disable monitoring, reset risk, or delete evidence.
4. **Non-transitive authority.** Provenance follows child processes/tools/subagents; authority
   does not unless explicitly delegated.
5. **Explicit, bounded delegation.** Default `delegable = false`; delegation records both
   principals, scope, expiry, uses, depth, and reason.
6. **Expiring and use-bounded leases.** Expired/revoked/exhausted leases never authorize.
7. **Specific approval.** Approval binds to the material action and relevant session/resource;
   there is no default broad time-window bypass.
8. **Budgets never self-increase or go negative.** Reservation is atomic and race-safe.
9. **Risk can only reduce authority.** The agent cannot veto degradation.
10. **Deterministic final authority.** Detectors and LLMs can enrich but cannot produce the
    final permit.
11. **Control-plane integrity.** Protected agents cannot modify VIGIL code, policy, keys,
    configuration, IPC endpoints, or evidence.
12. **Evidence survives agent failure.** Session/process termination does not remove history.
13. **Policy failure is safe.** Invalid or unavailable policy never becomes allow-all.
14. **No silent downgrade.** Missing controls are visible; profiles requiring them fail launch.
15. **Identity is verified.** Caller-supplied PID, session ID, and environment are not identity.
16. **Monotone combination.** No later stage turns a more restrictive decision into a less
    restrictive one.

Current Phase 3 note: the local launcher truthfully reports `observe_only`. Semantic filesystem,
structured process, network-probe, and configured secret-interface requests are enforced when
routed through their brokers. The Endpoint authorization model and native API adapter are built
and simulated but not installed, signed, or entitled, so arbitrary child behavior still does not
satisfy the OS-enforcement portion of invariants 1, 3, 4, and 11. This is not a containment
boundary.

## Where each invariant stands locally

For brokered requests in `vigil-local`. "Enforced" here always means *for requests that pass
through a broker*; a process that goes around the brokers is unaffected by any of it.

| # | Local status | Held up by |
|---|---|---|
| 1 | Enforced | `default-deny-outside-workspace`; unknown actions fail parsing |
| 2 | Enforced | leases scope action, resolved resource, uses and lifetime (ADR 0017) |
| 3 | **Not satisfied** | structural only — see below |
| 4 | Partial | provenance propagates through the process graph; authority does not propagate, but nothing stops a child bypassing the brokers |
| 5 | Enforced | `capability_leases.delegable CHECK(delegable = 0)` — a database constraint, not a convention |
| 6 | Enforced | expiry is a SQL predicate, not a status column; revocation and exhaustion are immediate (ADR 0017) |
| 7 | Enforced | approvals bind `sha256(session, action, resolved_resource)`; the grant chooses uses and TTL only |
| 8 | Enforced | atomic `BEGIN IMMEDIATE` reservation plus `CHECK(consumed + reserved <= limit_value)` (ADR 0006) |
| 9 | Enforced | risk degradation is purely subtractive and monotone (ADR 0018); a new session on a recently contained workspace inherits elevated standing, so containment is not shed by restarting (ADR 0033) |
| 10 | Enforced | no detector, lease, or approval can produce a permit from a denial |
| 11 | **Not satisfied** | the state database is owner-only, which an agent running as the same user can still write |
| 12 | Enforced | SQLite persists across agent exit; ended sessions stay queryable, and the event log is hash-chained so an edit or deletion is evident (ADR 0019) |
| 13 | Enforced | invalid profile or unresolvable workspace refuses to start a session |
| 14 | Enforced | `vigil status` and `vigil doctor` report `OBSERVE ONLY` and `os_enforcement: false` |
| 15 | Partial | `VIGIL_CORRELATION_SESSION_ID` is a hint, never identity; but a local session ID is a lookup key any local process can guess or read |
| 16 | Enforced | `Decision::combine`; locally, `DecisionOutcome::restrictiveness` with exhaustive monotonicity tests |

### Invariant 3 in particular

`grant_approval` requires an `ApproverIdentity` that no broker module can construct, and a test
asserts no broker source references the grant path. That prevents a refactor from opening the path
by accident. It does **not** prevent a deliberate attacker: with no `vigild` and no authenticated
IPC, an agent that can execute code runs as the same user and can invoke `vigil approvals grant`
itself. Invariant 3 is not satisfied at the operating-system level and must not be described as
satisfied until an entitled, signed daemon owns the approval store and authenticates its callers.
See ADR 0017 and `TRUST_BOUNDARIES.md`.
