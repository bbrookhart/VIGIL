# Capability model

A capability represents bounded authority for a principal to perform one class of action on a
resource. The normalized vocabulary includes filesystem, process, network, secret, Git, package,
system, UI, and VIGIL-administration capabilities.

```json
{
  "lease_id": "cap_...",
  "principal": "AgentSession::ags_...",
  "action": "fs.read",
  "resource": "/workspace/package.json",
  "expires_at": "...",
  "max_uses": 1,
  "delegable": false,
  "approval_id": null
}
```

`secret.use` and `secret.export` are intentionally distinct. Brokered use is preferred so raw
credentials never enter agent context. VIGIL administrative actions are not grantable to AI
agent principals.

Deletion is brokered like any other filesystem action: it consumes `file_deletes`, captures the
file's content as a restorable preimage *before* removing it, refuses directories because a tree is
a blast radius one delete does not account for, and is approval-bound under `untrusted-agent`.
Rollback of a deletion refuses if the path has been recreated, since restoring would overwrite
content VIGIL never saw.

The current local evaluator implements a conservative subset: filesystem actions, process
execution, network connection, secret use/export, persistence, and privilege. Unknown actions
fail parsing. Workspace reads/mutations are component-aware and symlink-aware; protected roots
deny independently. The structured process policy permits only a small exact-path set of
side-effect-free system utilities in enforced profiles. It binds canonical executable identity — device, inode, and content hash, re-checked before the spawn —
arguments, workspace CWD, an environment allowlist, timeout, session, and budget. Shells,
interpreters, network, credential, persistence, privilege, workspace, and unknown executable
classes deny or require future resource-bound approval. The payload-free network probe binds an
exact normalized hostname/port to profile data, validated public resolution, a connected peer,
and connection/destination budgets; unknown destinations require future scoped approval. The
secret broker interface requires an exact trusted profile/opaque-handle/purpose/target grant,
returns no secret bytes, consumes the brokered-use budget, and always denies raw export.
Persistence and privilege also deny.

Portable signed capability leases already enforce TTL, action binding, replay protection, and
gateway redemption. Local OS adapters will map those normalized capabilities to observed macOS
operations; authority will not silently inherit across child processes.

The experimental filesystem, process, network-probe, and secret-interface brokers bind authority
to a durable semantic session, profile, normalized resource/request, and budget reservation where
applicable. Local session IDs are correlation/lookup keys, not cryptographic bearer capabilities;
authenticated daemon IPC and signed local leases remain required before cross-process broker
access can be considered stable.

## Local capability leases

A local `REQUIRE_APPROVAL` decision is no longer a dead end. It records an approval request; a
human grants it; granting mints exactly one lease. A lease is the only thing that can satisfy a
`REQUIRE_APPROVAL`, and there is no API that mints one from a caller's say-so. See ADR 0017.

For a multi-resource MCP call, required lease uses are consumed in one immediate transaction. The
call consumes every bound use or none; a missing member rolls back earlier decrements before any
approval is raised. See ADR 0020.

```json
{
  "lease_id": "cap_…",
  "session_id": "ags_…",
  "approval_id": "apr_…",
  "action": "process.exec",
  "resource": "/usr/bin/uname",
  "issued_at": "…",
  "expires_at": "…",
  "max_uses": 1,
  "uses_remaining": 1,
  "delegable": false,
  "status": "active"
}
```

What binds it:

- **The triple.** An approval binds `sha256(session_id, action, resolved_resource)` in canonical
  JSON. The lease inherits action and resource from the approval — the grant command chooses only
  how many uses and for how long. An operator decides *whether*, never *what*.
- **The resolved resource.** Never the string the caller typed, so `~/w/../.ssh` cannot be
  laundered past authority granted for `~/w`.
- **Expiry against monotone time.** Comparisons use `max(wall clock, stored high water)`, so
  turning the system clock back cannot make an expired lease valid again (ADR 0030).
- **Expiry as a predicate.** Every statement that could act on a lease compares `expires_at`
  inline. An expired lease is inert immediately; no cleanup job is part of the security argument,
  and the stored row may still read `active`.
- **Non-delegability as a database constraint.** `CHECK(delegable = 0)` — a delegable lease cannot
  be stored, which is stronger than a code convention.
- **One statement per use.** Check-and-decrement is a single `UPDATE ... WHERE` inside
  `BEGIN IMMEDIATE`, so two concurrent callers cannot both spend the last use.

Ceilings match the portable capability tokens: at most 900 seconds, at most 64 uses, defaulting to
one use. A grant asking for more is refused rather than clamped.

A lease can raise `REQUIRE_APPROVAL` to `ALLOW`. It can never touch a `DENY`, and risk degradation
is applied *after* the lease, so a lease issued before a session was contained is worthless
afterwards. Reaching a containing risk state also revokes outstanding leases outright.

Inspect them with `vigil capabilities <session>`; decide requests with `vigil approvals`.

**This is not yet invariant 3.** Nothing in a broker can reach the grant path, but with no `vigild`
and no authenticated IPC an agent running as the same user can invoke the CLI itself. See ADR 0017
and `docs/security/SECURITY_INVARIANTS.md`.
