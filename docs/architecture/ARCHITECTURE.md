# VIGIL Control Plane architecture

**Status:** Phase 1–2 foundation, Phase 3 Endpoint fast path/adapter, Phase 4 network fast path/adapter,
Phase 6 detection/
response, Phase 7 MCP security, intent-execution reconciliation, and Phase 8 integrity,
rollback and deception — EXPERIMENTAL  
**Platform target:** Apple Silicon macOS  
**Current effective posture:** OBSERVE ONLY for directly launched processes

VIGIL treats an agent as an untrusted principal acting for a human within a bounded task. It
does not equate possession of the user's login session with authorization.

## Layers

```text
Agent adapter / vigil run
          │ semantic request + correlation
          ▼
Portable Rust core
  identity · provenance · policy · remit · risk · capabilities
          │ signed, resource-bound authority
          ▼
Gateway / semantic brokers                 [built: tool, filesystem, process, network probe,
                                             secret interface/simulator]
          │
          ├────────► Local session store   [built: SQLite/WAL]
          │
          ▼
vigild                                      [planned]
          │ compact precompiled state
      ┌───┴────────────────┐
      ▼                    ▼
Endpoint Security      Network Extension   [both data-path adapters built;
                                             installable targets planned]
      │ EXEC/OPEN/CREATE/   │ flow verdicts
      │ RENAME/UNLINK       │
      └──────────┬──────────┘
                 ▼
              macOS
```

The security model requires dual enforcement. Semantic brokers know the requested tool,
arguments, task, capability, and resource. OS adapters observe the executable, process
lineage, file object, and network flow. Neither view substitutes for the other. The
Intent–Execution Reconciliation Engine correlates them; see below.

## Current vertical slice

`vigil run` validates a named profile and a real directory, creates a random `ags_...` session,
appends session/process lifecycle events to SQLite, launches the command, and seals its final
state. `vigil session show` reconstructs the timeline. The environment correlation value is
explicitly advisory and is never accepted as identity.

`vigil policy evaluate` resolves an existing path—or the deepest existing ancestor for a new
write—through the filesystem. This catches symlink escape and path-prefix confusion. Protected
credential, persistence, Keychain, and VIGIL storage roots are denied independently of the
workspace. OS enforcement must later reconcile the semantic path with the file macOS actually
opens to close remaining TOCTOU races.

Reusable `semantic_enforced` sessions initialize durable per-dimension limits. The filesystem
broker performs `reserve → authorize → execute → commit/refund`, writes through a same-directory
temporary file and atomic rename, and stores only operation metadata—not file content. Policy or
budget denial occurs before filesystem I/O. Failed I/O refunds its reservation. If accounting
cannot be reconciled after an operation occurred, the reservation remains held and the operation
is reported as failed rather than creating uncounted authority.

An executable path is not an executable. The broker takes the object's device and inode at
validation, hashes its contents when it is small enough, re-checks the identity immediately before
spawning, and records the hash in the provenance node — so the graph says *what ran* rather than
only where it was. Code signature is not checked: that needs a native API, and it belongs with the
adapter that already checks code requirements. See ADR 0032.

The structured process broker accepts an absolute program path, argument vector, workspace CWD,
four-key environment allowlist, and a timeout capped at 30 seconds. It performs no PATH lookup or
shell parsing, clears the inherited environment, rejects set-id executables, captures and drains
stdout/stderr with 1 MB return bounds, and consumes the durable `process_executions` budget only
after a successful spawn. Enforced profiles currently permit only exact-path, side-effect-free
data utilities. Shells, interpreters, network clients, credential/persistence/privilege tools,
workspace executables, and unknown binaries are denied or approval-bound.

This is semantic enforcement only. A process can bypass the brokers with direct OS calls;
Endpoint Security remains the required second enforcement point.

Within the broker, an operation is bound to the *object* rather than the name: a read captures
device and inode before opening and compares them against the open file handle, and a write
rechecks the parent directory's identity immediately before the rename. A path is not an identity,
and without this a symlink dropped in place between the decision and the open would return content
policy never approved while the event recorded the approved path. This narrows the race to
stat-to-open and makes it detectable; it does not eliminate decide-to-open, which needs `openat`
against a held directory handle and therefore `unsafe`. See ADR 0031. Process timeout
currently terminates only the direct child, so unrestricted process classes remain unavailable
until OS process-tree attribution and termination exist.

The basic network broker is intentionally a payload-free TCP probe. It normalizes an explicit
hostname/port, applies an exact profile allowlist before DNS, validates every resolved IPv4/IPv6
address, rejects direct-IP egress and private/local/metadata/special-use resolution in enforced
profiles, opens and immediately closes the connection, and records zero application bytes. A
simulated event source provides hermetic positive, negative, port, rebinding, IPv4/IPv6, failure,
and budget tests. The system source bounds caller-visible DNS/connect time, but it is not a Network
Extension and cannot intercept sockets opened elsewhere.

The Phase 4 `vigil-network` crate is the deterministic flow-policy contract used by the native
Network Extension adapter. It binds a full audit-token process identity to exact hostname, protocol, port,
approved public IP set, and exclusive resolution expiry; direct IP, rebinding, private/local
address, stale resolution, and exhausted flow/destination budget all fail closed for managed
processes. `OFF`, `OBSERVE`, `PROMPT`, and `ENFORCE` have distinct decision semantics. Strict
snapshots install only at a newer generation, and refresh preserves spent budget. A simulator
proves these rules without entitlement. A public `NEFilterDataProvider` subclass compiles and
verifies the exact domain-separated, instance-bound Ed25519 snapshot generated by Rust. The
protected out-of-band publisher and installable target are not built, so this is still not
installed enforcement. See ADRs 0035–0036 and the
[Network Extension model](NETWORK_EXTENSION_MODEL.md).

The secret broker completes the Phase 2 interface without pretending native custody exists. A
trusted precompiled grant binds profile, opaque handle, fixed use purpose, and exact target before
provider access. The provider performs the operation and can return only success/failure; its
error text is discarded, raw export always denies, and events contain no secret material. A
successful use consumes `brokered_secret_uses`; provider failure refunds it. The shipped provider
is simulation-only, and the CLI exposes status rather than an ad hoc secret-use command. Native
Keychain custody, signed grant loading, and authenticated IPC remain later work.

## Approvals, leases, risk, and provenance

The profile ladder produces `REQUIRE_APPROVAL` for capabilities a profile will not grant on its
own. That outcome now leads somewhere. `crates/vigil-local/src/authorize.rs` is the single seam
where a profile decision meets the session that made the request, and it runs three steps in an
order that is load-bearing:

1. the profile ladder, unchanged by session state;
2. the **lease upgrade**, which may raise `REQUIRE_APPROVAL` to `ALLOW` and may never touch a
   `DENY`;
3. **risk degradation**, which is purely subtractive.

Keeping this in one place is deliberate: three brokers each re-deriving the order is three chances
to get it wrong.

An approval binds `sha256(session, action, resolved_resource)`. Granting it mints exactly one
lease over that same triple, with a lifetime and use count the operator chooses within fixed
ceilings — the operator decides whether, not what. Leases expire by SQL predicate rather than by a
status column, are use-counted by a single atomic statement, and carry a `CHECK(delegable = 0)`
that makes non-delegability a property of the database. See ADR 0017.

Risk is twelve named dimensions and a documented threshold function over them, not one opaque
score; `vigil risk` prints the dimensions behind the state. It is monotone within a session, and
only denials that already carry a detection label load it, so ordinary refusals do not creep a
session toward containment. Reaching `CONTAINED` or `QUARANTINED` revokes outstanding leases in the
same transaction that records the transition. See ADR 0018.

Repeating a refused request is itself a signal: an identical pending request returns the existing
row rather than creating a second, and re-asking for something a human already denied loads the
policy-evasion dimension until the capability is withheld outright. At that point the agent stops
reaching the operator at all, so approval fatigue stops being a usable pressure tactic.

Process lineage is durable. Every process VIGIL launches — the child of `vigil run`, each child of
the process broker — becomes a node with an opaque `node_id`, a parent pointer, and a generation.
A partial unique index over live PIDs refuses to let two live nodes in one session claim one PID,
so a recycled PID becomes a separate node rather than inheriting an identity.

That graph is what `vigil contain --terminate` walks. Each node carries the kernel's start time and
command as read at spawn, and termination re-reads them immediately before signalling: a PID whose
identity no longer matches is left running and reported rather than killed (ADR 0041). Children are
stopped before their parents, so nothing is orphaned to `launchd` mid-pass.

The graph still bounds what can be reached. Nothing here observes grandchildren or any process
VIGIL did not start, so an absence in the graph is not evidence of absence, and a process that
escaped attribution is not stopped.

None of this is OS enforcement. Degradation withholds authority from *brokered* requests; a process
that bypasses the brokers is unaffected. Termination reaches what VIGIL recorded, but a
one-second-granularity start time is evidence of identity rather than proof of it, and the
OS-verified identity that would make it proof still requires the entitled half of the product.

## Detections, incidents, and response

Denials that name a detection produce one, from a fixed catalogue of twelve rules across
`crates/vigil-local/src/detection.rs` and `mcp.rs`. Each rule carries a severity and a *separate* confidence —
"how bad if real" and "how sure it is real" are different questions — plus the Agentic Runtime
Security Tactic it belongs to and the risk weight it loads. Rules are Rust constants rather than a
scripting surface: a detection rule that could execute code would be a way to run code inside the
security control.

Every rule fires from a decision VIGIL actually made. Two tests hold the correspondence closed in
both directions, so a label cannot exist without a rule and a rule cannot exist that no label
reaches. Behaviour VIGIL cannot observe locally has no rule at all rather than one that never
fires.

A critical detection, or a session reaching a containing risk state, opens an incident. A partial
unique index allows one open incident per session, so a second alarming thing joins the
investigation under way. Responses — revoke capabilities, restrict, quarantine, seal — are named,
idempotent, and recorded even when they changed nothing. `vigil incidents show` renders them as a
timeline in which every line is backed by a stored record rather than narrated prose, and
`vigil incidents export` writes a metadata-only evidence bundle.

Process-tree termination is not among the responses. Killing a process safely requires certainty
that the PID still belongs to the process VIGIL recorded, which needs OS-verified process identity
this build does not have; the command is `vigil contain`, not `vigil kill`, and says so.

The event log is hash-chained. Each event's link commits to its sequence number, its content, and
its predecessor, so editing a record, deleting one, or reordering two all fail
`vigil audit verify-local`. This is tamper-*evident*, not immutable: anything that can write the
database can rewrite the whole chain, and no signed checkpoint yet anchors the head.

## MCP security

An MCP server is a program the agent asks to act on its behalf, which makes it a confused deputy
by construction. The obvious design — a map from tool name to permitted capability — fails against
the threat it is meant to cover, because the tool name is a string the server chooses.

So `crates/vigil-local/src/mcp.rs` authorizes the *arguments*. Every string in a call that could
denote a path or a URL is extracted and decided independently through the same path a direct
broker request takes, whatever the tool is called and whatever it declared. One refusal refuses
the whole call: a tool touching four allowed paths and one protected one does not get to perform
the four.

Declared capabilities are recorded and compared, but they never grant. A tool declaring every
capability in the vocabulary is still refused when it reaches for a protected credential;
reaching beyond its declaration is both detected and refused. Server registration, tool
registration, and at least one extractable action/resource pair are prerequisites, so an empty
resource walk cannot become a fail-open allow.

Server identity is the operator-chosen name **and** the SHA-256 of the binary behind it, computed
by VIGIL rather than asserted by the caller. Re-registering a name over a different binary is
refused. `vigil mcp sync` compares presented tools against the recorded baseline and reports tools
added or removed, schemas changed, descriptions changed, and capabilities newly claimed —
description drift on its own, because the description is what an agent reads when deciding to call
a tool. Drifted manifests are rolled back instead of replacing the baseline. Substitution carries
enough weight to quarantine a session by itself.

Only local stdio servers can currently be trusted, and they require an exact executable path plus
an observed digest. HTTP and unknown transports fail registration until authenticated remote
endpoint and publisher identity are implemented. Authorization rechecks identity completeness, so
a legacy database row missing its executable or digest also fails closed.

This is the security core, not a transport proxy. Nothing speaks JSON-RPC or intercepts live MCP
traffic; a server an agent contacts directly is unobserved. See ADR 0020.

## Intent-execution reconciliation

`crates/vigil-local/src/reconcile.rs` answers the second question the two enforcement points
exist for: not *should this be permitted*, but *did what happened match what was asked for*.

Declarations are read back from the hash-chained event log, so a reconciliation runs long after a
session ended and can be replayed by a reviewer who was not there. The comparison itself is a pure
function — same inputs, same findings, same order, no database.

Five classes, ordered by what they prove. `DENIED_OPERATION_OBSERVED` is categorically different
from the other four: they mean the semantic layer was *incomplete*, it means the layer was
*defeated* — VIGIL said no and the operation happened anyway. It quarantines a session on its own.
`RESOURCE_MISMATCH`, `UNDECLARED_SIDE_EFFECT`, `CHILD_PROCESS_MISMATCH`, and `SCOPE_EXPANSION`
cover the rest, with workspace-internal expansion kept separate from reaching outside so the
severe finding is not buried in the mild one. An operation the OS *refused* is not a mismatch:
counting a blocked action as a divergence would report the system working as a failure.

The load-bearing decision is what an empty result means. With no installed extension, no
observations means *nothing was watching*, not *nothing happened*. `Coverage` distinguishes the
two, `consistent()` is always false without an observer, and `vigil reconcile` exits non-zero and
prints an explicit `NO OBSERVER` block. See ADR 0024.

`ObservedOperation` is not tied to Endpoint Security. Today its producers are the `vigil-endpoint`
simulator and fixtures; an entitled extension becomes a third producer and the engine is unchanged.

## Rollback and deception

Before a managed write the broker records what the file was — content addressed by SHA-256, or
the fact that it did not exist — plus the **postimage** it is about to leave behind.
`vigil rollback` walks those newest-first, so a file written three times unwinds to its state
before the first write.

Two properties keep rollback from becoming destructive in its own right. A restore refuses unless
the file still matches the recorded postimage, because otherwise something else has written it and
restoring would discard a change VIGIL knows nothing about. And a stored blob is re-verified
against its own digest before being written back, so a corrupted blob store cannot become a way to
place arbitrary content on disk. Refusals are never silent: the command exits non-zero.

Coverage is exactly as wide as broker coverage and every report says so. Endpoint Security will
not widen it — observing a write tells you it happened, not what the bytes were beforehand.

Deception places synthetic assets that exist only to be touched. They go **only** inside the
session workspace: placement is refused outside it and in every protected category, resolved
through the filesystem so a symlink cannot get there either. Content carries the `VIGILCANARY`
marker and grants nothing anywhere. The detection fires on an *allowed* read — a canary is an
ordinary workspace file, so a subsystem that only inspected denials would miss every hit — and is
rated `CRITICAL`/`MEDIUM`, containing rather than quarantining, because a legitimate recursive
tool can sweep a workspace. See ADR 0025.

## Git broker

Git is the highest-leverage tool a coding agent touches and a confused deputy with an unusually
large mouth: **Git configuration executes programs**. `core.pager`, `core.editor`,
`core.sshCommand`, `credential.helper`, `filter.*.clean`, every `alias.*`, and hooks in
`.git/hooks` all run commands. An agent that can write files in a workspace can write
`.git/config`, so in a repository it controls a plain `git status` is a code-execution primitive.

Every invocation is therefore built with `-c` overrides for each execution-bearing key — applied
*unconditionally*, because inspecting the repository first is a race against a file the agent can
rewrite. `core.hooksPath` points at a fresh empty directory, `GIT_CONFIG_NOSYSTEM` and a redirected
`HOME` remove system and user config, the environment is otherwise cleared, and no caller-supplied
value may begin with `-` (a branch named `--upload-pack=…` would otherwise be parsed as an option).
A live test rigs a repository with five executable keys and a hook, runs five operations without
the payload firing, and a control proves the same payload *does* fire when Git is invoked naively.

Capabilities split by reach: status/read/stage are local; commit is a workspace mutation; push is
egress, so it is approval-bound *and* its remote host goes through network destination policy, with
the lease bound to `git:push:<remote>:<branch>`; force-push is denied in every enforcing profile;
`git.config` and `git.remote_modify` are denied because they change what every later command does.
See ADR 0026.

## Local IPC

An agent does not need the network to escalate. `$SSH_AUTH_SOCK` uses the user's keys without
reading them; a container socket is root-equivalent without a privileged executable. Both are in
the protected registry (`local_ipc_escalation`), denied in every enforcing profile, and fire
`VIGIL-L031`.

The registry is consulted against the requested path *before* resolution as well as against the
resolved path after it. Resolution can fail for a path whose ancestors are absent or untraversable,
and without the earlier check that produced a generic invalid-path denial carrying no detection —
so probing for a Docker socket on a machine without Docker fired nothing at all. The pre-resolution
check can only make a decision more restrictive, and does not replace the resolved-path check,
which is the one that sees through aliasing.

## Deadline-safe macOS design

The `vigil-endpoint` crate now implements bounded precompiled policy, audit-token attribution,
exec/open/create/rename/unlink decisions, fork/exit transitions, per-message deadline guards,
sequence-gap detection, latency/drop metrics, and deterministic replay. The Swift
`MacOSEndpointSecuritySource` compiles against the installed public SDK for AUTH_EXEC, AUTH_OPEN,
AUTH_CREATE, AUTH_RENAME, AUTH_UNLINK, NOTIFY_FORK, and NOTIFY_EXIT; it projects owned values,
responds with the event-appropriate API, and never caches a verdict. A bounded Swift policy state
accepts only monotonically versioned snapshots and mirrors process/path attribution decisions for
the native callback. Rust signs canonical snapshot bytes with an installation-bound Ed25519
envelope; Swift verifies the signature before strict decoding and fast-path validation. Neither
side performs SQLite I/O, network calls, UI work, policy compilation, logging, or model inference
inside authorization.

Outside the authorization callback, the native adapter implements a bounded
`vigil.endpoint-control/v1` install/bind/health layer and XPC dictionary bridge. It obtains the
sender's dynamic code object from the message's kernel-attached audit token with
`SecCodeCreateWithXPCMessage`, checks a configured code requirement, and only then dispatches the
request. Installation is atomic and acknowledged after the state swap.

`NativeXPCControlListener` owns start/stop, a serial queue, peer activation/cancellation, malformed
peer teardown, and a 64-peer bound. Its production mode uses public
`xpc_connection_create_mach_service`; its test mode creates an anonymous endpoint. The native check
sends a real request through that endpoint and successfully evaluates the sender's self-designated
code requirement from the kernel-associated message. Every peer has a validated refreshable idle
timer (30 seconds by default, bounded to 1–300 seconds in production). Only an authenticated
message refreshes it; wrong-identity peers receive a fixed rejection and are immediately removed.
`NativeXPCControlClient` separately bounds end-to-end requests, invalidates on timeout, and reports
that a timed-out mutation has an unknown outcome. A launchd-registered Mach service, signed daemon
target, and production requirement are not present.

The production control service also requires a durable generation store. It recovers the signed
policy high-water mark at startup and commits a newer value with file and directory fsync before
activating policy or acknowledging installation. Corrupt state fails startup. Because the record is
not a policy cache, a restarted extension remains unready until it receives a newer generation.

The ES source and control service share one fixed-size native metrics accumulator. Callback updates
perform no I/O or serialization; authenticated health snapshots expose latency, deadline headroom,
late/failed responses, verdict counts, and sequence loss. Metrics are diagnostic only and reset on
extension restart. Policy evaluation is checked against the deadline again immediately before the
response, so an allow cannot survive consuming the configured safety margin.

The signed snapshot expiry is retained in native fast-path state as an exclusive runtime lease.
Each managed authorization performs one bounded wall-clock read and denies if the clock is
unavailable or the lease has expired. Health reports the installed generation but becomes unready
at the same boundary. Unmanaged processes continue to allow so a daemon outage cannot deny the
entire host; new managed-root attribution is refused while policy is expired.

The control protocol also supports root registration with the complete 32-byte audit token, exact
session ID, and installed generation. It accepts no PID field, treats identical replay as
idempotent, rejects generation races, and prevents a token already assigned to one session from
being reassigned. A future daemon must obtain the token from a supported trusted launch/OS path;
agent-provided identity remains untrusted.

This is not yet an installed System Extension. Full Xcode, Apple entitlement approval, containing-
app activation, XPC Mach-service/daemon packaging, protected key and code-requirement provisioning,
and privileged-device testing remain Phase 3 work. Deadline misses and queue drops are security
health signals, not ordinary telemetry noise.

The network filter data provider accepts only an already authenticated compact `vigil-network`
snapshot. Rust signing and Swift verification are built; a future protected publisher will use a
supported configuration/shared-container mechanism because the public SDK makes the filter
control provider unavailable on macOS. The design does not assume unrestricted network, database,
or IPC access from the data provider. Distribution storage/notification is not yet implemented.

## Persistence

The local database uses SQLite WAL mode, foreign keys, prepared statements, bounded query
limits, indexed session/timestamp/decision/correlation fields, migrations, and owner-only
filesystem permissions. Budget counters and multi-dimensional reservations use immediate
transactions and database constraints preventing negative or over-limit state. Schema v3 adds
atomic first-use network destination claims: committed destinations are charged once, failed
first use releases the claim, and pending first use blocks a concurrent undercount. This event store
is not yet the signed audit chain; the portable `vigil-audit` crate remains the tamper-evident
evidence implementation.

## Failure posture

| Failure | Managed session | Rest of host |
|---|---|---|
| Invalid local profile/workspace | launch denied | unaffected |
| Local database unavailable | launch denied | unaffected |
| UI unavailable | policy continues when daemon exists | unaffected |
| Endpoint Security unavailable | enforced-profile launch must be denied; current build reports observe-only | unaffected |
| Network Extension unavailable | network-enforced profile must be denied; current build reports observe-only | unaffected |
| Cloud/export unavailable | local authorization continues | unaffected |

VIGIL is not a defense against a fully compromised kernel or omnipotent root attacker. It is
designed to reduce the ambient authority available to autonomous agents running for a user.
