# Fail-closed matrix

This page defines failure semantics. For the canonical implementation and activation status of
each boundary, see [ENFORCEMENT_STATUS.md](ENFORCEMENT_STATUS.md).

What happens to a managed agent session, and to the rest of the machine, when a VIGIL component
fails.

Two rules govern every row:

1. **A managed session fails closed.** If a control a session's profile depends on is unavailable,
   the session loses the authority that control was bounding — it does not proceed unbounded.
2. **The rest of the host is unaffected.** VIGIL constrains agents running under a human's
   authority. It is not a machine-wide chokepoint, and a VIGIL failure must never become a
   host-wide denial of service. This is why the Endpoint Security fast path allows unattributed
   processes (ADR 0012): an outage stops VIGIL from bounding agents, not from letting the user work.

## Local control plane

| Failure | Managed session | Rest of host |
|---|---|---|
| State database unreadable or corrupt | Session cannot start; brokered requests fail. No decision is made without durable evidence. | Unaffected |
| State database read-only or out of space | Reservation fails, so the operation it was bounding never runs. | Unaffected |
| Schema newer than the binary | `LocalStore::open` refuses rather than downgrading; no session runs. | Unaffected |
| Invalid profile or unresolvable workspace | Session refuses to start. | Unaffected |
| Workspace path resolves inside a protected category | Session refuses to start. | Unaffected |
| Budget dimension exhausted | The request is denied; the operation does not run. | Unaffected |
| A reservation cannot be reconciled after a side effect | The reservation stays held. Authority shrinks, and the discrepancy is recorded as `budget.reconciliation_failed`. | Unaffected |
| Risk state unreadable | Authorization fails; no request proceeds on an unknown risk state. | Unaffected |
| Lease store unreadable | No lease is found, so `REQUIRE_APPROVAL` stands. Failure denies. | Unaffected |
| Approval store unwritable | The approval cannot be recorded, so the request stays refused. | Unaffected |
| No operator answers a pending approval | The capability is never granted. The request expires after 15 minutes and must be asked again. | Unaffected |
| Approval expires between grant and use | The lease expiry predicate refuses it. No sweeper is needed. | Unaffected |
| A live PID is already claimed in the graph | The process is terminated and the spawn is refused rather than misattributed. | Unaffected |
| Event chain head unreadable | The append fails, so the operation it was recording does not proceed unrecorded. | Unaffected |
| Event chain does not verify | `vigil audit verify-local` exits non-zero and names the first disagreeing record. Enforcement continues — a tampered *past* does not license an unbounded *present*. | Unaffected |
| Detection rule catalogue has no rule for a label | No detection fires and no risk is loaded. The decision itself is unaffected: detections describe, they do not authorize. | Unaffected |
| Incident cannot be opened | The response fails and is reported. Risk degradation has already taken effect independently. | Unaffected |
| MCP server not registered | Every call is refused. Extracted resources remain attributable, but the call cannot spend a lease or raise an approval. | Unaffected |
| MCP tool not registered or call has no extractable resource | The call is refused because no trusted action/resource pair exists to authorize. | Unaffected |
| MCP resource exceeds the tool's declaration | The call is refused and a scope-escape detection loads risk. The declaration still cannot grant the resource by itself. | Unaffected |
| One resource in an MCP lease batch is missing or expired | The transaction rolls back every staged lease decrement; only missing resources raise approvals and the call remains refused. | Unaffected |
| MCP server quarantined | Every call is refused before its arguments are considered. | Unaffected |
| MCP tool manifest unreadable | The sync fails; the last known baseline stands, so drift is still measured against something. | Unaffected |
| MCP tool manifest drifts | Differences are returned, but staged changes roll back; observing drift never replaces the trusted baseline. | Unaffected |
| MCP stdio executable or observed binary hash missing | Registration is refused. A legacy row missing either field also cannot authorize calls. | Unaffected |
| MCP HTTP/unknown transport identity unavailable | Registration is refused until authenticated endpoint and publisher identity exist. | Unaffected |
| No observations supplied to a reconciliation | Reported as `NO_OBSERVER` and exits non-zero. An unwatched session is never reported as consistent. | Unaffected |
| Reconciliation finds a denied operation was observed | Critical detection, session quarantined, incident opened. This is the one finding that proves the broker was bypassed. | Unaffected |
| Preimage cannot be captured before a write | The write is refused. An irreversible change is not made because the record of how to reverse it could not be written. | Unaffected |
| A file changed after VIGIL wrote it | Rollback refuses that path rather than clobbering a change VIGIL did not make, and exits non-zero. | Unaffected |
| Prior content above the preservation limit | The write proceeds; the preimage is recorded as non-restorable with the reason, rather than silently absent. | Unaffected |
| A stored preimage blob is corrupt | Verified against its own digest before restore; a mismatch refuses rather than writing arbitrary content to disk. | Unaffected |
| Rollback attempted on a running session | Refused — a live session could overwrite what was just restored. | Unaffected |
| Canary placement outside the workspace or in a protected location | Refused. Deception never contaminates real credential storage. | Unaffected |
| Repository configures Git to run a program | Overridden unconditionally by `-c`, hooks redirected to an empty directory. Nothing executes; the key names are reported. | Unaffected |
| Git exceeds its 30s bound | The child is killed and the operation reports failure rather than hanging the caller. | Unaffected |
| A push remote's host is not in the profile allowlist | Refused. Being permitted to push is not permission to push anywhere. | Unaffected |
| Network flow has no hostname or uses an IP literal | A managed `PROMPT`/`ENFORCE` flow is withheld; hostname authority cannot be bypassed. | Unaffected |
| Network flow resolves to a private/local address or outside its pinned set | The managed flow is denied as destination-integrity failure. | Unaffected |
| Network resolution lease expires or clock is unavailable | The managed flow is denied until fresh compact policy is installed. | Unaffected |
| Network flow or distinct-destination budget is exhausted | Further managed flows are denied; counters cannot overrun or reset on policy refresh. | Unaffected |
| Network policy snapshot is malformed or rolls generation backward | Installation is rejected atomically and the last valid generation remains active. | Unaffected |
| Network policy signature/key/instance is invalid | Authentication fails before payload decoding; no state is installed. | Unaffected |
| Whole network policy lease expires or its clock is unavailable | Managed flows are denied with forced enforce semantics, even if the last mode was `OFF` or `OBSERVE`. | Unaffected |
| Network policy transport is missing, symlinked, oversized, insecure, or corrupt | Reload fails and activates no new state; the callback never reads the transport directly. | Unaffected |
| Network generation persistence fails or the same generation names different envelope bytes | Installation stops before activation. A restart may restore only the exact envelope committed at the durable replay floor. | Unaffected |
| Network filter preferences fail to load/save/remove or do not round-trip exactly | The containing app reports failure or configuration drift; it never claims the filter is enabled. | Unaffected |
| Network filter preference operation times out | The outcome is reported unknown and that controller instance refuses every subsequent operation, preventing a blind mutation retry. | Unaffected |
| Any network enforcement health signal is missing | `FULLY ENFORCED` is impossible. An inactive/unknown extension reports `OBSERVE ONLY`; missing downstream evidence reports `DEGRADED`. | Unaffected |
| Network provider/flow evidence is stale, future-dated, expired, or generation-mismatched | Health reports `BROKEN`; prior observations cannot authorize a current protection claim. | Unaffected |
| Entitled allow/deny probe has the wrong outcome | Health reports `BROKEN`, including when the denied destination is reachable. | Unaffected |
| Provider-health attestation is forged, malformed, oversized, wrong-instance/provider, or signed by an unknown key | Verification rejects it before health fields are trusted; ready evidence cannot be constructed. | Unaffected |
| Provider-health transport is missing, symlinked, oversized, insecure, partial, or tampered | The reader returns no verified health. Publication is atomic and never runs in the flow callback. | Unaffected |
| Provider-health Keychain state is unavailable, corrupt, or races creation | Provider startup fails; corrupt state is never overwritten and a creation loser reloads the winning identity. | Unaffected |
| Provider-health publication has no current policy or trustworthy clock | No attestation is published; failure counters advance and health cannot become ready. | Unaffected |
| Provider-health enrollment is missing, malformed, wrong-instance/provider, or cannot authenticate fresh health | No trust pin or ready evidence is created. | Unaffected |
| An enrolled provider-health identity changes or the host pin is corrupt | Automatic rotation is refused and health remains unavailable pending explicit recovery. | Unaffected |
| The durable network installation identity is missing, malformed, or races creation | Runtime construction fails or reloads the winning insert; it never replaces corrupt identity or verifies another installation's health. | Unaffected |
| Network policy-signing Keychain state is unavailable or corrupt | Bootstrap publication and preference enablement stop; no embedded or replacement key is used. | Unaffected |
| Bootstrap policy publication fails before filter configuration | Preferences are not mutated; a provider is never pointed at policy that was not durably committed. | Unaffected |
| Automatic network-policy maintenance sees an inactive extension or non-exact preferences | No new generation is published. Maintenance cannot preserve authority for an inactive, disabled, or drifted filter. | Unaffected |
| Provider policy reload fails, observes no clock, or sees incoherent durable state | The last verified snapshot remains active only until its signed exclusive expiry; no authority is extended and managed traffic then fails closed. | Unaffected |
| System clock moves backwards | Expiry uses `max(wall, high water)`, so expired leases and approvals stay expired. A material regression fires `VIGIL-L032`. | Unaffected |
| System clock moves far forward | Leases and approvals expire early. Fails safe, and is not detected — see ADR 0030. | Unaffected |
| Clock state row is unreadable | The reading falls back to the wall clock for that call; monotonicity is lost until it is readable again. | Unaffected |
| A file changes identity between the decision and the open | The read is refused before any content is returned; device and inode are compared against the opened handle (ADR 0031). | Unaffected |
| A directory changes identity during a write | The rename is refused, so approved content is never placed somewhere policy did not see. | Unaffected |
| An executable changes identity between validation and spawn | The execution is refused and `VIGIL-L033` fires; the binary that was checked is not the one that would have run (ADR 0032). | Unaffected |
| An executable is too large to hash | It is still identified by device and inode; the provenance node records no content hash rather than a wrong one. | Unaffected |
| A new session starts on a recently contained workspace | It starts `ELEVATED`, so mutations need a human while reads continue. Containment is not shed by restarting (ADR 0033). | Unaffected |
| Sessions are cycled on one workspace to multiply budget | `VIGIL-L035` fires with the cumulative consumption, and the new session starts `ELEVATED` (ADR 0037). | Unaffected |
| Process identity cannot be confirmed | Termination is **refused**, not attempted. Killing the wrong process is worse than not containing an agent. | Unaffected |
| Evidence append fails after a process spawned | The child is terminated and the error returned. The budget stays committed — the side effect happened. | Unaffected |

## Controls that are not installed

These rows describe the current state of this repository, not a hypothetical outage.

| Missing control | Managed session | Rest of host |
|---|---|---|
| Endpoint Security extension (**not installed**) | `vigil run` reports `OBSERVE ONLY`. The child keeps the launching user's ambient macOS authority and can bypass every broker. | Unaffected |
| Network Extension (**not installed**) | The network broker probes payload-free and enforces destination policy only for requests routed through it. Direct sockets are unaffected. | Unaffected |
| `vigild` and authenticated IPC (**not built**) | Approvals, leases and risk are enforced in-process. Invariant 3 is not satisfied at the OS level: see ADR 0017. | Unaffected |
| Keychain provider: purposes beyond git (**not built**) | `KeychainSecretProvider` reads real Keychain items and authenticates to git remotes without the credential entering `argv`, VIGIL's files, or the event log (ADR 0042). HTTP authentication and artifact signing return an error rather than reporting a use that did not happen. A locked keychain prompts, and a prompt that never returns is a bounded failure. | Unaffected |
| OS-verified process identity (**not available**) | `vigil contain --terminate` stops the recorded process tree, verifying `(pid, start time, command)` immediately before each signal and refusing where it no longer matches (ADR 0041). Identity rests on a one-second-granularity start time, so it is evidence rather than proof; a process that escaped attribution is not in the graph and is not stopped. | Unaffected |
| OS observer for reconciliation (**not installed**) | Every reconciliation on a real session reports `NO_OBSERVER`. The engine works; nothing feeds it. | Unaffected |
| Rollback for non-brokered writes (**impossible**) | Not covered and reported as not covered. VIGIL never held those bytes; observing a write does not recover its predecessor. | Unaffected |
| MCP transport is contacted outside the proxy | Direct traffic is unmediated. Traffic routed through `vigil mcp proxy` receives argument authorization and live drift checks. | Unaffected |
| Checkpoint seed readable by the attacker | Checkpoints detect a wholesale rewrite by something with *database* write access (ADR 0040). An attacker who also reads the `0600` seed file can forge one; holding the seed off-host is what closes that. A chain with no checkpoint taken is as rewritable as before, and `vigil audit verify-local` says so rather than reporting an unqualified success. | Unaffected |

When the entitled half exists, the first two rows change meaning: a profile that *requires* OS
enforcement must refuse to launch when it is unavailable, rather than degrading to observation.
Until then the CLI reports the degraded posture prominently and never uses the words "protected",
"contained", or "enforced" for the launcher.

## Portable core

| Failure | Managed request | Rest of host |
|---|---|---|
| Policy engine error | Impact tier ≥ 2 fails closed; tiers 0–1 allow with constraints and a `DEGRADED_MODE_ALLOW` reason code. | Unaffected |
| Detector timeout or error | Converted to a non-zero-risk degraded result with `DETECTOR_DEGRADED`. A detector cannot fail *open*. | Unaffected |
| Audit sink write failure | The append is aborted rather than acknowledged unchained. | Unaffected |
| Telemetry export unavailable | Local enforcement continues. Export is never on the decision path. | Unaffected |
| No network / fully offline | Local enforcement continues. Nothing in the authorization path makes a remote call. | Unaffected |
| Nonce store unavailable | Capability verification fails, so replay protection denies rather than skips. | Unaffected |
