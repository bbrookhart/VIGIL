# Incident response

## When an incident opens

Automatically, when a critical detection fires or a session reaches a containing risk state. One
session has at most one open incident — a second alarming thing joins the investigation already
under way. Or manually: `vigil contain <session>`.

## Triage, in order

```console
vigil incidents list
vigil incidents show <incident-id>          # timeline; every line backed by a stored record
vigil detections --session <session-id>
vigil risk <session-id>                     # which dimensions, and why
vigil capabilities <session-id>             # what it holds, what was revoked
vigil processes <session-id>                # what it launched
vigil audit verify-local                    # is the evidence itself trustworthy?
```

Run `audit verify-local` **first** if you suspect the agent reached the control plane. If the
chain does not verify, everything below it is suspect and the investigation changes character.

## Reading severity and confidence

They are separate axes on purpose. `CRITICAL`/`MEDIUM` means "this would be very bad if real, and
we are not certain" — a canary hit, which a recursive search can also cause. `MEDIUM`/`HIGH` means
"we are sure, and it is not an emergency". Do not sort by severity alone.

Three rules can quarantine a session on their own evidence, because each is unambiguous:

| Rule | What it means |
|---|---|
| `VIGIL-L003` | The agent reached for VIGIL's own configuration or evidence. |
| `VIGIL-L011` | The binary behind a trusted MCP server was swapped. |
| `VIGIL-L013` | VIGIL refused an operation and the OS observed it happen — **the broker was bypassed**. |

`VIGIL-L013` is the one that changes what you are dealing with. Everything else means the semantic
layer was incomplete; this means it was defeated.

## Containment

```console
vigil contain <session-id>              # revoke capabilities, withhold everything but reads
vigil contain <session-id> --quarantine # withhold everything
vigil contain <session-id> --seal       # and end the session
```

Responses are idempotent; re-running one reports `already_applied` rather than acting twice.

**Nothing here terminates a process.** Killing safely requires certainty that the PID still
belongs to the process VIGIL recorded, which needs OS-verified process identity this build does
not have. Containment withholds authority from brokered requests; a process already running is
unaffected. If you need it stopped, stop it yourself — and treat the fact that VIGIL could not as
part of the incident.

## Undoing damage

```console
vigil rollback <session-id> --dry-run
vigil rollback <session-id>
```

Covers **broker-mediated writes and deletes only**. Anything a process wrote directly was never held by VIGIL
and cannot be restored. A file that changed after VIGIL wrote it is refused rather than clobbered,
and the command exits non-zero if anything was refused — read those reasons; they are the
interesting part.

## Evidence

```console
vigil incidents export <incident-id>
```

Writes `<incident-id>.vigilincident`, mode `0600`: incident, session, detections, responses, risk
history, leases, approvals, budget, process graph, event log, and a chain verification result.

**Metadata only.** No file contents, argument values, or secret material — a bundle full of the
user's data would itself be worth stealing. If you need content, collect it deliberately and say
so, rather than expecting the bundle to have kept it.

Seal the incident when you are done: `vigil incidents seal <incident-id>`.

## What an incident cannot tell you

Whether the agent did anything outside the brokers. With no Endpoint Security extension installed,
`vigil reconcile` reports `NO_OBSERVER`, and that is not a clean result — it means nothing was
watching. Treat the absence of findings as absence of visibility, not absence of activity.


## Cross-session patterns

`vigil analyze <session>` also looks across sessions. `VIGIL-L026-LAUNDERING` fires when a
resource one session was refused is then requested by a different one — the shape of an agent
that cannot do something arranging for another principal to do it instead.

Read the confidence, which is `MEDIUM` for a reason: VIGIL can see that a refusal in one session
was followed by the same request in another. It **cannot prove one caused the other**, and the
evidence says `causation_established: false`. Two agents working the same repository can both
reach the same protected path without either laundering anything. Treat it as a reason to look at
both sessions, not as a finding about either.
