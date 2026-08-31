# Security model

## The claim, stated precisely

VIGIL constrains what an autonomous agent can do **through the interfaces it mediates**. It does
not constrain a process. That sentence is the whole model, and every honest statement about this
system is a consequence of it.

An agent that routes a request through a VIGIL broker gets a decision bounded by profile, risk,
budget, lease, and approval. An agent that opens a file descriptor directly gets whatever the
logged-in user could get. Closing that gap is what Endpoint Security and a Network Extension are
for, and neither is installed in this build.

## Principals

| Principal | Trusted for | Never trusted for |
|---|---|---|
| Human operator | Approving capability escalation; policy authorship | Nothing is assumed about intent — approvals are specific and expiring |
| Agent session | Nothing. It is the untrusted principal | Its own identity, its own risk state, its own budget, its own approvals |
| Child process | Nothing. Provenance propagates; authority does not | Any claim it makes about which session it belongs to |
| MCP server | Nothing. Every argument is attacker-controlled (T3) | Its tool names, its declared capabilities, its schemas |
| Secret provider | Performing an authorized operation | Returning secret bytes; its own error text |
| OS observer | Reporting what the kernel told it | Not present in this build |

## What holds a decision

Authorization is a fold, and every participant may only restrict:

```
profile ladder → lease upgrade → risk degradation
```

A lease can raise `REQUIRE_APPROVAL` to `ALLOW`. Nothing can turn a `DENY` into anything else.
Risk degradation runs last and only subtracts. Detectors, LLMs, MCP declarations, and tool names
are inputs to that fold; none can produce a permit. See ADR 0002, 0017, 0018.

## Where the boundaries actually are

`docs/security/TRUST_BOUNDARIES.md` is the authority. In summary, and stated as limits rather
than as features:

- **Agent → broker** is real for requests that pass through it, and bypassable by any process.
- **Agent → human approval** is structurally protected but **not a trust boundary on this host**:
  with no `vigild`, an agent runs as the same user and can invoke the CLI. Invariant 3 is not
  satisfied at the OS level.
- **Control plane → storage** is owner-only files, which an agent running as the same user can
  write. The event chain makes tampering evident, not impossible.
- **Root** is out of scope. VIGIL does not defend against a compromised kernel or an omnipotent
  root attacker, and must never require weakening SIP, Gatekeeper, or TCC.

## Local IPC is part of the credential surface

Protecting a credential *file* protects the wrong thing if the credential can be used without
reading it. Two cases matter on macOS:

- **The SSH agent.** A process that can reach `$SSH_AUTH_SOCK` authenticates as the user to every
  host the agent holds a key for, without ever opening `~/.ssh/id_ed25519`. Protecting the key and
  not the agent is a gap, not a control.
- **Container daemons.** Anything that can talk to a Docker, OrbStack, Colima, Lima, Podman, or
  containerd socket can start a privileged container with the host filesystem mounted. That is
  root-equivalent, and it involves no privileged executable and no `sudo`, so none of the
  process-broker checks see it.

Both are in the protected registry as `local_ipc_escalation`, denied in every enforcing profile,
and fire `VIGIL-L031` at a weight that contains the session on a single occurrence. Nothing a
workspace-scoped coding agent legitimately does reaches for them.

The registry is checked against the *named* path as well as the resolved one, so probing for a
socket that is absent on this machine still fires. The attempt is the signal, not whether the
target happened to be there.

## What VIGIL is good at

Bounding a *cooperative* agent — one using the tools it was given — to a task-scoped set of
capabilities, with quantitative limits, expiring authority, specific human approval, explainable
risk, and durable evidence. That covers the dominant realistic failure: a competent agent steered
somewhere it should not go by injected content (T1), which is OWASP's top agentic risk.

## What VIGIL is not good at yet

Stopping a *determined* agent that declines to use those tools. Until an entitled System Extension
is installed, a process can bypass every broker in this repository, and the reconciliation engine
that would catch it has nothing feeding it. `vigil status` reports `OBSERVE ONLY` and the word
"protected" is never used for the launcher.

## Failure posture

Every component fails toward less agent authority and away from host disruption. See
`FAIL_CLOSED_MATRIX.md` for the per-component table. The two rules: a managed session fails
closed; the rest of the host is unaffected.
