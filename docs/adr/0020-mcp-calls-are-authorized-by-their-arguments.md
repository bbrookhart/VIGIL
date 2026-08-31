# ADR 0020 — MCP calls are authorized by their arguments, not their names

**Status:** Accepted  
**Date:** 2026-08-30

## Context

An MCP server is a program the agent can ask to do things on its behalf. That makes it a confused
deputy by construction: the tool holds whatever authority its own process has, and the agent
supplies the arguments. `vigil-protocol` had defined reason codes for this surface —
`MCP_TOOL_DEFINITION_CHANGED`, `MCP_TOOL_DESCRIPTION_POISONED`, `MCP_EXCESSIVE_SCOPE`,
`MCP_SERVER_SUBSTITUTION` — since before this work, and nothing emitted any of them.

The obvious design is a capability map from tool name to permitted action: `filesystem.read_file`
maps to `fs.read`, and so on. That design fails against exactly the threat it is meant to cover.
A tool name is a string the server chooses. A malicious or compromised server that wants to write
`~/.ssh/config` simply calls its tool `read_file`.

## Decision

### Authorize every resource in the arguments, whatever the tool is called

`extract_resources` walks the entire argument document — not a declared argument name — and pulls
out every string that could denote a path or a URL. Each one is then authorized *independently*
through the same path a direct broker request takes. A tool that says it writes to the workspace
and is handed `~/.ssh/config` fails on the argument.

Extraction is deliberately generous about what counts as a resource, because the costs are
asymmetric: a false positive is one extra policy evaluation that resolves to a workspace path and
is allowed, while a false negative is an unchecked resource. Anything that could *escape* —
absolute, home-relative, containing traversal, containing a path separator, or a URL scheme — is
always treated as a resource. A bare non-path word like `utf-8` is not.

Extraction is depth-bounded (16), count-bounded (64), and length-bounded (4096 bytes per string),
so a hostile server cannot turn argument inspection into a denial of service.

### One refusal refuses the call

A tool that touches four allowed paths and one protected one does not get to perform the four.
Partial execution of a call whose full effect was refused is not a safe middle ground; it is the
attacker choosing which half runs.

Lease use follows the same all-or-nothing rule. MCP first preflights every resource without
spending authority. If any deterministic denial exists, no approval-bound resource is touched. If
leases are required, all exact action/resource uses are selected and decremented in one
`BEGIN IMMEDIATE`; one missing or expired lease rolls back every decrement. Only the missing
resources raise approvals. Concurrent batches therefore serialize as whole units rather than
partially burning each other's authority.

### Declared capabilities notice discrepancies; they never grant

A tool's declared capability footprint is recorded at registration and compared against what a
call actually reaches for. Reaching beyond the declaration fires `VIGIL-L012`. But declaring a
capability grants nothing: a test asserts that a tool declaring every capability in the vocabulary
is still refused when it reaches for `~/.ssh/id_ed25519`. A declaration is the server's claim
about itself, and a claim is not authority.

Server and tool registration are prerequisites. An unregistered server or an unknown tool is
refused before resource authority is considered; extracted resources remain attached to the
decision for attribution, but the call cannot spend a lease or raise an approval. A registered
tool call with no extractable resource is also refused because VIGIL has no action/resource pair
it can positively authorize. This avoids the empty-loop failure mode where inspecting zero
resources accidentally means unanimous approval.

Reaching beyond a registered tool's declared capabilities is both a detection and a refusal.
Declaration is therefore necessary for that capability but never sufficient: ordinary policy,
risk, budget, and lease checks still decide the resource itself. Scope is checked before resource
authorization so a call already destined for refusal cannot consume a lease or create an approval.

### Server identity is the name *and* the binary hash

Without a hash, "the same server" means only "the same name", which an attacker controls.
Registration records the SHA-256 of a local executable — computed by VIGIL from the file even when
the caller also supplies a digest. Re-registering the same name over a different binary is
**refused**, not silently accepted: an operator must remove and re-add it deliberately.

Only local stdio servers can enter the trusted registry in this slice, and registration requires
both the exact executable path and its observed digest. HTTP and unknown transports are refused
until VIGIL has an identity model for their endpoint, publisher, and authenticated transport;
accepting only a caller-supplied URL or digest would be a silent downgrade from binary identity.

### Drift is compared against a baseline, and the first sync is not drift

`sync_mcp_tools` compares the tools a server currently presents against what is on record and
reports every difference: tools added or removed, schemas changed, **descriptions** changed, and
capabilities newly claimed. Description drift matters on its own, because the description is what
an agent reads to decide whether to call a tool — changing it after trust is established is how a
tool gets repurposed without its schema moving.

A server has not misbehaved by being observed for the first time, so the first sync establishes
the baseline and reports nothing — except a binary-hash disagreement, which is drift regardless.
Any later drift rolls back staged tool inserts and updates. Observation is not authorization to
rewrite the trusted baseline, so the same changed manifest remains drift on every sync until a
future explicit, operator-authenticated rebaseline operation is implemented.

### Substitution alone quarantines

`VIGIL-L011` (server substitution) carries weight 80, enough to quarantine a session on its own.
It joins `VIGIL-L003` (an agent reaching for VIGIL's own evidence) as the second and only other
rule allowed to do that; a test pins that list so a third cannot be added without deliberation.
Everything else needs corroboration.

MCP rules live in `mcp.rs` beside the code that fires them, so a rule and its logic cannot drift
apart, but they share one `VIGIL-L###` namespace with the rest of the catalogue via
`detection::all_rules()`. The uniqueness and reachability tests cover the merged set.

## Consequences

Prompt Demo 5 works end to end: the same tool call is permitted for `./src/main.rs` and refused
for `~/.ssh/config`, attributed to the tool and server, with the argument's *content* never
reaching evidence — only the resources policy decided about.

### What this is not

This is the security core, not a transport proxy. Nothing here speaks JSON-RPC over stdio or
intercepts live MCP traffic. A tool call reaches these checks when an adapter routes it here,
exactly as a filesystem operation reaches the filesystem broker when something calls it. **A
server an agent contacts directly is unobserved**, and no detection will fire for it.

That is the same limitation every broker in this build has, and it does not go away until
Endpoint Security and a Network Extension can see what the agent actually did. It is stated here
so that a green `vigil mcp authorize` is not mistaken for "the MCP surface is covered".
