# ADR 0029 — An MCP proxy that sits in the path

**Status:** Accepted  
**Date:** 2026-08-30

## Context

ADR 0020 built the MCP security core: registry, binary identity, drift, and argument-level
authorization. Its closing section said plainly what was missing — "this is the security core,
not a transport proxy… a server an agent contacts directly is unobserved". `vigil mcp authorize`
could answer the question, but only if something thought to ask.

## Decision

`vigil mcp proxy` stands between the agent and the server, speaking the newline-delimited
JSON-RPC stdio transport. A `tools/call` is authorized before the server sees it.

### The protocol logic is separate from the plumbing

`mcp_proxy.rs` parses messages and decides; the CLI moves bytes. Every decision is therefore
testable without spawning a process or opening a pipe, and eleven unit tests cover the parsing
rules directly.

### A refusal must be answered, not dropped

Silently discarding a refused request would hang the agent waiting for a response that will never
arrive, and a hung agent is an outage rather than a control. Every refusal produces a well-formed
JSON-RPC error carrying the request's own `id`, with code `-32000` — inside the
implementation-defined server-error range, which is where "understood, and the answer is no"
belongs. The message says VIGIL refused rather than that the tool failed: an agent that believes
its tool is broken will retry; one that knows it was refused can do something else.

A `tools/call` with **no** `id` is a notification, which by definition has no response. It cannot
be refused politely, so it is dropped and logged — and a client sending a tool call it does not
want an answer to is itself worth noticing.

### Ambiguity is refused, never forwarded

A message that is not valid JSON, not an object, or a `tools/call` whose `params.name` cannot be
read is refused. Forwarding an unparseable tool call on the hope it is harmless would make the
parser's blind spots into the policy.

**JSON-RPC batches are refused wholesale.** Handling one usefully would mean authorizing some
array members and refusing others inside a single response envelope; refusing the batch is
unambiguous and no MCP client requires them.

### Framing is a security property

The transport is line-delimited, so a rendered message containing a newline would split into two
and let the second half be read as its own JSON-RPC message. `render` refuses any output with a
line break, and messages are bounded at 4 MiB because an unbounded line is an unbounded
allocation driven by whichever side sends it first.

### Drift becomes live

The server-to-agent direction captures `tools/list` responses and compares them against the
recorded baseline, so a server that changes its tool set mid-session is noticed the moment it says
so rather than at the next manual `vigil mcp sync`.

Only a response whose ID matches an outstanding `tools/list` request may update that baseline.
An arbitrary server result that happens to contain a `tools` array is forwarded as ordinary
traffic. The bounded correlation set is single-use, so unsolicited and replayed responses cannot
manufacture drift observations.

A server does **not** get to declare its own capabilities over the wire. Captured tools carry an
empty declaration; the recorded one comes from registration, which an operator reviewed. Otherwise
a server could widen its own declared scope simply by claiming to.

## Consequences

The decisive test is not that VIGIL said no — it is that the MCP server **never received the
refused call**. The adversarial harness runs a stand-in server that logs every message handed to
it, sends a listing, a permitted call, and a call targeting `~/.ssh`, and asserts the third never
appears in that log while the agent still gets its error response.

Phase 7 moves from "can authorize a tool call if asked" to "is in the path".

The proxy also proves that the process it launches is the registered server identity: the
requested executable must resolve to the same canonical path, still be executable, and still
hash to the recorded digest. The canonical registered path, rather than the caller's spelling,
is passed to process creation. ADR 0034 records why the server name alone is insufficient.

### What it still does not close

An agent that talks to the server directly, rather than through the proxy, is unmediated —
exactly as a process that bypasses the filesystem broker is. The proxy narrows the gap for traffic
routed through it; it does not make the surface non-bypassable. Only OS-level enforcement does
that, and it is not installed.

There is also a narrow check-to-spawn race between hashing the executable and the operating
system reopening its path. Closing that requires an OS-backed execution boundary or a platform
facility that executes an already-verified file descriptor; the portable proxy fails closed on
identity disagreement but does not claim to eliminate that race.
