# ADR 0034 — MCP proxy binds the live process and correlates tool listings

**Status:** Accepted  
**Date:** 2026-08-30

## Context

The MCP registry gives a server name a reviewed executable path and content hash. A proxy that
authorizes calls using that name but launches an unrelated caller-supplied program has confused a
database identity with a process identity. The unrelated process inherits the registered server's
tool baseline and policy decisions.

The reverse direction has a similar ambiguity. A JSON-RPC result containing a `tools` array is not
necessarily a response to `tools/list`; treating it as one lets unrelated or unsolicited server
traffic alter the observed baseline.

## Decision

Before spawning a stdio MCP server, the proxy:

1. requires the registry entry to be trusted and to contain a complete executable identity;
2. canonicalizes both registered and requested executable paths and requires exact equality;
3. requires a regular executable file within the hashing size bound;
4. hashes the current bytes and compares them with the registered SHA-256 digest; and
5. gives process creation the canonical registered path.

Arguments remain caller supplied because they configure the registered executable; they do not
choose the executable identity.

For live tool discovery, the client-side pump records the string or numeric ID of each
`tools/list` request. The server-side pump may synchronize a returned tool array only after
atomically consuming the matching ID. The pending set is bounded at 64 entries and each ID is
single-use. Missing, unsupported, unsolicited, duplicate, and replayed IDs are forwarded but
cannot alter the baseline. Reaching the bound fails safe: traffic can continue, but additional
responses cannot change security state until an outstanding ID is consumed.

## Consequences

Selecting a trusted server name no longer grants that identity to an arbitrary local program, and
ordinary JSON-RPC results cannot masquerade as live discovery. Unit coverage proves path and hash
substitution are refused and correlation IDs are consumed once. The adversarial proxy test runs
the registered executable itself and still proves a refused escape never reaches it.

The portable implementation still has a narrow check-to-spawn race: process creation reopens the
verified path. Eliminating that race requires an OS enforcement mechanism or a supported way to
execute an already-verified file descriptor. VIGIL documents this gap rather than treating the
portable proxy as a non-bypassable OS boundary.

## Alternatives rejected

- **Trust the `--server` name.** Names select records; they do not prove which bytes will run.
- **Trust only canonical path equality.** A file can be replaced in place, so its recorded digest
  must also match current bytes.
- **Treat every result with `tools` as discovery.** Shape alone provides no request provenance.
- **Drop uncorrelated results.** The proxy need not break unrelated protocol traffic; forwarding
  without changing the baseline preserves compatibility while keeping the security state closed.
