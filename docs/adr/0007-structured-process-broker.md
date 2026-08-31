# ADR 0007 — Structured process broker before general shell mediation

**Status:** Accepted  
**Date:** 2026-08-29

## Context

`vigil run` records lifecycle evidence but deliberately retains the launching user's ambient
authority. Phase 2 requires a semantic shell/process broker, while arbitrary shell strings are a
large language with pipelines, substitutions, redirections, expansion, and nested interpreters.
A regex classifier would create a false enforcement claim. The entitlement-independent build
also cannot yet guarantee descendant termination or prevent direct process creation.

## Decision

Add a structured process broker accepting only `program`, `argv[]`, workspace `cwd`, a four-key
environment allowlist, and a timeout. Require an absolute canonical executable and reject set-id
binaries. Clear the inherited environment, disable stdin, pipe both output streams, drain them
concurrently, cap returned content at 1 MB per stream, and cap execution at 30 seconds.

Policy classifies high-risk executable families, but classification alone never authorizes.
Enforced profiles currently allow only an exact-path registry of side-effect-free data/timing
utilities. Shells, interpreters, network clients, credential tools, persistence tools, privilege
tools, workspace binaries, and unknown binaries deny or remain approval-bound. General shell
syntax is not accepted, so VIGIL does not claim to parse or safely authorize it.

Reserve one `process_executions` unit before spawn. A spawn failure refunds it. A successful spawn
commits immediately because the side effect occurred; non-zero exits and timeouts still consume
the unit. Spawn and exit events contain executable identity, counts, timing, status, and truncation
metadata but no argument values, environment values, or output content.

## Consequences

Managed callers gain a useful non-shell process path with deterministic policy, quantitative
authority, bounded resource handling, and correlated lifecycle evidence. The exact allowlist is
intentionally narrow until scoped approvals and OS attribution exist. The broker terminates only
its direct child and remains bypassable through direct OS calls, so it is semantic enforcement—not
a sandbox or OS-level prevention. Endpoint Security remains required for `AUTH_EXEC`, descendant
attribution, non-bypassability, and intent–execution reconciliation.
