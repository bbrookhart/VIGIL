# ADR 0038 — The filesystem capability surface is complete

**Status:** Accepted  
**Date:** 2026-08-30

## Context

`fs.delete`, `fs.rename`, `fs.list`, and `fs.metadata` were in the capability vocabulary from the
first local slice. They had policy decisions, `fs.delete` had a budget dimension, and
`approve-untrusted-delete` had a dedicated approval rule. None of them had a broker path.

A capability with no broker is not a control. An agent that wants to delete or move a file does it
with a direct syscall, which VIGIL cannot see — so the vocabulary described authority the system
never mediated, and `file_deletes` counted an operation that could not occur.

`fs.rename` additionally had no budget dimension at all, despite §13's example budget listing one.

## Decision

### A rename is two effects wearing one name

The destination loses whatever it held; the source ceases to exist. Recording it as "the file
moved" would leave rollback unable to restore an overwritten destination — which is the
*destructive* half, and the reason rename deserves mediation at all.

So it decomposes into the two preimages it actually is: the destination gains the source's
content, and the source becomes absent. Rollback already walks newest-first, so both come back in
the right order with no special case. A rename that overwrote a file restores both files; a rename
onto a new path undoes by removing it rather than leaving an empty file behind.

The source content is read *before* the move, because it is the destination's postimage and cannot
be reconstructed afterwards.

### Both endpoints are authorized; one refusal refuses the rename

Same rule as an MCP call. Performing half of a refused operation lets the caller choose which half
runs. A refused rename moves nothing and spends no budget — asserted, because "refused but the
counter moved" is the kind of thing that only shows up under budget pressure.

### Directories are refused, for delete and rename alike

A tree is a blast radius that one `file_deletes` or `file_renames` charge does not account for.
Accepting one quietly would let a single call do arbitrarily more than the budget says.

### Enumeration is mediated even though it changes nothing

`fs.list` alters no state, so it is tempting to leave unbrokered. But an agent walking toward a
protected location is a signal, and without a broker path it enumerates with direct syscalls that
VIGIL sees none of. Listing `~/.ssh` now produces a `credential_access` detection that previously
could not exist.

Listing consumes a read charge, so enumeration sits inside the same blast-radius accounting as
reading. Entry names are counted but not stored: a directory's contents can themselves be
sensitive, and the count is the security-relevant fact.

Both listing and reading are bounded — 4096 entries, 64 MiB — because an unbounded listing of a
directory the agent controls is an unbounded allocation driven by the agent.

## Consequences

Schema 11 adds `file_renames`, backfilled for existing sessions so an upgraded session is not
silently denied a capability it should have.

`fs.metadata` remains unbrokered. It is the one member of the group that reveals nothing `fs.list`
does not, and adding a command for it would be surface without a control behind it.

### What this does not change

Coverage is still exactly as wide as the brokers. A process that renames or deletes with a direct
syscall is unmediated and unrecorded, and rollback cannot restore what VIGIL never held. That gap
closes with Endpoint Security, not here.
