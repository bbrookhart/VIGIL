# ADR 0006 — Transactional local budgets and the filesystem broker

**Status:** Accepted  
**Date:** 2026-08-29

## Context

The local session foundation could evaluate a path but had no durable quantitative authority and
no enforcement point that performed a real operation. Checking a limit and incrementing it in
separate statements permits concurrent overrun. Writing a destination directly can follow a
last-moment symlink replacement and leaves partial output on failure.

## Decision

Every semantic session receives fixed profile counters in SQLite. An operation reserves every
affected dimension in one `BEGIN IMMEDIATE` transaction. Execution follows only after policy and
reservation succeed. Success commits reserved units to consumed; failure refunds them. Database
constraints prohibit negative counters and `consumed + reserved > limit`.

The first local semantic enforcement point is a filesystem broker. Reads are bounded to 64 MB and
never persist content in events. Writes enforce count, cumulative bytes, and maximum single-write
limits, then use a `0600` same-directory temporary file, `fsync`, permission preservation for
replacements, and atomic rename. Content is accepted through standard input by the CLI and is
never placed in command arguments or audit metadata.

If an operation succeeds but budget reconciliation fails, VIGIL does not refund or report a clean
success. The reservation remains held (reducing authority), an integrity event is attempted, and
the caller receives an error.

## Consequences

Concurrent callers cannot overspend a local budget, failed I/O does not consume it, and a policy
denial performs no filesystem mutation. The broker remains bypassable by direct OS calls and path
resolution cannot close every rename race. Endpoint Security is therefore still required for
non-bypassability and intent–execution reconciliation; this ADR makes no OS-enforcement claim.
