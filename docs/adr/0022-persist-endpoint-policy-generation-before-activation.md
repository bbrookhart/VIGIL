# ADR 0022 — Persist Endpoint policy generation before activation

**Status:** Accepted  
**Date:** 2026-08-30

## Context

The fast-path state rejects a non-increasing policy generation in memory, but an extension restart
previously reset that comparison to zero. An old, correctly signed snapshot could therefore be
replayed after restart. Signature validity establishes who produced a snapshot; it does not make
that snapshot current.

The generation record is security state. Treating a corrupt or unavailable record as empty would
silently remove rollback protection. Acknowledging installation before the record is durable would
also allow the daemon to believe a generation survived when it did not.

## Decision

Production construction of `NativeEndpointControlService` requires a `NativeGenerationStore`.
`NativeFileGenerationStore` loads one strict, bounded versioned record and fails startup on corrupt,
symlinked, insecurely permissioned, or unreadable existing state. Its containing directory must
already exist, be owned by the effective user, and not be writable by group or other users.

A commit holds an advisory lock shared by store instances, rereads current state, writes a uniquely
named 0600 file in the same directory, fsyncs it, atomically renames it over the generation record,
and fsyncs the directory. The service serializes installation, rejects any generation at or below
the recovered high-water mark, and commits a newer generation before
publishing it to the authorization fast path or sending success. A storage failure returns a fixed
internal failure and leaves new policy state inactive. Once rename succeeds, the process never
permits that generation again even if the directory fsync reports an uncertain failure.

The record stores only the high-water mark, not active policy. After restart, health remains
unready until a newer valid snapshot is installed; replaying the last snapshot is intentionally
refused. Entitlement-free checks may explicitly use the in-memory implementation without claiming
restart safety.

## Consequences

A previously accepted signed snapshot cannot be rolled back across a normal extension restart.
Corrupt persistence fails closed rather than resetting authority, and an install acknowledgement
means the generation record was durably committed first. The containing app/extension installer
must provision a protected directory and preserve it across upgrades. This does not protect against
an attacker that can replace extension-owned protected storage, nor does it build the signed System
Extension, daemon, or launchd lifecycle.
