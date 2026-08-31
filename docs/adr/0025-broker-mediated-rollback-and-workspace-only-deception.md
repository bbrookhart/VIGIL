# ADR 0025 — Broker-mediated rollback, and deception that stays in the workspace

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Two Phase 8 items remained: managed rollback (§40) and deception (§36). Both are features where
the obvious implementation is worse than useless, in opposite ways — one over-promises coverage,
the other contaminates the thing it is meant to protect.

## Decision — rollback

### Coverage is exactly as wide as broker coverage, and the report says so

The broker records what a file was immediately before a managed write: its content, addressed by
SHA-256, or the fact that it did not exist. `vigil rollback` puts those back.

It can undo **only** writes that went through `FilesystemBroker`, because that is the only moment
VIGIL held the prior bytes. A process that wrote directly, a subprocess that deleted a directory,
a network side effect, a modified database — none are covered. Endpoint Security will not change
this: observing a write tells you it happened, not what the bytes were beforehand.

So every `RollbackReport` carries a `coverage_note` stating this, printed on every run. A rollback
that restores four files restored the four VIGIL mediated, not "the session's changes", and the
tool must not let anyone read it the second way.

### Restoring is itself destructive, so it verifies first

Writing old content over a file destroys what is there now. Each preimage therefore records the
**postimage** as well — what the broker left behind — and a restore refuses unless the file still
matches it exactly. If something else has written the file since, restoring would discard a change
VIGIL knows nothing about, and that path reports a refusal instead of proceeding. A test drives
exactly this: an external edit after a managed write survives the rollback untouched.

Refusals are never silent skips. `vigil rollback` exits non-zero when anything was refused, so a
partial rollback cannot be mistaken for a complete one.

### Capture failure fails the write

If the preimage cannot be recorded, the write does not happen. Performing an irreversible change
because the record of how to reverse it could not be written is the wrong order of priorities.

### Content above the preservation limit is marked non-restorable, not silently dropped

Prior content above 8 MiB is not stored. The write still proceeds — refusing would make VIGIL
break legitimate work on large files — but the preimage records `preserved = false` with the
reason, so the path is explicitly non-restorable rather than quietly missing from a later
rollback. Saying "this one cannot be undone, and here is why" is the honest third option between
breaking the work and lying about coverage.

### Other properties

Blobs are content-addressed, so three writes over identical prior content store one blob.
Restores walk newest-first, so a file written three times unwinds to its state before the *first*
write. A stored blob is re-verified against its own digest before being written back — a corrupted
blob store must not become a way to place arbitrary content on disk. A running session cannot be
rolled back, because it could overwrite the restored file immediately and make the result
meaningless.

## Decision — deception

### Bait never leaves the workspace, and never goes near real credentials

`place_canary` refuses any path outside the session workspace and any path in a protected
category — `~/.ssh`, `~/.aws`, Keychain storage, LaunchAgents, VIGIL's own directories. It
resolves through the filesystem first, so a symlinked subdirectory cannot be used to get there
either.

This is not caution for its own sake. Salting a user's actual credential directories with decoys
risks a real tool picking up a fake key and failing in a way that is very hard to diagnose, and it
contaminates precisely the locations whose integrity matters most. §36 says "do not contaminate
real user credential locations recklessly"; the refusal makes that structural rather than advisory.
A canary also never overwrites an existing file.

### No canary contains anything real

Content is generated from fixed synthetic patterns carrying the marker `VIGILCANARY`, shaped to
look plausible to a scanner while granting nothing. Anyone who finds one — in a log, in a paste,
in an attacker's exfiltrated archive — can tell at a glance that it authorizes nothing anywhere.

### Detection fires on an *allowed* read

This is the design point. A canary sits inside the workspace, so reading it is permitted by
policy. A subsystem that only inspected denials would miss every canary hit. The check therefore
runs in `authorize_decision` against the resolved resource regardless of outcome.

### The confidence is MEDIUM, and that is deliberate

`VIGIL-L018` is `CRITICAL` severity with `MEDIUM` confidence and weight 60 — it *contains* a
session rather than quarantining it. A workspace canary can be swept by an entirely legitimate
recursive tool: a search, a linter, a test that walks the tree, a backup. Rating it high
confidence would make the detection untrustworthy the first time it fired on a `grep -r`, and a
detection nobody believes is worse than no detection. It is a strong reason to look, not a verdict.

That also keeps intact the pinned rule that only `VIGIL-L003`, `VIGIL-L011` and `VIGIL-L013` may
quarantine on their own evidence.

## Consequences

Prompt §40 and §36 are delivered. Schema 7 adds `write_preimages` and `canaries`; blobs live in a
content-addressed store beside the state database, owner-only.

### What neither of these is

Rollback is not transactional and not universal: it is an undo log for brokered writes. Deception
is a diagnostic placed by an operator in a workspace, not a honeypot network, and it observes only
what routes through VIGIL — a process that reads a canary directly, without the broker, produces
no detection at all. Both inherit the same boundary as every other control in this build.
