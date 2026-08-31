# 0043 — Network policy restart restores only the exact durable envelope

Status: accepted
Date: 2026-08-30

## Context

The network data provider verified a signed, instance-bound policy and rejected non-increasing
generations in memory. Neither property survived extension restart. A captured older envelope
could be presented to a fresh process, and there was no protected atomic boundary through which a
containing application could publish policy without adding file or IPC work to `handleNewFlow`.

Persisting only a generation creates a recovery trap. If generation 12 is committed before policy
activation and the process crashes, a restart must reject generation 12 as replay—but then it can
never restore the policy whose durable commit caused the crash window. Permitting any envelope at
generation 12 instead allows two differently encoded or signed policies to equivocate at one
generation.

## Decision

The shared-container transport has two owner-controlled atomic records:

- the exact bounded signed envelope bytes; and
- `(generation, SHA-256(exact envelope bytes))` as the durable replay floor.

The trusted containing application or daemon owns publication. One advisory lock serializes the
complete transaction across publisher processes. The publisher authenticates the candidate,
writes a uniquely named owner-only envelope file in the same directory, fsyncs it, atomically
renames it over the policy record, fsyncs the directory, and then commits the matching replay
record atomically. A crash between those records creates an unavailable pair, never usable stale
authority; republishing the same exact generation repairs that gap idempotently.

The filter data provider has a read-only App Group view. Reload therefore happens outside the flow
callback without creating files or taking write locks:

1. read the durable replay record;
2. read the exact envelope bytes;
3. read the replay record again and require both reads to match;
4. authenticate the envelope and require its generation and digest to match the stable record;
5. activate the verified snapshot in memory.

After restart, the one envelope whose digest matches the current durable generation may be
restored. An older generation is rollback; different bytes at the same generation are
equivocation. Persistence failure activates nothing. Re-reading the already active exact envelope
is idempotent.

## Consequences

A crash after the replay floor is renamed but before in-memory activation is recoverable without
reopening captured-policy replay. Two live publisher instances cannot race an older generation or
same-generation repair over a newer one. Symlinked policy, insecure container permissions,
corrupt records, oversized files, unstable record reads, and same-generation envelope substitution
fail closed.

The transport, strict provider configuration, App Group resolver, `startFilter`/`stopFilter`
lifecycle, and containing-app configuration factory are entitlement-free and XCTest-covered.
Provisioning the real App Group and keys in an installable target, then signing and activating it,
remain packaging work. The callback continues to perform no file, IPC, DNS, database, UI, or
logging work.
