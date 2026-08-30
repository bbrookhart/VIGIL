# ADR 0031 — A path is not an identity

**Status:** Accepted  
**Date:** 2026-08-30

## Context

The filesystem broker decided about a path and then opened it by name. Between those two moments
the name can be pointed at something else: a symlink dropped in place, a rename over the top, a
directory swapped out. `ARCHITECTURE.md` has acknowledged this since the first local slice — "the
broker's path resolution cannot eliminate every rename race without an OS-observed file identity" —
but nothing detected it.

The consequence is worse than an unauthorized read. The event would record the path policy decided
about, so the evidence would say one thing while the bytes returned came from another object. A
control that can be wrong *and* produce confident-looking evidence of being right is worse than one
that simply fails.

## Decision

Bind the operation to the object, not to the name.

**Reads.** `read_bounded` captures the object's device and inode with `symlink_metadata` — which
does not follow, so a link appearing where a regular file was is itself the substitution being
looked for — then opens the path and takes the identity from the *file handle*. A handle is the
object. If the two disagree, the read is refused before any content is returned.

**Writes.** `atomic_write` already wrote to a uniquely named temporary with `create_new` and
renamed it into place, so the final component is safe. The parent directory was not: `rename`
resolves it by name, so swapping that directory would land approved content somewhere policy never
saw. The parent's identity is captured up front and rechecked immediately before the rename.

Device and inode together identify an object; a path does not. A test asserts the comparison
distinguishes two files with identical content and treats a hard link as the same object, so it is
checking identity rather than name or bytes.

## Consequences

The substitution is now performed in a test rather than reasoned about: a file is read normally,
then replaced with a symlink to a different file, and the read is refused with an integrity error
instead of returning the substituted content.

### The window this closes, precisely

**Stat-to-open, not decide-to-open.** The gap between the policy decision and the broker's identity
capture remains. Closing that would mean holding a directory handle from resolution onward and
using `openat`, which is not reachable without `unsafe` in a crate that forbids it — and the crate
forbids it for reasons that outweigh this.

So the honest statement is: the race is narrower, and it is now *detectable* rather than silent.
A swap that lands inside the remaining window still succeeds. Endpoint Security, which reports the
file the kernel actually opened, is the real answer, and this is a defence-in-depth measure until
it exists.

### Why a refusal rather than a detection

A mismatch fails the operation. It is not merely recorded, because the alternative is returning
content from an object policy never approved and hoping someone reads the alert. Failing closed
here costs a legitimate caller a retry in the rare case where an editor replaced a file mid-read.
That is the right trade.
