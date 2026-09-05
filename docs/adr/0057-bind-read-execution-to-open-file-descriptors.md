# ADR 0057: Bind read execution to open file descriptors

Status: Accepted for bounded Linux reads; writes and native macOS execution pending.

## Problem

The authority service introduced in ADR 0056 cannot safely execute existing path-based
brokers under a separate account. A checked pathname can resolve to a different file
when reopened. An earlier ALLOW returned to an agent is also not an execution token.

## Decision

Add one executable method, `read`, to the authenticated daemon. Reuse local policy,
risk, budget and evidence storage, with a Linux-specific descriptor boundary. Preserve
existing brokers rather than changing their compatibility and rollback behavior.

Pin an agent-owned workspace directory at startup. Use `openat2` with `BENEATH`,
`NO_SYMLINKS`, `NO_MAGICLINKS` and `NO_XDEV` for descendant resolution. Open with
`O_PATH` first: reject non-regular, non-agent-owned, multiply linked or oversized
objects without reading or invoking device-open handlers. Reopen the pinned descriptor
through trusted procfs and recheck device/inode identity. No caller pathname is reopened
after authorization, and no fallback exists when kernel primitives are unavailable.

Obtain fresh authorization inside the read request. Charge the file-read budget before
reading. Read at most 4097 bytes, returning an error rather than content if the file
exceeds the 4096-byte limit. Record device, inode, byte count and reservation ID before
returning base64 data. Never accept caller-provided ALLOW, profile, identity or session.

## Evidence and limits

Deterministic tests replace the file pathname and workspace directory between open
and read: reads remain attached to the original object. Tests also reject links,
traversal, foreign owners, size overflow and growth after opening. The real Linux
account test verifies returned bytes, denied privileged/non-regular reads, the existing
1000-read untrusted-agent budget, and exhaustion across restart.

This narrows the consequence surface to bounded reads of agent-owned regular files.
It does not freeze file contents or prevent direct agent syscalls. Administrator/OS
integrity and trusted procfs remain assumptions. Kernel/filesystem stalls are not
cancelled by IPC timeouts. Failed or ambiguous attempted reads retain their budget
charge. Write/create/delete execution, crash-safe mutation recovery, native macOS
descriptor enforcement and whole-process confinement remain separate acceptance gates.

This extends ADR 0056's no-execution boundary only for the explicit Linux read method.
See the [protocol guide](../security/LOCAL_AUTHORITY_DAEMON.md).
