# 0041 — Process termination acts only where identity still confirms the target

Status: accepted
Date: 2026-08-30

## Context

Containment withheld authority and nothing else. `vigil contain` revoked leases and raised the
session to `CONTAINED` or `QUARANTINED`, so every *future* brokered request was denied — but a
process already running was untouched. The CLI said so, and `docs/security/FAIL_CLOSED_MATRIX.md`
listed it: *"`vigil contain` withholds authority and revokes leases but terminates nothing. A
process already running is unaffected."*

Withdrawing permission to ask for something is not the same as stopping what is already happening.
An agent that had spawned a long-running child kept it, and the child kept whatever file handles,
sockets and credentials it already held.

The reason it was never built was recorded in the code:

> Confirming that a PID still belongs to the process VIGIL recorded needs an OS-verified process
> identity this build does not have, and killing the wrong process is worse than not containing an
> agent.

That reasoning is sound and the conclusion was too strong. A PID is not an identity — the kernel
reuses it, and on macOS it wraps at around 99998 — but a PID *plus the kernel's start time for it*
is one. A recycled PID belongs to a process that started later.

## Decision

Terminate the session's process tree, verifying identity immediately before each signal.

- **Identity is `(pid, os_started_at, executable)`,** captured at spawn while the child handle is
  still held. Until a child is reaped its PID cannot be reused, so the reading taken at that moment
  is unambiguously the process just spawned.
- **Read with `/bin/ps`, not a syscall.** This crate is `#![forbid(unsafe_code)]` and every route to
  `sysctl`/`proc_pidinfo` is FFI. `ps` is run from an absolute path, never through `PATH`, with a
  deadline and no inherited stdin.
- **Both halves are compared `ps`-output against `ps`-output.** Comparing the observed command
  against the executable path the *caller asked to run* is not equivalent — `ps` has its own
  rendering, and a formatting difference would read as a recycled PID. The first version of this
  work compared the observed executable against itself, which made the check vacuous; that is why
  the observed command is stored at spawn rather than derived later.
- **Deepest generation first.** A parent stopped before its children orphans them to `launchd`,
  where they keep running and are no longer reachable through the tree being stopped.
- **Verification happens immediately before the signal, never as an earlier pass.** A
  check-then-signal split is a TOCTOU window in which the process can exit and the PID be reused.
  Identity is re-confirmed again before escalating from `SIGTERM` to `SIGKILL`.
- **Every uncertainty refuses and says why.** A node whose identity cannot be read, whose identity
  has changed, or which was recorded before start-time capture existed, is reported as `Refused`
  and left running. `SIGTERM`, a 2s grace period, then `SIGKILL`.

`ResponseAction::TerminateProcessTree` joins the response engine; `vigil contain --terminate`
exposes it. Termination is not the default: containment that withholds authority is safe to apply
broadly, and one that stops processes is not.

## Consequences

An operator can now actually stop a contained session, and is told precisely what was left
running and why:

```
Processes: 0 terminated, 0 already exited, 1 left running.
  pid 10179 ("/bin/sleep") was NOT stopped: pid 10179 now belongs to a process started at
  Sun Aug 30 16:43:49 2026, not the one recorded at Sun Jan 01 00:00:01 2001; the pid was recycled
```

A response where every live process was refused reports `refused`, not `applied`. Telling an
operator a tree was stopped when it was not is the failure that matters most here.

**Zombies were the bug the tests found.** A process that has been signalled but not yet reaped by
its parent still holds its PID, and `ps` renders its command as `<defunct>`. The first
implementation compared that against the recorded command, concluded the PID had been recycled, and
refused to finish the job — reporting *"pid was replaced during the grace period"* for a process it
had just successfully killed. This is not a corner case: it is the normal state of a signalled
child whose parent is still alive, which is exactly the tree being stopped. The process state
column is now read explicitly and `Z` is treated as exited.

**This is evidence of identity, not proof of it.** `lstart` has one-second granularity, so two
processes sharing a PID are indistinguishable only if a PID wraps and is reassigned *within the same
second* **and** the new process runs the same executable. That needs ~100k process creations in
under a second on the same machine. It is a real gap, and closing it needs the OS-verified identity
that Endpoint Security provides (ADR 0005, ADR 0013).

**Only processes in the graph are reached.** One spawned outside the brokers, daemonised, or
re-parented before it was recorded is not in the graph and is not stopped. That is the same
attribution gap ADR 0005 records, and `vigil contain --terminate` says so in its output rather than
implying the tree is now empty.

Nodes recorded before schema v13 have no `os_started_at` and are never signalled. Back-filling them
is impossible — the kernel does not retain a start time for a process that has since been replaced
— and guessing would be exactly the mistake this ADR exists to avoid.
