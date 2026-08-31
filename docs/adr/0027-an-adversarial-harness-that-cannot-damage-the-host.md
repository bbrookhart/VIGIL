# ADR 0027 — An adversarial harness that cannot damage the host

**Status:** Accepted  
**Date:** 2026-08-30

## Context

§62 requires an adversarial harness that executes the attack scenarios in §61 against disposable
fixtures, with "a prominent safety mechanism preventing destructive tests against `/`, `$HOME`, or
real sensitive paths". The threat model's own known-gaps list has said "the adversarial tests are
hand-written" since the first release.

The tension is obvious: a harness that runs real attacks is one bug away from destroying the
developer's machine, and it runs on the machine of every contributor and in CI.

## Decision

### Nothing happens outside a directory the harness created

`Disposable` is the only way a scenario obtains a writable path. A root is accepted only if it:

1. was created by this harness, under the system temp directory, with a random name — if the path
   already exists, construction aborts rather than reusing it;
2. carries a marker file written at creation;
3. is not `/`, not `$HOME`, not an ancestor of `$HOME`, not *inside* `$HOME`, not the repository or
   an ancestor of it, and not under `/Library`, `/System`, `/usr`, `/bin`, `/sbin`, `/etc`,
   `/var/db`, or `/Applications`;
4. still satisfies every one of those at cleanup, which is re-checked in `Drop`.

The marker is the belt to the guard's braces: a path the harness did not create cannot be removed
even if every other check were wrong. Refusing everything inside `$HOME` costs nothing on macOS,
where temp lives under `/var/folders`, and closes the case where someone sets `TMPDIR` under their
home directory.

### The guard is itself tested

`the_safety_guard_refuses_real_locations` asserts the guard rejects `/`, `/usr`, `/etc`, `$HOME`,
`$HOME/Documents`, `$HOME/.ssh`, and the repository — *and* accepts a genuine disposable root, so
it is not passing by refusing everything. `cleanup_refuses_a_directory_without_the_marker` creates
an unmarked directory containing a file and asserts both that cleanup panics and that the file
survives. A harness whose safety mechanism is untested is not a safe harness.

### Credential paths are named, never created or read

Scenarios that attack `~/.ssh` or `~/Library/LaunchAgents` use synthetic filenames that are never
created. VIGIL denies on the resolved *path*, so the file need not exist, and the persistence
scenario additionally asserts afterwards that no real LaunchAgent was written.

### Tests are named for the attack, not the control

A failure reads `ATTACK SUCCEEDED — an agent read a private key from ~/.ssh`, not
`test_credential_policy failed`. A deleted control then surfaces as the attack it enables. Sixteen
scenarios cover §61 items 1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 20, 26 and 30.

## Consequences

The harness runs under `cargo test --workspace`, so it is part of every CI run rather than an
out-of-band exercise, and the threat model's "hand-written adversarial tests" gap is closed with
executed ones.

### It immediately found a real defect

`attack_deleting_an_inconvenient_audit_record` failed on first run. Deleting the most recent
denial — `DELETE FROM events WHERE decision = 'DENY'` — left a log that verified cleanly, because
a hash chain detects breaks *between* records and there was nothing after the break to reveal it.
ADR 0019 had claimed the chain detected removal generally; that claim was wrong for truncation.

Verification now also compares SQLite's `AUTOINCREMENT` high-water mark, which `DELETE` does not
decrement, against the last record present. ADR 0019 is amended accordingly.

This is the argument for the harness in one example: the gap was in a claim a document made, not
in code anyone would have flagged in review, and only running the attack surfaced it.

### What it is not

These scenarios exercise the semantic layer, which is the layer that exists. None of them proves
containment of a process that bypasses the brokers, because nothing in this build can observe one.
The harness tests the controls VIGIL has; it does not test the ones it is still missing.
