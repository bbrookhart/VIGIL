# 0040 — Signed checkpoints close the chain-rewrite hole

Status: accepted
Date: 2026-08-30

## Context

The local event log is a hash chain: each event commits to its content, its sequence, and its
predecessor's link (ADR 0019). That makes an *edit* evident — change one record and every record
after it stops linking — and, since the truncation fix, makes a removed tail evident too by
comparing the last surviving sequence against SQLite's `AUTOINCREMENT` high-water mark.

It never made a *rewrite* evident, and the code said so. `verify_event_chain` carried the comment
"an attacker with database write access can also rewrite `sqlite_sequence`, so this raises the bar
rather than closing the door", `append_event` said "anything that can write the database can
rewrite the whole chain", and `vigil audit verify-local` printed that sentence to the operator on
every successful run. `docs/security/FAIL_CLOSED_MATRIX.md` listed **Signed chain checkpoints (not
built)** as a known gap.

The attack is not subtle. Delete the record you dislike, renumber what follows, recompute every
link hash from your own version of history, and set `sqlite_sequence` to match. Every check the
chain performs is a check of the log against itself, so a log that is internally consistent passes
regardless of whether it is true. Demonstrated end to end against a real database: a session with
one `DENY` among five events, the `DENY` deleted and the high-water mark reset, and
`vigil audit verify-local` reporting *"Event chain verified: 4 event(s)"* and exiting `0`.

`vigil-audit` already solved this for the portable side — `Checkpoint`, `CheckpointMismatch`,
`TruncatedBelowCheckpoint` — but it is built on `VigilSecurityEvent` and `TenantId` held in memory,
not on the local SQLite chain.

## Decision

Add signed checkpoints to the local store: a commitment to `(sequence, head_hash)` signed with a
key that lives outside the database, in a new `chain_checkpoints` table (schema v12).

Verification recomputes the chain, capturing the head at each checkpointed sequence, then holds
each checkpoint against it. A rewrite changes the head at every covered sequence, so without the
signing key it cannot be made to match. The last checkpoint pins everything at or before it.

Specifics that carry weight:

- **Domain separator `VIGIL_LOCAL_CHAIN_CHECKPOINT_V1\0`**, distinct from `vigil-audit`'s. The two
  checkpoint kinds may be signed with the same seed, and the separator is what stops a signature
  over one being presented as the other.
- **The signature is checked before the head.** An unsigned or forged checkpoint says nothing about
  the log; comparing its head first would report a misleading reason for the failure.
- **A verifier trusting no keys reports every checkpoint as `UnknownKey`**, never skips it. Silently
  passing an unverifiable checkpoint would report a rewritten chain as clean — the exact failure
  this ADR exists to remove.
- **A chain that does not verify is never checkpointed.** Signing a rewrite would launder it into a
  signed commitment, which is strictly worse than having no checkpoint. An empty log is refused for
  the same reason: a checkpoint over nothing is later indistinguishable from one whose events were
  all removed.
- **`vigil audit verify-local` distinguishes the two claims.** Without `--key` it says it checked
  links only, and says whether checkpoints exist that it did not check. With `--key` it reports the
  number of checkpoints the chain was held against. Reporting both runs as "verified" would
  overstate the weaker one.

Reusing the existing seed convention rather than adding a fourth key: `vigil audit checkpoint`
takes `--seed` or `VIGIL_AUDIT_KEY`, the same 32-byte hex seeds `vigil keys generate` writes, and
`--key key_id=hex` on verification matches `vigil audit verify`.

## Consequences

The hole is closed against the attacker it names, and the demonstration inverts: on the same
tampered database, `verify-local` alone still reports verified and exits `0`, while
`verify-local --key` reports *"Checkpoint at sequence 5 FAILED: covers a sequence past the end of
the log, which stops at 4; the tail was removed"* and exits `1`.

**This closes exactly one hole: an attacker with database write access.** It does nothing against
one who also holds the signing key. On a single-host install the seed sits in a `0600` file, so in
practice this raises the bar from "write the database" to "write the database and read the key
file". That is a real gain and not the same as closing the door; holding the seed off-host is what
actually closes it. The CLI says this in as many words after writing a checkpoint, because an
operator who believes the log is now immutable is worse off than one who knows what it is.

Checkpoints must actually be taken. A chain with no checkpoint is exactly as rewritable as before,
which is why `verify-local` now names that condition rather than printing an unqualified success.
Taking them on a schedule is an operator responsibility; nothing here does it automatically.

The link-by-link limitation is preserved as a **test**, not just prose:
`a_wholesale_rewrite_defeats_the_hash_chain_alone` asserts that the chain alone *misses* the
rewrite. If someone later strengthens the walk, that test fails and forces a decision rather than
letting this ADR quietly go stale.

Three schema-downgrade fixtures in the store tests each needed the new table dropped, and two were
missed on the first pass — the same hand-maintained-parallel-list failure recorded in ADR 0019 and
ADR 0031, now on its third appearance in this codebase. They are at least uniform now.
