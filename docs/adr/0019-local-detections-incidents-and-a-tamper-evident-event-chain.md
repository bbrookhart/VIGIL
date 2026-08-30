# ADR 0019 — Local detections, incidents, and a tamper-evident event chain

**Status:** Accepted  
**Date:** 2026-08-30

## Context

After ADR 0017 and ADR 0018 the local control plane could refuse an action, escalate risk, and
withhold authority — but it could not *say what it had seen*. Denials carried a free-text
`detection` label that nothing consumed, there was no record an operator could triage, no notion
of an incident, no response vocabulary, and the event log was an ordinary SQLite table that
anything could edit without leaving a mark.

Three separate problems, with one shared requirement: whatever is recorded has to be worth
believing later.

## Decision

### Detections are a fixed catalogue, not a scripting surface

`crates/vigil-local/src/detection.rs` holds nine rules, each with an id, a name, a severity, a
confidence, a tactic, and the risk weight it loads. Rules are Rust constants. A detection rule
that could execute arbitrary code would be a way to run arbitrary code inside the security
control, which is the thing the control exists to prevent.

**Severity and confidence are separate axes.** "How bad if real" and "how sure it is real" are
different questions, and collapsing them is how alert queues become unreadable. A test asserts the
catalogue has entries off the diagonal, so the two cannot quietly merge.

Rules fire only from decisions VIGIL actually made, via the detection labels the policy ladder
already emits. Two tests hold that correspondence closed in both directions: every label maps to a
rule, and every rule is reachable from some label. Behaviour VIGIL cannot yet observe locally —
archive-before-egress, interpreter cascades, process fan-out, MCP capability drift, deception
interaction — has **no rule at all** rather than a rule that never fires.

This also fixed a real mislabelling: every protected-resource denial reported `credential_access`,
so a LaunchAgent write and an `~/.ssh` read landed in the same bucket. They are now
`persistence_attempt` and `security_control_modification` respectively, and only the last —
an agent reaching for VIGIL's own store — carries enough weight to contain a session on its own.

### Tactics are a native taxonomy

`Tactic` implements the prompt's Agentic Runtime Security Tactics rather than mapping to MITRE
ATT&CK. Several of these categories have no honest ATT&CK equivalent, and bending an
agent-specific detection to fit an existing framework makes it worse at its actual job. A mapping
can be added later as an annotation; it must not become the primary taxonomy.

### One open incident per session

An incident opens when a critical detection fires or a session reaches a containing risk state. A
partial unique index (`incidents_open_per_session`) enforces at most one open incident per
session, so a second alarming thing joins the investigation under way rather than starting a rival
one. Severity rises but never falls, for the same reason risk is monotone.

### Responses are named, idempotent, and recorded — including the ones that changed nothing

`REVOKE_CAPABILITIES`, `RESTRICT_SESSION`, `QUARANTINE_SESSION`, `SEAL_SESSION`. Re-applying one
reports `already_applied` rather than acting twice, because an operator retrying a command under
pressure must not be punished for it. Every attempt appends to the same hash-chained event log as
a broker decision.

**`TERMINATE_PROCESS_TREE` is deliberately absent.** Killing a process requires certainty that the
PID still belongs to the process VIGIL recorded. On macOS that needs unsafe process-info FFI or an
Endpoint Security client, and this build has neither. The prompt is explicit that when confidence
is insufficient the system should fail safely and alert; killing an unrelated process belonging to
the user is a worse outcome than failing to contain an agent. The CLI command is therefore named
`vigil contain`, not `vigil kill`, and says in its own output that nothing was terminated.

### The event log is hash-chained

Each event stores `previous_hash` and `chain_hash`, where the link commits to the sequence number,
the full content, and the predecessor — hashed over canonical JSON with the domain separator
`VIGIL_LOCAL_EVENT_CHAIN_V1\0`. Appending reads the head and writes the link inside one
`BEGIN IMMEDIATE` transaction, so concurrent appenders cannot fork the chain.

`vigil audit verify-local` recomputes the whole chain and reports the first record that disagrees.
Committing to the sequence number is what makes reordering detectable; `AUTOINCREMENT` gaps are
what make interior deletion detectable. Upgrading backfills links over pre-existing events, so an
upgraded database has a complete chain rather than one that begins at the upgrade.

**Amended 2026-08-30.** The original text claimed the chain detected removal generally. That was
wrong for *truncation*: a hash chain only detects breaks between records, so deleting the newest
records leaves nothing after the break to reveal it. The adversarial harness (ADR 0027) found this
by running `DELETE FROM events WHERE decision = 'DENY'` against the most recent denial — the chain
verified cleanly.

Verification now also compares SQLite's `AUTOINCREMENT` high-water mark, which `DELETE` does not
decrement, against the last record present. A shorter log than the number of events issued is a
truncated tail. An attacker with database write access can rewrite `sqlite_sequence` too, so this
raises the bar rather than closing the door — consistent with the tamper-evident, not immutable,
claim below.

**This is a tamper-evident log, not an immutable one.** Anything that can write the database can
rewrite the entire chain. What it costs an attacker is the ability to edit or drop *one* record
and have the rest still verify. Nothing in VIGIL may call it immutable, and no signed checkpoint
exists yet to anchor the head against wholesale rewriting.

### Evidence bundles carry metadata only

`vigil incidents export` writes a single `vigil.incident-bundle/v1` JSON file, mode `0600`,
containing the incident, session, detections, responses, risk history, leases, approvals, budget,
process graph, event log, and a chain verification result. It records `content_captured: false`
and states that a process which bypassed the brokers produced no records in it. No file content,
argument value, or secret material is collected — a bundle full of the user's data would itself
become a thing worth stealing.

## Consequences

Prompt Demos 2 and 3 and the §81 incident timeline are now demonstrable end to end: a credential
probe becomes a detection, three of them contain the session and open an incident, containment
revokes authority, and the whole sequence exports as reviewable evidence whose chain verifies.
Rewriting a denial in the log fails `vigil audit verify-local` with a non-zero exit.

What this does not do: nothing here observes a process that bypasses the brokers, terminates
anything, or survives an attacker with write access to the database and the patience to
recompute. Signed chain checkpoints anchored in the Keychain or Secure Enclave, and OS-verified
process identity, both remain work for the entitled half of the product.
