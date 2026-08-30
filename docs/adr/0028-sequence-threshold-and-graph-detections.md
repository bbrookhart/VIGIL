# ADR 0028 — Sequence, threshold, and graph detections are retrospective

**Status:** Accepted  
**Date:** 2026-08-30

## Context

§34 requires the detection engine to support single-event, sequence, threshold, and graph rules.
Only the first existed. That is why several §35 detections — sensitive-read-then-egress,
archive-before-egress, interpreter cascade, process fan-out — had no rule at all rather than a
rule that never fired: nothing could express them.

These shapes are the ones that matter most and are hardest to see. Each individual step is
unremarkable: reading a file is allowed, running `tar` is allowed, opening a connection is
decided on its own merits. The pattern exists only across time, which is exactly what a
decision-time rule cannot look at.

## Decision

### They are retrospective, and the product says so

By the time a sequence is visible, every step in it has already been decided. These rules run
over the durable event log and the process graph *after the fact* and produce an explanation and
a risk contribution — never a block.

That distinction is stated rather than blurred: the command is `vigil analyze`, every finding is
recorded with `retrospective: true`, and the CLI closes with "each step was individually permitted
at the time, which is why the shape is worth naming". A tool that implied it had prevented
something it merely described would be worse than one that stayed quiet.

### Analysis is idempotent

It is expected to be run repeatedly — after a session ends, during triage, again when new
evidence arrives. Each finding is fingerprinted over `(session, rule, steps)` in canonical JSON,
and a fingerprint already on record is counted, not re-recorded. Re-analysing must never inflate
risk, and a test asserts that the second run changes neither findings nor risk state.

### Sequence rules require ordering and proximity, and both are load-bearing

`SENSITIVE_READ_THEN_EGRESS` fires only when the egress *follows* the reach and within five
minutes. Egress-then-credential-read is not exfiltration, and reporting it as such would train an
operator to ignore the finding. Activity an hour apart is not a plot. Both cases have their own
test.

One sequence produces one finding, not one per pair of steps: a session that read three
credentials and opened one connection is one story.

### The threshold rule is a rate, not a total

Twenty-five processes over an hour is ordinary work; twenty-five in a minute is not.
`PROCESS_FAN_OUT` slides a sixty-second window rather than counting a session total, and a test
asserts the slow case is silent.

### The graph rule is lineage, not adjacency

`INTERPRETER_CASCADE` walks the recorded process graph. Three interpreters started independently
by the same session are ordinary — a build does that. An interpreter started *by* a shell started
*by* an interpreter is a cascade. A non-interpreter in the chain ends it, and a cycle in stored
lineage terminates rather than looping.

### A benign control

The adversarial harness asserts that a session doing ordinary work — repeated reads of a source
file, a write — produces **no** findings and stays at `NORMAL`. A detection that fires on normal
activity is one an operator learns to ignore, taking the real findings with it.

## Consequences

Prompt §35's sequence-shaped detections exist, and §34's four rule kinds are all represented.

### It exposed five detections that could never fire

Wiring the new rules surfaced that `unknown_network_destination`, `credential_utility_invocation`,
`privilege_attempt`, `unmediated_network_utility`, and `unexpected_executable` were emitted at
decision sites with **no rule behind them**. They had been silently inert.

The cause was structural: the reachability tests kept their own hand-written copy of the label
list, so a label added at an emission site and forgotten in the test list went unnoticed. There is
now one `ALL_DETECTION_LABELS` constant referenced by both the emission sites and the tests, and
`every_label_maps_to_a_rule_and_every_rule_is_reachable` enforces the bijection in both
directions. Five rules were added for the orphaned labels.

This is the second time a hand-maintained parallel list has hidden a defect in this codebase. The
lesson is the same as ADR 0027's: the check has to derive from the thing it checks.

### What this cannot see

Only what VIGIL recorded. A session that went around the brokers leaves no timeline to analyze,
and `vigil analyze` says so rather than reporting a clean result. Cross-session patterns —
capability laundering between two agents — are not implemented; that needs a correlation model
across sessions that does not exist yet.
