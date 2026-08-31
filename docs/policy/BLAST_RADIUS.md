# Blast-radius budgets

Budgets bound harm even when intent classification or detection misses. Each dimension has
`limit`, `reserved`, `consumed`, and `remaining` state. Security-relevant operations follow:

```text
reserve → authorize → execute → reconcile → commit or refund
```

Reservation and consumption must share one transactional owner so concurrent requests cannot
both observe the same remaining unit. Remaining must never become negative. An agent can spend
or release its allocation through defined operations but cannot increase its own limits.

Required dimensions are file read/create/write/delete counts and bytes, process executions/
children/depth/interpreters, network destinations/connections/bytes, secret raw/brokered uses,
privileged and persistence actions, Git operations, and runtime duration.

The portable `BudgetLedger` enforces tool/model calls, duration, cost, destination fan-out,
repetition, and delegation depth under a per-session lock.

The local SQLite ledger now provides durable counters and atomic multi-dimensional reservations
for file reads/creates/writes/deletes and bytes, process executions, network connections and
destinations, brokered secret uses, privilege, and persistence. The filesystem broker consumes
the file dimensions and the structured process broker consumes `process_executions` after spawn.
Timeouts and non-zero exits still consume a unit because execution occurred; pre-spawn policy,
validation, budget, and spawn failures consume none. The payload-free network probe broker
consumes a connection unit and atomically charges each normalized hostname/port once per session.
A failed connect refunds both the attempt and an uncommitted first-destination claim; an
unreconciled claim blocks reuse in the safe direction. The secret broker interface consumes one
`brokered_secret_uses` unit only after exact profile/handle/purpose/target authorization and
provider metadata validation. Provider failure refunds the reservation; successful provider use
followed by accounting failure leaves it held in the safe direction.

Each profile also has a non-consumable `max_single_write_bytes` bound checked before reservation
or I/O. Zero-limit dimensions deterministically deny. Reconciliation is idempotent, and tests
prove simultaneous reservations cannot overrun the final unit.


## Budgets are per-session, and that is deliberate

A task gets a budget; a new task gets a new one. The consequence is that the *cumulative* effect
across sessions is unbounded for anyone who can start sessions — three sessions on one workspace
were measured performing 75 writes against a 25-write limit.

Making budgets workspace-cumulative would bound that, and would also mean a developer's second task
of the morning inherits the first one's spend. The chosen answer notices the pattern instead:
`VIGIL-L035` fires when a workspace accumulates sessions faster than work explains, carries the
summed consumption so the finding is actionable, and raises the new session to `ELEVATED`. See
ADR 0037.
