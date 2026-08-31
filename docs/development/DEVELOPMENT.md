# Development

## Getting started

```console
make dev-setup     # Python SDK virtualenv; Rust toolchain is assumed
make build
make verify        # everything CI runs: fmt, clippy -D warnings, Rust + Python tests
```

On macOS, `make verify-macos` adds the native Endpoint Security and Network adapter checks.

## The gates, and what each one is for

| Command | Protects |
|---|---|
| `make verify` | Formatting, lint, and the full test suite |
| `make test-macos-adapter` | The native Endpoint Security adapter's XCTest suite passes |
| `make policy-check` | Shipped bundles are behaviourally correct, not merely parseable |
| `make doctor` | Local configuration is coherent |
| `cargo test -p vigil-cli --test adversarial` | Threat-model attacks still fail |
| `cargo +nightly fuzz run <target>` | Attacker-controlled parsers |

## House rules

These are the conventions a reviewer will hold you to.

**No stubs.** A command that cannot be backed by a real API is absent, not present and printing
"not yet implemented". `vigil policy simulate`, `session inspect`, and `incident export` were
deliberately absent for exactly this reason until the APIs behind them existed.

**Claims need tests.** `ci.yml`'s header says every job corresponds to a claim the README makes. A
claim that cannot be checked mechanically does not belong in the README.

**Say what is not true.** Every module that cannot do something says so in its own documentation.
`vigil status` reports `OBSERVE ONLY`. Reconciliation reports `NO_OBSERVER` rather than
"consistent". This is not modesty — it is the difference between a security tool and a
reassurance generator.

**Fail closed, but scope it.** A managed session loses authority; the rest of the host is
unaffected. VIGIL must never become a machine-wide outage. See `FAIL_CLOSED_MATRIX.md`.

**Decisions are monotone.** Nothing may turn a more restrictive decision into a less restrictive
one. If you find yourself adding a path from `Deny` to `Allow`, stop.

**Bounds everywhere.** Every parser, every recursion, every subprocess wait, every collection
built from untrusted input has an explicit limit. An unbounded loop in a security control is a
denial of service in the thing meant to prevent one.

**Record the reasoning.** Non-trivial decisions get an ADR, including the ones that were wrong.
ADR 0019 is amended rather than rewritten, because the amendment is the useful part.

## Adding a detection rule

Rules are Rust constants in a fixed catalogue — a rule that could execute code would be a way to
run code inside the security control. Add it to the module that fires it, wire the label in
`detection::rule_for_label`, and note that two tests hold the correspondence closed in both
directions: every label maps to a rule, and every rule is reachable from a label.

Calibrate honestly. Severity and confidence are separate axes. Before choosing a weight, ask what
fires it in a *legitimate* workflow — `VIGIL-L021` started at CRITICAL/60 and would have contained
a session on `git status` in any git-lfs repository. A detection nobody believes is worse than no
detection.

## Adding a capability

Extend `LocalAction`, give it a decision in the ladder, add a budget dimension if it has
quantitative blast radius, and backfill that dimension for existing sessions in a migration — a
missing counter denies, which is safe but unexplained.

## Testing style

Tests are named for the property, and adversarial tests for the attack. A failure should read
`ATTACK SUCCEEDED — an agent read a private key from ~/.ssh`, not `test_policy_7 failed`.

Prefer exhaustive over sampled where the space is small: the monotonicity tests enumerate every
action, resource shape, lease state, and risk pair, because "risk accidentally granted something"
is exactly what a sampled test misses.

Anything destructive goes through the adversarial harness's `Disposable` guard. Never write a test
that touches `$HOME`, the repository, or a real credential path.

## Testing the native adapters

`make test-macos-adapter` and `make test-macos-network-adapter` run XCTest suites (ADR 0039).
XCTest ships with Xcode rather than the Command Line Tools, so on a CLT-only machine these
targets cannot run; `swift build --package-path extensions/<package>` still checks that the
adapters compile and link against the real SDK.
