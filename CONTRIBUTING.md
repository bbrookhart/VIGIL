# Contributing to VIGIL

## Before anything else

VIGIL is a security product. The bar for changes to the enforcement path is higher than for
ordinary software, and the reason is simple: a bug here does not cause a crash, it causes a
silent allow.

Run `make verify` before opening a pull request. It runs formatting, clippy with warnings
denied, and the full test suite including the cross-language contract tests.

## The rules that are not negotiable

**No stubs in security paths.** A function that returns a hardcoded `Allow`, a `TODO` where a
check belongs, or a mock in place of a verification is not acceptable in shipped code, even
temporarily. Mocks in tests are fine. If a control cannot be implemented yet, it does not
exist yet, and the README says so.

**Every security control needs a test that fails without it.** Not a test that exercises the
happy path — a test that would pass if the control were deleted is not evidence. The
convention is to name what the test proves: `an_expired_capability_never_executes`, not
`test_capability_2`.

**Decisions can only get stricter.** There is exactly one operation that merges decisions
(`Decision::combine`) and it returns the more restrictive of two. If you find yourself
wanting to write `decision = Decision::Allow`, stop: that is the shape of the bug the type
system is built to prevent. See [ADR 0002](docs/adr/0002-monotone-decision-algebra.md).

**Failure modes must be explicit.** Every dependency that can fail needs a documented answer
to "what happens when it does?", resolved against the action's impact tier. `unwrap()` and
`expect()` are denied by lint in non-test code.

## Module documentation

Every security-relevant module carries a header:

```rust
//! # Why      — the threat this addresses
//! # What     — the behaviour
//! # Assumptions — what must be true for it to work
//! # Failure mode — what happens when a dependency fails
//! # Evidence — the tests that prove it
```

This is not decoration. "Assumptions" and "Failure mode" are where the real security
properties live, and a reviewer who cannot find them cannot review the change.

## Changing policy

`policies/` is executable security configuration. Changes there are reviewed like code and
are covered by `crates/vigil-policy/tests/policy_behaviour.rs`, which runs against the
shipped bundles rather than fixtures.

Validation rejects the common ways a bundle silently stops enforcing — unknown matcher
fields, conditionless rules, universal allows, `*` host patterns. If validation rejects your
rule, it is usually right.

Note the approver-set semantics: when several rules require approval, their approver roles
are **intersected**. A base rule with a narrow approver set can make an action unapprovable
in combination with an agent rule. The error message says so explicitly when it happens.

## Changing the wire protocol

The protocol is versioned and has two implementations. Changes need:

1. the Rust type updated
2. the Python SDK updated
3. `make contract-fixtures` re-run and the diff reviewed
4. `make test-contract` passing

Fields are added optional with a default. Existing fields never change meaning or type.

## Changing canonicalization

Don't, unless you have read
[`crates/vigil-common/src/canonical.rs`](crates/vigil-common/src/canonical.rs) in full. It
determines what "the same action" means for every approval and every capability. A change
that makes two different actions hash identically is a signature-forgery primitive; a change
that makes the same action hash differently in Rust and Python breaks every deployment.

Both implementations execute `tests/contract/canonical_vectors.json`. Add vectors for
anything you change.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
