# Fuzzing

Coverage-guided fuzzing of the parsers that take hostile input.

```bash
cargo +nightly fuzz list
cargo +nightly fuzz run canonicalize -- -max_total_time=300
```

Requires a nightly toolchain and `cargo-fuzz` (`cargo install cargo-fuzz`). The `fuzz`
directory is its own workspace so `cargo test --workspace` on stable does not try to build
`libfuzzer-sys`.

## Targets

Each asserts a **property**, not merely absence of a crash. "Did not panic" is a weak result
for a security parser; the interesting question is whether the invariant downstream code
relies on can be violated.

| Target | Property asserted |
|---|---|
| `canonicalize` | Canonicalization is idempotent and deterministic, and its output re-parses. A violation is a signature-forgery primitive. |
| `capability_token` | A verifier trusting no keys accepts nothing, and a *rejected* token never consumes a nonce — otherwise an attacker exhausts a victim's live capability with garbage. |
| `policy_bundle` | Any bundle that loads survives validation, has unique rule ids, and contains no universal allow. |
| `network_analyze` | A destination resolving to a private or metadata address is never classified `Public`, and no finding string carries a raw newline. |
| `path_traversal` | A path judged inside a root genuinely normalizes inside it, and is never simultaneously reported as outside the allowlist. |
| `action_request` | A request body can never produce a verified workload identity, and action hashing is deterministic. |

## Results

Run on an Apple M2, one target at a time:

| Target | Runs | Findings |
|---|---:|---|
| `canonicalize` | 7,601,024 | none |
| `action_request` | 5,947,788 | none |
| `capability_token` | 4,110,441 | none |
| `network_analyze` | 1,981,264 | **1, fixed** |
| `path_traversal` | 1,313,107 | none |
| `policy_bundle` | 1,213,573 | none |

### The finding

`network_analyze` produced a URL whose redacted form contained a raw newline, tripping the
log-forging assertion.

The cause was in `vigil_common::redact::redact_url`: it stripped userinfo and query values —
the credential-leak concerns it was written for — but never stripped **control characters**.
A redacted URL is written into log lines, detector evidence and audit records, so a URL
containing `\n` produced a second, attacker-authored log entry. An operator or SIEM reading
that log would see a fabricated line.

This is the same class of bug the codebase already guards against elsewhere: `excerpt` and
`single_line_excerpt` exist precisely because attacker-influenced text reaches logs, and
`redact_url` predated that reasoning without being brought in line with it. It now routes its
output through `single_line_excerpt`, which strips control characters and bounds length.

Regression tests: `a_url_containing_control_characters_cannot_forge_a_log_line` and
`a_redacted_url_is_bounded_in_length` in `crates/vigil-common/src/redact.rs`. Both crash
artifacts replay clean.

## Corpus and artifacts

`fuzz/artifacts/<target>/` holds inputs that triggered a finding. They are committed: a
crashing input is a regression test that costs nothing to keep, and replaying it is the
fastest way to confirm a fix.

```bash
cargo +nightly fuzz run network_analyze fuzz/artifacts/network_analyze/crash-<hash>
```

## In CI

`.github/workflows/ci.yml` runs short smoke passes so a newly-introduced panic is caught on
the commit that introduces it. Long campaigns are run out of band; the numbers above came
from single-target runs of 40–90 seconds each, which is enough to explore the shallow input
space but not a substitute for sustained fuzzing.
