# Security Policy

## Status

VIGIL is pre-production. It is not ready to protect a real system, and the gaps that make
that true are listed explicitly in [`docs/threat-model/README.md`](docs/threat-model/README.md#known-gaps)
and in the README's [project status](README.md#project-status).

If you are evaluating VIGIL for a production deployment, start with those two lists.

## Reporting a vulnerability

Please report security issues privately.

Use **GitHub private vulnerability reporting**:

> [Security → Report a vulnerability](https://github.com/bbrookhart/VIGIL/security/advisories/new)

That channel is private to the maintainers until an advisory is published, so a report never
sits in a public issue tracker while the fix is being written.

**Do not** open a public issue for a vulnerability.

Please include:

- what an attacker can do that they should not be able to
- the shortest reproduction you have
- which component and version
- whether it is already public

You will get an acknowledgement within 3 working days and an assessment within 10.

## What we consider a vulnerability

VIGIL's security claims are the invariants in
[`docs/architecture/README.md`](docs/architecture/README.md). Anything that breaks one is in
scope, and the following are considered **critical**:

- an action reaching a protected tool without a valid capability
- a capability that verifies for an action it was not minted for
- replay of a capability or an approval
- an agent obtaining data or capabilities belonging to another tenant
- any path from `DENY` back to execution
- a detector, model output, or untrusted content causing an outcome to become *less*
  restrictive
- forging, modifying or truncating audit evidence without verification failing
- an agent modifying its own policy, remit or budgets

Also in scope, at lower severity: crashes from hostile input, denial of service against the
decision path, secret material appearing in logs, evidence or error messages, and
cross-tenant identifier leakage.

## What is not a vulnerability

- **A novel prompt injection that the phrase detectors do not match.** Expected, and
  documented in `crates/vigil-detect/src/injection.rs`. Injection detection is the weakest
  control by design; report it if it also evades the *causal* controls (provenance, taint,
  remit, policy), because that is the interesting case.
- **An agent bypassing VIGIL in a deployment with no network isolation.** Currently a known
  architectural gap, not a bug — see the threat model. Report it if it happens in a
  deployment that *does* isolate.
- Findings against components that do not exist yet (Console, Control, MCP gateway).
- Missing hardening in `CoreConfig::development()`, which is documented as development-only.

## Disclosure

Coordinated disclosure. We will agree a timeline with you, defaulting to 90 days or the fix
release, whichever comes first. Credit is given unless you prefer otherwise.

## Security-relevant design

Every security module carries a `Why / What / Assumptions / Failure mode / Evidence` header
naming the threat it addresses and the tests that prove the control. The most concentrated
statements of the security model:

| File | Property |
|---|---|
| `crates/vigil-protocol/src/decision.rs` | Decisions can only become more restrictive |
| `crates/vigil-protocol/src/detector.rs` | Detectors cannot express an allow |
| `crates/vigil-protocol/src/trust.rs` | Trust only ever flows downward |
| `crates/vigil-common/src/canonical.rs` | One byte-exact form per action |
| `crates/vigil-capability/src/signer.rs` | Verification order, and why it is that order |
| `crates/vigil-gateway/src/lib.rs` | Why the action hash is recomputed, never trusted |
| `crates/vigil-audit/src/lib.rs` | What a hash chain proves, and what only checkpoints prove |
