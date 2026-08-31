# VIGIL portfolio summary

## One line

VIGIL is an implementation-backed exploration of least-authority runtime security for autonomous
AI agents, spanning a portable Rust control plane, a dependency-free Python SDK, native Swift
macOS adapters, adversarial evaluation and honest enforcement-boundary reporting.

## The engineering problem

An agent's task is narrow; its process permissions are broad. Untrusted web, repository, email,
memory or tool content can steer it into using the user's authority for a different purpose. The
system needs more than input filtering: it needs explicit authority, causal evidence, quantitative
limits, an execution boundary and durable incident records.

## Design response

- Treat agent/session/child/tool identities as untrusted claims until bound at an enforcement point.
- Use deterministic monotone policy for the final permit.
- Carry authority as signed, resource-bound, expiring, use-limited capabilities.
- Track the provenance and taint of content that influenced a proposed action.
- Perform effects through semantic brokers with atomic budget reservation and reconciliation.
- Add specific human approval without allowing it to override a denial.
- Correlate semantic intent with native process/file/network observations.
- Preserve hash-chained evidence and subtract authority during incident response.

## Scope delivered

The repository contains 15 Rust workspace crates, Python instrumentation, native Endpoint Security
and Network Extension packages, a macOS product graph, policy/remit/manifest configuration,
deployment artifacts, 54 architectural decisions, generated evidence, adversarial/release/fuzz
gates and documented benchmark methods. See [generated inventory](../generated/evidence.md) for
current mechanically derived counts.

## Most important technical decisions

1. **Detector evidence is not authorization.** It avoids putting a probabilistic model at the
   final privilege boundary.
2. **A path is not an identity.** Resolution plus object/content checks defend tested swap and
   replacement cases while documenting the remaining race.
3. **Approval is a capability mint.** It grants one exact action/resource binding, not a global
   bypass window.
4. **Native health is compositional.** Activation, exact preferences, provider identity and current
   generation/flow evidence must agree before a strong status is displayed.
5. **Security claims are generated or linked to evidence.** Static “passing” counts were removed.

## Evidence

- `make recruiter-demo` — safe action, protected resource, injection interception and one-use approval.
- `make evaluate` — release gates, adversarial scenarios and detection-quality tests.
- `.github/workflows/ci.yml` — Rust/Python/Swift/contracts/policy/supply-chain/fuzz/deployment jobs.
- [Security invariants](../security/SECURITY_INVARIANTS.md) — mechanism, tests, bypass and hardening.
- [Benchmarks](../operations/benchmarks.md) — named Apple M2 methods and exclusions.
- [Research model](../research/VIGIL-runtime-security-model.md) — threat model and related systems.

## Honest boundary

VIGIL currently constrains what an agent does through mediated interfaces. It does not yet confine
an arbitrary macOS process. Signed Apple entitlements, an authenticated daemon and activated-device
coverage evidence are the critical path, documented in the
[macOS roadmap](../roadmap/MACOS_ENFORCEMENT.md).
