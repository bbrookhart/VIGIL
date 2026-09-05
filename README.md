<p align="center">
  <img src="assets/vigil-hero.svg" alt="VIGIL" width="760">
</p>

<p align="center">
  <strong>Runtime security that turns autonomous-agent intent into bounded, attributable side effects.</strong>
</p>

<p align="center">
  <a href="https://github.com/bbrookhart/VIGIL/actions/workflows/ci.yml"><img src="https://github.com/bbrookhart/VIGIL/actions/workflows/ci.yml/badge.svg?branch=vigil_v2" alt="CI"></a>
  <img src="https://img.shields.io/badge/Rust-1.88%2B-102a43" alt="Rust 1.88 or newer">
  <img src="https://img.shields.io/badge/macOS-Apple%20Silicon-102a43" alt="Apple Silicon macOS target">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-0f766e" alt="Apache 2.0 license"></a>
</p>

VIGIL treats an AI agent as an untrusted principal acting for a human. It combines deterministic
authorization, causal provenance, signed and use-bounded capabilities, quantitative budgets,
specific human approval, semantic side-effect brokers, durable evidence, and native macOS
enforcement adapters.

> **Current boundary:** VIGIL enforces requests routed through its brokers. The macOS Endpoint
> Security and Network Extension products are implemented and tested without entitlements, but
> signed, entitled, activated-device enforcement has not yet been demonstrated. A process that
> bypasses the brokers is not currently confined. See [Enforcement status](docs/security/ENFORCEMENT_STATUS.md).

![VIGIL architecture](assets/architecture.svg)

For the implementation-directive gap analysis and ordered acceptance gates, see the
[current-state audit](docs/current-state-audit.md).

The experimental [local authority daemon](docs/security/LOCAL_AUTHORITY_DAEMON.md)
separates agent, operator and service accounts for approvals and signing state.
It returns authorization decisions; tool execution integration remains pending.

## VIGIL in 60 seconds

| Question | Answer |
|---|---|
| What fails today? | An agent can inherit a user's ambient authority, then be steered by untrusted content into a high-impact side effect. |
| What is VIGIL? | A local-first control plane that decides, scopes, brokers, observes, and records agent actions. |
| What is unusual? | Authority is exact, expiring, use-bounded, non-delegable by default, and causally tied to the content that influenced the action. |
| What is real now? | Portable policy/core/gateway, local filesystem/process/network/secret/MCP brokers, approvals, budgets, risk, incident response, audit, native Swift adapters, tests and benchmarks. |
| What remains? | Apple signing and restricted entitlements, authenticated daemon ownership, activated-device evidence, and stronger kernel-backed process confinement. |
| Where is the proof? | [Generated source inventory](docs/generated/evidence.md), [CI](https://github.com/bbrookhart/VIGIL/actions/workflows/ci.yml), [evaluation framework](docs/evaluation/EVALUATION_FRAMEWORK.md), [ADRs](docs/adr/), and [benchmark method](docs/evaluation/BENCHMARK_METHOD.md). |

<!-- evidence:start -->
The committed inventory currently finds **745 Rust test entry points, 199 Swift test entry
points, 25 adversarial harness tests, 12 fuzz targets, 56 ADRs, 16 workspace
crates, and zero unsafe Rust constructs**. Those are source declarations, not a
hand-maintained “passing” count;
CI supplies execution status and rejects a stale inventory.
<!-- evidence:end -->

## See the security argument, not a feature montage

### 1. Intercept causal attacks before execution

VIGIL records where content came from, how much it is trusted, which sensitive values it carries,
and whether it influenced a proposed action. Pattern detectors add evidence; they never produce
the final permit. The policy result is deterministic and monotone.

![Indirect prompt-injection interception](assets/attack-interception.svg)

### 2. Turn approval into narrow authority

A human approves the material action and resolved resource, not a broad mode switch. The resulting
lease binds the session, principal, action hash, expiry, nonce, and maximum uses. A mismatch,
replay, revocation, exhaustion, or expiration refuses execution.

![Capability lifecycle](assets/capability-lifecycle.svg)

### 3. Contain by subtracting authority

Risk can only reduce authority. Containment revokes leases, withholds mutation, can seal the
session, and can terminate only processes whose recorded identity still matches. It preserves a
tamper-evident event chain and never claims it can undo direct host activity it did not mediate.

![Containment lifecycle](assets/containment-lifecycle.svg)

## Recruiter demo

The shortest useful walkthrough is one command:

```bash
make recruiter-demo
```

It uses a disposable directory and demonstrates four paths:

1. a safe brokered write and read;
2. a policy decision for a protected credential path without reading the credential;
3. an indirect prompt-injection chain stopped before tool execution;
4. a human approval that mints one exact, single-use process lease.

Requirements: Rust 1.88+, Python 3.10+, and a Unix-like host. The demo builds locally and does not
need a cloud account, Apple entitlement, real secret, or network request.

For a two-minute code review, start with:

```bash
python3 scripts/generate_evidence.py --check
make evaluate
```

## Architecture and trust boundaries

```mermaid
flowchart TD
    A[Agent or SDK] --> P[Provenance and policy]
    P --> D{Decision}
    D -->|allow or bounded approval| C[Signed capability]
    D -->|deny or quarantine| E[Audit and incident evidence]
    C --> B[Semantic broker]
    B --> O[OS adapter]
    O --> S[Side effect]
    B --> E
```

The semantic and OS layers see different facts. Brokers understand tool arguments, task scope,
budgets, and capabilities. OS adapters understand process identity, file events, and network flows.
Neither substitutes for the other; intent/execution reconciliation compares both.

The precise trust model is in [Security model](docs/security/SECURITY_MODEL.md) and [Trust
boundaries](docs/security/TRUST_BOUNDARIES.md). The most important rule is simple: **mediated
authority is real; whole-process confinement is not yet a current claim.**

## Enforcement status

| Boundary | Current status | Evidence | Important limit |
|---|---|---|---|
| Portable policy, identity, provenance, capability and audit | Implemented and tested | Rust core, contract vectors, release gates | A decision alone is not enforcement. |
| Filesystem, structured process, payload-free network probe, Git, MCP and secret-use brokers | Broker-enforced | End-to-end and adversarial tests | Direct syscalls can bypass these interfaces. |
| Endpoint Security policy and native adapter | Implemented; entitlement-free parity-tested | Rust simulator + Swift XCTest | Not signed, entitled, installed, or activated in CI. |
| Network Extension policy, product graph and health proof | Implemented; unsigned build/test path | Rust contract + Swift XCTest + Xcode graph | No activated-device flow proof yet. |
| Human approval and local evidence store | Structurally bounded | SQLite constraints and negative tests | Same-user CLI/storage is not an authenticated daemon boundary. |
| Full macOS process containment | Not demonstrated | Roadmap only | Must not be inferred from broker behavior. |

![Enforcement maturity](assets/enforcement-maturity.svg)

The canonical, file-by-file matrix is [docs/security/ENFORCEMENT_STATUS.md](docs/security/ENFORCEMENT_STATUS.md).

## Security properties

| Property | Mechanism | Representative evidence |
|---|---|---|
| Default deny | Explicit policy lattice; unknown actions fail parsing | [Policy model](docs/policy/POLICY_MODEL.md), policy behavior tests |
| Least authority | Exact resource/action bindings, expiry, uses, budgets | [Capability model](docs/policy/CAPABILITY_MODEL.md), ADR 0017 |
| No detector-issued permits | Detectors only restrict or enrich evidence | ADR 0002, decision monotonicity tests |
| No path-as-identity assumption | Canonical resolution, device/inode checks, content hash for executable replacement | ADRs 0031–0032, broker race tests |
| Replay resistance | Signed capability, nonce consumption, action-hash recomputation | Capability and gateway tests, fuzz target |
| Risk only subtracts | Monotone risk transitions; containment revokes authority | ADRs 0018, 0033, incident tests |
| Secret use without disclosure | Opaque handles and purpose-bound providers | [Secret broker model](docs/policy/SECRET_BROKER_MODEL.md), ADRs 0009, 0042 |
| Evidence survives failure | Durable event chain and signed checkpoints | ADRs 0019, 0040, audit tests |
| Missing native controls stay visible | Explicit observe/degraded/broken states | [Fail-closed matrix](docs/security/FAIL_CLOSED_MATRIX.md), status/doctor tests |
| Memory safety stance | `#![forbid(unsafe_code)]` in every workspace crate | Generated evidence gate |

Each invariant has rationale, mechanism, code, tests, bypass analysis, and future hardening in
[Security invariants](docs/security/SECURITY_INVARIANTS.md).

## Evaluation and performance

Security evaluation is layered:

- **release gates** encode conditions that make a candidate unshippable;
- **adversarial scenarios** attempt traversal, injection, replay, budget, process, network,
  credential, MCP, reconciliation, and control-plane attacks;
- **fuzzing** targets 12 unauthenticated or attacker-controlled parsers and normalization paths;
- **cross-language fixtures** require Rust, Swift, and Python to agree on signed bytes;
- **detection-quality tests** gate precision and recall against the committed corpus;
- **native suites** compile and test the public Apple adapter boundaries without claiming
  entitlement activation.

Run the review suite with `make evaluate`; see [Evaluation framework](docs/evaluation/EVALUATION_FRAMEWORK.md)
for hypotheses, pass criteria, known blind spots, and a result-recording template.

The published Apple M2 measurements report the full in-process decision shapes at roughly
**27–101 µs typical cost**, with a worst reported batched-sample p95 of **0.105 ms**. Local broker
authorization paths measure **18–273 µs** depending on durable evidence writes. These are not
network, entitlement, or true single-operation tail-latency claims. Hardware, toolchain,
methodology, exclusions, and raw Criterion locations are documented in
[benchmarks](docs/operations/benchmarks.md) and [benchmark method](docs/evaluation/BENCHMARK_METHOD.md).

## Build and test

```bash
# Portable workspace
cargo build --workspace --locked
cargo test --workspace --locked

# All portable contributor gates
make verify

# macOS adapter suites and unsigned product graph
make verify-macos
```

The Python SDK deliberately has no runtime dependencies. Development extras are isolated:

```bash
make dev-setup
make test-python
```

## Repository map

| Path | Purpose |
|---|---|
| `crates/vigil-core` | Decision pipeline, API, provenance and capability minting |
| `crates/vigil-local` | Durable local sessions, semantic brokers, risk, incidents and audit |
| `crates/vigil-endpoint` | Deterministic Endpoint Security policy contract and simulator |
| `crates/vigil-network` | Deterministic Network Extension flow policy contract |
| `extensions/endpoint-security` | Native Swift Endpoint Security adapter and tests |
| `extensions/network-filter` | Native Swift Network Extension adapter and tests |
| `platform/macos` | Containing app, System Extension lifecycle and health evidence |
| `sdk/python` | Dependency-free agent instrumentation SDK |
| `policies`, `remits`, `manifests` | Shipped security configuration and schemas |
| `docs/adr` | Decision records, including rejected simpler designs |
| `fuzz` | Fuzz targets, corpora and committed regression artifacts |

Start with [docs/START_HERE.md](docs/START_HERE.md) for reviewer paths by available time.

## Research questions

VIGIL is a research preview organized around testable questions:

- Can causal provenance stop indirect prompt injection without making a probabilistic detector
  the authorization authority?
- Can capability leases and quantitative budgets express useful agent autonomy without ambient
  user privilege?
- Can semantic intent and OS-observed execution be reconciled precisely enough to detect bypass?
- Which fail-closed choices protect the managed agent without making the rest of a developer's
  workstation unavailable?
- What evidence is sufficient to claim a native enforcement boundary is active rather than merely
  configured?

The argument, limitations, and related systems are developed in the [research model](docs/research/VIGIL-runtime-security-model.md).

## Roadmap to a defensible macOS claim

1. Move policy, approval, keys, and evidence behind an authenticated, separately owned daemon.
2. Obtain Apple Endpoint Security and Network Extension entitlements and sign the product graph.
3. Validate install, activation, upgrade, timeout, restart, and uninstall on dedicated devices.
4. Feed live process/file/network observations into reconciliation and prove bypass detections.
5. Publish reproducible device evidence and reclassify only the boundaries it supports.

Details and acceptance evidence are in [macOS enforcement roadmap](docs/roadmap/MACOS_ENFORCEMENT.md).

## Honest limitations

- VIGIL does not protect against root, a compromised kernel, or a user who deliberately disables
  the product.
- The local SQLite store is tamper-evident, not tamper-proof against code running as the same user.
- Approval call paths are structurally separated, but same-user CLI access is not human identity.
- Broker-mediated rollback covers broker writes only.
- Endpoint and network data-path code has entitlement-free tests; CI cannot prove an entitled
  extension received real events.
- Benchmarks characterize controlled code paths, not production end-to-end latency or efficacy.

These are release constraints, not footnotes. See [Publication checklist](docs/release/PUBLICATION_CHECKLIST.md).

## Interview and portfolio paths

- [Interview guide](docs/portfolio/INTERVIEW_GUIDE.md) — 14 hard design questions with concise answers.
- [Portfolio summary](docs/portfolio/PORTFOLIO_SUMMARY.md) — one-page project narrative and evidence map.
- [Five-perspective review](docs/portfolio/RECRUITER_REVIEW.md) — recruiter, security, systems, research and maintenance verdicts.
- [Architecture](docs/architecture/ARCHITECTURE.md) — implementation-level control flow.
- [Threat model](docs/threat-model/THREAT_MODEL.md) — assets, adversaries, threats and assumptions.
- [Operations](docs/operations/INSTALLATION.md) — deployment and operating guidance.

## License

Apache License 2.0. See [LICENSE](LICENSE).
