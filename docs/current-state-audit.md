# VIGIL current-state audit

Date: 2026-09-05. Baseline: `20c9040c6591a81ad2482a80458d1d7c26df9f5a`
on `vigil_v2`. Status: initial source, documentation and CI review; not a penetration
test, complete line-by-line audit, or production-readiness certification.

## Verdict

Preserve the existing implementation. VIGIL already contains a substantial semantic
authorization system, broker implementations, adversarial tests, and native adapter
prototypes. Its most consequential gap is the separation between broker enforcement
and independently enforced process confinement. Adding more policy features does not
close that gap.

The program charter makes VIGIL the active build. SENTINEL owns physical safety;
FAULTLINE may eventually consume reusable evaluation infrastructure; AEGIS-PQ may
eventually implement identity interfaces. None requires a new platform implementation
in this milestone.

This audit supplements the canonical [enforcement status](security/ENFORCEMENT_STATUS.md),
[trust boundaries](security/TRUST_BOUNDARIES.md), and
[evaluation framework](evaluation/EVALUATION_FRAMEWORK.md). It does not replace them.

## Inspection scope and evidence limits

Inspected the repository inventory, existing security and research documentation,
CI workflow and failed-job logs, and selected source paths for authorization,
approval, leases, budgets, path handling, credential custody and deployment.
Reviewed the later path-fuzz correction against the baseline. The complete source
inventory is not equivalent to reviewing every implementation path.

Rust/Cargo and Docker were not available on PATH in this review environment.
No local Rust suite, container deployment, native macOS activation or model-backed
experiment was executed. Historical CI evidence below belongs to its exact commit.
Document-link and generated-inventory checks are the local checks for this milestone.

## Repository map and maturity

| Component | Primary paths | Assessment and remaining boundary |
|---|---|---|
| Wire format, identities, canonicalization | `crates/vigil-protocol`, `crates/vigil-common`, `crates/vigil-identity` | Existing typed primitives and cross-language fixtures; preserve them. Supplied identity metadata is not automatically OS-authenticated identity. |
| Capability and policy kernel | `crates/vigil-capability`, `crates/vigil-policy`, `crates/vigil-remit` | Existing scoped authority and deterministic policy implementation; retain existing semantics until a concrete invariant requires change. |
| Service decision pipeline | `crates/vigil-core/src/pipeline.rs` | Uses authenticated requests and restrictive decision composition; low-impact policy-error degradation conflicts with the new directive's blanket fail-closed wording. |
| Gateway and credential custody | `crates/vigil-gateway` | Separate execution and credential types; custody depends on trusted backend and deployment isolation. |
| Local brokers and state | `crates/vigil-local` | Filesystem/process/network/Git/MCP brokers, SQLite transactions, approvals and leases exist. Same-user host authority remains outside the demonstrated boundary. |
| Local delegation | `crates/vigil-local/src/lease.rs` | Leases deliberately prohibit delegation. This is a restrictive default, not an implemented attenuation chain. |
| Provenance and detection | `crates/vigil-local/src/provenance.rs`, `crates/vigil-detect` | Existing causal records and detectors; acquisition and completeness must be evaluated against malicious callers. A supplied label alone is not trustworthy provenance. |
| Native enforcement | `crates/vigil-endpoint`, `crates/vigil-network`, `extensions`, `platform/macos` | Native API and policy paths exist; entitled activation and real event coverage remain unproven. |
| SDK and CLI | `sdk/python`, `crates/vigil-cli` | Existing integration and reviewer demo; direct tool access outside integration remains possible. |
| Deployment | `deploy/docker`, `deploy/helm`, `tests/e2e/k8s_bypass.sh` | Existing restricted deployment design; current baseline deployment test failed before its assertions. |
| Evaluation | `fuzz`, crate tests, `docs/evaluation`, `docs/research` | Existing adversarial and property tests; the requested comparative, ablation and paper package is not established by these tests. |

## Trust boundaries and critical gaps

### A1 — Complete mediation is deployment-specific and incomplete on macOS

The current native status explicitly permits direct activity outside brokers.
The new directive's INV-010 is therefore a target property, not a current guarantee.
Specify the protected resources, execution environment and attacker privileges for
each claim. Reject a requested enforced launch when its required boundary is missing;
keep observation-only operation explicitly separate.

Acceptance: an agent with arbitrary code execution inside the declared environment
cannot reach protected files, sockets, tools or credential stores outside mediation.
Test direct access, child processes, alternate paths and loss of enforcement health.
Entitled Apple device evidence is required for native macOS promotion.

### A2 — Human approval and state ownership are not independent locally

`crates/vigil-local/src/approval.rs` explicitly documents that an agent running as the
operator can invoke the same CLI. Constructor separation does not authenticate a
human. The local SQLite database and checkpoint seed also require isolation from
the protected principal; a hash chain does not prevent a writer with the signing key
from replacing evidence.

Acceptance: separately owned service state and keys, authenticated IPC caller identity,
independent approval authority, and negative tests for agent-originated approval,
database mutation and key access. Preserve existing exact-action lease bindings.

### A3 — Reconcile fail-closed semantics before claiming INV-014

The portable pipeline and [failure matrix](security/FAIL_CLOSED_MATRIX.md) document
policy-engine failure allowing constrained tier 0–1 requests. The directive requires
enforcement failures not to become permits. Low-impact classification does not by
itself establish permission to read sensitive information.

Acceptance: define which prerequisite failures always deny; a failed authorization
evaluation must not mint new authority. If any degraded operation is retained, it
must have independently verifiable existing authority and a documented narrower
contract. Add fault-injection tests before changing the claim. Do not silently
change the policy lattice or assume the current implementation meets the directive.

### A4 — Local delegation is intentionally absent

The local lease schema constrains `delegable = 0`. Preserve that default. A future
delegation implementation needs parent-child resource/operation/task intersection,
depth and lifetime limits, shared budget semantics and ancestor-revocation handling.
Do not infer support from identity parent fields or add a boolean that bypasses checks.

### A5 — Filesystem and process race resistance remains bounded

The brokers include canonical resolution and object identity checks. The canonical
status still lists held-directory `openat` design and kernel-confirmed process
identity as missing. Read-before-spawn or path rechecks are not an atomic execution
primitive. Review adversarial interleavings before strengthening TOCTOU claims.

Acceptance: controlled race tests inspect actual side effects and object identity,
including renamed ancestors, symlinks, executable substitution and PID reuse.

### A6 — Provenance integrity needs its own adversary tests

The directive assumes hostile agents and tools. Test omitted or forged source labels,
cross-task provenance substitution and laundering through generated content. Unknown
origin must not silently become trusted. Recorded causal edges demonstrate what the
system observed, not a proof of all influences on a model.

## CI findings at the baseline

The [default-branch run](https://github.com/bbrookhart/VIGIL/actions/runs/33393752732)
tested this baseline and failed three jobs. Rust, Python, contract, evidence, policy
and native adapter jobs succeeded in that run; the overall workflow did not.

| Finding | Observed evidence | Required resolution |
|---|---|---|
| Kubernetes installation timeout | Job `99493263455`: Helm reported `INSTALLATION FAILED: context deadline exceeded`; security assertions were not reached. | Collect pod readiness, scheduling and service diagnostics; fix the cause and rerun the complete test. Do not infer non-bypassability from a timeout. |
| Historical secret-scanner findings | Job `99493263547` reported 17 matches in native signing/health code, tests and `canary.rs` across historical commits. | Triage each match without printing values. Validate synthetic/code-identifier explanations; use narrow documented exceptions only for confirmed false positives. Real credentials require remediation. Do not disable the scanner or exempt directories. |
| Path fuzz assertion | Job `99493263570` panicked on `/workspace/./%5c/..`: raw containment and decoded detection disagreed. | Review and reuse the existing correction below; replay this exact input and the committed regression corpus. A stricter detector result is not itself a successful filesystem escape. |

Commit `566bf3c790ade74c1c9adc14540c6dda11d795a0` contains an existing correction
to encoded path analysis and its fuzz property, plus regression artifacts. Its
[CI run](https://github.com/bbrookhart/VIGIL/actions/runs/33460852961) succeeded,
but that commit is not the audited default-branch head. Review integration rather
than duplicating the patch. A feature-branch success must not stand in for a clean
default-branch run.

The README badge tracked `main` while the repository default is `vigil_v2`; this
milestone corrects that mismatch. `make verify` also described itself as everything
CI runs, though supply-chain, fuzz, deployment and native jobs are separate. This
milestone narrows that wording without removing any gate.

### Deployment test coverage defect

The `k8s_bypass.sh` introduction promises a valid-capability execution, but its
assertions cover gateway health, missing-capability refusal, direct-tool denial and
an internal reachability control. It does not perform that promised authorized
execution. Add a valid-capability path with an observed side effect and a matched
unauthorized request. Avoid using malformed JSON as the only authorization test.

Its `agent_curl` fallback also appends `000` after curl can already emit `000` on a
timeout, making the result `000000`. Separate curl exit status from HTTP status so
network denial is distinguished from kubectl or DNS failures. This is an inspection
finding; installation failed before this assertion in the cited run.

## Existing architecture to preserve and reconcile

- Keep typed request/capability contracts, restrictive decision composition,
  transactional budget/lease accounting and exact-action approval.
- Retain the 54 ADRs and existing nested documentation. Map the directive's suggested
  filenames to canonical documents rather than creating duplicate security models.
- Service-core authority and local lease authorization are distinct implementations.
  Compare their semantics with shared contract vectors before extracting a common
  kernel; similar names alone do not justify merging them.
- Keep probabilistic detectors out of permit issuance. This audit found no reason
  to replace deterministic policy with an LLM judge.
- Keep physical safety in SENTINEL. VIGIL should expose a versioned authorization
  result whose scope and expiry the future safety gateway can independently verify.

## Research gaps and acceptance criteria

The existing research-model document and evaluation framework are valuable starting
points. No `research/` directory exists at this baseline. That absence alone is not
proof of missing functionality; the gap is the requested experimental evidence.

| Requested deliverable | Required evidence before marking complete |
|---|---|
| Naive/static/VIGIL comparison | Same tasks, agent configuration, resources and attack inputs; declared differences and comparable baseline authority; raw traces and side effects. |
| Benign utility | Predefined success criteria, matched benign tasks, completion and approval burden, including failed tasks. |
| Ablations | One mechanism removed at a time with documented interactions and no accidental changes to remaining controls. |
| Model-backed results | Model/version and sampling configuration, repeated trials where stochastic, separation of model compromise, unsafe proposal and actual execution. |
| Formal model | Explicit scope, machine-checkable properties where feasible, counterexample-producing negative model and correspondence limits. |
| Paper | Claim-to-artifact traceability and verified citations; results remain empty until experiments run. |
| Performance | Preserve existing bounded microbenchmark claims; add end-to-end and concurrent-agent measurements without substituting batched timing for per-operation tail latency. |

## Recommended implementation order

1. Restore baseline verification: integrate reviewed existing path fixes, triage
   scanner matches, diagnose deployment readiness, complete its positive control,
   and rerun CI on the resulting commit.
2. Reconcile the security contract: scoped complete mediation, fail-closed rules,
   identity/approval independence, provenance integrity and revocation timing.
3. Build one isolated execution boundary around existing brokers. On macOS, implement
   independently owned service state and authenticate callers; obtain signing and
   entitlement access before claiming activated enforcement.
4. Verify effect-level behavior under races, direct calls, child execution, revoked
   leases and dependency failures. Patch findings with permanent regressions.
5. Add delegation only after isolation and base authority are defensible; preserve
   non-delegable defaults and ancestor revocation semantics.
6. Run bounded comparative experiments, benign tasks and ablations. Record raw
   failures as well as successes; produce the paper from those artifacts.
7. Promote packaging and deployment maturity only with evidence. Keep SENTINEL and
   AEGIS-PQ as documented interfaces until authorized as active builds.

## Milestone disposition

This milestone produces the initial audit and corrects verification descriptions.
It does not resolve the three failing CI jobs, activate macOS enforcement, establish
complete mediation, or complete the master directive. Those remain explicit gates,
not silently accepted limitations for a production release.
