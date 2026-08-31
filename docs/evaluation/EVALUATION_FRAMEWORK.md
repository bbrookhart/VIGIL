# Security evaluation framework

## Purpose

This framework turns VIGIL's security claims into falsifiable questions. It separates source
inventory, test execution, controlled benchmark measurements and native-device validation. A
large test count is not a substitute for coverage of a trust boundary.

## Evaluation layers

| Layer | Question | Command/evidence | Pass criterion |
|---|---|---|---|
| Policy algebra | Can order or a later stage weaken a prior restriction? | workspace unit/property tests | Exhaustive ordering properties hold; no detector issues a permit |
| Capability contract | Can a token be replayed, substituted, expired or overused? | capability/Gateway tests; fuzz target | Every altered material binding is rejected without consuming a valid nonce |
| Broker effect | Does denial happen before the broker's side effect and budget commit? | `vigil-cli` local control-plane tests | Host fixture remains unchanged on denial; reservations reconcile |
| Adversarial behavior | Do named attacker strategies cross a claimed boundary? | `cargo test -p vigil-cli --test adversarial -- --nocapture` | Every scenario observes the documented refusal/detection and host-safety guard |
| Release integrity | Would a known invariant regression still ship? | `cargo test -p vigil-cli --test release_gates` | All release-blocking conditions remain encoded and pass |
| Parser robustness | Can attacker-controlled bytes panic or forge meaning? | 12 fuzz targets + committed artifacts | No crash; target-specific semantic property holds |
| Cross-language bytes | Do Rust, Swift and Python sign/verify the same contract? | CI contract job | Generated fixtures are byte-stable and every implementation agrees |
| Detection quality | Does the committed corpus meet its labelled threshold? | `cargo test -p vigil-detect --test detection_quality` | Thresholds inside the test pass; corpus/version recorded |
| Performance | Is control-plane cost bounded on a named machine? | Criterion + benchmark report | Method and exclusions recorded; no unsupported production SLO inference |
| Native adapter | Does public adapter code compile and preserve policy semantics? | macOS Swift suites | Deadline/signature/generation/peer/health tests pass |
| Activated device | Does the OS actually route relevant events through the signed product? | dedicated evidence bundle | Promotion gate in `ENFORCEMENT_STATUS.md` satisfied |

## Attack families

| Family | Representative strategies | Expected result today |
|---|---|---|
| Indirect injection | hostile web/tool/memory content influences privileged action | causal evidence restricts or denies before mediated execution |
| Path confusion | traversal, double encoding, symlink swap, prefix collision | resolved-resource policy and object checks refuse tested escapes |
| Executable confusion | relative/PATH lookup, shell/interpreter, file replacement, PID reuse | structured broker rejects or detects identity change |
| Capability abuse | action/resource substitution, replay, expiry, exhaustion | verification refuses and preserves valid nonce state |
| Budget abuse | concurrency, refund manipulation, session churn | atomic limits hold; churn contributes risk/standing |
| Network abuse | direct IP, private/metadata range, DNS rebinding, stale generation | mediated/network-policy path refuses |
| Credential abuse | raw export, wrong purpose/target, error disclosure, local IPC reach | broker refuses/discards; protected IPC attempt is high risk |
| MCP abuse | server substitution, tool-list drift, arguments outside scope | process/manifest binding and per-resource authorization refuse |
| Control-plane abuse | policy rollback, key/store paths, evidence rewrite | protected mediated paths refuse; audit edit is detectable |
| Bypass/reconciliation | undeclared child/effect or denied operation observed | reconciliation raises evidence; live macOS completeness remains open |

## Metrics

### Correctness

- scenario pass/fail by stable test name;
- false-negative and false-positive counts for labelled detection corpus;
- policy decision and reason-code parity across implementations;
- capability substitution matrix coverage;
- count of release conditions encoded as executable gates.

### Robustness

- fuzz target, duration, corpus hash and newly minimized artifacts;
- crash, timeout or unbounded-allocation findings;
- behavior under missing/stale/corrupt policy, store and health evidence.

### Performance

- hardware, OS, toolchain, profile and commit;
- sample construction, warm-up, iterations and statistic type;
- in-process decision, local durable authorization and native deadline path measured separately;
- explicit non-measurements such as network RTT, entitlement activation and end-to-end model time.

### Native coverage

- event/flow types requested and observed;
- OS/hardware version, entitlement and code-signing inspection;
- extension state, preferences, provider health and policy generation;
- allow/deny/timeout/restart/upgrade/uninstall outcomes;
- blind spots and unsupported APIs per OS version.

## Running the portable evaluation

```bash
make evaluate
python3 scripts/generate_evidence.py --check
```

Full contributor verification is `make verify`; macOS compile/parity/product verification is
`make verify-macos`. Fuzz smoke runs in CI because a complete pass is intentionally longer.

## Result record template

```text
Commit:
Date/time (UTC):
Runner / OS / hardware:
Toolchains:
Commands:
Scenario totals and failures:
Detection corpus version and confusion matrix:
Fuzz duration and artifacts:
Benchmark raw-data location:
Native entitlements / signing / activation evidence:
Known deviations:
Reviewer:
```

Do not copy a result from another commit. Generated source counts may be compared across commits;
execution status must link to the exact CI run or signed device bundle.

## Known blind spots

- No activated-device Endpoint Security or Network Extension coverage measurement is committed.
- Same-user direct access to local approval/storage is outside the current trust boundary.
- Fuzz smoke is shallow; it is a regression signal, not an exhaustive parser proof.
- The detection corpus is curated and cannot represent open-world prompt-injection prevalence.
- Benchmark samples do not establish production tail latency or security efficacy.
