# VIGIL: a runtime security model for autonomous AI agents

**Artifact type:** implementation-backed research preview<br>
**Version:** 0.1 design baseline<br>
**Platform focus:** local Apple Silicon macOS, with a portable Rust control plane

## Abstract

Autonomous AI agents turn untrusted text and model output into actions under a user's ambient
authority. Conventional application authorization answers whether a principal may access a
resource, but it often lacks the causal context, bounded delegation, quantitative limits and
execution evidence needed when the principal is a probabilistic planner. VIGIL explores a runtime
model in which an agent is untrusted, authority is explicit and short-lived, provenance follows
the information that influenced an action, deterministic policy makes the final authorization
decision, semantic brokers perform high-level effects, and operating-system observers enforce and
reconcile actual execution.

The artifact implements the portable decision, capability, broker, risk, incident and audit paths,
plus macOS Endpoint Security and Network Extension adapters tested without restricted
entitlements. It does not yet demonstrate activated whole-process confinement. That distinction is
central: the current result is evidence for mediated agent actions and native policy contracts,
not a claim that arbitrary process syscalls are contained.

## Problem statement

An agent commonly runs with the user's files, network credentials, process privileges, tool
servers and local IPC endpoints. Its intended task is narrower than that ambient authority. A
malicious webpage, repository, email, tool response or memory entry can influence a plan without
ever becoming a traditional executable exploit. If authorization observes only the final tool
name—“send email,” “read file,” “run command”—it misses why that action was proposed and which
untrusted sources shaped it.

This resembles the confused-deputy problem: a component with authority is induced to use that
authority for another party's purpose. Capabilities are a natural tool because they make authority
explicit and attenuable, but an agent runtime also needs provenance, budgets, approval semantics,
evidence and OS-level coverage.

## Threat model

### Protected assets

- credentials and credential-use channels such as SSH agents and container sockets;
- files outside the declared workspace and security-sensitive paths inside it;
- network reachability and sensitive destinations;
- process execution, persistence and privilege transitions;
- policy, keys, approval state and audit evidence;
- the human operator's time and decision quality.

### Adversary

The primary adversary controls some content that the agent consumes and can craft tool arguments,
paths, URLs, encodings, MCP descriptions or repository state. A stronger adversary may induce the
agent to run arbitrary code as the logged-in user. Root, a compromised kernel, malicious firmware
and a user intentionally disabling the product are out of scope.

### Security goals

1. A mediated side effect requires explicit authority bound to the material action and resource.
2. Untrusted causal influence can restrict an action but never authorize it.
3. Authority expires, is use-bounded, is non-delegable by default and is revocable.
4. Aggregate actions remain within quantitative budgets.
5. Policy, missing evidence and control failures do not become allow-all.
6. A reviewer can reconstruct intent, decision, execution evidence and response.
7. Native enforcement status is proven from current signals, not inferred from configuration.

### Non-goals

VIGIL is not an LLM alignment method, malware detector, endpoint replacement, secret manager,
kernel sandbox or proof against an administrator. It does not promise that a detector recognizes
every injection. It instead prevents a detector or model from being the final source of authority.

## Model

### Agent as untrusted principal

The human's login session is not treated as the agent's authorization. A session has an explicit
profile, task, workspace, principal, budgets and risk state. Children and tools join the provenance
graph, but authority does not silently transit to them.

### Provenance before pattern matching

Content nodes carry origin, trust and taint. Actions cite influencing nodes. Detectors can recognize
credential shapes, injection patterns or suspicious event sequences, but their output only adds
evidence or restriction. This separates a fallible recognition problem from the deterministic
authorization boundary.

### Monotone authorization

Decisions form a restrictiveness ordering. In the local path:

```text
profile decision → exact lease upgrade (approval only) → risk degradation
```

A lease may upgrade only `REQUIRE_APPROVAL` for its exact binding. It cannot change `DENY`. Risk is
applied last and can only subtract. Order-independent combination and negative tests make this an
executable invariant rather than a documentation convention.

### Capability shape

A capability binds tenant/environment, agent and instance, session, principal, action kind, tool,
operation, resource/action hash, validity window, nonce, use limit and delegation constraints. The
Gateway recomputes the presented action hash and consumes the nonce/use atomically. The token is a
transport for already-decided authority, not an alternative policy language.

### Semantic brokers

Filesystem, process, network probe, Git, MCP and secret-use brokers understand intent the kernel
does not: structured arguments, workspace, host name, secret purpose, task scope and budgets. They
use reserve → authorize → execute → commit/refund so failure does not create uncounted authority.
They also narrow path and executable replacement races by comparing object identity and hashes.

### Native enforcement and reconciliation

Semantic mediation is bypassable by a process that makes direct OS calls. Endpoint Security and
Network Extension adapters are therefore a second, necessary boundary. The intended architecture
compares the semantic action with kernel-observed process/file/network activity and flags
undeclared children, side effects, resource mismatch and denied operations that nevertheless
occurred.

The repository implements both policy contracts and Swift adapter/product paths. Current CI can
compile and parity-test public APIs without restricted entitlements. It cannot establish that a
signed extension was installed, received every relevant event, met deadlines or survived real
restart/upgrade failure. The [canonical status](../security/ENFORCEMENT_STATUS.md) keeps those
states separate.

## Failure semantics

For a managed session, unavailable or invalid policy must reduce authority. For the rest of the
host, a VIGIL failure should not create a system-wide outage. Native health therefore distinguishes
absent, disabled, degraded, broken and fully enforced states. The Network Extension design requires
four current planes—activation, exact preferences, authenticated provider readiness and
generation-matched flow proof—before reporting full enforcement.

## Evaluation methodology

The artifact uses complementary evidence rather than a single test count:

- unit and property tests for policy algebra, canonicalization and capability binding;
- end-to-end broker tests for effect-before/after behavior and budgets;
- release gates for claims whose failure makes a candidate unshippable;
- adversarial scenarios for traversal, injection, replay, race, process, network, MCP and
  control-plane attacks;
- fuzz targets for attacker-controlled parsers and normalization code;
- shared fixtures across Rust, Swift and Python;
- a labelled injection corpus with precision/recall thresholds;
- Criterion measurements with hardware, toolchain and exclusions recorded;
- native Swift tests for deadlines, signatures, generations, peer identity and health-state
  composition.

The current inventory is generated by `scripts/generate_evidence.py`; runtime pass/fail state is
reported by GitHub Actions. The detailed hypotheses and recording format are in the
[evaluation framework](../evaluation/EVALUATION_FRAMEWORK.md).

## Results supported by the artifact

The source and automated suites support these limited conclusions:

1. deterministic decisions and capability bytes are stable across the implemented languages;
2. exact binding, expiry, replay and use-count checks reject tested substitutions;
3. semantic brokers prevent tested policy/budget violations before their own side effects;
4. the adversarial harness encodes named attack paths without using live credentials or damaging
   the host;
5. the native policy contracts and adapters agree in entitlement-free tests;
6. in-process decision and local authorization costs are small relative to an agent/model loop on
   the measured Apple M2 setup.

They do not establish universal attack detection, real-world efficacy, full native coverage,
production SLOs or protection from same-user direct bypass.

## Limitations and open questions

- **Same-user control plane:** approval and storage need a separately owned authenticated daemon.
- **Native proof:** signing, entitlements and dedicated-device fault injection are outstanding.
- **Coverage:** Endpoint Security and Network Extension expose specific event/flow models, not a
  universal observation interface; coverage must be measured per OS release.
- **Time of check/use:** object checks narrow races but safe handle-relative operations need a
  carefully reviewed native/unsafe boundary or OS mediation.
- **Human factors:** specific approval reduces scope but not fatigue or deceptive presentation.
- **Provenance completeness:** SDK and broker provenance is only as complete as the mediated path;
  reconciliation needs live observers.
- **External evidence:** local audit is tamper-evident, not externally witnessed or highly available.

## Related systems and design lineage

VIGIL follows the least-privilege and complete-mediation tradition, and uses capabilities to avoid
ambient authority. Capsicum demonstrates how application-level compartments can map policy to OS
capability primitives. VIGIL differs by modeling agent-specific causal provenance, approval and
budgets, while its current macOS path uses public user-space System Extension frameworks rather
than a new kernel primitive. OWASP's agentic-security work supplies a contemporary threat taxonomy;
VIGIL treats that taxonomy as evaluation input, not as proof of coverage.

## References

1. Robert N. M. Watson et al., [Capsicum: Practical Capabilities for UNIX](https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf), USENIX Security 2010.
2. Apple, [Endpoint Security framework](https://developer.apple.com/documentation/endpointsecurity).
3. Apple, [System Extensions](https://developer.apple.com/system-extensions/).
4. Apple, [Filter and tunnel network traffic with NetworkExtension](https://developer.apple.com/videos/play/wwdc2025/234/).
5. OWASP GenAI Security Project, [Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
6. OWASP Cheat Sheet Series, [AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
7. VIGIL, [Threat model](../threat-model/THREAT_MODEL.md), [ADRs](../adr/), and [security invariants](../security/SECURITY_INVARIANTS.md).
