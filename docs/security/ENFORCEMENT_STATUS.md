# Canonical enforcement status

**Last audited:** 2026-08-31<br>
**Scope:** repository source and entitlement-free CI; no claim of activated-device enforcement

This is the canonical status page. “Implemented” means code exists. “Tested” means an automated
suite exercises its stated boundary. “Broker-enforced” means the side effect is enforced only when
the caller uses that broker. “Native-ready” means the Apple adapter/product path exists but has not
crossed signing, entitlement, installation, activation, and real-event acceptance gates.

## One-screen verdict

VIGIL is a substantial, tested **semantic control plane and native-enforcement prototype**. It is
not yet a demonstrated whole-process macOS sandbox. Direct file, process, IPC, or network activity
outside the brokers remains a bypass until signed and entitled OS enforcement is activated and its
health is proven on a device.

| Area | State | What is enforced now | Evidence | Missing before stronger claim |
|---|---|---|---|---|
| Portable schema and canonicalization | Implemented + tested | Exact request validation and stable signed bytes | Rust/Python contract tests and Swift fixtures | Versioning and migration evidence at deployment scale |
| Identity and provenance | Implemented + tested | Supplied semantic identity and causal graph invariants | `vigil-identity`, `vigil-protocol`, provenance tests | OS-authenticated caller identity for local sessions |
| Deterministic policy/remit | Implemented + tested | Monotone decision combination for mediated actions | policy behavior suite; ADRs 0002, 0004 | None for the semantic decision boundary |
| Signed capabilities | Implemented + tested | Action/resource hash, expiry, nonce and use bounds at Gateway | capability, Gateway, replay and fuzz tests | Production key custody and rotation runbook evidence |
| Filesystem broker | Broker-enforced | Workspace resolution, budgets, atomic writes, deletes, renames, list/read | local control-plane and adversarial tests | OS interception of direct filesystem syscalls; held-directory `openat` design |
| Structured process broker | Broker-enforced | Exact executable, args, CWD, environment and timeout | process broker and adversarial tests | Process-tree confinement and kernel-confirmed execution identity |
| Network probe | Broker-enforced and intentionally bounded | Host/port allowlist, address checks, budgets; no payload | network broker tests | It does not intercept sockets opened elsewhere |
| Git broker | Broker-enforced | Remote validation and dangerous Git config neutralization | Git broker/adversarial tests; ADR 0026 | Direct Git/process bypass at OS boundary |
| MCP proxy | Broker-enforced | Manifest/process binding and argument-level authorization | MCP and adversarial tests; ADRs 0020, 0029, 0034 | Coverage for MCP traffic that does not use the proxy |
| Secret broker | Interface + Keychain Git-auth vertical slice | Purpose/target binding; provider returns success/failure, not bytes | simulator, Keychain macOS tests; ADRs 0009, 0042 | HTTP/signing provider operations and daemon-owned custody |
| Budgets and approvals | Implemented + tested | Atomic reservations; exact, expiring, use-bounded leases | SQLite constraints and local tests | Human identity/authenticated approval boundary |
| Risk, incidents, containment | Implemented + tested | Monotone risk, lease revocation, mutation withholding, safe process-stop checks | local/incident/adversarial tests | Live OS observer for complete activity and process tree |
| Audit chain and checkpoints | Implemented + tested | Tampering becomes evident for mediated event history | audit verification and checkpoint tests | Store isolation from the same untrusted user and external anchoring |
| Endpoint Security policy | Implemented + simulated | Deterministic event decisions in Rust | simulator, signed fixture and release tests | Live `ES_EVENT_TYPE_AUTH_*` evidence |
| Endpoint Security Swift adapter | Native-ready; entitlement-free tested | Fast-path mapping, deadlines, signed policy and XPC peer checks in tests | macOS CI XCTest | Apple entitlement, signing, install/activate/upgrade/device matrix |
| Network Extension policy | Implemented + simulated | Flow decisions over process, domain, port, IP set, generation and budget | Rust simulator/contract tests | Live flow coverage and failure/restart evidence |
| Network Extension product | Native-ready; unsigned build/test path | Provider, preferences, policy transport, activation state and four-plane health model | Swift/Xcode tests | Signing, entitlement, install, provider callbacks, generation-matched live flow proof |
| Kubernetes non-bypassability | Deployment-enforced when chart assumptions hold | Network path forced through the Gateway in the kind scenario | `tests/e2e/k8s_bypass.sh` | This does not establish the macOS boundary |

## Status vocabulary

| Label | Required evidence |
|---|---|
| Implemented | A non-stub code path exists and failure modes are explicit. |
| Tested | Automated positive and negative tests execute that code path. |
| Broker-enforced | The broker performs or refuses the side effect; callers can still go around it. |
| Simulated | A deterministic event source exercises the policy contract without the native source. |
| Native-ready | Public native APIs compile and parity tests pass without claiming live activation. |
| Activated | The signed, entitled component is installed, enabled and observed on a device. |
| Fully enforced | Activation, exact configuration, authenticated provider readiness and current flow/event proof all agree. |
| Broken | A required plane failed, drifted or produced contradictory evidence; never silently downgraded. |

## Claims that are safe today

- VIGIL provides deterministic, least-authority decisions and signed, bounded capabilities.
- Its semantic brokers enforce the requests routed through them and record durable evidence.
- It has native macOS adapter and product code with entitlement-free compile/parity tests.
- Missing or stale native evidence is represented explicitly rather than reported as protected.

## Claims that are not safe today

- “VIGIL sandboxes any macOS agent process.”
- “Endpoint Security or Network Extension enforcement is installed by this repository.”
- “An agent cannot grant its own approval” at the same-user operating-system boundary.
- “The event database cannot be modified by the protected user.”
- “A green simulator or XCTest run proves real kernel event coverage.”

## Promotion gate

No row may be promoted to activated or fully enforced without a signed evidence bundle containing:

1. product identifiers, build commit, signing identities and entitlement inspection;
2. clean install, enable, restart, upgrade, disable and uninstall results;
3. authenticated component and policy-generation evidence;
4. permitted and denied real events/flows, including timeout and stale-policy behavior;
5. OS version/hardware matrix and known blind spots;
6. independent reproduction instructions.

See [macOS enforcement roadmap](../roadmap/MACOS_ENFORCEMENT.md), [fail-closed matrix](FAIL_CLOSED_MATRIX.md),
and [security invariants](SECURITY_INVARIANTS.md).
