# VIGIL Architecture

This document describes what is built. Components in the design that do not exist yet are
listed in [Not yet built](#not-yet-built) rather than described as though they do.

## The one-sentence version

An agent asks VIGIL Core for permission; Core decides; if the answer is yes, Core mints a
short-lived capability bound to that exact action; the Gateway — which holds the credentials
the agent does not — verifies the capability and performs the action.

## Decision flow

```text
  agent
    │
    │ 1. ingest_content(origin, trust, content, tracked_values)
    │    every user turn, tool result, fetched page, memory read
    ▼
┌─────────────────────────────────────────────────────────────────┐
│ VIGIL Core                                                      │
│                                                                 │
│  session state ── provenance DAG ── budget ledger ── history    │
│                                                                 │
│  2. decide(action):                                             │
│     schema & identity → canonicalize → manifest                 │
│       → provenance/taint/DLP → remit → budgets                  │
│         → deterministic policy → detectors → risk               │
│           → approval → combine → capability                     │
└───────────────────────────┬─────────────────────────────────────┘
                            │ DecisionResponse { decision, capability?, reasons[] }
                            ▼
                      agent (holds a capability, still no credentials)
                            │ 3. execute(action, capability)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ VIGIL Gateway                                                   │
│   recompute action hash from the received body                  │
│   verify signature → lifetime → bindings → consume nonce        │
│   enforce constraints → broker injects credentials              │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
                    real tool / API / database
```

## Why the pipeline is ordered the way it is

The build specification lists provenance and taint analysis *after* deterministic policy.
VIGIL runs them **before**, deliberately.

The shipped policy rules match on taint and on untrusted influence —
`injection-driven-egress-001` is precisely such a rule. Evaluating policy against an empty
context would discard its most valuable inputs and reduce it to a static allowlist.

The invariant the specification's ordering protects — *deterministic policy is authoritative*
— is preserved by a stronger mechanism than ordering:

- detector results have no field that can express an allow ([`DetectorResult`](../../crates/vigil-protocol/src/detector.rs))
- every stage folds through [`Decision::combine`](../../crates/vigil-protocol/src/decision.rs),
  which returns the more restrictive of two decisions

Because `combine` is commutative, associative and monotone, **order cannot weaken a decision
no matter what runs first**. That is a property proved by exhaustive test rather than
asserted by convention.

## Components

| Crate | Responsibility | Holds |
|---|---|---|
| `vigil-common` | Canonicalization, hashing, ids, redaction, clock | — |
| `vigil-protocol` | Normalized action, trust labels, decisions, events | — |
| `vigil-policy` | `PolicyEngine` trait + deterministic rule engine | policy bundles |
| `vigil-remit` | Agent purpose, tool boundaries, budgets | remits |
| `vigil-trace` | Provenance DAG, trust propagation, value flow | session secrets (transient) |
| `vigil-detect` | Injection, DLP, SSRF, command safety | detector rulesets |
| `vigil-capability` | Issue and verify capabilities | Core: private key. Gateway: public only |
| `vigil-audit` | Hash chain, signed checkpoints, verifier | audit signing key |
| `vigil-core` | The pipeline, risk, approvals, session state | capability + approval private keys |
| `vigil-gateway` | The PEP, credential broker | **tool credentials** |

### The separation that matters

Core can authorize but cannot execute. Gateway can execute but cannot authorize — it holds
only public keys. Compromising either one alone does not yield both capabilities:

- an attacker with Core cannot reach a tool without going through Gateway
- an attacker with Gateway cannot mint a capability, because it has no signing key

This is spec §57 (privilege separation) expressed in the type system: `CapabilityIssuer` owns
`SigningKeyMaterial`, `CapabilityVerifier` owns only `VerifyingKey`, and there is no
constructor that gives a verifier a private key.

## Trust model

[`TrustLevel`](../../crates/vigil-protocol/src/trust.rs) is a total order. The only combining
operation returns the **minimum**:

```rust
TrustLevel::SystemTrusted.combine(TrustLevel::WebUntrusted) == TrustLevel::WebUntrusted
```

Content derived from a system prompt and a hostile web page is web-grade. There is
deliberately no operation that raises trust — promotion requires a separately authorized
admin action, never an inference inside the data path. This makes Invariant 4 ("trust cannot
self-escalate") structural rather than a rule someone must remember to check.

Content with no recorded provenance is treated as influenced by the session's *lowest-trust*
content. Missing instrumentation therefore makes VIGIL stricter, not blind — the opposite of
the usual default, and the reason under-reporting is a safe failure.

## Failure modes

Every dependency failure resolves against the action's impact tier (Invariant 7):

| Failure | Tier 0–1 (reads) | Tier 2+ (mutations, external, privileged) |
|---|---|---|
| Policy engine unavailable | `ALLOW_WITH_CONSTRAINTS` + `DEGRADED_MODE_ALLOW` | `DENY` + `FAIL_CLOSED` |
| Detector timeout or error | risk floor 0.35, `DETECTOR_DEGRADED`, confidence *lowered* | same, plus tier-driven denial |
| Nonce store unavailable | — | `DENY` (an unavailable replay check is treated as a replay) |
| Session store unavailable | error, no decision | error, no decision |
| Audit chain unwritable | decision fails | decision fails |

The last one is deliberate: an unauditable decision is a failed decision. A system that
keeps enforcing while silently losing its evidence is worse than one that stops.

## Latency architecture

The fast synchronous path is pure computation: canonicalization, identity, manifest lookup,
taint, remit, budgets, deterministic policy, built-in detectors. No network, no model, no
database.

The conditional deep path (`skip_detectors_on_deterministic_deny`, default on) skips analysis
that cannot change the outcome — if the deterministic layers already denied, an expensive
semantic detector is not consulted, and its result is recorded as `Skipped` so the decision
record shows what was and was not run.

**No latency figures are published.** The design targets p95 ≤ 25 ms, but no benchmark has
been run on documented reference hardware, so quoting a number would be inventing one.

## Not yet built

- **VIGIL Control** — tenants, OIDC, RBAC, policy lifecycle, simulation, canary rollout
- **VIGIL Console** — the operator UI
- **MCP / A2A gateways** — the protocol layer models them; no proxy exists
- **Persistence** — session state, audit and approvals are in-memory only. A Core restart
  loses session provenance (which makes it *more* restrictive) and loses the audit chain
  (which is unacceptable for production and is why this is pre-production)
- **Multi-replica correctness** — `InMemoryNonceStore` is single-process. A multi-replica
  deployment needs a shared store, or a capability can be redeemed once per replica. This is
  documented in the type's own docs.
