# VIGIL Threat Model

## Scope

VIGIL defends the boundary between an agent's intent and the world's state. It does **not**
attempt to make a model safe, align it, or prevent it from being deceived. The model will be
deceived. The design assumes it.

## Trust boundaries

```text
┌─ untrusted ──────────────────────────────────────────────────────┐
│  web pages · email · RAG corpora · MCP servers · other agents    │
│  tool results · memory written by an agent · user input          │
└──────────────────────────────┬───────────────────────────────────┘
                               │ crosses via ingest_content, labelled
┌─ semi-trusted ───────────────▼───────────────────────────────────┐
│  the agent process: model, framework, VIGIL SDK                  │
│  ASSUMED COMPROMISABLE. Holds no credentials for protected tools.│
└──────────────────────────────┬───────────────────────────────────┘
                               │ crosses via the decision API
┌─ trusted ────────────────────▼───────────────────────────────────┐
│  VIGIL Core (decides, signs) │ VIGIL Gateway (executes, holds     │
│                              │ credentials)                       │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌─ protected ──────────────────▼───────────────────────────────────┐
│  mail provider · databases · filesystem · internal APIs · money  │
└──────────────────────────────────────────────────────────────────┘
```

The critical assumption: **the agent process is assumed compromised.** Not "might be" —
*is*, for design purposes. Every control that depends on the agent behaving correctly is
therefore treated as ergonomics, not security. The SDK is ergonomics. The Gateway is security.

## Primary attack: indirect prompt injection to exfiltration

```text
attacker controls a web page the agent will read
  └─ page contains an instruction to read a secret and send it out
     └─ model follows it (working as designed)
        └─ agent requests a secret read          ← in remit, allowed
           └─ agent requests an outbound email    ← the action that matters
```

Controls, in the order they engage, and what each would catch alone:

| Control | Catches | Defeated by |
|---|---|---|
| Trust labelling (`vigil-trace`) | that the page carries no instruction authority | nothing — it is structural |
| Value-flow taint | the secret reaching the outbound argument, under 6 encodings | re-typing the secret with a character changed |
| `injection-driven-egress-001` | untrusted content causally steering an external write | an attack that never touches untrusted content |
| `secret-egress-001` | secret-tainted data crossing the boundary | a secret VIGIL never saw enter |
| Remit `forbidden_egress_classes` | credential classes leaving, with no approval path | a data class not declared |
| Injection heuristics | recognizable injection phrasing | novel phrasing (**expected**) |

No single row is sufficient. That is the design: the phrase-matching row is the weakest and
is documented as such in the detector itself. The rows that carry the weight are
deterministic and do not depend on recognizing the attack text.

## Attacks against VIGIL itself

VIGIL is a high-value target. If it can be bypassed, disabled or lied to, everything behind
it is exposed.

| Attack | Control | Status |
|---|---|---|
| Call the protected tool directly | Agent holds no credentials; Gateway holds them | ✅ tested |
| Forge a capability | Ed25519 signature; Gateway holds no private key | ✅ tested |
| Replay a capability | Single-use nonce, consumed atomically after all other checks | ✅ tested |
| Mutate the action after authorization | Gateway recomputes the hash from the received body | ✅ tested |
| Use another agent's / tenant's capability | Every binding checked at redemption | ✅ tested |
| `alg: none` style token attack | Algorithm allowlist, not read from the token | ✅ tested |
| Exhaust a victim's capability by replaying it | Nonce consumed *last*, only on otherwise-valid redemption | ✅ tested |
| Self-approve a high-impact action | Requester ≠ approver, enforced in the service not the UI | ✅ tested |
| Replay or mutate an approval | Bound to the action hash, single-use, TTL | ✅ tested |
| Prompt-inject a detector into allowing | `DetectorResult` cannot express an allow | ✅ structural |
| Argue a `DENY` back to `ALLOW` | `Decision::combine` is monotone; proved exhaustively | ✅ tested |
| Tamper with the audit log | Hash chain + signed checkpoints; independent verifier | ✅ tested |
| Rewrite history and re-link the chain | Checkpoint signature pins the pre-existing chain state | ✅ tested |
| Truncate the audit log | Checkpoint covering a missing sequence reports truncation | ✅ tested |
| Crash Core with hostile input | Bounded scans, bounded tokens, cycle-safe graph walks | ✅ partial — 12 parsers fuzzed; no chaos testing |
| Forge log lines via identifiers or errors | Narrow id charset; single-line excerpting | ✅ tested |
| Starve the decision path | Linear-time matchers, no regex backtracking in policy | ✅ tested |
| **Bypass by not calling VIGIL at all** | NetworkPolicy: agent egress denied except to the Gateway | ✅ [tested](../../tests/e2e/k8s_bypass.sh) |
| Forge a workload identity in the request body | `verified` is not deserializable; identity comes from the transport | ✅ tested |
| Self-approve over the HTTP API | Approver derived from the authenticated caller, never the body | ✅ tested |
| Impersonate another agent with a valid identity | Proven identity is cross-checked against the body's claims | ✅ tested |
| Redeem a stolen capability from another workload | Gateway binds the presenter to the capability's agent | ✅ tested |

The bypass row was previously ❌ and deployment-dependent. It is now enforced by the
NetworkPolicy in `deploy/helm/vigil`, which denies all egress from agent namespaces except to
the Gateway, and proved by `tests/e2e/k8s_bypass.sh` — which attempts the bypass from inside
an agent pod and asserts the connection is dropped. The script includes a control assertion
that the same tool *is* reachable from VIGIL's own namespace, so a broken cluster cannot make
the test pass for the wrong reason.

The guarantee is still a property of the deployment: install the chart with
`networkPolicy.enabled=false`, or onto a CNI that does not enforce NetworkPolicy, and VIGIL
observes rather than enforces. The chart refuses to render without naming the agent
namespaces, and the test script installs Calico explicitly rather than trusting kind's
default CNI, which does not enforce policy.

## Known gaps

Stated plainly, because a threat model that only lists solved problems is marketing:

1. **The bypass proof has not been executed in this environment.** The chart lints and
   renders, the manifests validate, and the script is syntax-checked, but no cluster was
   available to run it here. It runs in CI on push (`.github/workflows/ci.yml`, job
   `bypass`). Until that job has gone green, treat the ✅ above as "written and reviewable"
   rather than "observed".
2. **Detector coverage is heuristic.** Novel injection phrasing will not match. Mitigated by
   the causal controls, not by claiming better patterns.
3. **Value flow catches mechanical transformation, not paraphrase.** A model that re-types a
   secret with one character changed defeats it. Documented in `flow.rs`.
4. **Symlink resolution depends on the Gateway sharing the filesystem.** `PathRoots` is now
   checked twice: lexically, then against the real filesystem, so `/workspace/link -> /etc`
   followed by `/workspace/link/passwd` is refused (`is_inside_any_resolved`). The resolved
   check only ever *adds* a denial, so it cannot loosen the lexical one. It is only meaningful
   where the Gateway can see the paths it is deciding about; where it cannot, the lexical
   check stands alone and the symlink case is not covered.
5. **Session state is still in memory.** Provenance and budgets are lost on restart, which
   makes VIGIL *more* restrictive (unknown provenance is treated as maximally influenced),
   not less. Audit evidence is now durable and resumes its chain across restarts.
6. **Single-process nonce store.** Multi-replica deployment would permit one replay per
   replica. The Gateway binary and the Helm chart both refuse to start with more than one
   replica until a shared store exists, so this is a capacity limit rather than a live
   vulnerability.
7. **The adversarial corpus is hand-written.** `crates/vigil-cli/tests/adversarial.rs` now
   *executes* sixteen of the §61 scenarios against disposable fixtures rather than describing
   them, and it found a real defect on its first run — deleting the newest audit record left a
   chain that verified cleanly (ADR 0027). But the scenarios are still ones someone thought of.
   Fuzzing covers ten parsers; there is no chaos testing and no generated attack corpus.
8. **Approval preview shows recipient addresses in clear.** Deliberate — an approver who
   cannot see the recipient is rubber-stamping a hash — but it means the console is a
   sensitive surface requiring its own access control, which does not exist yet.

## Residual risk

With the gaps above, VIGIL currently provides: correct, tested, non-bypassable-by-forgery
enforcement **for actions that pass through it**, with tamper-evident evidence **for the
lifetime of the process**.

It does not yet provide: assurance that all actions pass through it, or durable evidence.
Both are deployment and persistence work, not design work.
