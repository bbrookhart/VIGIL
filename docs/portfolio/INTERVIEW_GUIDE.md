# VIGIL interview guide

These are the questions a skeptical security, systems or platform interviewer is likely to ask.
Answers are deliberately short enough to say aloud, with the next tradeoff made explicit.

## 1. What problem is VIGIL actually solving?

Agents inherit a user's ambient authority even though their task is narrow and their plan can be
influenced by untrusted content. VIGIL makes authority explicit, scoped, short-lived, budgeted and
auditable at runtime. The current system strongly mediates requests that use its brokers; native
macOS work exists to close direct-syscall bypass.

## 2. Why isn't ordinary RBAC enough?

RBAC answers what a role generally may do. Agent authorization also needs the exact action and
resource, task/session, causal inputs, expiry, use count, aggregate budget and current risk. VIGIL
can use roles as an input, but does not let a broad role become an unlimited runtime capability.

## 3. Why are capabilities better than a boolean permit?

A signed capability transports the precise result to the enforcement point and lets it verify the
action hash, principal/session, expiry, nonce and uses without trusting caller claims. The cost is
key/nonce/revocation state and a strict canonicalization contract, which is why cross-language
fixtures and replay tests are release gates.

## 4. Can a detector or LLM authorize an action?

No. Detectors and models can add evidence or restriction. Final authority comes from deterministic
policy and a monotone decision algebra. This keeps a probabilistic classifier from being the
component that turns uncertainty into a high-impact side effect.

## 5. How does VIGIL address indirect prompt injection?

It records provenance for content and references the influencing nodes on a candidate action.
Untrusted instruction taint and tracked sensitive-value flow can restrict the action before a
broker executes it. This is not a promise to classify every injection string; it is a design that
does not rely on perfect classification to establish authority.

## 6. What does “fail closed” mean without breaking the host?

Managed-session policy or evidence failure reduces that session's authority. It should not make
unmanaged host traffic unavailable. The native design has explicit absent, disabled, degraded,
broken and active states, so a failed control is visible without pretending the entire machine is
protected or taking an unrelated workload down.

## 7. How are budgets race-safe?

The local store reserves under SQLite `BEGIN IMMEDIATE` and constraints prevent consumed plus
reserved from exceeding the limit. The broker authorizes and executes after reservation, then
commits or refunds. If reconciliation fails after an effect, the reservation stays held instead of
creating uncounted authority.

## 8. How do approvals avoid becoming a bypass button?

An approval binds the session, action and resolved resource hash. The operator can choose bounded
TTL and use count, not change the action. A lease may upgrade `REQUIRE_APPROVAL`, never `DENY`, and
risk is applied afterward. The current weakness is approver identity: same-user CLI access is not
an OS trust boundary until a daemon and authenticated UI own it.

## 9. How do you handle path and executable TOCTOU attacks?

Paths are canonically resolved; filesystem objects are compared by device/inode around the open;
executables also use a content hash when bounded in size, so immediate inode reuse cannot validate
a replacement. This narrows races but does not eliminate every name-to-open gap. A safe
handle-relative native path or kernel mediation is still needed.

## 10. Why both semantic brokers and OS extensions?

Brokers know intent—tool arguments, task scope, hostname, secret purpose and budget. The OS knows
what executable, file object and flow actually occurred. Brokers alone are bypassable; OS events
alone lack semantic intent. Reconciliation between both is the core defense-in-depth argument.

## 11. What is the strongest current limitation?

Full macOS enforcement is not demonstrated. The native adapters and product graph have
entitlement-free tests, but there is no committed signed, entitled, activated-device evidence.
Also, local approvals and evidence share the user's trust domain. The documentation treats both as
release blockers for a stronger claim.

## 12. How do you know Rust, Swift and Python agree on signed data?

They consume committed canonicalization vectors and signed policy/request fixtures. CI regenerates
fixtures and fails on a byte diff. This matters because a serialization mismatch at a signature
boundary is an authorization vulnerability, not just an interoperability bug.

## 13. What does the test count prove?

Only source inventory and breadth. The generated count is mechanically checked, while CI reports
execution. Confidence comes from mapping specific boundaries to negative tests, adversarial
scenarios, release gates, fuzz properties, cross-language fixtures and explicit blind spots—not
from adding all tests into one “passing” number.

## 14. What would you build next?

First, a separately owned authenticated daemon for approvals, policy, keys and evidence. Second,
signed/entitled device validation across install, restart, upgrade and fault cases. Third, live
intent/execution reconciliation and coverage metrics. Those steps close actual trust boundaries;
more policy features would not.

## Useful code-review anchors

- `crates/vigil-policy` — deterministic policy and combination.
- `crates/vigil-capability` — token issue/verify/nonce semantics.
- `crates/vigil-local/src/authorize.rs` — profile → lease → risk ordering.
- `crates/vigil-local/src/process_broker.rs` — structured execution and identity checks.
- `crates/vigil-cli/tests/adversarial.rs` — attacker-oriented system evidence.
- `extensions/endpoint-security` and `extensions/network-filter` — native adapter boundaries.
