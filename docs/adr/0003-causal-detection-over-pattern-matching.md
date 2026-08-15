# ADR 0003 — Causal detection over pattern matching

**Status:** Accepted
**Date:** 2026-08-14

## Context

The instinctive way to defend against prompt injection is to detect injection text: match
"ignore previous instructions", score the content, block when the score is high.

This fails in both directions. It misses novel phrasing, since an attacker can rewrite freely
and the space of instructions is the space of language. And it fires on benign content —
security documentation, a support ticket quoting an attack, a user asking about prompt
injection — which produces false positives that get the control switched off.

## Decision

The question VIGIL asks is not *"does this look like prompt injection?"* but:

> **Did untrusted content causally influence the agent toward an unauthorized or dangerous
> operation?**

That is answered structurally, not statistically:

1. **Provenance** — every piece of content entering a session is labelled with its origin and
   trust level, and derived content takes the *minimum* trust of its inputs.
2. **Value flow** — sensitive values are tracked from the moment they enter, and matched in
   later actions across six encodings (verbatim, base64, hex, percent, reversed,
   separator-stripped).
3. **Policy on the causal fact** — `injection-driven-egress-001` denies any external write
   whose causal history includes untrusted instruction-like content, regardless of payload.

Phrase matching still exists (`vigil-detect/src/injection.rs`) but is explicitly the weakest
control. It raises risk and explains a finding to an analyst; it never carries a decision
alone.

## Consequences

**Good.** The Demo 1 chain is blocked by a rule that never inspects the injection's wording.
Base64-wrapping the secret does not help: the taint travelled with the value, not with the
bytes. Novel phrasing does not help: the causal rule does not depend on recognizing text.

Benign content that merely *mentions* injection scores low confidence rather than high risk,
because confidence rises only with the number of distinct indicator families.

**Cost.** It requires instrumentation. Content that is never ingested has no provenance. This
is mitigated by the default direction: an action with unknown provenance is treated as
influenced by the session's *lowest-trust* content, so under-reporting makes VIGIL stricter,
never blind.

**Limit.** Value flow catches mechanical transformation, not paraphrase. A model that re-types
a secret with one character changed defeats it. Documented in `flow.rs` and in the threat
model's known gaps.

## Alternatives rejected

**LLM judge as primary control.** Sees attacker-controlled input by definition, costs money
and latency per action, and cannot be deterministic. Retained as an optional detector behind
`SemanticDetector`, structurally unable to authorize anything.

**Blocking all untrusted content from reaching the model.** Would make agents useless —
reading untrusted content is the job. VIGIL constrains what the agent may *do* afterwards.
