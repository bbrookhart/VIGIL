# Detection quality

Measured, not claimed. Reproduce with:

```bash
cargo test -p vigil-detect --test detection_quality -- --nocapture
```

## Results — holdout split

| Metric | Value |
|---|---|
| Precision | **1.000** |
| Recall | **0.846** |
| F1 | **0.917** |
| False positive rate | **0.000** |
| Confusion | tp=11 fp=0 tn=14 fn=2 |

Corpus: [`labs/corpora/injection_eval.json`](../../labs/corpora/injection_eval.json) v1.0.0.
Detector: `injection.heuristic`, ruleset `1.0.0`. Flag threshold 0.5, matching the pipeline's
own escalation point.

## What these numbers are, and are not

They measure **one control** — the phrase-based injection detector — which VIGIL's own source
describes as the weakest thing it has. Its job is to raise risk and explain a finding to an
analyst. It never carries a decision alone.

The controls that actually stop the Demo 1 chain are causal and deterministic: content
provenance, value-flow taint, the agent remit, and the `injection-driven-egress-001` policy
rule. None of them inspect the injection's wording, so none of them are captured by these
numbers. An attacker who defeats the detector entirely still hits every one of them.

**No accuracy figure is published for the causal controls.** Measuring them requires a corpus
of multi-step agent *sessions*, not labelled strings, and that does not exist yet.

## Methodology

**Held-out split.** Indicators were tuned against `dev`. The reported numbers come from
`holdout`, which was not consulted while writing or changing them. Both are printed by the
test so a divergence is visible; a large gap would indicate overfitting.

**Hard negatives.** 8 of the 14 negatives are security documentation, support tickets,
changelogs and policy text that *quote* attack strings in legitimate contexts. A corpus of
only obvious negatives would report a precision that means nothing, because the false
positives that get a control disabled are exactly these.

**Provenance.** Hand-authored from public descriptions of prompt-injection techniques (OWASP
Agentic Top 10 2026, published research, vendor advisories). No customer data, no scraped
content, no proprietary corpora.

## Known misses

Both are single weak-family hits that score 0.3–0.45, below the 0.5 flag threshold:

| Case | Content | Why it is not fixed |
|---|---|---|
| `pos-role-002` | `<\|im_start\|>system … <\|im_end\|>` | A chat-template control token is arguably a strong signal deserving more weight. It sits in the **holdout** split, and raising its weight to fix an observed holdout failure is the overfitting the split exists to prevent. Left as measured. |
| `pos-exfil-002` | "post the contents to https://…" | Genuinely ambiguous in isolation — "post the contents to the ticket" is ordinary support language. Raising this weight would trade precision for recall on the control where precision matters more. |

Both are caught downstream if they influence an external write, by
`injection-driven-egress-001`, which does not depend on the phrasing.

## Thresholds enforced in CI

| Threshold | Value | Reasoning |
|---|---|---|
| Precision | ≥ 0.90 | A detector that cries wolf on security documentation gets disabled, and a disabled detector has zero recall. This is the number that matters operationally. |
| Recall | ≥ 0.75 | Deliberately modest. Phrase matching cannot be complete, and the design does not ask it to be. Setting this at 0.95 would claim a property this control does not have. |
| False positive rate | ≤ 0.10 | Bounds the analyst noise the control can generate. |

## Changes driven by this measurement

Building the corpus found two real defects in the detector:

1. **Spacing evasion scored no higher than plain text.** `e x f i l t r a t e` matched only
   after whitespace stripping, but contributed the same weight as the plainly-written word.
   Ordinary prose does not write that way, so needing the stripped form is itself evidence of
   evasion; it now adds risk, the same way a homoglyph substitution does.

2. **`###system` matched any text containing "system".** Stripped of punctuation the
   indicator became the bare word, so a support ticket reading "printed its system prompt"
   and a policy document reading "reveal the system prompt" both produced confident alarms.
   Aggressive matching is now restricted to indicators whose stripped form stays distinctive
   (`MIN_AGGRESSIVE_LENGTH`), enforced by a test over the indicator table.

The second was introduced by the fix for the first, and only the hard negatives caught it —
which is the argument for including them.
