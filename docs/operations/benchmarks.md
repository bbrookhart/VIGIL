# Decision pipeline latency

Measured, not claimed. Reproduce with:

```bash
cargo bench -p vigil-core --bench decision_pipeline
```

## Hardware

| | |
|---|---|
| CPU | Apple M2, 8 cores |
| Memory | 8 GB |
| OS | macOS 26.5.2 |
| Toolchain | rustc 1.94.0, `bench` profile (opt-level 3, LTO thin) |

A latency figure without the machine it came from is not a result. These numbers are from a
laptop; server-class hardware and a loaded system will differ.

## Results

Per-operation cost of a full in-process decision, 100 samples per shape:

| Action shape | p50 | p95 | p99 | max |
|---|---:|---:|---:|---:|
| `deny` — shell execution (deterministic short-circuit) | 27.1 µs | 27.9 µs | 28.7 µs | 28.8 µs |
| `deny` — injection chain with value-flow tracking | 48.1 µs | 49.8 µs | 50.3 µs | 50.4 µs |
| `allow` — low-impact read | 82.5 µs | 83.9 µs | 97.5 µs | 105.5 µs |
| `require_approval` — external write, all detectors | 101.2 µs | 105.3 µs | 106.7 µs | 152.5 µs |

**Worst case across all shapes: p95 = 0.105 ms, p99 = 0.107 ms.**

Against the design targets of p95 ≤ 25 ms and p99 ≤ 50 ms, that is roughly two orders of
magnitude of headroom. The pipeline is not the bottleneck in any realistic agent loop, where a
single model call costs hundreds of milliseconds.

## What these numbers mean — and what they do not

**Read the percentiles carefully.** Criterion collects *batched* samples: each of the 100
samples is the mean of several hundred iterations. The percentiles above are therefore
percentiles over sample means, not over individual operations, and batching averages away
individual-operation outliers. A true per-operation p99 — which is what a latency SLO usually
means — would be higher, and measuring it needs single-iteration timing that criterion's
batched mode does not provide. Treat these as a tight bound on *typical* cost, not as a tail
guarantee.

**What is measured:** the complete in-process decision path — schema validation, identity
checks, canonicalization, tool-manifest resolution, provenance and taint analysis, DLP
classification, remit evaluation, budgets, deterministic policy over all 30 shipped rules, the
four built-in detectors, composite risk, capability minting (Ed25519 signature), and the audit
chain append.

**What is not measured:** network round trips to Core, TLS handshakes, and any remote or
model-backed detector. Those are properties of a deployment rather than of the pipeline, and
folding them in would flatter the code by hiding what it actually costs. A deployed p95
includes at minimum one network hop each way.

## Observations

**The deterministic short-circuit works.** A denied shell execution costs 27 µs against 83 µs
for a permitted read, because `skip_detectors_on_deterministic_deny` (on by default) skips
analysis that cannot change an already-denied outcome. The saving is visible and matches the
design intent in `docs/architecture/README.md`.

**Value-flow tracking is affordable.** The Demo 1 shape — a provenance graph with tracked
secret values, checked across six encodings — costs 48 µs, less than a plain permitted read.
The read is slower because it reaches the allow path: capability minting, an Ed25519
signature, and an audit append.

**Signature and audit dominate the allow path.** The two allow-path shapes (83 µs, 101 µs) are
the only ones that mint a capability and append to the hash chain, and they are the two
slowest. If the pipeline ever needs optimizing, that is where to look — not in policy
evaluation.

## Reproducing

Criterion writes raw samples to `target/criterion/decide/*/new/sample.json`. The percentiles
above were computed from those directly, because criterion's own console output reports a
confidence interval on the *mean* rather than percentiles:

```bash
cargo bench -p vigil-core --bench decision_pipeline
python3 - <<'PY'
import json, glob
for path in sorted(glob.glob("target/criterion/decide/*/new/sample.json")):
    d = json.load(open(path))
    per_iter = sorted(t/i for t, i in zip(d["times"], d["iters"]))
    q = lambda p: per_iter[min(len(per_iter)-1, round(p*(len(per_iter)-1)))]
    name = path.split("/decide/")[1].split("/new/")[0]
    print(f"{name:<44} p50={q(.50)/1000:7.1f}µs p95={q(.95)/1000:7.1f}µs p99={q(.99)/1000:7.1f}µs")
PY
```


---

# Local authorization latency

Reproduce with:

```bash
cargo bench -p vigil-local --bench local_authorization
```

Same hardware as above. Figures are Criterion's `[lower, estimate, upper]` confidence interval
for the per-operation mean, over 100 samples. They are not percentiles; reporting p99 would mean
computing it, and this benchmark does not.

## What is being measured

The path every brokered request takes: profile ladder, session risk, lease consumption, detection
recording, risk aggregation, and approval raising. It has grown steadily and had never been
measured before this.

| Path | lower | estimate | upper |
|---|---:|---:|---:|
| `allow` — permitted workspace read | 18.3 µs | **18.4 µs** | 18.5 µs |
| `deny` — outside the workspace, no detection | 20.0 µs | **20.0 µs** | 20.1 µs |
| `deny` — protected resource, fires a detection | 264 µs | **273 µs** | 283 µs |
| `require_approval` — raises an approval request | 198 µs | **198 µs** | 199 µs |

MCP calls authorize every resource in their arguments independently, so cost scales with the
argument document rather than with the call:

| MCP call | lower | estimate | upper |
|---|---:|---:|---:|
| 1 resource | 192 µs | **222 µs** | 279 µs |
| 8 resources | 420 µs | **450 µs** | 483 µs |
| 32 resources | 780 µs | **810 µs** | 846 µs |

Roughly 20 µs of fixed cost plus ~19 µs per resource. The extraction cap is 64, so the worst
case a hostile server can force is around 1.3 ms.

## Budgets

| Path | Budget | Why |
|---|---|---|
| Permitted brokered request | < 100 µs | The common case, on every agent action |
| Denial without a detection | < 100 µs | Equally common; a refusal must not be slower to notice |
| Denial with a detection | < 1 ms | Rare, and it writes durable evidence |
| Approval raised | < 1 ms | Rare, and gated on a human anyway |
| MCP call, capped arguments | < 2 ms | Bounded by the 64-resource extraction cap |

All are met with margin.

## Why the expensive paths are acceptable

The 14× gap between an allow and a detection-firing deny is almost entirely SQLite transaction
commits: a detection writes a detection row, a risk signal, a re-derived aggregate, sometimes a
transition and an incident — each a `BEGIN IMMEDIATE` on a WAL database.

That cost buys durable evidence, and **it is not a trade worth making**. Batching or deferring
those writes would mean a session could act on a decision whose record had not landed, which is
precisely the property `INVARIANTS.md` item 12 exists to prevent. Latency here is paid once per
agent tool call, at LLM pace; a few hundred microseconds is not observable to anyone.

## What this is not

**This is not the Endpoint Security deadline path.** That path is `vigil-endpoint`, which is pure
in-memory, allocation-light, and does no I/O at all — precisely because an ES authorization
callback has a hard kernel deadline and a miss is a security failure. The numbers above are for
the semantic broker path, which runs at agent-tool-call rate and has no such deadline. Conflating
the two would be the wrong reading of every figure on this page.

## A measurement artifact worth recording

The first version of this benchmark reported 832 µs for the detection path. The fixture was moved
*into* the timed routine, so its `Drop` — which removes a directory tree — was inside the timer.
Returning the fixture instead moved the filesystem work outside and the real figure fell to 273 µs.

Roughly two-thirds of the original number was the benchmark measuring itself. It is recorded here
because a latency figure nobody has checked for that mistake is not a result.
