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
