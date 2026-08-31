# Benchmark method and claims policy

## Rule

A number may appear in public documentation only when the repository records the workload,
hardware, OS, toolchain, statistic, raw-data location and exclusions. “Fast” without those fields
is not evidence.

## Existing measurements

The current Apple M2 results are in [operations/benchmarks.md](../operations/benchmarks.md). They
cover:

- the complete in-process portable decision pipeline;
- durable local authorization, including SQLite writes on evidence-producing paths;
- MCP argument-resource scaling.

They do **not** cover network round trips, TLS, model calls, activated Endpoint Security deadlines,
Network Extension flow callback latency, installation, IPC or production concurrency.

## Reproduction

```bash
cargo bench -p vigil-core --bench decision_pipeline
cargo bench -p vigil-local --bench local_authorization
```

Criterion raw samples are written below `target/criterion/`. Preserve that directory or archive the
relevant JSON with the commit when producing a release result.

## Required report fields

| Field | Required content |
|---|---|
| Artifact | Commit SHA and dirty/clean state |
| Machine | CPU model, core count, memory and power mode |
| Platform | OS and version; virtualized or bare metal |
| Toolchain | `rustc -Vv`, cargo version and benchmark profile |
| Workload | Exact benchmark/group/case and fixture sizes |
| Sampling | Warm-up, sample count, iterations/batching and outlier policy |
| Statistic | Mean/CI, median or percentile—never interchange them |
| Raw data | Archive path or artifact link |
| Exclusions | Every material component outside the timed region |
| Interpretation | What decision the result supports and what it cannot support |

## Tail-latency caution

Criterion commonly reports confidence intervals over batched sample means. A p99 calculated over
those means is not a per-operation p99 because batching averages individual outliers. The current
report says so explicitly. A production tail claim requires single-operation instrumentation under
representative load, coordinated-omission analysis and enough samples for the claimed quantile.

## Native measurement plan

After entitlements are available, measure native paths separately:

1. kernel event timestamp to adapter verdict;
2. policy lookup and signature/generation validation outside the deadline callback;
3. callback timeout and fail-closed behavior under CPU/memory pressure;
4. Network Extension new-flow verdict latency and policy refresh;
5. containing-app/daemon IPC latency and cold restart;
6. end-to-end agent request to side effect, reported separately from model time.

Every device run must capture missed/dropped events and deadline failures alongside latency. A fast
path that loses coverage is not a successful optimization.

## Regression policy

CI records benchmarks but does not gate on GitHub-hosted-runner timing because noisy shared runners
create false precision. Gate deterministic size/complexity bounds in tests; investigate timing
trends on controlled hardware before setting a threshold.
