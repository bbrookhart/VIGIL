# Start here

VIGIL is easiest to review as a security argument with executable evidence, not as a directory
tour. Choose the path that matches the time you have.

## Five minutes: recruiter or hiring manager

1. Read [VIGIL in 60 seconds](../README.md#vigil-in-60-seconds).
2. Scan the [architecture image](../assets/architecture.svg) and [enforcement status](security/ENFORCEMENT_STATUS.md).
3. Look at the [generated evidence inventory](generated/evidence.md).
4. Read the [portfolio summary](portfolio/PORTFOLIO_SUMMARY.md).

Expected conclusion: the project has a coherent security thesis, substantial implementation and
test depth, and clearly labelled native-enforcement gaps.

## Fifteen minutes: security engineer

1. Read [Security model](security/SECURITY_MODEL.md) and [Trust boundaries](security/TRUST_BOUNDARIES.md).
2. Select three items from [Security invariants](security/SECURITY_INVARIANTS.md) and follow their
   code/test references.
3. Inspect `crates/vigil-cli/tests/adversarial.rs` and `release_gates.rs`.
4. Review [Fail-closed matrix](security/FAIL_CLOSED_MATRIX.md) and one relevant ADR.

Focus on the distinction between semantic mediation and OS confinement, and on whether a later
stage can ever widen a more restrictive decision.

## Thirty minutes: systems or platform engineer

1. Read [Architecture](architecture/ARCHITECTURE.md).
2. Trace one request through `vigil-protocol` → `vigil-core` → `vigil-capability` →
   `vigil-gateway` or a `vigil-local` broker.
3. Read the [Endpoint](architecture/ENDPOINT_SECURITY_MODEL.md) and
   [Network Extension](architecture/NETWORK_EXTENSION_MODEL.md) models.
4. Run `make recruiter-demo` and `make evaluate`.
5. Review [Benchmark method](evaluation/BENCHMARK_METHOD.md).

## Research reviewer

Start with [VIGIL's runtime security model](research/VIGIL-runtime-security-model.md), then use the
[evaluation framework](evaluation/EVALUATION_FRAMEWORK.md) to distinguish hypotheses already
tested from native-device claims that remain open.

## Interview preparation

Use the [interview guide](portfolio/INTERVIEW_GUIDE.md). Every answer includes the tradeoff or
limitation an experienced reviewer is likely to probe next.

## One-command evidence checks

```bash
python3 scripts/generate_evidence.py --check
python3 scripts/check_docs.py
make evaluate
```

The generated counts describe source declarations. GitHub Actions remains the execution record.
