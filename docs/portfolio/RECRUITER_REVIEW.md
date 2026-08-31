# Five-perspective portfolio review

**Review date:** 2026-08-31<br>
**Artifact:** recruiter-optimization pull-request branch<br>
**Decision:** strong interview portfolio; not yet a public release

## 1. Recruiter / hiring manager

**Verdict: ready for a technical-screen portfolio link after CI is green.**

The first screen now answers what VIGIL is, why it exists, what is implemented, what remains and
where the proof lives. The one-command demo and time-boxed `START_HERE` paths reduce reviewer cost.
The project reads as one coherent systems-security thesis rather than a catalogue of features.

**Residual risk:** the project is large. A reviewer who never runs the demo still needs the hero,
60-second table and architecture image to carry the story. Keep that opening stable and resist
moving implementation detail above it.

## 2. Security engineer

**Verdict: claims are reviewable and appropriately bounded.**

The invariant register maps rationale, mechanism, tests, boundary, bypass and hardening. The
canonical status page refuses to equate broker mediation, simulation, native compile tests and
activated enforcement. Static “passing” counts are gone; source declarations are generated and CI
is the execution record. Code fixes strengthen executable identity and SDK transport validation.
A fresh candidate fuzz run then found that malformed trailing bytes could turn an unset Keychain
attribute into a present kind; the parser now fails closed and the reproducer is committed. That
finding-and-repair loop is stronger evidence than a static test-count claim. A later MCP-manifest
fuzz case exposed a harness mismatch: an unstable exponent-form number round-tripped lossily, but
the real baseline path already refused it during canonical hashing. The harness now mirrors that
acceptance boundary, and an actual-store regression proves the rejected schema is never recorded.
A later path campaign found a genuine separator mismatch: detection folded Windows backslashes
before normalization while the shared containment helper did not. The common normalizer now treats
both separator spellings structurally, so suspicion and permission cannot disagree on that form.

**Residual risk:** same-user approval/storage and missing signed-entitled device evidence remain the
dominant trust-boundary gaps. A full-history secret scan and independent review are still required
before publication.

## 3. Systems / platform engineer

**Verdict: the architecture and failure semantics are credible.**

The repository distinguishes semantic intent from kernel-observed execution, documents the
reserve/authorize/execute/reconcile sequence, tests cross-language signed bytes, and now gates the
actual locked-dependency MSRV. Docker, CI, macOS adapter and product boundaries are visible.

**Residual risk:** deployment claims need real device and failure-injection evidence. The native
roadmap correctly prioritizes daemon ownership, signing/entitlements, lifecycle, coverage and
reconciliation before more product features.

## 4. Research reviewer

**Verdict: a clear implementation-backed research preview.**

The white paper states threat model, goals/non-goals, model, supported results, limitations and
related systems. The evaluation framework separates correctness, adversarial, fuzz, detection,
performance and native-device evidence. Benchmark statistics are qualified rather than promoted as
production SLOs.

**Residual risk:** there is not yet a comparative baseline, independent reproduction, open-world
efficacy study or activated-device dataset. Future research claims should be framed as hypotheses
until those artifacts exist.

## 5. Open-source maintainer

**Verdict: review structure is ready; publication operations are intentionally incomplete.**

The repository already has license, contribution, security and conduct files. New link/evidence
gates, release scope, metadata pack, social asset and publication checklist make drift visible.
Actions remain pinned and permissions are least-privileged.

**Residual risk:** repository description/topics/social preview are not applied, no research-preview
release is tagged, branch protections need manual confirmation, and the pre-existing open pull
request should be resolved or explained. Keep the repository private until the checklist records a
commit-specific GO.

## Prioritized follow-up

| Priority | Action | Why it matters |
|---|---|---|
| P0 | Make the candidate CI run green or document runner-infrastructure failures precisely | The README badge is the public execution signal |
| P0 | Run independent history/secret and claim audits | Avoid publishing credentials or inflated security language |
| P1 | Record a clean-room demo transcript on Rust 1.88+ | Proves the entry path works for someone other than the author |
| P1 | Apply metadata/topics/social preview and branch protection | Makes the public repository discoverable and maintainable |
| P1 | Build daemon ownership and authenticated approval/storage | Closes the clearest current same-user bypass |
| P1 | Produce signed, entitled device evidence | Enables any promotion beyond native-ready |
| P2 | Add comparative baselines and independent reproduction | Strengthens the research contribution |

## Final recommendation

Use the pull request for review and interview discussion now. Merge after required CI is green.
Publish only after the separate publication and release-readiness checklists are complete. Do not
change the current enforcement wording until device evidence satisfies the canonical promotion gate.
