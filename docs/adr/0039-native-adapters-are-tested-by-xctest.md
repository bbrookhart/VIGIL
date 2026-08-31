# 0039 — Native adapters are tested by XCTest, not by a check executable

Status: accepted
Date: 2026-08-30

## Context

Both Swift packages shipped their assertions as an executable target — `VigilEndpointAdapterCheck`
(1249 lines) and `VigilNetworkAdapterCheck` (157 lines) — built around a `require(_:_:)` helper
that wrote to stderr and called `exit(1)`.

This was never a design choice. XCTest ships with Xcode, not with the Command Line Tools, and the
development machine had only the latter. ADR 0010 and both package READMEs recorded the substitute
and said Xcode-based CI must add XCTest coverage. `docs/development/UNBLOCKING.md` §1 listed it as
the first thing full Xcode unblocks.

Xcode 26.6 is now installed, so the constraint is gone.

The substitute had costs that grew with the file:

- **One failure per run.** `exit(1)` on the first mismatch hid every later one, so a change that
  broke several behaviours was diagnosed and fixed one round-trip at a time.
- **No test names.** A failure was a stderr string; nothing named the behaviour that regressed, and
  nothing reported what passed.
- **Sequential state coupling.** The endpoint check was a single `do { }` block in which `control`
  and `state` mutated progressively — install 42, bind a root, move attribution through an exec,
  then install 43 to wipe the sessions. Assertions late in the file depended on mutations made
  hundreds of lines earlier. The cold-health assertions read counter values left behind by a
  metrics block written 300 lines above them.

The last point is the one that mattered: it made the checks hard to extend without disturbing an
unrelated assertion, and it hid coverage gaps, because a reader could not tell which state any
given assertion actually ran against.

## Decision

Replace both check executables with XCTest targets. The executable products and their
`Sources/*Check` directories are deleted; the Rust-generated fixtures move with them into
`Tests/*/Resources`, and the Makefile, CI workflow, `vigil-endpoint`'s parity test, and both
package READMEs are updated to the new paths and to `swift test`.

Assertions are regrouped by subject rather than transcribed in order, and **each test builds its
own fixtures** through helpers on `EndpointPolicyFixture` (`installedControl()`,
`withTemporaryDirectory(_:)`) and `NetworkPolicyFixture` (`installedState()`). Where a sequence is
the behaviour under test — exec moving attribution to the new audit token, fork inheriting it, exit
releasing it — it stays one test, because there the ordering is the claim.

Metrics values asserted through the control channel are now produced by a named helper
(`AuthorizationMetricsTests.populated()`) rather than inherited from whatever ran first.

The two packages are not merged, and the checks are not kept alongside the tests. Keeping both
would mean two copies of the same assertions drifting apart — the failure mode already recorded
twice in this project (ADR 0019, ADR 0031): a hand-maintained parallel list hides defects, and the
check has to derive from the thing it checks.

## Consequences

76 named tests replace two pass/fail binaries: 69 endpoint across eight suites, 7 network across
three. A failure names one behaviour, reports the rest of the suite, and no longer depends on the
order the file happens to be written in.

**The port was validated by mutation, not by the suite passing.** Three deliberate regressions were
introduced into `NativeFastPathPolicy` and the suite re-run. Two were caught. One was not:

> Deleting the expiry guard in `bindRoot` — the check that refuses to attribute a process to a
> session under lapsed policy — left all 65 tests green.

`NativeEndpointControlService` refuses a bind under expired policy before the fast path is reached,
so the existing test (`test_bind_under_expired_policy_fails_closed`, asserting `not_ready`) never
exercised the fast path's own guard. That guard is defense in depth for `bindRootFromControl`, and
nothing proved it was still wired up. **The check executable had the same hole**; the port
inherited it faithfully. Four tests were added against `bindRootForTesting` directly — expiry,
negative clock reading, unknown session, malformed audit token — bringing the suite to 69, after
which the mutation is caught.

This is the argument for the change restated as evidence: the gap was invisible while the
assertions were a script, and became visible as soon as they were addressable units that could be
run against a deliberately broken build.

Testing now requires Xcode. A Command Line Tools machine can still `swift build` both packages,
which is what proves the adapters compile and link against the real SDK, but it cannot run the
suites. Given that Xcode is a prerequisite for every remaining native phase, this is not a new
constraint.

This changes no runtime behaviour and no security posture. VIGIL still holds no Endpoint Security
or Network Extension entitlement and no signing identity; `vigil status` still reports
`OBSERVE ONLY`, and `gate_entitlement_dependent_functionality_is_never_reported_as_active`
still passes unchanged.
