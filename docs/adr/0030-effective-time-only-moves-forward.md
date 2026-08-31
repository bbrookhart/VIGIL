# ADR 0030 — Effective time only moves forward

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Capability leases and approval requests expire by comparing a stored `expires_at` to
`Utc::now()`. That is sound only while the clock moves forward.

A backwards jump — an NTP correction, a manual change, a VM restored from a snapshot, or an agent
that can set the system clock — makes an already-expired lease valid again. Authority that can be
resurrected by changing a setting was never really bounded, and §71 says explicitly not to rely on
wall-clock time alone for security intervals. ADR 0012 already recorded this gap on the native
side; the local side had it too and nothing said so.

## Decision

VIGIL stores a monotone high-water mark over every wall-clock reading it has ever taken. The
**effective** time is `max(wall clock, high water)`, and every expiry comparison uses it. Effective
time therefore never decreases, whatever the system clock does, and an expired lease stays expired.

### The mark is advanced at one-second granularity

Writing the mark on every authorization would put a database write on the hot path — measured at
18 µs for a permitted request, which is not where a write belongs. The mark is rewritten only when
the clock has advanced at least a second, which bounds writes to roughly one per second while
keeping the guarantee: a resurrection window shorter than a second is not useful to anyone.

The update is guarded (`WHERE high_water < ?`) so a concurrent process that got further ahead is
never walked back.

### Small regressions are absorbed silently; material ones are reported

A few seconds backwards is ordinary NTP behaviour. Reporting it would produce a detection on a
healthy laptop several times a day, and that is how a detection becomes noise. The tolerance is
five seconds; beyond it, `VIGIL-L032` fires at `MEDIUM`/`MEDIUM`.

Medium confidence is deliberate. A backwards clock is often innocent — a resumed laptop, a restored
snapshot — and the operator should get to decide which reading applies. The evidence records
`authority_resurrected: false`, because expiry used the monotone time regardless of why the clock
moved.

### Reading and reporting are separate calls

`observe_now` takes a reading with no possibility of a detection write; `observe_now_reporting`
adds the signal. The hot path uses the reporting form once per authorization, and code that merely
needs a timestamp is not forced to carry the risk of a write.

## Consequences

The adversarial harness grants a one-second lease, waits for it to expire, moves the mark forward
by an hour — which is what the store observes when the system clock is turned back — and asserts
the call is still refused *and* that the lease still has uses remaining, so the refusal is
demonstrably about time rather than exhaustion.

### What this is not

**It is not a trusted time source.** Anything that can write the database can rewrite the
high-water mark. A clock pushed far *forward* and left there expires things early, which fails safe
but is still interference. A complete answer needs monotonic boot time and protected continuity
state, which is native work on the entitled side.

This closes the direction that *grants* authority. It does not make time trustworthy.
