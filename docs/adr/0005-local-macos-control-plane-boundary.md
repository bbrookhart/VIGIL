# ADR 0005 — Establish the local control plane without claiming containment

**Status:** Accepted  
**Date:** 2026-08-29

## Context

The portable VIGIL core can authorize semantic tool calls and structurally custody credentials,
but a local CLI agent can bypass those adapters and use the logged-in user's ambient process,
filesystem, and network authority. macOS enforcement requires signed, entitled components that
cannot be honestly validated in ordinary portable CI.

## Decision

Build the local product in two explicit halves. The entitlement-independent half provides
durable session lifecycle, normalized local policy, events, simulation, and truthful health. The
entitled half will add `vigild`, Endpoint Security, Network Extension, and authenticated IPC.

Until the entitled half is active, `vigil run` always prints and persists `observe_only`. It does
not use the words protected, contained, or enforced. Profiles that later require unavailable
controls will fail launch rather than silently degrade.

The existing deterministic policy engine remains the Phase 1 provider behind `PolicyEngine`.
Cedar integration is planned as a separately tested provider. Cedar permits will still be
combined inside VIGIL's forbid-dominant, monotone decision algebra; Cedar will not absorb risk,
budget accounting, or approval state machines. This preserves the already-proved order-
independence and avoids changing the live authorization semantics while the local trust boundary
is being established.

## Consequences

The current launcher creates useful forensic/session evidence and a stable integration surface,
but does not reduce child-process authority. This limitation is prominent rather than hidden.
Portable CI remains meaningful without entitlements, while privileged release testing has a
clear, non-substitutable role.
