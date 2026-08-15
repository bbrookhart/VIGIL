# ADR 0001 — Non-bypassability through credential custody

**Status:** Accepted
**Date:** 2026-08-14

## Context

The product promise is that no high-impact agent action reaches the world without a VIGIL
decision. The obvious implementation — an SDK that wraps tool calls — cannot deliver it. An
agent that holds the mail provider's API key can call the mail provider directly, and the SDK
becomes a logging library that an attacker (or a careless refactor) routes around.

This is not a theoretical concern. Prompt injection means the agent's behaviour is partly
attacker-controlled, so "the agent will call the wrapper" is an assumption about a component
we have already assumed is compromised.

## Decision

The agent holds **no credentials** for protected tools. The VIGIL Gateway holds them.

The agent's only currency is a capability: a signed assertion that a specific action, for a
specific agent, in a specific session, was authorized seconds ago. It is worthless for
anything else and worthless twice.

Consequences for the type system, which is where this is actually enforced:

- `CapabilityIssuer` owns `SigningKeyMaterial`; `CapabilityVerifier` owns only `VerifyingKey`.
  There is no constructor giving a verifier a private key, so a compromised Gateway cannot
  mint capabilities for itself.
- The Gateway **recomputes** the action hash from the body it received. It never reads the
  hash from the token and never accepts one from the client.

## Consequences

**Good.** Bypassing VIGIL requires stealing credentials from the Gateway, not merely
convincing the agent to skip a function call. Compromise of Core alone yields authorization
without execution; compromise of Gateway alone yields execution without authorization.

**Cost.** Every protected tool needs a Gateway backend. This is real integration work and is
the main adoption cost of Protected Mode.

**Limit, stated plainly.** Credential custody is necessary but not sufficient. An agent with
raw network access could still reach a tool that authenticates some other way, or an internal
service that trusts the network. Closing that requires deployment-level isolation — network
policy, service mesh, workload identity — which is **not yet built**. Until it is, VIGIL
enforces correctly for traffic that reaches it and does not constrain traffic that does not.
That gap is recorded in the threat model rather than papered over.

## Alternatives rejected

**SDK-only enforcement.** Cannot survive an agent that ignores it. Retained as
Observability Mode, explicitly labelled as non-enforcing so nobody mistakes it for protection.

**Proxy-only interception (no capabilities).** A proxy that re-derives authorization from the
request alone cannot bind a decision to the analysis that produced it — it has no session
provenance, no taint history, no approval linkage. Capabilities carry that binding.
