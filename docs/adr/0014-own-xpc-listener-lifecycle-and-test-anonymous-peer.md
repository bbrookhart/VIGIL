# ADR 0014 — Own XPC listener lifecycle and test an anonymous peer

**Status:** Accepted  
**Date:** 2026-08-30
**Amended by:** ADR 0015 adds authenticated-only idle-timeout refresh and eviction.

## Context

The control message handler authenticated individual XPC dictionaries, but no component owned
listener activation, accepted-peer lifecycle, or teardown. A production Mach service cannot be
registered truthfully without the signed System Extension target. Testing only manufactured XPC
dictionaries proved rejection but could not prove that Security.framework accepts a real sender.

## Decision

Add `NativeXPCControlListener` with two construction modes. Production mode validates a configured
Mach-service name and calls public `xpc_connection_create_mach_service`. The explicitly named test
mode creates a public anonymous listener and exposes its endpoint only for integration checks.

Own a serial dispatch queue, explicit start/stop state, accepted-peer activation and cancellation,
malformed-message teardown, and a hard 64-peer limit. Every dictionary passes through the existing
message verifier and strict control service. Do not add a PID fallback or a test-only authentication
bypass to the listener.

In the native check, derive the running binary's designated requirement with public Security APIs,
connect through the anonymous endpoint, send a real reply-bearing XPC request, and require the
normal production handler to authenticate and answer it.

## Consequences

The repository now proves both rejection of a dictionary without a sender and successful
audit-token-derived authentication of a real XPC message. Listener lifecycle is independently
testable without launchd or Endpoint Security entitlements.

This does not prove production deployment. The signed `vigild`, System Extension target,
Mach-service registration, production code requirement, signing,
notarization, and entitled-device tests remain required.
