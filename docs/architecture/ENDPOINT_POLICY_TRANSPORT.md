# Endpoint policy transport contract

**Status:** signed content, durable generation floor, XPC message boundary, and listener lifecycle
implemented; registration and daemon pending

The Endpoint Security callback cannot query SQLite, call a daemon, or compile policy. A trusted
control process must prepare compact state ahead of time, while the extension must reject state
that is forged, stale, malformed, intended for another installation, or outside its validity
window.

```text
Rust control plane
  canonical compact snapshot
          │ Ed25519 + dedicated signing domain
          ▼
bounded signed envelope
          │ strict install request
          ▼
XPC message bridge
  audit-token code identity → exact schema → signature → bounds → generation
          ▼
NativeFastPathPolicyState
```

## Version 1

The outer envelope is `vigil.signed-envelope/v1`, uses the exact algorithm label `Ed25519`, names a
pre-provisioned key ID, and carries unpadded base64url payload and signature fields. The signature
covers:

```text
"VIGIL_ENDPOINT_POLICY_V1\0" || canonical_payload_bytes
```

The domain separator prevents a valid Endpoint snapshot signature from being reused as a
capability, approval, or audit signature. The verifier accepts neither padded nor non-URL-safe
base64 and bounds the envelope to 2 MiB and decoded payload to 1 MiB before allocation-heavy work.

The authenticated payload uses schema `vigil.endpoint-policy/v1` and contains:

- target extension instance ID;
- positive monotonic generation;
- issue and exclusive-expiry times, with at most a 24-hour validity window;
- bounded session IDs, workspace roots, and exact executable allowlists;
- bounded protected path prefixes.

Rust emits VIGIL Canonical JSON. Swift verifies the raw signature before parsing that JSON, rejects
unknown envelope, payload, and session fields, checks the configured instance and clock window,
then constructs normal `NativeSessionEnforcementPolicy` values. The ordinary fast-path installer
revalidates all bounds and refuses a generation less than or equal to the installed generation. The
production control-service constructor also recovers a durable generation high-water mark, so
restart cannot reset this comparison.

## XPC control protocol

The native adapter defines `vigil.endpoint-control/v1` with three operations:

- `install_policy`, carrying one signed envelope;
- `bind_root`, carrying a full audit token, exact session ID, and installed generation;
- `health`, returning readiness, the installed generation, and bounded native authorization
  metrics.

Requests are bounded to 2 MiB, use exact key sets, require a bounded request ID, and reject unknown
operations and fields. Replies contain fixed status/error codes and no parser or Security.framework
details. Concurrent installation of one generation produces exactly one success; all policy-
generation replays are rejected, and an acknowledgement is created only after the complete state
swap.

`bind_root` encodes the 32-byte audit token as strict unpadded base64url and the generation as a
canonical decimal string, avoiding JSON number coercion. The service accepts no claimed PID. The
same token/session/generation binding is idempotent, but a generation mismatch, expired policy,
unknown session, zero/malformed token, extra field, or attempt to reassign a token rejects without
changing attribution. The production fast-path state exposes no public general-purpose bind API;
registration enters through the authenticated control service.

`NativeXPCControlMessageHandler` accepts the opaque request bytes from an XPC dictionary and puts
the opaque acknowledgement bytes into a reply derived from that same message. Before dispatch it
requires `NativeXPCPeerVerifier`, which calls public `SecCodeCreateWithXPCMessage` and therefore
uses the kernel-attached sender audit token rather than a claimed PID. `SecCodeCheckValidity` then
checks the live sender against a precompiled daemon code requirement. The control service's normal
entry point requires the verifier's unforgeable peer marker; entitlement-free checks use an
explicitly named testing entry point.

## Listener lifecycle

`NativeXPCControlListener` creates either a production Mach-service listener or an explicitly named
anonymous testing listener. It validates the configured service name, owns a serial queue, limits
active peers to 64, activates accepted peers, cancels malformed or disconnected peers, and makes
duplicate start/stop misuse explicit. A failed wall-clock read is passed into the strict service as
an invalid time, so policy installation and binding cannot fail open.

Every accepted peer receives one refreshable dispatch timer. Production idle timeouts must be from
1 to 300 seconds and default to 30 seconds; the explicit test constructor permits shorter bounded
values. Timer resources are cancelled on every removal and listener shutdown path. Only a message
whose audit-token-derived code identity satisfies the configured requirement refreshes the timer.
A wrong-identity peer receives the fixed `unauthenticated_peer` reply and is then disconnected, so
it cannot retain one of the 64 slots by sending junk.

The native check creates an anonymous endpoint, connects a real XPC client, sends `health`, and
verifies the normal peer-authenticated production handler accepts the kernel-associated sender
against the running check binary's designated code requirement. This proves a successful public
XPC/Security.framework path without fabricating a signed daemon or registered Mach service.

`NativeXPCControlClient` gives each daemon request a bounded end-to-end deadline (2 seconds by
default, configurable from 50 milliseconds through 30 seconds), caps outstanding requests at 64,
and bounds request and response payloads at 2 MiB. A timeout completes exactly once with
`deadlineExceededOutcomeUnknown` and permanently invalidates that connection: XPC cannot prove a
mutation did not execute before its reply was lost, so callers must create a fresh client and
reconcile with `health` rather than blindly replaying it. Entitlement-free checks exercise both a
successful real anonymous request and a deliberately late peer.

Authenticated health replies snapshot process-lifetime native counters for authorization and
notification volume, verdicts, deadline-guard denials, late/failed responses, malformed denials,
sequence gaps/regressions, maximum callback latency, and minimum deadline headroom. Snapshot JSON
encoding occurs on the control path, not in an ES callback. These counters are health telemetry,
not authorization state or durable audit evidence. See ADR 0023.

## Failure posture

Unknown keys, algorithms, schemas, fields, invalid encodings, invalid signatures, wrong-instance
payloads, future issue times, expiry, malformed paths, duplicate sessions, and generation replay
all reject the update. A rejected update never partially changes installed state. Policy expiry is
also an exclusive runtime lease boundary: managed authorization denies at expiry or when the wall
clock cannot be read, health becomes unready, and new root attribution is refused. Unmanaged
processes remain unaffected to avoid a host-wide outage.

`NativeFileGenerationStore` keeps rollback state in one strict, bounded record within a
pre-provisioned owner-controlled directory. A policy install holds a cross-instance advisory lock,
rereads the floor, writes and fsyncs a same-directory 0600 temporary file, atomically renames it,
fsyncs the directory, and only then activates policy and
acknowledges success. Corrupt, symlinked, insecurely permissioned, or unavailable state fails
startup; it is never interpreted as generation zero. The record is a high-water mark rather than a
policy cache, so a restart is unready until a newer signed generation arrives. See ADR 0022.

## Contract fixture

`generate_policy_fixture` uses deliberately public synthetic key material to emit the committed
Swift resource. A Rust unit test asserts byte-for-byte envelope equality, and the macOS Swift check
verifies, decodes, installs, and adversarially mutates that same fixture. The fixture key is test
material and must never be trusted by a production target.

## Remaining boundary

These components authenticate policy content and individual XPC message senders and can establish
an anonymous test channel, but not an installed production channel. Phase 3 still requires a real
System Extension and containing application, `vigild`, Mach-service registration and launch
lifecycle, production code-requirement and key provisioning/rotation, protected generation-store
directory provisioning, trusted launched-root audit-token acquisition/wiring, and entitled-device
enforcement tests. The peer API
proves both no-sender rejection and a successful same-binary anonymous peer; a successful signed-
daemon peer cannot be exercised until those signed targets exist.
