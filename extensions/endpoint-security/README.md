# Endpoint Security native adapter

**Status: adapter compiles; System Extension packaging and activation are blocked.**

The Swift package imports the public `EndpointSecurity` module and implements the native source
for `AUTH_EXEC`, `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`, `NOTIFY_FORK`, and
`NOTIFY_EXIT`. It uses the required flags response for `AUTH_OPEN`, the auth response for other
authorization events, disables ES decision caching, projects no raw pointers beyond the callback,
guards each authorization against its own Mach deadline, and maps documented client-creation
failures without claiming entitlement success.

The callback also records fixed-size native health metrics without I/O or logging. It checks the
deadline again after policy evaluation, counts `es_respond_*` failures and late responses, detects
global/per-event sequence anomalies, and exposes latency/headroom through authenticated control
health. The source must share the control service's accumulator so production wiring cannot
silently report a disconnected metric set.

`NativeFastPathPolicyState` provides the callback with bounded, in-memory policy and process
attribution. It validates monotonically versioned snapshots before installation, keys process
identity by the complete audit token, enforces component-aware workspace/protected-path checks,
and handles exec, fork, and exit transitions.

`NativeSignedPolicyVerifier` accepts only pre-provisioned Ed25519 public keys. It verifies an
instance-bound, expiring, domain-separated Rust envelope before decoding the strict payload, then
runs the same validator used by fast-path installation. The committed resource fixture is emitted
by `vigil-endpoint` and checked by both languages. This proves policy-content authentication and
schema parity; it does not provide a running daemon IPC channel or provision production keys.

`NativeXPCPeerVerifier` authenticates an XPC dictionary sender using
`SecCodeCreateWithXPCMessage` and a configured Security.framework code requirement; no
caller-provided PID participates. `NativeXPCControlMessageHandler` bounds the opaque request and
connects the verified peer to an exact `install_policy`/`bind_root`/`health` protocol. Root
registration requires a complete audit token and installed generation, is idempotent for an exact
replay, and rejects PID fields or conflicting reassignment. The control service
atomically installs verified state and acknowledges only after success. These are
connected by `NativeXPCControlListener`, which owns a serial queue, start/stop, a 64-peer bound,
peer activation/cancellation, malformed-peer teardown, and refreshable per-peer idle timers.
Production timeouts default to 30 seconds and are bounded to 1–300 seconds. Only authenticated
messages refresh them; wrong-identity peers are rejected and immediately disconnected. Production
mode uses the public Mach-service listener API; the native check uses an anonymous endpoint to
exercise a real successful audit-token/code-requirement exchange. This package still has no
registered Mach service, signed daemon target, or production code requirement. A bounded native
client now owns request deadlines and treats timeout as an outcome-unknown channel failure.

`NativeFileGenerationStore` prevents a previously accepted signed snapshot from being replayed
after restart. Production construction recovers a strict high-water-mark record from a protected
owner-controlled directory. Installation fsyncs and atomically renames owner-only state before the
new fast-path policy becomes active or receives an acknowledgement. Corrupt or unavailable state
fails closed; restart does not restore active policy and requires a newer signed generation.

Snapshot validity is enforced after installation as a runtime lease. Managed authorization and
new root attribution deny at the exclusive expiry boundary or on clock failure, and control health
becomes unready while preserving the installed generation for diagnosis. Unmanaged processes
continue to allow so stale control state cannot deny the entire host.

The installed development environment used for this phase has Command Line Tools, macOS SDK 26.5,
and Swift 6.3.3, but not full Xcode. Consequently this directory is a buildable Swift package and
contains reviewed entitlement/identifier configuration, but it is not an activatable System
Extension bundle or containing application target. Those must be created and verified from the
matching full-Xcode System Extension template rather than inventing bundle metadata.

Apple approval for `com.apple.developer.endpoint-security.client`, Full Disk Access, signing,
notarization, containing-app activation, and privileged-device testing remain external release
dependencies. The entitlements files document the requested keys; their presence does not grant
them.

Local verification:

```bash
CLANG_MODULE_CACHE_PATH=/tmp/vigil-clang-modules \
SWIFT_MODULE_CACHE_PATH=/tmp/vigil-swift-modules \
swift build --package-path extensions/endpoint-security

CLANG_MODULE_CACHE_PATH=/tmp/vigil-clang-modules \
SWIFT_MODULE_CACHE_PATH=/tmp/vigil-swift-modules \
swift test --package-path extensions/endpoint-security
```

`Tests/VigilEndpointAdapterTests` is an XCTest suite, grouped by subject:

| Suite | Covers |
|---|---|
| `DeadlineGuardTests` | denial while a safety margin remains; no fail-open on tick overflow |
| `AuthorizationMetricsTests` | latency timebase conversion, deadline headroom, dropped events vs. sequence regressions, concurrent recording |
| `PeerVerifierTests` | code-requirement compilation, rejection of a message with no kernel-associated sender |
| `SignedPolicyEnvelopeTests` | Rust snapshot parity, signature tampering, instance binding, expiry |
| `GenerationStoreTests` | durable high-water mark, cross-instance and non-increasing commits, corrupt state, restart replay refusal, persistence failure |
| `ControlProtocolTests` | strict request parsing, concurrent atomic install, replay and forgery refusal, generation-bound root binding, health telemetry |
| `XPCControlTests` | listener and client configuration, lifecycle, live authentication, idle-peer eviction, wrong-identity disconnect, slow-peer single-completion timeout |
| `FastPathPolicyTests` | path denials, executable decisions, audit-token transitions, unmanaged-host isolation, runtime lease expiry, clock failure, snapshot rollback |

Each test builds its own fixtures, so a failure names one behaviour rather than halting a
sequential script at the first mismatch.

XCTest ships with Xcode, not with the Command Line Tools; a CLT-only machine cannot run this
suite. `swift build` still checks that the adapter compiles and links against the real SDK.
