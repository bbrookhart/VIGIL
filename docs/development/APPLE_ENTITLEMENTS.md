# Apple entitlements and external dependencies

The repository contains reviewed entitlement-request plist files for the Endpoint and Network
adapters,
but does not possess or claim production Apple security entitlements. A plist naming a restricted
entitlement is configuration, not an entitlement grant.

The Endpoint adapter was compiled against the installed public macOS SDK 26.5 with Swift 6.3.3.
The SDK headers verify macOS 10.15 availability for the selected ES client/events and the
`com.apple.developer.endpoint-security.client` key. The Swift package declares macOS 13 as its
current deployment floor. Placeholder bundle identifiers are centralized in
`extensions/endpoint-security/Configuration/VigilIdentifiers.xcconfig`; no personal team
identifier belongs in source.

The Network adapter compiles a public `NEFilterDataProvider` subclass against the same SDK and
declares macOS 15 because its numeric endpoint projection uses `remoteFlowEndpoint`. Its templates
request `content-filter-provider-systemextension`, a shared application group, and System
Extension installation in the containing host. The centralized placeholders include the network
bundle and application-group identifiers. These strings are not capabilities and must be replaced
only through the signed Xcode configuration/provisioning path.

The SDK marks `NEFilterControlProvider` and its rule-request APIs unavailable on macOS. Network
policy therefore arrives through the implemented protected out-of-band shared-container
publisher, as recorded in ADRs 0036 and 0043; the data-provider callback never waits for daemon
IPC. The containing-app configuration factory and provider startup parser share one strict
`vigil.network-provider/v1` contract carrying the provisioned App Group, installation instance,
and trusted public keys. The provider's group access is read-only and startup refuses a missing,
unstable, or mismatched envelope/replay-record pair.

The SDK also exposes public `SecCodeCreateWithXPCMessage`, which derives a dynamic code object from
the audit token attached to an XPC message, and `SecCodeCheckValidity`, which evaluates the daemon's
configured signing requirement. The adapter compiles this peer-verification path and rejects a
locally manufactured dictionary with no sender identity. Its entitlement-free native check also
sends a real anonymous XPC request and successfully validates the running check binary's designated
requirement. A successful production peer still requires the future signed daemon and registered
Mach service; CI does not fabricate either.

Endpoint Security and Network Extension capability approval/provisioning are external Apple
dependencies. CI uses simulated sources and entitlement-free native compile/parity checks; it
must never fake entitlement success or extension activation.

This machine now has Xcode 26.6 and can build and test the native Swift packages. The repository's
reviewable Xcode project also builds an unsigned SwiftUI containing app with the Network System
Extension embedded at `Contents/Library/SystemExtensions`. It has no valid code-signing identity,
approved security entitlement, or provisioning profile. Activation, signing, and entitled
behavior therefore cannot be tested here yet.

`APPLE_APPLICATION_PACK.md` holds the enrolment decision and drafted request
justifications; `UNBLOCKING.md` records the dependency order for obtaining these, and the disposable-VM
development path that validates the Endpoint Security exit criteria without an entitlement. That
path is for a throwaway developer machine only; nothing in the shipped product may depend on it,
and the release gates that assert the truthful posture must keep passing unchanged while it is
used.

Release work must include Hardened Runtime, least-privilege entitlements, library validation
where compatible, code signing, notarization, extension activation/upgrade health, and a
privileged-device test plan. VIGIL never asks users to disable SIP, Gatekeeper, TCC, or use
private/deprecated security APIs.
