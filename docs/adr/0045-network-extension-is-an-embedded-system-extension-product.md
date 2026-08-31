# ADR 0045: The network provider is an embedded System Extension product

**Status:** Accepted
**Date:** 2026-08-30

## Context

The native network adapter already compiled as a Swift package, but a package does not exercise
the Xcode product graph macOS installs. A Network System Extension is a `SYSX` bundle with a
`NetworkExtension` provider-class dictionary, embedded by its containing application under
`Contents/Library/SystemExtensions`. An app-extension-style `NSExtension` dictionary models a
different product and would make review evidence misleading.

## Decision

`platform/macos/VigilMac.xcodeproj` owns two reviewable products:

- `VigilHost`, a minimal SwiftUI containing application; and
- `VigilNetworkSystemExtension`, a `com.apple.product-type.system-extension` executable that
  starts Network Extension System Extension mode and links `VigilNetworkAdapter`.

The host depends on and embeds the System Extension with Xcode's System Extensions copy phase.
Bundle identifiers remain centralized in `VigilIdentifiers.xcconfig`. `make build-macos-app`
performs an unsigned build and asserts the two executables and property lists are present. Code
signing is disabled only for this structural gate; it is not an activation path.

## Consequences

Review now covers the real bundle types, provider entry point, package linkage, dependency order,
and embedded location. The result makes no enforcement claim: restricted entitlements,
provisioned App Group access, Developer ID signing, notarization, activation lifecycle, and
entitled-device behavior remain required before installation.

The small readiness UI states that boundary directly. Future UI and activation work extend these
targets rather than creating a parallel packaging path.
