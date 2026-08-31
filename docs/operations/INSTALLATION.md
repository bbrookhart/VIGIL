# Installation

## What you can install today

A CLI. `vigil` builds and runs from source on macOS and Linux, and gives you durable sessions,
semantic brokers, approvals, capability leases, risk, detections, incidents, rollback, deception,
MCP authorization, and a tamper-evident local log.

```console
git clone <repository> && cd vigil
make build
cargo run -p vigil-cli -- doctor
```

`vigil doctor` prints the real posture. It will say `Endpoint Security: not installed` and
`Network Extension: not installed`, because they are.

State lives in `~/Library/Application Support/VIGIL/vigil.db` (override with `--state-db`),
created owner-only, with preimage blobs beside it.

## What you cannot install today, and why

**There is no installable macOS enforcement.** A reviewable unsigned app/System Extension build
exists, but there is no activatable signed System Extension, installed Network Extension,
no `vigild`, no signed installer, no notarized package. The bundle targets still need real
provisioning and review on an entitled device; activation remains blocked on things Apple issues:

| Requirement | Status |
|---|---|
| `com.apple.developer.endpoint-security.client` entitlement | **Not held.** Requires Apple approval of a business justification. |
| Network Extension entitlement | **Not held.** |
| Apple Developer Team ID and Developer ID certificate | **Not held.** No signing identity on the build machine. |
| Full Xcode | **Installed:** Xcode 26.6. The unsigned application/System Extension graph builds. |
| Notarization | Requires the above. |

`docs/development/APPLE_ENTITLEMENTS.md` has the detail. The repository contains entitlement
*request* plists; a plist naming a restricted entitlement is configuration, not a grant, and
nothing here fakes entitlement success.

The repository does contain compile-checked public Endpoint Security and Network Extension Swift
adapters. The latter includes a real `NEFilterDataProvider`, strict signed-policy verifier,
protected publisher/reader, provider startup lifecycle, and a bounded containing-app
`NEFilterManager` preference controller. `make build-macos-app` produces an unsigned `.app` with
the `.systemextension` embedded at the standard bundle location. It cannot be activated.

The unsigned product is deliberately a compile/review artifact, not an installer. VIGIL will not
present it as protection until signing, activation, OS approval, and entitled-device tests agree.

## When the entitled half exists

The installation flow will be: a containing application requests activation of the System
Extension, the user approves it in System Settings, Full Disk Access is granted, `vigild`
registers its Mach service through launchd, and `vigil doctor` reports `FULLY ENFORCED` instead of
`OBSERVE ONLY`.

Until every one of those steps is real and tested on an entitled device, this document will keep
saying they are not.

## Uninstalling

Remove the state directory. There is nothing else installed — no daemon, no extension, no launch
item, no system modification. VIGIL has never asked you to weaken SIP, Gatekeeper, or TCC, and
never will.
