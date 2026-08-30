# Unblocking the entitled half

Roughly a fifth of VIGIL is unbuilt, and almost none of that is engineering work. It is four
external dependencies with different gatekeepers, in a dependency order that is worth respecting
because the slowest one does not block the most valuable one.

```
Full Xcode ─────────────────────────────────► Phase 5, XCTest, bundle targets
  free, immediate

Developer Program ($99/yr) ─┬───────────────► signing, notarization  (Phase 9)
  days; longer for an org   └── prerequisite ─► both entitlement requests
                                                        │
                                                        ▼
                              ES entitlement ──────────► Phase 3 ships
                              NE entitlement ──────────► Phase 4 ships
                                discretionary Apple review

Disposable VM ──────────────────────────────► Phase 3 *validated* today
  free, needs neither of the above
```

## 0. Prerequisites on this machine

Xcode is a ~10 GB download that expands to 25–40 GB. Budget **50 GB free**; a machine at 92% full
will fail partway through and leave a broken install. Check with `diskutil info /System/Volumes/Data`.

Install from the App Store, or:

```console
brew install xcodes
xcodes install --latest
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -version
```

Either route requires interactive Apple ID sign-in.

## 1. What full Xcode unblocks, with no approvals

- `.app` and `.systemextension` bundle targets. Still outstanding: producing them needs
  `xcodebuild` (now available), but *activating* one needs a Developer ID signing identity, and
  `security find-identity -v -p codesigning` reports none. An Apple ID alone does not grant one —
  that is step 2.
- ~~**XCTest targets.**~~ **Done** — both packages now run real XCTest suites (76 tests) instead
  of a check executable; see ADR 0039. The port was validated by mutation testing, which found a
  guard the old check had never exercised.
- The SwiftUI Control Center (Phase 5).
- `xcodebuild` in the macOS CI jobs.

## 2. Developer Program

Start this first even though Xcode is the quicker win, because it has the longest lead time.

Expect to need an **Organization** account rather than Individual for Endpoint Security, which
means a D-U-N-S number and a legal entity. Unblocks Developer ID signing, notarization, and
provisioning profiles, and is a hard prerequisite for both entitlement requests.

## 3. The entitlement requests

`com.apple.developer.endpoint-security.client` and the Network Extension entitlement are request
forms reached from developer.apple.com's support/contact section. Navigate rather than bookmarking
a URL; Apple moves them.

Approval is discretionary and not guaranteed. Submit *after* step 4, so the justification can cite
demonstrated behaviour rather than intent.

## 4. Validate Phase 3 today, with no Apple involvement

This is the step worth doing first, because it converts Phase 3 from "compiles" to "demonstrated"
and needs neither Xcode nor an entitlement.

Stand up a **disposable macOS VM** — Virtualization.framework, UTM, or Tart on Apple Silicon —
and on that VM only:

```console
# in recoveryOS
csrutil disable
# back in macOS
systemextensionsctl developer on
```

That runs an unsigned, unentitled System Extension for development.

> **This is not a softening of VIGIL's stance.** `APPLE_ENTITLEMENTS.md` says VIGIL never asks
> *users* to disable SIP, Gatekeeper, or TCC. A developer's throwaway VM is not a user's machine,
> and developer mode is Apple's own documented path for extension development. The distinction is
> between what the product requires of the people who run it and what its authors do on a machine
> they are about to delete. Nothing in the shipped product may ever depend on this.

### The exit criteria this closes

Each of these is currently backed only by a simulator. The ADR that names each requirement is
listed so the result can be recorded against it.

| Must demonstrate | Recorded against |
|---|---|
| A prohibited exec is denied **before** it runs | ADR 0010 |
| A prohibited file operation is denied before completion | ADR 0010 |
| Authorization latency under real kernel deadlines; deadline misses counted | ADR 0023 |
| Behaviour when events are dropped, and the sequence-gap count that follows | ADR 0023 |
| Decision caching stays disabled — a second identical exec is re-evaluated | ADR 0010 |
| Generation high-water mark survives an extension restart | ADR 0022 |
| A replayed older signed snapshot is refused after restart | ADR 0022 |
| Expired policy denies attributed processes and leaves untracked ones alone | ADR 0012 |
| An XPC request timeout reports outcome-unknown and invalidates the channel | ADR 0021 |
| Flow authority: allowlisted host reachable, pinned-IP mismatch refused | ADR 0035 |

Two of these have never been observable any other way: **wall-clock rollback resistance on the
native side** (ADR 0012 records it as still open, and ADR 0030 only closed the local half) and
**durable high-water persistence across restarts** (ADR 0022).

## 5. What must not move

Two controls exist specifically to stop the VM work from leaking optimism into the product.

`gate_entitlement_dependent_functionality_is_never_reported_as_active` asserts `vigil status`
reports `OBSERVE ONLY` and `os_enforcement: false`. A dev-mode extension on a SIP-disabled VM is
**not** `FULLY ENFORCED`. That gate must keep passing unchanged until a signed, entitled extension
is installed on a machine with SIP intact.

`gate_endpoint_deadlines_are_not_applicable_yet` is written to **fail** the moment an Endpoint
Security client exists. That failure is the trigger to replace it with a real deadline check —
not a test to relax.

## 6. Order

1. **Today** — start the Developer Program organization application. Longest lead time, blocks the most.
2. **Today** — free ~50 GB and install Xcode. Then bundle targets, XCTest, Phase 5.
3. **This week** — disposable VM, run the table in §4, record each result against its ADR.
4. **On membership** — submit both entitlement requests, citing the §4 results.
5. **On approval** — signing, notarization, entitled-device re-run on a SIP-intact machine, and the
   first honest `FULLY ENFORCED` from `vigil doctor`.

Steps 1–3 are independent and can run in parallel. Only step 5 is genuinely gated on Apple.
