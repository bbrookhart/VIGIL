# Unblocking the entitled half

Roughly a fifth of VIGIL is unbuilt, and almost none of that is engineering work. It is four
external dependencies with different gatekeepers, in a dependency order that is worth respecting
because the slowest one does not block the most valuable one.

```
Full Xcode ─────────────────────────────────► Phase 5, XCTest, bundle targets
  installed: Xcode 26.6
  app/SYSX graph + activation lifecycle built

Developer Program ($99/yr) ─┬───────────────► signing, notarization  (Phase 9)
  same day as an individual; └── prerequisite ─► both entitlement requests
  +5 business days for D-U-N-S                          │
                                                        ▼
                              ES entitlement ──────────► Phase 3 ships
                              NE entitlement ──────────► Phase 4 ships
                                discretionary; reports of 4-12 months
                                with no response. May never arrive.

Disposable VM ──────────────────────────────► Phase 3 *validated* today
  free, needs neither of the above
```

## 0. Xcode prerequisite — completed on this machine

Xcode 26.6 is installed and selected. The commands below remain the reproducible setup path for a
new development machine; they are no longer a blocker on this one.

Install from the App Store, or:

```console
brew install xcodes
xcodes install --latest
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -version
```

Either route requires interactive Apple ID sign-in.

## 1. What full Xcode unblocks, with no approvals

- **Done** — `.app` and Network `.systemextension` bundle targets plus the containing-app
  activation lifecycle build under `xcodebuild`. Successfully *activating* one needs a Developer ID signing identity, and
  `security find-identity -v -p codesigning` reports none. An Apple ID alone does not grant one —
  that is step 2.
- ~~**XCTest targets.**~~ **Done** — the native packages run real XCTest and Swift Testing suites; the
  current declaration count is generated in [`docs/generated/evidence.md`](../generated/evidence.md) instead
  of a check executable; see ADR 0039. The port was validated by mutation testing, which found a
  guard the old check had never exercised.
- The SwiftUI Control Center (Phase 5).
- `xcodebuild` in the macOS CI jobs.

## 2. Developer Program

Start this first even though Xcode is the quicker win, because it has the longest lead time.

Unblocks Developer ID signing, notarization, and provisioning profiles, and is a hard
prerequisite for both entitlement requests. Note that an Apple ID alone is *not* enough:
`security find-identity -v -p codesigning` reports no identities until you are enrolled.

`APPLE_APPLICATION_PACK.md` §2 covers the Individual-versus-Organization decision, and §3 has
drafted justifications ready to paste into the request form. Two things worth knowing before
you plan around this: entitlement approval is discretionary with no SLA and public reports of
4-12 month waits, and **development and distribution are granted separately** — ask for
development first, which is what Phase 3 actually needs.

## 3. The entitlement requests

`com.apple.developer.endpoint-security.client` and the Network Extension entitlement are request
forms reached from developer.apple.com's support/contact section. Navigate rather than bookmarking
a URL; Apple moves them.

Approval is discretionary and not guaranteed. Submit *after* step 4, so the justification can cite
demonstrated behaviour rather than intent.

## 4. Validate Phase 3 today, with no Apple involvement

This is the step worth doing first, because it converts Phase 3 from "compiles" to "demonstrated"
and needs neither Xcode nor an entitlement.

> **Check `APPLE_APPLICATION_PACK.md` §4 before starting this.** On the current machine the VM
> does not fit — 28.4 GB free against ~60 GB needed, and 8 GB RAM against a guest wanting 4-8 —
> and there is an unverified caveat about whether SIP-disable takes effect in an Apple Silicon
> guest at all. That section lists the cheapest way to find out before committing time.

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

1. **Today** — decide Individual vs Organization and enrol (`APPLE_APPLICATION_PACK.md` §2). If
   Organization, request the D-U-N-S number first: longest lead time, costs nothing.
2. **Completed** — Xcode 26.6 is installed. Bundle targets are now engineering work; activation
   still waits on signing and entitlements.
3. **This week** — disposable VM, run the table in §4, record each result against its ADR.
4. **On membership** — submit both entitlement requests, citing the §4 results.
5. **On approval** — signing, notarization, entitled-device re-run on a SIP-intact machine, and the
   first honest `FULLY ENFORCED` from `vigil doctor`.

Steps 1–3 are independent and can run in parallel. Only step 5 is genuinely gated on Apple.
