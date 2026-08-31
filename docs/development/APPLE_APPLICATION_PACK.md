# Apple application pack

Everything needed to apply, plus drafted justifications to paste into the forms. Companion to
`UNBLOCKING.md`, which describes the dependency order.

Facts here were checked against Apple's documentation and developer forums in August 2026;
Apple moves these pages and changes these processes, so treat URLs as starting points.

---

## 1. Two corrections to the earlier plan

**Entitlement approval is slower and less certain than "days".** Developers report requests
sitting for four months, and one for twelve, with no response. Approval is discretionary and
there is no SLA. Plan on the assumption that the entitlement may never arrive, rather than
treating it as a scheduled milestone.

The mitigation is the one already in the architecture: everything entitlement-independent is
built and tested, and `vigil status` reports `OBSERVE ONLY` honestly. Nothing is waiting on
Apple to be *useful*; what waits on Apple is enforcement.

**Development and distribution are approved separately.** You can be granted the entitlement
for development and refused it for distribution. That is the good news for this project's
next step: what Phase 3 needs is a *development* grant, which is the more achievable of the
two. Ask for development first and do not bundle the two requests.

---

## 2. Individual or Organization?

| | Individual — $99/yr | Organization — $99/yr + D-U-N-S |
|---|---|---|
| Lead time | Same day | D-U-N-S alone takes up to 5 business days, then Apple verification |
| Needs | Apple ID, payment | Legal entity, D-U-N-S registered to it, authority to bind it |
| Seller name | Your legal name | The organization's name |
| Endpoint Security | Not documented as excluded, but the granted cases in public forums are overwhelmingly organizations | The path Apple's reviewers expect |

Apple does not publish a rule that individuals cannot receive the Endpoint Security
entitlement. What is visible publicly is that grants go to organizations shipping security
products, and that reviewers weigh *who is asking* alongside *what for*.

**Recommendation.** If VIGIL is intended to ship, enrol as an Organization — the D-U-N-S wait
is the cheapest part of this timeline and re-enrolling later means a new Team ID and re-signing
everything. If this is currently personal research, enrol as an Individual today so Xcode
signing and notarization unblock immediately, and treat the ES entitlement as a separate bet.

D-U-N-S lookup and request: <https://developer.apple.com/support/D-U-N-S/>
Enrolment: <https://developer.apple.com/programs/enroll/>

---

## 3. The entitlement request

One form covers System Extension entitlements:
<https://developer.apple.com/contact/request/system-extension/>

Submit it **after** you can point at demonstrated behaviour. A request that describes intent
reads like every other; one that describes a system that already works and needs only the
kernel's cooperation reads differently.

### Drafted justification — Endpoint Security

> VIGIL is a runtime security control plane for autonomous AI coding agents on macOS. An agent
> given shell access runs with the full ambient authority of the user who launched it: it can
> read SSH keys, exfiltrate credentials, or modify files far outside the task it was given.
> VIGIL confines an agent to a declared workspace and an explicit capability budget, and
> produces a tamper-evident record of every decision.
>
> The product is built and working today as a semantic control plane: it brokers filesystem,
> process, network and git operations, enforces per-session capability leases with human
> approval, and maintains a hash-chained audit log with signed checkpoints. What it cannot do
> without `com.apple.developer.endpoint-security.client` is enforce any of it. Every control is
> advisory: an agent that calls `open(2)` directly, rather than through VIGIL's broker, is
> unaffected. Our own status output reports `OBSERVE ONLY` for exactly this reason.
>
> We request the entitlement to subscribe to `ES_EVENT_TYPE_AUTH_EXEC`, `AUTH_OPEN`,
> `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`, and the `NOTIFY_FORK` / `NOTIFY_EXIT` pair. The
> AUTH events let a prohibited operation be denied before it completes rather than reported
> after; the NOTIFY events maintain process attribution across `fork`/`exec` so that authority
> follows a lineage rather than a PID, which the kernel reuses.
>
> Scope is deliberately narrow. VIGIL makes decisions only for processes explicitly attributed
> to a managed agent session, identified by full audit token. Every event from an unattributed
> process is allowed unmodified — a bug in our client must not be able to deny the user's own
> work. Authorization decisions are made from a precompiled in-memory policy with no I/O,
> logging, or allocation on the callback path, under a deadline guard that denies while a
> safety margin remains rather than risking a missed kernel deadline.
>
> The native adapter is written and tested against the real SDK, including the deadline guard,
> audit-token attribution, expiry handling, and the signed policy transport between our daemon
> and the extension. It is currently exercised against a simulator because we cannot install an
> entitled System Extension. Distribution would be Developer ID, notarized, installed by the
> user who is being protected.

Trim to the form's limit if there is one; keep the third and fourth paragraphs, which are what
distinguish this from a request to observe the whole system.

### Drafted justification — Network Extension

> VIGIL confines autonomous AI coding agents on macOS. The same session that is restricted to a
> workspace on disk needs its network egress restricted to declared destinations, because
> exfiltration is the step that makes a credential read matter.
>
> We request the Network Extension entitlement to implement an `NEFilterDataProvider` that
> evaluates outbound flows for processes attributed to a managed agent session. A flow is
> permitted when its destination is on the session's allowlist *and* the address it resolved to
> is one previously pinned for that hostname; a hostname that resolves to a new address is
> refused rather than inheriting the name's authority. Flows from unattributed processes are
> passed through untouched.
>
> The provider performs no DNS, file, database, or IPC work in `handleNewFlow`: it consults a
> compact in-memory policy installed out of band through a signed, generation-monotonic
> envelope. The decision state, its verifier, and the flow logic are implemented and tested
> against the public SDK today.

### What the form will also ask

- **Team ID** — from your developer account after enrolment.
- **Bundle identifiers** — `Configuration/VigilIdentifiers.xcconfig` holds the reserved ones.
- **Distribution method** — Developer ID, notarized, direct download.
- **Whether you have shipped this before** — no; say so.

---

## 4. The disposable VM: not on this machine

`UNBLOCKING.md` §4 proposes a throwaway VM to validate Phase 3 without an entitlement. Checked
against this machine, that plan does not fit:

| | Needed | This machine |
|---|---|---|
| Free disk | ~60 GB (installer + guest volume + snapshots) | **28.4 GB** |
| RAM | 4–8 GB for the guest, plus the host's own | **8 GB total** |
| Virtualization tool | Tart, UTM, or Virtualization.framework host | none installed |

A macOS guest on an 8 GB host swaps continuously, which makes latency measurements — one of the
things §4 is for — meaningless.

**There is also a technical caveat I asserted earlier without checking.** On Apple Silicon,
changing boot security policy normally requires 1TR (hold-power recovery), and reports from
developers running macOS guests under Virtualization.framework describe `csrutil` reporting SIP
as disabled while the root filesystem stays read-only and unsigned code still refuses to load.
Those reports concern *kernel* extensions, and Endpoint Security clients are System Extensions
in userspace, which is a different mechanism — so the VM path may well work. But I have not
verified it end to end, and neither should you assume it.

### Options, cheapest first

1. **External SSD.** A 500 GB USB-C SSD is inexpensive and solves the disk constraint outright;
   the RAM constraint remains. Best value if you want the VM path.
2. **Prove the caveat before building the VM.** Before committing hours to a guest install,
   confirm on a scratch VM that `systemextensionsctl developer on` actually takes effect. If it
   does not, the whole §4 plan is void and you have lost an afternoon rather than a week.
3. **Borrow a machine with more headroom.** 16 GB and 100 GB free makes this comfortable.
4. **Skip the VM.** Do the §4 exit criteria on real hardware once a development entitlement
   arrives. This is the slowest path but needs no extra hardware and no reduced-security state
   anywhere.

Option 2 is the one to do first regardless of which you choose, because it is the cheapest way
to learn whether the plan is sound.

### If you do build it

```console
brew install cirruslabs/cli/tart
tart create --from-ipsw latest vigil-dev        # downloads a macOS restore image
tart set vigil-dev --memory 6144 --disk-size 80
tart run vigil-dev
```

Then inside the guest, and **only** inside it: enter recovery, `csrutil disable`, boot back,
`systemextensionsctl developer on`.

That machine is disposable and must never hold anything you cannot lose. VIGIL does not ask
users to weaken their systems; a developer's throwaway guest is not a user's machine, and
nothing shipped may depend on this.

---

## 5. Order of operations

1. **Today, 10 minutes** — decide Individual vs Organization (§2). If Organization, request the
   D-U-N-S number now; it is the longest pole and costs nothing.
2. **Today, 30 minutes** — enrol. Individual unblocks signing and notarization immediately.
3. **This week** — option 2 in §4: find out whether the VM path works at all.
4. **When you have results** — submit the System Extension request (§3), citing them.
5. **Then wait**, and keep building the entitlement-independent half, which is where every
   control that works today already lives.
