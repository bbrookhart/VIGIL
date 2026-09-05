# Experimental local authority daemon

`vigild` separates authority state and operator approval from an agent's OS account.
It supports **bounded file reads on Linux** through the `read` method. Other tool
execution remains disabled. Existing `vigil` local commands do not automatically
route through it. An `authorize` response is a decision, not an executable capability.

## Account and state model

| Principal | Access |
| --- | --- |
| Dedicated service UID | Owns SQLite, fixed policy binding and checkpoint seed |
| Dedicated agent UID | Status, filesystem authorization and bounded Linux file reads |
| Dedicated operator UID | Status, approval listing/grant/deny and checkpoint signing |
| Any other UID | Connection refused without request processing |

All three UIDs must be distinct and non-root. Do not run an agent under the operator
or service account. Root and the host administrator remain trusted. The service uses
the existing compiled local profiles; this milestone adds no mutable policy upload API.

State files are created as `0600` in a pre-provisioned service-owned `0700` directory.
Use a separate service-owned `0755` runtime directory. Both directories' ancestors
must be root/service-owned with no group/world write bit, and paths must be canonical
(no symlinks). For macOS, `/var` itself is a symlink; use canonical paths.
Provision without extended ACL grants to untrusted accounts; the current startup
checks inspect Unix ownership and mode bits, not platform-specific ACL entries.
Use trusted, administrator-installed binaries and service configuration.
On Linux the workspace itself must belong to the configured agent UID. The daemon
pins its directory descriptor at startup using `openat2`; unsupported kernels fail
closed. Reads also require a trusted `/proc/self/fd`, with no pathname fallback.

## Build and run

Build with `cargo build -p vigil-daemon --locked`. On a disposable Linux host,
`sudo python3 tests/e2e/daemon_accounts.py target/debug/vigild` provisions temporary
directories and uses numeric UIDs without creating persistent users. It tests real
kernel account separation and cleans up its processes and directories.

For a manually provisioned installation, assign dedicated accounts and directories,
then run this as the service account (replace example UIDs and paths):

```sh
vigild serve --state-dir /var/lib/vigild --socket /run/vigild/authority.sock \
  --agent-uid 61002 --operator-uid 61003 --workspace /srv/agent-work \
  --profile untrusted-agent
```

Call as the agent account, pinning the actual service UID:

```sh
vigild call --socket /run/vigild/authority.sock --server-uid 61001 \
  --request '{"method":"authorize","action":"fs.delete","resource":"example.txt"}'
```

Call as the operator account to list requests, then grant one exact request:

```sh
vigild call --socket /run/vigild/authority.sock --server-uid 61001 \
  --request '{"method":"approvals"}'
vigild call --socket /run/vigild/authority.sock --server-uid 61001 \
  --request '{"method":"grant","approval_id":"apr_REPLACE","max_uses":1,"ttl_seconds":60}'
```

The socket is `0666` for connectivity; kernel UID checks enforce access. Its parent
is not writable by either client. Client authentication checks the server's kernel
UID before sending any request, including at a substituted socket path.

## Protocol

One JSON request and response per connection. Each is prefixed by a four-byte
big-endian unsigned length, with a 16 KiB maximum. Reads and writes each have a
two-second deadline; malformed, truncated and oversized requests are rejected.
The service processes one connection at a time. Unknown JSON fields are rejected.

Methods: `status`, `authorize` (action, resource), `approvals`, `grant` (approval_id,
max_uses, ttl_seconds), `deny` (approval_id), `checkpoint`, `read` (resource). Authorization supports
`fs.read`, `fs.write`, `fs.create`, `fs.delete`, `fs.list`, `fs.metadata` only.
The agent cannot supply a session, profile, workspace, UID or approver label.
Approval listing returns at most 20 newest entries. Oversized responses return
`response_too_large`; no truncated decision is returned.

Success is `{"ok":true,"result":...}`; application rejection is
`{"ok":false,"error":"request_denied"}`. Transport failure is an error, never an
allow. The CLI exits nonzero on either kind of failure. Approval records attribute
decisions to `unix-uid:<kernel UID>`. Status returns only the public checkpoint key.
Pin that key independently if exporting checkpoints for later verification.

## Descriptor-bound reads

On Linux, call as the agent:

```sh
vigild call --socket /run/vigild/authority.sock --server-uid 61001 \
  --request '{"method":"read","resource":"example.txt"}'
```

`read` accepts relative workspace paths and returns at most 4096 bytes as
`content_base64`, plus device/inode identity and a durable execution event ID.
Status advertises `execution_actions: ["fs.read"]` on Linux; other platforms
advertise no execution actions and reject `read`.
New Linux state uses an active logical semantic session, as required by existing
budget enforcement. State created by the earlier authority-only release stays
authority-only and advertises no execution actions. Provision a new state directory
deliberately to enable reads; the daemon never promotes or resets old sessions.

The kernel resolves beneath the pinned workspace with no symlinks, magic links
or mount crossings. An `O_PATH` descriptor lets the daemon reject devices, FIFOs,
directories, foreign owners, multiple hard links and oversized files without opening
a device handler or reading content. Only singly linked, agent-owned regular files
are accepted. The daemon reopens its own pinned descriptor via procfs and checks
the device/inode again; it never reopens the caller's pathname after authorization.

Each read obtains fresh policy/risk authorization inside the executing call, charges
the existing file-read budget, reads from the held descriptor and records metadata
before returning content. A caller cannot submit an earlier ALLOW as execution
authority. Attempts charged before reading are not refunded on read failure, crash
or disconnection. A growth check prevents a file expanded after opening from exceeding
the response bound. Budget exhaustion persists across daemon restarts.

Tests cover deterministic file-path and workspace replacement, symlinks, hard links,
traversal, ownership and size/growth refusal. Linux cross-account CI additionally checks
actual returned bytes, FIFO refusal, policy-channel isolation, 1000 successful reads,
denial of the next read, and exhaustion after restart.

## Restart and limitations

The state binding persists the session, agent/operator UIDs, workspace and profile.
Restarting preserves the session, leases and key. Changing that binding is refused;
provision new state deliberately for a new assignment. A partially initialized state
directory fails closed and requires operator recovery. Back up the full directory
only while stopped. Do not copy unrelated legacy databases into this directory.

An exclusive lock prevents concurrent access by two daemon instances. The service
does not remove sockets at startup or shutdown. After verifying the old process is
stopped, the administrator may remove its stale socket before restarting.

This is a bounded read-execution milestone, not host confinement. Direct agent syscalls
are unaffected. Existing write/delete/rollback broker path races must be closed before
running those brokers with service authority. Authorization responses are not signed
execution tokens; the new read method obtains its own fresh authorization. File
contents may change concurrently: descriptor identity is pinned, not a byte snapshot.
No request timeout is claimed to interrupt a blocked filesystem/kernel operation.
No multi-agent tenancy, rate-limit availability guarantee, remote attestation or
production macOS service installation is claimed. See [ADR 0056](../adr/0056-separate-local-authority-by-os-account.md).
