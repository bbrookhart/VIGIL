# Experimental local authority daemon

`vigild` separates authority state and operator approval from an agent's OS account.
It does **not execute tools**. Existing `vigil` local commands do not automatically
route through it. An `ALLOW` response is a decision, not an executable capability.

## Account and state model

| Principal | Access |
| --- | --- |
| Dedicated service UID | Owns SQLite, fixed policy binding and checkpoint seed |
| Dedicated agent UID | Status and filesystem authorization requests |
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
max_uses, ttl_seconds), `deny` (approval_id), `checkpoint`. Authorization supports
`fs.read`, `fs.write`, `fs.create`, `fs.delete`, `fs.list`, `fs.metadata` only.
The agent cannot supply a session, profile, workspace, UID or approver label.
Approval listing returns at most 20 newest entries. Oversized responses return
`response_too_large`; no truncated decision is returned.

Success is `{"ok":true,"result":...}`; application rejection is
`{"ok":false,"error":"request_denied"}`. Transport failure is an error, never an
allow. The CLI exits nonzero on either kind of failure. Approval records attribute
decisions to `unix-uid:<kernel UID>`. Status returns only the public checkpoint key.
Pin that key independently if exporting checkpoints for later verification.

## Restart and limitations

The state binding persists the session, agent/operator UIDs, workspace and profile.
Restarting preserves the session, leases and key. Changing that binding is refused;
provision new state deliberately for a new assignment. A partially initialized state
directory fails closed and requires operator recovery. Back up the full directory
only while stopped. Do not copy unrelated legacy databases into this directory.

An exclusive lock prevents concurrent access by two daemon instances. The service
does not remove sockets at startup or shutdown. After verifying the old process is
stopped, the administrator may remove its stale socket before restarting.

This is an authority-boundary milestone, not host confinement. Direct agent syscalls
are unaffected. Existing filesystem broker path races must be closed before running
those brokers with service authority. Authorization responses are neither signed
execution tokens nor receipts; lease consumption here is a research/control-plane
operation, and a later executor must obtain fresh, execution-bound authority.
No multi-agent tenancy, rate-limit availability guarantee, remote attestation or
production macOS service installation is claimed. See [ADR 0056](../adr/0056-separate-local-authority-by-os-account.md).
