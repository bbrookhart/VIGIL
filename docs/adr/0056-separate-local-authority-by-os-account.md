# ADR 0056: Separate local authority by OS account

Status: Accepted for the experimental authority service; execution integration pending.

## Problem

The local CLI's operator label is not authentication. An agent sharing its account
can invoke the same command and access the same SQLite database and checkpoint seed.
Moving the current filesystem broker under a privileged identity would also turn
its documented path-check/open race into a cross-account file-access risk.

## Decision

Add `vigild` as a separate, unprivileged Unix service with three distinct non-root
UIDs: service, agent, operator. Authenticate both clients and server using Unix
socket peer credentials supplied by the kernel. No request field selects an identity.
Only the operator UID may grant, deny, list approvals or request checkpoints.
One service instance binds one agent UID, workspace, profile and persistent session.
An existing state directory cannot silently be reassigned to another principal or policy.

Reuse `LocalStore`, local policy, bounded nondelegable leases and checkpoint signing.
The agent may request filesystem authorization decisions. These consume existing
leases when applicable but are not portable capabilities and cannot authorize a
separate executor. The service performs no file-content, process, network or secret
operation on the agent's behalf. Existing brokers and CLI remain separate.

The private state directory must be service-owned and owner-only. All ancestors of
state and socket directories must be root/service-owned and not writable by others.
Reject symlinks, hard-linked state files, unsafe permissions, root/same-account
configurations, unknown fields and oversized messages. Hold an exclusive state lock.
Never delete an existing socket automatically. Pin the server UID in the client.

## Consequences

This establishes account separation for the new authority endpoint only. It does
not establish complete mediation or native macOS activation. The operator account
must not run untrusted agents; UID authentication does not prove a human is present.
Root, the service account, OS integrity, administrator provisioning and restrictive
ACLs remain trusted. A single serialized service has bounded message waits, but no
availability guarantee against an authorized client flooding requests.

Linux CI exercises real cross-UID calls and state access. Production macOS service
packaging, device validation, race-safe broker execution and authenticated
decision-to-execution binding are separate gates. See the
[deployment and protocol guide](../security/LOCAL_AUTHORITY_DAEMON.md).
