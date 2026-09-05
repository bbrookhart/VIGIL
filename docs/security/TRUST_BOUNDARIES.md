# Trust boundaries

## Human to control plane

The experimental [local authority daemon](LOCAL_AUTHORITY_DAEMON.md) authenticates
separate agent and operator UIDs through kernel Unix-socket credentials and keeps
state under a third account. This applies only to its authority endpoint; legacy
local CLI commands and brokers are not routed through it. UID identity does not
establish human presence or authenticate a macOS application signature.

Human approval is administrative authority, but UI possession alone is insufficient. Future
approval IPC must verify the signed caller and use LocalAuthentication for configured high-risk
operations. Approval is specific, expiring, and auditable.

## Agent to semantic gateway

Every request field is untrusted. Workload identity comes from authenticated transport or OS
provenance, never request JSON. The Gateway—not the agent—holds external credentials and verifies
the signed, single-use capability against the exact action before execution.

## Local launcher to child process

The current environment correlation ID is an observability hint only. A child can read or
change it. Until Endpoint Security identifies the audit token/responsible process and `vigild`
owns protected state, this boundary is not an enforcement boundary.

## Agent to local semantic brokers

Session IDs are lookup/correlation keys, not authenticated bearer capabilities. Filesystem and
structured process requests receive policy, validation, budget, and evidence handling inside the
broker, but direct system calls can bypass them. Process requests inherit no environment and use
no shell or PATH lookup; their output is untrusted and bounded. Authenticated `vigild` IPC and
signed local leases are required before this becomes a stable cross-process trust boundary.

The network probe source is also untrusted after resolution: it must return the authorized port,
all addresses pass special-use checks, and the connected peer must be a member of the validated
resolution set. The system implementation sends no application payload. Network Extension flow
attribution is still required to govern sockets opened outside this broker.

The secret provider is untrusted as an evidence source. It receives only an exactly granted
structured use, returns no secret bytes, and its error text is discarded before storage or caller
output. Fixed metadata enums prevent provider-controlled descriptions from becoming a credential
exfiltration channel. A Keychain-backed Git-use provider exists, but no authenticated
cross-process broker exists in the current build.

## `vigild` to system/network extensions

Messages require versioning, strict schemas, size bounds, timeouts, caller authentication, and
operation-specific authorization. Extensions receive compact least-privilege state. They do not
trust client-provided PID/session claims.

The future containing app treats Network Extension preferences as an untrusted asynchronous OS
boundary. It validates the exact provider identity and vendor configuration, loads before every
mutation, reloads after it, serializes callers, and abandons an instance after a timeout with an
unknown outcome. An enabled preference is configuration evidence, not proof of extension health
or traffic enforcement.

The Endpoint fast path keys process executions by the full audit token rather than PID, propagates
attribution from fork notifications, and replaces the token after an allowed exec. Native root
registration now requires the authenticated control path, full audit token, exact session, and
installed generation; it accepts no PID and cannot reassign an existing identity. Compact policy
now has a strict Ed25519-signed, instance-bound, expiring Rust/Swift envelope, and installation
rejects generation rollback. The extension commits a strict generation high-water mark to an
owner-controlled directory before activating or acknowledging a newer snapshot, and refuses
corrupt state rather than resetting it. This
authenticates snapshot bytes. The native XPC boundary also derives a dynamic code identity from the
message's kernel audit token and checks a configured code requirement before dispatching a strict
install/bind/health operation. A bounded listener lifecycle and anonymous integration path now
exist. There is still no registered Mach service, signed daemon peer, production requirement or
key, installer-provisioned protected generation directory, or signed daemon capable of
submitting a trusted launched-root audit token. Untracked processes are allowed to avoid a
host-wide outage, so attribution loss must prevent protected-session launch and raise health
failure in the final system.

Accepted peers are capped and expire on a bounded idle timer. Timer refresh occurs only after the
individual message sender passes its code requirement. An unauthenticated peer receives a fixed
rejection and is then disconnected, preventing unauthenticated connection-slot pinning.

Authenticated health includes fixed-size native authorization latency, deadline, response, and
sequence counters. These process-lifetime values are diagnostic telemetry only: they cannot grant
authority, and their reset or collection failure does not change a policy decision. Durable audit
evidence must consume snapshots outside the ES callback.

Signed Endpoint policy is a lease, not permanent authority. The native fast path retains the
exclusive expiry and denies attributed-process authorization after it, or if the system clock
cannot be read. Control health becomes unready and new root bindings reject at the same boundary;
untracked host processes remain outside that denial scope.

## Agent to human approval

This is a boundary in the design and **not yet a boundary on this host**.

`grant_approval` and `deny_approval` require an `ApproverIdentity` whose only constructor is
`from_cli_operator`. No broker module can build one, and a test asserts that no broker source
references the grant path. A refactor therefore cannot open the path by accident.

An attacker is a different matter. With no `vigild` and no authenticated IPC, an agent and the
operator hold the same ambient authority: an agent that can execute code can run `vigil approvals
grant` against the same state database. Until an entitled, signed daemon owns the approval store
and authenticates its callers by audit token, invariant 3 — no self-authorization — is **not**
satisfied at the operating-system level, and nothing in VIGIL may describe it as satisfied.

What the current controls do achieve is narrower and still worth having: an approval binds to one
session, action, and resolved resource, so a granted capability cannot be reused for anything else;
leases expire and are use-counted, so a stale grant does not accumulate; and probing a refused
boundary costs the session authority automatically, so approval fatigue is not a usable pressure
tactic against the human. See ADR 0017.

## Control plane to storage

SQLite content can contain attacker-controlled metadata and is never executable configuration.
Prepared statements and fixed schemas prevent field injection. Files are owner-only. A future
hash chain and signed checkpoints make modification evident; this is not called immutability.

## Root boundary

VIGIL constrains agents operating under a human account. It does not claim protection against a
fully compromised macOS kernel or an omnipotent root attacker. It must never require disabling
SIP, Gatekeeper, TCC, or other host protections.
