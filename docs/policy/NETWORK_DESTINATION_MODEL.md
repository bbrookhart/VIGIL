# Network destination integrity model

The Phase 2 network surface is a payload-free TCP probe, not a general socket API or firewall. The
Phase 4 foundation adds a compact flow-decision core and simulator in `vigil-network`. The Network
Extension data-provider boundary compiles, but no extension is packaged or installed.

## Authorization sequence

```text
normalize hostname + port
  → reject malformed/direct-IP/unknown destination before DNS
  → resolve through bounded event source
  → require 1..32 addresses, all on the requested port
  → reject any private, local, link-local, metadata, multicast, documentation, or special-use IP
  → atomically reserve connection + novel destination budget
  → connect to one validated address
  → verify connected peer belongs to the resolution set
  → close without application payload
  → commit budget and append metadata-only evidence
```

Hostname comparison is ASCII, case-insensitive, exact, and ignores one terminal DNS root dot. No
wildcards or suffix matching are used. Enforced profile allowlists currently contain a small set
of development/research destinations on TCP 443. Direct IPs are denied so hostname policy cannot
be bypassed. If any answer is non-public, the entire resolution is denied rather than selecting a
different answer; this prevents a mixed-answer rebinding bypass.

IPv4 checks reject unspecified, loopback, RFC1918, shared-address, link-local/metadata,
documentation, benchmarking, multicast, and reserved ranges. IPv6 checks require global-unicast
space and additionally reject unspecified, loopback, multicast, unique-local, link-local,
documentation, and mapped non-public IPv4 addresses.

## Limits

The system resolver is executed behind a caller-visible timeout, but platform resolver APIs do
not provide cancellation of an in-flight lookup. A timed-out worker can therefore finish later.
The probe carries no HTTP/TLS semantics, does not inspect SNI, sends no application bytes, and
does not govern direct sockets. Network Extension remains required for non-bypassability, flow
attribution, byte budgets, and continuous enforcement.

The Phase 4 contract carries a pre-resolved public address set and exclusive expiry into the
callback rather than resolving there. A managed flow must match exact hostname, protocol, port,
and one address in that set. Policy refreshes preserve spent flow and destination budget. See
[ADR 0035](../adr/0035-network-flow-authority-is-hostname-plus-pinned-address.md) and the
[Network Extension model](../architecture/NETWORK_EXTENSION_MODEL.md).
