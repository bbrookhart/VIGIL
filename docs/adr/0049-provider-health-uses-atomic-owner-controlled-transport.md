# ADR 0049 — Provider health uses atomic owner-controlled transport

**Status:** Accepted

## Context

A valid health signature does not make file transport safe. Readers must not follow symlinks,
consume unbounded data, accept group/world-writable state, or observe partially written envelopes.
The provider must also never perform publication from `handleNewFlow`.

## Decision

Signed provider-health envelopes use a dedicated App Group file with a 32 KiB limit. The
provider-side publisher:

- serializes writers with process and advisory locks;
- creates an owner-only same-directory temporary file without following links;
- writes completely, fsyncs, atomically renames, and fsyncs the directory; and
- requires an explicitly supplied signer rather than silently generating or persisting key data.

The containing-app reader opens the directory and file without following symlinks, requires the
effective owner, a regular owner-only file, a positive bounded size, and a complete read with no
trailing race. It then verifies the signed health envelope before returning the opaque verified
type. A missing read creates no lock or other shared-container state.

This path is for provider lifecycle/timer work only. It is not called by the flow verdict callback.

## Consequences

Atomic publication and protected read/verify are implemented and tested for missing, symlinked,
oversized, insecure, and tampered state. Provider-only signing-key custody and lifecycle scheduling
are now wired by ADR 0050, and ADR 0051 adds live-proof public-key enrollment. Production still
requires a provisioned App Group, host orchestration, cleanup semantics, and entitled-device proof.
Until those are complete, provider evidence remains unavailable to the Control Center.
