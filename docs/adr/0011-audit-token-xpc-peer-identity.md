# ADR 0011 — Authenticate local control messages from the XPC audit token

**Status:** Accepted  
**Date:** 2026-08-30
**Amended by:** ADR 0013 adds generation-bound full-audit-token root registration.
**Amended by:** ADR 0014 adds a bounded listener and successful anonymous-XPC peer check.

## Context

An Ed25519 snapshot signature authenticates policy content, but not the process delivering it.
Accepting a claimed PID, bundle identifier, session ID, or privilege flag over IPC would let a
local agent impersonate `vigild`. Looking up code identity from a PID after message receipt also
creates a PID-reuse race. The full signed daemon and System Extension targets are not available in
the current Command Line Tools environment.

## Decision

Use XPC dictionaries for the future daemon-to-extension control channel. For every message, call
the public Security.framework `SecCodeCreateWithXPCMessage`, which selects the live sender from the
kernel-attached audit token, and then `SecCodeCheckValidity` against a precompiled daemon code
requirement. Dispatch only after this check returns an unforgeable in-process peer marker.

Keep the operation layer independent of listener lifecycle. It accepts bounded opaque JSON with
an exact `vigil.endpoint-control/v1` schema and permits only signed policy installation and health.
Unknown operations/fields reject. Policy verification precedes compilation, installation is one
atomic state swap, and replies expose fixed codes only. Do not add a PID-based fallback.

## Consequences

The public Apple identity path and strict control service compile and can be tested without the
Endpoint entitlement. CI proves malformed requirements, messages without an associated sender,
forged policy, unknown operations, generation replay, and concurrent installation fail safely.

The original repository state could not demonstrate a successful peer. ADR 0014 later adds a real
same-binary anonymous-XPC check. A signed `vigild` peer still requires signed daemon and System
Extension targets, a provisioned production code requirement, Mach-service registration, and an
entitled device. ADR 0021 supplies the client request-deadline lifecycle. Content signatures remain
required even after peer authentication so a transport defect alone cannot forge compact policy.
