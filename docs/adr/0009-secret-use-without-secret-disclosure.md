# ADR 0009 — Define secret use without secret disclosure

**Status:** Accepted  
**Date:** 2026-08-29

## Context

Phase 2 requires a secret broker interface, but a convenience API that returns a token would give
the agent ambient credential authority and create new leak paths through output, errors, command
arguments, and SQLite events. A native Keychain provider and authenticated daemon boundary do not
exist yet, so the repository must not imply that production secret custody is available.

## Decision

Define `SecretProvider` around metadata and structured use. `perform` returns only success or
failure; no broker API returns raw secret bytes. Exact trusted grants bind profile, opaque handle,
purpose, and target before provider access. Metadata uses fixed enums, provider error strings are
discarded, raw export always denies, and successful use consumes the durable
`brokered_secret_uses` budget.

Ship a deterministic provider simulator that contains no real credential values. Do not add a
secret-use CLI command until a trusted grant loader, authenticated IPC, and a native provider make
its authority meaningful. Status output names the current component as interface/simulator only.

## Consequences

Native providers have a narrow, testable contract that makes accidental disclosure difficult and
supports hermetic success/failure tests. The current build cannot perform a useful authenticated
Git, HTTP, or signing operation and does not claim Keychain protection. Phase 3 and later work must
preserve this boundary while adding OS attribution, daemon authentication, and native custody.
