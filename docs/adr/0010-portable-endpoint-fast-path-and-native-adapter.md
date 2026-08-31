# ADR 0010 — Separate the portable Endpoint fast path from Apple API ownership

**Status:** Accepted  
**Date:** 2026-08-30

## Context

Endpoint Security authorization has a kernel deadline and an entitlement-dependent C API. Direct
Rust/Swift FFI would add unsafe ownership and lifetime complexity precisely where missed deadlines
can kill the ES client. CI and most developer machines also cannot activate an entitled System
Extension.

## Decision

Place normalized event types, audit-token attribution, compact policy, bounded decisions,
deadline/drop simulation, response semantics, and metrics in the safe Rust `vigil-endpoint` crate.
Keep `es_client_t`, `es_message_t`, Mach time, token decoding, API-specific response calls, and
same-thread client lifecycle in a thin Swift adapter.

Do not introduce direct Rust/Swift FFI in this phase. The native adapter projects owned, bounded
values into a synchronous handler closure; a later signed daemon/extension integration will use a
versioned generated protocol or another reviewed process boundary. `AUTH_OPEN` uses
`es_respond_flags_result`; other authorization events use `es_respond_auth_result`; caching stays
disabled until invalidation semantics are proven. The native side installs only validated,
monotonically versioned compact snapshots. Rust signs canonical payload bytes with Ed25519 and a
dedicated signing domain; Swift verifies against provisioned public keys before strict decoding.
This authenticates policy content but does not replace peer authentication at the eventual
daemon/extension boundary. Generation rollback is refused within the running extension; protected
durable high-water persistence remains required across restarts.

## Consequences

Portable CI can exhaustively test authorization semantics without an entitlement, while macOS CI
can compile the real public API adapter. The Swift check covers exec/open/create/rename/unlink,
fork/exit attribution, path boundaries, signature failure, expiry, wrong-instance targeting, and
snapshot replay. A Rust-generated fixture pins the current Swift decoder, but there is still
temporary duplication between normalized Swift and Rust types; schema changes therefore require
the blocking parity gate. An activatable System Extension target is intentionally not fabricated
without full Xcode; Phase 3 remains incomplete until entitled device tests prove pre-execution
denial.
