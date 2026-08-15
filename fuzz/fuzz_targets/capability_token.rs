//! Fuzz capability token parsing — the first thing an unauthenticated caller reaches.
//!
//! The Gateway parses whatever is in the `x-vigil-capability` header before it can decide
//! anything about it. A panic here is a denial-of-service reachable without credentials, and
//! a parser that accepts a malformed token is worse.
//!
//! The property asserted beyond "does not crash": a token that fails verification must never
//! consume a nonce. Otherwise an attacker who cannot forge a capability can still destroy a
//! victim's by replaying garbage until the use count is exhausted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use vigil_capability::{CapabilityVerifier, InMemoryNonceStore, NonceStore, PresentedAction};
use vigil_common::{ContentHash, FixedClock};

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };

    let clock = Arc::new(FixedClock::at_epoch());
    let nonces = Arc::new(InMemoryNonceStore::new());
    let verifier = CapabilityVerifier::new(clock, nonces.clone());

    let presented = PresentedAction {
        tenant_id: "acme".parse().expect("static id"),
        environment_id: "prod".parse().expect("static id"),
        agent_id: "agent-a".parse().expect("static id"),
        agent_instance_id: "inst-1".parse().expect("static id"),
        session_id: "sess-1".parse().expect("static id"),
        principal_id: "user-1".parse().expect("static id"),
        action_kind: "tool_call".to_string(),
        tool_id: None,
        operation: "read".to_string(),
        target_resource: None,
        action_hash: ContentHash::sha256(b"fuzz"),
    };

    // No key is trusted, so every input must be rejected. Any acceptance is a critical bug.
    let result = verifier.verify_and_consume(token, &presented);
    assert!(
        result.is_err(),
        "a verifier trusting no keys accepted a token"
    );

    // A rejected token must not have burned a nonce.
    assert!(
        nonces.is_empty(),
        "a rejected capability consumed a nonce, enabling exhaustion of a live one"
    );

    // Inspection takes the same untrusted input and must also stay total.
    let _ = verifier.inspect(token);
});
