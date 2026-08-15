//! Fuzz `ActionRequest` deserialization and hashing.
//!
//! This is the SDK-facing wire format: whatever a caller posts to `/v1/decisions` lands here
//! before authentication has established anything about them.
//!
//! The property beyond crash-freedom is the one every capability binding rests on: an action
//! that hashes must hash *deterministically*, and a body claiming a verified workload
//! identity must never produce one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_protocol::ActionRequest;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(request) = serde_json::from_str::<ActionRequest>(text) else {
        return;
    };

    // Validation must be total, whatever it decides.
    let _ = request.validate();

    // A body can claim a workload identity but never that it was verified.
    if let Some(workload) = &request.workload_identity {
        assert!(
            !workload.verified,
            "a deserialized request carried a verified workload identity"
        );
    }

    // Hashing is deterministic or capability binding is meaningless.
    if let Ok(first) = request.action_hash() {
        let second = request.action_hash().expect("hashing stayed deterministic");
        assert!(first.ct_eq(&second), "action hashing is not deterministic");
    }

    // Descriptors reach log lines and console rows.
    assert!(!request.descriptor().contains('\n'));
});
