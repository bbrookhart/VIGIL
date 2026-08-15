//! Fuzz path decoding and containment.
//!
//! Paths arrive from agent-chosen tool arguments. The property asserted is the one the
//! filesystem boundary depends on: a path reported as inside a root must not, after
//! normalization, escape it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_common::path;
use vigil_detect::command;

const ROOTS: &[&str] = &["/workspace", "/srv/data"];

fuzz_target!(|data: &[u8]| {
    let Ok(candidate) = std::str::from_utf8(data) else {
        return;
    };

    let roots: Vec<String> = ROOTS.iter().map(|r| r.to_string()).collect();
    let findings = command::analyze_path(candidate, &roots);

    let normalized = path::normalize(candidate);
    // Normalization is idempotent, so a caller gains nothing by pre-normalizing.
    assert_eq!(normalized, path::normalize(&normalized));

    // The load-bearing property: anything judged inside a root must genuinely be inside it
    // after normalization, with the separator boundary respected.
    if path::is_inside_any(candidate, &roots) {
        let inside = ROOTS.iter().any(|root| {
            normalized == *root || normalized.starts_with(&format!("{root}/"))
        });
        assert!(
            inside,
            "`{candidate}` was judged inside a root but normalizes to `{normalized}`"
        );
        // A contained path must not also be reported as escaping its base.
        assert!(
            !findings
                .reason_codes
                .contains(&vigil_protocol::reason::ReasonCode::PathOutsideAllowlist),
            "`{candidate}` was both inside a root and outside the allowlist"
        );
    }
});
