//! Fuzz canonicalization — the function whose correctness every signature binding rests on.
//!
//! Two properties are asserted, not merely "does not crash":
//!
//! 1. **Idempotence.** Canonical output, re-parsed and re-canonicalized, must be identical.
//!    A property test already found one violation here (`-956.3861133448573`, where the JSON
//!    parser resolves the literal to a neighbouring double); this searches for others with a
//!    coverage-guided engine rather than a random generator.
//! 2. **Determinism.** The same value canonicalizes the same way every time.
//!
//! Rejection is a valid outcome — VCJ/1 deliberately refuses values it cannot render
//! identically across SDKs — so the properties are stated over the accepted domain.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vigil_common::canonical::canonicalize;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };

    let Ok(once) = canonicalize(&value) else {
        // Refusing a value is correct behaviour, not a finding.
        return;
    };

    // Whatever we emit must be parseable, or a verifier could not re-canonicalize it.
    let reparsed: Value = serde_json::from_str(&once)
        .unwrap_or_else(|e| panic!("canonical output is not valid JSON: {e}\noutput: {once}"));

    let twice = canonicalize(&reparsed)
        .unwrap_or_else(|e| panic!("canonical output failed to re-canonicalize: {e}"));

    assert_eq!(
        once, twice,
        "canonicalization is not idempotent — this is a signature-forgery primitive"
    );

    // And repeated calls agree: no map iteration order leaking into the bytes.
    assert_eq!(once, canonicalize(&value).expect("still canonicalizes"));
});
