//! Fuzz the MCP tool manifest parser.
//!
//! A manifest is supplied by the MCP server itself, so every byte is attacker-controlled under
//! threat T3. Rejection is the expected outcome for almost all input; the properties concern
//! what happens when a manifest *is* accepted.
//!
//! Accepting a manifest is what establishes a drift baseline, so a manifest that parses
//! differently on two passes would let a server present one thing and have another recorded.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_common::canonical::canonicalize;
use vigil_local::McpToolManifest;

fuzz_target!(|data: &[u8]| {
    let Ok(manifests) = serde_json::from_slice::<Vec<McpToolManifest>>(data) else {
        // Refusing malformed input is correct behaviour, not a finding.
        return;
    };

    // Deserialization is not the system's acceptance boundary. Before a manifest can establish
    // a baseline, each schema is canonicalized and hashed; numerics that do not survive JSON
    // round trips (or require cross-language-ambiguous exponent notation) are refused there.
    // Mirror that boundary so the property applies only to manifests VIGIL would record.
    if manifests
        .iter()
        .any(|manifest| canonicalize(&manifest.input_schema).is_err())
    {
        return;
    }

    // Whatever was accepted must survive a round trip unchanged. The stored baseline is
    // derived from this value, and a lossy round trip would mean the recorded baseline is not
    // what the server actually presented.
    let rendered = serde_json::to_vec(&manifests).expect("an accepted manifest must re-serialize");
    let reparsed: Vec<McpToolManifest> =
        serde_json::from_slice(&rendered).expect("re-serialized manifest must re-parse");
    assert_eq!(
        manifests, reparsed,
        "a manifest does not round-trip; the recorded baseline could differ from what was presented"
    );
});
