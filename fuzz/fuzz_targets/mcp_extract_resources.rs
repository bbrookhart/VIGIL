//! Fuzz the argument walker that decides what an MCP call is allowed to touch.
//!
//! This function consumes JSON supplied by an MCP server, which the threat model treats as
//! hostile (T3). It is recursive and it feeds the authorization path, so a panic here is a
//! denial of service in the security control and a missed resource is an unchecked operation.
//!
//! Four properties are asserted rather than merely "does not crash":
//!
//! 1. **Bounded output.** A hostile server cannot make extraction produce unbounded work
//!    downstream — every resource found is authorized individually.
//! 2. **Determinism.** The same arguments always produce the same resources, so an
//!    authorization decision cannot depend on map iteration order.
//! 3. **Faithfulness.** Every value reported actually occurs in the input. Extraction must
//!    not invent a path, because an invented path is an authorization decision about
//!    something that was never requested.
//! 4. **Termination.** Deep nesting returns rather than exhausting the stack.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vigil_local::extract_resources;

/// Mirrors `MAX_EXTRACTED_RESOURCES` in the crate.
const MAX_RESOURCES: usize = 64;
const MAX_RESOURCE_BYTES: usize = 4096;

/// Whether `needle` occurs as a string anywhere in the document.
fn contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text == needle,
        Value::Array(items) => items.iter().any(|item| contains_string(item, needle)),
        Value::Object(entries) => entries.values().any(|item| contains_string(item, needle)),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };

    let found = extract_resources(&value);

    assert!(
        found.len() <= MAX_RESOURCES,
        "extraction returned {} resources, above the {MAX_RESOURCES} bound",
        found.len()
    );

    for resource in &found {
        assert!(
            !resource.value.is_empty(),
            "an empty string was reported as a resource"
        );
        assert!(
            resource.value.len() <= MAX_RESOURCE_BYTES,
            "a resource longer than the bound was reported"
        );
        // Faithfulness is checked against the *parsed* document, not the raw text. An earlier
        // version of this target searched the source string and fired on the JSON literal
        // ".\/", where the escape means the parsed value ./ never appears verbatim. That was
        // a flaw in the assertion, not in extraction.
        assert!(
            contains_string(&value, &resource.value),
            "extraction reported a resource that is not in the document: {}",
            resource.value
        );
    }

    let again = extract_resources(&value);
    assert_eq!(
        found, again,
        "extraction is not deterministic — an authorization decision would depend on iteration order"
    );
});
