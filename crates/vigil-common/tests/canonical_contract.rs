//! The Rust half of the cross-language canonicalization contract.
//!
//! Executes `tests/contract/canonical_vectors.json`, the same file
//! `sdk/python/tests/test_canonical_contract.py` executes. If the two implementations ever
//! disagree on a single byte, one of these two suites fails.
//!
//! This matters more than it looks: VIGIL Core signs a hash of an action's canonical bytes,
//! and the Python SDK recomputes that hash locally. A disagreement means either a valid
//! approval fails to verify, or — much worse — two different actions hash the same and an
//! approval binding covers something nobody approved.

use serde_json::Value;
use std::path::PathBuf;
use vigil_common::canonical::{canonicalize, CANONICAL_PROFILE};
use vigil_common::ContentHash;

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("tests/contract/canonical_vectors.json"))
        .expect("workspace root");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("contract vectors missing at {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("contract vectors are valid JSON")
}

#[test]
fn the_vector_file_targets_this_canonicalization_profile() {
    let v = vectors();
    assert_eq!(
        v["profile"].as_str(),
        Some(CANONICAL_PROFILE),
        "the contract vectors describe a different profile than this build implements"
    );
}

#[test]
fn every_accepted_vector_canonicalizes_to_the_specified_bytes() {
    let v = vectors();
    let accepted = v["accepted"].as_array().expect("accepted vectors");
    assert!(!accepted.is_empty(), "the contract suite is empty");

    for case in accepted {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let expected = case["canonical"].as_str().unwrap_or_default();
        let produced = canonicalize(&case["input"])
            .unwrap_or_else(|e| panic!("vector `{name}` failed to canonicalize: {e}"));
        assert_eq!(
            produced, expected,
            "vector `{name}` produced different canonical bytes"
        );
    }
}

#[test]
fn canonicalization_is_idempotent_for_every_vector() {
    // Re-parsing canonical output and canonicalizing again must be a no-op. A profile that
    // is not idempotent cannot be used for signature binding at all.
    let v = vectors();
    for case in v["accepted"].as_array().expect("accepted vectors") {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let once = canonicalize(&case["input"]).expect("canonicalizes");
        let reparsed: Value = serde_json::from_str(&once)
            .unwrap_or_else(|e| panic!("vector `{name}` output is not valid JSON: {e}"));
        assert_eq!(
            once,
            canonicalize(&reparsed).expect("canonicalizes"),
            "vector `{name}` is not idempotent"
        );
    }
}

#[test]
fn rejected_vectors_are_refused_rather_than_approximated() {
    let v = vectors();
    for case in v["rejected"].as_array().expect("rejected vectors") {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let literal = case["input_literal"].as_str().unwrap_or_default();

        // These literals are not representable in strict JSON, so they are constructed
        // directly rather than parsed — which is exactly how they would arrive from a
        // caller's in-memory value.
        let value = match literal {
            "1e17" => Value::Number(serde_json::Number::from_f64(1e17).expect("finite")),
            "Infinity" | "NaN" => {
                // serde_json refuses to construct non-finite numbers at all, which is a
                // stronger guarantee than rejecting them at canonicalization time.
                assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
                assert!(serde_json::Number::from_f64(f64::NAN).is_none());
                continue;
            }
            other => panic!("unhandled rejected vector literal `{other}` in `{name}`"),
        };

        assert!(
            canonicalize(&value).is_err(),
            "vector `{name}` should have been rejected"
        );
    }
}

#[test]
fn hashes_of_the_vectors_are_stable_across_key_orderings() {
    // The property the whole contract exists to protect.
    let v = vectors();
    let accepted = v["accepted"].as_array().expect("accepted vectors");

    let first = accepted
        .iter()
        .find(|c| c["name"] == "key_order_is_normalized")
        .expect("vector present");
    let second = accepted
        .iter()
        .find(|c| c["name"] == "key_order_is_normalized_reversed_input")
        .expect("vector present");

    let a = ContentHash::canonical_json(&first["input"]).expect("hashes");
    let b = ContentHash::canonical_json(&second["input"]).expect("hashes");
    assert!(
        a.ct_eq(&b),
        "the same action with reordered keys produced different hashes"
    );
}
