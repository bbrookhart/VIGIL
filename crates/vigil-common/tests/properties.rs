//! Property tests for canonicalization and path handling.
//!
//! Canonicalization is the one component where a subtle bug is a signature-forgery
//! primitive: if two different actions can canonicalize identically, an approval covers
//! something nobody approved. The contract vectors pin specific cases; these state the laws.

use proptest::prelude::*;
use serde_json::{json, Value};
use vigil_common::canonical::canonicalize;
use vigil_common::{path, ContentHash};

/// Arbitrary JSON, bounded in depth and size, and excluding the number forms VCJ/1
/// deliberately refuses to render.
fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-1_000_000i64..1_000_000).prop_map(|n| json!(n)),
        (-1000.0f64..1000.0).prop_map(|f| json!(f)),
        "[a-zA-Z0-9 _.:@/-]{0,40}".prop_map(Value::String),
        // Keys and values that exercise escaping and non-ASCII handling.
        prop::sample::select(vec!["\n", "\t", "\"", "\\", "é", "日本", "🙂", "\u{1}"])
            .prop_map(|s| Value::String(s.to_string())),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map("[a-zA-Z0-9_\u{ff3a}\u{10000}]{1,12}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    /// Canonical output must itself canonicalize to the same bytes. A profile that is not
    /// idempotent cannot be used for signature binding at all.
    ///
    /// VCJ/1 deliberately *rejects* values it cannot render deterministically — non-finite
    /// numbers, magnitudes at or above 1e16, values needing exponent notation, and floats
    /// that do not survive a JSON round trip on this platform. Rejection is a correct
    /// outcome, so these properties are stated over the accepted domain.
    #[test]
    fn canonicalization_is_idempotent(value in any_json()) {
        let Ok(once) = canonicalize(&value) else { return Ok(()); };
        let reparsed: Value = serde_json::from_str(&once).expect("output is valid JSON");
        prop_assert_eq!(&once, &canonicalize(&reparsed).expect("re-canonicalizes"));
    }

    /// The output is always parseable JSON. If it were not, a verifier could not
    /// re-canonicalize what it received.
    #[test]
    fn canonical_output_is_always_valid_json(value in any_json()) {
        let Ok(once) = canonicalize(&value) else { return Ok(()); };
        prop_assert!(serde_json::from_str::<Value>(&once).is_ok(), "not valid JSON: {}", once);
    }

    /// The property the whole scheme depends on: two values that differ must not hash the
    /// same. Stated as its contrapositive — equal hashes imply equal canonical bytes.
    #[test]
    fn equal_hashes_imply_equal_canonical_forms(a in any_json(), b in any_json()) {
        let (Ok(ca), Ok(cb)) = (canonicalize(&a), canonicalize(&b)) else { return Ok(()); };
        let (ha, hb) = (
            ContentHash::canonical_json(&a).expect("ok"),
            ContentHash::canonical_json(&b).expect("ok"),
        );
        if ha.ct_eq(&hb) {
            prop_assert_eq!(ca, cb, "distinct canonical forms produced the same hash");
        } else {
            prop_assert_ne!(ca, cb);
        }
    }

    /// Hashing is deterministic across repeated calls — no map iteration order leaking in.
    #[test]
    fn hashing_is_deterministic(value in any_json()) {
        let Ok(first) = ContentHash::canonical_json(&value) else { return Ok(()); };
        for _ in 0..8 {
            prop_assert!(first.ct_eq(&ContentHash::canonical_json(&value).expect("ok")));
        }
    }

    /// Rejection is deterministic too: a value the profile refuses must be refused every
    /// time. A canonicalizer that accepted a value intermittently would be worse than one
    /// that always refused it.
    #[test]
    fn rejection_is_deterministic(value in any_json()) {
        let first = canonicalize(&value).is_ok();
        for _ in 0..4 {
            prop_assert_eq!(first, canonicalize(&value).is_ok());
        }
    }

    /// Object key order in the input must never affect the output. This is the property an
    /// attacker attacks by reordering keys to reuse an approval.
    #[test]
    fn key_order_never_affects_the_canonical_form(
        // A *set* of keys: with duplicates, the forward and reverse maps genuinely hold
        // different values (last write wins), so they should differ. The property under
        // test is about ordering, not about duplicate-key resolution.
        keys in prop::collection::hash_set("[a-z]{1,8}", 1..8),
        values in prop::collection::vec(-1000i64..1000, 8..9),
    ) {
        let pairs: Vec<(String, i64)> =
            keys.iter().cloned().zip(values.iter().copied()).collect();

        let forward: serde_json::Map<String, Value> =
            pairs.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        let reverse: serde_json::Map<String, Value> =
            pairs.iter().rev().map(|(k, v)| (k.clone(), json!(v))).collect();

        prop_assert_eq!(
            canonicalize(&Value::Object(forward)).expect("ok"),
            canonicalize(&Value::Object(reverse)).expect("ok")
        );
    }

    // ------------------------------------------------------------------ paths

    /// A path that normalizes inside a root must not escape it. The lexical half of the
    /// filesystem boundary.
    #[test]
    fn containment_is_stable_under_normalization(
        root in prop::sample::select(vec!["/workspace", "/var/lib/vigil", "/srv/data"]),
        segments in prop::collection::vec("[a-z]{1,8}", 0..6),
    ) {
        let candidate = format!("{root}/{}", segments.join("/"));
        prop_assert!(
            path::is_inside_any(&candidate, &[root.to_string()]),
            "{candidate} should be inside {root}"
        );
    }

    /// Any number of `..` segments can leave a root but never re-enter it by accident.
    #[test]
    fn traversal_out_of_a_root_is_detected(
        root in prop::sample::select(vec!["/workspace", "/srv/data"]),
        depth in 1usize..8,
    ) {
        let escape = format!("{root}/{}etc/passwd", "../".repeat(depth));
        prop_assert!(
            !path::is_inside_any(&escape, &[root.to_string()]),
            "{escape} escaped {root} undetected"
        );
    }

    /// Normalization is idempotent, so a caller cannot gain anything by pre-normalizing.
    #[test]
    fn normalization_is_idempotent(raw in "[a-z./]{0,40}") {
        let once = path::normalize(&raw);
        prop_assert_eq!(&once, &path::normalize(&once));
    }

    /// A sibling directory sharing a prefix is never inside the root. `/workspace-evil`
    /// must not pass a `/workspace` check.
    #[test]
    fn prefix_lookalikes_are_never_contained(suffix in "[a-z]{1,10}") {
        let sibling = format!("/workspace-{suffix}/secret");
        prop_assert!(!path::is_inside_any(&sibling, &["/workspace".to_string()]));
    }
}
