//! Canonical JSON serialization — the byte-exact form every security binding uses.
//!
//! # Why
//!
//! Invariant 5 ("approval is transaction-bound") and Invariant 10 ("privileged actions are
//! replay resistant") both rest on one assumption: that "the same action" has exactly one
//! byte representation. If `{"to":"a","cc":"b"}` and `{"cc":"b","to":"a"}` hash differently,
//! an attacker reorders keys and reuses an approval for a different-looking request; if they
//! hash the *same* when a value actually changed, an approval covers an action nobody saw.
//!
//! # What
//!
//! VIGIL Canonical JSON (VCJ/1) is a profile of RFC 8785 (JCS):
//!
//! * object keys sorted ascending by UTF-16 code unit, duplicates impossible (input is a map)
//! * no insignificant whitespace
//! * strings escape only `"` `\` and C0 controls, using the short forms where JSON defines them
//! * `true` / `false` / `null` literal
//! * integers printed positionally
//! * non-integer finite numbers printed as shortest round-trip decimal, positional only
//!
//! # Assumptions
//!
//! VCJ/1 **rejects** numbers it cannot render identically in every VIGIL SDK: non-finite
//! values, and magnitudes at or beyond 1e16 where shortest-round-trip formatters disagree on
//! exponent style. Callers needing those must transport them as strings. This is a deliberate
//! narrowing: a canonicalizer that silently disagrees across languages is a signature forgery
//! primitive. See `sdk/python/vigil_sdk/canonical.py` for the matching implementation and
//! `tests/contract/` for the shared vector suite that pins them together.
//!
//! # Failure mode
//!
//! Canonicalization never falls back to a non-canonical encoding. A value that cannot be
//! canonicalized produces [`VigilError::Serialization`], which the pipeline treats as an
//! invalid request — not as an unhashed allow.

use crate::error::{Result, VigilError};
use serde_json::Value;
use std::cmp::Ordering;
use std::fmt::Write as _;

/// Identifier for this canonicalization profile, recorded alongside hashes so a future
/// profile change stays distinguishable in historical audit records.
pub const CANONICAL_PROFILE: &str = "VCJ/1";

/// Largest magnitude VCJ/1 will render for a non-integer number.
const MAX_CANONICAL_MAGNITUDE: f64 = 1e16;

/// Serialize a [`Value`] into VIGIL Canonical JSON.
pub fn canonicalize(value: &Value) -> Result<String> {
    let mut out = String::with_capacity(128);
    write_value(value, &mut out)?;
    Ok(out)
}

/// Serialize any serializable type into VIGIL Canonical JSON.
pub fn canonicalize_serializable<T: serde::Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    canonicalize(&value)
}

/// Canonical bytes, the input to every VIGIL hash and signature.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(canonicalize(value)?.into_bytes())
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Keys are sorted by UTF-16 code unit order, per RFC 8785. This differs from
            // Rust's byte-wise `str` ordering for supplementary-plane characters, so the
            // comparison is done explicitly rather than by `sort()`.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                let entry = map.get(*key).ok_or_else(|| {
                    VigilError::Serialization("object key vanished during canonicalization".into())
                })?;
                write_value(entry, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<()> {
    if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        let _ = write!(out, "{i}");
        return Ok(());
    }
    let f = n.as_f64().ok_or_else(|| {
        VigilError::Serialization("number is not representable as f64".to_string())
    })?;
    if !f.is_finite() {
        return Err(VigilError::Serialization(
            "non-finite numbers cannot be canonicalized; transport as a string".to_string(),
        ));
    }
    if f.abs() >= MAX_CANONICAL_MAGNITUDE {
        return Err(VigilError::Serialization(format!(
            "number magnitude >= {MAX_CANONICAL_MAGNITUDE:e} cannot be canonicalized identically \
             across SDKs; transport as a string"
        )));
    }
    if f == f.trunc() && f.abs() < 9_007_199_254_740_992.0 {
        // Integral doubles render without a fractional part, matching JCS and the Python SDK.
        let _ = write!(out, "{}", f as i64);
        return Ok(());
    }

    // Rendered through `serde_json::Number`, which formats via ryu and is guaranteed to be
    // the shortest decimal that round-trips.
    //
    // This previously used Rust's `{}`, which is *not* that guarantee. A property test found
    // `-956.3861133448573` printing as a string that re-parsed to a different double, so
    // canonicalizing → parsing → canonicalizing produced different bytes. For a function
    // whose entire purpose is that one action has exactly one byte representation, that is a
    // signature-forgery primitive: Core and the Gateway could derive different hashes for
    // the same action, and an approval could bind to bytes nobody sent.
    let rendered = n.to_string();

    // Ryu emits exponent notation for very small magnitudes (`1e-7`), and Python's `repr`
    // writes the same value as `1e-07`. Both are correct shortest round-trip forms and they
    // disagree on formatting, so a value that needs an exponent cannot be canonicalized
    // identically across SDKs. Rejecting is the only safe answer — the same reasoning that
    // already rejects magnitudes at or above 1e16.
    if rendered.contains('e') || rendered.contains('E') {
        return Err(VigilError::Serialization(format!(
            "number requires exponent notation ({rendered}), which VCJ/1 cannot render \
             identically across SDKs; transport as a string"
        )));
    }

    // Self-verification: emit only values proven to survive a round trip.
    //
    // Formatting alone is not sufficient. A property test found `-956.3861133448573`
    // canonicalizing, re-parsing, and canonicalizing again to `...572` — because the JSON
    // *parser* resolves that literal to a neighbouring double, not because the formatter was
    // wrong. No choice of formatter fixes a lossy parse on the receiving side.
    //
    // Since a canonical form that does not survive parse→re-canonicalize is unusable for
    // signature binding (Core and the Gateway would derive different hashes for the same
    // action), the value is checked here and rejected if it does not hold. Ordinary values —
    // `10.5`, `0.25`, anything needing fewer than ~17 significant digits — pass; only the
    // pathological tail is refused, and it is refused loudly rather than silently corrupting
    // a hash.
    // Re-parsed with `serde_json`, deliberately — not with `str::parse`. The receiving side
    // reads this value out of a JSON document, so the check has to exercise the same parser
    // that will actually see it. `str::parse` is correctly rounded and would pass values
    // that the JSON parser resolves to a different double, which is precisely the case that
    // breaks binding.
    match serde_json::from_str::<f64>(&rendered) {
        Ok(reparsed) if reparsed.to_bits() == f.to_bits() => {}
        _ => {
            return Err(VigilError::Serialization(format!(
                "number {rendered} does not survive a JSON round trip on this platform and \
                 cannot be canonicalized deterministically; transport it as a string or as a \
                 scaled integer"
            )))
        }
    }

    out.push_str(&rendered);
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two strings by UTF-16 code unit sequence, as RFC 8785 requires.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.encode_utf16();
    let mut bi = b.encode_utf16();
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                Ordering::Equal => continue,
                other => return other,
            },
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_affect_canonical_form() {
        let a = json!({"to": "x@example.com", "body": "hi", "cc": null});
        let b = json!({"cc": null, "body": "hi", "to": "x@example.com"});
        let ca = canonicalize(&a).unwrap();
        assert_eq!(ca, canonicalize(&b).unwrap());
        assert_eq!(ca, r#"{"body":"hi","cc":null,"to":"x@example.com"}"#);
    }

    #[test]
    fn array_order_is_significant() {
        let a = json!(["a", "b"]);
        let b = json!(["b", "a"]);
        assert_ne!(canonicalize(&a).unwrap(), canonicalize(&b).unwrap());
    }

    #[test]
    fn nested_objects_are_sorted_at_every_depth() {
        let v = json!({"z": {"b": 1, "a": 2}, "a": [{"d": 1, "c": 2}]});
        assert_eq!(
            canonicalize(&v).unwrap(),
            r#"{"a":[{"c":2,"d":1}],"z":{"a":2,"b":1}}"#
        );
    }

    #[test]
    fn control_characters_use_defined_escapes() {
        let v = json!({"k": "a\nb\tc\u{1}d\"e\\f"});
        assert_eq!(canonicalize(&v).unwrap(), r#"{"k":"a\nb\tc\u0001d\"e\\f"}"#);
    }

    #[test]
    fn non_ascii_is_emitted_literally_not_escaped() {
        let v = json!({"k": "héllo — 日本"});
        assert_eq!(canonicalize(&v).unwrap(), "{\"k\":\"héllo — 日本\"}");
    }

    #[test]
    fn integral_floats_and_integers_agree() {
        assert_eq!(canonicalize(&json!(10.0)).unwrap(), "10");
        assert_eq!(canonicalize(&json!(10)).unwrap(), "10");
        assert_eq!(canonicalize(&json!(-0.5)).unwrap(), "-0.5");
    }

    #[test]
    fn unrenderable_numbers_are_rejected_rather_than_approximated() {
        let huge = serde_json::Number::from_f64(1e17).unwrap();
        let err = canonicalize(&Value::Number(huge)).unwrap_err();
        assert!(matches!(err, VigilError::Serialization(_)));
    }

    #[test]
    fn a_float_that_does_not_survive_a_json_round_trip_is_rejected() {
        // Found by `tests/properties.rs`. This value canonicalized, re-parsed, and
        // canonicalized again to a *different* string — not because the formatter was wrong
        // (ryu is shortest-round-trip) but because the JSON parser resolves the literal to a
        // neighbouring double. Canonicalization that is not idempotent cannot be used for
        // signature binding, so the value is refused rather than silently corrupting a hash.
        let pathological = serde_json::Number::from_f64(-956.386_113_344_857_3).unwrap();
        let err = canonicalize(&Value::Number(pathological)).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not survive a JSON round trip"),
            "{err}"
        );
    }

    #[test]
    fn ordinary_decimal_values_are_still_accepted() {
        // The rejection above must not be so broad that it refuses everyday arguments.
        for value in [10.5, 0.25, -3.75, 1234.5678, 0.1, 99.99] {
            let number = serde_json::Number::from_f64(value).unwrap();
            let rendered = canonicalize(&Value::Number(number))
                .unwrap_or_else(|e| panic!("{value} should canonicalize: {e}"));
            // And it must survive the round trip the check promises.
            let reparsed: f64 = serde_json::from_str(&rendered).unwrap();
            assert_eq!(
                reparsed.to_bits(),
                value.to_bits(),
                "{value} did not round trip"
            );
        }
    }

    #[test]
    fn values_needing_exponent_notation_are_rejected() {
        // Ryu writes `1e-7`; Python's repr writes `1e-07`. Both are correct and they differ,
        // so the value cannot be canonicalized identically across SDKs.
        let tiny = serde_json::Number::from_f64(1e-7).unwrap();
        let err = canonicalize(&Value::Number(tiny)).unwrap_err();
        assert!(err.to_string().contains("exponent notation"), "{err}");
    }

    #[test]
    fn utf16_ordering_differs_from_byte_ordering_and_we_use_utf16() {
        // U+FF3A (fullwidth Z) encodes to EF BC BA in UTF-8, below U+10000's F0 90 80 80,
        // so byte order puts it first. In UTF-16, U+10000 leads with surrogate 0xD800 which
        // is below 0xFF3A, so code-unit order puts it first instead. RFC 8785 mandates the
        // latter; this test fails if anyone "simplifies" the comparator to `keys.sort()`.
        let v = json!({"\u{ff3a}": 1, "\u{10000}": 2});
        let out = canonicalize(&v).unwrap();
        let supplementary_at = out.find('\u{10000}').unwrap();
        let fullwidth_at = out.find('\u{ff3a}').unwrap();
        assert!(
            supplementary_at < fullwidth_at,
            "expected UTF-16 code-unit ordering, got {out}"
        );
        assert!("\u{ff3a}" < "\u{10000}", "byte ordering is the opposite");
    }

    #[test]
    fn canonicalization_is_idempotent_through_a_parse_round_trip() {
        let v = json!({"b": [1, {"y": "\u{1F600}", "x": true}], "a": "s"});
        let once = canonicalize(&v).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        assert_eq!(once, canonicalize(&reparsed).unwrap());
    }
}
