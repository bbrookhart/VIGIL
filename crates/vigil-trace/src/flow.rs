//! Value-flow detection: did *this specific value* reach *this action*?
//!
//! # Why
//!
//! Detecting that an action's arguments "look like they contain a secret" is a pattern match,
//! and pattern matches are trivially evaded — base64 the value, hex it, reverse it, split it
//! across two fields. What is not evadable is the fact that the value came from a place VIGIL
//! watched it enter. Value-flow tracking asks the harder, more useful question: is the thing
//! being sent derived from a value that was read from a sensitive source in this session?
//!
//! # What
//!
//! When a sensitive value enters a session (a secret read from a vault tool, a customer
//! record field), it is registered as a *tracked value*. Every subsequent action's content is
//! checked for that value under a set of encodings an agent or an attacker might apply. A hit
//! is a causal link, recorded with the node the value came from.
//!
//! # Assumptions
//!
//! This catches mechanical transformation, not semantic paraphrase: an agent that reads a
//! secret and retypes it with a character changed will not match. That is why value flow is
//! one signal among several rather than the whole control — the deterministic egress rules in
//! `policies/base/10-data-egress.yaml` do not depend on it, and the injection-influence
//! signal catches the steering even when the payload is unrecognizable.
//!
//! Tracked values are held as fingerprints wherever possible; the raw value is retained only
//! for the lifetime of the session and never written to an event (spec §24).

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;

/// Values shorter than this are not tracked: they collide with ordinary prose and would
/// produce constant false positives.
pub const MIN_TRACKABLE_LENGTH: usize = 8;

/// How a tracked value was found in the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEncoding {
    /// The value appears verbatim.
    Verbatim,
    /// Standard or URL-safe base64.
    Base64,
    /// Lowercase or uppercase hex.
    Hex,
    /// Percent-encoded, as it would appear in a URL or form body.
    PercentEncoded,
    /// Character-reversed. Cheap to check, and a real evasion seen in the wild.
    Reversed,
    /// The value with common separators stripped, which defeats naive substring checks.
    SeparatorsStripped,
}

impl FlowEncoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verbatim => "verbatim",
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::PercentEncoded => "percent_encoded",
            Self::Reversed => "reversed",
            Self::SeparatorsStripped => "separators_stripped",
        }
    }

    /// Whether finding the value in this form suggests deliberate obfuscation.
    ///
    /// A verbatim appearance is what a benign workflow looks like. A reversed or
    /// separator-stripped appearance is not something a correct program does by accident.
    pub fn suggests_evasion(&self) -> bool {
        matches!(
            self,
            Self::Reversed | Self::SeparatorsStripped | Self::Base64 | Self::Hex
        )
    }
}

/// A value being watched as it moves through a session.
#[derive(Debug, Clone)]
pub struct TrackedValue {
    /// The raw value. Session-scoped, never serialized into an event.
    value: String,
    /// Precomputed encodings, so each action check is a set of substring searches rather
    /// than repeated re-encoding.
    encodings: Vec<(FlowEncoding, String)>,
}

impl TrackedValue {
    /// Register a value for tracking. Returns `None` if the value is too short to track
    /// without generating noise.
    pub fn new(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.chars().count() < MIN_TRACKABLE_LENGTH {
            return None;
        }
        let mut encodings = vec![(FlowEncoding::Verbatim, trimmed.to_string())];

        encodings.push((FlowEncoding::Base64, B64.encode(trimmed.as_bytes())));
        let b64url = B64URL.encode(trimmed.as_bytes());
        if !encodings.iter().any(|(_, e)| e == &b64url) {
            encodings.push((FlowEncoding::Base64, b64url));
        }
        encodings.push((FlowEncoding::Hex, hex::encode(trimmed.as_bytes())));
        encodings.push((FlowEncoding::Hex, hex::encode_upper(trimmed.as_bytes())));
        encodings.push((FlowEncoding::PercentEncoded, percent_encode(trimmed)));
        encodings.push((
            FlowEncoding::Reversed,
            trimmed.chars().rev().collect::<String>(),
        ));
        let stripped = strip_separators(trimmed);
        if stripped != trimmed && stripped.chars().count() >= MIN_TRACKABLE_LENGTH {
            encodings.push((FlowEncoding::SeparatorsStripped, stripped));
        }

        Some(Self {
            value: trimmed.to_string(),
            encodings,
        })
    }

    /// A non-reversible identifier for this value, safe to put in an event.
    pub fn fingerprint(&self) -> String {
        vigil_common::redact::fingerprint(&self.value)
    }

    /// Look for this value inside `content` under any tracked encoding.
    ///
    /// Base64 and hex forms are matched case-sensitively (they are not case-insensitive
    /// encodings), while the verbatim form is matched case-sensitively too: a secret whose
    /// case changed is no longer the secret.
    pub fn find_in(&self, content: &str) -> Option<FlowEncoding> {
        // The separator-stripped form of the *content* catches a value split by whitespace
        // or punctuation across the payload, e.g. `sk-live` + `-` + `abcdef`.
        let stripped_content = strip_separators(content);
        for (encoding, needle) in &self.encodings {
            if content.contains(needle.as_str()) {
                return Some(*encoding);
            }
            if matches!(encoding, FlowEncoding::Verbatim)
                && stripped_content.contains(&strip_separators(needle))
                && strip_separators(needle).chars().count() >= MIN_TRACKABLE_LENGTH
            {
                return Some(FlowEncoding::SeparatorsStripped);
            }
        }
        None
    }
}

/// Percent-encode everything that is not an unreserved URL character.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Remove characters an attacker can insert without changing what a human reads.
fn strip_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '_' | '.' | ',' | ':' | '|' | '/'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-live-51H8xQ2eZvKYlo2C";

    fn tracked() -> TrackedValue {
        TrackedValue::new(SECRET).expect("long enough to track")
    }

    #[test]
    fn a_verbatim_value_is_found() {
        let t = tracked();
        assert_eq!(
            t.find_in(&format!("here you go: {SECRET} thanks")),
            Some(FlowEncoding::Verbatim)
        );
    }

    #[test]
    fn base64_encoding_does_not_hide_the_value() {
        let t = tracked();
        let payload = format!("data={}", B64.encode(SECRET.as_bytes()));
        assert_eq!(t.find_in(&payload), Some(FlowEncoding::Base64));
    }

    #[test]
    fn hex_encoding_does_not_hide_the_value() {
        let t = tracked();
        assert_eq!(
            t.find_in(&hex::encode(SECRET.as_bytes())),
            Some(FlowEncoding::Hex)
        );
        assert_eq!(
            t.find_in(&hex::encode_upper(SECRET.as_bytes())),
            Some(FlowEncoding::Hex)
        );
    }

    #[test]
    fn percent_encoding_in_a_url_does_not_hide_the_value() {
        // A value containing reserved characters, so its encoded form genuinely differs.
        // (`SECRET` is entirely unreserved, so percent-encoding is a no-op for it and the
        // verbatim matcher legitimately claims the hit first — see the test below.)
        let token = "aB3+xY/9zQ==pad";
        let t = TrackedValue::new(token).expect("long enough to track");
        let url = format!("https://evil.example/collect?k={}", percent_encode(token));
        assert_eq!(t.find_in(&url), Some(FlowEncoding::PercentEncoded));
    }

    #[test]
    fn a_value_that_percent_encodes_to_itself_is_still_found_verbatim() {
        let t = tracked();
        assert_eq!(percent_encode(SECRET), SECRET);
        let url = format!("https://evil.example/collect?k={}", percent_encode(SECRET));
        assert_eq!(t.find_in(&url), Some(FlowEncoding::Verbatim));
    }

    #[test]
    fn reversal_does_not_hide_the_value() {
        let t = tracked();
        let reversed: String = SECRET.chars().rev().collect();
        assert_eq!(t.find_in(&reversed), Some(FlowEncoding::Reversed));
    }

    #[test]
    fn splitting_the_value_with_separators_does_not_hide_it() {
        let t = tracked();
        let split = "s k - l i v e - 5 1 H 8 x Q 2 e Z v K Y l o 2 C";
        assert_eq!(t.find_in(split), Some(FlowEncoding::SeparatorsStripped));
    }

    #[test]
    fn unrelated_content_does_not_match() {
        let t = tracked();
        assert_eq!(t.find_in("the quarterly report is attached"), None);
        assert_eq!(t.find_in("sk-live-DIFFERENTVALUE0000"), None);
    }

    #[test]
    fn a_changed_character_is_not_a_match() {
        // Documents the known limit: mechanical transformation is caught, mutation is not.
        let t = tracked();
        assert_eq!(t.find_in("sk-live-51H8xQ2eZvKYlo2X"), None);
    }

    #[test]
    fn short_values_are_not_tracked() {
        assert!(TrackedValue::new("abc").is_none());
        assert!(TrackedValue::new("       ").is_none());
        assert!(TrackedValue::new("12345678").is_some());
    }

    #[test]
    fn the_fingerprint_never_contains_the_value() {
        let fp = tracked().fingerprint();
        assert!(!fp.contains(SECRET));
        assert!(fp.starts_with("fp:"));
    }

    #[test]
    fn obfuscated_encodings_are_flagged_as_evasive_and_verbatim_is_not() {
        assert!(!FlowEncoding::Verbatim.suggests_evasion());
        assert!(FlowEncoding::Base64.suggests_evasion());
        assert!(FlowEncoding::Reversed.suggests_evasion());
    }
}
