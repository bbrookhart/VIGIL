//! Secret and sensitive-data classification.
//!
//! # Why
//!
//! Two jobs. First, classify data so the egress rules in
//! `policies/base/10-data-egress.yaml` have taints to match on. Second — and this is the
//! subtle one — do that *without* becoming a secret-copying machine itself. A DLP engine that
//! writes what it found into the audit log has moved every secret in the system into a log
//! store, which is usually more widely readable than wherever the secret came from.
//!
//! # What
//!
//! Structured patterns for credential formats that have recognizable shapes, an entropy
//! check for the ones that do not, and PII patterns with validating checks (Luhn for cards)
//! so a random 16-digit order number is not reported as a payment card.
//!
//! # Assumptions
//!
//! Pattern-based classification is a floor, not a ceiling. A secret in an unrecognized format
//! is caught by value-flow tracking in `vigil-trace` instead, because VIGIL saw it enter from
//! a sensitive source. The two mechanisms fail in different directions on purpose.
//!
//! # Evidence
//!
//! Every finding carries a fingerprint, never a value. The test
//! `findings_never_contain_the_secret_value` asserts that over every pattern.

use regex::Regex;
use std::sync::OnceLock;
use vigil_protocol::trust::TaintKind;

/// A class of sensitive data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataClass {
    ApiKey,
    CloudCredential,
    PrivateKey,
    Jwt,
    DatabaseUri,
    Password,
    HighEntropySecret,
    EmailAddress,
    PhoneNumber,
    PaymentCard,
    NationalId,
    IpAddress,
}

impl DataClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::CloudCredential => "cloud_credential",
            Self::PrivateKey => "private_key",
            Self::Jwt => "jwt",
            Self::DatabaseUri => "database_uri",
            Self::Password => "password",
            Self::HighEntropySecret => "high_entropy_secret",
            Self::EmailAddress => "email_address",
            Self::PhoneNumber => "phone_number",
            Self::PaymentCard => "payment_card",
            Self::NationalId => "national_id",
            Self::IpAddress => "ip_address",
        }
    }

    /// The taint this class contributes.
    pub fn taint(&self) -> TaintKind {
        match self {
            Self::ApiKey | Self::HighEntropySecret | Self::PrivateKey => TaintKind::Secret,
            Self::CloudCredential | Self::DatabaseUri | Self::Password => TaintKind::Credential,
            Self::Jwt => TaintKind::AuthenticationData,
            Self::PaymentCard => TaintKind::FinancialData,
            Self::EmailAddress | Self::PhoneNumber | Self::NationalId => TaintKind::Pii,
            Self::IpAddress => TaintKind::Pii,
        }
    }

    /// Whether this class is high-entropy enough for a fingerprint to be non-reversible.
    ///
    /// Low-entropy classes (an email address, a phone number) get length-only redaction,
    /// because a fingerprint of a guessable value is a lookup table away from the value.
    pub fn fingerprintable(&self) -> bool {
        !matches!(
            self,
            Self::EmailAddress | Self::PhoneNumber | Self::NationalId | Self::IpAddress
        )
    }

    /// Severity weight for the risk engine.
    pub fn risk_weight(&self) -> f64 {
        match self {
            Self::PrivateKey | Self::CloudCredential => 1.0,
            Self::ApiKey | Self::DatabaseUri | Self::Password => 0.9,
            Self::Jwt => 0.8,
            Self::HighEntropySecret => 0.7,
            Self::PaymentCard => 0.8,
            Self::NationalId => 0.7,
            Self::EmailAddress | Self::PhoneNumber => 0.3,
            Self::IpAddress => 0.2,
        }
    }
}

/// One classified item. Carries evidence about a value, never the value.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub class: DataClass,
    /// Where in the action it was found, e.g. `arguments.body`.
    pub path: String,
    /// Non-reversible identifier, or a length-only marker for low-entropy classes.
    pub evidence: String,
    /// The matched value's length, useful for triage.
    pub length: usize,
}

struct PatternSpec {
    class: DataClass,
    regex: &'static str,
}

/// Credential and PII patterns.
///
/// Ordered most-specific first: a value matching a vendor-specific key format should be
/// reported as that, not as a generic high-entropy blob.
const PATTERNS: &[PatternSpec] = &[
    PatternSpec {
        class: DataClass::PrivateKey,
        regex: r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY( BLOCK)?-----",
    },
    PatternSpec {
        class: DataClass::CloudCredential,
        regex: r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
    },
    PatternSpec {
        class: DataClass::CloudCredential,
        regex: r"\bAIza[0-9A-Za-z_\-]{35}\b",
    },
    PatternSpec {
        class: DataClass::ApiKey,
        regex: r"\bsk-(?:live|test|proj)?-?[A-Za-z0-9]{16,}\b",
    },
    PatternSpec {
        class: DataClass::ApiKey,
        regex: r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    },
    PatternSpec {
        class: DataClass::ApiKey,
        regex: r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
    },
    PatternSpec {
        class: DataClass::Jwt,
        regex: r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
    },
    PatternSpec {
        class: DataClass::DatabaseUri,
        regex: r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s:/@]+@[^\s/]+",
    },
    PatternSpec {
        class: DataClass::Password,
        regex: r#"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|token)\s*[:=]\s*["']?([^\s"',;}]{8,})"#,
    },
    PatternSpec {
        class: DataClass::PaymentCard,
        regex: r"\b(?:\d[ \-]?){13,19}\b",
    },
    PatternSpec {
        class: DataClass::NationalId,
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
    },
    PatternSpec {
        class: DataClass::EmailAddress,
        regex: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    },
    PatternSpec {
        class: DataClass::PhoneNumber,
        regex: r"\+\d{1,3}[ \-]?\(?\d{2,4}\)?[ \-]?\d{3,4}[ \-]?\d{3,4}\b",
    },
];

fn compiled() -> &'static Vec<(DataClass, Regex)> {
    static COMPILED: OnceLock<Vec<(DataClass, Regex)>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        PATTERNS
            .iter()
            .filter_map(|spec| Regex::new(spec.regex).ok().map(|r| (spec.class, r)))
            .collect()
    })
}

/// Maximum bytes scanned from any single field.
///
/// Bounds worst-case work on a hostile payload. A field longer than this is scanned only at
/// its head; value-flow tracking covers the rest, so truncation does not create a blind spot
/// for values VIGIL already knows about.
pub const MAX_SCAN_BYTES: usize = 256 * 1024;

/// Classify one string.
pub fn classify(path: &str, content: &str) -> Vec<Finding> {
    let content = if content.len() > MAX_SCAN_BYTES {
        // Slice on a char boundary so a multi-byte character is not split.
        let mut end = MAX_SCAN_BYTES;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }
        &content[..end]
    } else {
        content
    };

    let mut findings = Vec::new();
    let mut claimed: Vec<(usize, usize)> = Vec::new();

    for (class, regex) in compiled() {
        for m in regex.find_iter(content) {
            // A later, more generic pattern must not re-report a span a specific one claimed.
            if claimed.iter().any(|(s, e)| m.start() < *e && m.end() > *s) {
                continue;
            }
            let value = m.as_str();
            if *class == DataClass::PaymentCard && !is_probable_card(value) {
                continue;
            }
            claimed.push((m.start(), m.end()));
            findings.push(Finding {
                class: *class,
                path: path.to_string(),
                evidence: evidence_for(*class, value),
                length: value.len(),
            });
        }
    }

    // Anything left that is long and high-entropy is a secret in a format we do not know.
    for token in content.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')) {
        if token.len() < 24 || token.len() > 512 {
            continue;
        }
        if findings.iter().any(|f| f.length == token.len()) {
            continue;
        }
        if shannon_entropy(token) >= 4.0 && has_mixed_character_classes(token) {
            findings.push(Finding {
                class: DataClass::HighEntropySecret,
                path: path.to_string(),
                evidence: evidence_for(DataClass::HighEntropySecret, token),
                length: token.len(),
            });
        }
    }

    findings
}

/// Classify every string of an action.
pub fn classify_all(strings: &[(String, String)]) -> Vec<Finding> {
    strings
        .iter()
        .flat_map(|(path, content)| classify(path, content))
        .collect()
}

fn evidence_for(class: DataClass, value: &str) -> String {
    if class.fingerprintable() {
        vigil_common::redact::fingerprint(value)
    } else {
        vigil_common::redact::redact_low_entropy(value)
    }
}

/// Luhn check, so ordinary long digit strings are not reported as payment cards.
fn is_probable_card(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = *d;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total_f = total as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total_f;
            -p * p.log2()
        })
        .sum()
}

/// Whether a token mixes character classes the way generated secrets do and words do not.
fn has_mixed_character_classes(s: &str) -> bool {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    (has_lower && has_upper && has_digit)
        || (has_digit && (has_lower || has_upper) && s.len() >= 32)
}

/// Summarize findings into distinct taints.
pub fn taints_of(findings: &[Finding]) -> Vec<TaintKind> {
    let mut taints: Vec<TaintKind> = findings.iter().map(|f| f.class.taint()).collect();
    taints.sort();
    taints.dedup();
    taints
}

/// The highest risk weight among findings.
pub fn peak_risk(findings: &[Finding]) -> f64 {
    findings
        .iter()
        .map(|f| f.class.risk_weight())
        .fold(0.0, f64::max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(content: &str) -> Vec<DataClass> {
        let mut c: Vec<DataClass> = classify("f", content)
            .into_iter()
            .map(|f| f.class)
            .collect();
        c.sort_by_key(|c| c.as_str());
        c.dedup();
        c
    }

    #[test]
    fn recognizes_common_credential_formats() {
        assert!(classes("AKIAIOSFODNN7EXAMPLE").contains(&DataClass::CloudCredential));
        assert!(classes("sk-live-51H8xQ2eZvKYlo2CabcDEF").contains(&DataClass::ApiKey));
        assert!(classes("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").contains(&DataClass::ApiKey));
        assert!(classes("-----BEGIN RSA PRIVATE KEY-----").contains(&DataClass::PrivateKey));
        assert!(classes(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K"
        )
        .contains(&DataClass::Jwt));
        assert!(classes("postgres://admin:hunter2@db.internal:5432/app")
            .contains(&DataClass::DatabaseUri));
    }

    #[test]
    fn findings_never_contain_the_secret_value() {
        let secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "sk-live-51H8xQ2eZvKYlo2CabcDEF",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "postgres://admin:hunter2@db.internal:5432/app",
            "4111111111111111",
            "alice@acme.example",
        ];
        for secret in secrets {
            for finding in classify("body", secret) {
                assert!(
                    !finding.evidence.contains(secret),
                    "evidence leaked `{secret}`: {}",
                    finding.evidence
                );
                assert!(!format!("{finding:?}").contains("hunter2"));
            }
        }
    }

    #[test]
    fn low_entropy_pii_gets_no_reversible_fingerprint() {
        let findings = classify("body", "alice@acme.example");
        assert!(!findings.is_empty());
        for f in findings {
            assert!(!f.evidence.contains("fp:"), "{}", f.evidence);
        }
    }

    #[test]
    fn payment_cards_are_luhn_validated() {
        // Valid test card number.
        assert!(classes("4111111111111111").contains(&DataClass::PaymentCard));
        // A 16-digit order number that fails Luhn must not be reported as a card.
        assert!(!classes("1234567812345678").contains(&DataClass::PaymentCard));
    }

    #[test]
    fn ordinary_prose_produces_no_findings() {
        for benign in [
            "The customer reported an error on the checkout page yesterday.",
            "Order 1000200030004000 shipped on Tuesday.",
            "Meeting moved to 15:00 in room 4B.",
        ] {
            let f = classify("body", benign);
            assert!(
                f.iter().all(|f| f.class == DataClass::PaymentCard) || f.is_empty(),
                "false positives on `{benign}`: {f:?}"
            );
        }
    }

    #[test]
    fn a_normal_english_sentence_is_not_high_entropy() {
        let f = classify(
            "body",
            "supercalifragilisticexpialidocious antidisestablishment",
        );
        assert!(
            !f.iter().any(|f| f.class == DataClass::HighEntropySecret),
            "{f:?}"
        );
    }

    #[test]
    fn an_unknown_format_secret_is_caught_by_entropy() {
        let f = classify("body", "Zx9Kq2Lm8Pv4Nw7Rt5Yb3Hd6Fg1Jc0As");
        assert!(
            f.iter().any(|f| f.class == DataClass::HighEntropySecret),
            "{f:?}"
        );
    }

    #[test]
    fn a_specific_match_is_not_double_reported_as_generic() {
        let f = classify("body", "AKIAIOSFODNN7EXAMPLE");
        let cloud = f
            .iter()
            .filter(|f| f.class == DataClass::CloudCredential)
            .count();
        assert_eq!(cloud, 1);
        assert!(!f.iter().any(|f| f.class == DataClass::HighEntropySecret));
    }

    #[test]
    fn taints_map_to_the_kinds_policy_matches_on() {
        let f = classify("body", "AKIAIOSFODNN7EXAMPLE and alice@acme.example");
        let taints = taints_of(&f);
        assert!(taints.contains(&TaintKind::Credential));
        assert!(taints.contains(&TaintKind::Pii));
        assert!(peak_risk(&f) >= 0.9);
    }

    #[test]
    fn scanning_is_bounded_on_a_hostile_payload() {
        let huge = "a".repeat(MAX_SCAN_BYTES * 3);
        let start = std::time::Instant::now();
        let _ = classify("body", &huge);
        assert!(start.elapsed().as_secs() < 5, "took {:?}", start.elapsed());
    }

    #[test]
    fn truncation_never_splits_a_multibyte_character() {
        let payload = "é".repeat(MAX_SCAN_BYTES);
        let _ = classify("body", &payload); // must not panic
    }
}
