//! Redaction and evidence fingerprinting.
//!
//! # Why
//!
//! A security product that logs the secret it caught has exfiltrated it into a lower-trust
//! store — often one with broader access than the system the secret belonged to. But an
//! analyst still has to answer "is the value the agent tried to send the same one that is
//! in our vault?" Fingerprints answer that question without moving the value.
//!
//! # What
//!
//! * [`redact`] replaces a value with its length and a truncated fingerprint.
//! * [`fingerprint`] produces a stable, comparable, non-reversible token for a value.
//! * [`redact_url`] strips userinfo and query values, which routinely carry tokens.
//!
//! # Assumptions
//!
//! Fingerprints are unsalted SHA-256 prefixes, so they are comparable across events and
//! across deployments — that comparability is the point. They are therefore *not* safe for
//! low-entropy values: an attacker with the audit log can confirm a guess of a 4-digit PIN.
//! Callers classifying low-entropy sensitive data (PII, card suffixes) must use
//! [`redact_low_entropy`], which emits no fingerprint at all.

use sha2::{Digest, Sha256};

/// Number of hex characters retained from a fingerprint digest.
const FINGERPRINT_HEX_LEN: usize = 16;

/// A non-reversible, comparable token for a sensitive value.
///
/// 16 hex characters is 64 bits — ample to make accidental collision between distinct
/// secrets in one investigation negligible, while too short to meaningfully assist an
/// offline attack on a high-entropy secret.
pub fn fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("fp:{}", &hex::encode(digest)[..FINGERPRINT_HEX_LEN])
}

/// Replace a sensitive value with safe evidence about it.
pub fn redact(value: &str) -> String {
    format!("[redacted len={} {}]", value.len(), fingerprint(value))
}

/// Replace a low-entropy sensitive value (PII, account suffixes) with evidence that
/// carries no fingerprint, because a fingerprint of a guessable value is reversible.
pub fn redact_low_entropy(value: &str) -> String {
    format!("[redacted len={}]", value.len())
}

/// Redact the parts of a URL that routinely carry credentials, keeping the parts a
/// detection engineer needs: scheme, host, port and path shape.
///
/// Query *keys* are retained because they are frequently the signal (`?token=`), while
/// values are always removed.
pub fn redact_url(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "[unparsable-url]".to_string();
    };
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Strip userinfo: anything before the last '@' in the authority.
    let host = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => format!("[redacted-userinfo]@{host}"),
        None => authority.to_string(),
    };
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };
    let rendered = match query {
        None => format!("{scheme}://{host}{path}"),
        Some(q) => {
            let keys: Vec<String> = q
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|pair| match pair.split_once('=') {
                    Some((k, _)) => format!("{k}=[redacted]"),
                    None => format!("{pair}=[redacted]"),
                })
                .collect();
            format!("{scheme}://{host}{path}?{}", keys.join("&"))
        }
    };

    // Control characters survive URL parsing, and a redacted URL is written into log lines,
    // detector evidence and audit records. Without this a URL containing a newline forges a
    // second log entry — found by `fuzz/fuzz_targets/network_analyze.rs`, which asserts that
    // no finding string carries a raw newline.
    //
    // Bounded as well as stripped: the host and path are attacker-chosen and otherwise
    // unbounded in length.
    single_line_excerpt(&rendered, MAX_REDACTED_URL_CHARS)
}

/// Longest redacted URL retained for evidence.
const MAX_REDACTED_URL_CHARS: usize = 200;

/// Truncate untrusted text for display, marking that truncation happened.
///
/// Detector evidence should reference canonical stored content rather than duplicate
/// attacker payloads; where a short excerpt genuinely aids triage, it goes through here so
/// a hostile payload cannot flood a log or a console cell.
pub fn excerpt(value: &str, max_chars: usize) -> String {
    let mut out: String = value.chars().take(max_chars).collect();
    if value.chars().nth(max_chars).is_some() {
        out.push_str("…[truncated]");
    }
    // Control characters in an excerpt can forge log structure or move a terminal cursor.
    // Newlines survive here because console evidence panes render multi-line content; see
    // `single_line_excerpt` for contexts where a newline is itself the attack.
    out.chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                '␦'
            } else {
                c
            }
        })
        .collect()
}

/// Truncate untrusted text for embedding in a *single-line* context: an error message, a
/// structured-log field, a metrics label.
///
/// Strips newlines as well as other control characters. A newline in a log line lets untrusted
/// input forge additional log entries, which is how an attacker makes a rejection look like an
/// approval to whatever parses the log downstream.
pub fn single_line_excerpt(value: &str, max_chars: usize) -> String {
    excerpt(value, max_chars)
        .chars()
        .map(|c| if c.is_control() { '␦' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_never_contains_the_original_value() {
        let secret = "sk-live-51H8xQ2eZvKYlo2C";
        let r = redact(secret);
        assert!(!r.contains(secret));
        assert!(!r.contains("51H8xQ2eZvKYlo2C"));
        assert!(r.contains("len=24"));
    }

    #[test]
    fn fingerprints_are_stable_and_distinguishing() {
        assert_eq!(fingerprint("abc"), fingerprint("abc"));
        assert_ne!(fingerprint("abc"), fingerprint("abd"));
    }

    #[test]
    fn low_entropy_redaction_emits_no_fingerprint() {
        let r = redact_low_entropy("4111111111111111");
        assert!(!r.contains("fp:"));
    }

    #[test]
    fn url_redaction_removes_credentials_and_query_values() {
        let r = redact_url("https://user:pass@api.example.com/v1/send?token=abc123&to=x");
        assert!(!r.contains("pass"));
        assert!(!r.contains("abc123"));
        assert!(r.contains("api.example.com"));
        assert!(r.contains("/v1/send"));
        assert!(r.contains("token=[redacted]"));
    }

    #[test]
    fn a_url_containing_control_characters_cannot_forge_a_log_line() {
        // Found by fuzzing. A redacted URL is written into logs, detector evidence and audit
        // records; a newline in it produces a second, attacker-authored log entry.
        let hostile = "https://evil.example/a\nlevel=info msg=\"approved\"";
        let redacted = redact_url(hostile);
        assert!(!redacted.contains('\n'), "{redacted}");
        assert!(!redacted.contains('\r'));
        assert!(
            redacted.contains("evil.example"),
            "the host must survive: {redacted}"
        );
    }

    #[test]
    fn a_redacted_url_is_bounded_in_length() {
        let huge = format!("https://evil.example/{}", "a".repeat(10_000));
        assert!(redact_url(&huge).chars().count() < 250);
    }

    #[test]
    fn url_redaction_handles_urls_without_path_or_query() {
        assert_eq!(redact_url("https://example.com"), "https://example.com");
        assert_eq!(redact_url("not a url"), "[unparsable-url]");
    }

    #[test]
    fn single_line_excerpts_cannot_forge_a_second_log_line() {
        let hostile = "ok\nlevel=info msg=\"approved\"";
        let e = single_line_excerpt(hostile, 100);
        assert!(!e.contains('\n'));
        assert!(!e.contains('\r'));
        // The multi-line variant intentionally keeps newlines, which is why the two exist.
        assert!(excerpt(hostile, 100).contains('\n'));
    }

    #[test]
    fn excerpts_are_bounded_and_strip_control_characters() {
        let hostile = format!("ignore previous\r\x1b[2Jfake-log-line{}", "A".repeat(500));
        let e = excerpt(&hostile, 40);
        assert!(e.chars().count() <= 40 + "…[truncated]".chars().count());
        assert!(!e.contains('\r'));
        assert!(!e.contains('\u{1b}'));
    }
}
