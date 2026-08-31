//! The capability token wire format.
//!
//! ```text
//! vcap1.<base64url(header)>.<base64url(claims)>.<base64url(signature)>
//! ```
//!
//! The signature covers `<header>.<claims>` exactly as transmitted, so a verifier never has
//! to re-serialize before checking — re-serialization is where "signature valid but the
//! bytes I parsed differ from the bytes I verified" bugs come from.
//!
//! The header carries only `alg` and `kid`. It is unauthenticated until the signature
//! verifies, so nothing security-relevant beyond key selection may be read from it, and the
//! algorithm is checked against an allowlist rather than trusted — the `alg: none` family of
//! JWT vulnerabilities exists because that check was optional.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use vigil_common::{Result, VigilError};

/// Format marker. Bumped if the token layout ever changes.
pub const CAPABILITY_TOKEN_PREFIX: &str = "vcap1";

/// The only signature algorithm this build accepts.
pub const ALG_ED25519: &str = "Ed25519";

/// Maximum accepted token length, checked before any parsing.
///
/// Bounds the work an unauthenticated caller can make the gateway do.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Unauthenticated token header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenHeader {
    /// Signature algorithm. Verified against the allowlist, never trusted.
    pub alg: String,
    /// Which signing key was used, so keys can rotate without a flag day.
    pub kid: String,
}

/// A token split into its parts, with the exact signed bytes preserved.
#[derive(Debug)]
pub(crate) struct ParsedToken {
    pub header: TokenHeader,
    pub claims_json: Vec<u8>,
    pub signature: Vec<u8>,
    /// `<header_b64>.<claims_b64>` — the bytes that were actually signed.
    pub signed_payload: Vec<u8>,
}

/// Encode a signed token.
pub(crate) fn encode(header: &TokenHeader, claims_json: &[u8], signature: &[u8]) -> Result<String> {
    let header_json = serde_json::to_vec(header)?;
    Ok(format!(
        "{CAPABILITY_TOKEN_PREFIX}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header_json),
        URL_SAFE_NO_PAD.encode(claims_json),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// The bytes to sign for a given header and claims encoding.
pub(crate) fn signing_input(header_b64: &str, claims_b64: &str) -> Vec<u8> {
    format!("{header_b64}.{claims_b64}").into_bytes()
}

/// Split and decode a token without verifying anything.
pub(crate) fn parse(token: &str) -> Result<ParsedToken> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(VigilError::CapabilityRejected(
            "capability token exceeds maximum length".to_string(),
        ));
    }
    let mut parts = token.split('.');
    let (Some(prefix), Some(header_b64), Some(claims_b64), Some(sig_b64), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(VigilError::CapabilityRejected(
            "capability token is malformed".to_string(),
        ));
    };
    if prefix != CAPABILITY_TOKEN_PREFIX {
        return Err(VigilError::CapabilityRejected(format!(
            "unsupported capability token format `{}`",
            // The prefix is attacker-controlled; bound it before it reaches a log.
            vigil_common::redact::single_line_excerpt(prefix, 16)
        )));
    }

    let decode = |part: &str, what: &'static str| -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(part).map_err(|_| {
            VigilError::CapabilityRejected(format!("capability token {what} is not base64url"))
        })
    };

    let header_bytes = decode(header_b64, "header")?;
    let header: TokenHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        VigilError::CapabilityRejected("capability token header is not valid JSON".to_string())
    })?;

    Ok(ParsedToken {
        header,
        claims_json: decode(claims_b64, "claims")?,
        signature: decode(sig_b64, "signature")?,
        signed_payload: signing_input(header_b64, claims_b64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> TokenHeader {
        TokenHeader {
            alg: ALG_ED25519.to_string(),
            kid: "k1".to_string(),
        }
    }

    #[test]
    fn tokens_round_trip() {
        let t = encode(&header(), b"{\"a\":1}", &[7u8; 64]).unwrap();
        let p = parse(&t).unwrap();
        assert_eq!(p.header, header());
        assert_eq!(p.claims_json, b"{\"a\":1}");
        assert_eq!(p.signature, vec![7u8; 64]);
    }

    #[test]
    fn the_signed_payload_is_the_transmitted_bytes_not_a_reserialization() {
        let t = encode(&header(), b"{\"b\":2,\"a\":1}", &[0u8; 64]).unwrap();
        let p = parse(&t).unwrap();
        let expected: Vec<&str> = t.splitn(4, '.').collect();
        assert_eq!(
            p.signed_payload,
            format!("{}.{}", expected[1], expected[2]).into_bytes()
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_rather_than_partially_parsed() {
        for bad in [
            "",
            "vcap1",
            "vcap1.a.b",
            "vcap1.a.b.c.d",
            "jwt.a.b.c",
            "vcap1.!!!.b.c",
            "vcap1.aGk.b.c", // header decodes but is not JSON
        ] {
            assert!(parse(bad).is_err(), "`{bad}` should not parse");
        }
    }

    #[test]
    fn oversized_tokens_are_rejected_before_decoding() {
        let huge = format!("vcap1.{}.{}.{}", "A".repeat(9000), "A", "A");
        let err = parse(&huge).unwrap_err();
        assert!(err.to_string().contains("maximum length"));
    }

    #[test]
    fn an_attacker_controlled_prefix_cannot_flood_or_forge_a_log_line() {
        let hostile = format!("{}.a.b.c", "X\n\rFAKE ".repeat(40));
        let err = parse(&hostile).unwrap_err().to_string();
        assert!(!err.contains('\n') && !err.contains('\r'));
        assert!(err.len() < 120, "error was {} chars", err.len());
    }
}
