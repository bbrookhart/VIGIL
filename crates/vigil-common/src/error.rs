//! Structured errors.
//!
//! Security errors are never stringly-typed: callers in the enforcement path must be able
//! to branch on *why* something failed (a malformed request is a client bug; a policy
//! backend outage is a fail-closed condition) without parsing messages.

use std::fmt;

pub type Result<T> = std::result::Result<T, VigilError>;

/// Every failure mode that can arise inside a VIGIL component.
///
/// The `Display` text of these variants is safe to return to a remote caller: it never
/// embeds secrets, raw untrusted payloads, or cross-tenant identifiers. Detail that is
/// useful only to operators belongs in the `tracing` span, not here.
#[derive(Debug, thiserror::Error)]
pub enum VigilError {
    /// The request did not satisfy its schema. Deterministically a client error.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// A value was structurally valid but semantically unusable (bad id charset, etc).
    #[error("invalid value for {field}: {reason}")]
    InvalidValue { field: &'static str, reason: String },

    /// Serialization or canonicalization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The caller could not be authenticated.
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),

    /// The caller was authenticated but is not permitted to do this.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// A capability, approval or token failed verification.
    #[error("capability rejected: {0}")]
    CapabilityRejected(String),

    /// A policy bundle could not be compiled or evaluated.
    #[error("policy error: {0}")]
    Policy(String),

    /// A remit definition could not be compiled or evaluated.
    #[error("remit error: {0}")]
    Remit(String),

    /// A detector failed. Callers MUST treat this as a risk signal, never as an allow.
    #[error("detector `{detector}` failed: {reason}")]
    Detector { detector: String, reason: String },

    /// A dependency in the enforcement path timed out.
    #[error("`{component}` timed out after {elapsed_ms}ms")]
    Timeout {
        component: &'static str,
        elapsed_ms: u64,
    },

    /// A dependency in the enforcement path is unavailable.
    #[error("`{component}` unavailable: {reason}")]
    Unavailable {
        component: &'static str,
        reason: String,
    },

    /// Tamper-evident storage failed an integrity check.
    #[error("audit integrity failure: {0}")]
    AuditIntegrity(String),

    /// A resource was not found. Note this is deliberately not tenant-revealing.
    #[error("not found: {0}")]
    NotFound(String),

    /// A budget or rate limit was exhausted.
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),

    /// I/O failure.
    #[error("io error: {0}")]
    Io(String),

    /// Configuration is invalid; the process should refuse to start.
    #[error("configuration error: {0}")]
    Config(String),
}

impl VigilError {
    /// Machine-readable class, used for metrics labels and reason codes.
    ///
    /// Kept low-cardinality on purpose: these become Prometheus label values.
    pub fn class(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) | Self::InvalidValue { .. } => "invalid_request",
            Self::Serialization(_) => "serialization",
            Self::Unauthenticated(_) => "unauthenticated",
            Self::Unauthorized(_) => "unauthorized",
            Self::CapabilityRejected(_) => "capability_rejected",
            Self::Policy(_) => "policy",
            Self::Remit(_) => "remit",
            Self::Detector { .. } => "detector",
            Self::Timeout { .. } => "timeout",
            Self::Unavailable { .. } => "unavailable",
            Self::AuditIntegrity(_) => "audit_integrity",
            Self::NotFound(_) => "not_found",
            Self::BudgetExhausted(_) => "budget_exhausted",
            Self::Io(_) => "io",
            Self::Config(_) => "config",
        }
    }

    /// Whether this failure indicates a degraded *dependency* rather than a bad request.
    ///
    /// The decision pipeline uses this to pick fail-closed vs degraded-mode behaviour
    /// (see `docs/architecture/failure-modes.md`). A bad request is always rejected; a
    /// degraded dependency is resolved against the action's configured failure policy.
    pub fn is_dependency_failure(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::Unavailable { .. } | Self::Detector { .. }
        )
    }

    /// HTTP status this error should surface as.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) | Self::InvalidValue { .. } | Self::Serialization(_) => 400,
            Self::Unauthenticated(_) => 401,
            Self::Unauthorized(_) | Self::CapabilityRejected(_) => 403,
            Self::NotFound(_) => 404,
            Self::BudgetExhausted(_) => 429,
            Self::Timeout { .. } => 504,
            Self::Unavailable { .. } => 503,
            _ => 500,
        }
    }
}

impl From<serde_json::Error> for VigilError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<serde_yaml_ng::Error> for VigilError {
    fn from(e: serde_yaml_ng::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for VigilError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// A redacted wrapper used when an error must reference a value that may be sensitive.
pub struct Sanitized<'a>(pub &'a str);

impl fmt::Display for Sanitized<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", crate::redact::redact(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_failures_are_distinguished_from_client_errors() {
        assert!(VigilError::Timeout {
            component: "policy",
            elapsed_ms: 10
        }
        .is_dependency_failure());
        assert!(!VigilError::InvalidRequest("x".into()).is_dependency_failure());
    }

    #[test]
    fn error_display_never_echoes_raw_input_for_sanitized_values() {
        let e = VigilError::InvalidValue {
            field: "token",
            reason: Sanitized("sk-live-abcdefghijklmnop").to_string(),
        };
        let rendered = e.to_string();
        assert!(!rendered.contains("abcdefghijklmnop"), "{rendered}");
    }
}
