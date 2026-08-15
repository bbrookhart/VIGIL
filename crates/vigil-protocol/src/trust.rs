//! Trust labels, provenance references, and taint kinds.
//!
//! # Why
//!
//! Invariant 3: external content cannot grant authority. That invariant is only enforceable
//! if every piece of content entering an agent's context carries where it came from. A model
//! sees a retrieved web page and a system prompt as the same kind of token sequence; VIGIL
//! must not.
//!
//! # What
//!
//! [`TrustLevel`] is a *total order* of authority. The ordering is the mechanism: when
//! content from several sources combines, the result takes the **minimum** trust of its
//! inputs ([`TrustLevel::combine`]). Trust therefore only ever flows downward, which is what
//! makes Invariant 4 ("trust cannot self-escalate") structural rather than a rule someone has
//! to remember to check.

use serde::{Deserialize, Serialize};
use std::fmt;
use vigil_common::ids::ProvenanceNodeId;

/// Where a piece of content came from, and therefore how much authority it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustLevel {
    /// VIGIL's own configuration and the application's system prompt. Highest authority.
    SystemTrusted,
    /// Content authored by an administrator through an authenticated control-plane path.
    AdminTrusted,
    /// A tool binary/manifest whose signature verified against a trusted key.
    ToolSigned,
    /// Memory content that passed validation when it was written.
    MemoryValidated,
    /// Direct input from the authenticated end user of this session.
    UserAuthenticated,
    /// Input attributed to a user but not authenticated (e.g. an unauthenticated widget).
    UserUntrusted,
    /// A tool whose identity or manifest could not be verified.
    ToolUnverified,
    /// Memory content with no validation record, including anything written by an agent.
    MemoryUntrusted,
    /// Output of another agent.
    AgentUntrusted,
    /// A response from an MCP server.
    McpUntrusted,
    /// Content returned by a retrieval/RAG system.
    RagUntrusted,
    /// Email bodies, headers and attachments.
    EmailUntrusted,
    /// Fetched web content.
    WebUntrusted,
    /// Any other external source. Lowest authority; the safe default.
    ExternalUntrusted,
}

impl TrustLevel {
    /// Position in the authority order. Higher is more trusted.
    ///
    /// Gaps are intentional so new labels can be inserted without renumbering, which would
    /// change the meaning of historical audit records.
    pub fn rank(&self) -> u8 {
        match self {
            Self::SystemTrusted => 100,
            Self::AdminTrusted => 90,
            Self::ToolSigned => 70,
            Self::MemoryValidated => 60,
            Self::UserAuthenticated => 50,
            Self::UserUntrusted => 30,
            Self::ToolUnverified => 25,
            Self::MemoryUntrusted => 20,
            Self::AgentUntrusted => 18,
            Self::McpUntrusted => 15,
            Self::RagUntrusted => 12,
            Self::EmailUntrusted => 10,
            Self::WebUntrusted => 8,
            Self::ExternalUntrusted => 0,
        }
    }

    /// Combine two trust levels. The result is always the *lower* of the two.
    ///
    /// This is the whole trust model in one function: content derived from a trusted prompt
    /// and an untrusted web page is untrusted. There is deliberately no operation that
    /// raises trust — promotion requires an explicit, separately authorized action recorded
    /// as an [`TrustLevel::AdminTrusted`] event, never an inference inside the data path.
    pub fn combine(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// Whether instructions found in content with this label may influence privileged action.
    ///
    /// Below [`TrustLevel::UserAuthenticated`], the answer is no: such content is data.
    pub fn carries_instruction_authority(&self) -> bool {
        self.rank() >= Self::UserAuthenticated.rank()
    }

    /// Whether this label denotes content that crossed a trust boundary from outside.
    pub fn is_external(&self) -> bool {
        matches!(
            self,
            Self::ExternalUntrusted
                | Self::WebUntrusted
                | Self::EmailUntrusted
                | Self::RagUntrusted
                | Self::McpUntrusted
                | Self::AgentUntrusted
        )
    }

    /// The label to assume when a source is unknown.
    pub const fn conservative_default() -> Self {
        Self::ExternalUntrusted
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_string(self).unwrap_or_else(|_| "\"UNKNOWN\"".to_string());
        f.write_str(s.trim_matches('"'))
    }
}

/// A reference to a node in the session's provenance graph.
///
/// Events carry references, not content: the content lives once in the trace store, and
/// evidence points at it. This keeps attacker payloads from being duplicated into every
/// downstream record (see `docs/architecture/evidence.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRef {
    pub node_id: ProvenanceNodeId,
    pub trust_level: TrustLevel,
    /// Human-meaningful origin, already redacted: `web:https://example.com/a`, `mcp:mail/send`.
    pub origin: String,
    /// Hash of the content at this node, so evidence can be verified without storing it here.
    pub content_hash: Option<vigil_common::ContentHash>,
}

/// Categories of sensitive or dangerous data that propagate through a session.
///
/// Taint answers a different question from trust. Trust asks "may this content command the
/// agent?"; taint asks "what would it mean for this content to leave?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintKind {
    /// Text from an untrusted source that reads as a directive to the agent.
    UntrustedInstruction,
    /// A high-entropy secret: API key, token, private key.
    Secret,
    /// A credential pair or authentication material.
    Credential,
    /// Personally identifiable information.
    Pii,
    /// Financial data: card numbers, account numbers, balances.
    FinancialData,
    /// Authentication artifacts: OTPs, session cookies, MFA codes.
    AuthenticationData,
    /// Data marked confidential by tenant classification.
    ConfidentialData,
    /// Content that would be executed if it reached an interpreter.
    ExecutableContent,
    /// A URL pointing outside the trust boundary.
    ExternalUrl,
    /// Source code or scripts from an untrusted origin.
    UntrustedCode,
    /// Text that purports to be security policy.
    SecurityPolicyContent,
    /// Data belonging to an approval transaction.
    ApprovalData,
}

impl TaintKind {
    /// Whether this taint leaving the trust boundary is, by itself, a reportable event.
    pub fn is_egress_sensitive(&self) -> bool {
        matches!(
            self,
            Self::Secret
                | Self::Credential
                | Self::Pii
                | Self::FinancialData
                | Self::AuthenticationData
                | Self::ConfidentialData
        )
    }

    /// Severity weight fed into the composite risk engine.
    pub fn risk_weight(&self) -> f64 {
        match self {
            Self::Secret | Self::Credential | Self::AuthenticationData => 1.0,
            Self::FinancialData => 0.9,
            Self::Pii => 0.7,
            Self::ConfidentialData => 0.6,
            Self::UntrustedInstruction => 0.5,
            Self::UntrustedCode | Self::ExecutableContent => 0.5,
            Self::SecurityPolicyContent => 0.4,
            Self::ApprovalData => 0.3,
            Self::ExternalUrl => 0.2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combining_trust_never_raises_it() {
        let cases = [
            TrustLevel::SystemTrusted,
            TrustLevel::UserAuthenticated,
            TrustLevel::WebUntrusted,
            TrustLevel::ExternalUntrusted,
        ];
        for a in cases {
            for b in cases {
                let c = a.combine(b);
                assert!(
                    c.rank() <= a.rank() && c.rank() <= b.rank(),
                    "{a:?} + {b:?} = {c:?} escalated"
                );
            }
        }
    }

    #[test]
    fn combining_is_commutative_and_idempotent() {
        let a = TrustLevel::RagUntrusted;
        let b = TrustLevel::AdminTrusted;
        assert_eq!(a.combine(b), b.combine(a));
        assert_eq!(a.combine(a), a);
    }

    #[test]
    fn system_prompt_plus_web_page_is_web_grade_authority() {
        let mixed = TrustLevel::SystemTrusted.combine(TrustLevel::WebUntrusted);
        assert_eq!(mixed, TrustLevel::WebUntrusted);
        assert!(!mixed.carries_instruction_authority());
    }

    #[test]
    fn only_user_authenticated_and_above_can_instruct() {
        assert!(TrustLevel::UserAuthenticated.carries_instruction_authority());
        assert!(TrustLevel::SystemTrusted.carries_instruction_authority());
        assert!(!TrustLevel::UserUntrusted.carries_instruction_authority());
        assert!(!TrustLevel::McpUntrusted.carries_instruction_authority());
        assert!(!TrustLevel::MemoryUntrusted.carries_instruction_authority());
    }

    #[test]
    fn the_default_is_the_least_trusted_label() {
        let d = TrustLevel::conservative_default();
        for level in [
            TrustLevel::SystemTrusted,
            TrustLevel::WebUntrusted,
            TrustLevel::AgentUntrusted,
        ] {
            assert!(d.rank() <= level.rank());
        }
    }

    #[test]
    fn trust_labels_serialize_as_documented_screaming_snake() {
        assert_eq!(
            serde_json::to_string(&TrustLevel::WebUntrusted).unwrap(),
            "\"WEB_UNTRUSTED\""
        );
        assert_eq!(TrustLevel::WebUntrusted.to_string(), "WEB_UNTRUSTED");
    }

    #[test]
    fn secret_taint_outranks_url_taint_for_risk() {
        assert!(TaintKind::Secret.risk_weight() > TaintKind::ExternalUrl.risk_weight());
        assert!(TaintKind::Secret.is_egress_sensitive());
        assert!(!TaintKind::ExternalUrl.is_egress_sensitive());
    }
}
