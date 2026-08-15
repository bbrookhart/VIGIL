//! Identity types.
//!
//! # Why
//!
//! "Who is doing this?" has at least five distinct answers in an agentic system, and
//! collapsing them into one `user` field destroys the ability to reason about delegation.
//! When Agent B acts on work delegated by Agent A on behalf of user U, authorization depends
//! on all three, and the audit record is meaningless without all three (Invariant 8, 9).
//!
//! # What
//!
//! * [`Principal`] — the human or service on whose behalf work happens.
//! * [`WorkloadIdentity`] — the cryptographically attested compute identity (SPIFFE), which
//!   answers "is this really the agent process we registered?" rather than "who asked?".
//! * [`TraceContext`] — W3C-compatible correlation, so a decision joins to the OpenTelemetry
//!   span that produced it.

use serde::{Deserialize, Serialize};
use vigil_common::ids::{AgentId, AgentInstanceId, PrincipalId, TenantId};

/// What kind of principal is behind a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// An authenticated human.
    Human,
    /// A service account acting without a human in the loop (batch, cron).
    Service,
    /// An agent acting for itself, e.g. a scheduled autonomous agent.
    Agent,
    /// Authentication was not established. Treated as the lowest privilege available.
    Anonymous,
}

impl PrincipalKind {
    /// Whether a human can be held accountable for this request.
    ///
    /// Approval flows require this: an unattended service principal cannot satisfy a
    /// human-approval obligation.
    pub fn is_accountable_human(&self) -> bool {
        matches!(self, Self::Human)
    }
}

/// The principal on whose behalf an action is requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub tenant_id: TenantId,
    /// Roles as asserted by the identity provider, used by policy. Never self-asserted by
    /// the agent: the SDK cannot set these, they are populated from the verified token.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Authentication method, e.g. `oidc`, `mtls`, `api_key`. Policy may require a stronger
    /// method for high-impact actions.
    #[serde(default)]
    pub auth_method: Option<String>,
    /// Whether the identity provider asserted multi-factor authentication.
    #[serde(default)]
    pub mfa: bool,
}

impl Principal {
    pub fn new(id: PrincipalId, kind: PrincipalKind, tenant_id: TenantId) -> Self {
        Self {
            id,
            kind,
            tenant_id,
            roles: Vec::new(),
            auth_method: None,
            mfa: false,
        }
    }

    pub fn with_roles(mut self, roles: impl IntoIterator<Item = String>) -> Self {
        self.roles = roles.into_iter().collect();
        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// A cryptographically attested workload identity (SPIFFE ID or equivalent).
///
/// This is what makes agent identity non-forgeable: an attacker who can post JSON to Core
/// can claim any `agent_id`, but cannot present a valid mTLS peer certificate for it.
///
/// # The `verified` flag is not deserializable
///
/// [`Self::verified`] carries `#[serde(skip_deserializing)]`, so it is **always `false`** when
/// this type is parsed from a request body. That is deliberate and load-bearing: without it,
/// a caller could simply post `{"verified": true}` and satisfy Protected Mode's identity
/// requirement, which would reduce workload identity from a cryptographic claim to a
/// self-assertion.
///
/// The only way to obtain a verified identity is
/// [`WorkloadIdentity::attested`], which the API layer calls after establishing the identity
/// from the transport (an mTLS peer certificate, a SPIFFE SVID, a reviewed service-account
/// token). This mirrors how the Gateway builds its `PresentedAction` from the request it
/// actually received rather than from the token that accompanies it: the trusted value can
/// only come from the trusted source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    /// e.g. `spiffe://vigil.example/ns/agents/sa/support-assistant`
    pub id: String,
    /// How the identity was established: `mtls`, `spire`, `k8s_sa_token`, `dev_shared_secret`.
    pub attestation_method: String,
    /// True only when the identity was verified by this process from a cryptographic proof.
    ///
    /// Never populated by deserialization — see the type-level documentation. The pipeline
    /// treats an unverified workload identity as absent; it is carried anyway so audit
    /// records show what was *claimed* alongside what was *proven*.
    #[serde(skip_deserializing)]
    pub verified: bool,
}

impl WorkloadIdentity {
    /// The identity of an agent that has proven nothing. Used in Observability Mode.
    pub fn unverified(claimed: impl Into<String>) -> Self {
        Self {
            id: claimed.into(),
            attestation_method: "self_asserted".to_string(),
            verified: false,
        }
    }

    /// Construct a *verified* identity from a proof established by this process.
    ///
    /// Call sites are the authentication boundary and nowhere else. `attestation_method`
    /// should name how the proof was obtained (`mtls`, `spire`, `k8s_sa_token`) so an audit
    /// record shows not just that the identity was proven but how.
    pub fn attested(id: impl Into<String>, attestation_method: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            attestation_method: attestation_method.into(),
            verified: true,
        }
    }

    /// Whether this identity may satisfy Protected Mode's requirement.
    pub fn is_verified(&self) -> bool {
        self.verified
    }
}

/// W3C trace correlation, so security decisions line up with application traces.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TraceContext {
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub span_id: Option<String>,
    #[serde(default)]
    pub parent_span_id: Option<String>,
}

/// The agent identity triple that scopes budgets, remit and behavioural state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// The registered agent definition, which owns the remit.
    pub agent_id: AgentId,
    /// This particular run. Budgets and drift envelopes are per-instance.
    pub agent_instance_id: AgentInstanceId,
    /// Version of the remit this instance started under. Pinned for the instance's lifetime
    /// so a mid-session remit edit cannot retroactively legitimize earlier behaviour.
    pub remit_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn only_humans_can_satisfy_human_approval() {
        assert!(PrincipalKind::Human.is_accountable_human());
        assert!(!PrincipalKind::Service.is_accountable_human());
        assert!(!PrincipalKind::Agent.is_accountable_human());
        assert!(!PrincipalKind::Anonymous.is_accountable_human());
    }

    #[test]
    fn self_asserted_workload_identity_is_marked_unverified() {
        let w = WorkloadIdentity::unverified("spiffe://evil/ns/admin");
        assert!(!w.verified);
    }

    #[test]
    fn a_request_body_cannot_assert_that_it_is_verified() {
        // The whole point of the type. Without `skip_deserializing`, this payload would
        // satisfy Protected Mode's workload-identity requirement over plain HTTP.
        let forged = r#"{
            "id": "spiffe://vigil.example/ns/agents/sa/admin",
            "attestation_method": "mtls",
            "verified": true
        }"#;
        let parsed: WorkloadIdentity = serde_json::from_str(forged).unwrap();
        assert!(
            !parsed.verified,
            "a body-supplied `verified` flag must never survive deserialization"
        );
        assert!(!parsed.is_verified());
        // The claim itself is retained, so the audit record can show what was asserted.
        assert_eq!(parsed.id, "spiffe://vigil.example/ns/agents/sa/admin");
    }

    #[test]
    fn only_an_attested_identity_is_verified() {
        let attested = WorkloadIdentity::attested("spiffe://vigil.example/ns/a/sa/b", "mtls");
        assert!(attested.is_verified());
        assert_eq!(attested.attestation_method, "mtls");
    }

    #[test]
    fn a_verified_identity_still_serializes_its_flag_for_audit_records() {
        // Serialization keeps the field: an audit record must be able to show that the
        // identity behind a decision was proven. Only the *inbound* direction is blocked.
        let json =
            serde_json::to_string(&WorkloadIdentity::attested("spiffe://x", "mtls")).unwrap();
        assert!(json.contains("\"verified\":true"), "{json}");
    }

    #[test]
    fn a_round_trip_through_the_wire_downgrades_a_verified_identity() {
        // Consequence worth pinning: verification does not survive a serialize/deserialize
        // hop, so an intermediary cannot launder a verified identity onward. Anything that
        // needs it re-establishes it from its own transport.
        let attested = WorkloadIdentity::attested("spiffe://x", "mtls");
        let round_tripped: WorkloadIdentity =
            serde_json::from_str(&serde_json::to_string(&attested).unwrap()).unwrap();
        assert!(!round_tripped.verified);
    }

    #[test]
    fn principal_serialization_round_trips() {
        let p = Principal::new(
            PrincipalId::from_str("u-42").unwrap(),
            PrincipalKind::Human,
            TenantId::from_str("acme").unwrap(),
        )
        .with_roles(["support-agent".to_string()]);
        let json = serde_json::to_string(&p).unwrap();
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert!(back.has_role("support-agent"));
    }
}
