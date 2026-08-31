//! Caller authentication for VIGIL.
//!
//! # Why
//!
//! Core and Gateway both need to answer "who is calling?", and both must answer it from
//! *transport evidence* rather than from the request body. They are otherwise independent —
//! Core decides and holds a signing key, Gateway executes and holds tool credentials, and
//! neither depends on the other. That independence is a security property (spec §57), so the
//! shared answer to the identity question lives here rather than in either of them.
//!
//! # What
//!
//! [`VerifiedIdentity`] is an identity this process established and can vouch for. It is
//! deliberately **not** `Deserialize`: it cannot arrive over the wire, only be produced by an
//! [`Authenticator`] from a verified mTLS peer certificate, a SPIFFE SVID, or a reviewed
//! service-account token.
//!
//! # Assumptions
//!
//! This crate consumes transport evidence; it does not terminate TLS. The server binary
//! configures rustls with client-certificate verification and passes the resulting URI SANs
//! in. Behind a terminating proxy, the proxy is the authenticator and must strip any
//! client-supplied identity headers.
//!
//! # Failure mode
//!
//! Every ambiguity is a rejection. No certificate, an unregistered SPIFFE ID, or an unknown
//! token all produce [`VigilError::Unauthenticated`] and no identity.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use async_trait::async_trait;
use std::collections::HashMap;
use vigil_common::ids::{AgentId, PrincipalId, TenantId};
use vigil_common::{Result, VigilError};
use vigil_protocol::principal::WorkloadIdentity;

/// What kind of caller proved its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    /// A protected agent workload. May request decisions and execute actions.
    Agent,
    /// A human operating the console. May grant approvals; may not request decisions.
    Human,
    /// An internal VIGIL component, e.g. the Gateway reporting execution back to Core.
    Service,
}

/// An identity this process established from a cryptographic proof.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// The attested workload identity, e.g. a SPIFFE ID. Always verified.
    pub workload: WorkloadIdentity,
    /// The tenant this caller belongs to, taken from the proof — never from a request body.
    pub tenant_id: TenantId,
    /// The agent this workload runs, for agent callers.
    pub agent_id: Option<AgentId>,
    /// The principal, for human callers.
    pub principal_id: Option<PrincipalId>,
    /// Roles asserted by the identity provider. Used for approval authorization.
    pub roles: Vec<String>,
    pub kind: CallerKind,
}

impl VerifiedIdentity {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn is_human(&self) -> bool {
        self.kind == CallerKind::Human
    }

    pub fn is_agent(&self) -> bool {
        self.kind == CallerKind::Agent
    }
}

/// Establishes caller identity from transport evidence.
#[async_trait]
pub trait Authenticator: Send + Sync + std::fmt::Debug {
    /// Identify the caller, or fail.
    ///
    /// `peer_uri_sans` carries the URI SANs from a verified mTLS client certificate, which is
    /// where a SPIFFE ID lives. `headers` carries bearer tokens for providers that use them.
    /// An implementation must not derive identity from the request *body*.
    async fn authenticate(
        &self,
        headers: &HashMap<String, String>,
        peer_uri_sans: &[String],
    ) -> Result<VerifiedIdentity>;

    /// Name of the method, for readiness output and audit records.
    fn method(&self) -> &'static str;
}

/// Authenticates from a SPIFFE ID presented in a verified mTLS client certificate.
///
/// The Kubernetes path: SPIRE (or cert-manager) issues an SVID to the agent's pod, the TLS
/// listener verifies the chain, and this maps the resulting URI SAN onto a tenant and agent.
///
/// The mapping is **explicit registration, not string parsing**. Deriving a tenant by
/// splitting a SPIFFE path would mean anyone holding a valid SVID from the trust domain could
/// choose their tenant by choosing a workload name — turning a namespace convention into an
/// authorization decision.
#[derive(Debug, Default)]
pub struct MtlsSpiffeAuthenticator {
    registrations: HashMap<String, VerifiedIdentity>,
}

impl MtlsSpiffeAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a SPIFFE ID as belonging to an agent in a tenant.
    pub fn register_agent(
        mut self,
        spiffe_id: impl Into<String>,
        tenant_id: TenantId,
        agent_id: AgentId,
    ) -> Self {
        let spiffe_id = spiffe_id.into();
        self.registrations.insert(
            spiffe_id.clone(),
            VerifiedIdentity {
                workload: WorkloadIdentity::attested(spiffe_id, "mtls_spiffe"),
                tenant_id,
                agent_id: Some(agent_id),
                principal_id: None,
                roles: Vec::new(),
                kind: CallerKind::Agent,
            },
        );
        self
    }

    /// Register a SPIFFE ID as a human operator (the console), with approval roles.
    pub fn register_human(
        mut self,
        spiffe_id: impl Into<String>,
        tenant_id: TenantId,
        principal_id: PrincipalId,
        roles: Vec<String>,
    ) -> Self {
        let spiffe_id = spiffe_id.into();
        self.registrations.insert(
            spiffe_id.clone(),
            VerifiedIdentity {
                workload: WorkloadIdentity::attested(spiffe_id, "mtls_spiffe"),
                tenant_id,
                agent_id: None,
                principal_id: Some(principal_id),
                roles,
                kind: CallerKind::Human,
            },
        );
        self
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

#[async_trait]
impl Authenticator for MtlsSpiffeAuthenticator {
    async fn authenticate(
        &self,
        _headers: &HashMap<String, String>,
        peer_uri_sans: &[String],
    ) -> Result<VerifiedIdentity> {
        if peer_uri_sans.is_empty() {
            return Err(VigilError::Unauthenticated(
                "no client certificate was presented".to_string(),
            ));
        }
        for san in peer_uri_sans {
            if let Some(identity) = self.registrations.get(san) {
                return Ok(identity.clone());
            }
        }
        Err(VigilError::Unauthenticated(format!(
            "no registration for the presented workload identity `{}`",
            vigil_common::redact::single_line_excerpt(
                peer_uri_sans.first().map(String::as_str).unwrap_or(""),
                80
            )
        )))
    }

    fn method(&self) -> &'static str {
        "mtls_spiffe"
    }
}

/// A shared-secret authenticator for local development.
///
/// [`Self::new`] refuses to construct one for Protected Mode in a release build. Development
/// convenience that silently becomes production authentication is how deployments end up with
/// no authentication at all, and a warning in a log is not a control.
#[derive(Debug)]
pub struct SharedSecretAuthenticator {
    tokens: HashMap<String, VerifiedIdentity>,
}

impl SharedSecretAuthenticator {
    /// Construct, refusing when this would be an unsafe configuration.
    pub fn new(protected_mode: bool) -> Result<Self> {
        if protected_mode && !cfg!(debug_assertions) {
            return Err(VigilError::Config(
                "SharedSecretAuthenticator is a development-only authenticator and cannot be \
                 used in Protected Mode in a release build; configure mTLS/SPIFFE instead"
                    .to_string(),
            ));
        }
        Ok(Self {
            tokens: HashMap::new(),
        })
    }

    pub fn register(mut self, token: impl Into<String>, identity: VerifiedIdentity) -> Self {
        self.tokens.insert(token.into(), identity);
        self
    }
}

#[async_trait]
impl Authenticator for SharedSecretAuthenticator {
    async fn authenticate(
        &self,
        headers: &HashMap<String, String>,
        _peer_uri_sans: &[String],
    ) -> Result<VerifiedIdentity> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                VigilError::Unauthenticated("no bearer token was presented".to_string())
            })?;

        // The failure must not reveal which registered token was closest.
        self.tokens
            .get(token)
            .cloned()
            .ok_or_else(|| VigilError::Unauthenticated("unrecognized token".to_string()))
    }

    fn method(&self) -> &'static str {
        "dev_shared_secret"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spiffe() -> MtlsSpiffeAuthenticator {
        MtlsSpiffeAuthenticator::new().register_agent(
            "spiffe://vigil.test/ns/agents/sa/support",
            "acme".parse().unwrap(),
            "support".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn a_registered_svid_yields_a_verified_identity() {
        let identity = spiffe()
            .authenticate(
                &HashMap::new(),
                &["spiffe://vigil.test/ns/agents/sa/support".to_string()],
            )
            .await
            .unwrap();
        assert!(identity.workload.is_verified());
        assert_eq!(identity.tenant_id.as_str(), "acme");
        assert!(identity.is_agent());
    }

    #[tokio::test]
    async fn presenting_no_certificate_fails() {
        let err = spiffe()
            .authenticate(&HashMap::new(), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, VigilError::Unauthenticated(_)), "{err}");
    }

    #[tokio::test]
    async fn an_unregistered_svid_fails_even_though_its_certificate_is_valid() {
        // The distinction that matters: a valid SVID from the trust domain is not
        // authorization. Only a registered one maps to an identity.
        let err = spiffe()
            .authenticate(
                &HashMap::new(),
                &["spiffe://vigil.test/ns/agents/sa/attacker".to_string()],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, VigilError::Unauthenticated(_)), "{err}");
    }

    #[tokio::test]
    async fn the_rejection_message_is_bounded_and_single_line() {
        let hostile = format!("spiffe://{}\nFORGED", "a".repeat(500));
        let err = spiffe()
            .authenticate(&HashMap::new(), &[hostile])
            .await
            .unwrap_err()
            .to_string();
        assert!(!err.contains('\n'));
        assert!(err.len() < 200, "{}", err.len());
    }

    #[test]
    fn the_dev_authenticator_refuses_protected_mode_in_a_release_build() {
        let result = SharedSecretAuthenticator::new(true);
        if cfg!(debug_assertions) {
            assert!(result.is_ok(), "development builds may use it");
        } else {
            assert!(result.is_err(), "release builds must refuse it");
        }
        assert!(SharedSecretAuthenticator::new(false).is_ok());
    }

    #[tokio::test]
    async fn the_dev_authenticator_requires_a_known_token() {
        let identity = VerifiedIdentity {
            workload: WorkloadIdentity::attested("dev:agent", "dev_shared_secret"),
            tenant_id: "acme".parse().unwrap(),
            agent_id: Some("support".parse().unwrap()),
            principal_id: None,
            roles: vec![],
            kind: CallerKind::Agent,
        };
        let auth = SharedSecretAuthenticator::new(false)
            .unwrap()
            .register("s3cret", identity);

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer wrong".to_string());
        assert!(auth.authenticate(&headers, &[]).await.is_err());

        headers.insert("authorization".to_string(), "Bearer s3cret".to_string());
        assert!(auth.authenticate(&headers, &[]).await.is_ok());
    }

    #[tokio::test]
    async fn a_missing_authorization_header_fails() {
        let auth = SharedSecretAuthenticator::new(false).unwrap();
        assert!(auth.authenticate(&HashMap::new(), &[]).await.is_err());
    }
}
