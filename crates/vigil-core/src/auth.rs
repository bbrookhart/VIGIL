//! Binding a request to an authenticated caller.
//!
//! # Why
//!
//! Before this module existed, [`crate::pipeline::DecisionPipeline::decide`] accepted a bare
//! [`ActionRequest`] and read `workload_identity.verified` out of it — a boolean that arrived
//! in the request body. In process that was harmless, because the only caller was trusted
//! code. Over HTTP it was an authentication bypass: post `{"verified": true}` and Protected
//! Mode's identity requirement is satisfied.
//!
//! The fix is the one the codebase already applies twice. `CapabilityIssuer` holds a private
//! key and `CapabilityVerifier` holds only public keys, so a compromised Gateway cannot mint
//! capabilities. The Gateway builds `PresentedAction` from the request body it actually
//! received rather than from the token, so a client cannot describe its own authorization.
//! Both work because **the trusted value can only come from the trusted source**, and the
//! type system is what enforces "only".
//!
//! # What
//!
//! [`AuthenticatedRequest`] pairs a request with a [`VerifiedIdentity`] from
//! [`vigil_identity`], and its constructor is private. The only routes to one are
//! [`CoreAuthenticator::authenticate_request`], [`CoreAuthenticator::bind_verified`], and an
//! explicitly-named in-process constructor. The pipeline accepts nothing else, so "decide
//! without authenticating" is not a call that can be written.
//!
//! # Failure mode
//!
//! Authentication failure returns [`VigilError::Unauthenticated`] and no decision is made.
//! A caller whose proof disagrees with what its body claims returns
//! [`VigilError::Unauthorized`] — proving you are agent A does not let you act as agent B.
//!
//! # Evidence
//!
//! `crates/vigil-core/tests/authentication.rs`.

use async_trait::async_trait;
use std::collections::HashMap;
use vigil_common::{Result, VigilError};
use vigil_protocol::principal::{PrincipalKind, WorkloadIdentity};
use vigil_protocol::ActionRequest;

pub use vigil_identity::{
    Authenticator, CallerKind, MtlsSpiffeAuthenticator, SharedSecretAuthenticator, VerifiedIdentity,
};

/// A request whose caller has been authenticated.
///
/// The private fields are the mechanism: outside this module, the only ways to obtain one are
/// the [`CoreAuthenticator`] methods and [`Self::for_trusted_in_process_caller`].
#[derive(Debug, Clone)]
pub struct AuthenticatedRequest {
    request: ActionRequest,
    identity: VerifiedIdentity,
}

impl AuthenticatedRequest {
    /// The request, with its workload identity replaced by the *proven* one.
    pub fn request(&self) -> &ActionRequest {
        &self.request
    }

    pub fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }

    /// Construct without authenticating, for in-process callers already inside the trust
    /// boundary: the end-to-end tests and the `demo` example.
    ///
    /// Named at length on purpose. A reviewer scanning a diff should notice it immediately,
    /// and it should be impossible to reach for by accident while writing a handler. It is
    /// never called from `api.rs`, and `tests/authentication.rs` asserts that by reading the
    /// file.
    pub fn for_trusted_in_process_caller(request: ActionRequest) -> Self {
        let identity = VerifiedIdentity {
            // The attestation method records honestly that no cryptographic proof happened,
            // so an audit record never implies more assurance than there was.
            workload: WorkloadIdentity::attested(
                format!("in-process:{}", request.agent_id),
                "in_process_trusted_caller",
            ),
            tenant_id: request.tenant_id.clone(),
            agent_id: Some(request.agent_id.clone()),
            principal_id: Some(request.principal.id.clone()),
            roles: request.principal.roles.clone(),
            kind: CallerKind::Agent,
        };
        Self::bind(request, identity)
    }

    /// Pair a request with a proven identity, overwriting whatever the body claimed.
    fn bind(mut request: ActionRequest, identity: VerifiedIdentity) -> Self {
        // The proven identity replaces the claimed one outright. Merging them would leave a
        // body-supplied `id` next to a `verified: true` this process set, which is exactly
        // the confusion this module exists to prevent.
        request.workload_identity = Some(identity.workload.clone());
        Self { request, identity }
    }

    /// Check that what the body claims matches what the caller proved.
    ///
    /// A verified workload may only act as the agent and tenant its identity names. This is
    /// the control against an authenticated-but-impersonating caller.
    pub fn check_claims_match_proof(&self) -> Result<()> {
        if self.request.tenant_id != self.identity.tenant_id {
            return Err(VigilError::Unauthorized(format!(
                "caller is authenticated for tenant `{}` but submitted a request for another",
                self.identity.tenant_id
            )));
        }
        if let Some(proven_agent) = &self.identity.agent_id {
            if &self.request.agent_id != proven_agent {
                return Err(VigilError::Unauthorized(format!(
                    "caller is authenticated as agent `{proven_agent}` but submitted a request \
                     as another agent"
                )));
            }
        }
        if self.identity.kind == CallerKind::Human
            && self.request.principal.kind != PrincipalKind::Human
        {
            return Err(VigilError::Unauthorized(
                "a human caller may not submit a request on behalf of a non-human principal"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// The Core-side extension of [`Authenticator`]: turning a proven identity into an
/// [`AuthenticatedRequest`].
///
/// A blanket implementation over every `Authenticator`, so adding an authentication method
/// requires implementing only the shared trait while the binding logic — and the invariant
/// that binding always re-checks the claims — stays in one place.
#[async_trait]
pub trait CoreAuthenticator: Authenticator {
    /// Authenticate and bind in one step.
    async fn authenticate_request(
        &self,
        request: ActionRequest,
        headers: &HashMap<String, String>,
        peer_uri_sans: &[String],
    ) -> Result<AuthenticatedRequest> {
        let identity = self.authenticate(headers, peer_uri_sans).await?;
        self.bind_verified(request, identity)
    }

    /// Bind a request to an identity already established by this authenticator.
    ///
    /// The HTTP layer authenticates once in middleware and binds in the handler, so it needs
    /// the two halves separately.
    fn bind_verified(
        &self,
        request: ActionRequest,
        identity: VerifiedIdentity,
    ) -> Result<AuthenticatedRequest> {
        let authenticated = AuthenticatedRequest::bind(request, identity);
        authenticated.check_claims_match_proof()?;
        Ok(authenticated)
    }
}

impl<T: Authenticator + ?Sized> CoreAuthenticator for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_protocol::action::{Action, ToolCall, ToolProtocol};
    use vigil_protocol::principal::Principal;

    fn request(tenant: &str, agent: &str) -> ActionRequest {
        ActionRequest {
            schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
            request_id: vigil_common::ids::EventId::new_random(),
            occurred_at: chrono::Utc::now(),
            tenant_id: tenant.parse().unwrap(),
            environment_id: "prod".parse().unwrap(),
            session_id: "s-1".parse().unwrap(),
            agent_id: agent.parse().unwrap(),
            agent_instance_id: "i-1".parse().unwrap(),
            principal: Principal::new(
                "user-1".parse().unwrap(),
                PrincipalKind::Human,
                tenant.parse().unwrap(),
            ),
            workload_identity: None,
            trace: Default::default(),
            action: Action::ToolCall(ToolCall {
                protocol: ToolProtocol::Native,
                server: None,
                tool_id: "t".parse().unwrap(),
                name: "t".to_string(),
                version: None,
                operation: Some("read".to_string()),
                arguments: serde_json::json!({}),
                target_resource: None,
                declared_side_effect: None,
            }),
            context: Default::default(),
        }
    }

    fn spiffe() -> MtlsSpiffeAuthenticator {
        MtlsSpiffeAuthenticator::new().register_agent(
            "spiffe://vigil.test/ns/agents/sa/support",
            "acme".parse().unwrap(),
            "support".parse().unwrap(),
        )
    }

    const SUPPORT_SVID: &str = "spiffe://vigil.test/ns/agents/sa/support";

    #[tokio::test]
    async fn a_registered_workload_can_bind_a_request() {
        let authenticated = spiffe()
            .authenticate_request(
                request("acme", "support"),
                &HashMap::new(),
                &[SUPPORT_SVID.to_string()],
            )
            .await
            .expect("registered workload authenticates");
        assert!(authenticated.identity().workload.is_verified());
    }

    #[tokio::test]
    async fn the_proven_identity_overwrites_whatever_the_body_claimed() {
        let mut req = request("acme", "support");
        req.workload_identity = Some(WorkloadIdentity::unverified("spiffe://evil/ns/admin"));

        let authenticated = spiffe()
            .authenticate_request(req, &HashMap::new(), &[SUPPORT_SVID.to_string()])
            .await
            .unwrap();

        let carried = authenticated.request().workload_identity.as_ref().unwrap();
        assert_eq!(carried.id, SUPPORT_SVID);
        assert!(carried.verified);
    }

    #[tokio::test]
    async fn an_authenticated_agent_cannot_act_as_a_different_agent() {
        let err = spiffe()
            .authenticate_request(
                request("acme", "finance-agent"),
                &HashMap::new(),
                &[SUPPORT_SVID.to_string()],
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("as another agent"), "{err}");
    }

    #[tokio::test]
    async fn an_authenticated_agent_cannot_act_for_a_different_tenant() {
        let err = spiffe()
            .authenticate_request(
                request("other-corp", "support"),
                &HashMap::new(),
                &[SUPPORT_SVID.to_string()],
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("another"), "{err}");
    }

    #[test]
    fn the_in_process_constructor_records_that_no_proof_occurred() {
        let authenticated =
            AuthenticatedRequest::for_trusted_in_process_caller(request("acme", "support"));
        assert!(authenticated.identity().workload.is_verified());
        assert_eq!(
            authenticated.identity().workload.attestation_method,
            "in_process_trusted_caller",
            "the audit record must not imply a cryptographic proof that did not happen"
        );
    }
}
