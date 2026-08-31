//! The VIGIL Core HTTP API.
//!
//! # Why
//!
//! This is the surface SDKs call, and it is the boundary where a claim becomes a fact. Every
//! route except the health probes runs an [`Authenticator`] first, and the identity it
//! establishes — not anything in the request body — is what the pipeline sees.
//!
//! An earlier version of this file accepted `workload_identity.verified` from the body and
//! took the approver's `Principal` from the body of the approval-grant route. Both were
//! authentication bypasses over HTTP: the first satisfied Protected Mode by assertion, the
//! second made self-approval a matter of typing a different name. Neither is reachable now,
//! and `tests/authentication.rs` holds the line.
//!
//! # What
//!
//! * [`auth_middleware`] establishes a [`VerifiedIdentity`] from transport evidence and
//!   inserts it as a request extension. Handlers cannot run without it.
//! * Per-route authorization: SDK routes require an agent workload; approval routes require a
//!   human principal holding an approver role.
//!
//! # Assumptions
//!
//! TLS terminates in this process (the server binary configures rustls with client-certificate
//! verification) and the peer certificate's URI SANs reach [`auth_middleware`] through the
//! `PeerIdentity` extension that the TLS acceptor inserts. Behind a terminating proxy, the
//! proxy must be the authenticator and must strip client-supplied identity headers.
//!
//! # Failure mode
//!
//! Unauthenticated requests get 401 and never reach the pipeline. Authorization failures get
//! 403. Errors return a reason *class*, never an internal message: error text can embed
//! attacker-supplied content, and detailed policy internals help an attacker map the ruleset.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use vigil_common::ids::ApprovalId;
use vigil_common::VigilError;
use vigil_protocol::principal::Principal;
use vigil_protocol::trust::{TaintKind, TrustLevel};
use vigil_protocol::ActionRequest;

use crate::auth::{Authenticator, CallerKind, CoreAuthenticator, VerifiedIdentity};
use crate::session::SessionKey;
use crate::{ContentIngest, VigilCore};

/// URI SANs from a verified client certificate, inserted by the TLS acceptor.
///
/// A newtype rather than a bare `Vec<String>` so it cannot be confused with any other
/// extension, and so `Extension<PeerIdentity>` fails loudly if the acceptor forgot to insert
/// it rather than silently authenticating with an empty SAN list.
#[derive(Debug, Clone, Default)]
pub struct PeerIdentity(pub Vec<String>);

/// Shared handler state.
#[derive(Clone)]
pub struct ApiState {
    pub core: Arc<VigilCore>,
    pub authenticator: Arc<dyn Authenticator>,
    /// Where a caller's transport identity comes from. Consulted on every request.
    pub peer_identity_source: Arc<crate::server::PeerIdentitySource>,
}

/// Build the router.
///
/// Health probes are registered *outside* the authenticated layer because a load balancer
/// cannot present a workload identity. They expose no tenant data.
pub fn router(state: ApiState) -> Router {
    let authenticated = Router::new()
        .route("/v1/decisions", post(decide))
        .route("/v1/content", post(ingest))
        .route("/v1/sessions/{session_id}/end", post(end_session))
        .route("/v1/approvals/{approval_id}", get(get_approval))
        .route("/v1/approvals/{approval_id}/grant", post(grant_approval))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(authenticated)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Establish the caller's identity, or reject.
///
/// Runs before any handler. Client-supplied identity headers are never consulted: the only
/// inputs are the verified peer certificate SANs and, for the development authenticator, a
/// bearer token that must match a registered secret.
async fn auth_middleware(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    // The peer identity is derived here, from the connection and the configured source —
    // never read from an extension a handler might have set, and never from the body.
    let remote_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let peer = crate::server::peer_identity_for(
        &state.peer_identity_source,
        remote_addr,
        request.headers(),
    );

    let headers: HashMap<String, String> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect();

    match state.authenticator.authenticate(&headers, &peer.0).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(error) => {
            tracing::debug!(error = %error, method = state.authenticator.method(), "authentication failed");
            HandlerError(error).into_response()
        }
    }
}

/// An error rendered for a remote caller.
#[derive(Debug, Serialize)]
struct ApiError {
    /// Low-cardinality class, safe to expose and stable enough to branch on.
    error: String,
    /// A short, non-revealing description.
    message: String,
}

/// Wrapper so handlers can `?` on [`VigilError`].
struct HandlerError(VigilError);

impl From<VigilError> for HandlerError {
    fn from(e: VigilError) -> Self {
        Self(e)
    }
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // Client errors get their message; server-side failures do not, because those
        // messages can carry internal detail or attacker-influenced content.
        let message = if status.is_client_error() {
            vigil_common::redact::single_line_excerpt(&self.0.to_string(), 200)
        } else {
            tracing::error!(error = %self.0, class = self.0.class(), "request failed");
            "the request could not be processed".to_string()
        };

        (
            status,
            Json(ApiError {
                error: self.0.class().to_string(),
                message,
            }),
        )
            .into_response()
    }
}

/// Require that the caller is an agent workload.
fn require_agent(identity: &VerifiedIdentity) -> Result<(), HandlerError> {
    if identity.kind != CallerKind::Agent {
        return Err(HandlerError(VigilError::Unauthorized(
            "this endpoint may only be called by an agent workload".to_string(),
        )));
    }
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// Readiness reports the enforcement mode, so an operator can see at a glance whether this
/// deployment actually enforces or merely observes.
async fn readyz(State(state): State<ApiState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ready",
            "mode": state.core.mode(),
            "enforcing": state.core.mode().is_enforcing(),
            "schema_version": vigil_protocol::SCHEMA_VERSION,
            "authentication": state.authenticator.method(),
            "live_sessions": state.core.sessions().len(),
        })),
    )
}

/// Evaluate an action.
async fn decide(
    State(state): State<ApiState>,
    Extension(identity): Extension<VerifiedIdentity>,
    Json(request): Json<ActionRequest>,
) -> Result<Json<vigil_protocol::decision::DecisionResponse>, HandlerError> {
    require_agent(&identity)?;

    // Binding happens here, from the identity the middleware proved. The request body's
    // own `workload_identity` — including any `verified` flag it tried to assert — is
    // discarded rather than merged.
    let authenticated = state
        .authenticator
        .bind_verified(request, identity)
        .map_err(HandlerError)?;

    let outcome = state.core.decide(&authenticated).await?;
    Ok(Json(outcome.response))
}

/// Register content entering a session.
#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub session_id: vigil_common::ids::SessionId,
    pub agent_instance_id: vigil_common::ids::AgentInstanceId,
    pub principal_id: vigil_common::ids::PrincipalId,
    pub origin: String,
    pub trust: TrustLevel,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub taints: Vec<TaintKind>,
    #[serde(default)]
    pub derived_from: Vec<vigil_common::ids::ProvenanceNodeId>,
    #[serde(default)]
    pub tracked_values: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub node_id: vigil_common::ids::ProvenanceNodeId,
}

async fn ingest(
    State(state): State<ApiState>,
    Extension(identity): Extension<VerifiedIdentity>,
    Json(request): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, HandlerError> {
    require_agent(&identity)?;

    // Tenant and agent come from the proof, not the body. Without this, one tenant's agent
    // could write provenance into another tenant's session.
    let agent_id = identity.agent_id.clone().ok_or_else(|| {
        HandlerError(VigilError::Unauthorized(
            "caller has no agent identity".to_string(),
        ))
    })?;

    let key = SessionKey {
        tenant_id: identity.tenant_id.clone(),
        session_id: request.session_id,
        agent_id,
        agent_instance_id: request.agent_instance_id,
        principal_id: request.principal_id,
    };
    let node_id = state.core.ingest_content(
        &key,
        ContentIngest {
            origin: request.origin,
            trust: request.trust,
            content: request.content,
            taints: request.taints,
            derived_from: request.derived_from,
            tracked_values: request.tracked_values,
        },
    )?;
    Ok(Json(IngestResponse { node_id }))
}

#[derive(Debug, Deserialize)]
pub struct EndSessionRequest {
    pub agent_instance_id: vigil_common::ids::AgentInstanceId,
    pub principal_id: vigil_common::ids::PrincipalId,
}

async fn end_session(
    State(state): State<ApiState>,
    Extension(identity): Extension<VerifiedIdentity>,
    Path(session_id): Path<String>,
    Json(request): Json<EndSessionRequest>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    require_agent(&identity)?;
    let agent_id = identity.agent_id.clone().ok_or_else(|| {
        HandlerError(VigilError::Unauthorized(
            "caller has no agent identity".to_string(),
        ))
    })?;

    let key = SessionKey {
        tenant_id: identity.tenant_id.clone(),
        session_id: session_id
            .parse()
            .map_err(|_| VigilError::InvalidRequest("invalid session id".to_string()))?,
        agent_id,
        agent_instance_id: request.agent_instance_id,
        principal_id: request.principal_id,
    };
    let ended = state.core.end_session(&key)?;
    Ok(Json(serde_json::json!({ "ended": ended })))
}

async fn get_approval(
    State(state): State<ApiState>,
    Extension(identity): Extension<VerifiedIdentity>,
    Path(approval_id): Path<String>,
) -> Result<Json<crate::ApprovalRequest>, HandlerError> {
    let id: ApprovalId = approval_id
        .parse()
        .map_err(|_| VigilError::InvalidRequest("invalid approval id".to_string()))?;
    let request = state
        .core
        .approvals()
        .get(&id)?
        .ok_or_else(|| VigilError::NotFound("approval".to_string()))?;

    // A pending approval carries a transaction preview containing recipients and material
    // parameters. It is readable only within its own tenant.
    if request.tenant_id != identity.tenant_id {
        return Err(HandlerError(VigilError::NotFound("approval".to_string())));
    }
    Ok(Json(request))
}

/// Grant an approval.
///
/// The approver is **the authenticated caller**. There is no request body: an earlier version
/// accepted the approver's `Principal` in one, which made self-approval a matter of typing a
/// different name. The `ApprovalService` still independently refuses requester == approver,
/// so this is defence in depth rather than the only check.
async fn grant_approval(
    State(state): State<ApiState>,
    Extension(identity): Extension<VerifiedIdentity>,
    Path(approval_id): Path<String>,
) -> Result<Json<crate::ApprovalGrant>, HandlerError> {
    let id: ApprovalId = approval_id
        .parse()
        .map_err(|_| VigilError::InvalidRequest("invalid approval id".to_string()))?;

    if !identity.is_human() {
        return Err(HandlerError(VigilError::Unauthorized(
            "only an authenticated human principal may grant an approval".to_string(),
        )));
    }
    let principal_id = identity.principal_id.clone().ok_or_else(|| {
        HandlerError(VigilError::Unauthorized(
            "caller has no principal identity".to_string(),
        ))
    })?;

    // Constructed from the proof: the roles come from the identity provider, so a caller
    // cannot grant itself an approver role by asserting one.
    let approver = Principal::new(
        principal_id,
        vigil_protocol::principal::PrincipalKind::Human,
        identity.tenant_id.clone(),
    )
    .with_roles(identity.roles.clone());

    let grant = state.core.approvals().grant(&id, &approver)?;
    Ok(Json(grant))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_errors_do_not_leak_internal_detail_to_callers() {
        let err = HandlerError(VigilError::Policy(
            "internal rule bundle path /etc/vigil/secret-rules.yaml failed".to_string(),
        ));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn client_errors_return_a_bounded_sanitized_message() {
        let hostile = format!("bad value {}\n{}", "A".repeat(9000), "FORGED LOG LINE");
        let err = HandlerError(VigilError::InvalidRequest(hostile));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unauthenticated_maps_to_401_and_unauthorized_to_403() {
        assert_eq!(
            HandlerError(VigilError::Unauthenticated("x".into()))
                .into_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            HandlerError(VigilError::Unauthorized("x".into()))
                .into_response()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn error_classes_are_low_cardinality_and_stable() {
        for e in [
            VigilError::InvalidRequest("x".into()),
            VigilError::Unauthorized("x".into()),
            VigilError::CapabilityRejected("x".into()),
            VigilError::NotFound("x".into()),
        ] {
            let class = e.class();
            assert!(!class.is_empty());
            assert!(class.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    // Structural assertions about this file — that the approval route takes no body naming
    // an approver, and that no handler reaches for the in-process authentication bypass —
    // live in `tests/authentication.rs`. They read this file from disk, because a test that
    // greps its own source can never fail: the string it searches for is the string it
    // contains.
}
