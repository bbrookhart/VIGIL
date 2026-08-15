//! The gateway's HTTP surface.
//!
//! One route that matters: `POST /v1/execute`. The capability travels in a header rather than
//! the body so it cannot be confused with the action being authorized, and so the action body
//! that gets hashed is exactly the action body — nothing about the token participates in it.
//!
//! # Authentication
//!
//! The route is authenticated, and a capability alone is not sufficient. A capability is a
//! bearer token for the seconds it lives; if one leaks, anything holding it could redeem it.
//! Requiring the presenter to *be* the agent the capability names means theft now also
//! requires stealing an SVID and its private key.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use vigil_identity::{Authenticator, VerifiedIdentity};
use vigil_protocol::ActionRequest;

use crate::Gateway;

/// URI SANs from a verified client certificate, inserted by the TLS acceptor.
#[derive(Debug, Clone, Default)]
pub struct PeerIdentity(pub Vec<String>);

/// Header carrying the execution capability.
pub const CAPABILITY_HEADER: &str = "x-vigil-capability";

#[derive(Clone)]
pub struct GatewayState {
    pub gateway: Arc<Gateway>,
    pub authenticator: Arc<dyn Authenticator>,
}

pub fn router(state: GatewayState) -> Router {
    // The health probe sits outside the authenticated layer: a load balancer cannot present
    // a workload identity, and the probe exposes nothing.
    let authenticated =
        Router::new()
            .route("/v1/execute", post(execute))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ));

    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .merge(authenticated)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Establish the caller's identity, or reject with 401.
async fn auth_middleware(
    State(state): State<GatewayState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<PeerIdentity>()
        .cloned()
        .unwrap_or_default();
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
            tracing::debug!(error = %error, "gateway authentication failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(ExecuteResponse {
                    executed: false,
                    output: None,
                    refusal_reason: Some(error.class().to_string()),
                    detail: "authentication failed".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    pub detail: String,
}

async fn execute(
    State(state): State<GatewayState>,
    Extension(caller): Extension<VerifiedIdentity>,
    headers: HeaderMap,
    Json(request): Json<ActionRequest>,
) -> Response {
    let capability = headers
        .get(CAPABILITY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match state
        .gateway
        .execute_as(&request, capability.as_deref(), Some(&caller))
        .await
    {
        Ok(result) => {
            // A refusal is a 403, not a 200 with a flag: a client that ignores the body must
            // still fail, and a proxy or SIEM in between must be able to see the refusal
            // without parsing JSON.
            let status = if result.executed {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            (
                status,
                Json(ExecuteResponse {
                    executed: result.executed,
                    output: result.output,
                    refusal_reason: result.refusal.map(|r| r.to_string()),
                    detail: vigil_common::redact::single_line_excerpt(&result.detail, 300),
                }),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(error = %error, "gateway execution failed");
            (
                StatusCode::from_u16(error.http_status())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(ExecuteResponse {
                    executed: false,
                    output: None,
                    refusal_reason: Some(error.class().to_string()),
                    detail: "the request could not be processed".to_string(),
                }),
            )
                .into_response()
        }
    }
}
