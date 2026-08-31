//! Serving VIGIL Core.
//!
//! # Why
//!
//! Until this module existed, `api.rs` defined a `Router` that nothing ever bound a listener
//! to. There was no deployable artifact: VIGIL ran in tests and in the demo, in-process,
//! where the caller is trusted code. Everything the threat model says about network callers
//! was untested because there were no network callers.
//!
//! # What
//!
//! Configuration loading, the listener, caller-identity extraction, and graceful shutdown.
//!
//! # Assumptions
//!
//! [`PeerIdentitySource`] decides where a caller's proven identity comes from, and the
//! choice is explicit in configuration because it is a trust decision:
//!
//! * [`PeerIdentitySource::None`] — no transport identity. Only usable with an authenticator
//!   that does not need one (the development shared-secret authenticator).
//! * [`PeerIdentitySource::TrustedProxy`] — a service mesh terminates mTLS and forwards the
//!   peer's SPIFFE ID in a header. Accepted **only** from configured peer addresses, because
//!   a header anyone can set is not an identity.
//!
//! Native TLS termination with in-process client-certificate verification is not implemented
//! (see `docs/architecture/README.md`); on Kubernetes the mesh path is the deployed one, and
//! the NetworkPolicy — not the transport — is what makes VIGIL unbypassable.
//!
//! # Failure mode
//!
//! A configuration that would silently weaken authentication is rejected at startup rather
//! than warned about. `TrustedProxy` with an empty peer list, or the development
//! authenticator in a release Protected-Mode build, both refuse to start.

use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use vigil_common::{Result, VigilError};
use vigil_identity::{Authenticator, MtlsSpiffeAuthenticator, SharedSecretAuthenticator};

use crate::api::{ApiState, PeerIdentity};
use crate::config::{CoreConfig, EnforcementMode};

/// Where a caller's proven identity comes from.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerIdentitySource {
    /// No transport identity is available.
    None,
    /// A service mesh or reverse proxy terminated mTLS and forwards the verified peer
    /// identity in a header.
    ///
    /// `trusted_peers` is mandatory and must be non-empty: the header is only honoured when
    /// the immediate connection comes from one of these addresses. Without that, any client
    /// could set the header and choose its own identity — which is the bug this whole
    /// authentication effort exists to remove, reintroduced one layer up.
    TrustedProxy {
        /// Header carrying the peer's SPIFFE ID, e.g. `x-forwarded-client-cert`.
        header: String,
        /// Addresses permitted to assert that header.
        trusted_peers: Vec<IpAddr>,
    },
}

/// How callers authenticate.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthConfig {
    /// Map SPIFFE IDs to agents and humans by explicit registration.
    MtlsSpiffe { registrations: Vec<Registration> },
    /// Development only. Refused in a release build running Protected Mode.
    DevSharedSecret { tokens: Vec<DevToken> },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub spiffe_id: String,
    pub tenant_id: String,
    /// Present for agent workloads.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Present for human operators.
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevToken {
    pub token: String,
    pub tenant_id: String,
    pub agent_id: String,
}

/// Everything the server needs beyond [`CoreConfig`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub core: CoreConfig,
    pub auth: AuthConfig,
    #[serde(default = "default_peer_source")]
    pub peer_identity: PeerIdentitySource,
    /// Directories the policy bundles, remits and tool manifests load from.
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
    #[serde(default = "default_remit_dir")]
    pub remit_dir: String,
    #[serde(default = "default_manifest_file")]
    pub manifest_file: String,
    /// How often to evict abandoned sessions and checkpoint the audit chain, in seconds.
    #[serde(default = "default_maintenance_interval")]
    pub maintenance_interval_seconds: u64,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:8080"
        .parse()
        .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 8080)))
}
fn default_peer_source() -> PeerIdentitySource {
    PeerIdentitySource::None
}
fn default_policy_dir() -> String {
    "policies".to_string()
}
fn default_remit_dir() -> String {
    "policies/remits".to_string()
}
fn default_manifest_file() -> String {
    "policies/tools/manifests.yaml".to_string()
}
fn default_maintenance_interval() -> u64 {
    60
}

impl ServerConfig {
    pub fn from_yaml(src: &str) -> Result<Self> {
        let config: Self = serde_yaml_ng::from_str(src)
            .map_err(|e| VigilError::Config(format!("server config is not valid: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| VigilError::Config(format!("{}: {e}", path.display())))?;
        Self::from_yaml(&src)
    }

    /// Reject configurations that would silently weaken authentication.
    pub fn validate(&self) -> Result<()> {
        self.core.validate()?;

        if let PeerIdentitySource::TrustedProxy { trusted_peers, .. } = &self.peer_identity {
            if trusted_peers.is_empty() {
                return Err(VigilError::Config(
                    "peer_identity.trusted_peers must not be empty: an identity header that any \
                     client may set is not an identity"
                        .to_string(),
                ));
            }
        }

        if matches!(self.auth, AuthConfig::DevSharedSecret { .. }) {
            // Constructing the authenticator performs the same check; doing it here means a
            // bad configuration fails at load rather than on the first request.
            SharedSecretAuthenticator::new(self.core.mode == EnforcementMode::Protected)?;
        }

        if matches!(self.auth, AuthConfig::MtlsSpiffe { .. })
            && matches!(self.peer_identity, PeerIdentitySource::None)
        {
            return Err(VigilError::Config(
                "auth.method=mtls_spiffe requires a peer_identity source; with `none` there is \
                 no certificate to derive an identity from and every request would fail"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Build the configured authenticator.
    pub fn build_authenticator(&self) -> Result<Arc<dyn Authenticator>> {
        match &self.auth {
            AuthConfig::MtlsSpiffe { registrations } => {
                let mut authenticator = MtlsSpiffeAuthenticator::new();
                for registration in registrations {
                    let tenant = registration.tenant_id.parse()?;
                    match (&registration.agent_id, &registration.principal_id) {
                        (Some(agent), None) => {
                            authenticator = authenticator.register_agent(
                                registration.spiffe_id.clone(),
                                tenant,
                                agent.parse()?,
                            );
                        }
                        (None, Some(principal)) => {
                            authenticator = authenticator.register_human(
                                registration.spiffe_id.clone(),
                                tenant,
                                principal.parse()?,
                                registration.roles.clone(),
                            );
                        }
                        _ => {
                            return Err(VigilError::Config(format!(
                                "registration for `{}` must name exactly one of agent_id or \
                                 principal_id",
                                registration.spiffe_id
                            )))
                        }
                    }
                }
                Ok(Arc::new(authenticator))
            }
            AuthConfig::DevSharedSecret { tokens } => {
                let mut authenticator =
                    SharedSecretAuthenticator::new(self.core.mode == EnforcementMode::Protected)?;
                for token in tokens {
                    authenticator = authenticator.register(
                        token.token.clone(),
                        vigil_identity::VerifiedIdentity {
                            workload: vigil_protocol::principal::WorkloadIdentity::attested(
                                format!("dev:{}", token.agent_id),
                                "dev_shared_secret",
                            ),
                            tenant_id: token.tenant_id.parse()?,
                            agent_id: Some(token.agent_id.parse()?),
                            principal_id: None,
                            roles: vec![],
                            kind: vigil_identity::CallerKind::Agent,
                        },
                    );
                }
                Ok(Arc::new(authenticator))
            }
        }
    }
}

/// Extract the peer's proven identity for this connection.
///
/// Returns the URI SANs the authenticator will look up. An empty result means "no transport
/// identity", which every certificate-based authenticator treats as a rejection.
pub fn peer_identity_for(
    source: &PeerIdentitySource,
    remote_addr: Option<IpAddr>,
    headers: &axum::http::HeaderMap,
) -> PeerIdentity {
    match source {
        PeerIdentitySource::None => PeerIdentity::default(),
        PeerIdentitySource::TrustedProxy {
            header,
            trusted_peers,
        } => {
            // The header is only meaningful if it came from a proxy we trust. Without this
            // check any client could assert its own identity — the same defect as a
            // body-supplied `verified` flag, one layer up.
            let from_trusted_peer = remote_addr.is_some_and(|addr| trusted_peers.contains(&addr));
            if !from_trusted_peer {
                return PeerIdentity::default();
            }
            let sans = headers
                .get(header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            PeerIdentity(sans)
        }
    }
}

/// Serve until SIGTERM or SIGINT.
pub async fn serve(config: ServerConfig, state: ApiState) -> Result<()> {
    let router = crate::api::router(state.clone());
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| VigilError::Config(format!("cannot bind {}: {e}", config.listen)))?;

    tracing::info!(
        listen = %config.listen,
        mode = ?state.core.mode(),
        authentication = state.authenticator.method(),
        "VIGIL Core listening"
    );

    // Maintenance runs alongside serving: evicting abandoned sessions bounds memory, and
    // periodic checkpoints bound how much of the audit chain an attacker could rewrite.
    let maintenance = tokio::spawn(maintenance_loop(
        state.clone(),
        config.maintenance_interval_seconds,
    ));

    // `into_make_service_with_connect_info` is what populates `ConnectInfo`, which
    // `auth_middleware` needs to decide whether a forwarded identity header came from a
    // trusted peer. Without it the extension is absent, every trusted-peer check fails, and
    // mesh-terminated mTLS would silently authenticate nobody.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| VigilError::Io(e.to_string()))?;

    maintenance.abort();
    tracing::info!("VIGIL Core stopped");
    Ok(())
}

async fn maintenance_loop(state: ApiState, interval_seconds: u64) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_seconds.max(1)));
    loop {
        ticker.tick().await;
        match state.core.evict_stale_sessions() {
            Ok(evicted) if evicted > 0 => tracing::info!(evicted, "evicted abandoned sessions"),
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "session eviction failed"),
        }
        if !state.core.audit().is_empty() {
            if let Err(error) = state.core.audit().checkpoint() {
                // A checkpoint failure is a real integrity concern: without checkpoints, a
                // truncation of the chain tail is undetectable.
                tracing::error!(%error, "audit checkpoint failed");
            }
        }
    }
}

/// Resolve when the process is asked to stop.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            // If the handler cannot be installed, fall back to waiting forever rather than
            // shutting down immediately — an unexpected exit is worse than a missed signal.
            Err(error) => {
                tracing::error!(%error, "cannot install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => tracing::info!("received SIGINT, draining"),
        _ = terminate => tracing::info!("received SIGTERM, draining"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_CONFIG: &str = r#"
listen: "127.0.0.1:8080"
auth:
  method: dev_shared_secret
  tokens:
    - token: s3cret
      tenant_id: acme
      agent_id: customer-support-assistant
core:
  mode: observability
"#;

    #[test]
    fn a_development_config_loads_and_builds_an_authenticator() {
        let config = ServerConfig::from_yaml(DEV_CONFIG).expect("loads");
        assert!(config.build_authenticator().is_ok());
    }

    #[test]
    fn a_trusted_proxy_source_with_no_trusted_peers_is_rejected() {
        let src = r#"
auth: {method: dev_shared_secret, tokens: []}
core: {mode: observability}
peer_identity:
  source: trusted_proxy
  header: x-forwarded-client-cert
  trusted_peers: []
"#;
        let err = ServerConfig::from_yaml(src).unwrap_err();
        assert!(err.to_string().contains("not an identity"), "{err}");
    }

    #[test]
    fn mtls_without_a_peer_identity_source_is_rejected() {
        let src = r#"
auth: {method: mtls_spiffe, registrations: []}
core: {mode: protected}
"#;
        let err = ServerConfig::from_yaml(src).unwrap_err();
        assert!(
            err.to_string().contains("requires a peer_identity"),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_config_key_is_rejected() {
        let src = "listn: '0.0.0.0:1'\nauth: {method: dev_shared_secret, tokens: []}\n";
        assert!(ServerConfig::from_yaml(src).is_err());
    }

    #[test]
    fn a_registration_naming_both_an_agent_and_a_principal_is_rejected() {
        let src = r#"
auth:
  method: mtls_spiffe
  registrations:
    - spiffe_id: spiffe://x/a
      tenant_id: acme
      agent_id: support
      principal_id: user-1
peer_identity:
  source: trusted_proxy
  header: x-fcc
  trusted_peers: ["127.0.0.1"]
"#;
        let config = ServerConfig::from_yaml(src).expect("loads");
        let err = config.build_authenticator().unwrap_err();
        assert!(err.to_string().contains("exactly one of"), "{err}");
    }

    #[test]
    fn a_proxy_header_from_an_untrusted_peer_is_ignored() {
        let source = PeerIdentitySource::TrustedProxy {
            header: "x-forwarded-client-cert".to_string(),
            trusted_peers: vec!["10.0.0.1".parse().unwrap()],
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-client-cert",
            "spiffe://evil/admin".parse().unwrap(),
        );

        // From an untrusted address the header is discarded entirely.
        let from_attacker =
            peer_identity_for(&source, Some("203.0.113.9".parse().unwrap()), &headers);
        assert!(
            from_attacker.0.is_empty(),
            "an identity header from an untrusted peer must be ignored"
        );

        // From the mesh, it is honoured.
        let from_mesh = peer_identity_for(&source, Some("10.0.0.1".parse().unwrap()), &headers);
        assert_eq!(from_mesh.0, vec!["spiffe://evil/admin".to_string()]);
    }

    #[test]
    fn an_unknown_remote_address_never_satisfies_the_trusted_peer_check() {
        let source = PeerIdentitySource::TrustedProxy {
            header: "x-fcc".to_string(),
            trusted_peers: vec!["10.0.0.1".parse().unwrap()],
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-fcc", "spiffe://x/y".parse().unwrap());
        assert!(peer_identity_for(&source, None, &headers).0.is_empty());
    }

    #[test]
    fn the_none_source_never_yields_an_identity() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-client-cert", "spiffe://x/y".parse().unwrap());
        assert!(peer_identity_for(
            &PeerIdentitySource::None,
            Some("10.0.0.1".parse().unwrap()),
            &headers
        )
        .0
        .is_empty());
    }
}
