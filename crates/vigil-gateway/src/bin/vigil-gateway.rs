//! The VIGIL Gateway server.
//!
//! Holds the credentials the agent does not, verifies capabilities minted by Core, and
//! forwards authorized actions to real tools.
//!
//! It holds **only public keys**. There is no configuration path that gives the Gateway a
//! capability signing key, because a Gateway that could mint its own capabilities would
//! collapse the privilege separation the whole design rests on.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use vigil_capability::{CapabilityVerifier, InMemoryNonceStore};
use vigil_common::{Result, SystemClock, VigilError};
use vigil_gateway::api::{router, GatewayState};
use vigil_gateway::tools::RecordingBackend;
use vigil_gateway::{CredentialBroker, CredentialRef, Gateway, ToolRegistry};
use vigil_identity::{Authenticator, MtlsSpiffeAuthenticator, SharedSecretAuthenticator};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayConfig {
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    /// Public keys the Gateway will accept capabilities from, as `key_id -> hex`.
    trusted_capability_keys: Vec<TrustedKey>,
    #[serde(default)]
    tools: Vec<ToolConfig>,
    auth: AuthConfig,
    /// Replicas sharing one nonce store. More than one requires a shared store, which is not
    /// yet implemented — see `validate`.
    #[serde(default = "default_replicas")]
    replicas: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKey {
    key_id: String,
    /// Hex-encoded Ed25519 public key, or a path to a file containing one.
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolConfig {
    name: String,
    /// Reference to the credential this tool uses. Resolved from the environment so the
    /// value never appears in a config file.
    #[serde(default)]
    credential_ref: Option<String>,
    #[serde(default)]
    credential_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum AuthConfig {
    MtlsSpiffe { registrations: Vec<Registration> },
    DevSharedSecret { tokens: Vec<DevToken> },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    spiffe_id: String,
    tenant_id: String,
    agent_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevToken {
    token: String,
    tenant_id: String,
    agent_id: String,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8081))
}
fn default_replicas() -> u32 {
    1
}

impl GatewayConfig {
    fn validate(&self) -> Result<()> {
        if self.trusted_capability_keys.is_empty() {
            return Err(VigilError::Config(
                "no trusted capability keys configured; the Gateway would reject every action"
                    .to_string(),
            ));
        }
        if self.replicas > 1 {
            // The in-memory nonce store is per-process, so N replicas permit N redemptions
            // of a single-use capability. Refusing to start is the honest response until a
            // shared store exists.
            return Err(VigilError::Config(
                "replicas > 1 requires a shared nonce store, which is not yet implemented: with \
                 the in-memory store each replica would independently accept the same \
                 single-use capability, permitting one replay per replica"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "VIGIL Gateway failed to start");
            eprintln!("vigil-gateway: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("VIGIL_GATEWAY_CONFIG").ok())
        .unwrap_or_else(|| "vigil-gateway.yaml".to_string());

    let src = std::fs::read_to_string(&config_path)
        .map_err(|e| VigilError::Config(format!("{config_path}: {e}")))?;
    let config: GatewayConfig = serde_yaml_ng::from_str(&src)
        .map_err(|e| VigilError::Config(format!("gateway config is not valid: {e}")))?;
    config.validate()?;

    let clock = Arc::new(SystemClock);
    let mut verifier = CapabilityVerifier::new(clock.clone(), Arc::new(InMemoryNonceStore::new()));
    for key in &config.trusted_capability_keys {
        verifier = verifier.trust_key(key.key_id.clone(), load_public_key(&key.public_key)?);
    }

    // Tool backends. The reference deployment registers recording backends so an operator can
    // exercise the path end to end; a real deployment replaces these with HTTP/MCP clients.
    let broker = Arc::new(CredentialBroker::new());
    let mut tools = ToolRegistry::new();
    for tool in &config.tools {
        tools = tools.register(Arc::new(RecordingBackend::new(
            tool.name.clone(),
            serde_json::json!({"status": "ok"}),
        )));
        if let (Some(reference), Some(variable)) = (&tool.credential_ref, &tool.credential_env) {
            let value = std::env::var(variable).map_err(|_| {
                VigilError::Config(format!(
                    "tool `{}` declares credential_env `{variable}`, which is not set",
                    tool.name
                ))
            })?;
            broker.register(tool.name.clone(), CredentialRef(reference.clone()), value)?;
        }
    }

    let authenticator = build_authenticator(&config.auth)?;
    let gateway = Arc::new(Gateway::new(verifier, Arc::new(tools), broker));

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| VigilError::Config(format!("cannot bind {}: {e}", config.listen)))?;
    tracing::info!(
        listen = %config.listen,
        tools = config.tools.len(),
        authentication = authenticator.method(),
        "VIGIL Gateway listening"
    );

    let state = GatewayState {
        gateway,
        authenticator,
    };
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received SIGINT, draining");
    })
    .await
    .map_err(|e| VigilError::Io(e.to_string()))?;

    tracing::info!("VIGIL Gateway stopped");
    Ok(())
}

fn build_authenticator(config: &AuthConfig) -> Result<Arc<dyn Authenticator>> {
    match config {
        AuthConfig::MtlsSpiffe { registrations } => {
            let mut authenticator = MtlsSpiffeAuthenticator::new();
            for registration in registrations {
                authenticator = authenticator.register_agent(
                    registration.spiffe_id.clone(),
                    registration.tenant_id.parse()?,
                    registration.agent_id.parse()?,
                );
            }
            Ok(Arc::new(authenticator))
        }
        AuthConfig::DevSharedSecret { tokens } => {
            // The Gateway has no enforcement-mode setting of its own; a shared secret here is
            // a development choice and is reported as such at startup.
            let mut authenticator = SharedSecretAuthenticator::new(false)?;
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
            tracing::warn!("using development shared-secret authentication");
            Ok(Arc::new(authenticator))
        }
    }
}

/// Load an Ed25519 public key from hex or from a file.
fn load_public_key(source: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let bytes = if let Ok(contents) = std::fs::read_to_string(PathBuf::from(source)) {
        hex::decode(contents.trim())
    } else {
        hex::decode(source.trim())
    }
    .map_err(|_| VigilError::Config("capability public key is not valid hex".to_string()))?;

    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VigilError::Config("capability public key must be 32 bytes".to_string()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| VigilError::Config("capability public key is not a valid Ed25519 key".into()))
}
