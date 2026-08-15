//! The VIGIL Core server.
//!
//! Loads policy bundles, remits and tool manifests from disk, builds the decision pipeline,
//! and serves the authenticated decision API until asked to stop.
//!
//! Signing keys come from files rather than being generated: an ephemeral key means every
//! restart invalidates in-flight capabilities and orphans the audit chain's checkpoints, so
//! the server refuses to start Protected Mode without real key material.

use std::path::PathBuf;
use std::sync::Arc;
use vigil_common::ids::{PolicyBundleId, TenantId};
use vigil_common::{Result, SystemClock, VigilError};
use vigil_core::api::ApiState;
use vigil_core::server::{self, ServerConfig};
use vigil_core::{CoreConfig, EnforcementMode, ToolManifestRegistry, VigilCore};
use vigil_policy::{DeterministicPolicyEngine, PolicyBundle, PolicyEffect};
use vigil_remit::RemitRegistry;

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
            // A configuration or startup failure must be loud and must not degrade into
            // serving with weaker settings.
            tracing::error!(%error, "VIGIL Core failed to start");
            eprintln!("vigil-core: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("VIGIL_CONFIG").ok())
        .unwrap_or_else(|| "vigil-core.yaml".to_string());

    let config = ServerConfig::load(&PathBuf::from(&config_path))?;
    let tenant: TenantId = std::env::var("VIGIL_TENANT")
        .unwrap_or_else(|_| "default".to_string())
        .parse()?;

    let policy = load_policy(&config)?;
    let remits = RemitRegistry::load_directory(&PathBuf::from(&config.remit_dir))?;
    let manifests = ToolManifestRegistry::load_file(&PathBuf::from(&config.manifest_file))?;
    let authenticator = config.build_authenticator()?;

    let (capability_seed, approval_seed, audit_seed) = load_signing_seeds(&config.core)?;

    let core = Arc::new(
        VigilCore::builder()
            .config(config.core.clone())
            .policy(policy)
            .remits(remits)
            .manifests(manifests)
            .clock(Arc::new(SystemClock))
            .tenant(tenant)
            .signing_seeds(capability_seed, approval_seed, audit_seed)
            .build()?,
    );

    let state = ApiState {
        core,
        authenticator,
        peer_identity_source: Arc::new(config.peer_identity.clone()),
    };

    server::serve(config, state).await
}

/// Merge every bundle under the configured policy directory.
fn load_policy(config: &ServerConfig) -> Result<Arc<DeterministicPolicyEngine>> {
    let root = PathBuf::from(&config.policy_dir);
    let mut rules = Vec::new();

    // `base` and `agents` are merged; `remits` and `tools` hold other document types.
    for subdirectory in ["base", "agents", "tenants", "environments"] {
        let dir = root.join(subdirectory);
        if !dir.is_dir() {
            continue;
        }
        let engine =
            DeterministicPolicyEngine::from_directory(&dir, PolicyBundleId::new("staging")?)?;
        rules.extend(engine.bundle().rules.clone());
    }

    if rules.is_empty() {
        return Err(VigilError::Config(format!(
            "no policy rules found under {}; refusing to start with an empty ruleset",
            root.display()
        )));
    }

    let bundle = PolicyBundle {
        version: PolicyBundleId::new(
            std::env::var("VIGIL_POLICY_VERSION").unwrap_or_else(|_| "bundle-local".to_string()),
        )?,
        description: format!("merged from {}", root.display()),
        default_effect: PolicyEffect::Deny,
        rules,
    };
    bundle.validate()?;
    tracing::info!(
        rules = bundle.rules.len(),
        version = %bundle.version,
        "policy bundle loaded"
    );
    Ok(Arc::new(DeterministicPolicyEngine::new(bundle)))
}

/// Load the three signing seeds.
///
/// Three distinct keys on purpose: compromise of the audit key must not let an attacker mint
/// capabilities, and compromise of the approval key must not let them forge checkpoints.
fn load_signing_seeds(core: &CoreConfig) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let capability = read_seed("VIGIL_CAPABILITY_KEY");
    let approval = read_seed("VIGIL_APPROVAL_KEY");
    let audit = read_seed("VIGIL_AUDIT_KEY");

    match (capability, approval, audit) {
        (Some(c), Some(a), Some(u)) => {
            if c == a || a == u || c == u {
                return Err(VigilError::Config(
                    "the capability, approval and audit signing keys must be distinct".to_string(),
                ));
            }
            Ok((c, a, u))
        }
        _ if core.mode == EnforcementMode::Protected => Err(VigilError::Config(
            "VIGIL_CAPABILITY_KEY, VIGIL_APPROVAL_KEY and VIGIL_AUDIT_KEY must all be set in \
             Protected Mode: an ephemeral key invalidates in-flight capabilities on every \
             restart and orphans the audit chain's checkpoints"
                .to_string(),
        )),
        _ => {
            tracing::warn!(
                "generating ephemeral signing keys; capabilities and audit checkpoints will not \
                 survive a restart. Acceptable only outside Protected Mode."
            );
            let mut seeds = [[0u8; 32]; 3];
            for seed in seeds.iter_mut() {
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed);
            }
            Ok((seeds[0], seeds[1], seeds[2]))
        }
    }
}

/// Read a 32-byte seed from a hex-encoded environment variable or a file path.
fn read_seed(variable: &str) -> Option<[u8; 32]> {
    let raw = std::env::var(variable).ok()?;
    // A path is the Kubernetes shape (a mounted Secret); hex is convenient locally.
    let bytes = if let Ok(contents) = std::fs::read(&raw) {
        contents
    } else {
        hex::decode(raw.trim()).ok()?
    };
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}
