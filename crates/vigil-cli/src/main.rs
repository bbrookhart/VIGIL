//! The `vigil` command-line tool.
//!
//! Every subcommand here is implemented against a real API. Commands from the design that
//! cannot be implemented against what exists today — `policy simulate`, `session inspect`,
//! `incident export` — are deliberately absent rather than present and stubbed: a CLI that
//! prints "not yet implemented" teaches operators to distrust its output.

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use vigil_audit::AuditBundle;
use vigil_common::ids::PolicyBundleId;
use vigil_policy::DeterministicPolicyEngine;
use vigil_remit::RemitRegistry;

#[derive(Parser)]
#[command(
    name = "vigil",
    version,
    about = "Operational tooling for VIGIL runtime agent security"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and inspect policy bundles.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Validate agent remits.
    #[command(subcommand)]
    Remit(RemitCommand),
    /// Validate tool security manifests.
    #[command(subcommand)]
    Manifest(ManifestCommand),
    /// Verify tamper-evident audit evidence.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Signing key material.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Check that a deployment's configuration is coherent.
    Doctor {
        /// Directory holding policies, remits and manifests.
        #[arg(default_value = "policies")]
        policy_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Parse and validate every bundle under a directory.
    Validate {
        #[arg(default_value = "policies")]
        dir: PathBuf,
    },
    /// Print every rule with its effect, so a reviewer can read the whole posture at once.
    List {
        #[arg(default_value = "policies")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum RemitCommand {
    Validate {
        #[arg(default_value = "policies/remits")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ManifestCommand {
    Validate {
        #[arg(default_value = "policies/tools/manifests.yaml")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify an exported audit bundle against trusted checkpoint keys.
    Verify {
        /// Path to a JSON audit bundle.
        bundle: PathBuf,
        /// Trusted checkpoint key as `key_id=hex`. Repeatable.
        #[arg(long = "key", value_name = "KEY_ID=HEX")]
        keys: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Generate the three distinct signing seeds a Core needs.
    Generate {
        /// Directory to write `capability.key`, `approval.key` and `audit.key` into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Print the public key for a seed.
    ///
    /// This is how a Gateway is configured to trust a Core without ever being given the
    /// private seed — which is the whole point of the two holding different key material.
    Public {
        /// Path to a file containing a hex-encoded 32-byte seed.
        seed: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vigil: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> vigil_common::Result<()> {
    match cli.command {
        Command::Policy(PolicyCommand::Validate { dir }) => validate_policies(&dir),
        Command::Policy(PolicyCommand::List { dir }) => list_policies(&dir),
        Command::Remit(RemitCommand::Validate { dir }) => validate_remits(&dir),
        Command::Manifest(ManifestCommand::Validate { file }) => validate_manifests(&file),
        Command::Audit(AuditCommand::Verify { bundle, keys }) => verify_audit(&bundle, &keys),
        Command::Keys(KeysCommand::Generate { out }) => generate_keys(&out),
        Command::Keys(KeysCommand::Public { seed }) => print_public_key(&seed),
        Command::Doctor { policy_dir } => doctor(&policy_dir),
    }
}

/// Merge every bundle under a directory, the way the server does.
fn load_rules(dir: &Path) -> vigil_common::Result<Vec<vigil_policy::Rule>> {
    let mut rules = Vec::new();
    let mut found_any = false;
    for subdirectory in ["base", "agents", "tenants", "environments"] {
        let path = dir.join(subdirectory);
        if !path.is_dir() {
            continue;
        }
        found_any = true;
        let engine =
            DeterministicPolicyEngine::from_directory(&path, PolicyBundleId::new("check")?)?;
        rules.extend(engine.bundle().rules.clone());
    }
    if !found_any {
        // Also accept a directory of bundles directly, which is how a single-tenant
        // deployment often lays them out.
        let engine = DeterministicPolicyEngine::from_directory(dir, PolicyBundleId::new("check")?)?;
        rules.extend(engine.bundle().rules.clone());
    }
    Ok(rules)
}

fn merged_bundle(dir: &Path) -> vigil_common::Result<vigil_policy::PolicyBundle> {
    let bundle = vigil_policy::PolicyBundle {
        version: PolicyBundleId::new("merged")?,
        description: format!("merged from {}", dir.display()),
        default_effect: vigil_policy::PolicyEffect::Deny,
        rules: load_rules(dir)?,
    };
    bundle.validate()?;
    Ok(bundle)
}

fn validate_policies(dir: &Path) -> vigil_common::Result<()> {
    let bundle = merged_bundle(dir)?;
    println!(
        "✓ {} rules valid, merged from {}",
        bundle.rules.len(),
        dir.display()
    );
    println!("  default effect: {:?}", bundle.default_effect);

    // The merged set is what actually runs, so a duplicate id across files is the failure
    // mode worth reporting loudly — decisions must be attributable to exactly one rule.
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for rule in &bundle.rules {
        *counts.entry(rule.id.as_str()).or_default() += 1;
    }
    for (id, count) in counts.iter().filter(|(_, c)| **c > 1) {
        println!("  ! rule `{id}` appears {count} times");
    }
    Ok(())
}

fn list_policies(dir: &Path) -> vigil_common::Result<()> {
    let bundle = merged_bundle(dir)?;
    let mut rules = bundle.rules.clone();
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    println!("{:<34} {:<22} SEVERITY", "RULE", "EFFECT");
    for rule in rules {
        println!(
            "{:<34} {:<22} {}{}",
            rule.id,
            format!("{:?}", rule.effect),
            rule.severity.as_str(),
            if rule.audit_only {
                "  (audit-only)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn validate_remits(dir: &Path) -> vigil_common::Result<()> {
    let registry = RemitRegistry::load_directory(dir)?;
    println!("✓ {} remit(s) valid in {}", registry.len(), dir.display());
    Ok(())
}

fn validate_manifests(file: &Path) -> vigil_common::Result<()> {
    let registry = vigil_core::ToolManifestRegistry::load_file(file)?;
    println!(
        "✓ {} tool manifest(s) valid in {}",
        registry.len(),
        file.display()
    );
    Ok(())
}

fn verify_audit(bundle_path: &Path, keys: &[String]) -> vigil_common::Result<()> {
    let raw = std::fs::read_to_string(bundle_path)?;
    let bundle: AuditBundle = serde_json::from_str(&raw)?;

    let mut trusted = HashMap::new();
    for entry in keys {
        let (key_id, hex_key) = entry.split_once('=').ok_or_else(|| {
            vigil_common::VigilError::Config("--key must be given as key_id=hex".to_string())
        })?;
        let bytes: [u8; 32] = hex::decode(hex_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| {
                vigil_common::VigilError::Config(
                    "checkpoint key must be 32 hex-encoded bytes".to_string(),
                )
            })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
            vigil_common::VigilError::Config("not a valid Ed25519 public key".to_string())
        })?;
        trusted.insert(key_id.to_string(), key);
    }

    let report = bundle.verify(&trusted);
    println!(
        "entries: {}  checkpoints: {}",
        report.entries_checked, report.checkpoints_checked
    );

    if report.is_valid() {
        println!("✓ audit chain verified");
        return Ok(());
    }

    // A failed verification exits non-zero so it can gate a pipeline.
    println!("✗ {} integrity failure(s):", report.failures.len());
    for failure in &report.failures {
        println!("  {failure:?}");
    }
    Err(vigil_common::VigilError::AuditIntegrity(format!(
        "{} failure(s)",
        report.failures.len()
    )))
}

fn generate_keys(out: &Path) -> vigil_common::Result<()> {
    std::fs::create_dir_all(out)?;
    for name in ["capability", "approval", "audit"] {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let path = out.join(format!("{name}.key"));
        std::fs::write(&path, hex::encode(seed))?;

        // The seeds are private key material. Anyone who can read them can mint
        // capabilities or forge audit checkpoints.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        println!("wrote {}", path.display());
    }
    println!();
    println!("Three distinct keys, deliberately: compromise of the audit key must not allow");
    println!("minting capabilities, and compromise of the approval key must not allow forging");
    println!("checkpoints. Give the Gateway only the *public* half:");
    println!();
    println!("  vigil keys public {}/capability.key", out.display());
    Ok(())
}

fn print_public_key(seed_path: &Path) -> vigil_common::Result<()> {
    let raw = std::fs::read_to_string(seed_path)?;
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            vigil_common::VigilError::Config("seed must be 32 hex-encoded bytes".to_string())
        })?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&bytes);
    println!("{}", hex::encode(signing.verifying_key().to_bytes()));
    Ok(())
}

fn doctor(policy_dir: &Path) -> vigil_common::Result<()> {
    let mut problems = 0;

    println!("VIGIL configuration check");
    println!("─────────────────────────");

    match merged_bundle(policy_dir) {
        Ok(bundle) => {
            println!("✓ policy: {} rules", bundle.rules.len());
            if bundle.rules.iter().any(|r| {
                r.matcher.match_all && matches!(r.effect, vigil_policy::PolicyEffect::Allow)
            }) {
                println!("  ! a universal allow rule is present, which disables enforcement");
                problems += 1;
            }
        }
        Err(error) => {
            println!("✗ policy: {error}");
            problems += 1;
        }
    }

    match RemitRegistry::load_directory(&policy_dir.join("remits")) {
        Ok(registry) if registry.is_empty() => {
            println!("  ! no remits registered: every agent will be treated as unregistered");
        }
        Ok(registry) => println!("✓ remits: {}", registry.len()),
        Err(error) => {
            println!("✗ remits: {error}");
            problems += 1;
        }
    }

    match vigil_core::ToolManifestRegistry::load_file(&policy_dir.join("tools/manifests.yaml")) {
        Ok(registry) => println!("✓ tool manifests: {}", registry.len()),
        Err(error) => {
            println!("✗ tool manifests: {error}");
            problems += 1;
        }
    }

    for variable in [
        "VIGIL_CAPABILITY_KEY",
        "VIGIL_APPROVAL_KEY",
        "VIGIL_AUDIT_KEY",
    ] {
        if std::env::var(variable).is_ok() {
            println!("✓ {variable} is set");
        } else {
            println!("  ! {variable} is not set; Protected Mode will refuse to start");
        }
    }

    println!();
    if problems == 0 {
        println!("No blocking problems found.");
        Ok(())
    } else {
        Err(vigil_common::VigilError::Config(format!(
            "{problems} problem(s) found"
        )))
    }
}
