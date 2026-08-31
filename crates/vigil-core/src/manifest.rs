//! Tool security manifests (spec §19).
//!
//! # Why
//!
//! VIGIL cannot infer that `send_email` leaves the trust boundary from its name. The manifest
//! is where a tool declares what it *does*: its side effect, its impact tier, whether its
//! arguments carry sensitive data, where it may talk to, and whether its credentials are
//! brokered. Without it, every tool would have to be treated identically, and the only safe
//! identical treatment is "deny".
//!
//! # Failure mode
//!
//! An unregistered tool is not an unrestricted tool. [`ToolManifestRegistry::lookup`] returns
//! a conservative synthetic manifest — Tier 3, external write, approval required — so a tool
//! someone forgot to register is inconvenient rather than dangerous. The
//! `TOOL_UNREGISTERED` reason code makes that visible so it gets fixed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vigil_common::{Result, VigilError};
use vigil_protocol::action::{ImpactTier, SideEffectClass};

/// Sensitivity metadata for one argument.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgumentSpec {
    #[serde(default)]
    pub sensitivity: Option<String>,
    #[serde(default)]
    pub may_contain_sensitive_data: bool,
    /// Whether this argument must never be populated from untrusted content.
    #[serde(default)]
    pub requires_trusted_source: bool,
}

/// Approval defaults for a tool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSpec {
    #[serde(default)]
    pub default: bool,
    /// Operations that always require approval regardless of the default.
    #[serde(default)]
    pub operations: Vec<String>,
}

/// Network destinations a tool may reach.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    #[serde(default)]
    pub destinations: Vec<String>,
}

/// Credential handling for a tool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    /// Whether the gateway injects credentials, keeping them out of model context
    /// (Invariant 6).
    #[serde(default)]
    pub brokered: bool,
    #[serde(default)]
    pub credential_ref: Option<String>,
}

/// Rate limits for a tool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSpec {
    #[serde(default)]
    pub per_agent_per_minute: Option<u32>,
}

/// A tool's declared security properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub side_effect: SideEffectClass,
    /// Declared impact. Raised to the side effect's floor if the manifest under-claims.
    pub impact: ImpactTier,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub arguments: HashMap<String, ArgumentSpec>,
    #[serde(default)]
    pub approval: ApprovalSpec,
    #[serde(default)]
    pub network: NetworkSpec,
    #[serde(default)]
    pub credentials: CredentialSpec,
    #[serde(default)]
    pub rate_limit: RateLimitSpec,
    /// Whether this manifest was found, or synthesized because the tool is unregistered.
    #[serde(skip, default)]
    pub synthetic: bool,
}

impl ToolManifest {
    /// The effective impact tier.
    ///
    /// A manifest may classify a tool *higher* than its side effect implies but never lower:
    /// an operator cannot make a destructive tool Tier 0 by editing YAML. This is enforced
    /// here rather than at validation so it also holds for manifests loaded by other paths.
    pub fn effective_tier(&self) -> ImpactTier {
        self.impact.max(self.side_effect.floor_tier())
    }

    /// Whether this operation requires approval by manifest default.
    pub fn requires_approval(&self, operation: &str) -> bool {
        self.approval.default
            || self
                .approval
                .operations
                .iter()
                .any(|o| o.eq_ignore_ascii_case(operation))
            || self.effective_tier().default_requires_approval()
    }

    /// The conservative manifest used for an unregistered tool.
    pub fn conservative(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: "unregistered tool; conservative defaults applied".to_string(),
            side_effect: SideEffectClass::ExternalWrite,
            impact: ImpactTier::conservative_default(),
            resources: vec![],
            arguments: HashMap::new(),
            approval: ApprovalSpec {
                default: true,
                operations: vec![],
            },
            network: NetworkSpec::default(),
            credentials: CredentialSpec::default(),
            rate_limit: RateLimitSpec::default(),
            synthetic: true,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(VigilError::Config("tool manifest has no name".to_string()));
        }
        if self.impact < self.side_effect.floor_tier() {
            // Not an error — `effective_tier` corrects it — but the operator should know
            // their declared tier is being overridden.
            tracing::warn!(
                tool = %self.name,
                declared = ?self.impact,
                floor = ?self.side_effect.floor_tier(),
                "manifest declares an impact tier below its side effect's floor; the floor applies"
            );
        }
        Ok(())
    }
}

/// Every registered tool.
#[derive(Debug, Default)]
pub struct ToolManifestRegistry {
    manifests: HashMap<String, ToolManifest>,
}

impl ToolManifestRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, manifest: ToolManifest) -> Result<()> {
        manifest.validate()?;
        self.manifests.insert(manifest.name.clone(), manifest);
        Ok(())
    }

    pub fn from_yaml(src: &str) -> Result<Self> {
        let manifests: Vec<ToolManifest> = serde_yaml_ng::from_str(src)
            .map_err(|e| VigilError::Config(format!("tool manifests are not valid: {e}")))?;
        let mut registry = Self::new();
        for manifest in manifests {
            registry.register(manifest)?;
        }
        Ok(registry)
    }

    pub fn load_file(path: &std::path::Path) -> Result<Self> {
        let src = std::fs::read_to_string(path)?;
        Self::from_yaml(&src).map_err(|e| VigilError::Config(format!("{}: {e}", path.display())))
    }

    pub fn len(&self) -> usize {
        self.manifests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.manifests.is_empty()
    }

    /// Look up a tool, falling back to conservative defaults.
    pub fn lookup(&self, name: &str) -> ToolManifest {
        self.manifests
            .get(name)
            .cloned()
            .unwrap_or_else(|| ToolManifest::conservative(name))
    }

    pub fn is_registered(&self, name: &str) -> bool {
        self.manifests.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFESTS: &str = r#"
- name: send_email
  side_effect: external_write
  impact: tier3_high_impact
  approval:
    default: true
  network:
    destinations: [mail-provider.example]
  credentials:
    brokered: true
    credential_ref: mail-provider-api-key
- name: read_customer_record
  side_effect: internal_read
  impact: tier1_low_risk_read
"#;

    #[test]
    fn manifests_load_and_look_up() {
        let r = ToolManifestRegistry::from_yaml(MANIFESTS).unwrap();
        assert_eq!(r.len(), 2);
        let email = r.lookup("send_email");
        assert!(!email.synthetic);
        assert!(email.credentials.brokered);
        assert!(email.requires_approval("send"));
    }

    #[test]
    fn an_unregistered_tool_gets_conservative_defaults() {
        let r = ToolManifestRegistry::from_yaml(MANIFESTS).unwrap();
        let unknown = r.lookup("mystery_tool");
        assert!(unknown.synthetic);
        assert_eq!(unknown.effective_tier(), ImpactTier::Tier3HighImpact);
        assert!(unknown.requires_approval("anything"));
        assert!(!r.is_registered("mystery_tool"));
    }

    #[test]
    fn a_manifest_cannot_declare_a_tier_below_its_side_effects_floor() {
        let src = r#"
- name: nuke_everything
  side_effect: destructive
  impact: tier0_observational
"#;
        let r = ToolManifestRegistry::from_yaml(src).unwrap();
        assert_eq!(
            r.lookup("nuke_everything").effective_tier(),
            ImpactTier::Tier4Critical,
            "a destructive tool must not be declarable as observational"
        );
    }

    #[test]
    fn low_impact_reads_do_not_require_approval() {
        let r = ToolManifestRegistry::from_yaml(MANIFESTS).unwrap();
        assert!(!r.lookup("read_customer_record").requires_approval("read"));
    }

    #[test]
    fn a_misspelled_manifest_field_is_rejected() {
        let src = "- name: t\n  side_efect: external_write\n  impact: tier3_high_impact\n";
        assert!(ToolManifestRegistry::from_yaml(src).is_err());
    }
}
