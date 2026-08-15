//! The remit document.
//!
//! Written by a human, reviewed like code, versioned like code. `deny_unknown_fields`
//! throughout: a misspelled key in a remit would silently widen an agent's authority, which
//! is the same failure mode as a misspelled policy matcher and gets the same treatment.

use serde::{Deserialize, Serialize};
use vigil_common::{Result, VigilError};

/// What an agent may do with one tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPermission {
    /// The tool name as it appears in a normalized action.
    pub name: String,
    /// Operations permitted on it. An empty list permits nothing, not everything.
    pub operations: Vec<String>,
    /// Operations that additionally require human approval, even though they are in remit.
    #[serde(default)]
    pub approval_required_operations: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// Data classes an agent may handle and may never let out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataBoundary {
    /// Classes the agent legitimately works with.
    #[serde(default)]
    pub allowed_classes: Vec<String>,
    /// Classes that must never cross the trust boundary, regardless of approval.
    #[serde(default)]
    pub forbidden_egress_classes: Vec<String>,
}

/// Filesystem boundary.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemBoundary {
    #[serde(default)]
    pub allowed_roots: Vec<String>,
}

/// Network boundary.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBoundary {
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
}

/// Execution budgets.
///
/// These are the denial-of-wallet and runaway-loop controls (spec §36). Defaults are
/// deliberately modest: an agent that needs more says so explicitly in a reviewed file,
/// rather than inheriting an unbounded budget by omission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_tool_calls")]
    pub max_tool_calls: u32,
    #[serde(default = "default_max_model_calls")]
    pub max_model_calls: u32,
    #[serde(default = "default_max_session_minutes")]
    pub max_session_minutes: u32,
    #[serde(default = "default_max_external_domains")]
    pub max_external_domains: u32,
    #[serde(default = "default_max_cost_usd")]
    pub max_cost_usd: f64,
    #[serde(default = "default_max_delegation_depth")]
    pub max_delegation_depth: u32,
    /// How many semantically identical actions may repeat before it counts as a loop.
    #[serde(default = "default_max_repeated_actions")]
    pub max_repeated_actions: u32,
}

fn default_max_tool_calls() -> u32 {
    40
}
fn default_max_model_calls() -> u32 {
    25
}
fn default_max_session_minutes() -> u32 {
    30
}
fn default_max_external_domains() -> u32 {
    3
}
fn default_max_cost_usd() -> f64 {
    2.0
}
fn default_max_delegation_depth() -> u32 {
    2
}
fn default_max_repeated_actions() -> u32 {
    3
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tool_calls: default_max_tool_calls(),
            max_model_calls: default_max_model_calls(),
            max_session_minutes: default_max_session_minutes(),
            max_external_domains: default_max_external_domains(),
            max_cost_usd: default_max_cost_usd(),
            max_delegation_depth: default_max_delegation_depth(),
            max_repeated_actions: default_max_repeated_actions(),
        }
    }
}

/// An agent's declared purpose and boundaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remit {
    /// The registered agent id this remit governs.
    pub agent: String,
    /// Monotonic version. Recorded on every decision made under this remit.
    pub version: String,
    /// What the agent is for, in plain language. Used in detector context and the console.
    pub purpose: Vec<String>,
    /// What the agent must never pursue, regardless of what a tool permits.
    #[serde(default)]
    pub forbidden_goals: Vec<String>,
    #[serde(default)]
    pub tools: Vec<ToolPermission>,
    #[serde(default)]
    pub data: DataBoundary,
    #[serde(default)]
    pub filesystem: FilesystemBoundary,
    #[serde(default)]
    pub network: NetworkBoundary,
    #[serde(default)]
    pub limits: Limits,
}

impl Remit {
    pub fn from_yaml(src: &str) -> Result<Self> {
        let remit: Self = serde_yaml_ng::from_str(src)
            .map_err(|e| VigilError::Remit(format!("remit is not valid: {e}")))?;
        remit.validate()?;
        Ok(remit)
    }

    /// Reject remits that would behave surprisingly.
    pub fn validate(&self) -> Result<()> {
        if self.agent.trim().is_empty() {
            return Err(VigilError::Remit("remit has no agent name".to_string()));
        }
        vigil_common::ids::validate_id("agent", &self.agent)
            .map_err(|e| VigilError::Remit(e.to_string()))?;
        if self.version.trim().is_empty() {
            return Err(VigilError::Remit(format!(
                "remit for `{}` has no version; decisions must reference an exact remit version",
                self.agent
            )));
        }
        if self.purpose.is_empty() {
            return Err(VigilError::Remit(format!(
                "remit for `{}` declares no purpose; an agent with no stated purpose cannot be \
                 checked for drift",
                self.agent
            )));
        }

        let mut seen = std::collections::HashSet::new();
        for tool in &self.tools {
            if !seen.insert(tool.name.as_str()) {
                return Err(VigilError::Remit(format!(
                    "remit for `{}` lists tool `{}` twice",
                    self.agent, tool.name
                )));
            }
            if tool.operations.is_empty() {
                return Err(VigilError::Remit(format!(
                    "tool `{}` lists no operations; remove it rather than granting it with an \
                     empty operation set",
                    tool.name
                )));
            }
            for op in &tool.approval_required_operations {
                if !tool.operations.contains(op) {
                    return Err(VigilError::Remit(format!(
                        "tool `{}` requires approval for `{op}`, which is not among its permitted \
                         operations",
                        tool.name
                    )));
                }
            }
        }

        if self.limits.max_tool_calls == 0 || self.limits.max_session_minutes == 0 {
            return Err(VigilError::Remit(format!(
                "remit for `{}` sets a zero budget, which would block every action",
                self.agent
            )));
        }
        // A wildcard destination in a remit is the same mistake as one in a policy: it reads
        // as "anywhere", which is never what an operator means to write down.
        if self.network.allowed_destinations.iter().any(|d| d == "*") {
            return Err(VigilError::Remit(format!(
                "remit for `{}` allows `*` as a network destination; list the destinations \
                 explicitly",
                self.agent
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
agent: customer-support-assistant
version: "3"
purpose:
  - answer product support questions
tools:
  - name: send_email
    operations: [draft, send]
    approval_required_operations: [send]
"#;

    #[test]
    fn a_valid_remit_parses() {
        let r = Remit::from_yaml(VALID).unwrap();
        assert_eq!(r.agent, "customer-support-assistant");
        assert_eq!(r.limits.max_tool_calls, 40, "defaults apply when omitted");
    }

    #[test]
    fn a_misspelled_key_is_rejected_rather_than_ignored() {
        let src = VALID.replace("operations:", "operatons:");
        assert!(Remit::from_yaml(&src).is_err());
    }

    #[test]
    fn a_remit_without_a_purpose_is_rejected() {
        let src = "agent: a\nversion: \"1\"\npurpose: []\n";
        let err = Remit::from_yaml(src).unwrap_err();
        assert!(err.to_string().contains("no purpose"), "{err}");
    }

    #[test]
    fn a_remit_without_a_version_is_rejected() {
        let src = "agent: a\nversion: \"\"\npurpose: [x]\n";
        assert!(Remit::from_yaml(src).is_err());
    }

    #[test]
    fn approval_for_an_unpermitted_operation_is_rejected() {
        let src = r#"
agent: a
version: "1"
purpose: [x]
tools:
  - name: t
    operations: [read]
    approval_required_operations: [write]
"#;
        let err = Remit::from_yaml(src).unwrap_err();
        assert!(err.to_string().contains("not among its permitted"), "{err}");
    }

    #[test]
    fn an_empty_operation_list_is_rejected() {
        let src =
            "agent: a\nversion: \"1\"\npurpose: [x]\ntools:\n  - name: t\n    operations: []\n";
        assert!(Remit::from_yaml(src).is_err());
    }

    #[test]
    fn a_wildcard_destination_is_rejected() {
        let src =
            "agent: a\nversion: \"1\"\npurpose: [x]\nnetwork:\n  allowed_destinations: ['*']\n";
        let err = Remit::from_yaml(src).unwrap_err();
        assert!(err.to_string().contains("explicitly"), "{err}");
    }

    #[test]
    fn an_agent_name_that_is_unsafe_to_interpolate_is_rejected() {
        let src = "agent: ../etc\nversion: \"1\"\npurpose: [x]\n";
        assert!(Remit::from_yaml(src).is_err());
    }
}
