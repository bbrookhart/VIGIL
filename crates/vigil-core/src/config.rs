//! Core configuration.
//!
//! Every field here changes security posture, so each carries the reasoning for its default
//! and the consequence of changing it. Defaults are the safe end of each choice; loosening
//! one is a decision someone should have to write down.

use serde::{Deserialize, Serialize};

/// How VIGIL is deployed relative to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// The agent cannot reach protected tools except through the VIGIL Gateway, and holds no
    /// long-lived execution credentials. This is the mode the product promise depends on.
    Protected,
    /// VIGIL observes and decides but cannot prevent execution, because the agent retains
    /// direct access. Useful for evaluation and for the first weeks of a rollout.
    ///
    /// A deployment in this mode has *not* met the non-bypassability requirement, and the
    /// console labels it accordingly rather than implying protection it cannot provide.
    Observability,
}

impl EnforcementMode {
    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Protected)
    }
}

/// Runtime configuration for VIGIL Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    #[serde(default = "default_mode")]
    pub mode: EnforcementMode,

    /// Whether a verified workload identity is required in Protected mode.
    ///
    /// Default true. With it false, any process that can reach Core can claim to be any
    /// agent, which reduces agent identity to an assertion — acceptable only inside a
    /// trust boundary that already authenticates the caller some other way.
    #[serde(default = "default_true")]
    pub require_workload_identity: bool,

    /// Whether agents with no registered remit may act.
    ///
    /// Default false. True is a development convenience: it means an unregistered agent is
    /// governed by policy alone, with no declared purpose to check drift against.
    #[serde(default)]
    pub allow_unregistered_agents: bool,

    /// Lifetime of minted capabilities, in seconds.
    #[serde(default = "default_capability_ttl")]
    pub capability_ttl_seconds: i64,

    /// Whether to skip semantic detectors once the deterministic layers have denied.
    ///
    /// Default true: it saves the cost of analysis that cannot change the outcome. Set false
    /// when building the evaluation corpus, where detector output is wanted for every case
    /// including ones policy already blocks.
    #[serde(default = "default_true")]
    pub skip_detectors_on_deterministic_deny: bool,

    /// Roles that may approve when a policy rule does not name a set.
    #[serde(default = "default_approver_roles")]
    pub default_approver_roles: Vec<String>,

    /// Maximum accepted request body size, in bytes.
    #[serde(default = "default_max_body_bytes")]
    pub max_request_body_bytes: usize,

    /// Deadline for a whole decision, in milliseconds.
    ///
    /// Exceeding it fails closed for anything above Tier 1 — a decision that never returns
    /// must not become an implicit allow when the caller times out.
    #[serde(default = "default_decision_deadline_ms")]
    pub decision_deadline_ms: u64,

    /// How long a session may live before its state is evicted.
    #[serde(default = "default_session_max_minutes")]
    pub session_max_lifetime_minutes: i64,
}

fn default_mode() -> EnforcementMode {
    EnforcementMode::Protected
}
fn default_true() -> bool {
    true
}
fn default_capability_ttl() -> i64 {
    vigil_capability::DEFAULT_CAPABILITY_TTL_SECONDS
}
fn default_approver_roles() -> Vec<String> {
    vec![
        "SecurityAnalyst".to_string(),
        "TenantAdmin".to_string(),
        "IncidentResponder".to_string(),
    ]
}
fn default_max_body_bytes() -> usize {
    1024 * 1024
}
fn default_decision_deadline_ms() -> u64 {
    500
}
fn default_session_max_minutes() -> i64 {
    240
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            require_workload_identity: true,
            allow_unregistered_agents: false,
            capability_ttl_seconds: default_capability_ttl(),
            skip_detectors_on_deterministic_deny: true,
            default_approver_roles: default_approver_roles(),
            max_request_body_bytes: default_max_body_bytes(),
            decision_deadline_ms: default_decision_deadline_ms(),
            session_max_lifetime_minutes: default_session_max_minutes(),
        }
    }
}

impl CoreConfig {
    /// A configuration suitable for local development and tests.
    ///
    /// Named so it is obvious in a diff when it appears somewhere it should not. It relaxes
    /// workload identity and unregistered agents; it does **not** relax any enforcement
    /// decision, so tests still exercise real policy.
    pub fn development() -> Self {
        Self {
            require_workload_identity: false,
            allow_unregistered_agents: true,
            ..Self::default()
        }
    }

    /// Reject configurations that would quietly disable enforcement.
    pub fn validate(&self) -> vigil_common::Result<()> {
        if self.capability_ttl_seconds > vigil_capability::MAX_CAPABILITY_TTL_SECONDS {
            return Err(vigil_common::VigilError::Config(format!(
                "capability_ttl_seconds exceeds the maximum of {}",
                vigil_capability::MAX_CAPABILITY_TTL_SECONDS
            )));
        }
        if self.capability_ttl_seconds < 1 {
            return Err(vigil_common::VigilError::Config(
                "capability_ttl_seconds must be at least 1".to_string(),
            ));
        }
        if self.mode == EnforcementMode::Protected
            && !self.require_workload_identity
            && !cfg!(debug_assertions)
        {
            tracing::warn!(
                "protected mode with require_workload_identity=false: agent identity is \
                 self-asserted and cannot be relied upon"
            );
        }
        if self.max_request_body_bytes == 0 {
            return Err(vigil_common::VigilError::Config(
                "max_request_body_bytes must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_safe_end_of_every_choice() {
        let c = CoreConfig::default();
        assert_eq!(c.mode, EnforcementMode::Protected);
        assert!(c.require_workload_identity);
        assert!(!c.allow_unregistered_agents);
        assert!(c.capability_ttl_seconds <= vigil_capability::MAX_CAPABILITY_TTL_SECONDS);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn an_over_long_capability_ttl_is_rejected_at_startup() {
        let c = CoreConfig {
            capability_ttl_seconds: 86_400,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn development_config_relaxes_identity_but_not_enforcement() {
        let c = CoreConfig::development();
        assert!(!c.require_workload_identity);
        assert_eq!(
            c.mode,
            EnforcementMode::Protected,
            "development must still exercise real enforcement"
        );
        assert!(c.validate().is_ok());
    }

    #[test]
    fn an_unknown_config_key_is_rejected() {
        let json = r#"{"mode":"protected","requre_workload_identity":true}"#;
        assert!(serde_json::from_str::<CoreConfig>(json).is_err());
    }

    #[test]
    fn observability_mode_reports_that_it_does_not_enforce() {
        assert!(!EnforcementMode::Observability.is_enforcing());
        assert!(EnforcementMode::Protected.is_enforcing());
    }
}
