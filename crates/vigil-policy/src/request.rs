//! The typed authorization question: principal, action, resource, context.
//!
//! This shape is deliberately provider-neutral. Cedar, OPA/Rego and the built-in rule engine
//! all answer the same question, so VIGIL Core never depends on which one is deployed
//! (spec §9) — swapping providers must not change what Core knows how to ask.

use serde::{Deserialize, Serialize};
use vigil_common::ids::{
    AgentId, EnvironmentId, PolicyBundleId, PrincipalId, SessionId, TenantId, ToolId,
};
use vigil_protocol::action::{ImpactTier, SideEffectClass};
use vigil_protocol::decision::{Constraint, Decision, Obligation};
use vigil_protocol::reason::ReasonCode;
use vigil_protocol::trust::{TaintKind, TrustLevel};

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPrincipal {
    pub id: PrincipalId,
    pub tenant_id: TenantId,
    pub kind: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub mfa: bool,
    /// The agent acting for this principal.
    pub agent_id: AgentId,
    /// Agents this work passed through, oldest first, for delegation rules.
    #[serde(default)]
    pub delegation_lineage: Vec<AgentId>,
}

/// What they want to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyAction {
    /// Action class: `tool_call`, `network`, `shell`, `file`, `database`, …
    pub kind: String,
    /// The operation within that class: `send`, `POST`, `read`, `DROP`.
    pub operation: String,
    pub side_effect: SideEffectClass,
    pub impact_tier: ImpactTier,
}

/// What they want to do it to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyResource {
    /// Canonical resource name, matched by glob: a tool name, `net:host`, `file:read`.
    pub name: String,
    #[serde(default)]
    pub tool_id: Option<ToolId>,
    /// Destination hostname for network-bearing actions, already lowercased.
    #[serde(default)]
    pub destination_host: Option<String>,
    /// Filesystem paths the action touches, already normalized.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Data classes the action reads or writes.
    #[serde(default)]
    pub data_classes: Vec<String>,
}

/// Everything else the decision depends on.
///
/// This is where VIGIL differs from a conventional authorization system: the same principal
/// performing the same operation on the same resource can be allowed or denied depending on
/// whether untrusted content influenced the request. Those signals live here.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyContext {
    pub environment_id: Option<EnvironmentId>,
    pub session_id: Option<SessionId>,
    /// Lowest trust level among the sources that influenced this action.
    #[serde(default)]
    pub lowest_influencing_trust: Option<TrustLevel>,
    /// Whether untrusted, instruction-like content is among those influences.
    #[serde(default)]
    pub untrusted_instruction_influence: bool,
    /// Taints carried by the action's content.
    #[serde(default)]
    pub taints: Vec<TaintKind>,
    /// Whether a valid approval already covers this exact action.
    #[serde(default)]
    pub approval_satisfied: bool,
    /// How many actions this session has already had denied.
    #[serde(default)]
    pub prior_denials: u32,
    /// Delegation depth, for multi-agent rules.
    #[serde(default)]
    pub delegation_depth: u32,
}

/// The complete authorization question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub principal: PolicyPrincipal,
    pub action: PolicyAction,
    pub resource: PolicyResource,
    #[serde(default)]
    pub context: PolicyContext,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    /// Rule ids that matched, in bundle order, for attribution.
    #[serde(default)]
    pub matched_policies: Vec<String>,
    #[serde(default)]
    pub reason_codes: Vec<ReasonCode>,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    /// The bundle that produced this, recorded on every decision (Invariant 9).
    pub bundle_version: PolicyBundleId,
    /// Highest severity among matched rules, for alert routing.
    #[serde(default)]
    pub severity: Option<String>,
}

impl PolicyDecision {
    pub fn permits_execution(&self) -> bool {
        self.decision.permits_execution()
    }
}
