//! Deterministic local detections.
//!
//! A detection is a named, versioned claim about behaviour, with a severity and a *separate*
//! confidence. Those are different questions — "how bad would this be if real" and "how sure
//! are we it is real" — and collapsing them into one number is how alert queues become
//! unreadable.
//!
//! Rules are a fixed catalogue rather than a scripting surface. A detection rule that could
//! execute arbitrary code would be a way to run arbitrary code inside the security control,
//! which is precisely what the control exists to prevent.
//!
//! Every rule here fires from a decision VIGIL actually made. Nothing infers behaviour it did
//! not observe, and the brokers are the only observation point, so a process that bypasses
//! them produces no detections at all.

use crate::{LocalStore, RiskDimension};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vigil_common::{Result, VigilError};

/// Severity: how much damage this behaviour implies if the claim is correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        parse_severity(value)
    }
}

pub(crate) fn parse_severity(value: &str) -> Result<Severity> {
    match value {
        "INFO" => Ok(Severity::Info),
        "LOW" => Ok(Severity::Low),
        "MEDIUM" => Ok(Severity::Medium),
        "HIGH" => Ok(Severity::High),
        "CRITICAL" => Ok(Severity::Critical),
        _ => Err(VigilError::Serialization(format!(
            "database contains unknown severity `{value}`"
        ))),
    }
}

/// Confidence: how sure VIGIL is that the claim is correct. Deliberately separate from
/// severity, and deliberately coarse — three levels an operator can act on beats a percentage
/// nobody can calibrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "LOW" => Ok(Self::Low),
            "MEDIUM" => Ok(Self::Medium),
            "HIGH" => Ok(Self::High),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown confidence `{value}`"
            ))),
        }
    }
}

/// Agentic Runtime Security Tactics — a native taxonomy for what an agent was reaching for.
///
/// Kept separate from MITRE ATT&CK on purpose. Several of these have no honest ATT&CK
/// equivalent, and distorting an agent-specific detection to fit an existing framework makes
/// it worse at its actual job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Tactic {
    AgentDiscovery,
    CapabilityEscalation,
    CredentialAccess,
    ToolAbuse,
    DelegationAbuse,
    Persistence,
    PolicyEvasion,
    DataCollection,
    Exfiltration,
    DestructiveAction,
    SecurityControlEvasion,
    AgentToAgentAbuse,
}

impl Tactic {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentDiscovery => "AGENT_DISCOVERY",
            Self::CapabilityEscalation => "CAPABILITY_ESCALATION",
            Self::CredentialAccess => "CREDENTIAL_ACCESS",
            Self::ToolAbuse => "TOOL_ABUSE",
            Self::DelegationAbuse => "DELEGATION_ABUSE",
            Self::Persistence => "PERSISTENCE",
            Self::PolicyEvasion => "POLICY_EVASION",
            Self::DataCollection => "DATA_COLLECTION",
            Self::Exfiltration => "EXFILTRATION",
            Self::DestructiveAction => "DESTRUCTIVE_ACTION",
            Self::SecurityControlEvasion => "SECURITY_CONTROL_EVASION",
            Self::AgentToAgentAbuse => "AGENT_TO_AGENT_ABUSE",
        }
    }
}

/// One rule in the fixed catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub tactic: Tactic,
    pub description: &'static str,
    /// The risk dimension a firing loads, and by how much.
    pub dimension: RiskDimension,
    pub weight: u32,
}

/// Detection labels this crate emits, so a caller never spells one as a bare literal.
pub const DETECTION_BUDGET_EXHAUSTION: &str = "budget_exhaustion";
pub const DETECTION_UNEXPECTED_EXECUTABLE: &str = "unexpected_executable";
pub const DETECTION_UNEXPECTED_INTERPRETER: &str = "unexpected_interpreter";
pub const DETECTION_CREDENTIAL_UTILITY: &str = "credential_utility_invocation";
pub const DETECTION_PRIVILEGE_ATTEMPT: &str = "privilege_attempt";
pub const DETECTION_UNMEDIATED_NETWORK_UTILITY: &str = "unmediated_network_utility";
pub const DETECTION_UNKNOWN_NETWORK_DESTINATION: &str = "unknown_network_destination";
pub const DETECTION_DIRECT_IP_EGRESS: &str = "direct_ip_egress";
pub const DETECTION_DNS_REBINDING: &str = "dns_rebinding_or_private_destination";
pub const DETECTION_LOCAL_IPC_ESCALATION: &str = "local_ipc_escalation";
pub const DETECTION_CLOCK_REGRESSION: &str = "clock_regression";
pub const DETECTION_EXECUTABLE_IDENTITY_CHANGED: &str = "executable_identity_changed";
pub const DETECTION_WORKSPACE_STANDING_INHERITED: &str = "workspace_standing_inherited";
pub const DETECTION_SESSION_CHURN: &str = "session_churn";
pub const DETECTION_CREDENTIAL_ACCESS: &str = "credential_access";
pub const DETECTION_PERSISTENCE_ATTEMPT: &str = "persistence_attempt";
pub const DETECTION_SECURITY_CONTROL_MODIFICATION: &str = "security_control_modification";

/// Every detection label this crate can emit.
///
/// One list, referenced by both the emission sites and the tests. Before this existed the
/// tests carried their own hand-written copy, and five labels — `unknown_network_destination`,
/// `credential_utility_invocation`, `privilege_attempt`, `unmediated_network_utility`, and
/// `unexpected_executable` — were emitted with no rule behind them. They could never fire, and
/// nothing said so. `every_label_maps_to_a_rule_and_every_rule_is_reachable` now enforces the
/// bijection, so adding one without the other fails the build.
pub const ALL_DETECTION_LABELS: &[&str] = &[
    DETECTION_CREDENTIAL_ACCESS,
    DETECTION_PERSISTENCE_ATTEMPT,
    DETECTION_SECURITY_CONTROL_MODIFICATION,
    DETECTION_BUDGET_EXHAUSTION,
    DETECTION_UNEXPECTED_EXECUTABLE,
    DETECTION_LOCAL_IPC_ESCALATION,
    DETECTION_CLOCK_REGRESSION,
    DETECTION_EXECUTABLE_IDENTITY_CHANGED,
    DETECTION_WORKSPACE_STANDING_INHERITED,
    DETECTION_SESSION_CHURN,
    DETECTION_UNEXPECTED_INTERPRETER,
    DETECTION_CREDENTIAL_UTILITY,
    DETECTION_PRIVILEGE_ATTEMPT,
    DETECTION_UNMEDIATED_NETWORK_UTILITY,
    DETECTION_UNKNOWN_NETWORK_DESTINATION,
    DETECTION_DIRECT_IP_EGRESS,
    DETECTION_DNS_REBINDING,
    crate::approval::DETECTION_ESCALATION_PROBING,
    crate::approval::DETECTION_APPROVAL_FATIGUE,
    crate::mcp::DETECTION_MCP_CAPABILITY_DRIFT,
    crate::mcp::DETECTION_MCP_SERVER_SUBSTITUTION,
    crate::mcp::DETECTION_MCP_SCOPE_ESCAPE,
    crate::reconcile::DETECTION_DENIED_OPERATION_OBSERVED,
    crate::reconcile::DETECTION_INTENT_RESOURCE_MISMATCH,
    crate::reconcile::DETECTION_UNDECLARED_SIDE_EFFECT,
    crate::reconcile::DETECTION_UNDECLARED_CHILD_PROCESS,
    crate::reconcile::DETECTION_SCOPE_EXPANSION,
    crate::canary::DETECTION_CANARY_ACCESS,
    crate::git_broker::DETECTION_GIT_CONTROL_SURFACE,
    crate::git_broker::DETECTION_GIT_HISTORY_REWRITE,
    crate::git_broker::DETECTION_GIT_EXECUTABLE_CONFIG,
    crate::sequence::DETECTION_SENSITIVE_READ_THEN_EGRESS,
    crate::sequence::DETECTION_ARCHIVE_BEFORE_EGRESS,
    crate::sequence::DETECTION_INTERPRETER_CASCADE,
    crate::sequence::DETECTION_PROCESS_FAN_OUT,
    crate::sequence::DETECTION_CAPABILITY_LAUNDERING,
];

/// Version of the rule catalogue. Bump when a rule is added, removed, or reweighted, so a
/// stored detection stays interpretable against the rules that produced it.
pub const RULESET_VERSION: &str = "local/1.0.0";

/// The catalogue.
///
/// Each entry is reachable from a decision the brokers actually make. Rules for behaviour
/// VIGIL cannot yet observe locally — archive-before-egress, interpreter cascades, process
/// fan-out, MCP capability drift, deception interaction — are deliberately absent rather than
/// present and never firing.
pub const RULES: &[DetectionRule] = &[
    DetectionRule {
        id: "VIGIL-L001",
        name: "Credential access",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::CredentialAccess,
        description: "The session tried to reach a protected credential resource.",
        dimension: RiskDimension::CredentialAccess,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L002",
        name: "Persistence attempt",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::Persistence,
        description: "The session tried to write to a launch-agent or launch-daemon location.",
        dimension: RiskDimension::Persistence,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L003",
        name: "Security control modification",
        severity: Severity::Critical,
        confidence: Confidence::High,
        tactic: Tactic::SecurityControlEvasion,
        description: "The session tried to reach VIGIL's own configuration or evidence.",
        dimension: RiskDimension::PolicyEvasion,
        weight: 80,
    },
    DetectionRule {
        id: "VIGIL-L004",
        name: "Capability escalation probing",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::CapabilityEscalation,
        description: "The session re-requested a capability a human had already refused.",
        dimension: RiskDimension::PolicyEvasion,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L005",
        name: "Approval fatigue",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tactic: Tactic::PolicyEvasion,
        description: "The session generated approval requests faster than an operator can answer.",
        dimension: RiskDimension::CapabilityAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L006",
        name: "Unexpected interpreter",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::ToolAbuse,
        description: "The session tried to execute a shell or interpreter.",
        dimension: RiskDimension::ProcessAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L007",
        name: "Direct-IP egress",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::Exfiltration,
        description: "The session tried to connect to an IP literal, bypassing hostname policy.",
        dimension: RiskDimension::NetworkAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L008",
        name: "Private or rebound destination",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::Exfiltration,
        description: "A destination resolved to a private, link-local, or metadata address.",
        dimension: RiskDimension::NetworkAnomaly,
        weight: 40,
    },
    // Weight 60 contains the session on a single occurrence. That is deliberate and it is the
    // right call here: nothing a workspace-scoped coding agent legitimately does involves
    // reaching for a container socket or the SSH agent. A build tool probing for Docker would
    // do so by running `docker`, which the process broker already refuses — it would not open
    // the socket path through the filesystem broker.
    // Medium confidence because a backwards clock is often innocent — an NTP correction, a
    // laptop resuming, a VM restored from a snapshot. It is reported because the alternative
    // reading is an attempt to resurrect expired authority, and an operator should get to
    // decide which one it was. Nothing was resurrected either way: expiry used the monotone
    // time, not the wall clock.
    // High confidence: a binary that changes identity in the moment between being validated
    // and being executed is not something that happens by accident. A package upgrade could
    // in principle land in that window, which is why it is not weighted to quarantine alone.
    // Informational rather than alarming. Starting a new session after an incident is what a
    // person does when they are trying to get work done, and it is also what an agent does
    // when it is trying to shed containment. The finding says which workspace and which prior
    // session, and lets the operator decide; the authority consequence is carried by the
    // elevated standing, not by this weight.
    // Weight 20 elevates on its own, because the pattern it names is specifically an attempt
    // to get more authority than one session is allowed. It is not weighted higher: a person
    // iterating on a hard problem also starts sessions, and the evidence carries the
    // cumulative consumption so an operator can tell the two apart.
    DetectionRule {
        id: "VIGIL-L035",
        name: "Session churn on a workspace",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tactic: Tactic::CapabilityEscalation,
        description: "Sessions were started on one workspace faster than work explains, which \
                      multiplies the per-session blast-radius budget.",
        dimension: RiskDimension::CapabilityAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L034",
        name: "Session started on a recently contained workspace",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::PolicyEvasion,
        description: "A new session opened on a workspace whose previous session was contained.",
        dimension: RiskDimension::PolicyEvasion,
        weight: 10,
    },
    DetectionRule {
        id: "VIGIL-L033",
        name: "Executable changed between validation and execution",
        severity: Severity::Critical,
        confidence: Confidence::High,
        tactic: Tactic::ToolAbuse,
        description: "The binary at a validated path was replaced before it could be run.",
        dimension: RiskDimension::ProcessAnomaly,
        weight: 60,
    },
    DetectionRule {
        id: "VIGIL-L032",
        name: "System clock moved backwards",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tactic: Tactic::PolicyEvasion,
        description: "The system clock regressed materially, which would extend expired \
                      authority if expiry trusted it.",
        dimension: RiskDimension::PolicyEvasion,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L031",
        name: "Local IPC escalation endpoint",
        severity: Severity::Critical,
        confidence: Confidence::High,
        tactic: Tactic::CapabilityEscalation,
        description: "The session tried to reach a local socket that confers authority it was \
                      never granted, such as a container daemon or the SSH agent.",
        dimension: RiskDimension::PrivilegeEscalation,
        weight: 60,
    },
    DetectionRule {
        id: "VIGIL-L026",
        name: "Unknown network destination",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::Exfiltration,
        description: "The session tried to reach a destination outside its profile's allowlist.",
        dimension: RiskDimension::NetworkAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L027",
        name: "Credential utility invocation",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::CredentialAccess,
        description: "The session tried to run a tool whose purpose is reading stored secrets.",
        dimension: RiskDimension::CredentialAccess,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L028",
        name: "Privilege escalation attempt",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::CapabilityEscalation,
        description: "The session tried to run a privilege-escalation tool.",
        dimension: RiskDimension::PrivilegeEscalation,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L029",
        name: "Unmediated network utility",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::Exfiltration,
        description: "The session tried to run a network client that would bypass the broker.",
        dimension: RiskDimension::NetworkAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L030",
        name: "Unexpected executable",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tactic: Tactic::ToolAbuse,
        description: "The session tried to run a program outside the structured allowlist.",
        dimension: RiskDimension::ProcessAnomaly,
        weight: 10,
    },
    DetectionRule {
        id: "VIGIL-L009",
        name: "Blast-radius budget exhausted",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::DestructiveAction,
        description: "The session reached a quantitative limit its profile sets.",
        dimension: RiskDimension::DestructiveBehavior,
        weight: 20,
    },
];

/// Find a rule by the detection label a policy decision carries.
///
/// Labels are the existing vocabulary the policy ladder already emits, so a rule cannot fire
/// for something no decision names.
pub fn rule_for_label(label: &str) -> Option<&'static DetectionRule> {
    let id = match label {
        "credential_access" => "VIGIL-L001",
        "persistence_attempt" => "VIGIL-L002",
        "security_control_modification" => "VIGIL-L003",
        "capability_escalation_probing" => "VIGIL-L004",
        "approval_fatigue" => "VIGIL-L005",
        "unexpected_interpreter" => "VIGIL-L006",
        "direct_ip_egress" => "VIGIL-L007",
        "dns_rebinding_or_private_destination" => "VIGIL-L008",
        "budget_exhaustion" => "VIGIL-L009",
        DETECTION_UNKNOWN_NETWORK_DESTINATION => "VIGIL-L026",
        DETECTION_LOCAL_IPC_ESCALATION => "VIGIL-L031",
        DETECTION_CLOCK_REGRESSION => "VIGIL-L032",
        DETECTION_EXECUTABLE_IDENTITY_CHANGED => "VIGIL-L033",
        DETECTION_WORKSPACE_STANDING_INHERITED => "VIGIL-L034",
        DETECTION_SESSION_CHURN => "VIGIL-L035",
        DETECTION_CREDENTIAL_UTILITY => "VIGIL-L027",
        DETECTION_PRIVILEGE_ATTEMPT => "VIGIL-L028",
        DETECTION_UNMEDIATED_NETWORK_UTILITY => "VIGIL-L029",
        DETECTION_UNEXPECTED_EXECUTABLE => "VIGIL-L030",
        crate::mcp::DETECTION_MCP_CAPABILITY_DRIFT => "VIGIL-L010",
        crate::mcp::DETECTION_MCP_SERVER_SUBSTITUTION => "VIGIL-L011",
        crate::mcp::DETECTION_MCP_SCOPE_ESCAPE => "VIGIL-L012",
        crate::reconcile::DETECTION_DENIED_OPERATION_OBSERVED => "VIGIL-L013",
        crate::reconcile::DETECTION_INTENT_RESOURCE_MISMATCH => "VIGIL-L014",
        crate::reconcile::DETECTION_UNDECLARED_SIDE_EFFECT => "VIGIL-L015",
        crate::reconcile::DETECTION_UNDECLARED_CHILD_PROCESS => "VIGIL-L016",
        crate::reconcile::DETECTION_SCOPE_EXPANSION => "VIGIL-L017",
        crate::canary::DETECTION_CANARY_ACCESS => "VIGIL-L018",
        crate::git_broker::DETECTION_GIT_CONTROL_SURFACE => "VIGIL-L019",
        crate::git_broker::DETECTION_GIT_HISTORY_REWRITE => "VIGIL-L020",
        crate::git_broker::DETECTION_GIT_EXECUTABLE_CONFIG => "VIGIL-L021",
        crate::sequence::DETECTION_SENSITIVE_READ_THEN_EGRESS => "VIGIL-L022",
        crate::sequence::DETECTION_ARCHIVE_BEFORE_EGRESS => "VIGIL-L023",
        crate::sequence::DETECTION_INTERPRETER_CASCADE => "VIGIL-L024",
        crate::sequence::DETECTION_PROCESS_FAN_OUT => "VIGIL-L025",
        crate::sequence::DETECTION_CAPABILITY_LAUNDERING => "VIGIL-L026-LAUNDERING",
        _ => return None,
    };
    all_rules().find(|rule| rule.id == id)
}

/// Every rule, from this module's catalogue and the MCP one.
///
/// MCP rules live beside the code that fires them so the catalogue and the logic cannot drift
/// apart, but they are part of one namespace and share the `VIGIL-L###` sequence.
pub fn all_rules() -> impl Iterator<Item = &'static DetectionRule> {
    RULES
        .iter()
        .chain(crate::mcp::MCP_RULES.iter())
        .chain(crate::reconcile::RECONCILE_RULES.iter())
        .chain(crate::canary::CANARY_RULES.iter())
        .chain(crate::git_broker::GIT_RULES.iter())
        .chain(crate::sequence::SEQUENCE_RULES.iter())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub detection_id: String,
    pub session_id: String,
    pub at: DateTime<Utc>,
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub tactic: String,
    pub description: String,
    /// Metadata only. Never file content, never argument values, never secret material.
    pub evidence: serde_json::Value,
    pub source_event_id: Option<String>,
    pub incident_id: Option<String>,
}

impl LocalStore {
    /// Record one detection and load the risk dimension it implies.
    ///
    /// Returns the detection together with the session's risk state after it, because the
    /// caller almost always needs to know whether this firing changed the session's standing.
    pub fn record_detection(
        &self,
        session_id: &str,
        rule: &DetectionRule,
        evidence: serde_json::Value,
        source_event_id: Option<&str>,
    ) -> Result<Detection> {
        let detection = Detection {
            detection_id: format!("det_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.to_string(),
            at: Utc::now(),
            rule_id: rule.id.to_string(),
            name: rule.name.to_string(),
            severity: rule.severity,
            confidence: rule.confidence,
            tactic: rule.tactic.as_str().to_string(),
            description: rule.description.to_string(),
            evidence,
            source_event_id: source_event_id.map(str::to_string),
            incident_id: None,
        };
        self.connection
            .execute(
                "INSERT INTO detections
                 (detection_id, session_id, at, rule_id, name, severity, confidence, tactic,
                  description, evidence_json, source_event_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    detection.detection_id,
                    detection.session_id,
                    detection.at.to_rfc3339(),
                    detection.rule_id,
                    detection.name,
                    detection.severity.as_str(),
                    detection.confidence.as_str(),
                    detection.tactic,
                    detection.description,
                    serde_json::to_string(&detection.evidence)?,
                    detection.source_event_id,
                ],
            )
            .map_err(super::store::storage_error)?;
        Ok(detection)
    }

    pub fn detections_for_session(&self, session_id: &str) -> Result<Vec<Detection>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT detection_id, session_id, at, rule_id, name, severity, confidence,
                        tactic, description, evidence_json, source_event_id, incident_id
                 FROM detections WHERE session_id = ?1 ORDER BY at, detection_id",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([session_id], detection_from_row)
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }

    /// List detections across sessions, newest first.
    pub fn list_detections(&self, limit: usize) -> Result<Vec<Detection>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        let mut statement = self
            .connection
            .prepare(
                "SELECT detection_id, session_id, at, rule_id, name, severity, confidence,
                        tactic, description, evidence_json, source_event_id, incident_id
                 FROM detections ORDER BY at DESC, detection_id LIMIT ?1",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([limit], detection_from_row)
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }
}

fn detection_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Detection>> {
    let detection_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let at: String = row.get(2)?;
    let rule_id: String = row.get(3)?;
    let name: String = row.get(4)?;
    let severity: String = row.get(5)?;
    let confidence: String = row.get(6)?;
    let tactic: String = row.get(7)?;
    let description: String = row.get(8)?;
    let evidence: String = row.get(9)?;
    let source_event_id: Option<String> = row.get(10)?;
    let incident_id: Option<String> = row.get(11)?;

    Ok((|| {
        Ok(Detection {
            detection_id,
            session_id,
            at: DateTime::parse_from_rfc3339(&at)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|error| VigilError::Serialization(error.to_string()))?,
            rule_id,
            name,
            severity: Severity::parse(&severity)?,
            confidence: Confidence::parse(&confidence)?,
            tactic,
            description,
            evidence: serde_json::from_str(&evidence)?,
            source_event_id,
            incident_id,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bijection. A label with no rule is a detection that can never fire; a rule with no
    /// label is a rule nothing can reach. Both are silent failures, and both used to be
    /// possible because the tests kept their own copy of the label list.
    #[test]
    fn every_label_maps_to_a_rule_and_every_rule_is_reachable() {
        for label in ALL_DETECTION_LABELS {
            assert!(
                rule_for_label(label).is_some(),
                "label `{label}` has no detection rule, so it can never fire"
            );
        }
        for rule in all_rules() {
            assert!(
                ALL_DETECTION_LABELS
                    .iter()
                    .any(|label| rule_for_label(label).is_some_and(|found| found.id == rule.id)),
                "rule {} is unreachable from any label",
                rule.id
            );
        }
        assert!(rule_for_label("not-a-real-label").is_none());
    }

    #[test]
    fn rule_identifiers_are_unique() {
        let mut ids: Vec<_> = all_rules().map(|rule| rule.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate detection rule id");
    }

    /// Labels are constants, not literals, so an emission site cannot invent one.
    #[test]
    fn no_label_is_duplicated() {
        let mut labels: Vec<_> = ALL_DETECTION_LABELS.to_vec();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "duplicate detection label");
    }

    #[test]
    fn severity_and_confidence_are_independent() {
        // A rule may be severe but uncertain, or mild and certain. If the catalogue ever
        // collapsed them, every entry would sit on the diagonal.
        let off_diagonal = all_rules().any(|rule| {
            matches!(
                (rule.severity, rule.confidence),
                (Severity::Medium, Confidence::High) | (Severity::High, Confidence::Medium)
            )
        });
        assert!(
            off_diagonal,
            "severity and confidence have collapsed into one axis"
        );
    }

    #[test]
    fn only_the_control_plane_rule_can_quarantine_a_session_alone() {
        // A single firing that immediately quarantines is a big hammer. Exactly one rule is
        // allowed to be that: an agent reaching for VIGIL's own evidence.
        let alone: Vec<_> = all_rules()
            .filter(|rule| rule.weight >= 80)
            .map(|rule| rule.id)
            .collect();
        // Reaching for VIGIL's own evidence, and swapping the binary behind a trusted MCP
        // server. Both are unambiguous, and both mean the session is no longer what it was.
        // Three rules, each unambiguous on its own:
        //   L003 — an agent reaching for VIGIL's own evidence;
        //   L011 — the binary behind a trusted MCP server was swapped;
        //   L013 — VIGIL refused an operation and the OS observed it happen anyway.
        // The last is the only finding in the system that proves the broker was bypassed.
        assert_eq!(alone, ["VIGIL-L003", "VIGIL-L011", "VIGIL-L013"]);
    }
}
