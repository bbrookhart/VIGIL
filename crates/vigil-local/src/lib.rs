//! Local macOS control-plane primitives.
//!
//! This crate is the entitlement-independent half of the local VIGIL runtime: durable
//! sessions, normalized local events, and bounded workspace policy. It deliberately does
//! not claim OS enforcement. Endpoint Security and Network Extension adapters will consume
//! these decisions in later phases; until then the launcher reports `observe_only`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod approval;
mod authorize;
mod broker;
mod budget;
mod canary;
mod checkpoint;
mod clock;
mod detection;
mod git_broker;
mod incident;
mod lease;
mod mcp;
mod mcp_proxy;
mod network_broker;
mod policy;
mod process_broker;
mod provenance;
mod reconcile;
mod risk;
mod rollback;
mod secret_broker;
mod sequence;
mod store;

pub use approval::{
    fingerprint, ApprovalOutcome, ApprovalRequest, ApprovalStatus, ApproverIdentity, CapabilityAsk,
    APPROVAL_TTL_SECONDS, DETECTION_APPROVAL_FATIGUE, DETECTION_ESCALATION_PROBING,
};
pub use authorize::LocalAuthorization;
pub use broker::{BrokerResult, FilesystemBroker};
pub use budget::{
    budget_limit, BudgetCharge, BudgetCounter, BudgetDimension, BudgetReservation,
    ReservationStatus,
};
pub use canary::{Canary, CanaryKind, CANARY_MARKER, CANARY_RULES, DETECTION_CANARY_ACCESS};
pub use checkpoint::{
    CheckpointFailure, LocalCheckpoint, LocalCheckpointSigner, LocalCheckpointVerifier,
};
pub use clock::{ClockReading, CLOCK_REGRESSION_TOLERANCE_SECONDS};
pub use detection::{
    all_rules, rule_for_label, Confidence, Detection, DetectionRule, Severity, Tactic,
    ALL_DETECTION_LABELS, DETECTION_BUDGET_EXHAUSTION, DETECTION_CLOCK_REGRESSION,
    DETECTION_CREDENTIAL_ACCESS, DETECTION_CREDENTIAL_UTILITY, DETECTION_DIRECT_IP_EGRESS,
    DETECTION_DNS_REBINDING, DETECTION_EXECUTABLE_IDENTITY_CHANGED, DETECTION_LOCAL_IPC_ESCALATION,
    DETECTION_PERSISTENCE_ATTEMPT, DETECTION_PRIVILEGE_ATTEMPT,
    DETECTION_SECURITY_CONTROL_MODIFICATION, DETECTION_SESSION_CHURN,
    DETECTION_UNEXPECTED_EXECUTABLE, DETECTION_UNEXPECTED_INTERPRETER,
    DETECTION_UNKNOWN_NETWORK_DESTINATION, DETECTION_UNMEDIATED_NETWORK_UTILITY,
    DETECTION_WORKSPACE_STANDING_INHERITED, RULES, RULESET_VERSION,
};
pub use git_broker::{
    remote_host, GitBroker, GitRequest, GitResult, DETECTION_GIT_CONTROL_SURFACE,
    DETECTION_GIT_EXECUTABLE_CONFIG, DETECTION_GIT_HISTORY_REWRITE, GIT_RULES,
};
pub use incident::{Incident, IncidentResponse, IncidentStatus, ResponseAction, ResponseOutcome};
pub use lease::{
    CapabilityLease, LeaseState, DEFAULT_LEASE_TTL_SECONDS, MAX_LEASE_TTL_SECONDS, MAX_LEASE_USES,
};
pub use mcp::{
    extract_resources, ExtractedResource, McpAuthorization, McpDrift, McpResourceDecision,
    McpServer, McpTool, McpToolCall, McpToolManifest, McpTransport, McpTrustState, ResourceKind,
    DETECTION_MCP_CAPABILITY_DRIFT, DETECTION_MCP_SCOPE_ESCAPE, DETECTION_MCP_SERVER_SUBSTITUTION,
    MCP_RULES,
};
pub use mcp_proxy::{
    inspect_client_message, inspect_server_message, refusal_response, render, ClientIntent,
    McpProxyCorrelation, ServerIntent, MAX_MESSAGE_BYTES, MAX_TOOLS_PER_RESPONSE,
    REFUSED_ERROR_CODE,
};
pub use network_broker::{
    NetworkBroker, NetworkEventSource, NetworkProbeRequest, NetworkProbeResult,
    SimulatedNetworkSource, SystemNetworkSource,
};
pub use policy::{
    classify_executable, evaluate, evaluate_in_context, evaluate_process,
    evaluate_process_in_context, normalize_workspace, DecisionOutcome, ExecutableClass,
    LeaseStatus, LocalAction, LocalDecision, LocalProfile, LocalRequest, RiskState,
};
pub use process_broker::{ProcessBroker, ProcessBrokerResult, ProcessRequest};
pub use provenance::{
    ProcessEdge, ProcessGraph, ProcessNode, ProcessStatus, MAX_PROCESS_GENERATION,
};
pub use reconcile::{
    reconcile, Coverage, DeclaredIntent, Mismatch, MismatchClass, ObservedKind, ObservedOperation,
    Reconciliation, DETECTION_DENIED_OPERATION_OBSERVED, DETECTION_INTENT_RESOURCE_MISMATCH,
    DETECTION_SCOPE_EXPANSION, DETECTION_UNDECLARED_CHILD_PROCESS,
    DETECTION_UNDECLARED_SIDE_EFFECT, RECONCILE_RULES,
};
pub use risk::{
    aggregate_state, DimensionScore, RiskAssessment, RiskDimension, RiskTransition,
    MAX_SIGNAL_WEIGHT,
};
pub use rollback::{
    PostimageState, PriorState, RestoreOutcome, RollbackReport, WritePreimage, MAX_PRESERVED_BYTES,
};
pub use secret_broker::{
    SecretBroker, SecretBrokerPolicy, SecretKind, SecretMetadata, SecretMetadataResult,
    SecretProvider, SecretUseGrant, SecretUsePurpose, SecretUseRequest, SecretUseResult,
    SimulatedSecretProvider,
};
pub use sequence::{
    AnalysisReport, SequenceFinding, DETECTION_ARCHIVE_BEFORE_EGRESS,
    DETECTION_CAPABILITY_LAUNDERING, DETECTION_INTERPRETER_CASCADE, DETECTION_PROCESS_FAN_OUT,
    DETECTION_SENSITIVE_READ_THEN_EGRESS, SEQUENCE_RULES,
};
pub use store::{
    ChainFailure, ChainVerification, LocalEvent, LocalSession, LocalStore, NewSession,
    SessionStatus,
};
