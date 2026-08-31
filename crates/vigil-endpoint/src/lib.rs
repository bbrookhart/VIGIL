//! Deadline-safe Endpoint Security authorization model.
//!
//! This crate contains no Apple framework calls. It is the deterministic contract shared by the
//! native adapter and entitlement-free simulation: immutable policy data, audit-token process
//! attribution, bounded path/exec decisions, per-message deadline guards, sequence-gap detection,
//! and authorization latency metrics. The authorization path performs no I/O, allocation-heavy
//! policy compilation, database access, network calls, UI work, or model inference.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use vigil_common::{Result, VigilError};

mod snapshot;
pub use snapshot::{
    EndpointPolicySigningKey, EndpointPolicySnapshot, EndpointPolicyVerifier,
    SignedEndpointPolicyEnvelope, ENDPOINT_POLICY_ALGORITHM, ENDPOINT_POLICY_FORMAT,
    ENDPOINT_POLICY_SCHEMA,
};

pub const OPEN_READ: u32 = 1 << 0;
pub const OPEN_WRITE: u32 = 1 << 1;
pub const OPEN_EXECUTE: u32 = 1 << 2;
pub const OPEN_KNOWN_FLAGS: u32 = OPEN_READ | OPEN_WRITE | OPEN_EXECUTE;

const MAX_SESSIONS: usize = 1_024;
const MAX_ATTRIBUTIONS: usize = 16_384;
const MAX_WORKSPACES_PER_SESSION: usize = 16;
const MAX_EXECUTABLES_PER_SESSION: usize = 256;
const MAX_PROTECTED_PREFIXES: usize = 128;
const MAX_PATH_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessKey(pub [u8; 32]);

impl ProcessKey {
    pub const fn synthetic(value: u8) -> Self {
        Self([value; 32])
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub key: ProcessKey,
    pub pid: i32,
    pub parent_pid: i32,
    pub executable: EndpointPath,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub is_platform_binary: bool,
    pub is_es_client: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointPath {
    pub value: String,
    pub truncated: bool,
}

impl EndpointPath {
    pub fn complete(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            truncated: false,
        }
    }

    pub fn truncated(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            truncated: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointEventType {
    AuthExec,
    AuthOpen,
    AuthCreate,
    AuthRename,
    AuthUnlink,
    NotifyFork,
    NotifyExit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EndpointOperation {
    AuthExec {
        target: ProcessIdentity,
    },
    AuthOpen {
        file: EndpointPath,
        requested_flags: u32,
    },
    AuthCreate {
        destination: EndpointPath,
    },
    AuthRename {
        source: EndpointPath,
        destination: EndpointPath,
    },
    AuthUnlink {
        target: EndpointPath,
    },
    NotifyFork {
        child: ProcessIdentity,
    },
    NotifyExit {
        status: i32,
    },
}

impl EndpointOperation {
    pub const fn event_type(&self) -> EndpointEventType {
        match self {
            Self::AuthExec { .. } => EndpointEventType::AuthExec,
            Self::AuthOpen { .. } => EndpointEventType::AuthOpen,
            Self::AuthCreate { .. } => EndpointEventType::AuthCreate,
            Self::AuthRename { .. } => EndpointEventType::AuthRename,
            Self::AuthUnlink { .. } => EndpointEventType::AuthUnlink,
            Self::NotifyFork { .. } => EndpointEventType::NotifyFork,
            Self::NotifyExit { .. } => EndpointEventType::NotifyExit,
        }
    }

    pub const fn is_authorization(&self) -> bool {
        matches!(
            self,
            Self::AuthExec { .. }
                | Self::AuthOpen { .. }
                | Self::AuthCreate { .. }
                | Self::AuthRename { .. }
                | Self::AuthUnlink { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEvent {
    pub actor: ProcessIdentity,
    pub operation: EndpointOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEnvelope {
    /// Monotonic nanoseconds in the source's clock domain.
    pub observed_at_ns: u64,
    /// Per-message authorization deadline, normalized to the same clock domain.
    pub deadline_ns: Option<u64>,
    /// Per-event-type sequence, available in ES message version 2 and later.
    pub sequence: Option<u64>,
    /// Global sequence, available in ES message version 4 and later.
    pub global_sequence: Option<u64>,
    pub event: EndpointEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointVerdict {
    Allow,
    Deny,
    Observe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EndpointResponse {
    Auth { allow: bool, cache: bool },
    OpenFlags { authorized_flags: u32, cache: bool },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointReason {
    UnmanagedProcess,
    NotificationOnly,
    PermitExactExecutable,
    DenyExecutable,
    PermitWorkspacePath,
    DenyOutsideWorkspace,
    DenyProtectedPath,
    DenyTruncatedPath,
    DenyMalformedPath,
    DenyUnknownOpenFlags,
    DenyMalformedProcessIdentity,
    DenyMissingSessionPolicy,
    DenyDeadlineGuard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDecision {
    pub event_type: EndpointEventType,
    pub verdict: EndpointVerdict,
    pub response: EndpointResponse,
    pub reason: EndpointReason,
    pub session_id: Option<String>,
    pub authorization_latency_ns: u64,
    pub deadline_remaining_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnforcementPolicy {
    pub session_id: String,
    pub workspace_roots: Vec<String>,
    pub allowed_executables: BTreeSet<String>,
}

impl SessionEnforcementPolicy {
    pub fn new(
        session_id: impl Into<String>,
        workspace_roots: Vec<String>,
        allowed_executables: BTreeSet<String>,
    ) -> Result<Self> {
        let policy = Self {
            session_id: session_id.into(),
            workspace_roots,
            allowed_executables,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        let session_id = &self.session_id;
        if session_id.is_empty() || session_id.len() > 128 {
            return Err(VigilError::InvalidValue {
                field: "session_id",
                reason: "session identifier is empty or exceeds its bound".to_string(),
            });
        }
        if self.workspace_roots.is_empty()
            || self.workspace_roots.len() > MAX_WORKSPACES_PER_SESSION
        {
            return Err(VigilError::InvalidValue {
                field: "workspace_roots",
                reason: "one to sixteen workspace roots are required".to_string(),
            });
        }
        if self.allowed_executables.len() > MAX_EXECUTABLES_PER_SESSION {
            return Err(VigilError::InvalidValue {
                field: "allowed_executables",
                reason: "executable allowlist exceeds its fast-path bound".to_string(),
            });
        }
        for path in self
            .workspace_roots
            .iter()
            .chain(self.allowed_executables.iter())
        {
            validate_precompiled_path(path)?;
        }
        Ok(())
    }
}

/// Compact mutable state owned by one serial event-processing lane.
///
/// Policy compilation and path canonicalization happen before construction. Evaluation itself
/// performs only bounded map/set lookup and component-aware path comparisons.
#[derive(Debug, Clone)]
pub struct FastPathState {
    sessions: BTreeMap<String, SessionEnforcementPolicy>,
    attributions: BTreeMap<ProcessKey, String>,
    protected_prefixes: Vec<String>,
    deadline_safety_margin_ns: u64,
}

impl FastPathState {
    pub fn new(
        policies: Vec<SessionEnforcementPolicy>,
        protected_prefixes: Vec<String>,
        deadline_safety_margin_ns: u64,
    ) -> Result<Self> {
        if policies.len() > MAX_SESSIONS {
            return Err(VigilError::InvalidValue {
                field: "sessions",
                reason: "session policy count exceeds its fast-path bound".to_string(),
            });
        }
        if protected_prefixes.len() > MAX_PROTECTED_PREFIXES {
            return Err(VigilError::InvalidValue {
                field: "protected_prefixes",
                reason: "protected path count exceeds its fast-path bound".to_string(),
            });
        }
        for path in &protected_prefixes {
            validate_precompiled_path(path)?;
        }
        let mut sessions = BTreeMap::new();
        for policy in policies {
            policy.validate()?;
            if sessions.insert(policy.session_id.clone(), policy).is_some() {
                return Err(VigilError::InvalidValue {
                    field: "sessions",
                    reason: "duplicate session policy".to_string(),
                });
            }
        }
        Ok(Self {
            sessions,
            attributions: BTreeMap::new(),
            protected_prefixes,
            deadline_safety_margin_ns,
        })
    }

    pub fn bind_root(&mut self, process: ProcessKey, session_id: &str) -> Result<()> {
        if process.is_zero() {
            return Err(VigilError::InvalidValue {
                field: "audit_token",
                reason: "zero audit token cannot identify a process execution".to_string(),
            });
        }
        if !self.sessions.contains_key(session_id) {
            return Err(VigilError::NotFound("endpoint session policy".to_string()));
        }
        if let Some(existing) = self.attributions.get(&process) {
            if existing != session_id {
                return Err(VigilError::Unauthorized(
                    "endpoint process identity is already bound".to_string(),
                ));
            }
            return Ok(());
        }
        if self.attributions.len() >= MAX_ATTRIBUTIONS && !self.attributions.contains_key(&process)
        {
            return Err(VigilError::BudgetExhausted(
                "endpoint attribution table is full".to_string(),
            ));
        }
        self.attributions.insert(process, session_id.to_string());
        Ok(())
    }

    pub fn attributed_session(&self, process: ProcessKey) -> Option<&str> {
        self.attributions.get(&process).map(String::as_str)
    }

    pub fn attribution_count(&self) -> usize {
        self.attributions.len()
    }

    pub fn evaluate(&self, envelope: &EndpointEnvelope, processed_at_ns: u64) -> EndpointDecision {
        let event_type = envelope.event.operation.event_type();
        let latency = processed_at_ns.saturating_sub(envelope.observed_at_ns);
        let remaining = envelope
            .deadline_ns
            .map(|deadline| deadline.saturating_sub(processed_at_ns));
        let session_id = self
            .attributed_session(envelope.event.actor.key)
            .map(str::to_string);

        if !envelope.event.operation.is_authorization() {
            return EndpointDecision {
                event_type,
                verdict: EndpointVerdict::Observe,
                response: EndpointResponse::None,
                reason: EndpointReason::NotificationOnly,
                session_id,
                authorization_latency_ns: latency,
                deadline_remaining_ns: remaining,
            };
        }
        let Some(session_id) = session_id else {
            return decision(
                event_type,
                EndpointVerdict::Allow,
                response_for(&envelope.event.operation, true),
                EndpointReason::UnmanagedProcess,
                None,
                latency,
                remaining,
            );
        };
        let Some(policy) = self.sessions.get(&session_id) else {
            return decision(
                event_type,
                EndpointVerdict::Deny,
                response_for(&envelope.event.operation, false),
                EndpointReason::DenyMissingSessionPolicy,
                Some(session_id),
                latency,
                remaining,
            );
        };
        if envelope.deadline_ns.is_none_or(|deadline| {
            processed_at_ns.saturating_add(self.deadline_safety_margin_ns) >= deadline
        }) {
            return decision(
                event_type,
                EndpointVerdict::Deny,
                response_for(&envelope.event.operation, false),
                EndpointReason::DenyDeadlineGuard,
                Some(session_id),
                latency,
                remaining,
            );
        }

        let (allow, reason) = match &envelope.event.operation {
            EndpointOperation::AuthExec { target } => {
                if target.key.is_zero() {
                    (false, EndpointReason::DenyMalformedProcessIdentity)
                } else {
                    match path_status(&target.executable, &self.protected_prefixes) {
                        PathStatus::Truncated => (false, EndpointReason::DenyTruncatedPath),
                        PathStatus::Malformed => (false, EndpointReason::DenyMalformedPath),
                        PathStatus::Protected => (false, EndpointReason::DenyProtectedPath),
                        PathStatus::Usable => {
                            if policy
                                .allowed_executables
                                .contains(&target.executable.value)
                            {
                                (true, EndpointReason::PermitExactExecutable)
                            } else {
                                (false, EndpointReason::DenyExecutable)
                            }
                        }
                    }
                }
            }
            EndpointOperation::AuthOpen {
                file,
                requested_flags,
            } => {
                if *requested_flags == 0 || *requested_flags & !OPEN_KNOWN_FLAGS != 0 {
                    (false, EndpointReason::DenyUnknownOpenFlags)
                } else {
                    evaluate_workspace_path(file, policy, &self.protected_prefixes)
                }
            }
            EndpointOperation::AuthCreate { destination } => {
                evaluate_workspace_path(destination, policy, &self.protected_prefixes)
            }
            EndpointOperation::AuthRename {
                source,
                destination,
            } => {
                let source = evaluate_workspace_path(source, policy, &self.protected_prefixes);
                let destination =
                    evaluate_workspace_path(destination, policy, &self.protected_prefixes);
                if source.0 && destination.0 {
                    (true, EndpointReason::PermitWorkspacePath)
                } else if !source.0 {
                    source
                } else {
                    destination
                }
            }
            EndpointOperation::AuthUnlink { target } => {
                evaluate_workspace_path(target, policy, &self.protected_prefixes)
            }
            EndpointOperation::NotifyFork { .. } | EndpointOperation::NotifyExit { .. } => {
                (false, EndpointReason::NotificationOnly)
            }
        };
        decision(
            event_type,
            if allow {
                EndpointVerdict::Allow
            } else {
                EndpointVerdict::Deny
            },
            response_for(&envelope.event.operation, allow),
            reason,
            Some(session_id),
            latency,
            remaining,
        )
    }

    fn apply_successful_transition(
        &mut self,
        envelope: &EndpointEnvelope,
        decision: &EndpointDecision,
    ) {
        match &envelope.event.operation {
            EndpointOperation::AuthExec { target }
                if decision.verdict == EndpointVerdict::Allow =>
            {
                if let Some(session) = self.attributions.remove(&envelope.event.actor.key) {
                    self.attributions.insert(target.key, session);
                }
            }
            EndpointOperation::NotifyFork { child } => {
                if !child.key.is_zero() {
                    if let Some(session) = self.attributions.get(&envelope.event.actor.key).cloned()
                    {
                        if self.attributions.len() < MAX_ATTRIBUTIONS
                            || self.attributions.contains_key(&child.key)
                        {
                            self.attributions.insert(child.key, session);
                        }
                    }
                }
            }
            EndpointOperation::NotifyExit { .. } => {
                self.attributions.remove(&envelope.event.actor.key);
            }
            _ => {}
        }
    }
}

fn evaluate_workspace_path(
    path: &EndpointPath,
    policy: &SessionEnforcementPolicy,
    protected_prefixes: &[String],
) -> (bool, EndpointReason) {
    match path_status(path, protected_prefixes) {
        PathStatus::Truncated => (false, EndpointReason::DenyTruncatedPath),
        PathStatus::Malformed => (false, EndpointReason::DenyMalformedPath),
        PathStatus::Protected => (false, EndpointReason::DenyProtectedPath),
        PathStatus::Usable => {
            if policy
                .workspace_roots
                .iter()
                .any(|root| Path::new(&path.value).starts_with(root))
            {
                (true, EndpointReason::PermitWorkspacePath)
            } else {
                (false, EndpointReason::DenyOutsideWorkspace)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathStatus {
    Usable,
    Protected,
    Truncated,
    Malformed,
}

fn path_status(path: &EndpointPath, protected_prefixes: &[String]) -> PathStatus {
    if path.truncated {
        return PathStatus::Truncated;
    }
    if validate_event_path(&path.value).is_err() {
        return PathStatus::Malformed;
    }
    if protected_prefixes
        .iter()
        .any(|prefix| Path::new(&path.value).starts_with(prefix))
    {
        return PathStatus::Protected;
    }
    PathStatus::Usable
}

fn validate_precompiled_path(path: &str) -> Result<()> {
    validate_event_path(path).map_err(|reason| VigilError::InvalidValue {
        field: "path",
        reason,
    })
}

fn validate_event_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.as_bytes().contains(&0)
        || !Path::new(path).is_absolute()
        || Path::new(path).components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("path must be complete, bounded, absolute, and normalized".to_string());
    }
    Ok(())
}

fn response_for(operation: &EndpointOperation, allow: bool) -> EndpointResponse {
    match operation {
        EndpointOperation::AuthOpen {
            requested_flags, ..
        } => EndpointResponse::OpenFlags {
            authorized_flags: if allow { *requested_flags } else { 0 },
            cache: false,
        },
        operation if operation.is_authorization() => EndpointResponse::Auth {
            allow,
            cache: false,
        },
        _ => EndpointResponse::None,
    }
}

fn decision(
    event_type: EndpointEventType,
    verdict: EndpointVerdict,
    response: EndpointResponse,
    reason: EndpointReason,
    session_id: Option<String>,
    authorization_latency_ns: u64,
    deadline_remaining_ns: Option<u64>,
) -> EndpointDecision {
    EndpointDecision {
        event_type,
        verdict,
        response,
        reason,
        session_id,
        authorization_latency_ns,
        deadline_remaining_ns,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// Keeping the event inline avoids a second heap allocation in replay and native-adapter queues.
#[allow(clippy::large_enum_variant)]
pub enum EndpointSourceItem {
    Event {
        envelope: EndpointEnvelope,
        processing_delay_ns: u64,
    },
    Dropped {
        count: u64,
    },
}

pub trait EndpointEventSource {
    fn next_item(&mut self) -> Result<Option<EndpointSourceItem>>;
}

#[derive(Debug, Clone, Default)]
pub struct SimulatedEndpointSecuritySource {
    items: VecDeque<EndpointSourceItem>,
    fail_next: bool,
}

impl SimulatedEndpointSecuritySource {
    pub fn new(items: impl IntoIterator<Item = EndpointSourceItem>) -> Self {
        Self {
            items: items.into_iter().collect(),
            fail_next: false,
        }
    }

    pub fn push(&mut self, item: EndpointSourceItem) {
        self.items.push_back(item);
    }

    pub fn set_failure(&mut self, fail: bool) {
        self.fail_next = fail;
    }
}

impl EndpointEventSource for SimulatedEndpointSecuritySource {
    fn next_item(&mut self) -> Result<Option<EndpointSourceItem>> {
        if self.fail_next {
            self.fail_next = false;
            return Err(VigilError::Unavailable {
                component: "simulated_endpoint_security",
                reason: "simulated source failure".to_string(),
            });
        }
        Ok(self.items.pop_front())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationMetrics {
    pub authorization_events: u64,
    pub allows: u64,
    pub denials: u64,
    pub deadline_guard_denials: u64,
    pub late_events: u64,
    pub dropped_events: u64,
    pub maximum_authorization_latency_ns: u64,
}

impl AuthorizationMetrics {
    fn record_decision(&mut self, decision: &EndpointDecision) {
        if decision.response == EndpointResponse::None {
            return;
        }
        self.authorization_events = self.authorization_events.saturating_add(1);
        self.maximum_authorization_latency_ns = self
            .maximum_authorization_latency_ns
            .max(decision.authorization_latency_ns);
        match decision.verdict {
            EndpointVerdict::Allow => self.allows = self.allows.saturating_add(1),
            EndpointVerdict::Deny => self.denials = self.denials.saturating_add(1),
            EndpointVerdict::Observe => {}
        }
        if decision.reason == EndpointReason::DenyDeadlineGuard {
            self.deadline_guard_denials = self.deadline_guard_denials.saturating_add(1);
            if decision.deadline_remaining_ns == Some(0) {
                self.late_events = self.late_events.saturating_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSimulationReport {
    pub decisions: Vec<EndpointDecision>,
    pub metrics: AuthorizationMetrics,
    pub remaining_attributions: usize,
}

#[derive(Debug, Default)]
pub struct EndpointSimulator {
    last_global_sequence: Option<u64>,
}

impl EndpointSimulator {
    pub fn run(
        &mut self,
        source: &mut dyn EndpointEventSource,
        state: &mut FastPathState,
    ) -> Result<EndpointSimulationReport> {
        let mut decisions = Vec::new();
        let mut metrics = AuthorizationMetrics::default();
        while let Some(item) = source.next_item()? {
            match item {
                EndpointSourceItem::Dropped { count } => {
                    metrics.dropped_events = metrics.dropped_events.saturating_add(count);
                }
                EndpointSourceItem::Event {
                    envelope,
                    processing_delay_ns,
                } => {
                    if let Some(global) = envelope.global_sequence {
                        if let Some(previous) = self.last_global_sequence {
                            metrics.dropped_events = metrics
                                .dropped_events
                                .saturating_add(global.saturating_sub(previous).saturating_sub(1));
                        }
                        self.last_global_sequence = Some(global);
                    }
                    let processed_at = envelope.observed_at_ns.saturating_add(processing_delay_ns);
                    let decision = state.evaluate(&envelope, processed_at);
                    metrics.record_decision(&decision);
                    state.apply_successful_transition(&envelope, &decision);
                    decisions.push(decision);
                }
            }
        }
        Ok(EndpointSimulationReport {
            decisions,
            metrics,
            remaining_attributions: state.attribution_count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "ags_endpoint_test";
    const WORKSPACE: &str = "/Users/test/workspace";
    const ALLOWED_EXEC: &str = "/usr/bin/stat";

    fn process(key: u8, executable: &str) -> ProcessIdentity {
        ProcessIdentity {
            key: ProcessKey::synthetic(key),
            pid: i32::from(key),
            parent_pid: 1,
            executable: EndpointPath::complete(executable),
            signing_id: None,
            team_id: None,
            is_platform_binary: false,
            is_es_client: false,
        }
    }

    fn state() -> FastPathState {
        let policy = SessionEnforcementPolicy::new(
            SESSION,
            vec![WORKSPACE.to_string()],
            BTreeSet::from([ALLOWED_EXEC.to_string()]),
        )
        .expect("policy");
        let mut state = FastPathState::new(
            vec![policy],
            vec![
                "/Users/test/.ssh".to_string(),
                "/Library/LaunchDaemons".to_string(),
            ],
            5_000_000,
        )
        .expect("state");
        state
            .bind_root(ProcessKey::synthetic(1), SESSION)
            .expect("bind root");
        state
    }

    fn envelope(actor: ProcessIdentity, operation: EndpointOperation) -> EndpointEnvelope {
        EndpointEnvelope {
            observed_at_ns: 1_000_000_000,
            deadline_ns: Some(1_100_000_000),
            sequence: Some(1),
            global_sequence: Some(1),
            event: EndpointEvent { actor, operation },
        }
    }

    #[test]
    fn exact_exec_is_allowed_and_attribution_moves_to_the_new_pidversion() {
        let mut state = state();
        let target = process(2, ALLOWED_EXEC);
        let event = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthExec {
                target: target.clone(),
            },
        );
        let decision = state.evaluate(&event, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Allow);
        assert_eq!(decision.reason, EndpointReason::PermitExactExecutable);
        assert_eq!(
            decision.response,
            EndpointResponse::Auth {
                allow: true,
                cache: false
            }
        );
        state.apply_successful_transition(&event, &decision);
        assert_eq!(state.attributed_session(target.key), Some(SESSION));
        assert_eq!(state.attributed_session(ProcessKey::synthetic(1)), None);
    }

    #[test]
    fn unknown_exec_is_denied_without_cache() {
        let state = state();
        let event = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthExec {
                target: process(2, "/bin/zsh"),
            },
        );
        let decision = state.evaluate(&event, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Deny);
        assert_eq!(decision.reason, EndpointReason::DenyExecutable);
        assert_eq!(
            decision.response,
            EndpointResponse::Auth {
                allow: false,
                cache: false
            }
        );
    }

    #[test]
    fn zero_target_audit_token_cannot_receive_managed_attribution() {
        let state = state();
        let event = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthExec {
                target: process(0, ALLOWED_EXEC),
            },
        );
        let decision = state.evaluate(&event, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Deny);
        assert_eq!(
            decision.reason,
            EndpointReason::DenyMalformedProcessIdentity
        );
    }

    #[test]
    fn root_binding_is_idempotent_but_cannot_reassign_a_process_identity() {
        let second_session = "ags_endpoint_second";
        let policy =
            SessionEnforcementPolicy::new(SESSION, vec![WORKSPACE.to_string()], BTreeSet::new())
                .expect("first policy");
        let second_policy = SessionEnforcementPolicy::new(
            second_session,
            vec![WORKSPACE.to_string()],
            BTreeSet::new(),
        )
        .expect("second policy");
        let mut state = FastPathState::new(vec![policy, second_policy], Vec::new(), 0)
            .expect("fast path state");
        let process = ProcessKey::synthetic(9);

        state.bind_root(process, SESSION).expect("initial binding");
        state
            .bind_root(process, SESSION)
            .expect("idempotent replay");
        assert!(matches!(
            state.bind_root(process, second_session),
            Err(VigilError::Unauthorized(_))
        ));
        assert_eq!(state.attributed_session(process), Some(SESSION));
        assert_eq!(state.attribution_count(), 1);
    }

    #[test]
    fn open_uses_flags_response_and_workspace_and_protected_boundaries() {
        let state = state();
        let allowed = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthOpen {
                file: EndpointPath::complete(format!("{WORKSPACE}/src/main.rs")),
                requested_flags: OPEN_READ | OPEN_WRITE,
            },
        );
        let decision = state.evaluate(&allowed, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Allow);
        assert_eq!(
            decision.response,
            EndpointResponse::OpenFlags {
                authorized_flags: OPEN_READ | OPEN_WRITE,
                cache: false
            }
        );

        let protected = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthOpen {
                file: EndpointPath::complete("/Users/test/.ssh/id_ed25519"),
                requested_flags: OPEN_READ,
            },
        );
        let decision = state.evaluate(&protected, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Deny);
        assert_eq!(decision.reason, EndpointReason::DenyProtectedPath);
    }

    #[test]
    fn rename_requires_both_paths_to_remain_inside_the_workspace() {
        let state = state();
        let event = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthRename {
                source: EndpointPath::complete(format!("{WORKSPACE}/safe")),
                destination: EndpointPath::complete("/tmp/escaped"),
            },
        );
        let decision = state.evaluate(&event, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Deny);
        assert_eq!(decision.reason, EndpointReason::DenyOutsideWorkspace);
    }

    #[test]
    fn unmanaged_processes_are_not_globally_blocked() {
        let state = state();
        let event = envelope(
            process(9, "/usr/bin/unmanaged"),
            EndpointOperation::AuthExec {
                target: process(10, "/bin/zsh"),
            },
        );
        let decision = state.evaluate(&event, 1_001_000_000);
        assert_eq!(decision.verdict, EndpointVerdict::Allow);
        assert_eq!(decision.reason, EndpointReason::UnmanagedProcess);
    }

    #[test]
    fn deadline_margin_and_already_late_events_fail_closed() {
        let state = state();
        let event = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthExec {
                target: process(2, ALLOWED_EXEC),
            },
        );
        let near = state.evaluate(&event, 1_096_000_000);
        assert_eq!(near.verdict, EndpointVerdict::Deny);
        assert_eq!(near.reason, EndpointReason::DenyDeadlineGuard);
        let late = state.evaluate(&event, 1_101_000_000);
        assert_eq!(late.deadline_remaining_ns, Some(0));
    }

    #[test]
    fn fork_inherits_attribution_and_exit_removes_it() {
        let mut state = state();
        let child = process(2, "/usr/bin/agent");
        let fork = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::NotifyFork {
                child: child.clone(),
            },
        );
        let fork_decision = state.evaluate(&fork, 1_001_000_000);
        state.apply_successful_transition(&fork, &fork_decision);
        assert_eq!(state.attributed_session(child.key), Some(SESSION));

        let exit = envelope(child.clone(), EndpointOperation::NotifyExit { status: 0 });
        let exit_decision = state.evaluate(&exit, 1_001_000_000);
        state.apply_successful_transition(&exit, &exit_decision);
        assert_eq!(state.attributed_session(child.key), None);
    }

    #[test]
    fn simulator_records_sequence_gaps_drops_deadlines_and_latency() {
        let mut first = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthExec {
                target: process(2, "/bin/zsh"),
            },
        );
        first.global_sequence = Some(10);
        let mut second = envelope(
            process(1, "/usr/bin/agent"),
            EndpointOperation::AuthOpen {
                file: EndpointPath::complete(format!("{WORKSPACE}/README.md")),
                requested_flags: OPEN_READ,
            },
        );
        second.global_sequence = Some(13);
        let mut source = SimulatedEndpointSecuritySource::new([
            EndpointSourceItem::Event {
                envelope: first,
                processing_delay_ns: 1_000_000,
            },
            EndpointSourceItem::Dropped { count: 3 },
            EndpointSourceItem::Event {
                envelope: second,
                processing_delay_ns: 101_000_000,
            },
        ]);
        let report = EndpointSimulator::default()
            .run(&mut source, &mut state())
            .expect("simulation");
        assert_eq!(report.metrics.authorization_events, 2);
        assert_eq!(report.metrics.denials, 2);
        assert_eq!(report.metrics.deadline_guard_denials, 1);
        assert_eq!(report.metrics.late_events, 1);
        assert_eq!(report.metrics.dropped_events, 5);
        assert_eq!(report.metrics.maximum_authorization_latency_ns, 101_000_000);
    }

    #[test]
    fn truncated_malformed_and_unknown_open_flags_deny() {
        let state = state();
        let cases = [
            (
                EndpointPath::truncated(format!("{WORKSPACE}/partial")),
                OPEN_READ,
                EndpointReason::DenyTruncatedPath,
            ),
            (
                EndpointPath::complete(format!("{WORKSPACE}/../escape")),
                OPEN_READ,
                EndpointReason::DenyMalformedPath,
            ),
            (
                EndpointPath::complete(format!("{WORKSPACE}/file")),
                1 << 31,
                EndpointReason::DenyUnknownOpenFlags,
            ),
        ];
        for (file, requested_flags, expected) in cases {
            let event = envelope(
                process(1, "/usr/bin/agent"),
                EndpointOperation::AuthOpen {
                    file,
                    requested_flags,
                },
            );
            let decision = state.evaluate(&event, 1_001_000_000);
            assert_eq!(decision.verdict, EndpointVerdict::Deny);
            assert_eq!(decision.reason, expected);
        }
    }

    #[test]
    fn a_source_failure_is_not_reinterpreted_as_clean_end_of_stream() {
        let mut source = SimulatedEndpointSecuritySource::default();
        source.set_failure(true);
        let result = EndpointSimulator::default().run(&mut source, &mut state());
        assert!(matches!(result, Err(VigilError::Unavailable { .. })));
    }

    #[test]
    fn invalid_or_oversized_precompiled_state_is_rejected() {
        assert!(SessionEnforcementPolicy::new(
            SESSION,
            vec!["relative/workspace".to_string()],
            BTreeSet::new()
        )
        .is_err());
        assert!(FastPathState::new(
            Vec::new(),
            (0..=MAX_PROTECTED_PREFIXES)
                .map(|index| format!("/protected/{index}"))
                .collect(),
            1
        )
        .is_err());
        assert!(state().bind_root(ProcessKey([0; 32]), SESSION).is_err());
    }
}
