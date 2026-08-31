//! Workspace-scoped local authorization.
//!
//! Paths are resolved through the real filesystem as far as it exists. This catches a
//! workspace symlink that points outside its root and avoids the usual `/work` versus
//! `/workspace-evil` prefix confusion. A later Endpoint Security adapter must still compare
//! this semantic decision with the object macOS actually opened to close TOCTOU gaps.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use vigil_common::{Result, VigilError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalProfile {
    Observe,
    DeveloperStandard,
    DeveloperRestricted,
    Research,
    UntrustedAgent,
}

impl LocalProfile {
    pub const ALL: [Self; 5] = [
        Self::Observe,
        Self::DeveloperStandard,
        Self::DeveloperRestricted,
        Self::Research,
        Self::UntrustedAgent,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::DeveloperStandard => "developer-standard",
            Self::DeveloperRestricted => "developer-restricted",
            Self::Research => "research",
            Self::UntrustedAgent => "untrusted-agent",
        }
    }
}

impl FromStr for LocalProfile {
    type Err = VigilError;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.as_str() == value)
            .ok_or_else(|| {
                VigilError::Config(format!(
                    "unknown local profile `{value}`; expected observe, developer-standard, \
                     developer-restricted, research, or untrusted-agent"
                ))
            })
    }
}

/// The local capability vocabulary.
///
/// Serialization goes through [`LocalAction::as_str`] rather than a derived rename rule, so
/// the dotted name is the *only* spelling: `process.exec` in an event payload, in JSON output,
/// on the command line, and in the docs. A derived `snake_case` rule would render
/// `process_exec` in JSON while every other surface said `process.exec`, and a capability
/// vocabulary with two spellings is one an operator can be wrong about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAction {
    FsList,
    FsMetadata,
    FsRead,
    FsCreate,
    FsWrite,
    FsRename,
    FsDelete,
    FsExecute,
    ProcessExec,
    NetworkConnect,
    SecretMetadata,
    SecretUse,
    SecretExport,
    SystemPersistence,
    SystemPrivileged,
    GitStatus,
    GitRead,
    GitStage,
    GitCommit,
    GitPush,
    GitForcePush,
    GitConfig,
    GitRemoteModify,
}

impl LocalAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsList => "fs.list",
            Self::FsMetadata => "fs.metadata",
            Self::FsRead => "fs.read",
            Self::FsCreate => "fs.create",
            Self::FsWrite => "fs.write",
            Self::FsRename => "fs.rename",
            Self::FsDelete => "fs.delete",
            Self::FsExecute => "fs.execute",
            Self::ProcessExec => "process.exec",
            Self::NetworkConnect => "network.connect",
            Self::SecretMetadata => "secret.metadata",
            Self::SecretUse => "secret.use",
            Self::SecretExport => "secret.export",
            Self::SystemPersistence => "system.persistence",
            Self::SystemPrivileged => "system.privileged",
            Self::GitStatus => "git.status",
            Self::GitRead => "git.read",
            Self::GitStage => "git.stage",
            Self::GitCommit => "git.commit",
            Self::GitPush => "git.push",
            Self::GitForcePush => "git.force_push",
            Self::GitConfig => "git.config",
            Self::GitRemoteModify => "git.remote_modify",
        }
    }

    /// Whether this is a Git capability, which the Git broker mediates.
    pub const fn is_git(self) -> bool {
        matches!(
            self,
            Self::GitStatus
                | Self::GitRead
                | Self::GitStage
                | Self::GitCommit
                | Self::GitPush
                | Self::GitForcePush
                | Self::GitConfig
                | Self::GitRemoteModify
        )
    }

    fn is_read(self) -> bool {
        matches!(
            self,
            Self::FsList | Self::FsMetadata | Self::FsRead | Self::GitStatus | Self::GitRead
        )
    }

    fn is_workspace_mutation(self) -> bool {
        matches!(
            self,
            Self::FsCreate | Self::FsWrite | Self::FsRename | Self::FsDelete
        )
    }

    fn is_path_bearing(self) -> bool {
        matches!(
            self,
            Self::FsList
                | Self::FsMetadata
                | Self::FsRead
                | Self::FsCreate
                | Self::FsWrite
                | Self::FsRename
                | Self::FsDelete
                | Self::FsExecute
                | Self::ProcessExec
        )
    }
}

impl Serialize for LocalAction {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LocalAction {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for LocalAction {
    type Err = VigilError;

    fn from_str(value: &str) -> Result<Self> {
        let action = match value {
            "fs.list" => Self::FsList,
            "fs.metadata" => Self::FsMetadata,
            "fs.read" => Self::FsRead,
            "fs.create" => Self::FsCreate,
            "fs.write" => Self::FsWrite,
            "fs.rename" => Self::FsRename,
            "fs.delete" => Self::FsDelete,
            "fs.execute" => Self::FsExecute,
            "process.exec" => Self::ProcessExec,
            "network.connect" => Self::NetworkConnect,
            "secret.metadata" => Self::SecretMetadata,
            "secret.use" => Self::SecretUse,
            "secret.export" => Self::SecretExport,
            "system.persistence" => Self::SystemPersistence,
            "system.privileged" => Self::SystemPrivileged,
            "git.status" => Self::GitStatus,
            "git.read" => Self::GitRead,
            "git.stage" => Self::GitStage,
            "git.commit" => Self::GitCommit,
            "git.push" => Self::GitPush,
            "git.force_push" => Self::GitForcePush,
            "git.config" => Self::GitConfig,
            "git.remote_modify" => Self::GitRemoteModify,
            _ => {
                return Err(VigilError::InvalidValue {
                    field: "action",
                    reason: format!("unknown capability `{value}`"),
                })
            }
        };
        Ok(action)
    }
}

/// Session risk, ordered by how much authority it removes.
///
/// The derived ordering follows declaration order, so `Normal < Elevated < Restricted <
/// Contained < Quarantined`. Risk is monotone within a session: it never decreases. That is
/// a deliberate choice with a real cost — a session that trips a signal stays degraded until
/// it ends — taken so that nothing an agent does can walk its own risk back down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskState {
    Normal,
    Elevated,
    Restricted,
    Contained,
    Quarantined,
}

impl RiskState {
    pub const ALL: [Self; 5] = [
        Self::Normal,
        Self::Elevated,
        Self::Restricted,
        Self::Contained,
        Self::Quarantined,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Elevated => "ELEVATED",
            Self::Restricted => "RESTRICTED",
            Self::Contained => "CONTAINED",
            Self::Quarantined => "QUARANTINED",
        }
    }

    /// Whether reaching this state should revoke the session's outstanding leases.
    ///
    /// A lease issued while a session was healthy must not keep working once the session is
    /// contained, so containment revokes rather than merely out-ranking it.
    pub const fn revokes_leases(self) -> bool {
        matches!(self, Self::Contained | Self::Quarantined)
    }
}

impl FromStr for RiskState {
    type Err = VigilError;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|state| state.as_str() == value)
            .ok_or_else(|| VigilError::Serialization(format!("unknown local risk state `{value}`")))
    }
}

/// Whether a valid capability lease covers this exact request.
///
/// A lease can raise `REQUIRE_APPROVAL` to `ALLOW`. It can never touch a `DENY`; see
/// [`evaluate_in_context`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Absent,
    Present,
}

/// One local authorization question, with the session state that bounds it.
#[derive(Debug, Clone, Copy)]
pub struct LocalRequest<'a> {
    pub profile: LocalProfile,
    pub workspace: &'a Path,
    pub action: LocalAction,
    pub resource: &'a str,
    pub risk: RiskState,
    pub lease: LeaseStatus,
}

/// Security-relevant executable classes used by the structured process broker.
///
/// Classification is an input to policy, never an authorization by itself. The broker also
/// binds the canonical executable path, arguments, working directory, environment, profile,
/// session, and budget before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableClass {
    DataUtility,
    Shell,
    Interpreter,
    NetworkUtility,
    CredentialUtility,
    PersistenceUtility,
    PrivilegeUtility,
    SystemAdministration,
    Unknown,
}

impl ExecutableClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataUtility => "data_utility",
            Self::Shell => "shell",
            Self::Interpreter => "interpreter",
            Self::NetworkUtility => "network_utility",
            Self::CredentialUtility => "credential_utility",
            Self::PersistenceUtility => "persistence_utility",
            Self::PrivilegeUtility => "privilege_utility",
            Self::SystemAdministration => "system_administration",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionOutcome {
    Allow,
    Deny,
    RequireApproval,
    Observe,
}

impl DecisionOutcome {
    /// Rank by how much the outcome withholds, so "never grants authority" is expressible.
    ///
    /// `Observe` sits below `Allow` because the observe profile does not enforce at all.
    /// Both permit; the ordering matters only against `RequireApproval` and `Deny`.
    pub const fn restrictiveness(self) -> u8 {
        match self {
            Self::Observe => 0,
            Self::Allow => 1,
            Self::RequireApproval => 2,
            Self::Deny => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDecision {
    pub outcome: DecisionOutcome,
    pub action: String,
    pub requested_resource: String,
    pub resolved_resource: Option<String>,
    pub determining_policy: String,
    pub reason: String,
    pub risk_before: RiskState,
    pub risk_after: RiskState,
    #[serde(default)]
    pub detection: Option<String>,
}

impl LocalDecision {
    pub fn permits_execution(&self) -> bool {
        matches!(
            self.outcome,
            DecisionOutcome::Allow | DecisionOutcome::Observe
        )
    }
}

pub fn normalize_workspace(path: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(path)?;
    let resolved = std::fs::canonicalize(&expanded).map_err(|error| {
        VigilError::Config(format!(
            "workspace `{}` cannot be resolved: {error}",
            expanded.display()
        ))
    })?;
    if !resolved.is_dir() {
        return Err(VigilError::Config(format!(
            "workspace `{}` is not a directory",
            resolved.display()
        )));
    }
    if protected_category(&resolved).is_some() {
        return Err(VigilError::Config(format!(
            "protected resource `{}` cannot be used as a workspace",
            resolved.display()
        )));
    }
    Ok(resolved)
}

/// Evaluate a local capability against a profile and one declared workspace.
///
/// This is the what-if form used by `vigil policy evaluate` and `vigil simulate`, which have
/// no session behind them. It answers as a healthy session holding no lease would be
/// answered. Anything acting on behalf of a real session must use [`evaluate_in_context`].
pub fn evaluate(
    profile: LocalProfile,
    workspace: &Path,
    action: LocalAction,
    resource: &str,
) -> LocalDecision {
    evaluate_in_context(&LocalRequest {
        profile,
        workspace,
        action,
        resource,
        risk: RiskState::Normal,
        lease: LeaseStatus::Absent,
    })
}

/// Evaluate one local capability against the session state that bounds it.
///
/// The three steps run in this order, and the order is load-bearing:
///
/// 1. the profile ladder ([`evaluate_base`]), which is unchanged by session state;
/// 2. the lease upgrade, which may turn `REQUIRE_APPROVAL` into `ALLOW` and may never touch
///    a `DENY` — the local analogue of the rule in ADR 0002 that a detector result cannot
///    express an allow;
/// 3. risk degradation, which is purely subtractive.
///
/// Degradation running last is what makes a lease issued before containment worthless
/// afterwards. (Reaching a containing state also revokes the session's leases outright; the
/// ordering here means correctness does not depend on that revocation having happened yet.)
pub fn evaluate_in_context(request: &LocalRequest<'_>) -> LocalDecision {
    let decision = evaluate_base(
        request.profile,
        request.workspace,
        request.action,
        request.resource,
    );
    apply_session_state(decision, request.action, request.risk, request.lease)
}

/// Evaluate one structured process request against the session state that bounds it.
///
/// Same three steps, same order, as [`evaluate_in_context`].
pub fn evaluate_process_in_context(
    profile: LocalProfile,
    workspace: &Path,
    executable: &Path,
    argv: &[String],
    risk: RiskState,
    lease: LeaseStatus,
) -> LocalDecision {
    let decision = evaluate_process(profile, workspace, executable, argv);
    apply_session_state(decision, LocalAction::ProcessExec, risk, lease)
}

/// Apply the lease upgrade and then risk degradation to a base decision.
pub(crate) fn apply_session_state(
    mut decision: LocalDecision,
    action: LocalAction,
    risk: RiskState,
    lease: LeaseStatus,
) -> LocalDecision {
    if lease == LeaseStatus::Present && decision.outcome == DecisionOutcome::RequireApproval {
        decision.outcome = DecisionOutcome::Allow;
        decision.determining_policy = "permit-approved-capability-lease".to_string();
        decision.reason =
            "a valid capability lease covers this exact action and resolved resource".to_string();
    }

    let degraded = degrade_for_risk(action, decision.outcome, risk);
    if degraded != decision.outcome {
        decision.outcome = degraded;
        decision.determining_policy = format!("risk-degradation-{}", risk.as_str());
        decision.reason = format!(
            "session risk is {}; this capability is withheld until the session ends",
            risk.as_str()
        );
    }

    // The ladder reports the risk a request of this shape justifies. The session's own risk
    // is the floor, and risk never decreases.
    decision.risk_before = risk;
    decision.risk_after = decision.risk_after.max(risk);
    decision
}

/// Reduce an outcome to what the session's risk state still permits.
///
/// This function can only move an outcome toward `Deny`; it is never consulted for a way to
/// permit something. The observe profile is exempt because its contract is that it does not
/// enforce, and degrading it would silently turn it into an enforcing profile.
fn degrade_for_risk(
    action: LocalAction,
    outcome: DecisionOutcome,
    risk: RiskState,
) -> DecisionOutcome {
    if outcome == DecisionOutcome::Observe {
        return outcome;
    }
    let floor = match risk {
        RiskState::Normal => outcome,
        RiskState::Elevated => {
            if action.is_workspace_mutation() {
                DecisionOutcome::RequireApproval
            } else if matches!(action, LocalAction::SecretUse | LocalAction::SecretMetadata) {
                DecisionOutcome::Deny
            } else {
                outcome
            }
        }
        // Restricted and Contained coincide here: both permit only reads, and a read outside
        // the workspace is already denied by the base ladder. What separates them is that
        // Contained also revokes outstanding leases (`RiskState::revokes_leases`), which this
        // function does not express.
        RiskState::Restricted | RiskState::Contained => {
            if action.is_read() {
                outcome
            } else {
                DecisionOutcome::Deny
            }
        }
        RiskState::Quarantined => DecisionOutcome::Deny,
    };
    if floor.restrictiveness() > outcome.restrictiveness() {
        floor
    } else {
        outcome
    }
}

fn evaluate_base(
    profile: LocalProfile,
    workspace: &Path,
    action: LocalAction,
    resource: &str,
) -> LocalDecision {
    let requested = resource.to_string();
    if matches!(
        action,
        LocalAction::SecretExport | LocalAction::SystemPersistence | LocalAction::SystemPrivileged
    ) {
        return deny(
            action,
            requested,
            Some(resource.to_string()),
            "deny-agent-ambient-authority",
            "protected agents cannot export secrets, establish persistence, or use privilege",
            None,
            RiskState::Restricted,
        );
    }

    // Check the protected registry against the *named* path before resolving it, as well as
    // against the resolved path below.
    //
    // Resolution can fail — a path whose ancestors do not exist, or that the process cannot
    // traverse. Without this, naming a protected resource that happens to be absent produced a
    // generic `local-path-invalid` denial carrying no detection, so probing for a Docker
    // socket on a machine without Docker fired no signal at all. The attempt is the
    // interesting part, not whether the target happened to be there.
    //
    // This can only make a decision more restrictive: it turns a denial into a *labelled*
    // denial, and the resolved-path check still runs afterwards. It is not a substitute for
    // that check, because a lexical path can be aliased and only resolution sees through it.
    if action.is_path_bearing() {
        if let Ok(named) = expand_tilde(Path::new(resource)) {
            let named = if named.is_absolute() {
                named
            } else {
                workspace.join(named)
            };
            if let Some(category) = protected_category(&clean_components(&named)) {
                return deny(
                    action,
                    requested,
                    Some(named.display().to_string()),
                    "deny-protected-resources",
                    format!("resource is protected ({category})"),
                    Some(detection_for_category(category)),
                    RiskState::Elevated,
                );
            }
        }
    }

    let resolved = if action.is_path_bearing() {
        match resolve_resource(resource, workspace) {
            Ok(path) => Some(path),
            Err(error) => {
                return deny(
                    action,
                    requested,
                    None,
                    "local-path-invalid",
                    error.to_string(),
                    None,
                    RiskState::Elevated,
                )
            }
        }
    } else {
        None
    };
    let resolved_text = resolved
        .as_deref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| resource.to_string());

    if let Some(category) = resolved.as_deref().and_then(protected_category) {
        return deny(
            action,
            requested,
            Some(resolved_text),
            "deny-protected-resources",
            format!("resource is protected ({category})"),
            Some(detection_for_category(category)),
            RiskState::Elevated,
        );
    }

    if profile == LocalProfile::Observe {
        return decision(
            DecisionOutcome::Observe,
            action,
            requested,
            Some(resolved_text),
            "observe-profile",
            "recorded only; this profile does not enforce",
            RiskState::Normal,
        );
    }

    let inside_workspace = resolved
        .as_deref()
        .is_some_and(|path| path.starts_with(workspace));
    if action.is_read() && inside_workspace {
        return allow(action, requested, resolved_text, "permit-workspace-read");
    }
    if action.is_workspace_mutation() && inside_workspace {
        if profile == LocalProfile::UntrustedAgent && action == LocalAction::FsDelete {
            return decision(
                DecisionOutcome::RequireApproval,
                action,
                requested,
                Some(resolved_text),
                "approve-untrusted-delete",
                "untrusted-agent deletions require a resource-bound approval",
                RiskState::Elevated,
            );
        }
        return allow(
            action,
            requested,
            resolved_text,
            "permit-workspace-mutation",
        );
    }
    if action == LocalAction::FsExecute && inside_workspace {
        return if profile == LocalProfile::DeveloperStandard {
            decision(
                DecisionOutcome::RequireApproval,
                action,
                requested,
                Some(resolved_text),
                "approve-workspace-execution",
                "executing workspace content requires a scoped approval",
                RiskState::Elevated,
            )
        } else {
            deny(
                action,
                requested,
                Some(resolved_text),
                "deny-workspace-execution",
                "this profile does not permit executing workspace content",
                None,
                RiskState::Elevated,
            )
        };
    }
    // Git capabilities are decided on the operation, not on a path: the repository is the
    // workspace, and what varies is how far the operation reaches beyond it. Reading is local,
    // committing is a workspace mutation, pushing leaves the machine, and rewriting config or
    // remotes changes what every *future* Git command will do.
    if action.is_git() {
        return match action {
            LocalAction::GitStatus | LocalAction::GitRead | LocalAction::GitStage => allow(
                action,
                requested,
                resolved_text,
                "permit-local-git-inspection",
            ),
            LocalAction::GitCommit => {
                if profile == LocalProfile::UntrustedAgent {
                    decision(
                        DecisionOutcome::RequireApproval,
                        action,
                        requested,
                        Some(resolved_text),
                        "approve-untrusted-commit",
                        "this profile requires a scoped approval to record history",
                        RiskState::Elevated,
                    )
                } else {
                    allow(action, requested, resolved_text, "permit-workspace-commit")
                }
            }
            // A push is the point at which workspace content leaves the machine. It is bound
            // to a destination and needs the same scrutiny as any other egress.
            LocalAction::GitPush => decision(
                DecisionOutcome::RequireApproval,
                action,
                requested,
                Some(resolved_text),
                "approve-git-push",
                "pushing sends workspace content to a remote and requires a scoped approval",
                RiskState::Elevated,
            ),
            // Force-pushing destroys history that already exists on the remote, including
            // other people's. No profile grants it and no approval widens it here.
            LocalAction::GitForcePush => deny(
                action,
                requested,
                Some(resolved_text),
                "deny-git-force-push",
                "force-pushing discards remote history and is never granted to an agent",
                Some(crate::git_broker::DETECTION_GIT_HISTORY_REWRITE),
                RiskState::Elevated,
            ),
            // Config and remote changes are not ordinary writes: they change what every later
            // Git command does, and several config keys execute arbitrary programs.
            LocalAction::GitConfig | LocalAction::GitRemoteModify => deny(
                action,
                requested,
                Some(resolved_text),
                "deny-git-control-surface",
                "changing Git configuration or remotes alters what every future command does",
                Some(crate::git_broker::DETECTION_GIT_CONTROL_SURFACE),
                RiskState::Elevated,
            ),
            _ => deny(
                action,
                requested,
                Some(resolved_text),
                "default-deny-git",
                "this Git capability is not granted",
                None,
                RiskState::Elevated,
            ),
        };
    }

    if action == LocalAction::ProcessExec {
        return decision(
            DecisionOutcome::RequireApproval,
            action,
            requested,
            Some(resolved_text),
            "approve-process-exec",
            "process execution requires executable identity and a scoped approval",
            RiskState::Elevated,
        );
    }
    if action == LocalAction::NetworkConnect {
        return decision(
            DecisionOutcome::RequireApproval,
            action,
            requested,
            Some(resolved_text),
            "approve-new-destination",
            "network destinations require an explicit profile allowlist or approval",
            RiskState::Elevated,
        );
    }
    if matches!(action, LocalAction::SecretMetadata | LocalAction::SecretUse) {
        return decision(
            DecisionOutcome::RequireApproval,
            action,
            requested,
            Some(resolved_text),
            "approve-brokered-secret-use",
            "secret metadata and use must be brokered and specifically authorized",
            RiskState::Elevated,
        );
    }

    deny(
        action,
        requested,
        Some(resolved_text),
        "default-deny-outside-workspace",
        "resource is outside every declared workspace",
        None,
        RiskState::Elevated,
    )
}

/// Evaluate one fully structured process request.
///
/// Enforced profiles currently permit only a deliberately tiny set of side-effect-free system
/// utilities. Shells, interpreters, network clients, credential tools, persistence utilities,
/// privilege tools, workspace executables, and unknown binaries remain denied or approval-bound.
pub fn evaluate_process(
    profile: LocalProfile,
    workspace: &Path,
    executable: &Path,
    argv: &[String],
) -> LocalDecision {
    let requested = executable.display().to_string();
    let resolved = match std::fs::canonicalize(executable) {
        Ok(path) => path,
        Err(_) => {
            return deny(
                LocalAction::ProcessExec,
                requested,
                None,
                "deny-unresolved-executable",
                "executable identity could not be resolved",
                Some(crate::DETECTION_UNEXPECTED_EXECUTABLE),
                RiskState::Elevated,
            )
        }
    };
    let resolved_text = resolved.display().to_string();
    let class = classify_executable(&resolved);

    if profile == LocalProfile::Observe {
        return decision(
            DecisionOutcome::Observe,
            LocalAction::ProcessExec,
            requested,
            Some(resolved_text),
            "observe-profile",
            "recorded only; this profile does not enforce process policy",
            RiskState::Normal,
        );
    }

    if resolved.starts_with(workspace) {
        return decision(
            DecisionOutcome::RequireApproval,
            LocalAction::ProcessExec,
            requested,
            Some(resolved_text),
            "approve-workspace-executable",
            "workspace executables require a hash-bound human approval",
            RiskState::Elevated,
        );
    }

    if class != ExecutableClass::DataUtility {
        let (policy, reason, detection) = match class {
            ExecutableClass::Shell | ExecutableClass::Interpreter => (
                "deny-interpreter-without-approval",
                "shells and interpreters require argument-bound approval",
                Some(crate::DETECTION_UNEXPECTED_INTERPRETER),
            ),
            ExecutableClass::NetworkUtility => (
                "deny-network-utility-without-network-policy",
                "network utilities require destination-aware mediation",
                Some(crate::DETECTION_UNMEDIATED_NETWORK_UTILITY),
            ),
            ExecutableClass::CredentialUtility => (
                "deny-credential-utility",
                "credential utilities are not available to semantic sessions",
                Some(crate::DETECTION_CREDENTIAL_UTILITY),
            ),
            ExecutableClass::PersistenceUtility => (
                "deny-persistence-utility",
                "persistence utilities are not available to semantic sessions",
                Some("persistence_attempt"),
            ),
            ExecutableClass::PrivilegeUtility => (
                "deny-privilege-utility",
                "privilege utilities are not available to semantic sessions",
                Some(crate::DETECTION_PRIVILEGE_ATTEMPT),
            ),
            ExecutableClass::SystemAdministration | ExecutableClass::Unknown => (
                "approve-unknown-executable",
                "the executable is not in the structured low-risk allowlist",
                Some(crate::DETECTION_UNEXPECTED_EXECUTABLE),
            ),
            // Guarded above. Keeping a non-panicking arm preserves fail-safe behavior if this
            // branch is refactored later.
            ExecutableClass::DataUtility => (
                "deny-process-policy-inconsistency",
                "process classification could not be authorized consistently",
                Some(crate::DETECTION_UNEXPECTED_EXECUTABLE),
            ),
        };
        let mut result = decision(
            if class == ExecutableClass::Unknown {
                DecisionOutcome::RequireApproval
            } else {
                DecisionOutcome::Deny
            },
            LocalAction::ProcessExec,
            requested,
            Some(resolved_text),
            policy,
            reason,
            RiskState::Elevated,
        );
        result.detection = detection.map(str::to_string);
        return result;
    }

    // The current data utilities do not interpret options as code or paths. Keep the check
    // explicit so expanding the registry requires reviewing argument semantics here.
    if argv.iter().any(|argument| argument.as_bytes().contains(&0)) {
        return deny(
            LocalAction::ProcessExec,
            requested,
            Some(resolved_text),
            "deny-invalid-process-argument",
            "process arguments contain a null byte",
            None,
            RiskState::Elevated,
        );
    }

    decision(
        DecisionOutcome::Allow,
        LocalAction::ProcessExec,
        requested,
        Some(resolved_text),
        "permit-structured-data-utility",
        "canonical side-effect-free utility permitted with structured arguments",
        RiskState::Normal,
    )
}

/// Classify a canonical executable path. Exact path allowlisting is used for the only class that
/// may execute without approval; basename classification is conservative and denial-oriented.
pub fn classify_executable(executable: &Path) -> ExecutableClass {
    let exact = executable.to_string_lossy();
    if matches!(
        exact.as_ref(),
        "/bin/echo"
            | "/usr/bin/echo"
            | "/bin/true"
            | "/usr/bin/true"
            | "/bin/false"
            | "/usr/bin/false"
            | "/bin/sleep"
            | "/usr/bin/sleep"
    ) {
        return ExecutableClass::DataUtility;
    }

    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    match name {
        "sh" | "bash" | "zsh" | "fish" | "dash" | "csh" | "tcsh" => ExecutableClass::Shell,
        "python" | "python3" | "node" | "ruby" | "perl" | "swift" | "java" | "osascript" => {
            ExecutableClass::Interpreter
        }
        "curl" | "ssh" | "scp" | "sftp" | "nc" | "ncat" | "socat" => {
            ExecutableClass::NetworkUtility
        }
        "security" => ExecutableClass::CredentialUtility,
        "launchctl" | "defaults" => ExecutableClass::PersistenceUtility,
        "sudo" => ExecutableClass::PrivilegeUtility,
        "diskutil" | "chmod" | "chown" | "xattr" | "codesign" | "installer" | "pkgutil"
        | "open" => ExecutableClass::SystemAdministration,
        _ => ExecutableClass::Unknown,
    }
}

fn allow(action: LocalAction, requested: String, resolved: String, policy: &str) -> LocalDecision {
    decision(
        DecisionOutcome::Allow,
        action,
        requested,
        Some(resolved),
        policy,
        "resource is inside the declared workspace",
        RiskState::Normal,
    )
}

fn deny(
    action: LocalAction,
    requested: String,
    resolved: Option<String>,
    policy: &str,
    reason: impl Into<String>,
    detection: Option<&str>,
    risk_after: RiskState,
) -> LocalDecision {
    let mut result = decision(
        DecisionOutcome::Deny,
        action,
        requested,
        resolved,
        policy,
        reason,
        risk_after,
    );
    result.detection = detection.map(str::to_string);
    result
}

fn decision(
    outcome: DecisionOutcome,
    action: LocalAction,
    requested: String,
    resolved: Option<String>,
    policy: &str,
    reason: impl Into<String>,
    risk_after: RiskState,
) -> LocalDecision {
    LocalDecision {
        outcome,
        action: action.as_str().to_string(),
        requested_resource: requested,
        resolved_resource: resolved,
        determining_policy: policy.to_string(),
        reason: reason.into(),
        risk_before: RiskState::Normal,
        risk_after,
        detection: None,
    }
}

/// Resolve a requested resource to the path policy actually decided about.
///
/// Leases and approvals bind to this value, never to the requested string, so a later
/// request cannot launder `~/w/../.ssh` past authority granted for `~/w`.
pub(crate) fn resolve_resource(resource: &str, workspace: &Path) -> Result<PathBuf> {
    if resource.as_bytes().contains(&0) {
        return Err(VigilError::InvalidValue {
            field: "resource",
            reason: "path contains a null byte".to_string(),
        });
    }
    let expanded = expand_tilde(Path::new(resource))?;
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        workspace.join(expanded)
    };
    resolve_existing_ancestor(&absolute)
}

fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = existing
                    .file_name()
                    .ok_or_else(|| VigilError::InvalidValue {
                        field: "resource",
                        reason: "path has no resolvable ancestor".to_string(),
                    })?;
                missing.push(name.to_os_string());
                existing = existing.parent().ok_or_else(|| VigilError::InvalidValue {
                    field: "resource",
                    reason: "path has no resolvable ancestor".to_string(),
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = std::fs::canonicalize(existing)?;
    for component in missing.iter().rev() {
        if component == ".." || component == "." {
            return Err(VigilError::InvalidValue {
                field: "resource",
                reason: "unresolved traversal component".to_string(),
            });
        }
        resolved.push(component);
    }
    Ok(clean_components(&resolved))
}

fn clean_components(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = home_directory()?;
        return Ok(if text == "~" {
            home
        } else {
            home.join(&text[2..])
        });
    }
    if text.starts_with('~') {
        return Err(VigilError::InvalidValue {
            field: "resource",
            reason: "only `~` and `~/...` home expansion are supported".to_string(),
        });
    }
    Ok(path.to_path_buf())
}

fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| VigilError::Config("HOME is not an absolute path".to_string()))
}

/// What kind of thing a protected-resource denial actually is.
///
/// These are very different events. Reaching for `~/.ssh` is credential access; writing a
/// LaunchAgent is persistence; touching VIGIL's own store is an attempt on the control plane,
/// and is the one case severe enough to contain a session on its own. Reporting all three as
/// "credential access" would put them in one bucket an operator cannot triage.
const fn detection_for_category(category: &str) -> &'static str {
    match category.as_bytes() {
        b"persistence" => "persistence_attempt",
        b"vigil_integrity" => "security_control_modification",
        b"local_ipc_escalation" => "local_ipc_escalation",
        _ => "credential_access",
    }
}

/// Crate-visible view of the protected-resource registry.
///
/// Exposed so deception can refuse to place bait in a location whose integrity matters.
pub(crate) fn protected_category_of(path: &Path) -> Option<&'static str> {
    protected_category(path)
}

fn protected_category(path: &Path) -> Option<&'static str> {
    let home = home_directory().ok();
    let home_relative = [
        (".ssh", "ssh_credentials"),
        (".aws", "cloud_credentials"),
        (".azure", "cloud_credentials"),
        (".config/gcloud", "cloud_credentials"),
        (".kube", "cluster_credentials"),
        // Local IPC endpoints. See `local_ipc_endpoint` for why these are protected.
        (".docker/run/docker.sock", "local_ipc_escalation"),
        (".orbstack/run/docker.sock", "local_ipc_escalation"),
        (".colima/default/docker.sock", "local_ipc_escalation"),
        (".lima/default/sock/docker.sock", "local_ipc_escalation"),
        (
            ".local/share/containers/podman/machine/podman.sock",
            "local_ipc_escalation",
        ),
        (".gnupg/S.gpg-agent", "local_ipc_escalation"),
        ("Library/Keychains", "keychain_storage"),
        ("Library/LaunchAgents", "persistence"),
        ("Library/Application Support/VIGIL", "vigil_integrity"),
    ];
    if let Some(home) = home {
        for (relative, category) in home_relative {
            if path.starts_with(home.join(relative)) {
                return Some(category);
            }
        }
    }
    for (root, category) in [
        ("/Library/LaunchAgents", "persistence"),
        ("/Library/LaunchDaemons", "persistence"),
        ("/Library/Application Support/VIGIL", "vigil_integrity"),
        ("/var/run/docker.sock", "local_ipc_escalation"),
        ("/run/docker.sock", "local_ipc_escalation"),
        ("/var/run/containerd", "local_ipc_escalation"),
    ] {
        if path.starts_with(root) {
            return Some(category);
        }
    }
    if local_ipc_endpoint(path) {
        return Some("local_ipc_escalation");
    }
    None
}

/// Whether a path is a local IPC endpoint whose reachability is an escalation.
///
/// This closes a gap that the credential protections above do not: `~/.ssh/id_ed25519` is
/// protected, but an agent that can reach the **SSH agent socket** can authenticate as the
/// user to every host that agent holds a key for *without ever reading a key file*. Protecting
/// the key and not the agent protects the wrong thing.
///
/// The container sockets are worse still. Anything that can talk to a Docker or containerd
/// socket can start a privileged container with the host filesystem mounted, which is
/// root-equivalent on the machine. It is a privilege-escalation primitive that involves no
/// privileged executable and no `sudo`, so none of the process-broker checks see it.
///
/// `SSH_AUTH_SOCK` is read from the environment because its path is assigned at login and is
/// not knowable statically. That makes this function depend on the environment, which is
/// unusual for a policy predicate and is why it is isolated here: everything else in the
/// protected registry is a fixed path.
fn local_ipc_endpoint(path: &Path) -> bool {
    if let Some(agent) = std::env::var_os("SSH_AUTH_SOCK") {
        let agent = PathBuf::from(agent);
        if !agent.as_os_str().is_empty() && path.starts_with(&agent) {
            return true;
        }
    }
    // macOS assigns the launchd SSH agent socket a per-boot directory under a private temp
    // root; the `Listeners` leaf is the stable part.
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Listeners" || name.ends_with("docker.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("vigil-policy-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create fixture");
        (
            root,
            std::fs::canonicalize(workspace).expect("canonical workspace"),
        )
    }

    #[test]
    fn workspace_access_is_allowed_and_prefix_confusion_is_denied() {
        let (root, workspace) = fixture();
        let inside = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsWrite,
            "src/main.rs",
        );
        assert_eq!(inside.outcome, DecisionOutcome::Allow);

        let lookalike = root.join("workspace-evil/secret");
        let outside = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsRead,
            &lookalike.display().to_string(),
        );
        assert_eq!(outside.outcome, DecisionOutcome::Deny);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn traversal_is_resolved_outside_and_denied() {
        let (root, workspace) = fixture();
        let decision = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsRead,
            "../outside.txt",
        );
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_escape_the_workspace() {
        use std::os::unix::fs::symlink;
        let (root, workspace) = fixture();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).expect("create outside");
        symlink(&outside, workspace.join("link")).expect("create symlink");
        let decision = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsWrite,
            "link/new.txt",
        );
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_symlink_is_denied_instead_of_treated_as_a_new_file() {
        use std::os::unix::fs::symlink;
        let (root, workspace) = fixture();
        symlink(
            root.join("outside/not-created-yet"),
            workspace.join("broken-link"),
        )
        .expect("create broken symlink");
        let decision = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsWrite,
            "broken-link",
        );
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.determining_policy, "local-path-invalid");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_actions_fail_during_parsing() {
        assert!("vigil.security.disable".parse::<LocalAction>().is_err());
    }

    #[test]
    fn secret_metadata_is_a_distinct_approval_bound_capability() {
        let (root, workspace) = fixture();
        let action = LocalAction::from_str("secret.metadata").expect("parse metadata action");
        let decision = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            action,
            "sec_github_readonly",
        );
        assert_eq!(decision.outcome, DecisionOutcome::RequireApproval);
        assert_eq!(decision.action, "secret.metadata");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Protecting `~/.ssh/id_ed25519` and not the agent socket protects the wrong thing: an
    /// agent that can reach the SSH agent authenticates as the user to every host that agent
    /// holds a key for, without ever opening a key file.
    #[test]
    fn local_ipc_endpoints_are_protected_alongside_the_credentials_they_stand_in_for() {
        let (root, workspace) = fixture();
        let home = home_directory().expect("home");

        for endpoint in [
            home.join(".docker/run/docker.sock"),
            home.join(".orbstack/run/docker.sock"),
            home.join(".colima/default/docker.sock"),
            home.join(".gnupg/S.gpg-agent"),
            PathBuf::from("/var/run/docker.sock"),
        ] {
            assert_eq!(
                protected_category(&endpoint),
                Some("local_ipc_escalation"),
                "`{}` is not protected",
                endpoint.display()
            );
        }

        // The launchd SSH agent socket, whose directory is assigned per boot.
        assert!(local_ipc_endpoint(Path::new(
            "/private/tmp/com.apple.launchd.abc123/Listeners"
        )));

        // A decision about one denies, and names it as escalation rather than as a
        // credential read — they are different findings.
        let decision = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsRead,
            "/var/run/docker.sock",
        );
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.detection.as_deref(),
            Some(crate::DETECTION_LOCAL_IPC_ESCALATION)
        );

        // An ordinary workspace file is unaffected: the rule must not swallow normal work.
        assert!(protected_category(&workspace.join("server.sock.rs")).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    /// `SSH_AUTH_SOCK` is read from the environment, so its handling is asserted directly.
    #[test]
    fn the_configured_ssh_agent_socket_is_protected() {
        let previous = std::env::var_os("SSH_AUTH_SOCK");
        // SAFETY-adjacent: this test sets a process-wide variable. It restores it, and the
        // value is only read by `local_ipc_endpoint`.
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/vigil-test-agent/agent.42");
        assert!(local_ipc_endpoint(Path::new(
            "/tmp/vigil-test-agent/agent.42"
        )));
        assert!(!local_ipc_endpoint(Path::new(
            "/tmp/vigil-test-agent-other/x"
        )));
        match previous {
            Some(value) => std::env::set_var("SSH_AUTH_SOCK", value),
            None => std::env::remove_var("SSH_AUTH_SOCK"),
        }
    }

    #[test]
    fn protected_credentials_are_denied_even_when_the_file_is_absent() {
        let (root, workspace) = fixture();
        let decision = evaluate(
            LocalProfile::DeveloperStandard,
            &workspace,
            LocalAction::FsRead,
            "~/.ssh/vigil-synthetic-key-that-does-not-exist",
        );
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.detection.as_deref(), Some("credential_access"));
        assert_eq!(decision.risk_after, RiskState::Elevated);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn process_policy_distinguishes_safe_utilities_from_interpreters() {
        let (root, workspace) = fixture();
        let utility = ["/bin/true", "/usr/bin/true"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .expect("system true utility");
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .expect("system shell");

        let allowed = evaluate_process(LocalProfile::DeveloperStandard, &workspace, &utility, &[]);
        let denied = evaluate_process(
            LocalProfile::DeveloperStandard,
            &workspace,
            &shell,
            &["-c".to_string(), "exit 0".to_string()],
        );
        assert_eq!(allowed.outcome, DecisionOutcome::Allow);
        assert_eq!(denied.outcome, DecisionOutcome::Deny);
        assert_eq!(
            denied.detection.as_deref(),
            Some(crate::DETECTION_UNEXPECTED_INTERPRETER)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn request<'a>(
        workspace: &'a Path,
        action: LocalAction,
        resource: &'a str,
        risk: RiskState,
        lease: LeaseStatus,
    ) -> LocalRequest<'a> {
        LocalRequest {
            profile: LocalProfile::DeveloperStandard,
            workspace,
            action,
            resource,
            risk,
            lease,
        }
    }

    #[test]
    fn a_lease_raises_require_approval_to_allow() {
        let (root, workspace) = fixture();
        let without = evaluate_in_context(&request(
            &workspace,
            LocalAction::ProcessExec,
            "anything",
            RiskState::Normal,
            LeaseStatus::Absent,
        ));
        assert_eq!(without.outcome, DecisionOutcome::RequireApproval);

        let with = evaluate_in_context(&request(
            &workspace,
            LocalAction::ProcessExec,
            "anything",
            RiskState::Normal,
            LeaseStatus::Present,
        ));
        assert_eq!(with.outcome, DecisionOutcome::Allow);
        assert_eq!(with.determining_policy, "permit-approved-capability-lease");
        let _ = std::fs::remove_dir_all(root);
    }

    /// The load-bearing rule. A lease is authority to stop asking a human, never authority to
    /// overturn a denial — the local form of ADR 0002's monotone decision algebra.
    #[test]
    fn a_lease_can_never_upgrade_a_deny() {
        let (root, workspace) = fixture();
        let denials = [
            // Ambient authority the profile refuses outright.
            (LocalAction::SystemPersistence, "anything".to_string()),
            (LocalAction::SystemPrivileged, "anything".to_string()),
            (LocalAction::SecretExport, "anything".to_string()),
            // A protected credential resource.
            (LocalAction::FsRead, "~/.ssh/id_ed25519".to_string()),
            // Outside every declared workspace.
            (
                LocalAction::FsWrite,
                root.join("elsewhere/file").display().to_string(),
            ),
        ];
        for (action, resource) in denials {
            let base = evaluate_in_context(&request(
                &workspace,
                action,
                &resource,
                RiskState::Normal,
                LeaseStatus::Absent,
            ));
            assert_eq!(
                base.outcome,
                DecisionOutcome::Deny,
                "fixture for {} is not a denial",
                action.as_str()
            );
            let leased = evaluate_in_context(&request(
                &workspace,
                action,
                &resource,
                RiskState::Normal,
                LeaseStatus::Present,
            ));
            assert_eq!(
                leased.outcome,
                DecisionOutcome::Deny,
                "a lease upgraded a denial of {}",
                action.as_str()
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn containment_and_quarantine_withhold_everything_but_reads() {
        let (root, workspace) = fixture();
        let write = |risk| {
            evaluate_in_context(&request(
                &workspace,
                LocalAction::FsWrite,
                "src/main.rs",
                risk,
                LeaseStatus::Present,
            ))
            .outcome
        };
        let read = |risk| {
            evaluate_in_context(&request(
                &workspace,
                LocalAction::FsRead,
                "src/main.rs",
                risk,
                LeaseStatus::Absent,
            ))
            .outcome
        };

        assert_eq!(write(RiskState::Normal), DecisionOutcome::Allow);
        // Elevated turns a workspace mutation into a question for a human.
        assert_eq!(write(RiskState::Elevated), DecisionOutcome::RequireApproval);
        for risk in [
            RiskState::Restricted,
            RiskState::Contained,
            RiskState::Quarantined,
        ] {
            assert_eq!(write(risk), DecisionOutcome::Deny, "{}", risk.as_str());
        }
        // Reads survive containment, and stop at quarantine.
        for risk in [
            RiskState::Normal,
            RiskState::Elevated,
            RiskState::Restricted,
            RiskState::Contained,
        ] {
            assert_eq!(read(risk), DecisionOutcome::Allow, "{}", risk.as_str());
        }
        assert_eq!(read(RiskState::Quarantined), DecisionOutcome::Deny);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Exhaustive over the whole input space rather than a sample of it: for every action,
    /// resource shape, lease state and pair of risk states, raising the risk must never make
    /// the outcome less restrictive.
    #[test]
    fn raising_risk_never_grants_authority() {
        let (root, workspace) = fixture();
        let outside = root.join("elsewhere/file").display().to_string();
        let resources = [
            "src/main.rs",
            "~/.ssh/id_ed25519",
            outside.as_str(),
            "../escape",
        ];
        for action in ALL_ACTIONS {
            for resource in resources {
                for lease in [LeaseStatus::Absent, LeaseStatus::Present] {
                    let outcomes: Vec<_> = RiskState::ALL
                        .into_iter()
                        .map(|risk| {
                            evaluate_in_context(&request(&workspace, action, resource, risk, lease))
                                .outcome
                                .restrictiveness()
                        })
                        .collect();
                    for pair in outcomes.windows(2) {
                        assert!(
                            pair[1] >= pair[0],
                            "raising risk relaxed {} on {resource}: {pair:?}",
                            action.as_str()
                        );
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// Likewise for leases: holding one must never make the outcome more restrictive.
    #[test]
    fn holding_a_lease_never_removes_authority() {
        let (root, workspace) = fixture();
        let outside = root.join("elsewhere/file").display().to_string();
        for action in ALL_ACTIONS {
            for resource in ["src/main.rs", "~/.ssh/id_ed25519", outside.as_str()] {
                for risk in RiskState::ALL {
                    let without = evaluate_in_context(&request(
                        &workspace,
                        action,
                        resource,
                        risk,
                        LeaseStatus::Absent,
                    ))
                    .outcome
                    .restrictiveness();
                    let with = evaluate_in_context(&request(
                        &workspace,
                        action,
                        resource,
                        risk,
                        LeaseStatus::Present,
                    ))
                    .outcome
                    .restrictiveness();
                    assert!(
                        with <= without,
                        "a lease restricted {} on {resource} at {}",
                        action.as_str(),
                        risk.as_str()
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// The observe profile's contract is that it does not enforce. Degradation must not
    /// quietly turn it into a profile that does.
    #[test]
    fn risk_does_not_make_the_observe_profile_enforce() {
        let (root, workspace) = fixture();
        for risk in RiskState::ALL {
            let decision = evaluate_in_context(&LocalRequest {
                profile: LocalProfile::Observe,
                workspace: &workspace,
                action: LocalAction::FsWrite,
                resource: "src/main.rs",
                risk,
                lease: LeaseStatus::Absent,
            });
            assert_eq!(
                decision.outcome,
                DecisionOutcome::Observe,
                "observe enforced at {}",
                risk.as_str()
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_decision_reports_the_sessions_risk_as_its_floor() {
        let (root, workspace) = fixture();
        let decision = evaluate_in_context(&request(
            &workspace,
            LocalAction::FsRead,
            "src/main.rs",
            RiskState::Contained,
            LeaseStatus::Absent,
        ));
        assert_eq!(decision.risk_before, RiskState::Contained);
        assert!(decision.risk_after >= RiskState::Contained);
        let _ = std::fs::remove_dir_all(root);
    }

    const ALL_ACTIONS: [LocalAction; 15] = [
        LocalAction::FsList,
        LocalAction::FsMetadata,
        LocalAction::FsRead,
        LocalAction::FsCreate,
        LocalAction::FsWrite,
        LocalAction::FsRename,
        LocalAction::FsDelete,
        LocalAction::FsExecute,
        LocalAction::ProcessExec,
        LocalAction::NetworkConnect,
        LocalAction::SecretMetadata,
        LocalAction::SecretUse,
        LocalAction::SecretExport,
        LocalAction::SystemPersistence,
        LocalAction::SystemPrivileged,
    ];
}
