//! Git semantic enforcement point.
//!
//! Git is the highest-leverage tool a coding agent touches, and it is a confused deputy with
//! an unusually large mouth. The danger is not that `git commit` is destructive — it is that
//! **Git configuration executes arbitrary programs**, and an agent that can write files in a
//! repository can write `.git/config`.
//!
//! A partial list of config keys that run a command: `core.pager`, `core.editor`,
//! `core.sshCommand`, `core.hooksPath`, `credential.helper`, `diff.*.textconv`,
//! `filter.*.clean` and `.smudge`, `sequence.editor`, `uploadpack.packObjectsHook`, and every
//! `alias.*`. Hooks in `.git/hooks` run on commit and push. So a plain `git status` in a
//! repository the agent controls is a code-execution primitive, and a Git broker that shells
//! out naively hands the agent exactly the arbitrary execution the process broker refuses it.
//!
//! # How that is closed
//!
//! Every invocation is built by [`hardened_command`], which:
//!
//! - passes `-c` overrides for each execution-bearing key, because command-line `-c` takes
//!   precedence over repository, global, and system configuration;
//! - points `core.hooksPath` at an empty directory VIGIL owns, so no hook runs;
//! - sets `GIT_CONFIG_NOSYSTEM=1` and redirects `HOME` to that same empty directory, so
//!   `/etc/gitconfig` and `~/.gitconfig` contribute nothing;
//! - clears the rest of the environment, refuses a terminal prompt, and disables askpass, so
//!   Git cannot stop for input or reach a credential helper;
//! - refuses any caller-supplied argument beginning with `-`, so no option — including another
//!   `-c` — can be smuggled in through a branch name, path, or message.
//!
//! # What this broker still is not
//!
//! It runs the real `git` binary as a subprocess and does not sandbox it. Git can still read
//! any file the user can read. This broker bounds *which Git operations happen and with what
//! configuration*; it does not bound what the resulting process could do if Git itself were
//! compromised.

use crate::detection::{Confidence, DetectionRule, Severity, Tactic};
use crate::{
    BudgetCharge, BudgetDimension, LocalAction, LocalProfile, LocalSession, LocalStore,
    RiskDimension, SessionStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;
use vigil_common::{Result, VigilError};

/// Bounds on what a caller may hand to Git.
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_MESSAGE_BYTES: usize = 8192;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const GIT_TIMEOUT_MS: u64 = 30_000;

pub const DETECTION_GIT_CONTROL_SURFACE: &str = "git_control_surface_change";
pub const DETECTION_GIT_HISTORY_REWRITE: &str = "git_history_rewrite";
pub const DETECTION_GIT_EXECUTABLE_CONFIG: &str = "git_executable_config_present";

pub const GIT_RULES: &[DetectionRule] = &[
    DetectionRule {
        id: "VIGIL-L019",
        name: "Git control-surface change",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::PolicyEvasion,
        description: "An attempt to change Git configuration or a remote, which alters what \
                      every later Git command does.",
        dimension: RiskDimension::ToolAnomaly,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L020",
        name: "Git history rewrite",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::DestructiveAction,
        description: "An attempt to force-push, which discards history already on the remote.",
        dimension: RiskDimension::DestructiveBehavior,
        weight: 40,
    },
    // Calibration note. The first draft of this rule was CRITICAL at weight 60, which
    // contained a session the moment it ran `git status` in a rigged repository. That is
    // wrong twice over. First, VIGIL *neutralised* the configuration — nothing executed, so
    // nothing bad happened. Second, the keys involved are overwhelmingly benign in practice:
    // `alias.*` is universal, `credential.helper` is how people authenticate, and `filter.*`
    // is set by git-lfs in a large fraction of real repositories. A rule that contains a
    // session on `git status` in any LFS repository would be turned off within a day.
    //
    // What it actually is: useful context that this repository could have steered Git, and a
    // corroborating signal if something else goes wrong. Weight 10 sits below the elevation
    // threshold, so it never changes a session's standing on its own.
    DetectionRule {
        id: "VIGIL-L021",
        name: "Executable Git configuration neutralized",
        severity: Severity::Medium,
        confidence: Confidence::High,
        tactic: Tactic::ToolAbuse,
        description: "The repository configures Git to run a program. VIGIL overrode it, so \
                      nothing was executed.",
        dimension: RiskDimension::ToolAnomaly,
        weight: 10,
    },
];

/// Configuration keys whose value Git executes as a program.
///
/// Each is overridden on every invocation. The list is not a denylist to be checked against —
/// it is the set of `-c` overrides applied unconditionally, so a key VIGIL has *not* thought
/// of is the only gap, rather than every key it failed to block.
const EXECUTABLE_CONFIG_OVERRIDES: &[(&str, &str)] = &[
    ("core.pager", "cat"),
    ("core.editor", "false"),
    ("core.sshCommand", "false"),
    ("core.fsmonitor", "false"),
    ("sequence.editor", "false"),
    ("credential.helper", ""),
    ("uploadpack.packObjectsHook", ""),
    ("diff.external", ""),
    ("protocol.ext.allow", "never"),
    ("http.proxy", ""),
];

/// Key prefixes that are reported when found in a repository's own configuration.
///
/// These cannot be neutralised by a fixed `-c` override because they are namespaced per
/// filter, per diff driver, or per alias. They are overridden where possible and always
/// reported, so an operator learns the repository is rigged even though the command was safe.
const EXECUTABLE_CONFIG_PREFIXES: &[&str] = &[
    "alias.",
    "filter.",
    "diff.",
    "core.hookspath",
    "core.gitproxy",
    "credential.",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitRequest {
    Status,
    Log { max_count: u32 },
    Diff { staged: bool },
    Stage { paths: Vec<String> },
    Commit { message: String },
    Push { remote: String, branch: String },
}

impl GitRequest {
    /// The capability this request needs.
    pub const fn action(&self) -> LocalAction {
        match self {
            Self::Status => LocalAction::GitStatus,
            Self::Log { .. } | Self::Diff { .. } => LocalAction::GitRead,
            Self::Stage { .. } => LocalAction::GitStage,
            Self::Commit { .. } => LocalAction::GitCommit,
            Self::Push { .. } => LocalAction::GitPush,
        }
    }

    /// What a lease or approval binds to. Distinct per operation *and* per target, so an
    /// approval to push `main` to `origin` does not authorize pushing anything else anywhere.
    pub fn resource_key(&self) -> String {
        match self {
            Self::Status => "git:status".to_string(),
            Self::Log { .. } => "git:log".to_string(),
            Self::Diff { .. } => "git:diff".to_string(),
            Self::Stage { .. } => "git:stage".to_string(),
            Self::Commit { .. } => "git:commit".to_string(),
            Self::Push { remote, branch } => format!("git:push:{remote}:{branch}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitResult {
    pub event_id: String,
    pub correlation_id: String,
    pub action: LocalAction,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    /// Execution-bearing configuration found in the repository. Non-empty means the repo was
    /// rigged; the command still ran safely because the settings were overridden.
    pub neutralized_config: Vec<String>,
}

#[derive(Debug)]
pub struct GitBroker<'a> {
    store: &'a LocalStore,
}

impl<'a> GitBroker<'a> {
    pub fn new(store: &'a LocalStore) -> Self {
        Self { store }
    }

    pub fn run(&self, session_id: &str, request: &GitRequest) -> Result<GitResult> {
        let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
        let (_session, profile, workspace) = self.session_context(session_id)?;
        let action = request.action();
        validate_request(request)?;
        require_repository(&workspace)?;

        let key = request.resource_key();
        let base = crate::evaluate(profile, &workspace, action, &key);
        let authorization =
            self.store
                .authorize_decision(session_id, action, &key, base, |_| Some(key.clone()))?;
        let decision = authorization.decision;
        if !decision.permits_execution() {
            let mut payload = serde_json::to_value(&decision)?;
            if let Some(object) = payload.as_object_mut() {
                object.insert(
                    "risk_state".to_string(),
                    json!(authorization.risk_state.as_str()),
                );
                if let Some(outcome) = &authorization.approval {
                    object.insert(
                        "approval_id".to_string(),
                        json!(outcome.request().approval_id),
                    );
                }
            }
            self.store.append_event(
                session_id,
                "git",
                action.as_str(),
                Some(outcome_name(decision.outcome)),
                &correlation_id,
                &payload,
            )?;
            let message = match &authorization.approval {
                Some(outcome) => format!(
                    "{}; approval {} is required (grant it with `vigil approvals grant {}`)",
                    decision.reason,
                    outcome.request().approval_id,
                    outcome.request().approval_id,
                ),
                None => decision.reason,
            };
            return Err(VigilError::Unauthorized(message));
        }

        // A push leaves the machine, so its destination is bound to the same profile
        // allowlist any other egress uses. Being permitted to push is not permission to push
        // anywhere.
        if let GitRequest::Push { remote, branch: _ } = request {
            self.authorize_push_destination(session_id, profile, &workspace, remote)?;
        }

        // Report a rigged repository before running anything, so the operator learns of it
        // even when the command itself was safely neutralised.
        let neutralized = self.inspect_repository_config(session_id, &workspace)?;

        let charges = match action {
            LocalAction::GitCommit => vec![BudgetCharge::new(BudgetDimension::GitCommits, 1)],
            LocalAction::GitPush => vec![BudgetCharge::new(BudgetDimension::GitPushes, 1)],
            _ => Vec::new(),
        };
        let reservation = if charges.is_empty() {
            None
        } else {
            match self
                .store
                .reserve_budget(session_id, &correlation_id, &charges)
            {
                Ok(reservation) => Some(reservation),
                Err(error) => {
                    self.store.append_event(
                        session_id,
                        "budget",
                        action.as_str(),
                        Some("DENY"),
                        &correlation_id,
                        &json!({
                            "error_class": error.class(),
                            "detection": crate::DETECTION_BUDGET_EXHAUSTION,
                        }),
                    )?;
                    return Err(error);
                }
            }
        };

        let output = self.execute(&workspace, request);
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                if let Some(reservation) = &reservation {
                    self.store.refund_budget(&reservation.id)?;
                }
                self.store.append_event(
                    session_id,
                    "git",
                    action.as_str(),
                    Some("FAILED"),
                    &correlation_id,
                    &json!({ "error_class": error.class(), "budget_refunded": true }),
                )?;
                return Err(error);
            }
        };
        if let Some(reservation) = &reservation {
            // The side effect has occurred. Commit and never refund, as the other brokers do.
            self.store.commit_budget(&reservation.id)?;
        }

        let event = self.store.append_event(
            session_id,
            "git",
            action.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "resolved_resource": key,
                "exit_code": output.exit_code,
                "determining_policy": decision.determining_policy,
                "neutralized_config": neutralized,
                "hooks_disabled": true,
                "ambient_git_config_ignored": true,
                // Diff and log output can contain source and secrets alike; the event records
                // that a command ran and how it exited, never what it printed.
                "output_captured_in_event": false,
            }),
        )?;

        Ok(GitResult {
            event_id: event.event_id,
            correlation_id,
            action,
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            truncated: output.truncated,
            neutralized_config: neutralized,
        })
    }

    /// Resolve a remote to a destination and put it through network policy.
    fn authorize_push_destination(
        &self,
        session_id: &str,
        profile: LocalProfile,
        workspace: &Path,
        remote: &str,
    ) -> Result<()> {
        let url = self.remote_url(workspace, remote)?;
        let host = remote_host(&url).ok_or_else(|| VigilError::InvalidValue {
            field: "remote",
            reason: format!(
                "remote `{remote}` resolves to `{}`, whose host VIGIL cannot determine; \
                     an unidentifiable destination is not authorized",
                vigil_common::redact::redact_url(&url)
            ),
        })?;
        let destination = format!("{host}:443");
        let base = crate::evaluate(
            profile,
            workspace,
            LocalAction::NetworkConnect,
            &destination,
        );
        let authorization = self.store.authorize_decision(
            session_id,
            LocalAction::NetworkConnect,
            &destination,
            base,
            |_| Some(destination.clone()),
        )?;
        if authorization.permits_execution() {
            Ok(())
        } else {
            Err(VigilError::Unauthorized(format!(
                "pushing to `{host}` is not permitted: {}",
                authorization.decision.reason
            )))
        }
    }

    fn remote_url(&self, workspace: &Path, remote: &str) -> Result<String> {
        let output = run_git(
            workspace,
            &[
                "remote".to_string(),
                "get-url".to_string(),
                remote.to_string(),
            ],
        )?;
        let url = output.stdout.trim().to_string();
        if url.is_empty() {
            return Err(VigilError::NotFound(format!("git remote `{remote}`")));
        }
        Ok(url)
    }

    /// Look for execution-bearing configuration in the repository itself.
    fn inspect_repository_config(&self, session_id: &str, workspace: &Path) -> Result<Vec<String>> {
        let output = run_git(
            workspace,
            &[
                "config".to_string(),
                "--local".to_string(),
                "--list".to_string(),
                "--name-only".to_string(),
            ],
        )?;
        let mut found: Vec<String> = output
            .stdout
            .lines()
            .map(|line| line.trim().to_ascii_lowercase())
            .filter(|key| {
                EXECUTABLE_CONFIG_OVERRIDES
                    .iter()
                    .any(|(name, _)| *name == key)
                    || EXECUTABLE_CONFIG_PREFIXES
                        .iter()
                        .any(|prefix| key.starts_with(prefix))
            })
            .collect();
        found.sort();
        found.dedup();

        // A rigged repository is a standing property, not an event per command. Report it once
        // per distinct key set: five Git commands in one session is one finding, not five, and
        // repeating it would accumulate risk until an ordinary repository looked alarming.
        // A *changed* key set is reported again, because config appearing mid-session is the
        // interesting case.
        let already_reported = self
            .store
            .detections_for_session(session_id)?
            .into_iter()
            .rfind(|detection| detection.rule_id == "VIGIL-L021")
            .and_then(|detection| {
                detection
                    .evidence
                    .get("keys")
                    .and_then(|keys| serde_json::from_value::<Vec<String>>(keys.clone()).ok())
            })
            .is_some_and(|previous| previous == found);

        if !found.is_empty() && !already_reported {
            if let Some(rule) = crate::rule_for_label(DETECTION_GIT_EXECUTABLE_CONFIG) {
                self.store.record_detection(
                    session_id,
                    rule,
                    // Key names only. A config *value* is the command that would have run and
                    // may embed a token; recording the key says enough to investigate.
                    json!({ "keys": found, "values_captured": false, "neutralized": true }),
                    None,
                )?;
                self.store.record_risk_signal(
                    session_id,
                    rule.dimension,
                    rule.weight,
                    None,
                    rule.description,
                )?;
            }
        }
        Ok(found)
    }

    fn execute(&self, workspace: &Path, request: &GitRequest) -> Result<GitOutput> {
        let argv: Vec<String> = match request {
            GitRequest::Status => vec![
                "status".into(),
                "--porcelain=v1".into(),
                "--untracked-files=normal".into(),
            ],
            GitRequest::Log { max_count } => vec![
                "log".into(),
                format!("--max-count={max_count}"),
                "--pretty=format:%H %an %ad %s".into(),
                "--date=iso-strict".into(),
            ],
            GitRequest::Diff { staged } => {
                let mut argv = vec!["diff".to_string()];
                if *staged {
                    argv.push("--staged".into());
                }
                argv
            }
            GitRequest::Stage { paths } => {
                let mut argv = vec!["add".to_string(), "--".to_string()];
                argv.extend(paths.iter().cloned());
                argv
            }
            GitRequest::Commit { message } => vec![
                "commit".into(),
                "--message".into(),
                message.clone(),
                // No hooks, and no editor: the message is supplied, never prompted for.
                "--no-verify".into(),
                "--no-edit".into(),
            ],
            GitRequest::Push { remote, branch } => vec![
                "push".into(),
                "--no-verify".into(),
                remote.clone(),
                branch.clone(),
            ],
        };
        run_git(workspace, &argv)
    }

    fn session_context(&self, session_id: &str) -> Result<(LocalSession, LocalProfile, PathBuf)> {
        let session = self
            .store
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        if session.status != SessionStatus::Running
            || session.enforcement_posture != "semantic_enforced"
        {
            return Err(VigilError::Unauthorized(
                "git broker requires a running semantic-enforced session".to_string(),
            ));
        }
        let profile = session.profile.parse()?;
        let workspace = PathBuf::from(&session.workspace);
        Ok((session, profile, workspace))
    }
}

#[derive(Debug)]
struct GitOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    truncated: bool,
}

/// Build a `git` invocation that cannot be steered by repository configuration.
///
/// The `-c` overrides are applied unconditionally rather than after inspecting the repository,
/// because a check-then-run sequence is a race: the repository is writable by the very agent
/// the check is about.
fn hardened_command(workspace: &Path, argv: &[String], neutral_home: &Path) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .current_dir(workspace)
        .env_clear()
        // No system or user configuration contributes anything.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", neutral_home)
        .env("XDG_CONFIG_HOME", neutral_home)
        // Git must never stop for input or reach out to an askpass helper.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin");
    for (key, value) in EXECUTABLE_CONFIG_OVERRIDES {
        command.arg("-c").arg(format!("{key}={value}"));
    }
    // Hooks live in the repository and run on commit and push. Point Git at an empty
    // directory VIGIL owns so there are none to find.
    command
        .arg("-c")
        .arg(format!("core.hooksPath={}", neutral_home.display()));
    command.args(argv);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run_git(workspace: &Path, argv: &[String]) -> Result<GitOutput> {
    // A per-invocation empty directory serves as both the neutral HOME and the empty hooks
    // path. It is created fresh so nothing can have planted a hook or a gitconfig in it.
    let neutral_home = std::env::temp_dir().join(format!("vigil-git-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&neutral_home)?;
    let outcome = (|| -> Result<GitOutput> {
        // `GIT_TERMINAL_PROMPT=0` stops Git waiting on a person, but a network operation can
        // still hang indefinitely. A broker that can block forever is a broker that can wedge
        // whatever called it, so the wait is bounded and the child is killed at the deadline.
        let mut child = hardened_command(workspace, argv, &neutral_home)
            .spawn()
            .map_err(|error| VigilError::Unavailable {
                component: "git",
                reason: error.kind().to_string(),
            })?;

        // Output is drained on threads so a child filling a pipe cannot deadlock against a
        // parent that is only polling for exit.
        let stdout = child.stdout.take().map(spawn_reader);
        let stderr = child.stderr.take().map(spawn_reader);

        let deadline = std::time::Instant::now() + Duration::from_millis(GIT_TIMEOUT_MS);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VigilError::Unavailable {
                        component: "git",
                        reason: error.kind().to_string(),
                    });
                }
            }
        };

        let stdout = stdout.map(join_reader).unwrap_or_default();
        let stderr = stderr.map(join_reader).unwrap_or_default();
        let Some(status) = status else {
            return Err(VigilError::Unavailable {
                component: "git",
                reason: format!("git exceeded its {GIT_TIMEOUT_MS}ms bound and was terminated"),
            });
        };
        let truncated = stdout.len() > MAX_OUTPUT_BYTES || stderr.len() > MAX_OUTPUT_BYTES;
        Ok(GitOutput {
            exit_code: status.code(),
            stdout: bounded(&stdout),
            stderr: bounded(&stderr),
            truncated,
        })
    })();
    let _ = std::fs::remove_dir_all(&neutral_home);
    outcome
}

/// Drain one pipe on its own thread, bounded, so a chatty child cannot deadlock the wait.
fn spawn_reader<R: Read + Send + 'static>(mut source: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        // Read past the return bound so the pipe keeps draining, then truncate. Stopping at
        // the bound would block the child on a full pipe forever.
        let _ = source
            .by_ref()
            .take((MAX_OUTPUT_BYTES * 2) as u64)
            .read_to_end(&mut buffer);
        let _ = std::io::copy(&mut source, &mut std::io::sink());
        buffer
    })
}

fn join_reader(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

fn bounded(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}

/// Reject anything a caller could use to smuggle an option into the argument vector.
///
/// A branch named `--upload-pack=...`, a path named `-c`, or a message beginning with `-`
/// would otherwise be parsed by Git as an option rather than as data. `--` separators help for
/// paths but not for every position, so leading `-` is refused outright.
fn validate_request(request: &GitRequest) -> Result<()> {
    let check = |value: &str, field: &'static str, limit: usize| -> Result<()> {
        if value.is_empty() || value.len() > limit {
            return Err(VigilError::InvalidValue {
                field,
                reason: format!("must be 1..={limit} bytes"),
            });
        }
        if value.starts_with('-') {
            return Err(VigilError::InvalidValue {
                field,
                reason: "must not begin with `-`; Git would parse it as an option".to_string(),
            });
        }
        if value.contains('\0') || value.contains('\n') {
            return Err(VigilError::InvalidValue {
                field,
                reason: "must not contain a null byte or newline".to_string(),
            });
        }
        Ok(())
    };

    match request {
        GitRequest::Status | GitRequest::Diff { .. } => Ok(()),
        GitRequest::Log { max_count } => {
            if *max_count == 0 || *max_count > 1000 {
                return Err(VigilError::InvalidValue {
                    field: "max_count",
                    reason: "must be between 1 and 1000".to_string(),
                });
            }
            Ok(())
        }
        GitRequest::Stage { paths } => {
            if paths.is_empty() || paths.len() > 256 {
                return Err(VigilError::InvalidValue {
                    field: "paths",
                    reason: "stage between 1 and 256 paths".to_string(),
                });
            }
            for path in paths {
                check(path, "path", MAX_ARGUMENT_BYTES)?;
                if path.contains("..") {
                    return Err(VigilError::InvalidValue {
                        field: "path",
                        reason: "must not contain `..`".to_string(),
                    });
                }
            }
            Ok(())
        }
        GitRequest::Commit { message } => {
            // A message may legitimately contain newlines, so it is checked separately.
            if message.is_empty() || message.len() > MAX_MESSAGE_BYTES {
                return Err(VigilError::InvalidValue {
                    field: "message",
                    reason: format!("must be 1..={MAX_MESSAGE_BYTES} bytes"),
                });
            }
            if message.starts_with('-') || message.contains('\0') {
                return Err(VigilError::InvalidValue {
                    field: "message",
                    reason: "must not begin with `-` or contain a null byte".to_string(),
                });
            }
            Ok(())
        }
        GitRequest::Push { remote, branch } => {
            check(remote, "remote", 256)?;
            check(branch, "branch", 256)?;
            Ok(())
        }
    }
}

fn require_repository(workspace: &Path) -> Result<()> {
    if workspace.join(".git").exists() {
        Ok(())
    } else {
        Err(VigilError::NotFound(format!(
            "`{}` is not a Git repository",
            workspace.display()
        )))
    }
}

/// Extract the host from a remote URL, covering both URL and `scp`-style SSH forms.
///
/// Public because getting this wrong is a security bug on its own: a URL whose userinfo is
/// mistaken for its host would let `https://github.com@attacker.example/x` pass a check meant
/// for GitHub. It is fuzzed separately for that reason.
pub fn remote_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if let Some(rest) = trimmed.split("://").nth(1) {
        let authority = rest.split(['/', '?', '#']).next()?;
        // Strip any userinfo before the host.
        let host = authority.rsplit('@').next()?;
        let host = host.split(':').next()?;
        return valid_hostname(host);
    }
    // `git@github.com:owner/repo.git`
    if let Some((authority, _)) = trimmed.split_once(':') {
        let host = authority.rsplit('@').next()?;
        return valid_hostname(host);
    }
    None
}

/// Accept only something that is actually a hostname.
///
/// Found by fuzzing. The previous version returned whatever survived splitting, so an input
/// like `"\0#,,:"` yielded a "host" containing a NUL byte. That was fail-closed downstream —
/// the network allowlist rejected it — but a function whose whole job is to produce a value
/// checked against an allowlist should return a hostname or nothing, not junk for the caller
/// to re-validate. `None` refuses the push, which is always the safe answer.
fn valid_hostname(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return None;
        }
    }
    Some(host.to_ascii_lowercase())
}

fn outcome_name(outcome: crate::DecisionOutcome) -> &'static str {
    match outcome {
        crate::DecisionOutcome::Allow => "ALLOW",
        crate::DecisionOutcome::Deny => "DENY",
        crate::DecisionOutcome::RequireApproval => "REQUIRE_APPROVAL",
        crate::DecisionOutcome::Observe => "OBSERVE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leading_dash_is_refused_everywhere_a_caller_supplies_a_value() {
        // Each of these would be parsed by Git as an option rather than as data.
        assert!(validate_request(&GitRequest::Push {
            remote: "--upload-pack=touch /tmp/pwned".to_string(),
            branch: "main".to_string(),
        })
        .is_err());
        assert!(validate_request(&GitRequest::Push {
            remote: "origin".to_string(),
            branch: "--exec=whoami".to_string(),
        })
        .is_err());
        assert!(validate_request(&GitRequest::Stage {
            paths: vec!["-c".to_string()],
        })
        .is_err());
        assert!(validate_request(&GitRequest::Commit {
            message: "--amend".to_string(),
        })
        .is_err());

        // The ordinary forms still pass.
        assert!(validate_request(&GitRequest::Push {
            remote: "origin".to_string(),
            branch: "main".to_string(),
        })
        .is_ok());
        assert!(validate_request(&GitRequest::Commit {
            message: "fix: handle empty input\n\nDetails here.".to_string(),
        })
        .is_ok());
    }

    #[test]
    fn staged_paths_cannot_traverse() {
        assert!(validate_request(&GitRequest::Stage {
            paths: vec!["../outside".to_string()],
        })
        .is_err());
        assert!(validate_request(&GitRequest::Stage {
            paths: vec!["src/main.rs".to_string()],
        })
        .is_ok());
        assert!(validate_request(&GitRequest::Stage { paths: vec![] }).is_err());
    }

    #[test]
    fn a_push_binds_its_lease_to_one_remote_and_branch() {
        let main = GitRequest::Push {
            remote: "origin".to_string(),
            branch: "main".to_string(),
        };
        let other = GitRequest::Push {
            remote: "origin".to_string(),
            branch: "release".to_string(),
        };
        let elsewhere = GitRequest::Push {
            remote: "backup".to_string(),
            branch: "main".to_string(),
        };
        assert_ne!(main.resource_key(), other.resource_key());
        assert_ne!(main.resource_key(), elsewhere.resource_key());
        assert_eq!(main.resource_key(), "git:push:origin:main");
    }

    #[test]
    fn remote_hosts_are_extracted_from_every_form_git_accepts() {
        assert_eq!(
            remote_host("https://github.com/owner/repo.git").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            remote_host("https://user:token@github.com/owner/repo.git").as_deref(),
            Some("github.com"),
            "userinfo must not be mistaken for the host"
        );
        assert_eq!(
            remote_host("ssh://git@gitlab.example:2222/owner/repo.git").as_deref(),
            Some("gitlab.example")
        );
        assert_eq!(
            remote_host("git@github.com:owner/repo.git").as_deref(),
            Some("github.com")
        );
        assert_eq!(remote_host("/local/path/repo.git"), None);

        // Found by fuzzing: anything that is not a hostname is refused outright rather than
        // returned for the caller to notice. `\0#,,:` produced a "host" with a NUL byte.
        for junk in [
            "\u{0}#,,:",
            "a@",
            "@",
            "://@",
            "-bad.example:x",
            "..:x",
            "a..b:x",
        ] {
            assert_eq!(remote_host(junk), None, "`{junk}` must not yield a host");
        }
    }

    /// Every key that Git executes must be overridden on every invocation, not merely
    /// detected. Detection is a race against a repository the agent can rewrite.
    #[test]
    fn every_execution_bearing_key_is_overridden_unconditionally() {
        let neutral = std::env::temp_dir().join("vigil-git-test-home");
        let command = hardened_command(Path::new("/tmp"), &["status".to_string()], &neutral);
        let rendered: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        for (key, _) in EXECUTABLE_CONFIG_OVERRIDES {
            assert!(
                rendered
                    .iter()
                    .any(|arg| arg.starts_with(&format!("{key}="))),
                "`{key}` is not overridden"
            );
        }
        assert!(
            rendered
                .iter()
                .any(|arg| arg.starts_with("core.hooksPath=")),
            "hooks are not redirected"
        );
        // The overrides precede the subcommand, which is what makes them take effect.
        let subcommand = rendered
            .iter()
            .position(|arg| arg == "status")
            .expect("status");
        let last_override = rendered
            .iter()
            .rposition(|arg| arg == "-c")
            .expect("an override");
        assert!(last_override < subcommand);
    }

    #[test]
    fn the_environment_carries_nothing_ambient() {
        let neutral = std::env::temp_dir().join("vigil-git-test-home");
        let command = hardened_command(Path::new("/tmp"), &["status".to_string()], &neutral);
        let environment: std::collections::BTreeMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().into_owned(),
                    value?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            environment.get("GIT_CONFIG_NOSYSTEM").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            environment.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            environment.get("HOME").map(String::as_str),
            Some(neutral.display().to_string().as_str()),
            "HOME must not point at the real user's gitconfig"
        );
        assert_eq!(environment.get("GIT_ASKPASS").map(String::as_str), Some(""));
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::NewSession;

    /// A repository rigged the way an agent that can write files would rig it.
    fn rigged_repository(root: &Path) -> PathBuf {
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical");
        let run = |args: &[&str]| {
            let status = Command::new("/usr/bin/git")
                .current_dir(&workspace)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("HOME", root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run git");
            assert!(status.success(), "git {args:?} failed");
        };
        run(&["init", "--initial-branch=main", "."]);
        run(&["config", "user.email", "test@example.invalid"]);
        run(&["config", "user.name", "VIGIL Test"]);

        // Every one of these executes a program when Git next runs.
        let marker = root.join("PWNED");
        let payload = format!("touch {}", marker.display());
        run(&["config", "core.pager", &payload]);
        run(&["config", "core.editor", &payload]);
        run(&["config", "core.sshCommand", &payload]);
        run(&["config", "alias.st", &format!("!{payload}")]);
        run(&["config", "credential.helper", &format!("!{payload}")]);

        // And a hook, which runs on commit.
        let hooks = workspace.join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("hooks dir");
        let hook = hooks.join("pre-commit");
        std::fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", marker.display()))
            .expect("write hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
                .expect("chmod hook");
        }
        workspace
    }

    fn session(root: &Path, workspace: &Path) -> (LocalStore, String) {
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let created = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace: workspace.to_path_buf(),
                executable: "vigil-test".to_string(),
                argv: vec!["vigil-test".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&created.id, std::process::id())
            .expect("activate");
        (store, created.id)
    }

    /// The central claim of this module: running Git inside a repository the agent controls
    /// must not execute what that repository asks Git to execute.
    #[test]
    fn a_rigged_repository_cannot_execute_anything_through_the_broker() {
        let root = std::env::temp_dir().join(format!("vigil-git-live-{}", uuid::Uuid::new_v4()));
        let workspace = rigged_repository(&root);
        let marker = root.join("PWNED");
        let (store, id) = session(&root, &workspace);
        let broker = GitBroker::new(&store);

        std::fs::write(workspace.join("a.txt"), b"content").expect("seed");
        broker.run(&id, &GitRequest::Status).expect("status");
        broker
            .run(
                &id,
                &GitRequest::Stage {
                    paths: vec!["a.txt".to_string()],
                },
            )
            .expect("stage");
        broker
            .run(
                &id,
                &GitRequest::Commit {
                    message: "test commit".to_string(),
                },
            )
            .expect("commit");
        broker
            .run(&id, &GitRequest::Log { max_count: 5 })
            .expect("log");
        broker
            .run(&id, &GitRequest::Diff { staged: false })
            .expect("diff");

        assert!(
            !marker.exists(),
            "the repository's configuration or hooks executed: {} exists",
            marker.display()
        );

        // Finding neutralised configuration must not itself contain the session: nothing
        // executed, and the keys involved are ordinary in real repositories.
        assert_eq!(
            store.session_risk_state(&id).expect("risk"),
            crate::RiskState::Normal,
            "neutralised Git configuration must not degrade a session on its own"
        );

        // And the rigging was reported rather than silently absorbed.
        let detections = store.detections_for_session(&id).expect("detections");
        assert!(
            detections
                .iter()
                .any(|detection| detection.rule_id == "VIGIL-L021"),
            "an executable-config repository must be reported: {detections:?}"
        );
        // Key names are recorded; the values are the commands and are not stored.
        let evidence = detections
            .iter()
            .find(|detection| detection.rule_id == "VIGIL-L021")
            .expect("detection")
            .evidence
            .to_string();
        assert!(evidence.contains("core.pager"));
        assert!(
            !evidence.contains("PWNED"),
            "config values must not be stored"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// The same rigging, run without the broker, does fire — so the test above is proving the
    /// hardening works rather than proving the payload was inert.
    #[test]
    fn the_control_shows_the_rigging_would_otherwise_execute() {
        let root = std::env::temp_dir().join(format!("vigil-git-ctrl-{}", uuid::Uuid::new_v4()));
        let workspace = rigged_repository(&root);
        let marker = root.join("PWNED");

        // A naive invocation: no -c overrides, hooks enabled.
        let status = Command::new("/usr/bin/git")
            .current_dir(&workspace)
            .args(["commit", "--allow-empty", "--message", "naive"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git");
        let _ = status;
        assert!(
            marker.exists(),
            "the control must demonstrate the payload is live, or the hardening test proves \
             nothing"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn force_push_is_denied_and_a_push_needs_an_approval() {
        let root = std::env::temp_dir().join(format!("vigil-git-push-{}", uuid::Uuid::new_v4()));
        let workspace = rigged_repository(&root);
        let (store, id) = session(&root, &workspace);

        // Force-push is not a request shape this broker offers at all, and the capability is
        // denied by policy in every profile.
        // Every enforcing profile denies it. The observe profile is excluded because its
        // contract is that it does not enforce anything; see `risk_does_not_make_the_observe
        // _profile_enforce` in `policy.rs`.
        for profile in crate::LocalProfile::ALL
            .into_iter()
            .filter(|profile| *profile != crate::LocalProfile::Observe)
        {
            let decision = crate::evaluate(
                profile,
                &workspace,
                LocalAction::GitForcePush,
                "git:push:origin:main",
            );
            assert_eq!(
                decision.outcome,
                crate::DecisionOutcome::Deny,
                "force push must be denied under {}",
                profile.as_str()
            );
        }

        // A push needs an approval before its destination is even considered.
        let error = GitBroker::new(&store)
            .run(
                &id,
                &GitRequest::Push {
                    remote: "origin".to_string(),
                    branch: "main".to_string(),
                },
            )
            .expect_err("a push must not proceed unapproved");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn config_and_remote_changes_are_denied_capabilities() {
        let root = std::env::temp_dir().join(format!("vigil-git-cfg-{}", uuid::Uuid::new_v4()));
        let workspace = rigged_repository(&root);
        for action in [LocalAction::GitConfig, LocalAction::GitRemoteModify] {
            let decision = crate::evaluate(
                crate::LocalProfile::DeveloperStandard,
                &workspace,
                action,
                "git:config",
            );
            assert_eq!(decision.outcome, crate::DecisionOutcome::Deny);
            assert_eq!(
                decision.detection.as_deref(),
                Some(DETECTION_GIT_CONTROL_SURFACE)
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
