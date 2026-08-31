//! Structured process semantic enforcement point.
//!
//! Requests bind an absolute canonical executable, argument vector, workspace working directory,
//! small environment allowlist, timeout, session, policy decision, and durable process budget.
//! No shell string is accepted. This broker does not sandbox the spawned process or prevent a
//! process from bypassing VIGIL; Endpoint Security remains the required OS enforcement point.

use crate::provenance::NewProcess;
use crate::{
    classify_executable, evaluate_process, BudgetCharge, BudgetDimension, DecisionOutcome,
    ExecutableClass, LocalAction, LocalProfile, LocalSession, LocalStore, ProcessStatus,
    SessionStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use vigil_common::{Result, VigilError};

const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_TOTAL_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 8;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 256;
const MAX_TIMEOUT_MS: u64 = 30_000;
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const ALLOWED_ENVIRONMENT_KEYS: [&str; 4] = ["LANG", "LC_ALL", "NO_COLOR", "TZ"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRequest {
    pub program: PathBuf,
    pub arguments: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
    pub timeout_ms: u64,
}

impl ProcessRequest {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            cwd: None,
            environment: BTreeMap::new(),
            timeout_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessBrokerResult {
    pub event_id: String,
    pub spawn_event_id: String,
    pub reservation_id: String,
    pub correlation_id: String,
    pub executable: PathBuf,
    pub executable_class: ExecutableClass,
    pub pid: u32,
    /// Identity of this process in the session's provenance graph. Unlike the PID, it is
    /// never reused.
    pub process_node_id: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug)]
pub struct ProcessBroker<'a> {
    store: &'a LocalStore,
}

impl<'a> ProcessBroker<'a> {
    pub fn new(store: &'a LocalStore) -> Self {
        Self { store }
    }

    pub fn execute(
        &self,
        session_id: &str,
        request: &ProcessRequest,
    ) -> Result<ProcessBrokerResult> {
        let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
        let (_session, profile, workspace) = self.session_context(session_id)?;
        let validated = match validate_request(request, &workspace) {
            Ok(validated) => validated,
            Err(error) => {
                self.store.append_event(
                    session_id,
                    "process",
                    "process.request_invalid",
                    Some("DENY"),
                    &correlation_id,
                    &json!({"error_class": error.class()}),
                )?;
                return Err(error);
            }
        };
        let base = evaluate_process(
            profile,
            &workspace,
            &validated.executable,
            &request.arguments,
        );
        // A lease or approval for process execution binds to the canonical executable path —
        // the binary that would actually run, not the string the caller typed.
        let executable_key = validated.executable.display().to_string();
        let authorization = self.store.authorize_decision(
            session_id,
            LocalAction::ProcessExec,
            &executable_key,
            base,
            |_| Some(executable_key.clone()),
        )?;
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
                    if let Some(detection) = outcome.detection() {
                        object.insert("detection".to_string(), json!(detection));
                    }
                }
            }
            self.store.append_event(
                session_id,
                "policy",
                &decision.action,
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
        let executable_class = classify_executable(&validated.executable);
        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[BudgetCharge::new(BudgetDimension::ProcessExecutions, 1)],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.store.append_event(
                    session_id,
                    "budget",
                    "process.exec",
                    Some("DENY"),
                    &correlation_id,
                    &json!({
                        "determining_policy": decision.determining_policy,
                        "error_class": error.class(),
                    }),
                )?;
                return Err(error);
            }
        };

        // The name is resolved again by `spawn`, so confirm it still refers to the object
        // that was validated and hashed. This narrows the validate-to-spawn race in the same
        // way ADR 0031 narrows decide-to-open; it does not eliminate it, because only the
        // kernel can report what was actually executed.
        if !executable_unchanged(&validated.executable, &validated.identity) {
            let error = VigilError::AuditIntegrity(format!(
                "`{}` changed identity between validation and execution; refusing to run a \
                 binary that was never checked",
                validated.executable.display()
            ));
            self.store.append_event(
                session_id,
                "process",
                "process.identity_changed",
                Some("DENY"),
                &correlation_id,
                &json!({
                    "executable": executable_key,
                    "error_class": error.class(),
                    "detection": crate::DETECTION_EXECUTABLE_IDENTITY_CHANGED,
                }),
            )?;
            if let Some(rule) = crate::rule_for_label(crate::DETECTION_EXECUTABLE_IDENTITY_CHANGED)
            {
                self.store.record_detection(
                    session_id,
                    rule,
                    json!({ "executable": executable_key }),
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
            return Err(error);
        }

        let mut command = Command::new(&validated.executable);
        command
            .args(&request.arguments)
            .current_dir(&validated.cwd)
            .env_clear()
            .envs(&request.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                self.store.refund_budget(&reservation.id)?;
                self.store.append_event(
                    session_id,
                    "process",
                    "process.exec",
                    Some("FAILED"),
                    &correlation_id,
                    &json!({
                        "reservation_id": reservation.id,
                        "determining_policy": decision.determining_policy,
                        "error_class": "io",
                        "budget_refunded": true,
                    }),
                )?;
                return Err(error.into());
            }
        };
        let pid = child.id();
        // Read the kernel's start time while the child handle is still held: until it is
        // reaped the PID cannot be reused, so this identity is unambiguously the process
        // just spawned. A failure to read it is recorded as absence, which makes the node
        // unsignallable rather than mis-signallable.
        let observed = crate::process_identity::identify(pid).ok().flatten();
        let node = match self.store.record_process_start(&NewProcess {
            session_id,
            parent_node_id: None,
            pid,
            executable: &executable_key,
            argv: &request.arguments,
            executable_sha256: validated.identity.sha256.as_deref(),
            observed: observed.as_ref(),
        }) {
            Ok(node) => node,
            Err(error) => {
                terminate_child(&mut child);
                let _ = self.store.append_event(
                    session_id,
                    "process",
                    "process.attribution_failed",
                    Some("ERROR"),
                    &correlation_id,
                    &json!({
                        "pid": pid,
                        "reservation_id": reservation.id,
                        "error_class": error.class(),
                    }),
                );
                return Err(error);
            }
        };
        // Every path from here on must close the node, including the error paths: a node left
        // open holds its PID in the live index, which would make a later unrelated process
        // that happens to be given the same PID unrecordable.
        let node_guard = ProcessNodeGuard::new(self.store, node.node_id.clone());

        // The side effect has occurred once spawn succeeds. Commit immediately and never refund
        // afterward, including for non-zero exits, timeouts, or evidence-storage failures.
        if let Err(error) = self.store.commit_budget(&reservation.id) {
            terminate_child(&mut child);
            let _ = self.store.append_event(
                session_id,
                "budget",
                "budget.reconciliation_failed",
                Some("ERROR"),
                &correlation_id,
                &json!({
                    "reservation_id": reservation.id,
                    "operation_executed": true,
                    "error_class": error.class(),
                }),
            );
            return Err(error);
        }
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            terminate_child(&mut child);
            let error = VigilError::Unavailable {
                component: "process_broker",
                reason: "child output pipes were not created".to_string(),
            };
            let _ = self.store.append_event(
                session_id,
                "process",
                "process.capture_failed",
                Some("ERROR"),
                &correlation_id,
                &json!({
                    "pid": pid,
                    "reservation_id": reservation.id,
                    "error_class": error.class(),
                }),
            );
            return Err(error);
        };
        let stdout_capture = spawn_capture(stdout);
        let stderr_capture = spawn_capture(stderr);

        let spawn_event = match self.store.append_event(
            session_id,
            "process",
            "process.spawn",
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "pid": pid,
                "executable": validated.executable,
                "executable_class": executable_class.as_str(),
                "argument_count": request.arguments.len(),
                "environment_keys": request.environment.keys().collect::<Vec<_>>(),
                "cwd": validated.cwd,
                "timeout_ms": request.timeout_ms,
                "reservation_id": reservation.id,
                "determining_policy": decision.determining_policy,
                "argument_content_captured": false,
                "environment_values_captured": false,
                "os_enforcement": false,
            }),
        ) {
            Ok(event) => event,
            Err(error) => {
                terminate_child(&mut child);
                let _ = join_capture(stdout_capture);
                let _ = join_capture(stderr_capture);
                return Err(error);
            }
        };

        let (status, timed_out) = match wait_bounded(&mut child, request.timeout_ms) {
            Ok(result) => result,
            Err(error) => {
                terminate_child(&mut child);
                let _ = join_capture(stdout_capture);
                let _ = join_capture(stderr_capture);
                let _ = self.store.append_event(
                    session_id,
                    "process",
                    "process.wait_failed",
                    Some("ERROR"),
                    &correlation_id,
                    &json!({
                        "pid": pid,
                        "reservation_id": reservation.id,
                        "error_class": error.class(),
                    }),
                );
                return Err(error);
            }
        };
        let stdout = join_capture(stdout_capture);
        let stderr = join_capture(stderr_capture);
        let (stdout, stderr) = match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => (stdout, stderr),
            (stdout, stderr) => {
                let error = stdout.err().or_else(|| stderr.err()).ok_or_else(|| {
                    VigilError::Unavailable {
                        component: "process_broker",
                        reason: "output capture failed without an error".to_string(),
                    }
                })?;
                let _ = self.store.append_event(
                    session_id,
                    "process",
                    "process.capture_failed",
                    Some("ERROR"),
                    &correlation_id,
                    &json!({
                        "pid": pid,
                        "reservation_id": reservation.id,
                        "error_class": error.class(),
                    }),
                );
                return Err(error);
            }
        };
        let event = self.store.append_event(
            session_id,
            "process",
            "process.exit",
            Some(if timed_out { "TIMEOUT" } else { "EXECUTED" }),
            &correlation_id,
            &json!({
                "pid": pid,
                "exit_code": status.code(),
                "timed_out": timed_out,
                "stdout_bytes_observed": stdout.observed,
                "stderr_bytes_observed": stderr.observed,
                "stdout_truncated": stdout.truncated,
                "stderr_truncated": stderr.truncated,
                "output_content_captured_in_event": false,
                "reservation_id": reservation.id,
            }),
        )?;
        node_guard.close(
            status.code(),
            if timed_out {
                ProcessStatus::Terminated
            } else {
                ProcessStatus::Exited
            },
        );

        Ok(ProcessBrokerResult {
            event_id: event.event_id,
            spawn_event_id: spawn_event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            executable: validated.executable,
            executable_class,
            pid,
            process_node_id: node.node_id,
            exit_code: status.code(),
            timed_out,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_truncated: stdout.truncated,
            stderr_truncated: stderr.truncated,
        })
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
                "process broker requires a running semantic-enforced session".to_string(),
            ));
        }
        let profile = session.profile.parse()?;
        let workspace = PathBuf::from(&session.workspace);
        Ok((session, profile, workspace))
    }
}

/// Closes a provenance node however the broker leaves the function.
///
/// The broker has six exits after a successful spawn, several of them error paths. Rather
/// than trusting each one to remember, closing is tied to the scope. An unclosed node would
/// keep its PID in the live-PID index forever, so the failure mode of forgetting is not a
/// missing record but a later refusal to record an unrelated process.
struct ProcessNodeGuard<'a> {
    store: &'a LocalStore,
    node_id: String,
    outcome: Option<(Option<i32>, ProcessStatus)>,
}

impl<'a> ProcessNodeGuard<'a> {
    fn new(store: &'a LocalStore, node_id: String) -> Self {
        Self {
            store,
            node_id,
            outcome: None,
        }
    }

    /// Close with a known result. Consuming `self` runs the drop immediately.
    fn close(mut self, exit_code: Option<i32>, status: ProcessStatus) {
        self.outcome = Some((exit_code, status));
    }
}

impl Drop for ProcessNodeGuard<'_> {
    fn drop(&mut self) {
        // An unclosed guard means the broker gave up without observing an exit. `Unknown` is
        // the honest record of that, and is preferable to claiming a clean exit.
        let (exit_code, status) = self
            .outcome
            .take()
            .unwrap_or((None, ProcessStatus::Unknown));
        // The node must be released even if evidence storage is failing; a storage error here
        // has already been reported by whatever is returning.
        let _ = self
            .store
            .record_process_exit(&self.node_id, exit_code, status);
    }
}

#[derive(Debug)]
struct ValidatedRequest {
    executable: PathBuf,
    cwd: PathBuf,
    /// The executable as it was at validation time.
    ///
    /// §17 is explicit that an executable path is not sufficient identity. Recording the
    /// object lets the spawn be checked against the thing that was validated rather than
    /// against a name that may since point elsewhere, and recording the hash is what makes
    /// the provenance graph say *what ran*.
    identity: ExecutableIdentity,
}

/// Largest executable VIGIL will hash before spawning it.
///
/// Hashing is per-execution work on the broker's path, and the enforced profiles permit only
/// small system utilities. A binary above this bound still records its device and inode, so it
/// is still identified — just not by content.
const MAX_HASHED_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

/// How VIGIL identifies a binary: the object it is, and the bytes it contains.
///
/// Both, because they answer different questions. The object says "this is still the file I
/// checked"; the hash says "and these are the bytes that ran", which is what the provenance
/// graph needs long after the file has been replaced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExecutableIdentity {
    /// Device and inode. `None` on platforms that do not expose them.
    object: Option<(u64, u64)>,
    /// Content hash. `None` when the file is too large to hash.
    sha256: Option<String>,
}

/// Identify an executable by object and, where practical, by content.
fn identify_executable(path: &Path) -> Result<ExecutableIdentity> {
    let metadata = std::fs::symlink_metadata(path)?;
    let sha256 = if metadata.len() <= MAX_HASHED_EXECUTABLE_BYTES {
        Some(vigil_common::ContentHash::sha256(&std::fs::read(path)?).to_string())
    } else {
        None
    };
    #[cfg(unix)]
    let object = {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    };
    #[cfg(not(unix))]
    let object = None;
    Ok(ExecutableIdentity { object, sha256 })
}

/// Whether the executable is still the object that was validated.
///
/// A path that can no longer be read counts as changed: it is certainly not the object that
/// was checked.
fn executable_unchanged(path: &Path, expected: &ExecutableIdentity) -> bool {
    let Ok(observed) = identify_executable(path) else {
        return false;
    };

    // Device/inode narrows a path-swap race, but filesystems may reuse an inode immediately
    // after unlink. When content was small enough to hash during validation, require the hash
    // too. On platforms without a stable object identifier the hash is the only evidence.
    let object_matches = match expected.object {
        Some(object) => observed.object == Some(object),
        None => true,
    };
    let content_matches = match &expected.sha256 {
        Some(sha256) => observed.sha256.as_ref() == Some(sha256),
        None => true,
    };
    object_matches && content_matches
}

fn validate_request(request: &ProcessRequest, workspace: &Path) -> Result<ValidatedRequest> {
    if !request.program.is_absolute() {
        return Err(VigilError::InvalidValue {
            field: "program",
            reason: "structured process execution requires an absolute executable path".to_string(),
        });
    }
    if request.timeout_ms == 0 || request.timeout_ms > MAX_TIMEOUT_MS {
        return Err(VigilError::InvalidValue {
            field: "timeout_ms",
            reason: format!("timeout must be between 1 and {MAX_TIMEOUT_MS} milliseconds"),
        });
    }
    if request.arguments.len() > MAX_ARGUMENTS {
        return Err(VigilError::InvalidValue {
            field: "arguments",
            reason: format!("at most {MAX_ARGUMENTS} arguments are accepted"),
        });
    }
    let mut total = 0usize;
    for argument in &request.arguments {
        if argument.as_bytes().contains(&0) || argument.len() > MAX_ARGUMENT_BYTES {
            return Err(VigilError::InvalidValue {
                field: "arguments",
                reason: "an argument is invalid or exceeds the per-argument bound".to_string(),
            });
        }
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| VigilError::InvalidValue {
                field: "arguments",
                reason: "total argument size overflowed".to_string(),
            })?;
    }
    if total > MAX_TOTAL_ARGUMENT_BYTES {
        return Err(VigilError::InvalidValue {
            field: "arguments",
            reason: format!("total argument data exceeds {MAX_TOTAL_ARGUMENT_BYTES} bytes"),
        });
    }
    validate_environment(&request.environment)?;

    let executable =
        std::fs::canonicalize(&request.program).map_err(|_| VigilError::InvalidValue {
            field: "program",
            reason: "executable identity could not be resolved".to_string(),
        })?;
    let metadata = std::fs::metadata(&executable)?;
    if !metadata.is_file() {
        return Err(VigilError::InvalidValue {
            field: "program",
            reason: "executable is not a regular file".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o6000 != 0 {
            return Err(VigilError::Unauthorized(
                "executable lacks execute permission or has set-id bits".to_string(),
            ));
        }
    }

    let requested_cwd = request.cwd.as_deref().unwrap_or(workspace);
    let cwd = std::fs::canonicalize(requested_cwd).map_err(|_| VigilError::InvalidValue {
        field: "cwd",
        reason: "working directory could not be resolved".to_string(),
    })?;
    if !cwd.is_dir() || !cwd.starts_with(workspace) {
        return Err(VigilError::Unauthorized(
            "process working directory must be inside the declared workspace".to_string(),
        ));
    }
    let identity = identify_executable(&executable)?;
    Ok(ValidatedRequest {
        executable,
        cwd,
        identity,
    })
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<()> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(VigilError::InvalidValue {
            field: "environment",
            reason: format!("at most {MAX_ENVIRONMENT_ENTRIES} environment entries are accepted"),
        });
    }
    for (key, value) in environment {
        if !ALLOWED_ENVIRONMENT_KEYS.contains(&key.as_str()) {
            return Err(VigilError::Unauthorized(
                "environment contains a key outside the broker allowlist".to_string(),
            ));
        }
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || value.as_bytes().contains(&0)
            || value.chars().any(char::is_control)
        {
            return Err(VigilError::InvalidValue {
                field: "environment",
                reason: "environment value is invalid or exceeds its bound".to_string(),
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    observed: u64,
    truncated: bool,
}

fn spawn_capture<R>(mut reader: R) -> JoinHandle<std::io::Result<CapturedOutput>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut observed = 0u64;
        let mut buffer = [0u8; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            observed = observed.saturating_add(count as u64);
            let remaining = MAX_CAPTURE_BYTES.saturating_sub(bytes.len());
            bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        }
        Ok(CapturedOutput {
            truncated: observed > bytes.len() as u64,
            bytes,
            observed,
        })
    })
}

fn join_capture(handle: JoinHandle<std::io::Result<CapturedOutput>>) -> Result<CapturedOutput> {
    handle
        .join()
        .map_err(|_| VigilError::Unavailable {
            component: "process_broker",
            reason: "output capture worker failed".to_string(),
        })?
        .map_err(Into::into)
}

fn wait_bounded(child: &mut std::process::Child, timeout_ms: u64) -> Result<(ExitStatus, bool)> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, false));
        }
        if started.elapsed() >= Duration::from_millis(timeout_ms) {
            // A natural exit can race the timeout. Waiting still reaps the direct child and the
            // conservative timeout marker remains true.
            let _ = child.kill();
            return Ok((child.wait()?, true));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn outcome_name(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
        DecisionOutcome::RequireApproval => "REQUIRE_APPROVAL",
        DecisionOutcome::Observe => "OBSERVE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewSession;

    fn fixture(profile: &str) -> (PathBuf, LocalStore, String, PathBuf) {
        let root = std::env::temp_dir().join(format!("vigil-process-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(workspace).expect("canonical workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: profile.to_string(),
                workspace: workspace.clone(),
                executable: "vigil-process-broker".to_string(),
                argv: vec!["vigil-process-broker".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .activate_semantic_session(&session.id)
            .expect("activate session");
        (root, store, session.id, workspace)
    }

    fn existing(paths: &[&str]) -> PathBuf {
        paths
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
            .expect("required system utility")
    }

    fn consumed(store: &LocalStore, session: &str) -> u64 {
        store
            .budget_snapshot(session)
            .expect("budget")
            .into_iter()
            .find(|counter| counter.dimension == BudgetDimension::ProcessExecutions)
            .expect("process counter")
            .consumed
    }

    #[test]
    fn a_structured_data_utility_executes_and_records_content_free_events() {
        let (root, store, session, _) = fixture("developer-standard");
        let mut request = ProcessRequest::new(existing(&["/bin/echo", "/usr/bin/echo"]));
        request.arguments = vec!["process-broker-secret-marker".to_string()];
        let result = ProcessBroker::new(&store)
            .execute(&session, &request)
            .expect("execute echo");
        assert!(String::from_utf8_lossy(&result.stdout).contains("process-broker-secret-marker"));
        assert_eq!(result.executable_class, ExecutableClass::DataUtility);
        assert_eq!(consumed(&store, &session), 1);
        let events = store.events_for_session(&session).expect("events");
        let encoded = serde_json::to_string(&events).expect("serialize events");
        assert!(!encoded.contains("process-broker-secret-marker"));
        assert!(events.iter().any(|event| event.action == "process.spawn"));
        assert!(events.iter().any(|event| event.action == "process.exit"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_shell_is_denied_before_spawn_and_budget_use() {
        let (root, store, session, _) = fixture("developer-standard");
        let shell = existing(&["/bin/sh", "/usr/bin/sh"]);
        let mut request = ProcessRequest::new(shell);
        request.arguments = vec!["-c".to_string(), "exit 0".to_string()];
        let error = ProcessBroker::new(&store)
            .execute(&session, &request)
            .expect_err("shell must be denied");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        assert_eq!(consumed(&store, &session), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ambient_or_loader_environment_is_denied_before_spawn() {
        let (root, store, session, _) = fixture("developer-standard");
        let mut request = ProcessRequest::new(existing(&["/bin/true", "/usr/bin/true"]));
        request.environment.insert(
            "DYLD_INSERT_LIBRARIES".to_string(),
            "/tmp/attack.dylib".to_string(),
        );
        assert!(ProcessBroker::new(&store)
            .execute(&session, &request)
            .is_err());
        assert_eq!(consumed(&store, &session), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_working_directory_outside_the_workspace_is_denied() {
        let (root, store, session, _) = fixture("developer-standard");
        let mut request = ProcessRequest::new(existing(&["/bin/true", "/usr/bin/true"]));
        request.cwd = Some(root.clone());
        assert!(ProcessBroker::new(&store)
            .execute(&session, &request)
            .is_err());
        assert_eq!(consumed(&store, &session), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn timeout_kills_the_child_but_commits_the_execution_budget() {
        let (root, store, session, _) = fixture("developer-standard");
        let mut request = ProcessRequest::new(existing(&["/bin/sleep", "/usr/bin/sleep"]));
        request.arguments = vec!["2".to_string()];
        request.timeout_ms = 20;
        let result = ProcessBroker::new(&store)
            .execute(&session, &request)
            .expect("execute sleep");
        assert!(result.timed_out);
        assert_eq!(consumed(&store, &session), 1);
        let counter = store
            .budget_snapshot(&session)
            .expect("budget")
            .into_iter()
            .find(|counter| counter.dimension == BudgetDimension::ProcessExecutions)
            .expect("process counter");
        assert_eq!(counter.reserved, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_nonzero_exit_still_consumes_the_execution_budget() {
        let (root, store, session, _) = fixture("developer-standard");
        let request = ProcessRequest::new(existing(&["/bin/false", "/usr/bin/false"]));
        let result = ProcessBroker::new(&store)
            .execute(&session, &request)
            .expect("execute false");
        assert_ne!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert_eq!(consumed(&store, &session), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn output_capture_is_bounded_while_the_pipe_is_fully_drained() {
        let source = vec![b'x'; MAX_CAPTURE_BYTES + 17];
        let capture =
            join_capture(spawn_capture(std::io::Cursor::new(source))).expect("capture output");
        assert_eq!(capture.bytes.len(), MAX_CAPTURE_BYTES);
        assert_eq!(capture.observed, (MAX_CAPTURE_BYTES + 17) as u64);
        assert!(capture.truncated);
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    /// §17: an executable path is not sufficient identity. The provenance graph carries the
    /// content hash, so a later question about *which* binary ran has an answer.
    #[cfg(unix)]
    #[test]
    fn a_validated_executable_is_identified_by_content_and_by_object() {
        let root = std::env::temp_dir().join(format!("vigil-exec-id-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");
        let program = root.join("tool");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("write");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let identity = identify_executable(&program).expect("identify");
        assert!(identity.object.is_some(), "the object was not identified");
        let sha256 = identity
            .sha256
            .clone()
            .expect("a small executable must be hashed");
        assert!(sha256.starts_with("sha256:"));

        // The same bytes at a different path are the same content but a different object.
        let copy = root.join("tool-copy");
        std::fs::copy(&program, &copy).expect("copy");
        let copy_identity = identify_executable(&copy).expect("identify");
        assert_eq!(copy_identity.sha256.as_deref(), Some(sha256.as_str()));
        assert_ne!(
            copy_identity.object, identity.object,
            "two files shared one object identity"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// Replacing the binary after it has been validated must not go unnoticed.
    #[cfg(unix)]
    #[test]
    fn replacing_the_binary_after_validation_is_detected() {
        let root = std::env::temp_dir().join(format!("vigil-exec-swap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");
        let program = root.join("tool");
        std::fs::write(&program, b"original").expect("write");

        let identity = identify_executable(&program).expect("identify");
        assert!(executable_unchanged(&program, &identity));

        // Swap it for a different object at the same path, as an attacker with write access
        // to the directory would.
        std::fs::remove_file(&program).expect("remove");
        std::fs::write(&program, b"substituted").expect("substitute");
        assert!(
            !executable_unchanged(&program, &identity),
            "a replaced binary was reported as unchanged"
        );

        // And a path that no longer exists is not "unchanged" either.
        std::fs::remove_file(&program).expect("remove");
        assert!(!executable_unchanged(&program, &identity));

        let _ = std::fs::remove_dir_all(root);
    }
}
