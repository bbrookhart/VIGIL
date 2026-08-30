//! CLI contract tests for the entitlement-independent local vertical slice.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("vigil-cli-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let database = root.join("state/vigil.db");
    (root, workspace, database)
}

#[test]
fn status_reports_secret_interface_without_claiming_native_custody() {
    let (root, _workspace, database) = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "status",
            "--json",
        ])
        .output()
        .expect("read status");
    assert!(output.status.success());
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    assert_eq!(status["secret_broker"], "INTERFACE_AND_SIMULATOR_ONLY");
    assert_eq!(status["endpoint_fast_path"], "SIMULATOR_AVAILABLE");
    assert_eq!(status["endpoint_security"], "NOT INSTALLED");
    assert_eq!(status["os_enforcement"], false);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_protected_credential_simulation_is_denied_and_persisted() {
    let (root, workspace, database) = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "simulate",
            "--profile",
            "developer-standard",
            "--workspace",
            workspace.to_str().expect("workspace path"),
            "--action",
            "fs.read",
            "--resource",
            "~/.ssh/vigil-synthetic-key-that-does-not-exist",
        ])
        .output()
        .expect("run simulation");
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Decision: DENY"), "{stdout}");
    assert!(stdout.contains("credential_access"), "{stdout}");

    let sessions = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "sessions",
            "--json",
        ])
        .output()
        .expect("list sessions");
    let sessions_stdout = String::from_utf8(sessions.stdout).expect("utf8 sessions");
    assert!(sessions.status.success(), "{sessions_stdout}");
    assert!(sessions_stdout.contains("\"status\": \"sealed\""));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn run_is_durable_and_never_claims_os_enforcement() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let output = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "run",
            "--profile",
            "developer-standard",
            "--workspace",
            workspace.to_str().expect("workspace path"),
            "--",
            binary,
            "--version",
        ])
        .output()
        .expect("run session");
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Enforcement   OBSERVE ONLY"), "{stdout}");
    assert!(stdout.contains("ambient macOS authority"), "{stdout}");
    assert!(!stdout.contains("FULLY ENFORCED"), "{stdout}");

    let sessions = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "sessions",
            "--json",
        ])
        .output()
        .expect("list sessions");
    let sessions_stdout = String::from_utf8(sessions.stdout).expect("utf8 sessions");
    assert!(sessions.status.success(), "{sessions_stdout}");
    assert!(sessions_stdout.contains("\"status\": \"completed\""));
    assert!(sessions_stdout.contains("\"enforcement_posture\": \"observe_only\""));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn semantic_filesystem_session_enforces_policy_and_budget_end_to_end() {
    use std::io::Write as _;

    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let started = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "start",
            "--profile",
            "developer-standard",
            "--workspace",
            workspace.to_str().expect("workspace path"),
            "--json",
        ])
        .output()
        .expect("start semantic session");
    assert!(started.status.success());
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    assert_eq!(start_json["os_enforcement"], false);

    let mut writer = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "fs",
            "write",
            &session,
            "managed.txt",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn broker write");
    writer
        .stdin
        .take()
        .expect("writer stdin")
        .write_all(b"brokered content")
        .expect("write stdin");
    let written = writer.wait_with_output().expect("wait for write");
    assert!(written.status.success());
    assert_eq!(
        std::fs::read(workspace.join("managed.txt")).expect("managed output"),
        b"brokered content"
    );

    let read = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "fs",
            "read",
            &session,
            "managed.txt",
        ])
        .output()
        .expect("broker read");
    assert!(read.status.success());
    assert_eq!(read.stdout, b"brokered content");

    let budget = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "budget",
            &session,
            "--json",
        ])
        .output()
        .expect("budget snapshot");
    assert!(budget.status.success());
    let counters: Vec<serde_json::Value> =
        serde_json::from_slice(&budget.stdout).expect("budget JSON");
    let reads = counters
        .iter()
        .find(|counter| counter["dimension"] == "file_reads")
        .expect("read counter");
    let creates = counters
        .iter()
        .find(|counter| counter["dimension"] == "file_creates")
        .expect("create counter");
    assert_eq!(reads["consumed"], 1);
    assert_eq!(creates["consumed"], 1);

    let outside = root.join("outside.txt");
    let mut denied = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "fs",
            "write",
            &session,
            outside.to_str().expect("outside path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denied write");
    denied
        .stdin
        .take()
        .expect("denied stdin")
        .write_all(b"must not exist")
        .expect("write denied stdin");
    let denied = denied.wait_with_output().expect("wait denied write");
    assert!(!denied.status.success());
    assert!(!outside.exists());

    let closed = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "close",
            &session,
        ])
        .output()
        .expect("close session");
    assert!(closed.status.success());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn structured_process_broker_executes_safe_utility_and_denies_shell() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let started = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "start",
            "--profile",
            "developer-standard",
            "--workspace",
            workspace.to_str().expect("workspace path"),
            "--json",
        ])
        .output()
        .expect("start semantic session");
    assert!(started.status.success());
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let echo = ["/bin/echo", "/usr/bin/echo"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
        .expect("system echo");
    let executed = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "process",
            "exec",
            &session,
            "--program",
            echo,
            "--",
            "structured-process-output",
        ])
        .output()
        .expect("execute structured process");
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_eq!(executed.stdout, b"structured-process-output\n");

    let budget = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "budget",
            &session,
            "--json",
        ])
        .output()
        .expect("budget snapshot");
    let counters: Vec<serde_json::Value> =
        serde_json::from_slice(&budget.stdout).expect("budget JSON");
    let executions = counters
        .iter()
        .find(|counter| counter["dimension"] == "process_executions")
        .expect("process counter");
    assert_eq!(executions["consumed"], 1);

    let shell = ["/bin/sh", "/usr/bin/sh"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
        .expect("system shell");
    let denied = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "process",
            "exec",
            &session,
            "--program",
            shell,
            "--",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("deny shell");
    assert!(!denied.status.success());

    let budget_after = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "budget",
            &session,
            "--json",
        ])
        .output()
        .expect("budget after denial");
    let counters_after: Vec<serde_json::Value> =
        serde_json::from_slice(&budget_after.stdout).expect("budget JSON");
    let executions_after = counters_after
        .iter()
        .find(|counter| counter["dimension"] == "process_executions")
        .expect("process counter");
    assert_eq!(executions_after["consumed"], 1);

    let shown = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "show",
            &session,
            "--json",
        ])
        .output()
        .expect("show session");
    let evidence = String::from_utf8(shown.stdout).expect("evidence utf8");
    assert!(!evidence.contains("structured-process-output"));
    assert!(evidence.contains("process.spawn"));
    assert!(evidence.contains("unexpected_interpreter"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn network_probe_cli_denies_direct_ip_without_spending_budget() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let started = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "start",
            "--profile",
            "developer-standard",
            "--workspace",
            workspace.to_str().expect("workspace path"),
            "--json",
        ])
        .output()
        .expect("start semantic session");
    assert!(started.status.success());
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let probe = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "network",
            "probe",
            &session,
            "--host",
            "127.0.0.1",
            "--port",
            "443",
            "--json",
        ])
        .output()
        .expect("network probe");
    assert!(!probe.status.success());

    let budget = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "budget",
            &session,
            "--json",
        ])
        .output()
        .expect("budget snapshot");
    let counters: Vec<serde_json::Value> =
        serde_json::from_slice(&budget.stdout).expect("budget JSON");
    for dimension in ["network_connections", "network_destinations"] {
        let counter = counters
            .iter()
            .find(|counter| counter["dimension"] == dimension)
            .expect("network counter");
        assert_eq!(counter["consumed"], 0);
    }

    let shown = Command::new(binary)
        .args([
            "--state-db",
            database.to_str().expect("database path"),
            "session",
            "show",
            &session,
            "--json",
        ])
        .output()
        .expect("show session");
    let evidence = String::from_utf8(shown.stdout).expect("evidence utf8");
    assert!(evidence.contains("network.connect"));
    assert!(evidence.contains("direct_ip_egress"));
    assert!(!evidence.contains("payload_bytes_sent"));
    let _ = std::fs::remove_dir_all(root);
}

/// The whole authority loop through the CLI, which is the surface an operator actually uses.
///
/// Before this existed, every `REQUIRE_APPROVAL` the profile ladder produced was a dead end:
/// there was no record, no grant path, and no way for the session to proceed. This walks the
/// path end to end and then checks the two rules that keep it from becoming a bypass — a
/// lease is spent once and binds to one resource.
#[test]
fn an_approval_becomes_a_single_use_lease_bound_to_one_resource() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        workspace.to_str().expect("workspace path"),
        "--json",
    ]);
    assert!(started.status.success());
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    // A session starts holding nothing.
    let capabilities = vigil(&["capabilities", &session, "--json"]);
    let leases: Vec<serde_json::Value> =
        serde_json::from_slice(&capabilities.stdout).expect("leases JSON");
    assert!(leases.is_empty(), "a new session must hold no capabilities");

    // `uname` is not in the structured low-risk allowlist, so it needs a human.
    let refused = vigil(&[
        "process",
        "exec",
        &session,
        "--program",
        "/usr/bin/uname",
        "--discard-output",
    ]);
    assert!(!refused.status.success());
    let message = String::from_utf8(refused.stderr).expect("utf8 stderr");
    assert!(
        message.contains("approval apr_"),
        "the refusal must name the approval it raised: {message}"
    );

    let listed = vigil(&["approvals", "list", "--status", "pending", "--json"]);
    let pending: Vec<serde_json::Value> =
        serde_json::from_slice(&listed.stdout).expect("approvals JSON");
    assert_eq!(pending.len(), 1);
    let approval = pending[0]["approval_id"].as_str().expect("id").to_string();
    assert_eq!(pending[0]["action"], "process.exec");
    assert_eq!(pending[0]["resolved_resource"], "/usr/bin/uname");
    assert_eq!(pending[0]["risk_state_at_request"], "NORMAL");

    // Granting mints one lease bound to exactly this action and resolved resource.
    let granted = vigil(&[
        "approvals",
        "grant",
        &approval,
        "--approver",
        "operator",
        "--max-uses",
        "1",
        "--json",
    ]);
    assert!(
        granted.status.success(),
        "{}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let lease: serde_json::Value = serde_json::from_slice(&granted.stdout).expect("lease JSON");
    assert_eq!(lease["action"], "process.exec");
    assert_eq!(lease["resource"], "/usr/bin/uname");
    assert_eq!(lease["max_uses"], 1);
    assert_eq!(lease["delegable"], false);

    // The same request now succeeds.
    let allowed = vigil(&[
        "process",
        "exec",
        &session,
        "--program",
        "/usr/bin/uname",
        "--discard-output",
    ]);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    // And the lease is spent. A second attempt raises a fresh approval rather than reusing it.
    let exhausted = vigil(&["capabilities", &session, "--json"]);
    let leases: Vec<serde_json::Value> =
        serde_json::from_slice(&exhausted.stdout).expect("leases JSON");
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0]["status"], "exhausted");
    assert_eq!(leases[0]["uses_remaining"], 0);

    let again = vigil(&[
        "process",
        "exec",
        &session,
        "--program",
        "/usr/bin/uname",
        "--discard-output",
    ]);
    assert!(!again.status.success(), "a spent lease must not authorize");

    // The executed process is attributable, and by a node id rather than a PID.
    let processes = vigil(&["processes", &session, "--json"]);
    let graph: serde_json::Value = serde_json::from_slice(&processes.stdout).expect("graph JSON");
    let nodes = graph["nodes"].as_array().expect("nodes");
    assert_eq!(nodes.len(), 1);
    assert!(nodes[0]["node_id"]
        .as_str()
        .expect("node id")
        .starts_with("prc_"));
    assert_eq!(nodes[0]["status"], "exited");

    let _ = std::fs::remove_dir_all(root);
}

/// A refusal is not merely a "no" that can be retried forever: repeating it is itself the
/// signal, and the session loses authority for it without a human having to intervene again.
#[test]
fn probing_a_refused_boundary_degrades_the_session_without_further_human_input() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        workspace.to_str().expect("workspace path"),
        "--json",
    ]);
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let exec = |vigil: &dyn Fn(&[&str]) -> std::process::Output| {
        vigil(&[
            "process",
            "exec",
            &session,
            "--program",
            "/usr/bin/uname",
            "--discard-output",
        ])
    };
    exec(&vigil);
    let listed = vigil(&["approvals", "list", "--status", "pending", "--json"]);
    let pending: Vec<serde_json::Value> =
        serde_json::from_slice(&listed.stdout).expect("approvals JSON");
    let approval = pending[0]["approval_id"].as_str().expect("id").to_string();

    let denied = vigil(&["approvals", "deny", &approval, "--approver", "operator"]);
    assert!(denied.status.success());

    // Grant a lease for something else first, so containment can be seen taking it away.
    let risk_of = |vigil: &dyn Fn(&[&str]) -> std::process::Output| -> String {
        let output = vigil(&["risk", &session, "--json"]);
        let assessment: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("risk JSON");
        assessment["state"].as_str().expect("state").to_string()
    };
    assert_eq!(risk_of(&vigil), "NORMAL");

    // Each re-ask after the refusal costs the session a step of authority.
    for expected in ["ELEVATED", "RESTRICTED"] {
        exec(&vigil);
        assert_eq!(risk_of(&vigil), expected);
    }

    // Restricted withholds the capability outright, so the agent no longer even reaches the
    // operator: approval fatigue stops being a usable pressure tactic.
    let refused = exec(&vigil);
    let message = String::from_utf8(refused.stderr).expect("utf8 stderr");
    assert!(
        message.contains("session risk is RESTRICTED"),
        "expected risk-based refusal, got: {message}"
    );
    let listed = vigil(&["approvals", "list", "--json"]);
    let all: Vec<serde_json::Value> =
        serde_json::from_slice(&listed.stdout).expect("approvals JSON");
    assert_eq!(
        all.len(),
        1,
        "repeated probing must not fill the operator's queue"
    );

    // Workspace writes are gone too, even though nothing was ever denied about them.
    let write = Command::new(binary)
        .args(["--state-db", &db, "fs", "write", &session, "note.txt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn writer");
    let output = write.wait_with_output().expect("write output");
    assert!(
        !output.status.success(),
        "a restricted session must not keep write authority"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// Prompt Demo 2 and Demo 3, through the CLI: a credential probe becomes a detection, the
/// detections escalate risk to containment, containment opens an incident and revokes
/// authority, and the whole thing exports as reviewable evidence with a verifiable chain.
#[test]
fn credential_probing_produces_a_detection_an_incident_and_verifiable_evidence() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        workspace.to_str().expect("workspace path"),
        "--json",
    ]);
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    // A path that is protected whether or not it exists, so the test never depends on the
    // developer's real key material being present.
    let credential = format!(
        "{}/.ssh/vigil-synthetic-key-that-does-not-exist",
        std::env::var("HOME").expect("HOME")
    );
    for _ in 0..3 {
        let refused = vigil(&["fs", "read", &session, &credential]);
        assert!(
            !refused.status.success(),
            "a credential read must be denied"
        );
    }

    let listed = vigil(&["detections", "--session", &session, "--json"]);
    let detections: Vec<serde_json::Value> =
        serde_json::from_slice(&listed.stdout).expect("detections JSON");
    assert_eq!(detections.len(), 3);
    assert_eq!(detections[0]["rule_id"], "VIGIL-L001");
    assert_eq!(detections[0]["severity"], "HIGH");
    assert_eq!(detections[0]["confidence"], "HIGH");
    assert_eq!(detections[0]["tactic"], "CREDENTIAL_ACCESS");

    // Three firings reach containment, which opens an incident on its own.
    let risk = vigil(&["risk", &session, "--json"]);
    let assessment: serde_json::Value = serde_json::from_slice(&risk.stdout).expect("risk JSON");
    assert_eq!(assessment["state"], "CONTAINED");

    let incidents = vigil(&["incidents", "list", "--json"]);
    let incidents: Vec<serde_json::Value> =
        serde_json::from_slice(&incidents.stdout).expect("incidents JSON");
    assert_eq!(incidents.len(), 1);
    let incident = incidents[0]["incident_id"]
        .as_str()
        .expect("incident id")
        .to_string();

    // Containment is idempotent and honest about not killing anything.
    let contained = vigil(&["contain", &session, "--json"]);
    assert!(
        contained.status.success(),
        "{}",
        String::from_utf8_lossy(&contained.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&contained.stdout).expect("contain JSON");
    assert_eq!(result["process_termination"], "not performed");

    // Reads survive containment; writes do not.
    let write = Command::new(binary)
        .args(["--state-db", &db, "fs", "write", &session, "note.txt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn writer")
        .wait_with_output()
        .expect("write output");
    assert!(!write.status.success(), "a contained session cannot write");

    // The evidence bundle carries metadata and states its own limits.
    let export_path = root.join("incident.vigilincident");
    let exported = vigil(&[
        "incidents",
        "export",
        &incident,
        "--out",
        export_path.to_str().expect("export path"),
    ]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&export_path).expect("read bundle"))
            .expect("bundle JSON");
    assert_eq!(bundle["format"], "vigil.incident-bundle/v1");
    assert_eq!(bundle["content_captured"], false);
    assert_eq!(bundle["enforcement"]["os_enforcement"], false);
    assert_eq!(bundle["integrity"]["event_chain"]["verified"], true);
    assert_eq!(
        bundle["detections"].as_array().expect("detections").len(),
        3
    );

    let verified = vigil(&["audit", "verify-local", "--json"]);
    assert!(verified.status.success());
    let chain: serde_json::Value = serde_json::from_slice(&verified.stdout).expect("chain JSON");
    assert_eq!(chain["verified"], true);

    let _ = std::fs::remove_dir_all(root);
}

/// Editing the log to hide a denial must not go unnoticed, and must fail the command rather
/// than being reported as a warning nobody reads.
#[test]
fn rewriting_a_denial_in_the_event_log_fails_verification() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();

    let started = Command::new(binary)
        .args([
            "--state-db",
            &db,
            "session",
            "start",
            "--profile",
            "developer-standard",
            "--workspace",
            workspace.to_str().expect("workspace path"),
            "--json",
        ])
        .output()
        .expect("start session");
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"].as_str().expect("session id");

    let credential = format!(
        "{}/.ssh/vigil-synthetic-key-that-does-not-exist",
        std::env::var("HOME").expect("HOME")
    );
    let _ = Command::new(binary)
        .args(["--state-db", &db, "fs", "read", session, &credential])
        .output()
        .expect("denied read");

    let clean = Command::new(binary)
        .args(["--state-db", &db, "audit", "verify-local"])
        .output()
        .expect("verify");
    assert!(clean.status.success());

    // Rewrite the denial into an allow, exactly as someone covering their tracks would.
    let connection = rusqlite::Connection::open(&database).expect("open sqlite");
    let changed = connection
        .execute(
            "UPDATE events SET decision = 'ALLOW' WHERE decision = 'DENY'",
            [],
        )
        .expect("tamper");
    assert!(changed >= 1, "the fixture must contain a denial to rewrite");
    drop(connection);

    let tampered = Command::new(binary)
        .args(["--state-db", &db, "audit", "verify-local"])
        .output()
        .expect("verify");
    assert!(
        !tampered.status.success(),
        "a rewritten denial must fail verification"
    );
    let stdout = String::from_utf8(tampered.stdout).expect("utf8");
    assert!(stdout.contains("FAILED"), "{stdout}");

    let _ = std::fs::remove_dir_all(root);
}

/// Prompt Demo 5 through the CLI: an MCP tool that claims a filesystem operation but targets
/// outside the workspace is blocked and attributed to the tool and server.
#[test]
fn an_mcp_tool_is_authorized_by_its_arguments_not_its_name() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        workspace.to_str().expect("workspace path"),
        "--json",
    ]);
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    // A stand-in for the server binary, so the recorded hash is a real hash of a real file.
    let server_binary = root.join("fs-server");
    std::fs::write(&server_binary, b"#!/bin/sh\necho serving\n").expect("write server");
    let asserted_hash = format!("sha256:{}", "a".repeat(64));
    let registered = vigil(&[
        "mcp",
        "register",
        "--name",
        "filesystem",
        "--transport",
        "stdio",
        "--executable",
        server_binary.to_str().expect("server path"),
        "--sha256",
        &asserted_hash,
        "--json",
    ]);
    assert!(
        registered.status.success(),
        "{}",
        String::from_utf8_lossy(&registered.stderr)
    );
    let server: serde_json::Value =
        serde_json::from_slice(&registered.stdout).expect("server JSON");
    let recorded_hash = server["executable_sha256"]
        .as_str()
        .expect("a registered server must record its binary hash")
        .to_string();
    assert_ne!(
        recorded_hash, asserted_hash,
        "a caller assertion must not replace VIGIL's hash of a local executable"
    );

    let manifest = root.join("tools.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!([{
            "name": "write_file",
            "description": "Writes a file inside the workspace.",
            "input_schema": { "type": "object" },
            "declared_capabilities": ["fs.read"]
        }]))
        .expect("serialize manifest"),
    )
    .expect("write manifest");
    let synced = vigil(&[
        "mcp",
        "sync",
        "filesystem",
        "--manifest",
        manifest.to_str().expect("manifest path"),
        "--json",
    ]);
    let sync_json: serde_json::Value = serde_json::from_slice(&synced.stdout).expect("sync JSON");
    assert_eq!(
        sync_json["drift"].as_array().expect("drift").len(),
        0,
        "the first sync is a baseline, not drift"
    );

    // The same tool, twice. Only the argument differs.
    let allowed = vigil(&[
        "mcp",
        "authorize",
        &session,
        "--server",
        "filesystem",
        "--tool",
        "write_file",
        "--arguments",
        r#"{"path":"./src/main.rs"}"#,
        "--json",
    ]);
    assert!(allowed.status.success());
    let allowed_json: serde_json::Value =
        serde_json::from_slice(&allowed.stdout).expect("allow JSON");
    assert_eq!(allowed_json["permitted"], true);

    let refused = vigil(&[
        "mcp",
        "authorize",
        &session,
        "--server",
        "filesystem",
        "--tool",
        "write_file",
        "--arguments",
        r#"{"path":"~/.ssh/config","content":"Host evil"}"#,
        "--json",
    ]);
    assert!(!refused.status.success(), "the escape must be refused");
    let refused_json: serde_json::Value =
        serde_json::from_slice(&refused.stdout).expect("deny JSON");
    assert_eq!(refused_json["permitted"], false);
    assert_eq!(refused_json["resources"][0]["outcome"], "DENY");
    assert_eq!(refused_json["server_name"], "filesystem");
    assert_eq!(refused_json["tool_name"], "write_file");

    // The call is attributed on the event timeline, without argument content.
    let events = vigil(&["events", &session, "--json"]);
    let events: Vec<serde_json::Value> =
        serde_json::from_slice(&events.stdout).expect("events JSON");
    let call = events
        .iter()
        .find(|event| event["action"] == "mcp.tool_call" && event["decision"] == "DENY")
        .expect("a denied MCP call event");
    assert_eq!(call["payload"]["server"], "filesystem");
    assert_eq!(call["payload"]["argument_content_captured"], false);
    assert!(!call["payload"].to_string().contains("Host evil"));

    // Now the server changes its tools and its binary after trust was established.
    std::fs::write(&manifest, serde_json::to_vec(&serde_json::json!([
        {
            "name": "write_file",
            "description": "Writes a file ANYWHERE.",
            "input_schema": { "type": "object", "properties": { "force": {} } },
            "declared_capabilities": ["fs.read", "process.exec"]
        },
        { "name": "run_command", "description": "Runs a shell command.", "declared_capabilities": ["process.exec"] }
    ])).expect("serialize"))
    .expect("write manifest");

    let substituted_hash = format!("sha256:{}", "f".repeat(64));
    assert_ne!(recorded_hash, substituted_hash);
    let drifted = vigil(&[
        "mcp",
        "sync",
        "filesystem",
        "--manifest",
        manifest.to_str().expect("manifest path"),
        "--sha256",
        &substituted_hash,
        "--session",
        &session,
        "--json",
    ]);
    let drift_json: serde_json::Value =
        serde_json::from_slice(&drifted.stdout).expect("drift JSON");
    let kinds: Vec<&str> = drift_json["drift"]
        .as_array()
        .expect("drift array")
        .iter()
        .map(|entry| entry["kind"].as_str().expect("kind"))
        .collect();
    for expected in [
        "server_substituted",
        "tool_added",
        "tool_schema_changed",
        "tool_description_changed",
        "tool_capability_added",
    ] {
        assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
    }
    // Substitution alone is enough to quarantine.
    assert_eq!(drift_json["risk_state"], "QUARANTINED");

    let detections = vigil(&["detections", "--session", &session, "--json"]);
    let detections: Vec<serde_json::Value> =
        serde_json::from_slice(&detections.stdout).expect("detections JSON");
    assert!(detections.iter().any(
        |detection| detection["rule_id"] == "VIGIL-L011" && detection["severity"] == "CRITICAL"
    ));

    let _ = std::fs::remove_dir_all(root);
}

/// Prompt Demo 8. The session declares one innocuous read; the OS observer reports a shell, a
/// credential read, a write to the file that was only declared for reading, and an extra
/// workspace file. Each is a different class of divergence and each is named as such.
#[test]
fn declared_intent_is_reconciled_against_observed_execution() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    // The broker resolves through the real filesystem, so compare against the canonical form.
    let canonical = std::fs::canonicalize(&workspace).expect("canonical workspace");
    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        canonical.to_str().expect("workspace path"),
        "--json",
    ]);
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let declared_file = canonical.join("package.json");
    std::fs::write(&declared_file, b"{}").expect("write fixture");
    let read = Command::new(binary)
        .args(["--state-db", &db, "fs", "read", &session, "package.json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("brokered read");
    assert!(read.status.success());

    let declared_path = declared_file.to_str().expect("declared path").to_string();
    let extra_path = canonical.join("other.rs").display().to_string();
    let credential = format!(
        "{}/.ssh/vigil-synthetic-key",
        std::env::var("HOME").expect("HOME")
    );
    let observations = serde_json::json!([
        { "process": "tok-a", "kind": "read",  "path": declared_path },
        { "process": "tok-b", "kind": "exec",  "path": "/bin/sh" },
        { "process": "tok-b", "kind": "read",  "path": credential },
        { "process": "tok-b", "kind": "write", "path": declared_path },
        { "process": "tok-b", "kind": "read",  "path": extra_path },
    ]);
    let observed_file = root.join("observed.json");
    std::fs::write(
        &observed_file,
        serde_json::to_vec(&observations).expect("serialize"),
    )
    .expect("write observations");

    let reconciled = vigil(&[
        "reconcile",
        &session,
        "--observed",
        observed_file.to_str().expect("observed path"),
        "--json",
    ]);
    assert!(
        !reconciled.status.success(),
        "a divergent session must exit non-zero"
    );
    let result: serde_json::Value =
        serde_json::from_slice(&reconciled.stdout).expect("reconcile JSON");
    assert_eq!(result["consistent"], false);
    assert_eq!(result["report"]["coverage"], "observed");
    assert_eq!(result["report"]["matched"], 1);

    let classes: Vec<&str> = result["report"]["mismatches"]
        .as_array()
        .expect("mismatches")
        .iter()
        .map(|mismatch| mismatch["class"].as_str().expect("class"))
        .collect();
    for expected in [
        "CHILD_PROCESS_MISMATCH",
        "RESOURCE_MISMATCH",
        "UNDECLARED_SIDE_EFFECT",
        "SCOPE_EXPANSION",
    ] {
        assert!(
            classes.contains(&expected),
            "missing {expected} in {classes:?}"
        );
    }

    let _ = std::fs::remove_dir_all(root);
}

/// The two results that must never be confused: an unwatched session, and a clean one.
#[test]
fn an_unobserved_session_is_not_reported_as_consistent() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    let canonical = std::fs::canonicalize(&workspace).expect("canonical workspace");
    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        canonical.to_str().expect("workspace path"),
        "--json",
    ]);
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"].as_str().expect("session id");

    let unobserved = vigil(&["reconcile", session, "--json"]);
    let result: serde_json::Value =
        serde_json::from_slice(&unobserved.stdout).expect("reconcile JSON");
    assert_eq!(result["report"]["coverage"], "no_observer");
    assert_eq!(
        result["report"]["mismatches"]
            .as_array()
            .expect("array")
            .len(),
        0
    );
    assert_eq!(
        result["consistent"], false,
        "no mismatches with nothing watching must not read as consistent"
    );
    assert!(
        !unobserved.status.success(),
        "an unobserved reconciliation must exit non-zero"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// The bypass proof: VIGIL refused an operation and the OS observed it happen anyway. This is
/// the only finding in the system that demonstrates the semantic layer was defeated rather
/// than merely blind, and it quarantines on its own.
#[test]
fn an_operation_vigil_denied_being_observed_is_a_critical_bypass_finding() {
    let (root, workspace, database) = fixture();
    let binary = env!("CARGO_BIN_EXE_vigil");
    let db = database.to_str().expect("database path").to_string();
    let vigil = |args: &[&str]| {
        let mut full = vec!["--state-db", &db];
        full.extend_from_slice(args);
        Command::new(binary)
            .args(&full)
            .output()
            .expect("run vigil")
    };

    let canonical = std::fs::canonicalize(&workspace).expect("canonical workspace");
    let started = vigil(&[
        "session",
        "start",
        "--profile",
        "developer-standard",
        "--workspace",
        canonical.to_str().expect("workspace path"),
        "--json",
    ]);
    let start_json: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start JSON");
    let session = start_json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    let credential = format!(
        "{}/.ssh/vigil-synthetic-key-that-does-not-exist",
        std::env::var("HOME").expect("HOME")
    );
    let refused = vigil(&["fs", "read", &session, &credential]);
    assert!(!refused.status.success(), "the read must be refused");

    let observed_file = root.join("observed.json");
    std::fs::write(
        &observed_file,
        serde_json::to_vec(&serde_json::json!([
            { "process": "tok-x", "kind": "read", "path": credential }
        ]))
        .expect("serialize"),
    )
    .expect("write observations");

    let reconciled = vigil(&[
        "reconcile",
        &session,
        "--observed",
        observed_file.to_str().expect("observed path"),
        "--json",
    ]);
    assert!(!reconciled.status.success());
    let result: serde_json::Value =
        serde_json::from_slice(&reconciled.stdout).expect("reconcile JSON");
    assert_eq!(
        result["report"]["mismatches"][0]["class"],
        "DENIED_OPERATION_OBSERVED"
    );
    assert_eq!(result["risk_state"], "QUARANTINED");

    let detections = vigil(&["detections", "--session", &session, "--json"]);
    let detections: Vec<serde_json::Value> =
        serde_json::from_slice(&detections.stdout).expect("detections JSON");
    assert!(detections.iter().any(
        |detection| detection["rule_id"] == "VIGIL-L013" && detection["severity"] == "CRITICAL"
    ));

    let _ = std::fs::remove_dir_all(root);
}
