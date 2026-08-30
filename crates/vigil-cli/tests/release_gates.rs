//! The conditions under which a release candidate fails.
//!
//! §89 lists them as prose. Prose does not fail a build, so each is a test here, named for the
//! condition rather than for the control — a failure reads as "policy validation can fail
//! open", which is the sentence someone has to answer before shipping.
//!
//! Several gates are already enforced by tests elsewhere; those are asserted again from the
//! outside, at the CLI boundary, because that is the surface a release actually ships. Two
//! gates concern subsystems this build does not have, and they say so rather than passing
//! vacuously.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn fixture(label: &str) -> (PathBuf, PathBuf, String) {
    let root = std::env::temp_dir().join(format!("vigil-gate-{label}-{}", uuid::Uuid::new_v4()));
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = std::fs::canonicalize(&workspace).expect("canonical");
    let database = root
        .join("state/vigil.db")
        .to_str()
        .expect("database path")
        .to_string();
    (root, workspace, database)
}

fn vigil(database: &str, args: &[&str]) -> Output {
    let mut full = vec!["--state-db", database];
    full.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args(&full)
        .output()
        .expect("run vigil")
}

fn json(database: &str, args: &[&str]) -> serde_json::Value {
    serde_json::from_slice(&vigil(database, args).stdout).expect("JSON output")
}

fn session(database: &str, workspace: &Path, profile: &str) -> String {
    json(
        database,
        &[
            "session",
            "start",
            "--profile",
            profile,
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--json",
        ],
    )["session_id"]
        .as_str()
        .expect("session id")
        .to_string()
}

/// §89 — "policy validation can fail open".
#[test]
fn gate_policy_validation_cannot_fail_open() {
    // The shipped bundles validate, and the validator refuses the shapes that would disable
    // enforcement. A universal allow is the canonical one.
    //
    // Resolved from the manifest directory rather than the working directory: a test's CWD is
    // its crate, not the repository root.
    let policies = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies")
        .canonicalize()
        .expect("the shipped policies directory must exist");
    let output = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args(["policy", "validate", policies.to_str().expect("policies")])
        .output()
        .expect("validate");
    assert!(
        output.status.success(),
        "the shipped policy bundles do not validate: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let (root, _workspace, _database) = fixture("policy");
    let bundle = root.join("universal-allow.yaml");
    std::fs::write(
        &bundle,
        "version: gate\ndefault_effect: deny\nrules:\n  - id: everything\n    effect: allow\n    \
         when:\n      match_all: true\n",
    )
    .expect("write bundle");
    let refused = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args(["policy", "validate", root.to_str().expect("dir")])
        .output()
        .expect("validate");
    assert!(
        !refused.status.success(),
        "a universal-allow rule was accepted, which disables enforcement"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "entitlement-dependent functionality is falsely reported as active".
#[test]
fn gate_entitlement_dependent_functionality_is_never_reported_as_active() {
    let (root, _workspace, database) = fixture("posture");
    let status = json(&database, &["status", "--json"]);

    assert_eq!(status["os_enforcement"], false);
    assert_eq!(status["endpoint_security"], "NOT INSTALLED");
    assert_eq!(status["network_extension"], "NOT INSTALLED");
    assert_eq!(status["posture"], "OBSERVE ONLY");

    // And the words that would overstate it appear nowhere in the posture report.
    let rendered = String::from_utf8(vigil(&database, &["status"]).stdout).expect("utf8");
    let lowered = rendered.to_lowercase();
    for overstatement in ["fully enforced", "protected", "contained"] {
        assert!(
            !lowered.contains(overstatement),
            "the posture report says `{overstatement}` while enforcement is not installed:\n{rendered}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "an agent can directly alter policy" and "alter audit data without detection".
#[test]
fn gate_an_agent_cannot_reach_the_control_plane() {
    let (root, workspace, database) = fixture("control-plane");
    let session = session(&database, &workspace, "developer-standard");
    let home = std::env::var("HOME").expect("HOME");

    for target in [
        format!("{home}/Library/Application Support/VIGIL/vigil.db"),
        format!("{home}/Library/Application Support/VIGIL/policy.yaml"),
    ] {
        let refused = vigil(&database, &["fs", "read", &session, &target]);
        assert!(
            !refused.status.success(),
            "an agent read VIGIL's own state at {target}"
        );
    }
    let detections: Vec<serde_json::Value> = serde_json::from_value(json(
        &database,
        &["detections", "--session", &session, "--json"],
    ))
    .expect("detections");
    assert!(
        detections
            .iter()
            .any(|detection| detection["rule_id"] == "VIGIL-L003"),
        "reaching the control plane produced no detection"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "an agent can alter audit data without detection".
#[test]
fn gate_altering_audit_data_is_detected() {
    let (root, workspace, database) = fixture("audit");
    let session = session(&database, &workspace, "developer-standard");
    let home = std::env::var("HOME").expect("HOME");
    vigil(
        &database,
        &[
            "fs",
            "read",
            &session,
            &format!("{home}/.ssh/vigil-gate-synthetic"),
        ],
    );
    assert!(vigil(&database, &["audit", "verify-local"])
        .status
        .success());

    // Both shapes of tampering: editing a record, and removing the newest one.
    for statement in [
        "UPDATE events SET decision = 'ALLOW' WHERE decision = 'DENY'",
        "DELETE FROM events WHERE sequence = (SELECT MAX(sequence) FROM events)",
    ] {
        let copy = root.join(format!("copy-{}.db", uuid::Uuid::new_v4()));
        std::fs::copy(PathBuf::from(&database), &copy).expect("copy database");
        let connection = rusqlite::Connection::open(&copy).expect("open");
        connection.execute(statement, []).expect("tamper");
        drop(connection);

        let verified = Command::new(env!("CARGO_BIN_EXE_vigil"))
            .args([
                "--state-db",
                copy.to_str().expect("copy"),
                "audit",
                "verify-local",
            ])
            .output()
            .expect("verify");
        assert!(
            !verified.status.success(),
            "tampering went undetected: {statement}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "a budget race permits overrun".
#[test]
fn gate_a_budget_race_cannot_overrun() {
    // Covered exhaustively by the threaded reservation tests in `vigil-local`. Asserted here
    // as a boundary check that a zero-limit dimension refuses deterministically.
    let (root, workspace, database) = fixture("budget");
    let session = session(&database, &workspace, "untrusted-agent");
    let counters: Vec<serde_json::Value> =
        serde_json::from_value(json(&database, &["session", "budget", &session, "--json"]))
            .expect("budget");
    for dimension in ["privileged_actions", "persistence_changes"] {
        let counter = counters
            .iter()
            .find(|counter| counter["dimension"] == dimension)
            .unwrap_or_else(|| panic!("no counter for {dimension}"));
        assert_eq!(
            counter["limit"], 0,
            "{dimension} must be zero for an untrusted agent"
        );
        assert_eq!(counter["remaining"], 0);
    }
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "path traversal escapes the workspace".
#[test]
fn gate_path_traversal_cannot_escape_the_workspace() {
    let (root, workspace, database) = fixture("traversal");
    std::fs::write(root.join("outside.txt"), b"not for the agent").expect("seed");
    let session = session(&database, &workspace, "developer-standard");

    for escape in [
        "../outside.txt",
        "./../outside.txt",
        "sub/../../outside.txt",
    ] {
        let refused = vigil(&database, &["fs", "read", &session, escape]);
        assert!(
            !refused.status.success(),
            "`{escape}` escaped the workspace"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "sensitive values appear in logs".
#[test]
fn gate_sensitive_values_never_reach_evidence() {
    let (root, workspace, database) = fixture("redaction");
    let session = session(&database, &workspace, "developer-standard");

    // A file whose *content* is a secret, written through the broker.
    let secret = "ghp_VIGILGATE0000000000000000000000000000";
    let mut child = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--state-db",
            &database,
            "fs",
            "write",
            &session,
            "config.env",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn writer");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(format!("TOKEN={secret}\n").as_bytes())
            .expect("write");
    }
    assert!(child.wait().expect("wait").success());

    let events =
        String::from_utf8(vigil(&database, &["events", &session, "--json"]).stdout).expect("utf8");
    assert!(
        !events.contains(secret),
        "written content reached the event log"
    );

    // And an argument that looks like a credential is redacted before it is stored.
    let run = Command::new(env!("CARGO_BIN_EXE_vigil"))
        .args([
            "--state-db",
            &database,
            "run",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--",
            "/usr/bin/true",
            secret,
        ])
        .output()
        .expect("run");
    let _ = run;
    let sessions =
        String::from_utf8(vigil(&database, &["sessions", "--json"]).stdout).expect("utf8");
    assert!(
        !sessions.contains(secret),
        "a credential-shaped argument was stored verbatim"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "network policy silently falls back to unrestricted".
#[test]
fn gate_network_policy_never_falls_back_to_unrestricted() {
    let (root, workspace, database) = fixture("network");
    let session = session(&database, &workspace, "developer-standard");

    for (host, why) in [
        ("203.0.113.7", "a direct IP bypasses hostname policy"),
        ("attacker.example", "a host outside the allowlist"),
    ] {
        let refused = vigil(
            &database,
            &[
                "network", "probe", &session, "--host", host, "--port", "443",
            ],
        );
        assert!(!refused.status.success(), "{why} was permitted: {host}");
    }
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "privilege escalation occurs without explicit policy".
#[test]
fn gate_privilege_and_persistence_are_never_granted() {
    let (root, workspace, _database) = fixture("privilege");
    for profile in [
        "developer-standard",
        "developer-restricted",
        "research",
        "untrusted-agent",
    ] {
        for action in ["system.privileged", "system.persistence", "secret.export"] {
            let decision = Command::new(env!("CARGO_BIN_EXE_vigil"))
                .args([
                    "policy",
                    "evaluate",
                    "--profile",
                    profile,
                    "--workspace",
                    workspace.to_str().expect("workspace"),
                    "--action",
                    action,
                    "--resource",
                    "anything",
                    "--json",
                ])
                .output()
                .expect("evaluate");
            let decision: serde_json::Value =
                serde_json::from_slice(&decision.stdout).expect("decision JSON");
            assert_eq!(
                decision["outcome"], "DENY",
                "{action} was not denied under {profile}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "process termination can kill unrelated processes".
///
/// This build cannot terminate anything, and the gate is met by that being true and stated
/// rather than by a termination implementation being careful.
#[test]
fn gate_containment_does_not_terminate_processes() {
    let (root, workspace, database) = fixture("terminate");
    let session = session(&database, &workspace, "developer-standard");
    let contained = json(&database, &["contain", &session, "--json"]);
    assert_eq!(
        contained["process_termination"], "not performed",
        "containment claimed to terminate something"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// §89 — "authorization callbacks routinely miss Endpoint Security deadlines".
///
/// There is no installed Endpoint Security client, so there are no callbacks to miss
/// deadlines. The gate is recorded as not-applicable rather than passing vacuously, and it
/// becomes a real check when the entitled half exists.
#[test]
fn gate_endpoint_deadlines_are_not_applicable_yet() {
    let (root, _workspace, database) = fixture("deadline");
    let status = json(&database, &["status", "--json"]);
    assert_eq!(
        status["endpoint_security"], "NOT INSTALLED",
        "an Endpoint Security client exists, so this gate must become a real deadline check"
    );
    let _ = std::fs::remove_dir_all(root);
}
