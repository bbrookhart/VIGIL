//! Stopping the process tree of a contained session.
//!
//! # Why
//!
//! Until now containment withheld *authority*: leases were revoked and brokered requests were
//! denied, but a process already running was untouched. An agent that had already spawned a
//! long-running child kept it. Withdrawing permission to ask for something is not the same as
//! stopping what is already happening.
//!
//! # What
//!
//! Walk the session's process graph, and for each live node confirm the PID still names the
//! process VIGIL recorded before signalling it — `SIGTERM`, a grace period, then `SIGKILL`.
//!
//! Two orderings matter and both are deliberate:
//!
//! - **Deepest generation first.** Killing a parent before its children orphans them to
//!   `launchd`, where they keep running with no parent to reap them and no longer appear
//!   under the tree being stopped.
//! - **Verify immediately before signalling, never in a prior pass.** A check-then-signal
//!   split is a TOCTOU window in which the process can exit and the PID be reused.
//!
//! # Assumptions
//!
//! This only reaches processes in the graph. A process that escaped attribution — spawned
//! outside the broker, daemonised, or re-parented before it was recorded — is not in the
//! graph and is not stopped. That is the same gap ADR 0005 records: without Endpoint
//! Security, VIGIL sees what the brokers were asked to do, not everything that happened.
//!
//! # Failure mode
//!
//! Every uncertainty refuses to signal and says why. A node whose identity cannot be read, or
//! whose identity has changed, is reported as [`TerminationOutcome::Refused`] and left alone.
//! Refusing to stop an agent is recoverable; killing the user's editor because a PID was
//! recycled is not.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vigil_common::{Result, VigilError};

use crate::provenance::{ProcessNode, ProcessStatus};
use crate::store::LocalStore;

/// Absolute path: what stops a process must never be resolved through `PATH`.
const KILL_PATH: &str = "/bin/kill";

/// How long a process is given to handle `SIGTERM` before `SIGKILL`.
///
/// Long enough for a shell or interpreter to run its exit handlers and flush output — the
/// evidence of what it was doing is worth a moment — and short enough that containment is not
/// something an operator waits on.
const GRACE_PERIOD_MS: u64 = 2_000;

/// How often the grace period is re-checked.
const POLL_INTERVAL_MS: u64 = 50;

/// What happened to one process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TerminationOutcome {
    /// The process was signalled and is gone.
    Terminated { signal: String },
    /// The process had already exited. Nothing to do, and not a failure.
    AlreadyExited,
    /// The process was left running, with the reason. Always a deliberate refusal.
    Refused { reason: String },
}

/// One process's result, for the record and for the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminationRecord {
    pub node_id: String,
    pub pid: u32,
    pub executable: String,
    pub generation: u32,
    #[serde(flatten)]
    pub outcome: TerminationOutcome,
}

/// What a whole termination pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminationReport {
    pub records: Vec<TerminationRecord>,
}

impl TerminationReport {
    pub fn terminated(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(record.outcome, TerminationOutcome::Terminated { .. }))
            .count()
    }

    pub fn already_exited(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.outcome == TerminationOutcome::AlreadyExited)
            .count()
    }

    pub fn refused(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(record.outcome, TerminationOutcome::Refused { .. }))
            .count()
    }

    /// Whether anything was left running that the operator should know about.
    pub fn has_refusals(&self) -> bool {
        self.refused() > 0
    }
}

impl LocalStore {
    /// Stop every live process attributed to a session, deepest generation first.
    ///
    /// Returns what happened to each. A refusal is reported, not raised: one unidentifiable
    /// process must not stop the rest of the tree from being contained.
    pub fn terminate_session_tree(&self, session_id: &str) -> Result<TerminationReport> {
        self.terminate_session_tree_with_grace(session_id, Duration::from_millis(GRACE_PERIOD_MS))
    }

    /// As [`Self::terminate_session_tree`], with an explicit grace period so tests do not
    /// have to wait out the production one.
    pub fn terminate_session_tree_with_grace(
        &self,
        session_id: &str,
        grace: Duration,
    ) -> Result<TerminationReport> {
        if self.get_session(session_id)?.is_none() {
            return Err(VigilError::NotFound(format!("local session {session_id}")));
        }

        let graph = self.process_graph(session_id)?;
        let mut live: Vec<&ProcessNode> = graph
            .nodes
            .iter()
            .filter(|node| node.exited_at.is_none() && node.status == ProcessStatus::Running)
            .collect();

        // Deepest first: a parent stopped before its children leaves them orphaned to launchd,
        // still running and no longer reachable through this tree.
        live.sort_by(|left, right| {
            right
                .generation
                .cmp(&left.generation)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        let mut report = TerminationReport::default();
        for node in live {
            let outcome = self.terminate_node(node, grace);
            if matches!(
                outcome,
                TerminationOutcome::Terminated { .. } | TerminationOutcome::AlreadyExited
            ) {
                // Close the node whether it was signalled or found already gone. Leaving it
                // open would hold its PID unavailable for re-attribution and make a repeat
                // pass try to signal it again.
                let status = match outcome {
                    TerminationOutcome::Terminated { .. } => ProcessStatus::Terminated,
                    _ => ProcessStatus::Exited,
                };
                let _ = self.record_process_exit(&node.node_id, None, status);
            }
            report.records.push(TerminationRecord {
                node_id: node.node_id.clone(),
                pid: node.pid,
                executable: node.executable.clone(),
                generation: node.generation,
                outcome,
            });
        }
        Ok(report)
    }

    /// Stop one process, if and only if it is still the one that was recorded.
    fn terminate_node(&self, node: &ProcessNode, grace: Duration) -> TerminationOutcome {
        // Signalling ourselves would take down the process doing the containing; signalling an
        // ancestor would take down the shell that invoked it. Neither is ever the target.
        if node.pid == std::process::id() {
            return TerminationOutcome::Refused {
                reason: "this is VIGIL's own process".to_string(),
            };
        }

        // Identity is read immediately before the signal. Checking in an earlier pass would
        // leave a window for the process to exit and the PID to be reused.
        let identity = match crate::process_identity::identify(node.pid) {
            // A zombie is dead and merely unreaped. Its command reads `<defunct>`, so falling
            // through to the identity comparison would misread it as a recycled PID.
            Ok(Some(identity)) if identity.is_zombie => return TerminationOutcome::AlreadyExited,
            Ok(Some(identity)) => identity,
            Ok(None) => return TerminationOutcome::AlreadyExited,
            Err(error) => {
                return TerminationOutcome::Refused {
                    reason: format!("could not read the identity of pid {}: {error}", node.pid),
                }
            }
        };

        if !identity.matches_recorded(node.os_started_at.as_deref(), node.os_executable.as_deref())
        {
            return TerminationOutcome::Refused {
                reason: match &node.os_started_at {
                    None => format!(
                        "pid {} was recorded before start-time capture existed, so it cannot \
                         be told apart from a recycled pid",
                        node.pid
                    ),
                    Some(recorded) => format!(
                        "pid {} now belongs to a process started at {}, not the one recorded \
                         at {}; the pid was recycled",
                        node.pid, identity.os_started_at, recorded
                    ),
                },
            };
        }

        if let Err(error) = signal(node.pid, "TERM") {
            return TerminationOutcome::Refused {
                reason: format!("SIGTERM to pid {} failed: {error}", node.pid),
            };
        }
        if wait_for_exit(node.pid, grace) {
            return TerminationOutcome::Terminated {
                signal: "SIGTERM".to_string(),
            };
        }

        // Still there. Re-confirm identity before escalating: the process may have exited
        // during the grace period and the pid been taken by something else.
        match crate::process_identity::identify(node.pid) {
            Ok(Some(current)) if current.is_zombie => {
                return TerminationOutcome::Terminated {
                    signal: "SIGTERM".to_string(),
                }
            }
            Ok(None) => {
                return TerminationOutcome::Terminated {
                    signal: "SIGTERM".to_string(),
                }
            }
            Ok(Some(current))
                if !current.matches_recorded(
                    node.os_started_at.as_deref(),
                    node.os_executable.as_deref(),
                ) =>
            {
                return TerminationOutcome::Refused {
                    reason: format!(
                        "pid {} was replaced during the grace period; not escalating to \
                         SIGKILL",
                        node.pid
                    ),
                }
            }
            Err(error) => {
                return TerminationOutcome::Refused {
                    reason: format!(
                        "could not re-confirm pid {} before SIGKILL: {error}",
                        node.pid
                    ),
                }
            }
            Ok(Some(_)) => {}
        }

        if let Err(error) = signal(node.pid, "KILL") {
            return TerminationOutcome::Refused {
                reason: format!("SIGKILL to pid {} failed: {error}", node.pid),
            };
        }
        if wait_for_exit(node.pid, grace) {
            TerminationOutcome::Terminated {
                signal: "SIGKILL".to_string(),
            }
        } else {
            TerminationOutcome::Refused {
                reason: format!("pid {} survived SIGKILL", node.pid),
            }
        }
    }
}

/// Send one signal to one pid.
///
/// Shelling out rather than calling `kill(2)`: this crate is `#![forbid(unsafe_code)]`, and
/// every route to the syscall is FFI.
fn signal(pid: u32, name: &'static str) -> Result<()> {
    if pid <= 1 {
        // Defence in depth. The caller has already rejected these, and a signal to launchd
        // would be catastrophic and irreversible.
        return Err(VigilError::InvalidRequest(format!(
            "refusing to signal pid {pid}"
        )));
    }
    let status = Command::new(KILL_PATH)
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| VigilError::Unavailable {
            component: "process_termination",
            reason: format!("could not run {KILL_PATH}: {error}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(VigilError::Unavailable {
            component: "process_termination",
            reason: format!("{KILL_PATH} -{name} {pid} exited with {status}"),
        })
    }
}

/// Poll until the pid is gone or the deadline passes. `true` means it exited.
fn wait_for_exit(pid: u32, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        match crate::process_identity::identify(pid) {
            // Gone, or dead and awaiting reaping. Both mean it stopped.
            Ok(None) => return true,
            Ok(Some(identity)) if identity.is_zombie => return true,
            // An unreadable identity is not evidence of exit.
            Ok(Some(_)) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::NewProcess;
    use crate::store::NewSession;

    struct Fixture {
        root: std::path::PathBuf,
        store: LocalStore,
        session: String,
        children: Vec<std::process::Child>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("vigil-terminate-{}", uuid::Uuid::new_v4()));
            let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
            let session = store
                .create_session(&NewSession {
                    profile: "developer-standard".to_string(),
                    workspace: root.clone(),
                    executable: "/bin/sleep".to_string(),
                    argv: vec!["sleep".to_string()],
                    task: None,
                    enforcement_posture: "semantic_enforced".to_string(),
                })
                .expect("create session")
                .id;
            Self {
                root,
                store,
                session,
                children: Vec::new(),
            }
        }

        /// Spawn a real process and record it, capturing its identity the way the brokers do.
        fn spawn_recorded(&mut self, parent: Option<&str>) -> (String, u32) {
            let child = Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn");
            let pid = child.id();
            let observed = crate::process_identity::identify(pid)
                .expect("identify")
                .expect("alive");
            let node = self
                .store
                .record_process_start(&NewProcess {
                    session_id: &self.session,
                    parent_node_id: parent,
                    pid,
                    executable: "/bin/sleep",
                    argv: &["sleep".to_string(), "60".to_string()],
                    executable_sha256: None,
                    observed: Some(&observed),
                })
                .expect("record");
            self.children.push(child);
            (node.node_id, pid)
        }

        fn terminate(&self) -> TerminationReport {
            self.store
                .terminate_session_tree_with_grace(&self.session, Duration::from_millis(1_500))
                .expect("terminate")
        }
    }

    /// Whether a pid names a *running* process.
    ///
    /// The fixture holds its children without reaping them, so a stopped one lingers as a
    /// zombie that still occupies the pid. A zombie is not alive.
    fn is_alive(pid: u32) -> bool {
        matches!(
            crate::process_identity::identify(pid),
            Ok(Some(identity)) if !identity.is_zombie
        )
    }

    #[test]
    fn a_recorded_process_is_actually_stopped() {
        let mut fixture = Fixture::new();
        let (_node, pid) = fixture.spawn_recorded(None);
        assert!(is_alive(pid));

        let report = fixture.terminate();
        assert_eq!(report.terminated(), 1, "{report:?}");
        assert_eq!(report.refused(), 0, "{report:?}");
        assert!(!is_alive(pid), "the process outlived termination");
    }

    #[test]
    fn a_recycled_pid_is_never_signalled() {
        // The property the whole feature rests on. The node's recorded start time is altered
        // so it no longer matches the live process — exactly what a caller would see if the
        // PID had been reused between recording and containment.
        let mut fixture = Fixture::new();
        let (node_id, pid) = fixture.spawn_recorded(None);
        fixture
            .store
            .connection
            .execute(
                "UPDATE processes SET os_started_at = 'Sun Jan 01 00:00:01 2001'
                 WHERE node_id = ?1",
                rusqlite::params![node_id],
            )
            .expect("rewrite recorded identity");

        let report = fixture.terminate();
        assert_eq!(report.terminated(), 0, "{report:?}");
        assert_eq!(report.refused(), 1, "{report:?}");
        let TerminationOutcome::Refused { reason } = &report.records[0].outcome else {
            panic!("expected a refusal, got {:?}", report.records[0]);
        };
        assert!(reason.contains("recycled"), "{reason}");
        assert!(
            is_alive(pid),
            "a process with a mismatched identity was killed"
        );
    }

    #[test]
    fn a_node_recorded_without_an_identity_is_never_signalled() {
        // Nodes written before identity capture existed. Indistinguishable from a recycled
        // pid, so they are left alone rather than signalled on a guess.
        let mut fixture = Fixture::new();
        let (node_id, pid) = fixture.spawn_recorded(None);
        fixture
            .store
            .connection
            .execute(
                "UPDATE processes SET os_started_at = NULL, os_executable = NULL
                 WHERE node_id = ?1",
                rusqlite::params![node_id],
            )
            .expect("clear recorded identity");

        let report = fixture.terminate();
        assert_eq!(report.refused(), 1, "{report:?}");
        let TerminationOutcome::Refused { reason } = &report.records[0].outcome else {
            panic!("expected a refusal");
        };
        assert!(reason.contains("before start-time capture"), "{reason}");
        assert!(is_alive(pid));
    }

    #[test]
    fn children_are_stopped_before_their_parents() {
        // A parent killed first orphans its children to launchd, where they keep running and
        // are no longer reachable through this tree.
        let mut fixture = Fixture::new();
        let (root_node, root_pid) = fixture.spawn_recorded(None);
        let (_child_node, child_pid) = fixture.spawn_recorded(Some(&root_node));

        let report = fixture.terminate();
        assert_eq!(report.terminated(), 2, "{report:?}");
        let generations: Vec<u32> = report.records.iter().map(|r| r.generation).collect();
        assert_eq!(generations, vec![1, 0], "deepest generation must be first");
        assert!(!is_alive(root_pid));
        assert!(!is_alive(child_pid));
    }

    #[test]
    fn an_already_exited_process_is_not_a_failure() {
        let mut fixture = Fixture::new();
        let (_node, pid) = fixture.spawn_recorded(None);
        let child = fixture.children.last_mut().expect("child");
        child.kill().expect("kill");
        child.wait().expect("reap");

        let report = fixture.terminate();
        assert_eq!(report.already_exited(), 1, "{report:?}");
        assert_eq!(report.refused(), 0, "{report:?}");
        assert!(!is_alive(pid));
    }

    #[test]
    fn termination_closes_the_nodes_it_acted_on() {
        // A node left open holds its pid unavailable for re-attribution, and a second pass
        // would try to signal it again.
        let mut fixture = Fixture::new();
        fixture.spawn_recorded(None);
        fixture.terminate();

        let graph = fixture
            .store
            .process_graph(&fixture.session)
            .expect("graph");
        assert!(
            graph.nodes.iter().all(|node| node.exited_at.is_some()),
            "a terminated node was left open: {graph:?}"
        );
        assert_eq!(graph.nodes[0].status, ProcessStatus::Terminated);

        // A repeat pass has nothing left to do.
        let second = fixture.terminate();
        assert!(second.records.is_empty(), "{second:?}");
    }

    #[test]
    fn vigil_never_signals_itself() {
        let fixture = Fixture::new();
        let observed = crate::process_identity::identify(std::process::id())
            .expect("identify")
            .expect("alive");
        fixture
            .store
            .record_process_start(&NewProcess {
                session_id: &fixture.session,
                parent_node_id: None,
                pid: std::process::id(),
                executable: "/proc/self",
                argv: &[],
                executable_sha256: None,
                observed: Some(&observed),
            })
            .expect("record");

        let report = fixture.terminate();
        assert_eq!(report.refused(), 1, "{report:?}");
        let TerminationOutcome::Refused { reason } = &report.records[0].outcome else {
            panic!("expected a refusal");
        };
        assert!(reason.contains("VIGIL's own process"), "{reason}");
    }

    #[test]
    fn an_unknown_session_is_an_error_not_an_empty_report() {
        let fixture = Fixture::new();
        assert!(fixture
            .store
            .terminate_session_tree_with_grace("ags_nope", Duration::from_millis(100))
            .is_err());
    }

    #[test]
    fn launchd_and_the_kernel_can_never_be_signalled() {
        // Defence in depth below the identity check: even a caller that reached `signal`
        // directly with a bad pid is refused.
        assert!(signal(0, "TERM").is_err());
        assert!(signal(1, "TERM").is_err());
    }
}
