//! Durable process lineage for a session.
//!
//! A PID is not an identity. The kernel recycles PIDs, and an attribution scheme that keys on
//! one will eventually hand a stranger's process the authority of a dead one. Every node here
//! has an opaque `node_id`; the PID is recorded as an observation, and a partial unique index
//! (`processes_live_pid`) refuses to let two *live* nodes in one session claim the same PID.
//! A recycled PID is recordable only once the previous node is closed.
//!
//! Edges are derived from `parent_node_id` rather than stored separately, so the graph cannot
//! disagree with itself.
//!
//! # Scope
//!
//! This records what VIGIL itself launched: the child of `vigil run`, and each child of the
//! structured process broker. It does **not** see grandchildren. Nothing here observes a
//! process VIGIL did not start, because on this host there is no Endpoint Security client to
//! report one. The graph is complete with respect to brokered execution and silent about
//! everything else, and callers must not read absence from it as evidence of absence.

use crate::LocalStore;
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use vigil_common::{Result, VigilError};

/// Bound on lineage depth, so a runaway spawn chain cannot grow the graph without limit.
pub const MAX_PROCESS_GENERATION: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    Running,
    Exited,
    Terminated,
    Unknown,
}

impl ProcessStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Exited => "exited",
            Self::Terminated => "terminated",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "running" => Ok(Self::Running),
            "exited" => Ok(Self::Exited),
            "terminated" => Ok(Self::Terminated),
            "unknown" => Ok(Self::Unknown),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown process status `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessNode {
    pub node_id: String,
    pub session_id: String,
    pub parent_node_id: Option<String>,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub exited_at: Option<DateTime<Utc>>,
    /// The kernel's start time for this PID, captured at spawn.
    ///
    /// `None` for nodes recorded before identity capture existed. Such a node can never be
    /// distinguished from a recycled PID, so it is never signalled.
    #[serde(default)]
    pub os_started_at: Option<String>,
    /// The command as the kernel reported it at spawn, captured alongside
    /// [`Self::os_started_at`] so the later comparison is like for like.
    #[serde(default)]
    pub os_executable: Option<String>,
    pub executable: String,
    pub executable_sha256: Option<String>,
    pub argv: Vec<String>,
    /// Distance from the session root. The root is generation 0.
    pub generation: u32,
    pub exit_code: Option<i32>,
    pub status: ProcessStatus,
}

/// A process to record, mirroring `NewSession` for sessions.
///
/// Grouped rather than passed positionally because the identity fields are easy to transpose:
/// `executable` is the path the caller asked to run, while `observed` carries what the kernel
/// reported, and confusing the two is what makes an identity check vacuous (ADR 0041).
#[derive(Debug, Clone, Copy)]
pub struct NewProcess<'a> {
    pub session_id: &'a str,
    pub parent_node_id: Option<&'a str>,
    pub pid: u32,
    pub executable: &'a str,
    pub argv: &'a [String],
    pub executable_sha256: Option<&'a str>,
    /// What `ps` reported for this PID at spawn. `None` makes the node unsignallable.
    pub observed: Option<&'a crate::process_identity::ProcessIdentity>,
}

/// A parent-to-child relationship, derived from the nodes rather than stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEdge {
    pub parent_node_id: String,
    pub child_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessGraph {
    pub session_id: String,
    pub nodes: Vec<ProcessNode>,
    pub edges: Vec<ProcessEdge>,
}

impl ProcessGraph {
    fn index(&self) -> BTreeMap<&str, &ProcessNode> {
        self.nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node))
            .collect()
    }

    /// Every node reachable downward from `node_id`, excluding the node itself.
    ///
    /// Breadth-first over recorded parent pointers, with a visited set so a corrupted cycle
    /// cannot loop forever.
    pub fn descendants(&self, node_id: &str) -> Vec<&ProcessNode> {
        let mut children: BTreeMap<&str, Vec<&ProcessNode>> = BTreeMap::new();
        for node in &self.nodes {
            if let Some(parent) = node.parent_node_id.as_deref() {
                children.entry(parent).or_default().push(node);
            }
        }
        let mut seen: Vec<&str> = vec![node_id];
        let mut queue: VecDeque<&str> = VecDeque::from([node_id]);
        let mut found = Vec::new();
        while let Some(current) = queue.pop_front() {
            for child in children.get(current).into_iter().flatten() {
                if seen.contains(&child.node_id.as_str()) {
                    continue;
                }
                seen.push(child.node_id.as_str());
                found.push(*child);
                queue.push_back(child.node_id.as_str());
            }
        }
        found
    }

    /// Every node from `node_id`'s parent up to the session root, nearest first.
    pub fn ancestors(&self, node_id: &str) -> Vec<&ProcessNode> {
        let index = self.index();
        let mut found = Vec::new();
        let mut current = index
            .get(node_id)
            .and_then(|node| node.parent_node_id.as_deref());
        while let Some(parent_id) = current {
            let Some(parent) = index.get(parent_id) else {
                break;
            };
            if found
                .iter()
                .any(|node: &&ProcessNode| node.node_id == parent.node_id)
            {
                break;
            }
            found.push(*parent);
            current = parent.parent_node_id.as_deref();
        }
        found
    }

    /// The session's root nodes — those VIGIL launched directly.
    pub fn roots(&self) -> Vec<&ProcessNode> {
        self.nodes
            .iter()
            .filter(|node| node.parent_node_id.is_none())
            .collect()
    }
}

impl LocalStore {
    /// Record a process VIGIL just launched.
    ///
    /// Fails when the PID is already claimed by a live node in this session, which is what
    /// makes PID reuse a recorded conflict rather than a silent misattribution.
    pub fn record_process_start(&self, request: &NewProcess<'_>) -> Result<ProcessNode> {
        let NewProcess {
            session_id,
            parent_node_id,
            pid,
            executable,
            argv,
            executable_sha256,
            observed,
        } = *request;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let generation = match parent_node_id {
            None => 0,
            Some(parent) => {
                let parent_generation: Option<i64> = transaction
                    .query_row(
                        "SELECT generation FROM processes WHERE node_id = ?1 AND session_id = ?2",
                        params![parent, session_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(super::store::storage_error)?;
                let parent_generation = parent_generation
                    .ok_or_else(|| VigilError::NotFound(format!("parent process node {parent}")))?;
                u32::try_from(parent_generation)
                    .map_err(|_| {
                        VigilError::AuditIntegrity("process generation is out of range".to_string())
                    })?
                    .saturating_add(1)
            }
        };
        if generation > MAX_PROCESS_GENERATION {
            return Err(VigilError::InvalidRequest(format!(
                "process lineage exceeds the maximum depth of {MAX_PROCESS_GENERATION}"
            )));
        }

        let node = ProcessNode {
            node_id: format!("prc_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.to_string(),
            parent_node_id: parent_node_id.map(str::to_string),
            pid,
            started_at: Utc::now(),
            exited_at: None,
            os_started_at: observed.map(|identity| identity.os_started_at.clone()),
            os_executable: observed.map(|identity| identity.executable.clone()),
            executable: vigil_common::redact::single_line_excerpt(executable, 500),
            executable_sha256: executable_sha256.map(str::to_string),
            // Arguments routinely carry inline tokens; record their shape, never their value.
            argv: argv
                .iter()
                .map(|value| vigil_common::redact::redact_low_entropy(value))
                .collect(),
            generation,
            exit_code: None,
            status: ProcessStatus::Running,
        };
        transaction
            .execute(
                "INSERT INTO processes
                 (node_id, session_id, parent_node_id, pid, started_at, executable,
                  executable_sha256, argv_json, generation, status, os_started_at,
                  os_executable)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'running', ?10, ?11)",
                params![
                    node.node_id,
                    node.session_id,
                    node.parent_node_id,
                    node.pid,
                    node.started_at.to_rfc3339(),
                    node.executable,
                    node.executable_sha256,
                    serde_json::to_string(&node.argv)?,
                    node.generation,
                    node.os_started_at,
                    node.os_executable,
                ],
            )
            .map_err(|error| match error {
                rusqlite::Error::SqliteFailure(code, _)
                    if code.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    VigilError::AuditIntegrity(format!(
                        "pid {pid} is already held by a live process node in session \
                         {session_id}; refusing to attribute two live processes to one pid"
                    ))
                }
                other => super::store::storage_error(other),
            })?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(node)
    }

    /// Close a node. Idempotent: closing an already-closed node changes nothing.
    ///
    /// Closing is what frees the PID for reuse, so it must happen even on the error paths of
    /// whatever launched the process.
    pub fn record_process_exit(
        &self,
        node_id: &str,
        exit_code: Option<i32>,
        status: ProcessStatus,
    ) -> Result<()> {
        if status == ProcessStatus::Running {
            return Err(VigilError::InvalidRequest(
                "a process exit cannot be recorded as still running".to_string(),
            ));
        }
        self.connection
            .execute(
                "UPDATE processes SET exited_at = ?1, exit_code = ?2, status = ?3
                 WHERE node_id = ?4 AND exited_at IS NULL",
                params![Utc::now().to_rfc3339(), exit_code, status.as_str(), node_id],
            )
            .map_err(super::store::storage_error)?;
        Ok(())
    }

    /// The full process graph for a session.
    pub fn process_graph(&self, session_id: &str) -> Result<ProcessGraph> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT node_id, session_id, parent_node_id, pid, started_at, exited_at,
                        executable, executable_sha256, argv_json, generation, exit_code,
                        status, os_started_at, os_executable
                 FROM processes WHERE session_id = ?1 ORDER BY started_at, node_id",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([session_id], node_from_row)
            .map_err(super::store::storage_error)?;
        let nodes = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?
            .into_iter()
            .collect::<Result<Vec<ProcessNode>>>()?;
        let edges = nodes
            .iter()
            .filter_map(|node| {
                node.parent_node_id.as_ref().map(|parent| ProcessEdge {
                    parent_node_id: parent.clone(),
                    child_node_id: node.node_id.clone(),
                })
            })
            .collect();
        Ok(ProcessGraph {
            session_id: session_id.to_string(),
            nodes,
            edges,
        })
    }
}

/// Read a stored process node.
///
/// Every column is read up front, so the SQLite failure mode (a column that is missing or of
/// the wrong type) stays separate from the interpretation failure mode (a value SQLite handed
/// over intact that VIGIL will not accept). The nested `Result` keeps those two distinct
/// rather than collapsing a corrupted lineage record into a generic storage error.
fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ProcessNode>> {
    let node_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let parent_node_id: Option<String> = row.get(2)?;
    let pid: i64 = row.get(3)?;
    let started_at: String = row.get(4)?;
    let exited_at: Option<String> = row.get(5)?;
    let executable: String = row.get(6)?;
    let executable_sha256: Option<String> = row.get(7)?;
    let argv: String = row.get(8)?;
    let generation: i64 = row.get(9)?;
    let exit_code: Option<i32> = row.get(10)?;
    let status: String = row.get(11)?;
    let os_started_at: Option<String> = row.get(12)?;
    let os_executable: Option<String> = row.get(13)?;

    Ok((|| {
        Ok(ProcessNode {
            node_id,
            session_id,
            parent_node_id,
            pid: u32::try_from(pid).map_err(|_| {
                VigilError::AuditIntegrity("stored pid is out of range".to_string())
            })?,
            started_at: parse_time(&started_at)?,
            exited_at: exited_at.as_deref().map(parse_time).transpose()?,
            os_started_at,
            os_executable,
            executable,
            executable_sha256,
            argv: serde_json::from_str(&argv)?,
            generation: u32::try_from(generation).map_err(|_| {
                VigilError::AuditIntegrity("stored generation is out of range".to_string())
            })?,
            exit_code,
            status: ProcessStatus::parse(&status)?,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            VigilError::Serialization(format!("unparsable process timestamp: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewSession;
    use std::path::PathBuf;

    fn active_session() -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-provenance-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace,
                executable: "vigil-test".to_string(),
                argv: vec!["vigil-test".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        (root, store, session.id)
    }

    /// The reason node identity is not the PID. Two live processes may not claim one PID, and
    /// a PID reused after the first exits becomes a second, separate node.
    #[test]
    fn one_pid_cannot_belong_to_two_live_processes() {
        let (root, store, session) = active_session();
        let first = store
            .record_process_start(&NewProcess {
                session_id: &session,
                parent_node_id: None,
                pid: 4242,
                executable: "/bin/echo",
                argv: &[],
                executable_sha256: None,
                observed: None,
            })
            .expect("record first");

        let conflict = store
            .record_process_start(&NewProcess {
                session_id: &session,
                parent_node_id: None,
                pid: 4242,
                executable: "/bin/cat",
                argv: &[],
                executable_sha256: None,
                observed: None,
            })
            .expect_err("a live pid must not be reassignable");
        assert!(matches!(conflict, VigilError::AuditIntegrity(_)));

        // Once the first exits, the kernel may hand the PID to something unrelated, and that
        // is recordable as its own node.
        store
            .record_process_exit(&first.node_id, Some(0), ProcessStatus::Exited)
            .expect("close first");
        let second = store
            .record_process_start(&NewProcess {
                session_id: &session,
                parent_node_id: None,
                pid: 4242,
                executable: "/bin/cat",
                argv: &[],
                executable_sha256: None,
                observed: None,
            })
            .expect("record reused pid");

        assert_ne!(first.node_id, second.node_id);
        let graph = store.process_graph(&session).expect("graph");
        assert_eq!(graph.nodes.len(), 2);
        // Attribution follows the node, not the number: the reused PID did not inherit the
        // first process's identity or its executable.
        let reused = graph
            .nodes
            .iter()
            .find(|node| node.node_id == second.node_id)
            .expect("second node");
        assert_eq!(reused.executable, "/bin/cat");
        assert_eq!(reused.status, ProcessStatus::Running);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lineage_depth_is_recorded_and_bounded() {
        let (root, store, session) = active_session();
        let mut parent: Option<String> = None;
        for expected_generation in 0..4 {
            let node = store
                .record_process_start(&NewProcess {
                    session_id: &session,
                    parent_node_id: parent.as_deref(),
                    pid: 5000 + expected_generation,
                    executable: "/bin/echo",
                    argv: &[],
                    executable_sha256: None,
                    observed: None,
                })
                .expect("record");
            assert_eq!(node.generation, expected_generation);
            parent = Some(node.node_id);
        }
        let graph = store.process_graph(&session).expect("graph");
        let root_node = graph.roots()[0].node_id.clone();
        assert_eq!(graph.descendants(&root_node).len(), 3);
        assert_eq!(graph.edges.len(), 3);

        assert!(store
            .record_process_start(&NewProcess {
                session_id: &session,
                parent_node_id: Some("prc_missing"),
                pid: 6000,
                executable: "/bin/echo",
                argv: &[],
                executable_sha256: None,
                observed: None,
            })
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn closing_a_node_is_idempotent_and_arguments_are_never_stored_raw() {
        let (root, store, session) = active_session();
        let node = store
            .record_process_start(&NewProcess {
                session_id: &session,
                parent_node_id: None,
                pid: 7000,
                executable: "/bin/echo",
                argv: &["Authorization: Bearer secret-token-value".to_string()],
                executable_sha256: None,
                observed: None,
            })
            .expect("record");
        assert!(!node.argv.join(" ").contains("secret-token-value"));

        store
            .record_process_exit(&node.node_id, Some(0), ProcessStatus::Exited)
            .expect("close");
        // A second close must not overwrite the observed result with a later one.
        store
            .record_process_exit(&node.node_id, Some(9), ProcessStatus::Terminated)
            .expect("idempotent close");
        let graph = store.process_graph(&session).expect("graph");
        assert_eq!(graph.nodes[0].exit_code, Some(0));
        assert_eq!(graph.nodes[0].status, ProcessStatus::Exited);

        assert!(store
            .record_process_exit(&node.node_id, None, ProcessStatus::Running)
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    fn node(id: &str, parent: Option<&str>) -> ProcessNode {
        ProcessNode {
            node_id: id.to_string(),
            session_id: "ags_1".to_string(),
            parent_node_id: parent.map(str::to_string),
            pid: 1,
            started_at: Utc::now(),
            exited_at: None,
            executable: "/bin/true".to_string(),
            executable_sha256: None,
            argv: Vec::new(),
            generation: 0,
            exit_code: None,
            status: ProcessStatus::Running,
            os_started_at: None,
            os_executable: None,
        }
    }

    fn graph(nodes: Vec<ProcessNode>) -> ProcessGraph {
        let edges = nodes
            .iter()
            .filter_map(|node| {
                node.parent_node_id.as_ref().map(|parent| ProcessEdge {
                    parent_node_id: parent.clone(),
                    child_node_id: node.node_id.clone(),
                })
            })
            .collect();
        ProcessGraph {
            session_id: "ags_1".to_string(),
            nodes,
            edges,
        }
    }

    #[test]
    fn descendants_and_ancestors_walk_the_same_chain() {
        let graph = graph(vec![
            node("a", None),
            node("b", Some("a")),
            node("c", Some("b")),
            node("d", Some("a")),
            node("unrelated", None),
        ]);
        let mut descendants: Vec<_> = graph
            .descendants("a")
            .into_iter()
            .map(|node| node.node_id.as_str())
            .collect();
        descendants.sort_unstable();
        assert_eq!(descendants, ["b", "c", "d"]);

        let ancestors: Vec<_> = graph
            .ancestors("c")
            .into_iter()
            .map(|node| node.node_id.as_str())
            .collect();
        assert_eq!(ancestors, ["b", "a"]);

        assert!(graph.descendants("unrelated").is_empty());
        assert!(graph.ancestors("a").is_empty());
    }

    #[test]
    fn a_cycle_in_stored_lineage_does_not_hang_the_walk() {
        // Storage should make this unreachable; the traversal must still terminate if it
        // ever happens, because a hung security query is its own outage.
        let graph = graph(vec![node("a", Some("b")), node("b", Some("a"))]);
        // The start node is never reported as its own descendant, so the walk stops at `b`.
        assert_eq!(graph.descendants("a").len(), 1);
        assert_eq!(graph.ancestors("a").len(), 2);
    }
}
