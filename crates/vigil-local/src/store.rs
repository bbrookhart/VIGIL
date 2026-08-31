//! SQLite-backed local session and event storage.
//!
//! The database is WAL-backed, migrated before use, and created with owner-only
//! permissions. Security correctness never depends on a cleanup job: ended sessions remain
//! queryable and events are append-oriented.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vigil_common::{Result, VigilError};

const SCHEMA_VERSION: i64 = 12;

/// How long a workspace remembers that a session on it was contained.
///
/// An hour: long enough that restarting immediately gains nothing, short enough that a
/// workspace is not marked for the rest of the day by one incident.
const WORKSPACE_STANDING_WINDOW_SECONDS: i64 = 3600;

/// How many sessions on one workspace, inside [`CHURN_WINDOW_SECONDS`], reads as cycling
/// rather than as working.
///
/// Blast-radius budgets are per-session by design — a new task should get a new budget. The
/// consequence is that cycling sessions multiplies the total: three sessions on one workspace
/// performed 75 writes against a 25-write limit. Nothing here changes the per-task model,
/// which is correct; it notices the pattern that abuses it.
///
/// Five in ten minutes is well above ordinary iteration and well below what farming requires.
const CHURN_THRESHOLD: usize = 5;
const CHURN_WINDOW_SECONDS: i64 = 600;

/// Domain separator for the local event chain.
///
/// Prefixed to the canonical bytes before hashing so a chain link can never be confused with
/// any other SHA-256 this system computes over a JSON document.
const EVENT_CHAIN_DOMAIN: &[u8] = b"VIGIL_LOCAL_EVENT_CHAIN_V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Starting,
    Running,
    Completed,
    Failed,
    Sealed,
}

impl SessionStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Sealed => "sealed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "starting" => Ok(Self::Starting),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "sealed" => Ok(Self::Sealed),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown session status `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub profile: String,
    pub workspace: PathBuf,
    pub executable: String,
    pub argv: Vec<String>,
    pub task: Option<String>,
    pub enforcement_posture: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSession {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub profile: String,
    pub workspace: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub task: Option<String>,
    pub enforcement_posture: String,
    pub status: SessionStatus,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub risk_state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalEvent {
    pub sequence: i64,
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub category: String,
    pub action: String,
    pub decision: Option<String>,
    pub correlation_id: String,
    pub payload: serde_json::Value,
    /// Link to the preceding event. `None` only for the first event in the database.
    #[serde(default)]
    pub previous_hash: Option<String>,
    #[serde(default)]
    pub chain_hash: Option<String>,
}

impl LocalEvent {
    /// The chain link for this event.
    ///
    /// Commits to the sequence number as well as the content and the predecessor, so an event
    /// cannot be renumbered into a different position without breaking its own link. Hashed
    /// through the canonical JSON form, because hashing `serde_json` output directly would
    /// make the link depend on key insertion order.
    fn link_hash(&self) -> Result<String> {
        let document = serde_json::json!({
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp.to_rfc3339(),
            "session_id": self.session_id,
            "category": self.category,
            "action": self.action,
            "decision": self.decision,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        });
        let mut bytes = EVENT_CHAIN_DOMAIN.to_vec();
        bytes.extend_from_slice(&vigil_common::canonical::canonical_bytes(&document)?);
        Ok(vigil_common::ContentHash::sha256(&bytes).to_string())
    }
}

/// The result of recomputing the local event chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerification {
    pub verified: bool,
    pub events_checked: usize,
    /// The final link, which is what a checkpoint signs.
    pub head: Option<String>,
    pub failure: Option<ChainFailure>,
    /// How many signed checkpoints were checked against the recomputed chain.
    #[serde(default)]
    pub checkpoints_checked: usize,
    /// Checkpoints that did not hold, in sequence order. A chain whose links are all
    /// internally consistent still fails overall if any of these is populated: that is the
    /// signature of a wholesale rewrite.
    #[serde(default)]
    pub checkpoint_failures: Vec<(i64, crate::checkpoint::CheckpointFailure)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainFailure {
    pub at_sequence: i64,
    pub reason: String,
}

impl ChainVerification {
    fn failed(checked: usize, sequence: i64, reason: String) -> Self {
        Self {
            verified: false,
            events_checked: checked,
            head: None,
            failure: Some(ChainFailure {
                at_sequence: sequence,
                reason,
            }),
            checkpoints_checked: 0,
            checkpoint_failures: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct LocalStore {
    pub(crate) connection: Connection,
    path: PathBuf,
}

impl LocalStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            let parent_existed = parent.exists();
            std::fs::create_dir_all(parent)?;
            if !parent_existed {
                set_owner_only(parent, true)?;
            }
        }
        let connection = Connection::open(path).map_err(storage_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(storage_error)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage_error)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
        };
        store.migrate()?;
        set_owner_only(path, false)?;
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if sidecar.exists() {
                set_owner_only(&sidecar, false)?;
            }
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_version(&self) -> Result<i64> {
        self.connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage_error)
    }

    pub fn health_check(&self) -> Result<()> {
        let result: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(storage_error)?;
        if result == "ok" {
            Ok(())
        } else {
            Err(VigilError::AuditIntegrity(format!(
                "SQLite quick_check failed: {result}"
            )))
        }
    }

    pub fn create_session(&self, request: &NewSession) -> Result<LocalSession> {
        let profile: crate::LocalProfile = request.profile.parse()?;
        let argv = request
            .argv
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if index == 0 {
                    vigil_common::redact::single_line_excerpt(value, 500)
                } else {
                    // Command arguments frequently carry inline tokens, passwords, or user
                    // content. Local lifecycle evidence records their presence and length,
                    // never the raw value.
                    vigil_common::redact::redact_low_entropy(value)
                }
            })
            .collect();
        let session = LocalSession {
            id: format!("ags_{}", uuid::Uuid::new_v4().simple()),
            created_at: Utc::now(),
            ended_at: None,
            profile: request.profile.clone(),
            workspace: request.workspace.display().to_string(),
            executable: vigil_common::redact::single_line_excerpt(&request.executable, 500),
            argv,
            task: request
                .task
                .as_deref()
                .map(|task| vigil_common::redact::single_line_excerpt(task, 500)),
            enforcement_posture: request.enforcement_posture.clone(),
            status: SessionStatus::Starting,
            pid: None,
            exit_code: None,
            risk_state: "NORMAL".to_string(),
        };
        let argv = serde_json::to_string(&session.argv)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        transaction
            .execute(
                "INSERT INTO sessions
                 (id, created_at, profile, workspace, executable, argv_json, task,
                  enforcement_posture, status, risk_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    session.id,
                    session.created_at.to_rfc3339(),
                    session.profile,
                    session.workspace,
                    session.executable,
                    argv,
                    session.task,
                    session.enforcement_posture,
                    session.status.as_str(),
                    session.risk_state,
                ],
            )
            .map_err(storage_error)?;
        crate::budget::initialize_budget_rows(&transaction, &session.id, profile)?;
        transaction.commit().map_err(storage_error)?;
        self.apply_workspace_standing(&session)?;
        Ok(session)
    }

    /// A new session on a recently contained workspace does not start with a clean slate.
    ///
    /// Risk, budgets, and denial history are per-session, and anyone who can start a session
    /// gets fresh ones. That made containment escapable by simply starting again: a
    /// quarantined session's agent could open a new one on the same workspace and recover full
    /// authority immediately. Containment that lasts until the next command is not containment.
    ///
    /// The response is deliberately partial. The new session starts `ELEVATED`, not contained
    /// — so workspace mutations need a human, and reads still work. Inheriting full containment
    /// would let one bad session render a workspace unusable for an hour, which is a denial of
    /// service against the user rather than a control on the agent.
    ///
    /// This does not close the underlying gap, which is that an agent running as the user can
    /// start sessions at all. That is invariant 3, and it needs `vigild`. What this removes is
    /// the *free* reset.
    fn apply_workspace_standing(&self, session: &LocalSession) -> Result<()> {
        self.inherit_containment(session)?;
        self.notice_session_churn(session)?;
        Ok(())
    }

    /// Notice a workspace accumulating sessions faster than work explains.
    ///
    /// The evidence carries the *cumulative* consumption across those sessions, because the
    /// abstract fact that several sessions exist is not actionable while "these five sessions
    /// have written 120 files against a 25-file limit" is.
    fn notice_session_churn(&self, session: &LocalSession) -> Result<()> {
        let since = (Utc::now() - chrono::Duration::seconds(CHURN_WINDOW_SECONDS)).to_rfc3339();
        let recent: Vec<String> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT id FROM sessions
                     WHERE workspace = ?1 AND created_at > ?2 ORDER BY created_at DESC",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map(params![session.workspace, since], |row| row.get(0))
                .map_err(storage_error)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage_error)?
        };
        if recent.len() < CHURN_THRESHOLD {
            return Ok(());
        }

        // Sum what those sessions actually spent, per dimension.
        let mut cumulative: std::collections::BTreeMap<String, i64> =
            std::collections::BTreeMap::new();
        for id in &recent {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT dimension, consumed FROM budget_counters
                     WHERE session_id = ?1 AND consumed > 0",
                )
                .map_err(storage_error)?;
            let rows = statement
                .query_map([id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(storage_error)?;
            for row in rows {
                let (dimension, consumed) = row.map_err(storage_error)?;
                *cumulative.entry(dimension).or_default() += consumed;
            }
        }

        if let Some(rule) = crate::rule_for_label(crate::DETECTION_SESSION_CHURN) {
            self.record_detection(
                &session.id,
                rule,
                serde_json::json!({
                    "workspace": session.workspace,
                    "sessions_in_window": recent.len(),
                    "window_seconds": CHURN_WINDOW_SECONDS,
                    "cumulative_consumption": cumulative,
                    // Stated because the per-session model is deliberate, not a bug.
                    "budgets_are_per_session_by_design": true,
                }),
                None,
            )?;
            self.escalate_risk_to(
                &session.id,
                crate::RiskState::Elevated,
                &format!(
                    "{} sessions started on this workspace within {CHURN_WINDOW_SECONDS}s",
                    recent.len()
                ),
            )?;
        }
        Ok(())
    }

    fn inherit_containment(&self, session: &LocalSession) -> Result<()> {
        let since = (Utc::now() - chrono::Duration::seconds(WORKSPACE_STANDING_WINDOW_SECONDS))
            .to_rfc3339();
        let prior: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT id, risk_state FROM sessions
                 WHERE workspace = ?1 AND id != ?2 AND created_at > ?3
                   AND risk_state IN ('CONTAINED', 'QUARANTINED')
                 ORDER BY created_at DESC LIMIT 1",
                params![session.workspace, session.id, since],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let Some((prior_session, prior_state)) = prior else {
            return Ok(());
        };

        if let Some(rule) = crate::rule_for_label(crate::DETECTION_WORKSPACE_STANDING_INHERITED) {
            self.record_detection(
                &session.id,
                rule,
                serde_json::json!({
                    "workspace": session.workspace,
                    "prior_session": prior_session,
                    "prior_risk_state": prior_state,
                    "window_seconds": WORKSPACE_STANDING_WINDOW_SECONDS,
                }),
                None,
            )?;
        }
        self.escalate_risk_to(
            &session.id,
            crate::RiskState::Elevated,
            &format!("a session on this workspace reached {prior_state} recently"),
        )?;
        Ok(())
    }

    pub fn mark_running(&self, id: &str, pid: u32) -> Result<()> {
        self.update_exactly_one(
            "UPDATE sessions SET status = 'running', pid = ?1 WHERE id = ?2",
            params![pid, id],
        )
    }

    /// Activate a logical semantic-broker session that is not owned by one child PID.
    pub fn activate_semantic_session(&self, id: &str) -> Result<()> {
        self.update_exactly_one(
            "UPDATE sessions SET status = 'running' WHERE id = ?1
             AND enforcement_posture = 'semantic_enforced' AND status = 'starting'",
            [id],
        )
    }

    pub fn finish_session(&self, id: &str, exit_code: Option<i32>) -> Result<()> {
        let status = if exit_code == Some(0) {
            SessionStatus::Completed
        } else {
            SessionStatus::Failed
        };
        self.update_exactly_one(
            "UPDATE sessions SET status = ?1, ended_at = ?2, exit_code = ?3 WHERE id = ?4",
            params![status.as_str(), Utc::now().to_rfc3339(), exit_code, id],
        )
    }

    pub fn seal_session(&self, id: &str, risk_state: &str) -> Result<()> {
        self.update_exactly_one(
            "UPDATE sessions SET status = 'sealed', ended_at = ?1, risk_state = ?2 WHERE id = ?3",
            params![Utc::now().to_rfc3339(), risk_state, id],
        )
    }

    pub fn get_session(&self, id: &str) -> Result<Option<LocalSession>> {
        self.connection
            .query_row(
                "SELECT id, created_at, ended_at, profile, workspace, executable, argv_json,
                        task, enforcement_posture, status, pid, exit_code, risk_state
                 FROM sessions WHERE id = ?1",
                [id],
                session_from_row,
            )
            .optional()
            .map_err(storage_error)
    }

    pub fn list_sessions(&self, limit: usize) -> Result<Vec<LocalSession>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, created_at, ended_at, profile, workspace, executable, argv_json,
                        task, enforcement_posture, status, pid, exit_code, risk_state
                 FROM sessions ORDER BY created_at DESC LIMIT ?1",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map([limit], session_from_row)
            .map_err(storage_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage_error)
    }

    /// Append one event, linking it to the one before it.
    ///
    /// The insert and the chain read happen in one `BEGIN IMMEDIATE` transaction so two
    /// concurrent appenders cannot both link to the same predecessor and fork the chain.
    ///
    /// The chain makes tampering *evident*; it does not make the log immutable. Anything that
    /// can write the database can rewrite the whole chain. What it costs an attacker is the
    /// ability to edit or drop one record and have the rest still verify.
    pub fn append_event(
        &self,
        session_id: &str,
        category: &str,
        action: &str,
        decision: Option<&str>,
        correlation_id: &str,
        payload: &serde_json::Value,
    ) -> Result<LocalEvent> {
        let event = LocalEvent {
            sequence: 0,
            event_id: format!("evt_{}", uuid::Uuid::new_v4().simple()),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            category: category.to_string(),
            action: action.to_string(),
            decision: decision.map(str::to_string),
            correlation_id: correlation_id.to_string(),
            payload: payload.clone(),
            previous_hash: None,
            chain_hash: None,
        };
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let previous_hash: Option<String> = transaction
            .query_row(
                "SELECT chain_hash FROM events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?
            .flatten();
        transaction
            .execute(
                "INSERT INTO events
                 (event_id, timestamp, session_id, category, action, decision, correlation_id,
                  payload_json, previous_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    event.event_id,
                    event.timestamp.to_rfc3339(),
                    event.session_id,
                    event.category,
                    event.action,
                    event.decision,
                    event.correlation_id,
                    serde_json::to_string(payload)?,
                    previous_hash,
                ],
            )
            .map_err(storage_error)?;
        let sequence = transaction.last_insert_rowid();
        let event = LocalEvent {
            sequence,
            previous_hash,
            ..event
        };
        let chain_hash = event.link_hash()?;
        transaction
            .execute(
                "UPDATE events SET chain_hash = ?1 WHERE sequence = ?2",
                params![chain_hash, sequence],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(LocalEvent {
            chain_hash: Some(chain_hash),
            ..event
        })
    }

    /// Compute and store links for events written before the chain existed.
    fn backfill_event_chain(&self) -> Result<()> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let mut statement = transaction
            .prepare(
                "SELECT sequence, event_id, timestamp, session_id, category, action, decision,
                        correlation_id, payload_json, previous_hash, chain_hash
                 FROM events ORDER BY sequence",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], event_from_row)
            .map_err(storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        drop(statement);
        let mut previous: Option<String> = None;
        for raw in events {
            let event = LocalEvent {
                sequence: raw.sequence,
                event_id: raw.event_id,
                timestamp: parse_timestamp(&raw.timestamp).expect("timestamp"),
                session_id: raw.session_id,
                category: raw.category,
                action: "fs.read".to_string(),
                decision: raw.decision,
                correlation_id: raw.correlation_id,
                payload: serde_json::from_str(&raw.payload).expect("payload"),
                previous_hash: previous.clone(),
                chain_hash: None,
            };
            let link = event.link_hash().expect("link");
            store
                .connection
                .execute(
                    "UPDATE events SET previous_hash = ?1, chain_hash = ?2 WHERE sequence = ?3",
                    rusqlite::params![previous, link, raw.sequence],
                )
                .expect("relink");
            previous = Some(link);
        }
    }

    #[test]
    fn a_wholesale_rewrite_defeats_the_hash_chain_alone() {
        // The gap this feature exists to close, demonstrated before it is closed. Deleting a
        // record, recomputing every link, and resetting the AUTOINCREMENT high-water mark
        // leaves a log that the link-by-link walk reports as perfectly clean.
        let (root, store, _session) = store_with_events(5);
        assert!(store.verify_event_chain().expect("verify").verified);

        store
            .connection
            .execute("DELETE FROM events WHERE sequence = 3", [])
            .expect("delete");
        store
            .connection
            .execute(
                "UPDATE events SET sequence = sequence - 1 WHERE sequence > 3",
                [],
            )
            .expect("renumber");
        rewrite_chain_consistently(&store);
        store
            .connection
            .execute(
                "UPDATE sqlite_sequence SET seq = 4 WHERE name = 'events'",
                [],
            )
            .expect("reset high-water mark");

        let verification = store.verify_event_chain().expect("verify");
        assert!(
            verification.verified,
            "the hash chain alone was expected to miss a wholesale rewrite"
        );
        assert_eq!(verification.events_checked, 4);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_checkpoint_detects_the_rewrite_the_chain_alone_misses() {
        // The same attack as above, against a log that was checkpointed first.
        let (root, store, _session) = store_with_events(5);
        let checkpoint = store
            .write_checkpoint(&checkpoint_signer(), Utc::now())
            .expect("checkpoint");
        assert_eq!(checkpoint.sequence, 5);

        store
            .connection
            .execute("DELETE FROM events WHERE sequence = 3", [])
            .expect("delete");
        store
            .connection
            .execute(
                "UPDATE events SET sequence = sequence - 1 WHERE sequence > 3",
                [],
            )
            .expect("renumber");
        rewrite_chain_consistently(&store);
        store
            .connection
            .execute(
                "UPDATE sqlite_sequence SET seq = 4 WHERE name = 'events'",
                [],
            )
            .expect("reset high-water mark");

        // The links still agree with each other...
        assert!(store.verify_event_chain().expect("verify").verified);
        // ...but no longer with what was signed.
        let verification = store
            .verify_event_chain_with_checkpoints(&checkpoint_verifier())
            .expect("verify");
        assert!(!verification.verified);
        assert_eq!(verification.checkpoints_checked, 1);
        assert!(matches!(
            verification.checkpoint_failures.as_slice(),
            [(
                5,
                crate::checkpoint::CheckpointFailure::TruncatedBelowCheckpoint { .. }
            )]
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_checkpoint_detects_edited_content_that_was_relinked() {
        // A rewrite that preserves the record count: the head at the checkpointed sequence
        // changes, so the signature no longer matches.
        let (root, store, _session) = store_with_events(4);
        store
            .write_checkpoint(&checkpoint_signer(), Utc::now())
            .expect("checkpoint");

        store
            .connection
            .execute(
                "UPDATE events SET decision = 'ALLOW' WHERE decision = 'ALLOW' AND sequence = 2",
                [],
            )
            .expect("noop");
        store
            .connection
            .execute(
                "UPDATE events SET payload_json = '{\"index\":99}' WHERE sequence = 2",
                [],
            )
            .expect("edit");
        rewrite_chain_consistently(&store);

        assert!(store.verify_event_chain().expect("verify").verified);
        let verification = store
            .verify_event_chain_with_checkpoints(&checkpoint_verifier())
            .expect("verify");
        assert!(!verification.verified);
        assert!(matches!(
            verification.checkpoint_failures.as_slice(),
            [(4, crate::checkpoint::CheckpointFailure::HeadMismatch { .. })]
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_untampered_checkpointed_chain_verifies() {
        let (root, store, session) = store_with_events(3);
        store
            .write_checkpoint(&checkpoint_signer(), Utc::now())
            .expect("checkpoint");
        // Appending after a checkpoint is normal operation, not tampering.
        store
            .append_event(
                &session,
                "filesystem",
                "fs.read",
                Some("ALLOW"),
                "corr-later",
                &serde_json::json!({ "index": 99 }),
            )
            .expect("append");

        let verification = store
            .verify_event_chain_with_checkpoints(&checkpoint_verifier())
            .expect("verify");
        assert!(verification.verified, "{verification:?}");
        assert_eq!(verification.checkpoints_checked, 1);
        assert_eq!(verification.events_checked, 4);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_checkpoint_signed_by_an_untrusted_key_does_not_pass() {
        // Verifying with no trusted keys must not silently succeed: an unverifiable
        // checkpoint says nothing about the log, and reporting clean would be a lie.
        let (root, store, _session) = store_with_events(3);
        store
            .write_checkpoint(&checkpoint_signer(), Utc::now())
            .expect("checkpoint");
        let verification = store
            .verify_event_chain_with_checkpoints(&crate::checkpoint::LocalCheckpointVerifier::new())
            .expect("verify");
        assert!(!verification.verified);
        assert!(matches!(
            verification.checkpoint_failures.as_slice(),
            [(3, crate::checkpoint::CheckpointFailure::UnknownKey { .. })]
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_broken_chain_is_never_checkpointed() {
        // Signing a chain that already fails would launder a rewrite into a signed
        // commitment — worse than having no checkpoint at all.
        let (root, store, _session) = store_with_events(3);
        store
            .connection
            .execute(
                "UPDATE events SET payload_json = '{\"index\":42}' WHERE sequence = 2",
                [],
            )
            .expect("edit");
        assert!(!store.verify_event_chain().expect("verify").verified);
        assert!(store
            .write_checkpoint(&checkpoint_signer(), Utc::now())
            .is_err());
        assert!(store.checkpoints().expect("checkpoints").is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_empty_log_is_never_checkpointed() {
        // A checkpoint over nothing would later be indistinguishable from one whose events
        // were all removed.
        let (root, store) = store();
        assert!(store
            .write_checkpoint(&checkpoint_signer(), Utc::now())
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_future_schema_is_refused_without_downgrade() {
        let root = std::env::temp_dir().join(format!("vigil-store-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");
        let path = root.join("future.db");
        let connection = Connection::open(&path).expect("open sqlite");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("set future schema");
        drop(connection);

        assert!(LocalStore::open(&path).is_err());
        let connection = Connection::open(&path).expect("reopen sqlite");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("read schema");
        assert_eq!(version, SCHEMA_VERSION + 1);
        drop(connection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_version_one_database_upgrades_without_losing_sessions() {
        let (root, store) = store();
        let path = store.path().to_path_buf();
        let existing = store
            .create_session(&request())
            .expect("create old session");
        drop(store);
        let connection = Connection::open(&path).expect("open sqlite");
        connection
            .execute_batch(
                "ALTER TABLE write_preimages DROP COLUMN postimage_state;
                 DROP TABLE clock_state;
                 DROP TABLE canaries;
                 DROP TABLE write_preimages;
                 DROP TABLE mcp_tools;
                 DROP TABLE mcp_servers;
                 DROP TABLE incident_responses;
                 DROP TABLE incidents;
                 DROP TABLE detections;
                 ALTER TABLE events DROP COLUMN chain_hash;
                 ALTER TABLE events DROP COLUMN previous_hash;
                 DROP TABLE processes;
                 DROP TABLE risk_transitions;
                 DROP TABLE risk_signals;
                 DROP TABLE capability_leases;
                 DROP TABLE approval_requests;
                 DROP TABLE network_destination_claims;
                 DROP TABLE budget_reservation_items;
                 DROP TABLE budget_reservations;
                 DROP TABLE budget_counters;
                 DROP TABLE IF EXISTS chain_checkpoints;
                 PRAGMA user_version = 1;",
            )
            .expect("downgrade fixture");
        drop(connection);

        let upgraded = LocalStore::open(&path).expect("upgrade store");
        assert_eq!(upgraded.schema_version().expect("schema"), SCHEMA_VERSION);
        assert!(upgraded
            .get_session(&existing.id)
            .expect("load old session")
            .is_some());
        let new_session = upgraded.create_session(&request()).expect("new session");
        assert_eq!(
            upgraded
                .budget_snapshot(&new_session.id)
                .expect("new budget")
                .len(),
            crate::BudgetDimension::ALL.len()
        );
        drop(upgraded);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A schema-3 database is what a user upgrading from the previous release actually has.
    /// It must gain the new tables without losing anything it already held.
    #[test]
    fn a_version_three_database_upgrades_without_losing_sessions_or_budgets() {
        let (root, store) = store();
        let path = store.path().to_path_buf();
        let mut request = request();
        request.enforcement_posture = "semantic_enforced".to_string();
        let existing = store.create_session(&request).expect("create session");
        store
            .mark_running(&existing.id, 4242)
            .expect("activate session");
        store
            .append_event(
                &existing.id,
                "session",
                "start",
                None,
                "corr-1",
                &serde_json::json!({"safe": true}),
            )
            .expect("append event");
        let reservation = store
            .reserve_budget(
                &existing.id,
                "corr-1",
                &[crate::BudgetCharge::new(
                    crate::BudgetDimension::FileReads,
                    3,
                )],
            )
            .expect("reserve");
        store.commit_budget(&reservation.id).expect("commit");
        drop(store);

        // Roll the schema back to 3 by dropping only what version 4 introduced.
        let connection = Connection::open(&path).expect("open sqlite");
        connection
            .execute_batch(
                "ALTER TABLE write_preimages DROP COLUMN postimage_state;
                 DROP TABLE clock_state;
                 DROP TABLE canaries;
                 DROP TABLE write_preimages;
                 DROP TABLE mcp_tools;
                 DROP TABLE mcp_servers;
                 DROP TABLE incident_responses;
                 DROP TABLE incidents;
                 DROP TABLE detections;
                 ALTER TABLE events DROP COLUMN chain_hash;
                 ALTER TABLE events DROP COLUMN previous_hash;
                 DROP TABLE processes;
                 DROP TABLE risk_transitions;
                 DROP TABLE risk_signals;
                 DROP TABLE capability_leases;
                 DROP TABLE approval_requests;
                 DROP TABLE IF EXISTS chain_checkpoints;
                 PRAGMA user_version = 3;",
            )
            .expect("downgrade fixture");
        drop(connection);

        let upgraded = LocalStore::open(&path).expect("upgrade store");
        assert_eq!(upgraded.schema_version().expect("schema"), SCHEMA_VERSION);
        let session = upgraded
            .get_session(&existing.id)
            .expect("load session")
            .expect("session survived");
        assert_eq!(session.status, SessionStatus::Running);
        assert_eq!(session.risk_state, "NORMAL");
        assert_eq!(
            upgraded
                .events_for_session(&existing.id)
                .expect("events")
                .len(),
            1
        );
        let counters = upgraded
            .budget_snapshot(&existing.id)
            .expect("budget survived");
        let reads = counters
            .iter()
            .find(|counter| counter.dimension == crate::BudgetDimension::FileReads)
            .expect("file_reads counter");
        assert_eq!(reads.consumed, 3);

        // The new tables are usable against the pre-existing session.
        assert!(upgraded
            .leases_for_session(&existing.id)
            .expect("leases")
            .is_empty());
        assert_eq!(
            upgraded.session_risk_state(&existing.id).expect("risk"),
            crate::RiskState::Normal
        );
        assert!(upgraded
            .process_graph(&existing.id)
            .expect("graph")
            .nodes
            .is_empty());
        drop(upgraded);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The three tamper classes the chain is supposed to make evident.
    ///
    /// Each mutation is applied directly to SQLite, which is exactly what an attacker with
    /// write access to the database would do.
    #[test]
    fn the_event_chain_makes_modification_and_removal_evident() {
        let (root, store) = store();
        let path = store.path().to_path_buf();
        let mut request = request();
        request.enforcement_posture = "semantic_enforced".to_string();
        let session = store.create_session(&request).expect("create session");
        for index in 0..4 {
            store
                .append_event(
                    &session.id,
                    "policy",
                    "fs.read",
                    Some("DENY"),
                    &format!("corr-{index}"),
                    &serde_json::json!({ "index": index }),
                )
                .expect("append");
        }
        let clean = store.verify_event_chain().expect("verify");
        assert!(clean.verified, "{clean:?}");
        assert_eq!(clean.events_checked, 4);
        assert!(clean.head.is_some());
        drop(store);

        // 1. Content modified: turning a denial into an allow.
        let modified = root.join("modified.db");
        std::fs::copy(&path, &modified).expect("copy");
        let connection = Connection::open(&modified).expect("open");
        connection
            .execute(
                "UPDATE events SET decision = 'ALLOW' WHERE sequence = 2",
                [],
            )
            .expect("tamper");
        drop(connection);
        let result = LocalStore::open(&modified)
            .expect("open")
            .verify_event_chain()
            .expect("verify");
        assert!(!result.verified);
        let failure = result.failure.expect("failure");
        assert_eq!(failure.at_sequence, 2);
        assert!(failure.reason.contains("does not match"), "{failure:?}");

        // 2. Record removed: deleting the inconvenient denial outright.
        let deleted = root.join("deleted.db");
        std::fs::copy(&path, &deleted).expect("copy");
        let connection = Connection::open(&deleted).expect("open");
        connection
            .execute("DELETE FROM events WHERE sequence = 3", [])
            .expect("tamper");
        drop(connection);
        let result = LocalStore::open(&deleted)
            .expect("open")
            .verify_event_chain()
            .expect("verify");
        assert!(!result.verified);
        assert!(result.failure.expect("failure").reason.contains("removed"));

        // 3. Tail truncated: removing the newest records rather than an interior one. A hash
        // chain alone cannot see this, which is why the autoincrement high-water mark is
        // checked as well.
        let truncated = root.join("truncated.db");
        std::fs::copy(&path, &truncated).expect("copy");
        let connection = Connection::open(&truncated).expect("open");
        connection
            .execute("DELETE FROM events WHERE sequence = 4", [])
            .expect("tamper");
        drop(connection);
        let result = LocalStore::open(&truncated)
            .expect("open")
            .verify_event_chain()
            .expect("verify");
        assert!(!result.verified, "a truncated log must not verify");
        assert!(result
            .failure
            .expect("failure")
            .reason
            .contains("removed from the end"));

        // 4. Every record removed, leaving a log that is empty rather than broken.
        let emptied = root.join("emptied.db");
        std::fs::copy(&path, &emptied).expect("copy");
        let connection = Connection::open(&emptied).expect("open");
        connection
            .execute("DELETE FROM events", [])
            .expect("tamper");
        drop(connection);
        let result = LocalStore::open(&emptied)
            .expect("open")
            .verify_event_chain()
            .expect("verify");
        assert!(!result.verified, "an emptied log must not verify");

        // 5. Link stripped: blanking the hash rather than editing the content.
        let stripped = root.join("stripped.db");
        std::fs::copy(&path, &stripped).expect("copy");
        let connection = Connection::open(&stripped).expect("open");
        connection
            .execute("UPDATE events SET chain_hash = NULL WHERE sequence = 4", [])
            .expect("tamper");
        drop(connection);
        let result = LocalStore::open(&stripped)
            .expect("open")
            .verify_event_chain()
            .expect("verify");
        assert!(!result.verified);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A link commits to the sequence number, so an event cannot be renumbered into a
    /// different position and still verify.
    #[test]
    fn an_event_cannot_be_reordered_without_breaking_its_own_link() {
        let (root, store) = store();
        let path = store.path().to_path_buf();
        let mut request = request();
        request.enforcement_posture = "semantic_enforced".to_string();
        let session = store.create_session(&request).expect("create session");
        for index in 0..3 {
            store
                .append_event(
                    &session.id,
                    "policy",
                    "fs.read",
                    Some("DENY"),
                    &format!("corr-{index}"),
                    &serde_json::json!({ "index": index }),
                )
                .expect("append");
        }
        drop(store);

        let connection = Connection::open(&path).expect("open");
        // Swap the payloads of two events, leaving every hash untouched.
        connection
            .execute_batch(
                "UPDATE events SET payload_json = (
                     SELECT payload_json FROM events WHERE sequence = 3
                 ) WHERE sequence = 2;",
            )
            .expect("tamper");
        drop(connection);
        let result = LocalStore::open(&path)
            .expect("open")
            .verify_event_chain()
            .expect("verify");
        assert!(!result.verified);
        let _ = std::fs::remove_dir_all(root);
    }

    /// An upgraded database gets a complete chain, not one that only starts at the upgrade.
    #[test]
    fn upgrading_backfills_a_chain_over_pre_existing_events() {
        let (root, store) = store();
        let path = store.path().to_path_buf();
        let mut request = request();
        request.enforcement_posture = "semantic_enforced".to_string();
        let session = store.create_session(&request).expect("create session");
        for index in 0..3 {
            store
                .append_event(
                    &session.id,
                    "session",
                    "start",
                    None,
                    &format!("corr-{index}"),
                    &serde_json::json!({ "index": index }),
                )
                .expect("append");
        }
        drop(store);

        // Roll back to schema 4 by removing what version 5 introduced, including the links.
        let connection = Connection::open(&path).expect("open sqlite");
        connection
            .execute_batch(
                "ALTER TABLE write_preimages DROP COLUMN postimage_state;
                 DROP TABLE clock_state;
                 DROP TABLE canaries;
                 DROP TABLE write_preimages;
                 DROP TABLE mcp_tools;
                 DROP TABLE mcp_servers;
                 DROP TABLE incident_responses;
                 DROP TABLE incidents;
                 DROP TABLE detections;
                 ALTER TABLE events DROP COLUMN chain_hash;
                 ALTER TABLE events DROP COLUMN previous_hash;
                 DROP TABLE IF EXISTS chain_checkpoints;
                 PRAGMA user_version = 4;",
            )
            .expect("downgrade fixture");
        drop(connection);

        let upgraded = LocalStore::open(&path).expect("upgrade");
        let verification = upgraded.verify_event_chain().expect("verify");
        assert!(verification.verified, "{verification:?}");
        assert_eq!(verification.events_checked, 3);
        // And the backfilled chain keeps working for events appended afterwards.
        upgraded
            .append_event(
                &session.id,
                "session",
                "end",
                None,
                "corr-end",
                &serde_json::json!({}),
            )
            .expect("append");
        assert!(upgraded.verify_event_chain().expect("verify").verified);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_database_does_not_chmod_an_existing_parent() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("vigil-store-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("set fixture permissions");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let mode = std::fs::metadata(&root)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}
