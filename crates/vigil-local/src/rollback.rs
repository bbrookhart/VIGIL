//! Undoing what the brokers did.
//!
//! Before a managed write or delete, the broker records what the file was: its content,
//! addressed by hash, or the fact that it did not exist. `vigil rollback` puts those back.
//!
//! # What this covers, and what it cannot
//!
//! This is **broker-mediated rollback**. It can undo a write that went through
//! [`crate::FilesystemBroker`], because that is the only point at which VIGIL held the prior
//! content in its hands. It cannot undo anything else: a process that wrote a file directly,
//! a subprocess that deleted a directory, a network side effect, or a database an agent
//! modified are all outside it. Endpoint Security does not change this — observing a write
//! tells you it happened, not what the bytes were beforehand.
//!
//! Rollback coverage is therefore exactly as wide as broker coverage, and no wider. A
//! `vigil rollback` that restores four files has restored the four VIGIL mediated, not "the
//! session's changes".
//!
//! # Restoring is itself a destructive operation
//!
//! Putting old content back over a file destroys whatever is there now. So every restore
//! first checks that the file still holds exactly what the broker left — the recorded
//! postimage. If it does not, something else has written it since, and restoring would
//! clobber a change VIGIL knows nothing about. That path refuses and reports rather than
//! proceeding.

use crate::{LocalStore, SessionStatus};
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vigil_common::{ContentHash, Result, VigilError};

/// Largest prior content VIGIL will keep in order to be able to restore it.
///
/// Above this a write still proceeds, but its preimage is recorded as unpreserved so the path
/// is explicitly non-restorable. Refusing the write instead would make VIGIL break legitimate
/// work on large files; silently omitting the record would make rollback quietly incomplete.
/// Saying "this one cannot be undone, and here is why" is the honest third option.
pub const MAX_PRESERVED_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorState {
    /// The file existed and its content is (or could be) preserved.
    Existing,
    /// The file did not exist. Restoring means removing what the broker created.
    Absent,
}

impl PriorState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Existing => "existing",
            Self::Absent => "absent",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "existing" => Ok(Self::Existing),
            "absent" => Ok(Self::Absent),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown prior state `{value}`"
            ))),
        }
    }
}

/// What a managed operation left behind.
///
/// A write leaves content; a delete leaves absence. Both must be expressible, because the
/// restore check asks "is this still what VIGIL left?" and for a deletion the honest answer is
/// "still gone".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostimageState {
    Present,
    Absent,
}

impl PostimageState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "present" => Ok(Self::Present),
            "absent" => Ok(Self::Absent),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown postimage state `{value}`"
            ))),
        }
    }
}

/// What a managed operation is about to leave behind, as the broker knows it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Postimage<'a> {
    Content(&'a [u8]),
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritePreimage {
    pub preimage_id: String,
    pub session_id: String,
    pub at: DateTime<Utc>,
    pub resource: String,
    pub prior_state: PriorState,
    pub blob_sha256: Option<String>,
    pub blob_bytes: Option<u64>,
    /// False when the prior content was too large to keep. The write happened; it cannot be
    /// undone, and that is recorded rather than left to be discovered later.
    pub preserved: bool,
    pub unpreserved_reason: Option<String>,
    /// What the broker left behind. A restore refuses unless the file still matches this.
    pub postimage_sha256: String,
    pub postimage_bytes: u64,
    /// Whether the operation left content or absence.
    #[serde(default = "present")]
    pub postimage_state: PostimageState,
    pub event_id: Option<String>,
    pub restored_at: Option<DateTime<Utc>>,
}

impl WritePreimage {
    /// Whether this change can be undone at all, ignoring the current state of the file.
    pub fn restorable(&self) -> bool {
        self.restored_at.is_none() && (self.prior_state == PriorState::Absent || self.preserved)
    }
}

/// What happened to one preimage during a rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RestoreOutcome {
    /// Prior content written back.
    Restored { resource: String },
    /// A file the broker created was removed, because it did not exist before.
    Removed { resource: String },
    /// Would have been restored; `--dry-run` was in effect.
    WouldRestore { resource: String },
    /// Refused, with the reason. Never a silent skip.
    Refused { resource: String, reason: String },
}

impl RestoreOutcome {
    pub fn resource(&self) -> &str {
        match self {
            Self::Restored { resource }
            | Self::Removed { resource }
            | Self::WouldRestore { resource }
            | Self::Refused { resource, .. } => resource,
        }
    }

    pub fn refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    pub session_id: String,
    pub dry_run: bool,
    pub considered: usize,
    pub restored: usize,
    pub removed: usize,
    pub refused: usize,
    pub outcomes: Vec<RestoreOutcome>,
    /// Stated on every report so a caller cannot read a clean rollback as "the session's
    /// effects are undone".
    pub coverage_note: String,
}

fn present() -> PostimageState {
    PostimageState::Present
}

const COVERAGE_NOTE: &str = "Broker-mediated writes and deletes only. Anything a process \
                             changed without going through VIGIL is not covered and was not \
                             restored.";

impl LocalStore {
    /// Directory holding content-addressed preimage blobs.
    fn preimage_root(&self) -> Result<PathBuf> {
        let parent = self
            .path()
            .parent()
            .ok_or_else(|| VigilError::Config("state database has no parent directory".into()))?;
        Ok(parent.join("preimages"))
    }

    /// Capture what a file is before a brokered write replaces it.
    ///
    /// Called by the filesystem broker while it still has the prior bytes. Content is stored
    /// once per distinct hash, so repeatedly rewriting the same file costs one blob per
    /// distinct prior state rather than one per write.
    pub(crate) fn capture_preimage(
        &self,
        session_id: &str,
        resource: &Path,
        postimage: Postimage<'_>,
        event_id: Option<&str>,
    ) -> Result<WritePreimage> {
        let now = Utc::now();
        let existing = std::fs::metadata(resource).ok();
        let (prior_state, blob, preserved, unpreserved_reason) = match existing {
            None => (PriorState::Absent, None, true, None),
            Some(metadata) if metadata.len() > MAX_PRESERVED_BYTES => (
                PriorState::Existing,
                None,
                false,
                Some(format!(
                    "prior content is {} bytes, above the {MAX_PRESERVED_BYTES}-byte \
                     preservation limit",
                    metadata.len()
                )),
            ),
            Some(_) => {
                let content = std::fs::read(resource)?;
                let digest = ContentHash::sha256(&content).to_string();
                self.store_blob(&digest, &content)?;
                let bytes = u64::try_from(content.len()).unwrap_or(u64::MAX);
                (PriorState::Existing, Some((digest, bytes)), true, None)
            }
        };

        let preimage = WritePreimage {
            preimage_id: format!("pre_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.to_string(),
            at: now,
            resource: resource.display().to_string(),
            prior_state,
            blob_sha256: blob.as_ref().map(|(digest, _)| digest.clone()),
            blob_bytes: blob.as_ref().map(|(_, bytes)| *bytes),
            preserved,
            unpreserved_reason,
            postimage_sha256: match postimage {
                Postimage::Content(bytes) => ContentHash::sha256(bytes).to_string(),
                // A stable, explicit marker rather than the hash of nothing, so an absent
                // postimage cannot be confused with an empty file.
                Postimage::Absent => ContentHash::sha256(b"vigil.postimage.absent").to_string(),
            },
            postimage_bytes: match postimage {
                Postimage::Content(bytes) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                Postimage::Absent => 0,
            },
            postimage_state: match postimage {
                Postimage::Content(_) => PostimageState::Present,
                Postimage::Absent => PostimageState::Absent,
            },
            event_id: event_id.map(str::to_string),
            restored_at: None,
        };
        self.connection
            .execute(
                "INSERT INTO write_preimages
                 (preimage_id, session_id, at, resource, prior_state, blob_sha256, blob_bytes,
                  preserved, unpreserved_reason, postimage_sha256, postimage_bytes, event_id,
                  postimage_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    preimage.preimage_id,
                    preimage.session_id,
                    preimage.at.to_rfc3339(),
                    preimage.resource,
                    preimage.prior_state.as_str(),
                    preimage.blob_sha256,
                    preimage.blob_bytes,
                    i64::from(preimage.preserved),
                    preimage.unpreserved_reason,
                    preimage.postimage_sha256,
                    preimage.postimage_bytes,
                    preimage.event_id,
                    preimage.postimage_state.as_str(),
                ],
            )
            .map_err(super::store::storage_error)?;
        Ok(preimage)
    }

    /// Write one blob into the content-addressed store, if it is not already there.
    fn store_blob(&self, digest: &str, content: &[u8]) -> Result<()> {
        let path = self.blob_path(digest)?;
        if path.exists() {
            // Content-addressed: the same hash is the same bytes. Nothing to do.
            return Ok(());
        }
        let parent = path
            .parent()
            .ok_or_else(|| VigilError::Config("blob path has no parent".into()))?;
        std::fs::create_dir_all(parent)?;
        set_owner_only_dir(parent)?;

        // Same discipline as the broker's own writes: a uniquely named temporary in the same
        // directory, fsynced, then atomically renamed into place.
        let temporary = parent.join(format!(".{digest}.{}.tmp", uuid::Uuid::new_v4().simple()));
        write_owner_only(&temporary, content)?;
        std::fs::rename(&temporary, &path).inspect_err(|_| {
            let _ = std::fs::remove_file(&temporary);
        })?;
        Ok(())
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VigilError::AuditIntegrity(
                "preimage digest is not a SHA-256 hex string".to_string(),
            ));
        }
        // Split by prefix so one directory does not accumulate every blob ever stored.
        Ok(self.preimage_root()?.join(&hex[..2]).join(hex))
    }

    /// Every preimage recorded for a session, newest first.
    pub fn preimages_for_session(&self, session_id: &str) -> Result<Vec<WritePreimage>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT preimage_id, session_id, at, resource, prior_state, blob_sha256,
                        blob_bytes, preserved, unpreserved_reason, postimage_sha256,
                        postimage_bytes, event_id, restored_at, postimage_state
                 FROM write_preimages WHERE session_id = ?1 ORDER BY at DESC, preimage_id DESC",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([session_id], preimage_from_row)
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }

    /// Restore a session's brokered writes, newest first.
    ///
    /// Newest first because a file written three times must end up in the state before the
    /// *first* write, and walking backwards through each recorded step gets there while
    /// checking at every stage that the file is still what VIGIL left.
    pub fn rollback_session(
        &self,
        session_id: &str,
        only_resource: Option<&str>,
        dry_run: bool,
    ) -> Result<RollbackReport> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        // A running session could write again the moment a file is restored, which would make
        // the result meaningless and the race invisible.
        if session.status == SessionStatus::Running {
            return Err(VigilError::InvalidRequest(format!(
                "session {session_id} is still running; end or contain it before rolling back, \
                 otherwise it can overwrite what was just restored"
            )));
        }

        let preimages = self.preimages_for_session(session_id)?;
        let mut outcomes = Vec::new();
        let mut restored = 0usize;
        let mut removed = 0usize;
        let mut refused = 0usize;
        let mut considered = 0usize;

        for preimage in preimages {
            if only_resource.is_some_and(|wanted| wanted != preimage.resource) {
                continue;
            }
            considered += 1;
            let resource = preimage.resource.clone();

            if preimage.restored_at.is_some() {
                refused += 1;
                outcomes.push(RestoreOutcome::Refused {
                    resource,
                    reason: "already restored".to_string(),
                });
                continue;
            }
            if !preimage.preserved {
                refused += 1;
                outcomes.push(RestoreOutcome::Refused {
                    resource,
                    reason: preimage
                        .unpreserved_reason
                        .clone()
                        .unwrap_or_else(|| "prior content was not preserved".to_string()),
                });
                continue;
            }

            if let Err(reason) = self.verify_current_matches_postimage(&preimage) {
                refused += 1;
                outcomes.push(RestoreOutcome::Refused { resource, reason });
                continue;
            }

            if dry_run {
                outcomes.push(RestoreOutcome::WouldRestore { resource });
                continue;
            }

            match preimage.prior_state {
                PriorState::Absent => {
                    std::fs::remove_file(&preimage.resource)?;
                    self.mark_restored(&preimage.preimage_id)?;
                    removed += 1;
                    outcomes.push(RestoreOutcome::Removed { resource });
                }
                PriorState::Existing => {
                    let Some(digest) = &preimage.blob_sha256 else {
                        refused += 1;
                        outcomes.push(RestoreOutcome::Refused {
                            resource,
                            reason: "no preserved content is recorded".to_string(),
                        });
                        continue;
                    };
                    let content = std::fs::read(self.blob_path(digest)?)?;
                    // The stored blob is verified before it is written back: a corrupted blob
                    // store must not become a way to put arbitrary content on disk.
                    if ContentHash::sha256(&content).to_string() != *digest {
                        refused += 1;
                        outcomes.push(RestoreOutcome::Refused {
                            resource,
                            reason: "stored preimage does not match its own digest".to_string(),
                        });
                        continue;
                    }
                    atomic_restore(Path::new(&preimage.resource), &content)?;
                    self.mark_restored(&preimage.preimage_id)?;
                    restored += 1;
                    outcomes.push(RestoreOutcome::Restored { resource });
                }
            }
        }

        let report = RollbackReport {
            session_id: session_id.to_string(),
            dry_run,
            considered,
            restored,
            removed,
            refused,
            outcomes,
            coverage_note: COVERAGE_NOTE.to_string(),
        };
        if !dry_run {
            self.append_event(
                session_id,
                "rollback",
                "rollback.performed",
                Some(if report.refused == 0 {
                    "COMPLETE"
                } else {
                    "PARTIAL"
                }),
                &format!("cor_{}", uuid::Uuid::new_v4().simple()),
                &serde_json::json!({
                    "considered": report.considered,
                    "restored": report.restored,
                    "removed": report.removed,
                    "refused": report.refused,
                    "broker_mediated_only": true,
                }),
            )?;
        }
        Ok(report)
    }

    /// Confirm the file on disk is still exactly what the broker left behind.
    fn verify_current_matches_postimage(
        &self,
        preimage: &WritePreimage,
    ) -> std::result::Result<(), String> {
        if preimage.postimage_state == PostimageState::Absent {
            // The operation left the path gone. It must still be gone: something recreating it
            // means restoring would clobber content VIGIL never saw.
            return match std::fs::symlink_metadata(&preimage.resource) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Ok(_) => Err(
                    "the path exists again; something recreated it after VIGIL removed it"
                        .to_string(),
                ),
                Err(error) => Err(format!("the path cannot be examined: {}", error.kind())),
            };
        }
        match std::fs::read(&preimage.resource) {
            Ok(current) => {
                if ContentHash::sha256(&current).to_string() == preimage.postimage_sha256 {
                    Ok(())
                } else {
                    Err(
                        "the file has changed since VIGIL wrote it; restoring would discard a \
                         change VIGIL did not make"
                            .to_string(),
                    )
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
                "the file no longer exists; something removed it after VIGIL wrote it".to_string(),
            ),
            Err(error) => Err(format!("the file cannot be read: {}", error.kind())),
        }
    }

    fn mark_restored(&self, preimage_id: &str) -> Result<()> {
        self.connection
            .execute(
                "UPDATE write_preimages SET restored_at = ?1 WHERE preimage_id = ?2",
                params![Utc::now().to_rfc3339(), preimage_id],
            )
            .map_err(super::store::storage_error)?;
        Ok(())
    }
}

/// Write content back atomically, with the same discipline the broker uses.
fn atomic_restore(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| VigilError::Config("resource has no parent directory".into()))?;
    let previous = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let temporary = parent.join(format!(
        ".vigil-restore-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    write_owner_only(&temporary, content)?;
    if let Some(previous) = previous {
        let _ = std::fs::set_permissions(&temporary, previous);
    }
    std::fs::rename(&temporary, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })?;
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn write_owner_only(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn preimage_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<WritePreimage>> {
    let preimage_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let at: String = row.get(2)?;
    let resource: String = row.get(3)?;
    let prior_state: String = row.get(4)?;
    let blob_sha256: Option<String> = row.get(5)?;
    let blob_bytes: Option<i64> = row.get(6)?;
    let preserved: i64 = row.get(7)?;
    let unpreserved_reason: Option<String> = row.get(8)?;
    let postimage_sha256: String = row.get(9)?;
    let postimage_bytes: i64 = row.get(10)?;
    let event_id: Option<String> = row.get(11)?;
    let restored_at: Option<String> = row.get(12)?;
    let postimage_state: String = row.get(13)?;

    Ok((|| {
        Ok(WritePreimage {
            preimage_id,
            session_id,
            at: parse_time(&at)?,
            resource,
            prior_state: PriorState::parse(&prior_state)?,
            blob_sha256,
            blob_bytes: blob_bytes.map(|value| u64::try_from(value).unwrap_or(0)),
            preserved: preserved != 0,
            unpreserved_reason,
            postimage_sha256,
            postimage_bytes: u64::try_from(postimage_bytes).unwrap_or(0),
            event_id,
            restored_at: restored_at.as_deref().map(parse_time).transpose()?,
            postimage_state: PostimageState::parse(&postimage_state)?,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            VigilError::Serialization(format!("unparsable preimage timestamp: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FilesystemBroker, NewSession};

    fn session(root: &Path) -> (LocalStore, String, PathBuf) {
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical workspace");
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let created = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace: workspace.clone(),
                executable: "vigil-test".to_string(),
                argv: vec!["vigil-test".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&created.id, std::process::id())
            .expect("activate");
        (store, created.id, workspace)
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("vigil-rollback-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn a_modified_file_is_restored_and_a_created_file_is_removed() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("config.toml"), b"ORIGINAL").expect("seed");

        let broker = FilesystemBroker::new(&store);
        broker.write(&id, "config.toml", b"CHANGED").expect("write");
        broker.write(&id, "created.txt", b"NEW").expect("create");
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.refused, 0);
        assert_eq!(
            std::fs::read(workspace.join("config.toml")).expect("read"),
            b"ORIGINAL"
        );
        assert!(!workspace.join("created.txt").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    /// The property that keeps rollback from being a destructive operation of its own: if
    /// anything changed the file after VIGIL wrote it, restoring would discard that change.
    #[test]
    fn a_file_changed_after_the_write_is_refused_rather_than_clobbered() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("notes.md"), b"ORIGINAL").expect("seed");
        FilesystemBroker::new(&store)
            .write(&id, "notes.md", b"AGENT")
            .expect("write");
        // Something outside VIGIL edits it: a human, an editor, another tool.
        std::fs::write(workspace.join("notes.md"), b"SOMEONE ELSE").expect("external edit");
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 0);
        assert_eq!(report.refused, 1);
        assert!(report.outcomes[0].refused());
        // The external change survives untouched.
        assert_eq!(
            std::fs::read(workspace.join("notes.md")).expect("read"),
            b"SOMEONE ELSE"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_dry_run_changes_nothing_and_rollback_is_not_repeatable() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("a.txt"), b"ORIGINAL").expect("seed");
        FilesystemBroker::new(&store)
            .write(&id, "a.txt", b"CHANGED")
            .expect("write");
        store.finish_session(&id, Some(0)).expect("end session");

        let dry = store.rollback_session(&id, None, true).expect("dry run");
        assert_eq!(dry.restored, 0);
        assert!(matches!(
            dry.outcomes[0],
            RestoreOutcome::WouldRestore { .. }
        ));
        assert_eq!(
            std::fs::read(workspace.join("a.txt")).expect("read"),
            b"CHANGED",
            "a dry run must not touch the file"
        );

        assert_eq!(
            store
                .rollback_session(&id, None, false)
                .expect("real")
                .restored,
            1
        );
        // Restoring twice would put the preimage back over content that is now the preimage.
        // The second attempt is refused as already restored, not silently repeated.
        let again = store.rollback_session(&id, None, false).expect("again");
        assert_eq!(again.restored, 0);
        assert_eq!(again.refused, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A file written three times must end up in the state before the *first* write.
    #[test]
    fn repeated_writes_unwind_to_the_state_before_the_first_one() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("x.txt"), b"V0").expect("seed");
        let broker = FilesystemBroker::new(&store);
        for content in [b"V1".as_slice(), b"V2", b"V3"] {
            broker.write(&id, "x.txt", content).expect("write");
        }
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 3);
        assert_eq!(report.refused, 0);
        assert_eq!(std::fs::read(workspace.join("x.txt")).expect("read"), b"V0");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Rolling back underneath a live session would race whatever it does next.
    #[test]
    fn a_running_session_cannot_be_rolled_back() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("a.txt"), b"ORIGINAL").expect("seed");
        FilesystemBroker::new(&store)
            .write(&id, "a.txt", b"CHANGED")
            .expect("write");
        let error = store
            .rollback_session(&id, None, false)
            .expect_err("a running session must not be rolled back");
        assert!(matches!(error, VigilError::InvalidRequest(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    /// Identical prior content is stored once, whatever the path or the number of writes.
    #[test]
    fn preimage_blobs_are_content_addressed_and_deduplicated() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(workspace.join(name), b"IDENTICAL").expect("seed");
        }
        let broker = FilesystemBroker::new(&store);
        for name in ["a.txt", "b.txt", "c.txt"] {
            broker.write(&id, name, b"CHANGED").expect("write");
        }
        let digests: std::collections::BTreeSet<_> = store
            .preimages_for_session(&id)
            .expect("preimages")
            .into_iter()
            .filter_map(|preimage| preimage.blob_sha256)
            .collect();
        assert_eq!(digests.len(), 1, "identical content must share one blob");

        let mut blobs = 0;
        let mut stack = vec![store.preimage_root().expect("root")];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).expect("read dir") {
                let entry = entry.expect("entry");
                if entry.file_type().expect("file type").is_dir() {
                    stack.push(entry.path());
                } else {
                    blobs += 1;
                }
            }
        }
        assert_eq!(
            blobs, 1,
            "three writes of identical content stored {blobs} blobs"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_corrupt_blob_is_refused_rather_than_written_back() {
        let root = temp_root();
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("a.txt"), b"ORIGINAL").expect("seed");
        FilesystemBroker::new(&store)
            .write(&id, "a.txt", b"CHANGED")
            .expect("write");
        store.finish_session(&id, Some(0)).expect("end session");

        // Corrupt the stored preimage, as a tampered or damaged blob store would be.
        let digest = store.preimages_for_session(&id).expect("preimages")[0]
            .blob_sha256
            .clone()
            .expect("digest");
        let blob = store.blob_path(&digest).expect("blob path");
        std::fs::write(&blob, b"ATTACKER CONTENT").expect("corrupt");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 0);
        assert_eq!(report.refused, 1);
        // The corrupt bytes never reached the workspace.
        assert_eq!(
            std::fs::read(workspace.join("a.txt")).expect("read"),
            b"CHANGED"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod deletion_tests {
    use super::*;
    use crate::{FilesystemBroker, NewSession};

    fn session(root: &Path) -> (LocalStore, String, PathBuf) {
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical");
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let created = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace: workspace.clone(),
                executable: "vigil-test".to_string(),
                argv: vec!["vigil-test".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&created.id, std::process::id())
            .expect("activate");
        (store, created.id, workspace)
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vigil-delete-{label}-{}", uuid::Uuid::new_v4()))
    }

    /// Deletion is the operation rollback most needs, and the one where the content is gone by
    /// the time anyone notices. The preimage has to be taken before the file is.
    #[test]
    fn a_deleted_file_is_restored_with_its_content() {
        let root = temp_root("restore");
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("data.txt"), b"IMPORTANT").expect("seed");

        FilesystemBroker::new(&store)
            .delete(&id, "data.txt")
            .expect("delete");
        assert!(!workspace.join("data.txt").exists());
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 1);
        assert_eq!(report.refused, 0);
        assert_eq!(
            std::fs::read(workspace.join("data.txt")).expect("read"),
            b"IMPORTANT"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// If something recreated the path, restoring would clobber content VIGIL never saw. The
    /// "is this still what VIGIL left?" check has to mean "still gone" for a deletion.
    #[test]
    fn a_recreated_path_is_refused_rather_than_overwritten() {
        let root = temp_root("recreated");
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("data.txt"), b"ORIGINAL").expect("seed");
        FilesystemBroker::new(&store)
            .delete(&id, "data.txt")
            .expect("delete");
        std::fs::write(workspace.join("data.txt"), b"SOMEONE ELSE").expect("recreate");
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 0);
        assert_eq!(report.refused, 1);
        assert_eq!(
            std::fs::read(workspace.join("data.txt")).expect("read"),
            b"SOMEONE ELSE",
            "rollback overwrote content it never saw"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// One delete must not be able to remove a tree the `file_deletes` budget never accounted
    /// for.
    #[test]
    fn a_directory_is_refused() {
        let root = temp_root("dir");
        let (store, id, workspace) = session(&root);
        std::fs::create_dir_all(workspace.join("subdir")).expect("create");
        std::fs::write(workspace.join("subdir/inner.txt"), b"x").expect("seed");

        let error = FilesystemBroker::new(&store)
            .delete(&id, "subdir")
            .expect_err("a directory must be refused");
        assert!(matches!(error, VigilError::InvalidValue { .. }));
        assert!(workspace.join("subdir/inner.txt").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    /// The delete budget was defined and dimensioned long before anything could spend it.
    #[test]
    fn deletes_consume_the_delete_budget_and_stop_at_the_limit() {
        let root = temp_root("budget");
        let (store, id, workspace) = session(&root);
        let broker = FilesystemBroker::new(&store);

        // developer-standard permits five deletes.
        for index in 0..6 {
            let name = format!("f{index}.txt");
            std::fs::write(workspace.join(&name), b"x").expect("seed");
            let outcome = broker.delete(&id, &name);
            if index < 5 {
                outcome.expect("within budget");
            } else {
                assert!(
                    matches!(outcome, Err(VigilError::BudgetExhausted(_))),
                    "the sixth delete was not refused"
                );
            }
        }
        let consumed = store
            .budget_snapshot(&id)
            .expect("budget")
            .into_iter()
            .find(|counter| counter.dimension == crate::BudgetDimension::FileDeletes)
            .expect("counter");
        assert_eq!(consumed.consumed, 5);
        assert_eq!(consumed.remaining, 0);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod rename_tests {
    use super::*;
    use crate::{FilesystemBroker, NewSession};

    fn session(root: &Path) -> (LocalStore, String, PathBuf) {
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical");
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let created = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace: workspace.clone(),
                executable: "vigil-test".to_string(),
                argv: vec!["vigil-test".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&created.id, std::process::id())
            .expect("activate");
        (store, created.id, workspace)
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vigil-rename-{label}-{}", uuid::Uuid::new_v4()))
    }

    /// The destructive half of a rename is the destination it overwrites. Recording the
    /// operation as "the file moved" would leave that content unrecoverable.
    #[test]
    fn a_rename_that_overwrites_restores_both_files() {
        let root = temp_root("overwrite");
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("a.txt"), b"SOURCE").expect("seed");
        std::fs::write(workspace.join("b.txt"), b"DESTINATION").expect("seed");

        FilesystemBroker::new(&store)
            .rename(&id, "a.txt", "b.txt")
            .expect("rename");
        assert!(!workspace.join("a.txt").exists());
        assert_eq!(
            std::fs::read(workspace.join("b.txt")).expect("read"),
            b"SOURCE"
        );
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.restored, 2, "{report:?}");
        assert_eq!(report.refused, 0);
        assert_eq!(
            std::fs::read(workspace.join("a.txt")).expect("read"),
            b"SOURCE"
        );
        assert_eq!(
            std::fs::read(workspace.join("b.txt")).expect("read"),
            b"DESTINATION",
            "the overwritten destination was not recovered"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Renaming onto a path that did not exist must undo by removing it again, not by
    /// leaving an empty file behind.
    #[test]
    fn a_rename_to_a_new_path_undoes_by_removing_it() {
        let root = temp_root("new");
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("a.txt"), b"SOURCE").expect("seed");

        FilesystemBroker::new(&store)
            .rename(&id, "a.txt", "moved.txt")
            .expect("rename");
        store.finish_session(&id, Some(0)).expect("end session");

        let report = store.rollback_session(&id, None, false).expect("rollback");
        assert_eq!(report.refused, 0, "{report:?}");
        assert_eq!(
            std::fs::read(workspace.join("a.txt")).expect("read"),
            b"SOURCE"
        );
        assert!(
            !workspace.join("moved.txt").exists(),
            "the created path was left behind"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Both endpoints are authorized. One refusal refuses the rename, and nothing moves.
    #[test]
    fn a_refused_endpoint_refuses_the_whole_rename() {
        let root = temp_root("refuse");
        let (store, id, workspace) = session(&root);
        std::fs::write(workspace.join("a.txt"), b"SOURCE").expect("seed");
        let outside = root.join("escaped.txt").display().to_string();

        let error = FilesystemBroker::new(&store)
            .rename(&id, "a.txt", &outside)
            .expect_err("a destination outside the workspace must be refused");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        assert!(
            workspace.join("a.txt").exists(),
            "the source was moved anyway"
        );
        assert!(!Path::new(&outside).exists());

        // And no budget was spent on the refused operation.
        let counter = store
            .budget_snapshot(&id)
            .expect("budget")
            .into_iter()
            .find(|counter| counter.dimension == crate::BudgetDimension::FileRenames)
            .expect("counter");
        assert_eq!(counter.consumed, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_directory_rename_is_refused() {
        let root = temp_root("dir");
        let (store, id, workspace) = session(&root);
        std::fs::create_dir_all(workspace.join("subdir")).expect("create");
        let error = FilesystemBroker::new(&store)
            .rename(&id, "subdir", "moved")
            .expect_err("a directory must be refused");
        assert!(matches!(error, VigilError::InvalidValue { .. }));
        assert!(workspace.join("subdir").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Enumeration is mediated even though it changes nothing: walking toward a protected
    /// location is a signal, and without a broker path VIGIL sees none of it.
    #[test]
    fn listing_is_brokered_and_bounded() {
        let root = temp_root("list");
        let (store, id, workspace) = session(&root);
        for index in 0..5 {
            std::fs::write(workspace.join(format!("f{index}.txt")), b"x").expect("seed");
        }
        let listed = FilesystemBroker::new(&store).list(&id, ".").expect("list");
        assert_eq!(listed.value.len(), 5);
        // Sorted, so evidence and output are stable across runs.
        let mut sorted = listed.value.clone();
        sorted.sort();
        assert_eq!(listed.value, sorted);

        // A protected directory is refused like any other protected resource.
        let home = std::env::var("HOME").expect("HOME");
        assert!(FilesystemBroker::new(&store)
            .list(&id, &format!("{home}/.ssh"))
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
