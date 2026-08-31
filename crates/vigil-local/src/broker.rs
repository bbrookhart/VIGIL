//! Filesystem semantic enforcement point.
//!
//! The broker evaluates the normalized action, reserves blast-radius budget, performs the
//! operation against the resolved workspace path, reconciles the reservation, and appends a
//! content-free event. It does not claim to stop a process that bypasses the broker; the
//! future Endpoint Security adapter is the second enforcement point for that behavior.

use crate::{
    budget_limit, BudgetCharge, BudgetDimension, DecisionOutcome, LocalAction, LocalAuthorization,
    LocalProfile, LocalSession, LocalStore, SessionStatus,
};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use vigil_common::{Result, VigilError};

const MAX_BROKER_READ_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct BrokerResult<T> {
    pub value: T,
    pub event_id: String,
    pub reservation_id: String,
    pub correlation_id: String,
    pub resolved_resource: PathBuf,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct FilesystemBroker<'a> {
    store: &'a LocalStore,
}

impl<'a> FilesystemBroker<'a> {
    pub fn new(store: &'a LocalStore) -> Self {
        Self { store }
    }

    pub fn read(&self, session_id: &str, requested_path: &str) -> Result<BrokerResult<Vec<u8>>> {
        let correlation_id = new_correlation_id();
        let (session, profile, workspace) = self.session_context(session_id)?;
        let authorization = self.store.authorize_local(
            session_id,
            profile,
            &workspace,
            LocalAction::FsRead,
            requested_path,
        )?;
        let resolved = self.require_permit(&session, &correlation_id, &authorization)?;
        let decision = authorization.decision;
        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[BudgetCharge::new(BudgetDimension::FileReads, 1)],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.record_budget_denial(
                    session_id,
                    &correlation_id,
                    LocalAction::FsRead,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        let operation = read_bounded(&resolved);
        let bytes = match operation {
            Ok(value) => value,
            Err(error) => {
                self.refund_and_record_failure(
                    session_id,
                    &correlation_id,
                    &reservation.id,
                    LocalAction::FsRead,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };
        if let Err(error) = self.store.commit_budget(&reservation.id) {
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
        let event = self.store.append_event(
            session_id,
            "filesystem",
            LocalAction::FsRead.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "resolved_resource": resolved,
                "bytes": bytes.len(),
                "reservation_id": reservation.id,
                "determining_policy": decision.determining_policy,
                "content_captured": false,
            }),
        )?;
        Ok(BrokerResult {
            value: bytes,
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            resolved_resource: resolved,
            bytes: event
                .payload
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        })
    }

    pub fn write(
        &self,
        session_id: &str,
        requested_path: &str,
        content: &[u8],
    ) -> Result<BrokerResult<()>> {
        let correlation_id = new_correlation_id();
        let (session, profile, workspace) = self.session_context(session_id)?;
        let initial_path = workspace.join(requested_path);
        let action = if initial_path.exists() {
            LocalAction::FsWrite
        } else {
            LocalAction::FsCreate
        };
        let authorization =
            self.store
                .authorize_local(session_id, profile, &workspace, action, requested_path)?;
        let resolved = self.require_permit(&session, &correlation_id, &authorization)?;
        let decision = authorization.decision;
        let bytes = u64::try_from(content.len()).map_err(|_| {
            VigilError::BudgetExhausted("write size exceeds the platform range".to_string())
        })?;
        let maximum = budget_limit(profile, BudgetDimension::MaxSingleWriteBytes);
        if bytes > maximum {
            let error = VigilError::BudgetExhausted(format!(
                "max_single_write_bytes exhausted: limit={maximum}, requested={bytes}"
            ));
            self.record_budget_denial(
                session_id,
                &correlation_id,
                action,
                &decision.determining_policy,
                &error,
            )?;
            return Err(error);
        }
        let operation_dimension = if action == LocalAction::FsCreate {
            BudgetDimension::FileCreates
        } else {
            BudgetDimension::FileWrites
        };
        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[
                BudgetCharge::new(operation_dimension, 1),
                BudgetCharge::new(BudgetDimension::TotalWriteBytes, bytes),
            ],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.record_budget_denial(
                    session_id,
                    &correlation_id,
                    action,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        // Capture the prior content while it is still on disk. A failure here fails the
        // write: performing an irreversible change because the reversibility record could not
        // be written is precisely the wrong order of priorities.
        let preimage = match self.store.capture_preimage(
            session_id,
            &resolved,
            crate::rollback::Postimage::Content(content),
            None,
        ) {
            Ok(preimage) => preimage,
            Err(error) => {
                self.refund_and_record_failure(
                    session_id,
                    &correlation_id,
                    &reservation.id,
                    action,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        if let Err(error) = atomic_write(&resolved, content) {
            self.refund_and_record_failure(
                session_id,
                &correlation_id,
                &reservation.id,
                action,
                &decision.determining_policy,
                &error,
            )?;
            return Err(error);
        }
        if let Err(error) = self.store.commit_budget(&reservation.id) {
            // The side effect happened. Never report it as a clean denial or refund the
            // reservation; leaving it reserved bounds further damage.
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
        let event = self.store.append_event(
            session_id,
            "filesystem",
            action.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "resolved_resource": resolved,
                "bytes": bytes,
                "reservation_id": reservation.id,
                "determining_policy": decision.determining_policy,
                "content_captured": false,
                "atomic_replace": true,
                "preimage_id": preimage.preimage_id,
                "reversible": preimage.restorable(),
            }),
        )?;
        Ok(BrokerResult {
            value: (),
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            resolved_resource: resolved,
            bytes,
        })
    }

    /// Remove a workspace file through policy, budget, and a restorable preimage.
    ///
    /// Deletion is the most destructive filesystem operation VIGIL mediates and the one
    /// rollback most needs, so the preimage is captured before the file is gone — after that
    /// there is nothing left to capture. A capture failure fails the delete: removing content
    /// because the record of how to restore it could not be written is the wrong order.
    ///
    /// Directories are refused. Removing a tree is a different blast radius and a different
    /// restore problem, and quietly accepting one here would let a single call do far more
    /// than the `file_deletes` budget accounts for.
    pub fn delete(&self, session_id: &str, requested_path: &str) -> Result<BrokerResult<()>> {
        let correlation_id = new_correlation_id();
        let (session, profile, workspace) = self.session_context(session_id)?;
        let authorization = self.store.authorize_local(
            session_id,
            profile,
            &workspace,
            LocalAction::FsDelete,
            requested_path,
        )?;
        let resolved = self.require_permit(&session, &correlation_id, &authorization)?;
        let decision = authorization.decision;

        let metadata = std::fs::symlink_metadata(&resolved)?;
        if metadata.is_dir() {
            return Err(VigilError::InvalidValue {
                field: "resource",
                reason: "the filesystem broker deletes regular files only; a directory tree is \
                         a different blast radius and is not accounted for by one delete"
                    .to_string(),
            });
        }

        let preimage = match self.store.capture_preimage(
            session_id,
            &resolved,
            crate::rollback::Postimage::Absent,
            None,
        ) {
            Ok(preimage) => preimage,
            Err(error) => {
                self.record_budget_denial(
                    session_id,
                    &correlation_id,
                    LocalAction::FsDelete,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[BudgetCharge::new(BudgetDimension::FileDeletes, 1)],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.record_budget_denial(
                    session_id,
                    &correlation_id,
                    LocalAction::FsDelete,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        if let Err(error) = std::fs::remove_file(&resolved) {
            let error = VigilError::from(error);
            self.refund_and_record_failure(
                session_id,
                &correlation_id,
                &reservation.id,
                LocalAction::FsDelete,
                &decision.determining_policy,
                &error,
            )?;
            return Err(error);
        }
        if let Err(error) = self.store.commit_budget(&reservation.id) {
            // The file is gone. Never refund; leaving the reservation held bounds further
            // damage, as it does on the write path.
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

        let event = self.store.append_event(
            session_id,
            "filesystem",
            LocalAction::FsDelete.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "resolved_resource": resolved,
                "bytes": metadata.len(),
                "reservation_id": reservation.id,
                "determining_policy": decision.determining_policy,
                "content_captured": false,
                "preimage_id": preimage.preimage_id,
                "reversible": preimage.restorable(),
            }),
        )?;
        Ok(BrokerResult {
            value: (),
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            resolved_resource: resolved,
            bytes: metadata.len(),
        })
    }

    /// Move a workspace file, capturing enough to undo it.
    ///
    /// A rename is two effects wearing one name: the destination loses whatever it held, and
    /// the source ceases to exist. Recording it as a single "the file moved" would leave
    /// rollback unable to restore an overwritten destination, which is the destructive half.
    ///
    /// So it decomposes into the two preimages it actually is — the destination gains the
    /// source's content, and the source becomes absent — and rollback, which walks newest
    /// first, puts both back in the right order.
    ///
    /// Both paths are authorized independently. One refusal refuses the rename, for the same
    /// reason it refuses an MCP call: performing half of a refused operation lets the caller
    /// choose which half runs.
    pub fn rename(
        &self,
        session_id: &str,
        requested_from: &str,
        requested_to: &str,
    ) -> Result<BrokerResult<()>> {
        let correlation_id = new_correlation_id();
        let (session, profile, workspace) = self.session_context(session_id)?;

        let source = self.store.authorize_local(
            session_id,
            profile,
            &workspace,
            LocalAction::FsRename,
            requested_from,
        )?;
        let from = self.require_permit(&session, &correlation_id, &source)?;
        let target = self.store.authorize_local(
            session_id,
            profile,
            &workspace,
            LocalAction::FsRename,
            requested_to,
        )?;
        let to = self.require_permit(&session, &correlation_id, &target)?;
        let decision = source.decision;

        let metadata = std::fs::symlink_metadata(&from)?;
        if metadata.is_dir() {
            return Err(VigilError::InvalidValue {
                field: "resource",
                reason: "the filesystem broker renames regular files only; moving a directory \
                         tree is a blast radius one rename does not account for"
                    .to_string(),
            });
        }
        // The source content is the destination's postimage, so it has to be read before the
        // move rather than reconstructed after it.
        let moved = read_bounded(&from)?;

        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[BudgetCharge::new(BudgetDimension::FileRenames, 1)],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.record_budget_denial(
                    session_id,
                    &correlation_id,
                    LocalAction::FsRename,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        // Destination first: it is the one whose prior content is destroyed.
        let destination_preimage = self.store.capture_preimage(
            session_id,
            &to,
            crate::rollback::Postimage::Content(&moved),
            None,
        )?;
        let source_preimage = self.store.capture_preimage(
            session_id,
            &from,
            crate::rollback::Postimage::Absent,
            None,
        )?;

        if let Err(error) = std::fs::rename(&from, &to) {
            let error = VigilError::from(error);
            self.refund_and_record_failure(
                session_id,
                &correlation_id,
                &reservation.id,
                LocalAction::FsRename,
                &decision.determining_policy,
                &error,
            )?;
            return Err(error);
        }
        if let Err(error) = self.store.commit_budget(&reservation.id) {
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

        let event = self.store.append_event(
            session_id,
            "filesystem",
            LocalAction::FsRename.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "resolved_resource": to,
                "resolved_source": from,
                "bytes": moved.len(),
                "reservation_id": reservation.id,
                "determining_policy": decision.determining_policy,
                "content_captured": false,
                "preimage_ids": [source_preimage.preimage_id, destination_preimage.preimage_id],
                "reversible": source_preimage.restorable() && destination_preimage.restorable(),
            }),
        )?;
        Ok(BrokerResult {
            value: (),
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            resolved_resource: to,
            bytes: moved.len() as u64,
        })
    }

    /// List a workspace directory.
    ///
    /// Enumeration is worth mediating even though it changes nothing: an agent walking toward
    /// a protected location is a signal, and without a broker path it does so with direct
    /// syscalls that VIGIL cannot see at all. Consuming a read charge keeps enumeration inside
    /// the same blast-radius accounting as reading.
    pub fn list(
        &self,
        session_id: &str,
        requested_path: &str,
    ) -> Result<BrokerResult<Vec<String>>> {
        let correlation_id = new_correlation_id();
        let (session, profile, workspace) = self.session_context(session_id)?;
        let authorization = self.store.authorize_local(
            session_id,
            profile,
            &workspace,
            LocalAction::FsList,
            requested_path,
        )?;
        let resolved = self.require_permit(&session, &correlation_id, &authorization)?;
        let decision = authorization.decision;

        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[BudgetCharge::new(BudgetDimension::FileReads, 1)],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.record_budget_denial(
                    session_id,
                    &correlation_id,
                    LocalAction::FsList,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };

        let entries = match list_bounded(&resolved) {
            Ok(entries) => entries,
            Err(error) => {
                self.refund_and_record_failure(
                    session_id,
                    &correlation_id,
                    &reservation.id,
                    LocalAction::FsList,
                    &decision.determining_policy,
                    &error,
                )?;
                return Err(error);
            }
        };
        self.store.commit_budget(&reservation.id)?;

        let event = self.store.append_event(
            session_id,
            "filesystem",
            LocalAction::FsList.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "resolved_resource": resolved,
                "entries": entries.len(),
                "reservation_id": reservation.id,
                "determining_policy": decision.determining_policy,
                // Names can themselves be sensitive; the count is the security-relevant fact.
                "entry_names_captured": false,
            }),
        )?;
        Ok(BrokerResult {
            value: entries,
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            resolved_resource: resolved,
            bytes: 0,
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
                "filesystem broker requires a running semantic-enforced session".to_string(),
            ));
        }
        let profile = session.profile.parse()?;
        let workspace = PathBuf::from(&session.workspace);
        Ok((session, profile, workspace))
    }

    /// Record the decision and turn a non-permitting one into an error the operator can act on.
    ///
    /// A `REQUIRE_APPROVAL` is not a dead end any more: the authorization has already raised
    /// (or found) the approval request, so the error names it and says how to grant it.
    fn require_permit(
        &self,
        session: &LocalSession,
        correlation_id: &str,
        authorization: &LocalAuthorization,
    ) -> Result<PathBuf> {
        let decision = &authorization.decision;
        if !decision.permits_execution() {
            let mut payload = serde_json::to_value(decision)?;
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
                &session.id,
                "policy",
                &decision.action,
                Some(outcome_name(decision.outcome)),
                correlation_id,
                &payload,
            )?;
            let message = match &authorization.approval {
                Some(outcome) => format!(
                    "{}; approval {} is required (grant it with `vigil approvals grant {}`)",
                    decision.reason,
                    outcome.request().approval_id,
                    outcome.request().approval_id,
                ),
                None => decision.reason.clone(),
            };
            return Err(VigilError::Unauthorized(message));
        }
        decision
            .resolved_resource
            .as_deref()
            .map(PathBuf::from)
            .ok_or_else(|| {
                VigilError::Policy("filesystem decision omitted resolved resource".to_string())
            })
    }

    fn refund_and_record_failure(
        &self,
        session_id: &str,
        correlation_id: &str,
        reservation_id: &str,
        action: LocalAction,
        determining_policy: &str,
        error: &VigilError,
    ) -> Result<()> {
        self.store.refund_budget(reservation_id)?;
        self.store.append_event(
            session_id,
            "filesystem",
            action.as_str(),
            Some("FAILED"),
            correlation_id,
            &json!({
                "reservation_id": reservation_id,
                "determining_policy": determining_policy,
                "error_class": error.class(),
                "budget_refunded": true,
            }),
        )?;
        Ok(())
    }

    fn record_budget_denial(
        &self,
        session_id: &str,
        correlation_id: &str,
        action: LocalAction,
        determining_policy: &str,
        error: &VigilError,
    ) -> Result<()> {
        let event = self.store.append_event(
            session_id,
            "budget",
            action.as_str(),
            Some("DENY"),
            correlation_id,
            &json!({
                "determining_policy": determining_policy,
                "error_class": error.class(),
                "reason": error.to_string(),
                "detection": crate::DETECTION_BUDGET_EXHAUSTION,
            }),
        )?;
        // Reaching a blast-radius limit is a fact worth recording as a detection, not just a
        // failed call. A session that keeps hitting its ceiling is behaving differently from
        // one that never approaches it.
        if let Some(rule) = crate::rule_for_label(crate::DETECTION_BUDGET_EXHAUSTION) {
            self.store.record_detection(
                session_id,
                rule,
                json!({
                    "action": action.as_str(),
                    "determining_policy": determining_policy,
                    "error_class": error.class(),
                }),
                Some(&event.event_id),
            )?;
            self.store.record_risk_signal(
                session_id,
                rule.dimension,
                rule.weight,
                Some(&event.event_id),
                rule.description,
            )?;
        }
        Ok(())
    }
}

/// Whether two metadata records describe the same filesystem object.
///
/// Device and inode together identify an object; a path does not. This is what lets a
/// decision about a path be checked against the thing that was actually opened.
#[cfg(unix)]
fn same_object(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// Without device and inode there is nothing to compare, so the check cannot be made.
///
/// It reports "same" rather than refusing every read, because refusing would break the
/// platform entirely for a check it cannot perform. macOS is the target and it is unix.
#[cfg(not(unix))]
fn same_object(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

/// Read a file, verifying that the object opened is the object that was checked.
///
/// A path is not an identity. Between deciding about `path` and opening it, the name can be
/// pointed at something else — a symlink dropped in place, a rename over the top. Without this
/// check the broker would return the content of a file policy never saw, and the event would
/// record the path it decided about, so the evidence would be wrong too.
///
/// The object is identified before the open and again from the open file handle. A handle is
/// the object, so a mismatch means the name changed underneath and the read is refused before
/// any content is returned.
///
/// **The window this closes is stat-to-open, not decide-to-open.** Closing the wider one needs
/// `openat` against a directory handle held from resolution onward, which is not reachable
/// without `unsafe` in a crate that forbids it. The residual window is narrow and the failure
/// is now detectable rather than silent; Endpoint Security is the real answer.
/// Bound on entries returned from one listing.
const MAX_LIST_ENTRIES: usize = 4096;

/// List a directory, bounded.
///
/// An unbounded listing of a directory an agent controls is an unbounded allocation driven by
/// the agent.
fn list_bounded(path: &Path) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        if entries.len() >= MAX_LIST_ENTRIES {
            break;
        }
        entries.push(entry?.file_name().to_string_lossy().into_owned());
    }
    entries.sort();
    Ok(entries)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    // `symlink_metadata` does not follow: the resolved path should already be the real object,
    // so a link appearing here is itself the substitution being looked for.
    let before = std::fs::symlink_metadata(path)?;
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_object(&before, &opened) {
        return Err(VigilError::AuditIntegrity(format!(
            "`{}` changed identity between the policy decision and the open; refusing to \
             return content from an object that was never checked",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BROKER_READ_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BROKER_READ_BYTES {
        return Err(VigilError::InvalidValue {
            field: "resource",
            reason: format!("broker read exceeds {MAX_BROKER_READ_BYTES} bytes"),
        });
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| VigilError::InvalidValue {
        field: "resource",
        reason: "write target has no parent".to_string(),
    })?;
    // The rename below resolves `parent` by name. If the directory that name refers to is
    // swapped in between, the write lands somewhere policy never approved, so its identity is
    // captured now and rechecked immediately before the rename.
    let parent_before = std::fs::symlink_metadata(parent)?;
    let temporary = parent.join(format!(
        ".vigil-write-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let existing_permissions = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        if let Some(permissions) = existing_permissions {
            std::fs::set_permissions(&temporary, permissions)?;
        }
        // Last check before the content becomes visible under the approved name.
        let parent_now = std::fs::symlink_metadata(parent)?;
        if !same_object(&parent_before, &parent_now) {
            return Err(VigilError::AuditIntegrity(format!(
                "the directory `{}` changed identity during the write; refusing to place \
                 content somewhere policy never approved",
                parent.display()
            )));
        }
        std::fs::rename(&temporary, path)?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn outcome_name(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
        DecisionOutcome::RequireApproval => "REQUIRE_APPROVAL",
        DecisionOutcome::Observe => "OBSERVE",
    }
}

fn new_correlation_id() -> String {
    format!("cor_{}", uuid::Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewSession;

    fn broker_fixture(profile: &str) -> (PathBuf, LocalStore, String, PathBuf) {
        let root = std::env::temp_dir().join(format!("vigil-broker-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: profile.to_string(),
                workspace: std::fs::canonicalize(&workspace).expect("canonical workspace"),
                executable: "vigil-fs-broker".to_string(),
                argv: vec!["vigil-fs-broker".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&session.id, std::process::id())
            .expect("activate session");
        (root, store, session.id, workspace)
    }

    fn consumed(store: &LocalStore, session: &str, dimension: BudgetDimension) -> u64 {
        store
            .budget_snapshot(session)
            .expect("snapshot")
            .into_iter()
            .find(|counter| counter.dimension == dimension)
            .expect("counter")
            .consumed
    }

    #[test]
    fn a_workspace_read_executes_and_records_no_content() {
        let (root, store, session, workspace) = broker_fixture("developer-standard");
        std::fs::write(workspace.join("message.txt"), b"safe content").expect("write fixture");
        let result = FilesystemBroker::new(&store)
            .read(&session, "message.txt")
            .expect("broker read");
        assert_eq!(result.value, b"safe content");
        assert_eq!(consumed(&store, &session, BudgetDimension::FileReads), 1);
        let events = store.events_for_session(&session).expect("events");
        let rendered = serde_json::to_string(&events).expect("serialize events");
        assert!(!rendered.contains("safe content"));
        assert!(rendered.contains("content_captured"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_managed_write_is_atomic_and_charges_count_and_bytes() {
        let (root, store, session, workspace) = broker_fixture("developer-standard");
        let result = FilesystemBroker::new(&store)
            .write(&session, "output.txt", b"new value")
            .expect("broker write");
        assert_eq!(result.bytes, 9);
        assert_eq!(
            std::fs::read(workspace.join("output.txt")).expect("read output"),
            b"new value"
        );
        assert_eq!(consumed(&store, &session, BudgetDimension::FileCreates), 1);
        assert_eq!(
            consumed(&store, &session, BudgetDimension::TotalWriteBytes),
            9
        );
        assert!(std::fs::read_dir(&workspace)
            .expect("read workspace")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".vigil-write-")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_policy_denial_performs_no_io_and_spends_no_budget() {
        let (root, store, session, _) = broker_fixture("developer-standard");
        let outside = root.join("outside.txt");
        let result = FilesystemBroker::new(&store).write(
            &session,
            &outside.display().to_string(),
            b"must not exist",
        );
        assert!(matches!(result, Err(VigilError::Unauthorized(_))));
        assert!(!outside.exists());
        assert_eq!(consumed(&store, &session, BudgetDimension::FileCreates), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_io_failure_refunds_the_reservation() {
        let (root, store, session, _) = broker_fixture("developer-standard");
        let result = FilesystemBroker::new(&store).write(
            &session,
            "missing-parent/output.txt",
            b"cannot be written",
        );
        assert!(result.is_err());
        let count = store
            .budget_snapshot(&session)
            .expect("snapshot")
            .into_iter()
            .find(|counter| counter.dimension == BudgetDimension::FileCreates)
            .expect("create counter");
        assert_eq!((count.consumed, count.reserved), (0, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn maximum_single_write_is_checked_before_creating_a_file() {
        let (root, store, session, workspace) = broker_fixture("untrusted-agent");
        let content = vec![b'x'; 500_001];
        let result = FilesystemBroker::new(&store).write(&session, "large.bin", &content);
        assert!(matches!(result, Err(VigilError::BudgetExhausted(_))));
        assert!(!workspace.join("large.bin").exists());
        assert_eq!(
            consumed(&store, &session, BudgetDimension::TotalWriteBytes),
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    /// A path is not an identity. This performs the substitution directly against
    /// `read_bounded` and asserts the content of the substituted object is never returned.
    #[cfg(unix)]
    #[test]
    fn a_file_swapped_for_another_object_is_refused_rather_than_read() {
        let root = std::env::temp_dir().join(format!("vigil-toctou-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");

        let approved = root.join("approved.txt");
        let secret = root.join("secret.txt");
        std::fs::write(&approved, b"APPROVED CONTENT").expect("seed approved");
        std::fs::write(&secret, b"SECRET CONTENT").expect("seed secret");

        // The ordinary case still works: this must not refuse every read.
        assert_eq!(
            read_bounded(&approved).expect("read approved"),
            b"APPROVED CONTENT"
        );

        // Now the approved name points at something else. The identity captured before the
        // open is the link's; the open follows it to a different object; they disagree.
        std::fs::remove_file(&approved).expect("remove");
        std::os::unix::fs::symlink(&secret, &approved).expect("substitute");

        match read_bounded(&approved) {
            Err(VigilError::AuditIntegrity(reason)) => {
                assert!(reason.contains("changed identity"), "{reason}");
            }
            Err(other) => panic!("expected an integrity refusal, got {other:?}"),
            Ok(bytes) => panic!(
                "the substituted object was read: {:?}",
                String::from_utf8_lossy(&bytes)
            ),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// The comparison must distinguish objects, not names or content.
    #[cfg(unix)]
    #[test]
    fn identity_is_device_and_inode_not_the_name() {
        let root = std::env::temp_dir().join(format!("vigil-ident-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create root");
        let first = root.join("a");
        let second = root.join("b");
        std::fs::write(&first, b"same bytes").expect("seed");
        std::fs::write(&second, b"same bytes").expect("seed");

        let a = std::fs::symlink_metadata(&first).expect("stat");
        let b = std::fs::symlink_metadata(&second).expect("stat");
        // Identical content, different objects.
        assert!(!same_object(&a, &b));

        // A hard link is the same object under a second name.
        let link = root.join("a-link");
        std::fs::hard_link(&first, &link).expect("hard link");
        let linked = std::fs::symlink_metadata(&link).expect("stat");
        assert!(same_object(&a, &linked));
        let _ = std::fs::remove_dir_all(root);
    }
}
