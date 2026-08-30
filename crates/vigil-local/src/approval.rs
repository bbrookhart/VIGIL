//! Human approval for capabilities the profile will not grant on its own.
//!
//! An approval is *specific*. It binds to one session, one action, and one resolved resource
//! — the triple hashed into its fingerprint — and granting it mints exactly one lease bound
//! to that same triple. There is no shape in this API that expresses "allow everything for
//! ten minutes", which is invariant 8 held up by the absence of a function rather than by a
//! reviewer noticing.
//!
//! # What this module does not claim
//!
//! [`ApproverIdentity`] can only be constructed by [`ApproverIdentity::from_cli_operator`],
//! which no broker module calls, and a test asserts that. That is real defence in depth: no
//! code path from a brokered agent request reaches [`LocalStore::grant_approval`].
//!
//! It is **not** a trust boundary. On a host with no `vigild` and no authenticated IPC, the
//! agent and the operator run with the same ambient authority, and an agent that can execute
//! arbitrary code can run the `vigil` binary itself. Invariant 3 is not satisfied at the
//! operating-system level until the entitled half of the product exists. See
//! `docs/security/TRUST_BOUNDARIES.md` and ADR 0017.

use crate::lease::{
    issue_lease_in_transaction, CapabilityLease, LeaseGrant, MAX_LEASE_TTL_SECONDS, MAX_LEASE_USES,
};
use crate::risk::RiskDimension;
use crate::{LocalAction, LocalStore, RiskState};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use vigil_common::{ContentHash, Result, VigilError};

/// How long an unanswered approval request stays actionable.
pub const APPROVAL_TTL_SECONDS: i64 = 900;

/// Risk loaded each time a session re-requests something already denied.
///
/// Four attempts reach the quarantine threshold. Probing a boundary is not a mistake a
/// well-behaved agent makes repeatedly.
const PROBING_SIGNAL_WEIGHT: u32 = 20;

/// Risk loaded when a session generates approval requests faster than a human can answer.
const FATIGUE_SIGNAL_WEIGHT: u32 = 20;

/// How many requests inside [`FATIGUE_WINDOW_SECONDS`] count as flooding the operator.
const FATIGUE_THRESHOLD: usize = 8;
const FATIGUE_WINDOW_SECONDS: i64 = 300;

/// Detection labels attached to the events these paths record.
pub const DETECTION_ESCALATION_PROBING: &str = "capability_escalation_probing";
pub const DETECTION_APPROVAL_FATIGUE: &str = "approval_fatigue";

/// Proof that a decision on an approval came from a human operator.
///
/// The single constructor is the point. Broker code cannot build one, so broker code cannot
/// call [`LocalStore::grant_approval`] however it is refactored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverIdentity(String);

impl ApproverIdentity {
    /// Construct from the operator identity supplied on the `vigil` command line.
    pub fn from_cli_operator(identity: &str) -> Result<Self> {
        let trimmed = identity.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return Err(VigilError::InvalidValue {
                field: "approver",
                reason: "an approver identity must be 1..=128 characters".to_string(),
            });
        }
        if !trimmed
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:-@".contains(character))
        {
            return Err(VigilError::InvalidValue {
                field: "approver",
                reason: "an approver identity may use letters, digits and `._:-@` only".to_string(),
            });
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Denied,
}

impl ApprovalStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "granted" => Ok(Self::Granted),
            "denied" => Ok(Self::Denied),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown approval status `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub session_id: String,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub action: LocalAction,
    pub requested_resource: String,
    pub resolved_resource: String,
    pub determining_policy: String,
    pub reason: String,
    pub risk_state_at_request: RiskState,
    pub fingerprint: String,
    pub status: ApprovalStatus,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
    pub note: Option<String>,
    pub lease_id: Option<String>,
}

impl ApprovalRequest {
    /// Whether this request can still be granted, as of `now`.
    pub fn is_actionable(&self, now: DateTime<Utc>) -> bool {
        self.status == ApprovalStatus::Pending && self.expires_at > now
    }
}

/// What happened when a broker asked for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// A new request was recorded and is waiting for a human.
    Created(ApprovalRequest),
    /// An identical request was already waiting; no second one was created.
    AlreadyPending(ApprovalRequest),
    /// A human already refused this exact request. Asking again is a probing signal.
    PreviouslyDenied {
        request: ApprovalRequest,
        risk_state: RiskState,
    },
}

impl ApprovalOutcome {
    pub fn request(&self) -> &ApprovalRequest {
        match self {
            Self::Created(request)
            | Self::AlreadyPending(request)
            | Self::PreviouslyDenied { request, .. } => request,
        }
    }

    /// The detection label this outcome warrants, if any.
    pub fn detection(&self) -> Option<&'static str> {
        match self {
            Self::PreviouslyDenied { .. } => Some(DETECTION_ESCALATION_PROBING),
            _ => None,
        }
    }
}

/// Bind an approval to exactly one session, action, and resolved resource.
///
/// Hashed through the canonical JSON form so the fingerprint does not depend on field order.
pub fn fingerprint(
    session_id: &str,
    action: LocalAction,
    resolved_resource: &str,
) -> Result<String> {
    let document = serde_json::json!({
        "session_id": session_id,
        "action": action.as_str(),
        "resolved_resource": resolved_resource,
    });
    Ok(ContentHash::canonical_json(&document)?.to_string())
}

/// One capability a session is asking a human to authorize.
///
/// Grouped rather than passed positionally: `requested_resource` and `resolved_resource` are
/// both strings and mean very different things, and swapping them would silently bind the
/// approval to the unresolved path — exactly the laundering the resolution step exists to
/// prevent.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityAsk<'a> {
    pub session_id: &'a str,
    pub action: LocalAction,
    /// What the caller typed, recorded for the operator's benefit.
    pub requested_resource: &'a str,
    /// What policy actually decided about. The fingerprint and lease bind to this.
    pub resolved_resource: &'a str,
    pub determining_policy: &'a str,
    pub reason: &'a str,
}

impl LocalStore {
    /// Record that a session needs human authority for one specific capability.
    ///
    /// Re-asking is not free. An identical pending request returns the existing row rather
    /// than creating a second one, and re-asking for something already denied loads the
    /// policy-evasion dimension. Flooding the operator loads the capability-anomaly
    /// dimension. Approval fatigue is treated as an attack on the human, not as noise.
    pub fn request_approval(
        &self,
        ask: &CapabilityAsk<'_>,
        now: DateTime<Utc>,
    ) -> Result<ApprovalOutcome> {
        let CapabilityAsk {
            session_id,
            action,
            requested_resource,
            resolved_resource,
            determining_policy,
            reason,
        } = *ask;
        let fingerprint = fingerprint(session_id, action, resolved_resource)?;
        let risk_state = self.session_risk_state(session_id)?;

        // A prior refusal outranks a prior pending request: if a human has already said no to
        // this exact triple, asking again is the interesting fact.
        if let Some(denied) = self.find_by_fingerprint(&fingerprint, ApprovalStatus::Denied)? {
            if let Some(rule) = crate::detection::rule_for_label(DETECTION_ESCALATION_PROBING) {
                self.record_detection(
                    session_id,
                    rule,
                    serde_json::json!({
                        "action": action.as_str(),
                        "resolved_resource": resolved_resource,
                        "refused_approval_id": denied.approval_id,
                    }),
                    None,
                )?;
            }
            let risk_state = self.record_risk_signal(
                session_id,
                RiskDimension::PolicyEvasion,
                PROBING_SIGNAL_WEIGHT,
                None,
                "re-requested a capability a human already refused",
            )?;
            return Ok(ApprovalOutcome::PreviouslyDenied {
                request: denied,
                risk_state,
            });
        }
        if let Some(pending) = self.find_by_fingerprint(&fingerprint, ApprovalStatus::Pending)? {
            if pending.is_actionable(now) {
                return Ok(ApprovalOutcome::AlreadyPending(pending));
            }
        }

        let request = ApprovalRequest {
            approval_id: format!("apr_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.to_string(),
            requested_at: now,
            expires_at: now
                .checked_add_signed(Duration::seconds(APPROVAL_TTL_SECONDS))
                .ok_or_else(|| VigilError::InvalidValue {
                    field: "expires_at",
                    reason: "approval expiry overflows the representable range".to_string(),
                })?,
            action,
            requested_resource: vigil_common::redact::single_line_excerpt(requested_resource, 500),
            resolved_resource: resolved_resource.to_string(),
            determining_policy: determining_policy.to_string(),
            reason: vigil_common::redact::single_line_excerpt(reason, 500),
            risk_state_at_request: risk_state,
            fingerprint,
            status: ApprovalStatus::Pending,
            decided_at: None,
            decided_by: None,
            note: None,
            lease_id: None,
        };

        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        // An expired pending row still holds the partial unique index, so retire it before
        // inserting its replacement.
        transaction
            .execute(
                "UPDATE approval_requests SET status = 'denied', decided_at = ?1,
                        note = 'expired without a human decision'
                 WHERE session_id = ?2 AND fingerprint = ?3 AND status = 'pending'
                   AND expires_at <= ?4",
                params![
                    now.to_rfc3339(),
                    session_id,
                    request.fingerprint,
                    now.to_rfc3339()
                ],
            )
            .map_err(super::store::storage_error)?;
        transaction
            .execute(
                "INSERT INTO approval_requests
                 (approval_id, session_id, requested_at, expires_at, action, requested_resource,
                  resolved_resource, determining_policy, reason, risk_state_at_request,
                  fingerprint, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending')",
                params![
                    request.approval_id,
                    request.session_id,
                    request.requested_at.to_rfc3339(),
                    request.expires_at.to_rfc3339(),
                    request.action.as_str(),
                    request.requested_resource,
                    request.resolved_resource,
                    request.determining_policy,
                    request.reason,
                    request.risk_state_at_request.as_str(),
                    request.fingerprint,
                ],
            )
            .map_err(super::store::storage_error)?;
        let recent: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM approval_requests
                 WHERE session_id = ?1 AND requested_at > ?2",
                params![
                    session_id,
                    (now - Duration::seconds(FATIGUE_WINDOW_SECONDS)).to_rfc3339()
                ],
                |row| row.get(0),
            )
            .map_err(super::store::storage_error)?;
        transaction.commit().map_err(super::store::storage_error)?;

        if usize::try_from(recent).unwrap_or(usize::MAX) >= FATIGUE_THRESHOLD {
            if let Some(rule) = crate::detection::rule_for_label(DETECTION_APPROVAL_FATIGUE) {
                self.record_detection(
                    session_id,
                    rule,
                    serde_json::json!({
                        "requests_in_window": recent,
                        "window_seconds": FATIGUE_WINDOW_SECONDS,
                        "threshold": FATIGUE_THRESHOLD,
                    }),
                    None,
                )?;
            }
            let risk_state = self.record_risk_signal(
                session_id,
                RiskDimension::CapabilityAnomaly,
                FATIGUE_SIGNAL_WEIGHT,
                None,
                "generated approval requests faster than an operator can answer them",
            )?;
            // Recorded on the timeline as well as in the risk vector: an operator reading
            // back a session needs to see that they were being flooded, not just that the
            // capability-anomaly dimension moved for unstated reasons.
            self.append_event(
                session_id,
                "approval",
                "approval.fatigue",
                Some("DETECTED"),
                &request.approval_id,
                &serde_json::json!({
                    "detection": DETECTION_APPROVAL_FATIGUE,
                    "requests_in_window": recent,
                    "window_seconds": FATIGUE_WINDOW_SECONDS,
                    "threshold": FATIGUE_THRESHOLD,
                    "risk_state": risk_state.as_str(),
                }),
            )?;
        }
        Ok(ApprovalOutcome::Created(request))
    }

    /// Grant one approval, minting exactly one lease bound to its fingerprint triple.
    ///
    /// Requires an [`ApproverIdentity`], which broker code cannot construct.
    pub fn grant_approval(
        &self,
        approval_id: &str,
        approver: &ApproverIdentity,
        max_uses: u32,
        ttl_seconds: i64,
        note: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<CapabilityLease> {
        if max_uses == 0 || max_uses > MAX_LEASE_USES {
            return Err(VigilError::InvalidValue {
                field: "max_uses",
                reason: format!("a grant must permit between 1 and {MAX_LEASE_USES} uses"),
            });
        }
        if ttl_seconds <= 0 || ttl_seconds > MAX_LEASE_TTL_SECONDS {
            return Err(VigilError::InvalidValue {
                field: "ttl_seconds",
                reason: format!(
                    "a grant must expire within 1..={MAX_LEASE_TTL_SECONDS} seconds; a longer \
                     grant is refused rather than silently shortened"
                ),
            });
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let request = read_request(&transaction, approval_id)?;
        if request.status != ApprovalStatus::Pending {
            return Err(VigilError::InvalidRequest(format!(
                "approval {approval_id} is already {}",
                request.status.as_str()
            )));
        }
        if request.expires_at <= now {
            return Err(VigilError::InvalidRequest(format!(
                "approval {approval_id} expired at {} and must be requested again",
                request.expires_at.to_rfc3339()
            )));
        }
        // A session already contained cannot be handed authority back. Risk only subtracts.
        let risk = read_session_risk(&transaction, &request.session_id)?;
        if risk.revokes_leases() {
            return Err(VigilError::Unauthorized(format!(
                "session {} is {}; capabilities cannot be granted to a contained session",
                request.session_id,
                risk.as_str()
            )));
        }

        // The lease takes its action and resource from the approval, never from the grant
        // command. An operator decides *whether*, not *what*: the what was fixed when the
        // request was recorded.
        let lease = issue_lease_in_transaction(
            &transaction,
            &LeaseGrant {
                session_id: &request.session_id,
                approval_id: &request.approval_id,
                action: request.action,
                resource: &request.resolved_resource,
                max_uses,
                ttl_seconds,
            },
            now,
        )?;
        transaction
            .execute(
                "UPDATE approval_requests
                 SET status = 'granted', decided_at = ?1, decided_by = ?2, note = ?3,
                     lease_id = ?4
                 WHERE approval_id = ?5 AND status = 'pending'",
                params![
                    now.to_rfc3339(),
                    approver.as_str(),
                    note.map(|note| vigil_common::redact::single_line_excerpt(note, 500)),
                    lease.lease_id,
                    approval_id,
                ],
            )
            .map_err(super::store::storage_error)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(lease)
    }

    /// Refuse one approval. A later identical request becomes a probing signal.
    pub fn deny_approval(
        &self,
        approval_id: &str,
        approver: &ApproverIdentity,
        note: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<ApprovalRequest> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let request = read_request(&transaction, approval_id)?;
        if request.status != ApprovalStatus::Pending {
            return Err(VigilError::InvalidRequest(format!(
                "approval {approval_id} is already {}",
                request.status.as_str()
            )));
        }
        transaction
            .execute(
                "UPDATE approval_requests
                 SET status = 'denied', decided_at = ?1, decided_by = ?2, note = ?3
                 WHERE approval_id = ?4 AND status = 'pending'",
                params![
                    now.to_rfc3339(),
                    approver.as_str(),
                    note.map(|note| vigil_common::redact::single_line_excerpt(note, 500)),
                    approval_id,
                ],
            )
            .map_err(super::store::storage_error)?;
        let updated = read_request(&transaction, approval_id)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(updated)
    }

    pub fn get_approval(&self, approval_id: &str) -> Result<Option<ApprovalRequest>> {
        let row = self
            .connection
            .query_row(APPROVAL_COLUMNS_SQL, [approval_id], request_from_row)
            .optional()
            .map_err(super::store::storage_error)?;
        row.transpose()
    }

    /// List approvals, newest first, optionally narrowed to one session or status.
    pub fn list_approvals(
        &self,
        session_id: Option<&str>,
        status: Option<ApprovalStatus>,
        limit: usize,
    ) -> Result<Vec<ApprovalRequest>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        let mut statement = self
            .connection
            .prepare(
                "SELECT approval_id, session_id, requested_at, expires_at, action,
                        requested_resource, resolved_resource, determining_policy, reason,
                        risk_state_at_request, fingerprint, status, decided_at, decided_by,
                        note, lease_id
                 FROM approval_requests
                 WHERE (?1 IS NULL OR session_id = ?1) AND (?2 IS NULL OR status = ?2)
                 ORDER BY requested_at DESC, approval_id LIMIT ?3",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map(
                params![session_id, status.map(ApprovalStatus::as_str), limit],
                request_from_row,
            )
            .map_err(super::store::storage_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?
            .into_iter()
            .collect::<Result<Vec<_>>>()
    }

    fn find_by_fingerprint(
        &self,
        fingerprint: &str,
        status: ApprovalStatus,
    ) -> Result<Option<ApprovalRequest>> {
        let row = self
            .connection
            .query_row(
                "SELECT approval_id, session_id, requested_at, expires_at, action,
                        requested_resource, resolved_resource, determining_policy, reason,
                        risk_state_at_request, fingerprint, status, decided_at, decided_by,
                        note, lease_id
                 FROM approval_requests WHERE fingerprint = ?1 AND status = ?2
                 ORDER BY requested_at DESC LIMIT 1",
                params![fingerprint, status.as_str()],
                request_from_row,
            )
            .optional()
            .map_err(super::store::storage_error)?;
        row.transpose()
    }
}

const APPROVAL_COLUMNS_SQL: &str = "SELECT approval_id, session_id, requested_at, expires_at,
            action, requested_resource, resolved_resource, determining_policy, reason,
            risk_state_at_request, fingerprint, status, decided_at, decided_by, note, lease_id
     FROM approval_requests WHERE approval_id = ?1";

fn read_request(transaction: &Transaction<'_>, approval_id: &str) -> Result<ApprovalRequest> {
    transaction
        .query_row(APPROVAL_COLUMNS_SQL, [approval_id], request_from_row)
        .optional()
        .map_err(super::store::storage_error)?
        .ok_or_else(|| VigilError::NotFound(format!("approval {approval_id}")))?
}

fn read_session_risk(transaction: &Transaction<'_>, session_id: &str) -> Result<RiskState> {
    let state: String = transaction
        .query_row(
            "SELECT risk_state FROM sessions WHERE id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                VigilError::NotFound("local session".to_string())
            }
            other => super::store::storage_error(other),
        })?;
    state.parse()
}

/// Read a stored approval request.
///
/// Columns are read up front so a SQLite failure stays distinct from a value VIGIL declines
/// to interpret.
fn request_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ApprovalRequest>> {
    let approval_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let requested_at: String = row.get(2)?;
    let expires_at: String = row.get(3)?;
    let action: String = row.get(4)?;
    let requested_resource: String = row.get(5)?;
    let resolved_resource: String = row.get(6)?;
    let determining_policy: String = row.get(7)?;
    let reason: String = row.get(8)?;
    let risk: String = row.get(9)?;
    let fingerprint: String = row.get(10)?;
    let status: String = row.get(11)?;
    let decided_at: Option<String> = row.get(12)?;
    let decided_by: Option<String> = row.get(13)?;
    let note: Option<String> = row.get(14)?;
    let lease_id: Option<String> = row.get(15)?;

    Ok((|| {
        Ok(ApprovalRequest {
            approval_id,
            session_id,
            requested_at: parse_time(&requested_at)?,
            expires_at: parse_time(&expires_at)?,
            action: action.parse()?,
            requested_resource,
            resolved_resource,
            determining_policy,
            reason,
            risk_state_at_request: risk.parse()?,
            fingerprint,
            status: ApprovalStatus::parse(&status)?,
            decided_at: decided_at.as_deref().map(parse_time).transpose()?,
            decided_by,
            note,
            lease_id,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            VigilError::Serialization(format!("unparsable approval timestamp: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewSession;
    use std::path::PathBuf;

    fn active_session() -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-approval-{}", uuid::Uuid::new_v4()));
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
        store
            .mark_running(&session.id, std::process::id())
            .expect("activate");
        (root, store, session.id)
    }

    fn ask(store: &LocalStore, session: &str, resource: &str) -> ApprovalOutcome {
        store
            .request_approval(
                &CapabilityAsk {
                    session_id: session,
                    action: LocalAction::ProcessExec,
                    requested_resource: resource,
                    resolved_resource: resource,
                    determining_policy: "approve-process-exec",
                    reason: "test",
                },
                Utc::now(),
            )
            .expect("request approval")
    }

    fn operator() -> ApproverIdentity {
        ApproverIdentity::from_cli_operator("operator").expect("identity")
    }

    #[test]
    fn asking_twice_does_not_create_a_second_request() {
        let (root, store, session) = active_session();
        let first = ask(&store, &session, "/usr/bin/uname");
        assert!(matches!(first, ApprovalOutcome::Created(_)));
        let second = ask(&store, &session, "/usr/bin/uname");
        assert!(matches!(second, ApprovalOutcome::AlreadyPending(_)));
        assert_eq!(
            first.request().approval_id,
            second.request().approval_id,
            "a repeat request must reuse the pending row, not flood the operator"
        );
        assert_eq!(
            store
                .list_approvals(Some(&session), None, 100)
                .expect("list")
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn re_asking_after_a_refusal_is_recorded_as_probing_and_escalates_risk() {
        let (root, store, session) = active_session();
        let created = ask(&store, &session, "/usr/bin/uname");
        store
            .deny_approval(
                &created.request().approval_id,
                &operator(),
                Some("no"),
                Utc::now(),
            )
            .expect("deny");
        assert_eq!(
            store.session_risk_state(&session).expect("risk"),
            RiskState::Normal
        );

        let again = ask(&store, &session, "/usr/bin/uname");
        assert!(matches!(again, ApprovalOutcome::PreviouslyDenied { .. }));
        assert_eq!(again.detection(), Some(DETECTION_ESCALATION_PROBING));
        assert_eq!(
            store.session_risk_state(&session).expect("risk"),
            RiskState::Elevated
        );
        // No new row: probing does not get to fill the operator's queue either.
        assert_eq!(
            store
                .list_approvals(Some(&session), None, 100)
                .expect("list")
                .len(),
            1
        );

        // Each further attempt climbs one step. Four reaches quarantine.
        for expected in [
            RiskState::Restricted,
            RiskState::Contained,
            RiskState::Quarantined,
        ] {
            ask(&store, &session, "/usr/bin/uname");
            assert_eq!(store.session_risk_state(&session).expect("risk"), expected);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn flooding_the_operator_loads_the_capability_anomaly_dimension() {
        let (root, store, session) = active_session();
        for index in 0..FATIGUE_THRESHOLD {
            ask(&store, &session, &format!("/usr/bin/tool{index}"));
        }
        let assessment = store.risk_assessment(&session).expect("assessment");
        assert!(
            assessment
                .dimensions
                .iter()
                .any(|score| score.dimension == RiskDimension::CapabilityAnomaly
                    && score.score >= FATIGUE_SIGNAL_WEIGHT),
            "approval flooding did not load the capability-anomaly dimension: {:?}",
            assessment.dimensions
        );
        assert!(assessment.state > RiskState::Normal);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_contained_session_cannot_be_handed_authority_back() {
        let (root, store, session) = active_session();
        let created = ask(&store, &session, "/usr/bin/uname");
        store
            .record_risk_signal(
                &session,
                RiskDimension::CredentialAccess,
                60,
                None,
                "test containment",
            )
            .expect("signal");
        let error = store
            .grant_approval(
                &created.request().approval_id,
                &operator(),
                1,
                900,
                None,
                Utc::now(),
            )
            .expect_err("a contained session must not be granted capabilities");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_expired_request_cannot_be_granted() {
        let (root, store, session) = active_session();
        let created = store
            .request_approval(
                &CapabilityAsk {
                    session_id: &session,
                    action: LocalAction::ProcessExec,
                    requested_resource: "/usr/bin/uname",
                    resolved_resource: "/usr/bin/uname",
                    determining_policy: "approve-process-exec",
                    reason: "test",
                },
                Utc::now() - Duration::seconds(APPROVAL_TTL_SECONDS + 60),
            )
            .expect("request");
        let error = store
            .grant_approval(
                &created.request().approval_id,
                &operator(),
                1,
                900,
                None,
                Utc::now(),
            )
            .expect_err("an expired approval must not be grantable");
        assert!(matches!(error, VigilError::InvalidRequest(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_decided_approval_cannot_be_decided_again() {
        let (root, store, session) = active_session();
        let created = ask(&store, &session, "/usr/bin/uname");
        let id = &created.request().approval_id;
        store
            .grant_approval(id, &operator(), 1, 900, None, Utc::now())
            .expect("grant");
        assert!(store
            .grant_approval(id, &operator(), 1, 900, None, Utc::now())
            .is_err());
        assert!(store
            .deny_approval(id, &operator(), None, Utc::now())
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Structural, not behavioural: no broker can call the grant path, because no broker can
    /// build the `ApproverIdentity` it requires. This checks the property that makes that
    /// true, so a refactor that adds a broker-reachable constructor fails here.
    ///
    /// This is defence in depth. It is not a trust boundary — see the module documentation.
    #[test]
    fn no_broker_module_can_reach_the_grant_path() {
        let sources = [
            ("broker.rs", include_str!("broker.rs")),
            ("process_broker.rs", include_str!("process_broker.rs")),
            ("network_broker.rs", include_str!("network_broker.rs")),
            ("secret_broker.rs", include_str!("secret_broker.rs")),
            ("authorize.rs", include_str!("authorize.rs")),
        ];
        for (name, source) in sources {
            for forbidden in [
                "grant_approval",
                "deny_approval",
                "ApproverIdentity",
                "issue_lease_in_transaction",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{name} references `{forbidden}`; a brokered agent request must not be \
                     able to reach the human decision path"
                );
            }
        }
    }

    #[test]
    fn an_approver_identity_rejects_junk() {
        assert!(ApproverIdentity::from_cli_operator("operator-1").is_ok());
        assert!(ApproverIdentity::from_cli_operator("ops@example.com").is_ok());
        assert!(ApproverIdentity::from_cli_operator("").is_err());
        assert!(ApproverIdentity::from_cli_operator("   ").is_err());
        assert!(ApproverIdentity::from_cli_operator("bad identity").is_err());
        assert!(ApproverIdentity::from_cli_operator(&"a".repeat(129)).is_err());
    }

    #[test]
    fn a_fingerprint_binds_all_three_of_session_action_and_resource() {
        let base = fingerprint("ags_1", LocalAction::FsDelete, "/w/a").expect("fingerprint");
        assert_ne!(
            base,
            fingerprint("ags_2", LocalAction::FsDelete, "/w/a").expect("fingerprint")
        );
        assert_ne!(
            base,
            fingerprint("ags_1", LocalAction::FsWrite, "/w/a").expect("fingerprint")
        );
        assert_ne!(
            base,
            fingerprint("ags_1", LocalAction::FsDelete, "/w/b").expect("fingerprint")
        );
        assert_eq!(
            base,
            fingerprint("ags_1", LocalAction::FsDelete, "/w/a").expect("fingerprint")
        );
    }
}
