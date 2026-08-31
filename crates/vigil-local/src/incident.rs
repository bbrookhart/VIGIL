//! Incidents and the responses applied to them.
//!
//! An incident is opened when a session's standing changes enough to warrant one: it reaches a
//! containing risk state, or a critical detection fires. One session has at most one open
//! incident — a second alarming thing joins the investigation already under way rather than
//! starting a rival one, which a partial unique index enforces rather than the code.
//!
//! Responses are explicit, named, and idempotent. Re-applying one reports `already_applied`
//! rather than doing it twice, because an operator retrying a command under pressure must not
//! be punished for it. Every attempt is recorded, including the ones that were refused.

use crate::detection::Severity;
use crate::{LocalStore, RiskState, SessionStatus};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use vigil_common::{Result, VigilError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Sealed,
}

impl IncidentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "open" => Ok(Self::Open),
            "sealed" => Ok(Self::Sealed),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown incident status `{value}`"
            ))),
        }
    }
}

/// A containment or investigation action taken against a session.
///
/// Deliberately absent: `TERMINATE_PROCESS_TREE`. Killing a process requires being certain the
/// PID still belongs to the process VIGIL recorded, and on macOS that certainty needs either
/// unsafe process-info FFI or an Endpoint Security client — neither of which this build has.
/// Guessing would mean killing an unrelated process belonging to the user, which is a worse
/// outcome than not containing an agent. See `docs/security/FAIL_CLOSED_MATRIX.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseAction {
    /// Revoke every active capability lease the session holds.
    RevokeCapabilities,
    /// Raise the session to `CONTAINED`: reads only, leases revoked.
    RestrictSession,
    /// Raise the session to `QUARANTINED`: every brokered capability denied.
    QuarantineSession,
    /// End the session and freeze its evidence.
    SealSession,
}

impl ResponseAction {
    pub const ALL: [Self; 4] = [
        Self::RevokeCapabilities,
        Self::RestrictSession,
        Self::QuarantineSession,
        Self::SealSession,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RevokeCapabilities => "REVOKE_CAPABILITIES",
            Self::RestrictSession => "RESTRICT_SESSION",
            Self::QuarantineSession => "QUARANTINE_SESSION",
            Self::SealSession => "SEAL_SESSION",
        }
    }
}

impl std::str::FromStr for ResponseAction {
    type Err = VigilError;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_str() == value)
            .ok_or_else(|| VigilError::InvalidValue {
                field: "action",
                reason: format!("unknown response action `{value}`"),
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseOutcome {
    Applied,
    AlreadyApplied,
    Refused,
}

impl ResponseOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadyApplied => "already_applied",
            Self::Refused => "refused",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "applied" => Ok(Self::Applied),
            "already_applied" => Ok(Self::AlreadyApplied),
            "refused" => Ok(Self::Refused),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown response outcome `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub session_id: String,
    pub opened_at: DateTime<Utc>,
    pub sealed_at: Option<DateTime<Utc>>,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub reason: String,
    pub risk_state_at_open: RiskState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentResponse {
    pub id: String,
    pub incident_id: String,
    pub at: DateTime<Utc>,
    pub action: ResponseAction,
    pub outcome: ResponseOutcome,
    pub detail: serde_json::Value,
}

impl LocalStore {
    /// Open an incident for a session, or return the one already open.
    ///
    /// Raising the severity of an already-open incident is allowed; lowering it is not, for the
    /// same reason risk is monotone — an incident should not look less serious because a milder
    /// thing happened after a worse one.
    pub fn open_incident(
        &self,
        session_id: &str,
        severity: Severity,
        reason: &str,
    ) -> Result<Incident> {
        let reason = vigil_common::redact::single_line_excerpt(reason, 500);
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let existing = read_open_incident(&transaction, session_id)?;
        if let Some(existing) = existing {
            if severity > existing.severity {
                // Record what raised it, not only that it rose. An incident labelled with the
                // first thing that happened but carrying the severity of a later, worse thing
                // reads as a mislabelling to whoever picks it up.
                let reason = vigil_common::redact::single_line_excerpt(
                    &format!("{}; escalated by: {reason}", existing.reason),
                    500,
                );
                transaction
                    .execute(
                        "UPDATE incidents SET severity = ?1, reason = ?2 WHERE incident_id = ?3",
                        params![severity.as_str(), reason, existing.incident_id],
                    )
                    .map_err(super::store::storage_error)?;
            }
            let updated = read_incident(&transaction, &existing.incident_id)?;
            transaction.commit().map_err(super::store::storage_error)?;
            return Ok(updated);
        }

        let risk_state: String = transaction
            .query_row(
                "SELECT risk_state FROM sessions WHERE id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::store::storage_error)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        let incident = Incident {
            incident_id: format!("inc_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.to_string(),
            opened_at: Utc::now(),
            sealed_at: None,
            severity,
            status: IncidentStatus::Open,
            reason,
            risk_state_at_open: risk_state.parse()?,
        };
        transaction
            .execute(
                "INSERT INTO incidents
                 (incident_id, session_id, opened_at, severity, status, reason,
                  risk_state_at_open)
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6)",
                params![
                    incident.incident_id,
                    incident.session_id,
                    incident.opened_at.to_rfc3339(),
                    incident.severity.as_str(),
                    incident.reason,
                    incident.risk_state_at_open.as_str(),
                ],
            )
            .map_err(super::store::storage_error)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(incident)
    }

    /// Attach every unattached detection for the session to an incident.
    pub fn attach_detections(&self, incident_id: &str, session_id: &str) -> Result<usize> {
        let attached = self
            .connection
            .execute(
                "UPDATE detections SET incident_id = ?1
                 WHERE session_id = ?2 AND incident_id IS NULL",
                params![incident_id, session_id],
            )
            .map_err(super::store::storage_error)?;
        Ok(attached)
    }

    /// Apply one response action to an incident's session.
    ///
    /// Idempotent: an action whose effect is already in place records `already_applied` and
    /// changes nothing.
    pub fn apply_response(
        &self,
        incident_id: &str,
        action: ResponseAction,
    ) -> Result<IncidentResponse> {
        let incident = self
            .get_incident(incident_id)?
            .ok_or_else(|| VigilError::NotFound(format!("incident {incident_id}")))?;
        let session = self
            .get_session(&incident.session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        let risk = self.session_risk_state(&incident.session_id)?;

        let (outcome, detail) = match action {
            ResponseAction::RevokeCapabilities => {
                let revoked = self.revoke_session_leases(
                    &incident.session_id,
                    &format!("incident {incident_id}"),
                )?;
                (
                    if revoked == 0 {
                        ResponseOutcome::AlreadyApplied
                    } else {
                        ResponseOutcome::Applied
                    },
                    serde_json::json!({ "leases_revoked": revoked }),
                )
            }
            ResponseAction::RestrictSession | ResponseAction::QuarantineSession => {
                let target = if action == ResponseAction::QuarantineSession {
                    RiskState::Quarantined
                } else {
                    RiskState::Contained
                };
                if risk >= target {
                    (
                        ResponseOutcome::AlreadyApplied,
                        serde_json::json!({ "risk_state": risk.as_str() }),
                    )
                } else {
                    let reached = self.escalate_risk_to(
                        &incident.session_id,
                        target,
                        &format!("incident {incident_id} response {}", action.as_str()),
                    )?;
                    (
                        ResponseOutcome::Applied,
                        serde_json::json!({
                            "risk_state_before": risk.as_str(),
                            "risk_state": reached.as_str(),
                        }),
                    )
                }
            }
            ResponseAction::SealSession => match session.status {
                SessionStatus::Sealed => (
                    ResponseOutcome::AlreadyApplied,
                    serde_json::json!({ "status": "sealed" }),
                ),
                _ => {
                    let risk = self.session_risk_state(&incident.session_id)?;
                    self.seal_session(&incident.session_id, risk.as_str())?;
                    (
                        ResponseOutcome::Applied,
                        serde_json::json!({ "status": "sealed", "risk_state": risk.as_str() }),
                    )
                }
            },
        };

        let response = IncidentResponse {
            id: format!("rsp_{}", uuid::Uuid::new_v4().simple()),
            incident_id: incident_id.to_string(),
            at: Utc::now(),
            action,
            outcome,
            detail,
        };
        self.connection
            .execute(
                "INSERT INTO incident_responses (id, incident_id, at, action, outcome, detail_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    response.id,
                    response.incident_id,
                    response.at.to_rfc3339(),
                    response.action.as_str(),
                    response.outcome.as_str(),
                    serde_json::to_string(&response.detail)?,
                ],
            )
            .map_err(super::store::storage_error)?;
        self.append_event(
            &incident.session_id,
            "incident",
            "incident.response",
            Some(match outcome {
                ResponseOutcome::Applied => "APPLIED",
                ResponseOutcome::AlreadyApplied => "ALREADY_APPLIED",
                ResponseOutcome::Refused => "REFUSED",
            }),
            incident_id,
            &serde_json::json!({
                "incident_id": incident_id,
                "action": response.action.as_str(),
                "detail": response.detail,
            }),
        )?;
        Ok(response)
    }

    /// Seal an incident. Idempotent.
    pub fn seal_incident(&self, incident_id: &str) -> Result<Incident> {
        self.connection
            .execute(
                "UPDATE incidents SET status = 'sealed', sealed_at = ?1
                 WHERE incident_id = ?2 AND status = 'open'",
                params![Utc::now().to_rfc3339(), incident_id],
            )
            .map_err(super::store::storage_error)?;
        self.get_incident(incident_id)?
            .ok_or_else(|| VigilError::NotFound(format!("incident {incident_id}")))
    }

    pub fn get_incident(&self, incident_id: &str) -> Result<Option<Incident>> {
        let row = self
            .connection
            .query_row(INCIDENT_COLUMNS, [incident_id], incident_from_row)
            .optional()
            .map_err(super::store::storage_error)?;
        row.transpose()
    }

    pub fn list_incidents(&self, limit: usize) -> Result<Vec<Incident>> {
        let limit = i64::try_from(limit.min(1000)).unwrap_or(1000);
        let mut statement = self
            .connection
            .prepare(
                "SELECT incident_id, session_id, opened_at, sealed_at, severity, status, reason,
                        risk_state_at_open
                 FROM incidents ORDER BY opened_at DESC, incident_id LIMIT ?1",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([limit], incident_from_row)
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }

    pub fn responses_for_incident(&self, incident_id: &str) -> Result<Vec<IncidentResponse>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, incident_id, at, action, outcome, detail_json
                 FROM incident_responses WHERE incident_id = ?1 ORDER BY at, id",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([incident_id], |row| {
                let id: String = row.get(0)?;
                let incident_id: String = row.get(1)?;
                let at: String = row.get(2)?;
                let action: String = row.get(3)?;
                let outcome: String = row.get(4)?;
                let detail: String = row.get(5)?;
                Ok((|| {
                    Ok(IncidentResponse {
                        id,
                        incident_id,
                        at: parse_time(&at)?,
                        action: action.parse()?,
                        outcome: ResponseOutcome::parse(&outcome)?,
                        detail: serde_json::from_str(&detail)?,
                    })
                })())
            })
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }
}

const INCIDENT_COLUMNS: &str =
    "SELECT incident_id, session_id, opened_at, sealed_at, severity, status, reason,
            risk_state_at_open
     FROM incidents WHERE incident_id = ?1";

fn read_incident(transaction: &Transaction<'_>, incident_id: &str) -> Result<Incident> {
    transaction
        .query_row(INCIDENT_COLUMNS, [incident_id], incident_from_row)
        .optional()
        .map_err(super::store::storage_error)?
        .ok_or_else(|| VigilError::NotFound(format!("incident {incident_id}")))?
}

fn read_open_incident(transaction: &Transaction<'_>, session_id: &str) -> Result<Option<Incident>> {
    let row = transaction
        .query_row(
            "SELECT incident_id, session_id, opened_at, sealed_at, severity, status, reason,
                    risk_state_at_open
             FROM incidents WHERE session_id = ?1 AND status = 'open'",
            [session_id],
            incident_from_row,
        )
        .optional()
        .map_err(super::store::storage_error)?;
    row.transpose()
}

fn incident_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Incident>> {
    let incident_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let opened_at: String = row.get(2)?;
    let sealed_at: Option<String> = row.get(3)?;
    let severity: String = row.get(4)?;
    let status: String = row.get(5)?;
    let reason: String = row.get(6)?;
    let risk_state: String = row.get(7)?;

    Ok((|| {
        Ok(Incident {
            incident_id,
            session_id,
            opened_at: parse_time(&opened_at)?,
            sealed_at: sealed_at.as_deref().map(parse_time).transpose()?,
            severity: crate::detection::parse_severity(&severity)?,
            status: IncidentStatus::parse(&status)?,
            reason,
            risk_state_at_open: risk_state.parse()?,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            VigilError::Serialization(format!("unparsable incident timestamp: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NewSession, RiskDimension};
    use std::path::PathBuf;

    fn active_session() -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-incident-{}", uuid::Uuid::new_v4()));
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

    #[test]
    fn a_session_has_at_most_one_open_incident() {
        let (root, store, session) = active_session();
        let first = store
            .open_incident(&session, Severity::Medium, "first")
            .expect("open");
        let second = store
            .open_incident(&session, Severity::Medium, "second")
            .expect("open again");
        assert_eq!(
            first.incident_id, second.incident_id,
            "a second alarming thing must join the open investigation"
        );
        assert_eq!(store.list_incidents(100).expect("list").len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Severity is monotone for the same reason risk is: an incident must not look milder
    /// because something less serious happened after something worse.
    #[test]
    fn incident_severity_rises_but_never_falls() {
        let (root, store, session) = active_session();
        store
            .open_incident(&session, Severity::Low, "low")
            .expect("open");
        let raised = store
            .open_incident(&session, Severity::Critical, "critical")
            .expect("raise");
        assert_eq!(raised.severity, Severity::Critical);
        let lowered = store
            .open_incident(&session, Severity::Info, "info")
            .expect("lower");
        assert_eq!(lowered.severity, Severity::Critical);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn responses_are_idempotent_and_every_attempt_is_recorded() {
        let (root, store, session) = active_session();
        let incident = store
            .open_incident(&session, Severity::High, "test")
            .expect("open");

        let first = store
            .apply_response(&incident.incident_id, ResponseAction::QuarantineSession)
            .expect("quarantine");
        assert_eq!(first.outcome, ResponseOutcome::Applied);
        assert_eq!(
            store.session_risk_state(&session).expect("risk"),
            RiskState::Quarantined
        );

        let again = store
            .apply_response(&incident.incident_id, ResponseAction::QuarantineSession)
            .expect("quarantine again");
        assert_eq!(again.outcome, ResponseOutcome::AlreadyApplied);

        // Both attempts are on the record, including the one that changed nothing.
        let responses = store
            .responses_for_incident(&incident.incident_id)
            .expect("responses");
        assert_eq!(responses.len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Containment must not be reversible by a milder response applied afterwards.
    #[test]
    fn restricting_a_quarantined_session_cannot_walk_it_back() {
        let (root, store, session) = active_session();
        let incident = store
            .open_incident(&session, Severity::High, "test")
            .expect("open");
        store
            .apply_response(&incident.incident_id, ResponseAction::QuarantineSession)
            .expect("quarantine");
        let response = store
            .apply_response(&incident.incident_id, ResponseAction::RestrictSession)
            .expect("restrict");
        assert_eq!(response.outcome, ResponseOutcome::AlreadyApplied);
        assert_eq!(
            store.session_risk_state(&session).expect("risk"),
            RiskState::Quarantined
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sealing_an_incident_is_idempotent() {
        let (root, store, session) = active_session();
        let incident = store
            .open_incident(&session, Severity::High, "test")
            .expect("open");
        let sealed = store.seal_incident(&incident.incident_id).expect("seal");
        assert_eq!(sealed.status, IncidentStatus::Sealed);
        assert!(sealed.sealed_at.is_some());
        let again = store.seal_incident(&incident.incident_id).expect("seal");
        assert_eq!(again.sealed_at, sealed.sealed_at);

        // A sealed incident frees the session to open a new one if something else happens.
        let fresh = store
            .open_incident(&session, Severity::Low, "later")
            .expect("open");
        assert_ne!(fresh.incident_id, incident.incident_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn detections_attach_to_the_incident_investigating_them() {
        let (root, store, session) = active_session();
        let rule = crate::detection::rule_for_label("credential_access").expect("rule");
        store
            .record_detection(&session, rule, serde_json::json!({}), None)
            .expect("detection");
        let incident = store
            .open_incident(&session, Severity::High, "test")
            .expect("open");
        assert_eq!(
            store
                .attach_detections(&incident.incident_id, &session)
                .expect("attach"),
            1
        );
        let attached = store.detections_for_session(&session).expect("detections");
        assert_eq!(
            attached[0].incident_id.as_deref(),
            Some(incident.incident_id.as_str())
        );
        // Attaching again claims nothing new.
        assert_eq!(
            store
                .attach_detections(&incident.incident_id, &session)
                .expect("attach"),
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A response is a security-relevant action and must leave the same evidence trail as a
    /// broker decision, on the same hash-chained log.
    #[test]
    fn a_response_appends_a_chained_event() {
        let (root, store, session) = active_session();
        let incident = store
            .open_incident(&session, Severity::High, "test")
            .expect("open");
        store
            .apply_response(&incident.incident_id, ResponseAction::RevokeCapabilities)
            .expect("revoke");
        let events = store.events_for_session(&session).expect("events");
        let response_event = events
            .iter()
            .find(|event| event.action == "incident.response")
            .expect("response event");
        assert!(response_event.chain_hash.is_some());
        assert!(store.verify_event_chain().expect("verify").verified);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn risk_escalation_is_monotone_even_when_an_operator_asks_for_less() {
        let (root, store, session) = active_session();
        store
            .record_risk_signal(&session, RiskDimension::CredentialAccess, 60, None, "test")
            .expect("signal");
        assert_eq!(
            store
                .escalate_risk_to(&session, RiskState::Elevated, "operator asked for less")
                .expect("escalate"),
            RiskState::Contained
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
