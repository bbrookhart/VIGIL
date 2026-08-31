//! Deterministic, explainable session risk.
//!
//! Risk is not one opaque number. Every signal names the dimension it loads and the reason it
//! fired, and the aggregate state is a documented threshold function over those dimensions —
//! readable, reproducible, and arguable. There is no model here to be unable to explain.
//!
//! Risk is monotone within a session: `record_signal` can raise the state and can never lower
//! it. That costs something real — a session that trips one signal stays degraded until it
//! ends — and it is worth it, because the alternative is an agent with a way to reduce its
//! own risk.

use crate::{LocalStore, RiskState};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vigil_common::{Result, VigilError};

/// The security dimensions a signal can load.
///
/// Keeping these separate is the point: "this session read a credential" and "this session
/// opened an unexpected destination" are different facts and stay different facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDimension {
    CredentialAccess,
    Exfiltration,
    DestructiveBehavior,
    Persistence,
    PrivilegeEscalation,
    PolicyEvasion,
    ProcessAnomaly,
    NetworkAnomaly,
    CapabilityAnomaly,
    ToolAnomaly,
    DeceptionInteraction,
    IntentExecutionMismatch,
}

impl RiskDimension {
    pub const ALL: [Self; 12] = [
        Self::CredentialAccess,
        Self::Exfiltration,
        Self::DestructiveBehavior,
        Self::Persistence,
        Self::PrivilegeEscalation,
        Self::PolicyEvasion,
        Self::ProcessAnomaly,
        Self::NetworkAnomaly,
        Self::CapabilityAnomaly,
        Self::ToolAnomaly,
        Self::DeceptionInteraction,
        Self::IntentExecutionMismatch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialAccess => "credential_access",
            Self::Exfiltration => "exfiltration",
            Self::DestructiveBehavior => "destructive_behavior",
            Self::Persistence => "persistence",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::PolicyEvasion => "policy_evasion",
            Self::ProcessAnomaly => "process_anomaly",
            Self::NetworkAnomaly => "network_anomaly",
            Self::CapabilityAnomaly => "capability_anomaly",
            Self::ToolAnomaly => "tool_anomaly",
            Self::DeceptionInteraction => "deception_interaction",
            Self::IntentExecutionMismatch => "intent_execution_mismatch",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|dimension| dimension.as_str() == value)
            .ok_or_else(|| {
                VigilError::Serialization(format!(
                    "database contains unknown risk dimension `{value}`"
                ))
            })
    }
}

/// The largest weight one signal may carry.
///
/// A single observation should not be able to quarantine a session on its own unless it is
/// deliberately given the maximum, so callers must state a bounded weight rather than an
/// arbitrary one.
pub const MAX_SIGNAL_WEIGHT: u32 = 100;

/// Per-dimension score at which the aggregate reaches each state.
const ELEVATED_AT: u32 = 20;
const RESTRICTED_AT: u32 = 40;
const CONTAINED_AT: u32 = 60;
const QUARANTINED_AT: u32 = 80;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskTransition {
    pub id: String,
    pub session_id: String,
    pub at: DateTime<Utc>,
    pub previous_state: RiskState,
    pub new_state: RiskState,
    pub triggering_signals: Vec<String>,
}

/// The explainable view of one session's risk: the state, and every dimension behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub state: RiskState,
    pub dimensions: Vec<DimensionScore>,
    pub transitions: Vec<RiskTransition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionScore {
    pub dimension: RiskDimension,
    pub score: u32,
}

/// Derive the aggregate state from per-dimension scores.
///
/// The rule, in full:
///
/// - any dimension at or above 80 → `QUARANTINED`
/// - any at or above 60, or two at or above 40 → `CONTAINED`
/// - any at or above 40, or three at or above 20 → `RESTRICTED`
/// - any at or above 20 → `ELEVATED`
/// - otherwise → `NORMAL`
///
/// Scores are not summed across dimensions. One dimension going far is treated as worse than
/// several dimensions each moving slightly, because a session doing one alarming thing
/// repeatedly is a clearer signal than a session doing many ordinary things.
pub fn aggregate_state(scores: &BTreeMap<RiskDimension, u32>) -> RiskState {
    let at_or_above = |threshold: u32| scores.values().filter(|score| **score >= threshold).count();

    if at_or_above(QUARANTINED_AT) >= 1 {
        RiskState::Quarantined
    } else if at_or_above(CONTAINED_AT) >= 1 || at_or_above(RESTRICTED_AT) >= 2 {
        RiskState::Contained
    } else if at_or_above(RESTRICTED_AT) >= 1 || at_or_above(ELEVATED_AT) >= 3 {
        RiskState::Restricted
    } else if at_or_above(ELEVATED_AT) >= 1 {
        RiskState::Elevated
    } else {
        RiskState::Normal
    }
}

impl LocalStore {
    /// Record one risk signal and re-derive the session's state.
    ///
    /// Returns the state after the signal. If the state rose, a transition row is written and
    /// any lease-revoking state revokes the session's outstanding leases in the same
    /// transaction, so a contained session cannot be raced by a lease consumed a moment later.
    pub fn record_risk_signal(
        &self,
        session_id: &str,
        dimension: RiskDimension,
        weight: u32,
        source_event_id: Option<&str>,
        note: &str,
    ) -> Result<RiskState> {
        if weight == 0 || weight > MAX_SIGNAL_WEIGHT {
            return Err(VigilError::InvalidValue {
                field: "weight",
                reason: format!("risk signal weight must be within 1..={MAX_SIGNAL_WEIGHT}"),
            });
        }
        let note = vigil_common::redact::single_line_excerpt(note, 500);
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;

        let previous_state = read_session_risk(&transaction, session_id)?;
        let signal_id = format!("rsig_{}", uuid::Uuid::new_v4().simple());
        transaction
            .execute(
                "INSERT INTO risk_signals
                 (id, session_id, at, dimension, weight, source_event_id, note)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    signal_id,
                    session_id,
                    Utc::now().to_rfc3339(),
                    dimension.as_str(),
                    weight,
                    source_event_id,
                    note,
                ],
            )
            .map_err(super::store::storage_error)?;

        let scores = read_scores(&transaction, session_id)?;
        // Monotone: the derived state is a floor, never a ceiling.
        let new_state = aggregate_state(&scores).max(previous_state);
        if new_state != previous_state {
            transaction
                .execute(
                    "INSERT INTO risk_transitions
                     (id, session_id, at, previous_state, new_state, triggering_signals_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        format!("rtrn_{}", uuid::Uuid::new_v4().simple()),
                        session_id,
                        Utc::now().to_rfc3339(),
                        previous_state.as_str(),
                        new_state.as_str(),
                        serde_json::to_string(&[&signal_id])?,
                    ],
                )
                .map_err(super::store::storage_error)?;
            transaction
                .execute(
                    "UPDATE sessions SET risk_state = ?1 WHERE id = ?2",
                    params![new_state.as_str(), session_id],
                )
                .map_err(super::store::storage_error)?;
            if new_state.revokes_leases() {
                crate::lease::revoke_session_leases_in_transaction(
                    &transaction,
                    session_id,
                    &format!("session risk reached {}", new_state.as_str()),
                )?;
            }
        }
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(new_state)
    }

    /// Raise a session directly to a risk state, for a response action.
    ///
    /// This is the one path that sets a state rather than deriving it from signals, and it is
    /// still monotone: a target at or below the current state changes nothing. It exists so an
    /// operator containing a session does not have to reverse-engineer which signals would add
    /// up to the state they want.
    pub fn escalate_risk_to(
        &self,
        session_id: &str,
        target: RiskState,
        reason: &str,
    ) -> Result<RiskState> {
        let reason = vigil_common::redact::single_line_excerpt(reason, 500);
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let previous_state = read_session_risk(&transaction, session_id)?;
        if target <= previous_state {
            transaction.commit().map_err(super::store::storage_error)?;
            return Ok(previous_state);
        }
        transaction
            .execute(
                "INSERT INTO risk_transitions
                 (id, session_id, at, previous_state, new_state, triggering_signals_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    format!("rtrn_{}", uuid::Uuid::new_v4().simple()),
                    session_id,
                    Utc::now().to_rfc3339(),
                    previous_state.as_str(),
                    target.as_str(),
                    // Same shape as a signal-driven transition, so `risk_assessment` reads
                    // both kinds back without a special case.
                    serde_json::to_string(&[format!("response: {reason}")])?,
                ],
            )
            .map_err(super::store::storage_error)?;
        transaction
            .execute(
                "UPDATE sessions SET risk_state = ?1 WHERE id = ?2",
                params![target.as_str(), session_id],
            )
            .map_err(super::store::storage_error)?;
        if target.revokes_leases() {
            crate::lease::revoke_session_leases_in_transaction(&transaction, session_id, &reason)?;
        }
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(target)
    }

    /// The current risk state of a session.
    pub fn session_risk_state(&self, session_id: &str) -> Result<RiskState> {
        let state: Option<String> = self
            .connection
            .query_row(
                "SELECT risk_state FROM sessions WHERE id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::store::storage_error)?;
        state
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?
            .parse()
    }

    /// The state plus every contributing dimension and transition.
    pub fn risk_assessment(&self, session_id: &str) -> Result<RiskAssessment> {
        let state = self.session_risk_state(session_id)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT dimension, SUM(weight) FROM risk_signals
                 WHERE session_id = ?1 GROUP BY dimension ORDER BY dimension",
            )
            .map_err(super::store::storage_error)?;
        let dimensions = statement
            .query_map([session_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        let dimensions = dimensions
            .into_iter()
            .map(|(dimension, score)| {
                Ok(DimensionScore {
                    dimension: RiskDimension::parse(&dimension)?,
                    score: clamp_score(score),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        drop(statement);

        let mut statement = self
            .connection
            .prepare(
                "SELECT id, session_id, at, previous_state, new_state, triggering_signals_json
                 FROM risk_transitions WHERE session_id = ?1 ORDER BY at, id",
            )
            .map_err(super::store::storage_error)?;
        let transitions = statement
            .query_map([session_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        let transitions = transitions
            .into_iter()
            .map(|(id, session, at, previous, new, signals)| {
                Ok(RiskTransition {
                    id,
                    session_id: session,
                    at: DateTime::parse_from_rfc3339(&at)
                        .map(|value| value.with_timezone(&Utc))
                        .map_err(|error| VigilError::Serialization(error.to_string()))?,
                    previous_state: previous.parse()?,
                    new_state: new.parse()?,
                    triggering_signals: serde_json::from_str(&signals)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(RiskAssessment {
            state,
            dimensions,
            transitions,
        })
    }
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

fn read_scores(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> Result<BTreeMap<RiskDimension, u32>> {
    let mut statement = transaction
        .prepare(
            "SELECT dimension, SUM(weight) FROM risk_signals
             WHERE session_id = ?1 GROUP BY dimension",
        )
        .map_err(super::store::storage_error)?;
    let rows = statement
        .query_map([session_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(super::store::storage_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(super::store::storage_error)?;
    let mut scores = BTreeMap::new();
    for (dimension, score) in rows {
        scores.insert(RiskDimension::parse(&dimension)?, clamp_score(score));
    }
    Ok(scores)
}

/// Saturate rather than overflow. A dimension past the top threshold is already maximal, so
/// the exact value above it carries no further authority decision.
fn clamp_score(score: i64) -> u32 {
    u32::try_from(score.max(0)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scores(pairs: &[(RiskDimension, u32)]) -> BTreeMap<RiskDimension, u32> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn an_empty_session_is_normal() {
        assert_eq!(aggregate_state(&scores(&[])), RiskState::Normal);
    }

    #[test]
    fn thresholds_match_the_documented_rule() {
        use RiskDimension as D;
        assert_eq!(
            aggregate_state(&scores(&[(D::CredentialAccess, 19)])),
            RiskState::Normal
        );
        assert_eq!(
            aggregate_state(&scores(&[(D::CredentialAccess, 20)])),
            RiskState::Elevated
        );
        assert_eq!(
            aggregate_state(&scores(&[(D::CredentialAccess, 40)])),
            RiskState::Restricted
        );
        assert_eq!(
            aggregate_state(&scores(&[(D::CredentialAccess, 60)])),
            RiskState::Contained
        );
        assert_eq!(
            aggregate_state(&scores(&[(D::CredentialAccess, 80)])),
            RiskState::Quarantined
        );
    }

    #[test]
    fn breadth_escalates_without_any_single_dimension_doing_so() {
        use RiskDimension as D;
        // Three dimensions at the elevated threshold reach Restricted even though no single
        // dimension is anywhere near the Restricted threshold on its own.
        assert_eq!(
            aggregate_state(&scores(&[
                (D::CredentialAccess, 20),
                (D::NetworkAnomaly, 20),
                (D::ProcessAnomaly, 20),
            ])),
            RiskState::Restricted
        );
        // Two at the Restricted threshold reach Contained.
        assert_eq!(
            aggregate_state(&scores(
                &[(D::CredentialAccess, 40), (D::Exfiltration, 40),]
            )),
            RiskState::Contained
        );
    }

    #[test]
    fn dimensions_are_not_summed_together() {
        use RiskDimension as D;
        // Were these summed, 79 + 79 would quarantine. They are separate facts about
        // separate behaviours and neither one alone justifies quarantine.
        let state = aggregate_state(&scores(&[(D::ToolAnomaly, 79), (D::NetworkAnomaly, 79)]));
        assert_eq!(state, RiskState::Contained);
    }
}
