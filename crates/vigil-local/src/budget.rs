//! Durable blast-radius reservations.
//!
//! Every reservation checks and increments all affected counters inside one SQLite
//! `BEGIN IMMEDIATE` transaction. Concurrent callers therefore cannot both spend the last
//! unit. A reservation that cannot be reconciled remains reserved, reducing authority in the
//! safe direction.

use crate::{LocalProfile, LocalStore, SessionStatus};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vigil_common::{Result, VigilError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    FileReads,
    FileCreates,
    FileWrites,
    FileDeletes,
    FileRenames,
    TotalWriteBytes,
    MaxSingleWriteBytes,
    ProcessExecutions,
    NetworkConnections,
    NetworkDestinations,
    BrokeredSecretUses,
    PrivilegedActions,
    PersistenceChanges,
    GitCommits,
    GitPushes,
}

impl BudgetDimension {
    pub const ALL: [Self; 15] = [
        Self::FileReads,
        Self::FileCreates,
        Self::FileWrites,
        Self::FileDeletes,
        Self::FileRenames,
        Self::TotalWriteBytes,
        Self::MaxSingleWriteBytes,
        Self::ProcessExecutions,
        Self::NetworkConnections,
        Self::NetworkDestinations,
        Self::BrokeredSecretUses,
        Self::PrivilegedActions,
        Self::PersistenceChanges,
        Self::GitCommits,
        Self::GitPushes,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileReads => "file_reads",
            Self::FileCreates => "file_creates",
            Self::FileWrites => "file_writes",
            Self::FileDeletes => "file_deletes",
            Self::FileRenames => "file_renames",
            Self::TotalWriteBytes => "total_write_bytes",
            Self::MaxSingleWriteBytes => "max_single_write_bytes",
            Self::ProcessExecutions => "process_executions",
            Self::NetworkConnections => "network_connections",
            Self::NetworkDestinations => "network_destinations",
            Self::BrokeredSecretUses => "brokered_secret_uses",
            Self::PrivilegedActions => "privileged_actions",
            Self::PersistenceChanges => "persistence_changes",
            Self::GitCommits => "git_commits",
            Self::GitPushes => "git_pushes",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|dimension| dimension.as_str() == value)
            .ok_or_else(|| {
                VigilError::Serialization(format!(
                    "database contains unknown budget dimension `{value}`"
                ))
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetCharge {
    pub dimension: BudgetDimension,
    pub amount: u64,
}

impl BudgetCharge {
    pub const fn new(dimension: BudgetDimension, amount: u64) -> Self {
        Self { dimension, amount }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Pending,
    Committed,
    Refunded,
}

impl ReservationStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Refunded => "refunded",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "committed" => Ok(Self::Committed),
            "refunded" => Ok(Self::Refunded),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown reservation status `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReservation {
    pub id: String,
    pub session_id: String,
    pub correlation_id: String,
    pub created_at: DateTime<Utc>,
    pub status: ReservationStatus,
    pub charges: Vec<BudgetCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetCounter {
    pub dimension: BudgetDimension,
    pub limit: u64,
    pub consumed: u64,
    pub reserved: u64,
    pub remaining: u64,
}

/// The baseline limit for one profile and dimension.
pub fn budget_limit(profile: LocalProfile, dimension: BudgetDimension) -> u64 {
    use BudgetDimension as D;
    match profile {
        LocalProfile::Observe => match dimension {
            D::FileReads => 20_000,
            D::FileCreates | D::FileWrites => 1_000,
            D::FileDeletes => 100,
            D::TotalWriteBytes => 250_000_000,
            D::MaxSingleWriteBytes => 25_000_000,
            D::ProcessExecutions => 1_000,
            D::NetworkConnections => 2_000,
            D::NetworkDestinations => 100,
            D::BrokeredSecretUses => 25,
            D::PrivilegedActions | D::PersistenceChanges => 0,
            D::GitCommits => 100,
            D::GitPushes => 20,
            D::FileRenames => 500,
        },
        LocalProfile::DeveloperStandard => match dimension {
            D::FileReads => 5_000,
            D::FileCreates | D::FileWrites => 100,
            D::FileDeletes => 5,
            D::TotalWriteBytes => 25_000_000,
            D::MaxSingleWriteBytes => 5_000_000,
            D::ProcessExecutions => 150,
            D::NetworkConnections => 100,
            D::NetworkDestinations => 5,
            D::BrokeredSecretUses => 5,
            D::PrivilegedActions | D::PersistenceChanges => 0,
            D::GitCommits => 10,
            D::GitPushes => 1,
            D::FileRenames => 100,
        },
        LocalProfile::DeveloperRestricted => match dimension {
            D::FileReads => 2_000,
            D::FileCreates | D::FileWrites => 50,
            D::FileDeletes => 0,
            D::TotalWriteBytes => 10_000_000,
            D::MaxSingleWriteBytes => 2_000_000,
            D::ProcessExecutions => 50,
            D::NetworkConnections => 25,
            D::NetworkDestinations => 3,
            D::BrokeredSecretUses | D::PrivilegedActions | D::PersistenceChanges => 0,
            D::GitCommits => 5,
            D::GitPushes => 0,
            D::FileRenames => 25,
        },
        LocalProfile::Research => match dimension {
            D::FileReads => 10_000,
            D::FileCreates | D::FileWrites => 50,
            D::FileDeletes => 0,
            D::TotalWriteBytes => 10_000_000,
            D::MaxSingleWriteBytes => 2_000_000,
            D::ProcessExecutions => 100,
            D::NetworkConnections => 500,
            D::NetworkDestinations => 25,
            D::BrokeredSecretUses => 2,
            D::PrivilegedActions | D::PersistenceChanges => 0,
            D::GitCommits => 5,
            D::GitPushes => 0,
            D::FileRenames => 25,
        },
        LocalProfile::UntrustedAgent => match dimension {
            D::FileReads => 1_000,
            D::FileCreates | D::FileWrites => 25,
            D::FileDeletes => 0,
            D::TotalWriteBytes => 2_000_000,
            D::MaxSingleWriteBytes => 500_000,
            D::ProcessExecutions => 25,
            D::NetworkConnections => 20,
            D::NetworkDestinations => 2,
            D::BrokeredSecretUses | D::PrivilegedActions | D::PersistenceChanges => 0,
            D::GitCommits => 0,
            D::GitPushes => 0,
            D::FileRenames => 10,
        },
    }
}

pub(crate) fn initialize_budget_rows(
    transaction: &Transaction<'_>,
    session_id: &str,
    profile: LocalProfile,
) -> Result<()> {
    for dimension in BudgetDimension::ALL {
        let limit = to_sql_u64(budget_limit(profile, dimension), "budget limit")?;
        transaction
            .execute(
                "INSERT INTO budget_counters
                 (session_id, dimension, limit_value, consumed, reserved)
                 VALUES (?1, ?2, ?3, 0, 0)",
                params![session_id, dimension.as_str(), limit],
            )
            .map_err(super::store::storage_error)?;
    }
    Ok(())
}

impl LocalStore {
    /// Give every existing session a counter for dimensions added by a later release.
    ///
    /// A missing counter denies, which is the safe direction but an unexplained one for a
    /// session that predates the dimension. Backfilling at the session's own profile limit
    /// keeps an upgrade from silently narrowing what an in-flight session may do.
    pub(crate) fn backfill_budget_dimensions(&self, dimensions: &[BudgetDimension]) -> Result<()> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let sessions: Vec<(String, String)> = {
            let mut statement = transaction
                .prepare("SELECT id, profile FROM sessions")
                .map_err(super::store::storage_error)?;
            let rows = statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(super::store::storage_error)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(super::store::storage_error)?
        };
        for (session_id, profile) in sessions {
            let Ok(profile) = profile.parse::<LocalProfile>() else {
                // A profile this build does not recognise gets no new authority.
                continue;
            };
            for dimension in dimensions {
                let limit = to_sql_u64(budget_limit(profile, *dimension), "budget limit")?;
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO budget_counters
                         (session_id, dimension, limit_value, consumed, reserved)
                         VALUES (?1, ?2, ?3, 0, 0)",
                        params![session_id, dimension.as_str(), limit],
                    )
                    .map_err(super::store::storage_error)?;
            }
        }
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(())
    }

    /// Atomically reserve every charge or reserve none of them.
    pub fn reserve_budget(
        &self,
        session_id: &str,
        correlation_id: &str,
        charges: &[BudgetCharge],
    ) -> Result<BudgetReservation> {
        let aggregated = aggregate_charges(charges)?;
        // Acquire writer intent before reading counters so concurrent reservations
        // cannot both observe the same remaining capacity.
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        require_active_semantic_session(&transaction, session_id)?;
        let reservation =
            reserve_in_transaction(&transaction, session_id, correlation_id, &aggregated)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(reservation)
    }

    /// Atomically reserve a connection and, only for a novel committed destination, one
    /// destination unit. A pending first-use claim blocks concurrent use in the safe direction.
    pub fn reserve_network_budget(
        &self,
        session_id: &str,
        correlation_id: &str,
        destination_key: &str,
    ) -> Result<BudgetReservation> {
        if destination_key.is_empty() || destination_key.len() > 512 {
            return Err(VigilError::InvalidValue {
                field: "destination",
                reason: "destination key is empty or exceeds its bound".to_string(),
            });
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        require_active_semantic_session(&transaction, session_id)?;
        let claim: Option<String> = transaction
            .query_row(
                "SELECT status FROM network_destination_claims
                 WHERE session_id = ?1 AND destination_key = ?2",
                params![session_id, destination_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::store::storage_error)?;
        if claim.as_deref() == Some("pending") {
            return Err(VigilError::Unavailable {
                component: "network_budget",
                reason: "destination has an unreconciled first-use reservation".to_string(),
            });
        }
        let mut charges = vec![BudgetCharge::new(BudgetDimension::NetworkConnections, 1)];
        if claim.is_none() {
            charges.push(BudgetCharge::new(BudgetDimension::NetworkDestinations, 1));
        }
        let aggregated = aggregate_charges(&charges)?;
        let reservation =
            reserve_in_transaction(&transaction, session_id, correlation_id, &aggregated)?;
        if claim.is_none() {
            transaction
                .execute(
                    "INSERT INTO network_destination_claims
                     (session_id, destination_key, reservation_id, status)
                     VALUES (?1, ?2, ?3, 'pending')",
                    params![session_id, destination_key, reservation.id],
                )
                .map_err(super::store::storage_error)?;
        }
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(reservation)
    }

    pub fn commit_budget(&self, reservation_id: &str) -> Result<()> {
        self.reconcile_budget(reservation_id, ReservationStatus::Committed)
    }

    pub fn refund_budget(&self, reservation_id: &str) -> Result<()> {
        self.reconcile_budget(reservation_id, ReservationStatus::Refunded)
    }

    pub fn budget_snapshot(&self, session_id: &str) -> Result<Vec<BudgetCounter>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT dimension, limit_value, consumed, reserved
                 FROM budget_counters WHERE session_id = ?1 ORDER BY dimension",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([session_id], |row| {
                let dimension: String = row.get(0)?;
                let limit: i64 = row.get(1)?;
                let consumed: i64 = row.get(2)?;
                let reserved: i64 = row.get(3)?;
                let dimension = BudgetDimension::parse(&dimension).map_err(to_sql_error)?;
                counter_from_values(dimension, limit, consumed, reserved).map_err(to_sql_error)
            })
            .map_err(super::store::storage_error)?;
        let counters = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        if counters.is_empty() {
            return Err(VigilError::NotFound("budget for local session".to_string()));
        }
        Ok(counters)
    }

    fn reconcile_budget(&self, reservation_id: &str, target: ReservationStatus) -> Result<()> {
        if target == ReservationStatus::Pending {
            return Err(VigilError::InvalidRequest(
                "cannot reconcile a reservation to pending".to_string(),
            ));
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let current: Option<String> = transaction
            .query_row(
                "SELECT status FROM budget_reservations WHERE id = ?1",
                [reservation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::store::storage_error)?;
        let current =
            current.ok_or_else(|| VigilError::NotFound("local budget reservation".to_string()))?;
        let current = ReservationStatus::parse(&current)?;
        if current == target {
            return Ok(());
        }
        if current != ReservationStatus::Pending {
            return Err(VigilError::InvalidRequest(format!(
                "reservation is already {}",
                current.as_str()
            )));
        }
        let mut statement = transaction
            .prepare(
                "SELECT dimension, amount FROM budget_reservation_items
                 WHERE reservation_id = ?1 ORDER BY dimension",
            )
            .map_err(super::store::storage_error)?;
        let items = statement
            .query_map([reservation_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        drop(statement);
        for (dimension, amount) in items {
            let sql = if target == ReservationStatus::Committed {
                "UPDATE budget_counters
                 SET reserved = reserved - ?1, consumed = consumed + ?1
                 WHERE session_id = (SELECT session_id FROM budget_reservations WHERE id = ?2)
                   AND dimension = ?3 AND reserved >= ?1"
            } else {
                "UPDATE budget_counters SET reserved = reserved - ?1
                 WHERE session_id = (SELECT session_id FROM budget_reservations WHERE id = ?2)
                   AND dimension = ?3 AND reserved >= ?1"
            };
            let changed = transaction
                .execute(sql, params![amount, reservation_id, dimension])
                .map_err(super::store::storage_error)?;
            if changed != 1 {
                return Err(VigilError::AuditIntegrity(
                    "budget reservation accounting is inconsistent".to_string(),
                ));
            }
        }
        transaction
            .execute(
                "UPDATE budget_reservations SET status = ?1 WHERE id = ?2",
                params![target.as_str(), reservation_id],
            )
            .map_err(super::store::storage_error)?;
        if target == ReservationStatus::Committed {
            transaction
                .execute(
                    "UPDATE network_destination_claims SET status = 'committed'
                     WHERE reservation_id = ?1 AND status = 'pending'",
                    [reservation_id],
                )
                .map_err(super::store::storage_error)?;
        } else {
            transaction
                .execute(
                    "DELETE FROM network_destination_claims
                     WHERE reservation_id = ?1 AND status = 'pending'",
                    [reservation_id],
                )
                .map_err(super::store::storage_error)?;
        }
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(())
    }
}

fn aggregate_charges(charges: &[BudgetCharge]) -> Result<BTreeMap<BudgetDimension, u64>> {
    if charges.is_empty() {
        return Err(VigilError::InvalidRequest(
            "a budget reservation requires at least one charge".to_string(),
        ));
    }
    let mut aggregated: BTreeMap<BudgetDimension, u64> = BTreeMap::new();
    for charge in charges {
        if charge.amount == 0 {
            return Err(VigilError::InvalidRequest(
                "budget charge amount must be positive".to_string(),
            ));
        }
        let total = aggregated.entry(charge.dimension).or_default();
        *total = total
            .checked_add(charge.amount)
            .ok_or_else(|| VigilError::BudgetExhausted("budget charge overflow".to_string()))?;
    }
    Ok(aggregated)
}

fn reserve_in_transaction(
    transaction: &Transaction<'_>,
    session_id: &str,
    correlation_id: &str,
    aggregated: &BTreeMap<BudgetDimension, u64>,
) -> Result<BudgetReservation> {
    let mut resulting = Vec::new();
    for (dimension, amount) in aggregated {
        if *dimension == BudgetDimension::MaxSingleWriteBytes {
            return Err(VigilError::InvalidRequest(
                "max_single_write_bytes is a per-operation bound, not a consumable charge"
                    .to_string(),
            ));
        }
        let (limit, consumed, reserved): (i64, i64, i64) = transaction
            .query_row(
                "SELECT limit_value, consumed, reserved FROM budget_counters
                 WHERE session_id = ?1 AND dimension = ?2",
                params![session_id, dimension.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(super::store::storage_error)?
            .ok_or_else(|| {
                VigilError::BudgetExhausted(format!(
                    "budget `{}` is unavailable",
                    dimension.as_str()
                ))
            })?;
        let amount = to_sql_u64(*amount, "budget charge")?;
        let after = consumed
            .checked_add(reserved)
            .and_then(|value| value.checked_add(amount))
            .ok_or_else(|| VigilError::BudgetExhausted("budget overflow".to_string()))?;
        if after > limit {
            return Err(VigilError::BudgetExhausted(format!(
                "{} exhausted: limit={limit}, consumed={consumed}, reserved={reserved}, \
                 requested={amount}",
                dimension.as_str()
            )));
        }
        transaction
            .execute(
                "UPDATE budget_counters SET reserved = reserved + ?1
                 WHERE session_id = ?2 AND dimension = ?3",
                params![amount, session_id, dimension.as_str()],
            )
            .map_err(super::store::storage_error)?;
        resulting.push(counter_from_values(
            *dimension,
            limit,
            consumed,
            reserved + amount,
        )?);
    }

    let reservation = BudgetReservation {
        id: format!("bres_{}", uuid::Uuid::new_v4().simple()),
        session_id: session_id.to_string(),
        correlation_id: correlation_id.to_string(),
        created_at: Utc::now(),
        status: ReservationStatus::Pending,
        charges: resulting,
    };
    transaction
        .execute(
            "INSERT INTO budget_reservations
             (id, session_id, correlation_id, created_at, status)
             VALUES (?1, ?2, ?3, ?4, 'pending')",
            params![
                reservation.id,
                reservation.session_id,
                reservation.correlation_id,
                reservation.created_at.to_rfc3339(),
            ],
        )
        .map_err(super::store::storage_error)?;
    for (dimension, amount) in aggregated {
        transaction
            .execute(
                "INSERT INTO budget_reservation_items
                 (reservation_id, dimension, amount) VALUES (?1, ?2, ?3)",
                params![
                    reservation.id,
                    dimension.as_str(),
                    to_sql_u64(*amount, "budget charge")?
                ],
            )
            .map_err(super::store::storage_error)?;
    }
    Ok(reservation)
}

fn require_active_semantic_session(transaction: &Transaction<'_>, session_id: &str) -> Result<()> {
    let state: Option<(String, String)> = transaction
        .query_row(
            "SELECT status, enforcement_posture FROM sessions WHERE id = ?1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(super::store::storage_error)?;
    let (status, posture) =
        state.ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
    let status = SessionStatus::parse(&status)?;
    if status != SessionStatus::Running || posture != "semantic_enforced" {
        return Err(VigilError::Unauthorized(
            "budget reservations require a running semantic-enforced session".to_string(),
        ));
    }
    Ok(())
}

fn counter_from_values(
    dimension: BudgetDimension,
    limit: i64,
    consumed: i64,
    reserved: i64,
) -> Result<BudgetCounter> {
    let limit = from_sql_u64(limit, "budget limit")?;
    let consumed = from_sql_u64(consumed, "budget consumed")?;
    let reserved = from_sql_u64(reserved, "budget reserved")?;
    let remaining = limit
        .checked_sub(consumed)
        .and_then(|value| value.checked_sub(reserved))
        .ok_or_else(|| {
            VigilError::AuditIntegrity("budget remaining would be negative".to_string())
        })?;
    Ok(BudgetCounter {
        dimension,
        limit,
        consumed,
        reserved,
        remaining,
    })
}

fn to_sql_u64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| VigilError::InvalidValue {
        field: "budget",
        reason: format!("{field} exceeds SQLite integer range"),
    })
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        VigilError::AuditIntegrity(format!("{field} is negative in the local database"))
    })
}

fn to_sql_error(error: VigilError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewSession;
    use std::path::PathBuf;

    fn active_store(profile: &str) -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-budget-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: profile.to_string(),
                workspace,
                executable: "vigil-fs-broker".to_string(),
                argv: vec!["vigil-fs-broker".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&session.id, std::process::id())
            .expect("activate session");
        (root, store, session.id)
    }

    fn counter(store: &LocalStore, session: &str, dimension: BudgetDimension) -> BudgetCounter {
        store
            .budget_snapshot(session)
            .expect("snapshot")
            .into_iter()
            .find(|counter| counter.dimension == dimension)
            .expect("counter")
    }

    #[test]
    fn commit_and_refund_reconcile_the_ledger() {
        let (root, store, session) = active_store("developer-standard");
        let committed = store
            .reserve_budget(
                &session,
                "corr-commit",
                &[BudgetCharge::new(BudgetDimension::FileWrites, 2)],
            )
            .expect("reserve");
        assert_eq!(
            counter(&store, &session, BudgetDimension::FileWrites).reserved,
            2
        );
        store.commit_budget(&committed.id).expect("commit");
        store
            .commit_budget(&committed.id)
            .expect("idempotent commit");
        let after_commit = counter(&store, &session, BudgetDimension::FileWrites);
        assert_eq!((after_commit.consumed, after_commit.reserved), (2, 0));

        let refunded = store
            .reserve_budget(
                &session,
                "corr-refund",
                &[BudgetCharge::new(BudgetDimension::FileWrites, 3)],
            )
            .expect("reserve");
        store.refund_budget(&refunded.id).expect("refund");
        store
            .refund_budget(&refunded.id)
            .expect("idempotent refund");
        let after_refund = counter(&store, &session, BudgetDimension::FileWrites);
        assert_eq!((after_refund.consumed, after_refund.reserved), (2, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn network_destinations_are_charged_once_after_commit() {
        let (root, store, session) = active_store("developer-standard");
        let first = store
            .reserve_network_budget(&session, "corr-first", "github.com:443")
            .expect("first network reservation");
        store.commit_budget(&first.id).expect("commit first");
        let second = store
            .reserve_network_budget(&session, "corr-second", "github.com:443")
            .expect("second network reservation");
        store.commit_budget(&second.id).expect("commit second");
        assert_eq!(
            counter(&store, &session, BudgetDimension::NetworkConnections).consumed,
            2
        );
        assert_eq!(
            counter(&store, &session, BudgetDimension::NetworkDestinations).consumed,
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refunded_first_destination_can_be_reserved_again() {
        let (root, store, session) = active_store("developer-standard");
        let failed = store
            .reserve_network_budget(&session, "corr-failed", "github.com:443")
            .expect("network reservation");
        store.refund_budget(&failed.id).expect("refund");
        let retried = store
            .reserve_network_budget(&session, "corr-retry", "github.com:443")
            .expect("retry reservation");
        store.commit_budget(&retried.id).expect("commit retry");
        assert_eq!(
            counter(&store, &session, BudgetDimension::NetworkConnections).consumed,
            1
        );
        assert_eq!(
            counter(&store, &session, BudgetDimension::NetworkDestinations).consumed,
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_first_destination_blocks_concurrent_undercount() {
        let (root, store, session) = active_store("developer-standard");
        let pending = store
            .reserve_network_budget(&session, "corr-pending", "github.com:443")
            .expect("pending reservation");
        let competing = store.reserve_network_budget(&session, "corr-competing", "github.com:443");
        assert!(matches!(
            competing,
            Err(VigilError::Unavailable {
                component: "network_budget",
                ..
            })
        ));
        assert_eq!(
            counter(&store, &session, BudgetDimension::NetworkDestinations).reserved,
            1
        );
        store.refund_budget(&pending.id).expect("refund pending");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_multi_dimension_failure_reserves_nothing() {
        let (root, store, session) = active_store("developer-standard");
        let result = store.reserve_budget(
            &session,
            "corr-over",
            &[
                BudgetCharge::new(BudgetDimension::FileWrites, 1),
                BudgetCharge::new(BudgetDimension::TotalWriteBytes, 25_000_001),
            ],
        );
        assert!(matches!(result, Err(VigilError::BudgetExhausted(_))));
        assert_eq!(
            counter(&store, &session, BudgetDimension::FileWrites).reserved,
            0
        );
        assert_eq!(
            counter(&store, &session, BudgetDimension::TotalWriteBytes).reserved,
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn zero_limit_dimensions_deny_deterministically() {
        let (root, store, session) = active_store("developer-restricted");
        let result = store.reserve_budget(
            &session,
            "corr-delete",
            &[BudgetCharge::new(BudgetDimension::FileDeletes, 1)],
        );
        assert!(matches!(result, Err(VigilError::BudgetExhausted(_))));
        let snapshot = counter(&store, &session, BudgetDimension::FileDeletes);
        assert_eq!((snapshot.limit, snapshot.remaining), (0, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn simultaneous_reservations_cannot_overrun_the_limit() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (root, store, session) = active_store("developer-standard");
        let path = store.path().to_path_buf();
        drop(store);
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for index in 0..2 {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            let session = session.clone();
            handles.push(thread::spawn(move || {
                let store = LocalStore::open(&path).expect("open concurrent store");
                barrier.wait();
                store
                    .reserve_budget(
                        &session,
                        &format!("corr-{index}"),
                        &[BudgetCharge::new(BudgetDimension::FileWrites, 60)],
                    )
                    .is_ok()
            }));
        }
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .filter(|succeeded| *succeeded)
            .count();
        assert_eq!(successes, 1);
        let store = LocalStore::open(&path).expect("reopen store");
        let snapshot = counter(&store, &session, BudgetDimension::FileWrites);
        assert_eq!((snapshot.reserved, snapshot.remaining), (60, 40));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}
