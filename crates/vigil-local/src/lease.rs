//! Capability leases: bounded, expiring, use-counted authority.
//!
//! A lease is the only thing that can satisfy a `REQUIRE_APPROVAL` decision, and the only way
//! to obtain one is for a human to grant an approval request. There is deliberately no
//! function here that mints a lease from a caller's say-so — [`issue_lease_in_transaction`] is
//! crate-private and has exactly one caller, in [`crate::approval`]. That is the same
//! technique the secret broker uses for its precompiled grants: the absence of an API is the
//! control.
//!
//! Two properties are enforced by the database rather than by this code:
//!
//! - `delegable` carries a `CHECK(delegable = 0)`, so a lease that could be delegated cannot
//!   be stored at all;
//! - `uses_remaining` is bounded by `max_uses` and by zero, so no accounting bug can produce
//!   negative or inflated remaining uses.
//!
//! Expiry is evaluated in the predicate of every statement that could act on a lease, never
//! read from the `status` column. An expired lease is therefore inert the instant it expires,
//! with no sweeper needing to have run.
//!
//! Multi-resource callers use one `BEGIN IMMEDIATE` batch: every required use is decremented
//! and committed together, or any missing member rolls the entire batch back.

use crate::{LocalAction, LocalStore};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use vigil_common::{Result, VigilError};

/// Default lifetime of a granted lease.
pub const DEFAULT_LEASE_TTL_SECONDS: i64 = 900;

/// Hard ceiling on lease lifetime, matching `vigil-capability`'s token ceiling.
///
/// A grant asking for longer is refused rather than quietly clamped: an operator who believes
/// they granted eight hours should not discover later that they granted fifteen minutes.
pub const MAX_LEASE_TTL_SECONDS: i64 = 900;

/// Ceiling on how many times one grant may be used.
pub const MAX_LEASE_USES: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Exhausted,
    Revoked,
}

impl LeaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "exhausted" => Ok(Self::Exhausted),
            "revoked" => Ok(Self::Revoked),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown lease status `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLease {
    pub lease_id: String,
    pub session_id: String,
    pub approval_id: String,
    pub action: LocalAction,
    /// The resolved resource, as decided about — never the string the caller requested.
    pub resource: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
    pub uses_remaining: u32,
    /// Always false. Present so the schema and the wire form stay stable if bounded
    /// delegation is ever designed; see invariant 5.
    pub delegable: bool,
    pub status: LeaseState,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

impl CapabilityLease {
    /// Whether this lease can still authorize anything, as of `now`.
    ///
    /// Expiry is checked here as well as in SQL so a lease rendered from a listing is never
    /// described as usable when it is not.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.status == LeaseState::Active && self.uses_remaining > 0 && self.expires_at > now
    }
}

/// Exactly what a human decided to authorize.
///
/// Grouped into one value rather than passed as a run of positional arguments, because the
/// bindings are what make the lease specific: a caller that transposed `session_id` and
/// `approval_id`, or `max_uses` and `ttl_seconds`, would still compile.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LeaseGrant<'a> {
    pub session_id: &'a str,
    pub approval_id: &'a str,
    pub action: LocalAction,
    /// The resolved resource, as decided about.
    pub resource: &'a str,
    pub max_uses: u32,
    pub ttl_seconds: i64,
}

/// Mint one lease bound to an approval. Crate-private, and called only from `approval::grant`.
pub(crate) fn issue_lease_in_transaction(
    transaction: &Transaction<'_>,
    grant: &LeaseGrant<'_>,
    now: DateTime<Utc>,
) -> Result<CapabilityLease> {
    if grant.max_uses == 0 || grant.max_uses > MAX_LEASE_USES {
        return Err(VigilError::InvalidValue {
            field: "max_uses",
            reason: format!("a lease must permit between 1 and {MAX_LEASE_USES} uses"),
        });
    }
    if grant.ttl_seconds <= 0 || grant.ttl_seconds > MAX_LEASE_TTL_SECONDS {
        return Err(VigilError::InvalidValue {
            field: "ttl_seconds",
            reason: format!(
                "a lease must expire within 1..={MAX_LEASE_TTL_SECONDS} seconds; a longer \
                 grant is refused rather than silently shortened"
            ),
        });
    }
    let expires_at = now
        .checked_add_signed(Duration::seconds(grant.ttl_seconds))
        .ok_or_else(|| VigilError::InvalidValue {
            field: "ttl_seconds",
            reason: "lease expiry overflows the representable range".to_string(),
        })?;

    let lease = CapabilityLease {
        lease_id: format!("cap_{}", uuid::Uuid::new_v4().simple()),
        session_id: grant.session_id.to_string(),
        approval_id: grant.approval_id.to_string(),
        action: grant.action,
        resource: grant.resource.to_string(),
        issued_at: now,
        expires_at,
        max_uses: grant.max_uses,
        uses_remaining: grant.max_uses,
        delegable: false,
        status: LeaseState::Active,
        revoked_at: None,
        revocation_reason: None,
    };
    transaction
        .execute(
            "INSERT INTO capability_leases
             (lease_id, session_id, approval_id, action, resource, issued_at, expires_at,
              max_uses, uses_remaining, delegable, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 0, 'active')",
            params![
                lease.lease_id,
                lease.session_id,
                lease.approval_id,
                lease.action.as_str(),
                lease.resource,
                lease.issued_at.to_rfc3339(),
                lease.expires_at.to_rfc3339(),
                lease.max_uses,
            ],
        )
        .map_err(super::store::storage_error)?;
    Ok(lease)
}

pub(crate) fn revoke_session_leases_in_transaction(
    transaction: &Transaction<'_>,
    session_id: &str,
    reason: &str,
) -> Result<usize> {
    let reason = vigil_common::redact::single_line_excerpt(reason, 500);
    let revoked = transaction
        .execute(
            "UPDATE capability_leases
             SET status = 'revoked', revoked_at = ?1, revocation_reason = ?2
             WHERE session_id = ?3 AND status = 'active'",
            params![Utc::now().to_rfc3339(), reason, session_id],
        )
        .map_err(super::store::storage_error)?;
    Ok(revoked)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LeaseUse<'a> {
    pub action: LocalAction,
    pub resource: &'a str,
}

#[derive(Debug)]
pub(crate) enum AtomicLeaseConsumption {
    Consumed(Vec<CapabilityLease>),
    /// Zero-based indexes into the requested-use slice that could not be covered. No lease
    /// was changed when this variant is returned.
    Missing(Vec<usize>),
}

impl LocalStore {
    /// Atomically spend one use of a lease covering this exact action and resolved resource.
    ///
    /// Returns the lease that was charged, or `None` when no usable lease covers the request.
    /// The whole check-and-decrement is one `UPDATE ... WHERE` inside `BEGIN IMMEDIATE`, so
    /// two concurrent callers cannot both spend the last use — the same discipline the budget
    /// reservations use.
    pub fn consume_lease(
        &self,
        session_id: &str,
        action: LocalAction,
        resource: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CapabilityLease>> {
        match self.consume_leases_atomically(session_id, &[LeaseUse { action, resource }], now)? {
            AtomicLeaseConsumption::Consumed(mut leases) => Ok(leases.pop()),
            AtomicLeaseConsumption::Missing(_) => Ok(None),
        }
    }

    /// Consume every requested lease use in one transaction, or consume none.
    ///
    /// Selection and decrement happen under one `BEGIN IMMEDIATE`. Repeated uses of the same
    /// lease are supported: each update is visible to the next selection in the transaction.
    /// If any request cannot be covered, dropping the transaction rolls back all earlier
    /// decrements and returns the missing request indexes.
    pub(crate) fn consume_leases_atomically(
        &self,
        session_id: &str,
        uses: &[LeaseUse<'_>],
        now: DateTime<Utc>,
    ) -> Result<AtomicLeaseConsumption> {
        if uses.is_empty() {
            return Ok(AtomicLeaseConsumption::Consumed(Vec::new()));
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let now_text = now.to_rfc3339();
        let mut consumed_ids = Vec::with_capacity(uses.len());
        let mut missing = Vec::new();
        for (index, requested) in uses.iter().enumerate() {
            // Expiry is part of the predicate. A lease that expired a millisecond ago selects
            // nothing here, whatever its stored status says.
            let candidate: Option<String> = transaction
                .query_row(
                    "SELECT lease_id FROM capability_leases
                     WHERE session_id = ?1 AND action = ?2 AND resource = ?3
                       AND status = 'active' AND uses_remaining > 0 AND expires_at > ?4
                     ORDER BY expires_at, lease_id LIMIT 1",
                    params![
                        session_id,
                        requested.action.as_str(),
                        requested.resource,
                        now_text
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(super::store::storage_error)?;
            let Some(lease_id) = candidate else {
                missing.push(index);
                continue;
            };
            let charged = transaction
                .execute(
                    "UPDATE capability_leases SET uses_remaining = uses_remaining - 1
                     WHERE lease_id = ?1 AND status = 'active' AND uses_remaining > 0
                       AND expires_at > ?2",
                    params![lease_id, now_text],
                )
                .map_err(super::store::storage_error)?;
            if charged != 1 {
                return Err(VigilError::AuditIntegrity(
                    "capability lease accounting is inconsistent".to_string(),
                ));
            }
            transaction
                .execute(
                    "UPDATE capability_leases SET status = 'exhausted'
                     WHERE lease_id = ?1 AND uses_remaining = 0",
                    [&lease_id],
                )
                .map_err(super::store::storage_error)?;
            consumed_ids.push(lease_id);
        }

        if !missing.is_empty() {
            transaction
                .rollback()
                .map_err(super::store::storage_error)?;
            return Ok(AtomicLeaseConsumption::Missing(missing));
        }

        let leases = consumed_ids
            .iter()
            .map(|lease_id| read_lease(&transaction, lease_id))
            .collect::<Result<Vec<_>>>()?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(AtomicLeaseConsumption::Consumed(leases))
    }

    /// Every lease ever issued to a session, newest first.
    pub fn leases_for_session(&self, session_id: &str) -> Result<Vec<CapabilityLease>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT lease_id, session_id, approval_id, action, resource, issued_at,
                        expires_at, max_uses, uses_remaining, delegable, status, revoked_at,
                        revocation_reason
                 FROM capability_leases WHERE session_id = ?1 ORDER BY issued_at DESC, lease_id",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([session_id], lease_from_row)
            .map_err(super::store::storage_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?
            .into_iter()
            .collect::<Result<Vec<_>>>()
    }

    /// Revoke every active lease held by a session.
    pub fn revoke_session_leases(&self, session_id: &str, reason: &str) -> Result<usize> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let revoked = revoke_session_leases_in_transaction(&transaction, session_id, reason)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(revoked)
    }
}

fn read_lease(transaction: &Transaction<'_>, lease_id: &str) -> Result<CapabilityLease> {
    transaction
        .query_row(
            "SELECT lease_id, session_id, approval_id, action, resource, issued_at, expires_at,
                    max_uses, uses_remaining, delegable, status, revoked_at, revocation_reason
             FROM capability_leases WHERE lease_id = ?1",
            [lease_id],
            lease_from_row,
        )
        .map_err(super::store::storage_error)?
}

type LeaseRow = rusqlite::Result<Result<CapabilityLease>>;

/// Read a stored lease.
///
/// Every column is read up front so that a SQLite-level failure stays distinguishable from a
/// value SQLite returned intact but VIGIL refuses — a stored `delegable = 1`, for instance,
/// is an integrity failure and not a storage error.
fn lease_from_row(row: &rusqlite::Row<'_>) -> LeaseRow {
    let lease_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let approval_id: String = row.get(2)?;
    let action: String = row.get(3)?;
    let resource: String = row.get(4)?;
    let issued_at: String = row.get(5)?;
    let expires_at: String = row.get(6)?;
    let max_uses: i64 = row.get(7)?;
    let uses_remaining: i64 = row.get(8)?;
    let delegable: i64 = row.get(9)?;
    let status: String = row.get(10)?;
    let revoked_at: Option<String> = row.get(11)?;
    let revocation_reason: Option<String> = row.get(12)?;

    Ok((|| {
        if delegable != 0 {
            return Err(VigilError::AuditIntegrity(
                "a delegable capability lease was found in storage".to_string(),
            ));
        }
        Ok(CapabilityLease {
            lease_id,
            session_id,
            approval_id,
            action: action.parse()?,
            resource,
            issued_at: parse_time(&issued_at)?,
            expires_at: parse_time(&expires_at)?,
            max_uses: bounded_count(max_uses, "max_uses")?,
            uses_remaining: bounded_count(uses_remaining, "uses_remaining")?,
            delegable: false,
            status: LeaseState::parse(&status)?,
            revoked_at: revoked_at.as_deref().map(parse_time).transpose()?,
            revocation_reason,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| VigilError::Serialization(format!("unparsable lease timestamp: {error}")))
}

fn bounded_count(value: i64, field: &'static str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| VigilError::AuditIntegrity(format!("`{field}` is out of range")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApproverIdentity;
    use crate::NewSession;
    use rusqlite::Connection;
    use std::path::PathBuf;

    /// A session with one pending approval for `fs.delete` on `/w/target`.
    fn session_with_approval() -> (PathBuf, LocalStore, String, String) {
        let root = std::env::temp_dir().join(format!("vigil-lease-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: "untrusted-agent".to_string(),
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
        let approval = store
            .request_approval(
                &crate::approval::CapabilityAsk {
                    session_id: &session.id,
                    action: LocalAction::FsDelete,
                    requested_resource: "target",
                    resolved_resource: "/w/target",
                    determining_policy: "approve-untrusted-delete",
                    reason: "test",
                },
                Utc::now(),
            )
            .expect("request approval");
        let approval_id = approval.request().approval_id.clone();
        (root, store, session.id, approval_id)
    }

    fn operator() -> ApproverIdentity {
        ApproverIdentity::from_cli_operator("operator").expect("identity")
    }

    #[test]
    fn a_lease_is_spent_exactly_max_uses_times() {
        let (root, store, session, approval) = session_with_approval();
        store
            .grant_approval(&approval, &operator(), 2, 900, None, Utc::now())
            .expect("grant");
        let now = Utc::now();
        for expected_remaining in [1, 0] {
            let lease = store
                .consume_lease(&session, LocalAction::FsDelete, "/w/target", now)
                .expect("consume")
                .expect("a usable lease");
            assert_eq!(lease.uses_remaining, expected_remaining);
        }
        assert!(store
            .consume_lease(&session, LocalAction::FsDelete, "/w/target", now)
            .expect("consume")
            .is_none());
        let stored = store.leases_for_session(&session).expect("leases");
        assert_eq!(stored[0].status, LeaseState::Exhausted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_expired_lease_authorizes_nothing_with_no_sweeper_having_run() {
        let (root, store, session, approval) = session_with_approval();
        store
            .grant_approval(&approval, &operator(), 5, 1, None, Utc::now())
            .expect("grant");
        // Nothing has run in between. The lease row still says `active` with 5 uses left; it
        // is inert purely because every statement that could act on it compares the clock.
        let after_expiry = Utc::now() + Duration::seconds(2);
        let stored = &store.leases_for_session(&session).expect("leases")[0];
        assert_eq!(stored.status, LeaseState::Active);
        assert_eq!(stored.uses_remaining, 5);
        assert!(!stored.is_usable(after_expiry));
        assert!(store
            .consume_lease(&session, LocalAction::FsDelete, "/w/target", after_expiry)
            .expect("consume")
            .is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_revoked_lease_authorizes_nothing() {
        let (root, store, session, approval) = session_with_approval();
        store
            .grant_approval(&approval, &operator(), 5, 900, None, Utc::now())
            .expect("grant");
        assert_eq!(
            store
                .revoke_session_leases(&session, "test revocation")
                .expect("revoke"),
            1
        );
        assert!(store
            .consume_lease(&session, LocalAction::FsDelete, "/w/target", Utc::now())
            .expect("consume")
            .is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_lease_authorizes_only_its_own_action_and_resolved_resource() {
        let (root, store, session, approval) = session_with_approval();
        store
            .grant_approval(&approval, &operator(), 5, 900, None, Utc::now())
            .expect("grant");
        let now = Utc::now();
        // A neighbouring path, a prefix of the granted one, and a different action all miss.
        for (action, resource) in [
            (LocalAction::FsDelete, "/w/other"),
            (LocalAction::FsDelete, "/w"),
            (LocalAction::FsDelete, "/w/target/child"),
            (LocalAction::FsWrite, "/w/target"),
            (LocalAction::FsRead, "/w/target"),
        ] {
            assert!(
                store
                    .consume_lease(&session, action, resource, now)
                    .expect("consume")
                    .is_none(),
                "lease wrongly covered {} on {resource}",
                action.as_str()
            );
        }
        // The exact triple still works, proving the misses were not a broken lookup.
        assert!(store
            .consume_lease(&session, LocalAction::FsDelete, "/w/target", now)
            .expect("consume")
            .is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn simultaneous_consumers_cannot_overspend_one_lease() {
        let (root, store, session, approval) = session_with_approval();
        let path = store.path().to_path_buf();
        store
            .grant_approval(&approval, &operator(), 4, 900, None, Utc::now())
            .expect("grant");
        drop(store);

        // Eight threads race for four uses. Without the single-statement
        // check-and-decrement, two could observe the same remaining count.
        let granted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            let session = session.clone();
            let granted = std::sync::Arc::clone(&granted);
            handles.push(std::thread::spawn(move || {
                let store = LocalStore::open(&path).expect("open store");
                if store
                    .consume_lease(&session, LocalAction::FsDelete, "/w/target", Utc::now())
                    .expect("consume")
                    .is_some()
                {
                    granted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
        assert_eq!(granted.load(std::sync::atomic::Ordering::SeqCst), 4);
        let store = LocalStore::open(&path).expect("reopen");
        let stored = &store.leases_for_session(&session).expect("leases")[0];
        assert_eq!(stored.uses_remaining, 0);
        assert_eq!(stored.status, LeaseState::Exhausted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_batch_member_rolls_back_every_earlier_decrement() {
        let (root, store, session, approval) = session_with_approval();
        store
            .grant_approval(&approval, &operator(), 1, 900, None, Utc::now())
            .expect("grant");
        let outcome = store
            .consume_leases_atomically(
                &session,
                &[
                    LeaseUse {
                        action: LocalAction::FsDelete,
                        resource: "/w/target",
                    },
                    LeaseUse {
                        action: LocalAction::FsDelete,
                        resource: "/w/missing",
                    },
                ],
                Utc::now(),
            )
            .expect("batch");
        assert!(matches!(outcome, AtomicLeaseConsumption::Missing(ref indexes) if indexes == &[1]));
        assert_eq!(
            store.leases_for_session(&session).expect("leases")[0].uses_remaining,
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn simultaneous_batches_are_serialized_as_whole_units() {
        let (root, store, session, approval) = session_with_approval();
        let path = store.path().to_path_buf();
        store
            .grant_approval(&approval, &operator(), 4, 900, None, Utc::now())
            .expect("grant");
        drop(store);

        let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let path = path.clone();
            let session = session.clone();
            let completed = std::sync::Arc::clone(&completed);
            handles.push(std::thread::spawn(move || {
                let store = LocalStore::open(&path).expect("open store");
                let uses = [
                    LeaseUse {
                        action: LocalAction::FsDelete,
                        resource: "/w/target",
                    },
                    LeaseUse {
                        action: LocalAction::FsDelete,
                        resource: "/w/target",
                    },
                ];
                if matches!(
                    store
                        .consume_leases_atomically(&session, &uses, Utc::now())
                        .expect("batch"),
                    AtomicLeaseConsumption::Consumed(_)
                ) {
                    completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
        assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 2);
        let store = LocalStore::open(&path).expect("reopen");
        assert_eq!(
            store.leases_for_session(&session).expect("leases")[0].uses_remaining,
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_grant_longer_than_the_ceiling_is_refused_not_silently_shortened() {
        let (root, store, session, approval) = session_with_approval();
        let error = store
            .grant_approval(
                &approval,
                &operator(),
                1,
                MAX_LEASE_TTL_SECONDS + 1,
                None,
                Utc::now(),
            )
            .expect_err("must refuse");
        assert!(matches!(error, VigilError::InvalidValue { .. }));
        // Nothing was minted, and the approval is still there to decide properly.
        assert!(store
            .leases_for_session(&session)
            .expect("leases")
            .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// The `rusqlite::Row` getter above returns a nested Result; this exists so the row
    /// mapper's own error path stays covered rather than only its happy path.
    #[test]
    fn a_delegable_lease_in_storage_is_an_integrity_failure() {
        let connection = Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch(
                "CREATE TABLE capability_leases (
                   lease_id TEXT, session_id TEXT, approval_id TEXT, action TEXT, resource TEXT,
                   issued_at TEXT, expires_at TEXT, max_uses INTEGER, uses_remaining INTEGER,
                   delegable INTEGER, status TEXT, revoked_at TEXT, revocation_reason TEXT);
                 INSERT INTO capability_leases VALUES
                   ('cap_1', 'ags_1', 'apr_1', 'fs.read', '/w/a',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:15:00+00:00', 1, 1,
                    1, 'active', NULL, NULL);",
            )
            .expect("fixture");
        let outcome: Result<CapabilityLease> = connection
            .query_row("SELECT * FROM capability_leases", [], lease_from_row)
            .expect("row");
        assert!(matches!(outcome, Err(VigilError::AuditIntegrity(_))));
    }
}
