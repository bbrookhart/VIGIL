//! Time that only moves forward.
//!
//! Leases and approvals expire by comparing a stored `expires_at` to the current time. That is
//! sound only while the clock moves forward. A backwards jump — an NTP correction, a manual
//! change, a VM restored from a snapshot, or an agent that can set the system clock — would
//! make an already-expired lease valid again. Authority resurrected by changing a setting is
//! not authority that was bounded.
//!
//! §71 says not to rely on wall-clock time alone for security intervals, and ADR 0012 already
//! records the same gap on the native side. This is the local answer.
//!
//! # How
//!
//! A single stored high-water mark over every wall-clock reading VIGIL has ever taken. The
//! *effective* time is `max(wall clock, high water)`, so it never decreases no matter what the
//! system clock does. An expired lease stays expired.
//!
//! # What this is not
//!
//! It is not a trusted time source. Anything that can write the database can rewrite the
//! high-water mark, and a clock pushed far *forward* and then left there expires things early
//! — which fails safe, but is still a way to interfere. A real answer needs monotonic boot
//! time and protected continuity state, which is native work. This closes the direction that
//! grants authority; it does not make time trustworthy.

use crate::LocalStore;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use vigil_common::Result;

/// How far the clock may move backwards before it is reported.
///
/// Small corrections are ordinary NTP behaviour and are absorbed silently by the high-water
/// mark. Reporting them would produce a detection on a healthy laptop several times a day,
/// which is how a detection becomes noise.
pub const CLOCK_REGRESSION_TOLERANCE_SECONDS: i64 = 5;

/// How far the clock must advance before the stored mark is rewritten.
///
/// Without this the high-water mark would be written on every authorization — a database write
/// on the hot path for no benefit. One second of granularity bounds the writes while keeping
/// the guarantee: a resurrection window shorter than a second is not useful to anyone.
const ADVANCE_GRANULARITY_SECONDS: i64 = 1;

/// A time reading, and what the clock did to produce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockReading {
    /// The time to use. Never earlier than any previous reading.
    pub now: DateTime<Utc>,
    /// What the system clock actually said.
    pub wall: DateTime<Utc>,
    /// How far the wall clock sits behind the high-water mark, if it does.
    pub regressed_by_seconds: i64,
}

impl ClockReading {
    /// Whether the regression is large enough to be worth reporting.
    pub fn is_significant_regression(&self) -> bool {
        self.regressed_by_seconds > CLOCK_REGRESSION_TOLERANCE_SECONDS
    }
}

impl LocalStore {
    /// Read the time, monotonically.
    ///
    /// Returns `max(wall clock, high water)`. A caller that needs to know the clock moved
    /// backwards can see it in the reading; a caller that just needs a time can use `now` and
    /// be certain it never went backwards.
    pub fn observe_now(&self) -> Result<ClockReading> {
        let wall = Utc::now();
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT high_water FROM clock_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::store::storage_error)?;

        let high_water = match stored.as_deref().map(parse_time).transpose()? {
            Some(high_water) => high_water,
            None => {
                // First reading establishes the mark.
                self.connection
                    .execute(
                        "INSERT OR IGNORE INTO clock_state (id, high_water) VALUES (1, ?1)",
                        params![wall.to_rfc3339()],
                    )
                    .map_err(super::store::storage_error)?;
                return Ok(ClockReading {
                    now: wall,
                    wall,
                    regressed_by_seconds: 0,
                });
            }
        };

        if wall >= high_water + Duration::seconds(ADVANCE_GRANULARITY_SECONDS) {
            // Guarded so a concurrent writer that got further ahead is not walked back.
            self.connection
                .execute(
                    "UPDATE clock_state SET high_water = ?1 WHERE id = 1 AND high_water < ?1",
                    params![wall.to_rfc3339()],
                )
                .map_err(super::store::storage_error)?;
        }

        let regressed = (high_water - wall).num_seconds().max(0);
        Ok(ClockReading {
            now: wall.max(high_water),
            wall,
            regressed_by_seconds: regressed,
        })
    }

    /// Read the time and, if it moved backwards materially, record that as a detection.
    ///
    /// Separated from [`Self::observe_now`] so the hot path can take a reading without the
    /// possibility of a detection write, and callers that want the signal opt into it.
    pub fn observe_now_reporting(&self, session_id: &str) -> Result<ClockReading> {
        let reading = self.observe_now()?;
        if reading.is_significant_regression() {
            if let Some(rule) = crate::rule_for_label(crate::DETECTION_CLOCK_REGRESSION) {
                self.record_detection(
                    session_id,
                    rule,
                    serde_json::json!({
                        "regressed_by_seconds": reading.regressed_by_seconds,
                        "wall_clock": reading.wall.to_rfc3339(),
                        "effective_time": reading.now.to_rfc3339(),
                        // The effective time is what expiry actually used, so nothing was
                        // resurrected regardless of why the clock moved.
                        "authority_resurrected": false,
                    }),
                    None,
                )?;
                self.record_risk_signal(
                    session_id,
                    rule.dimension,
                    rule.weight,
                    None,
                    rule.description,
                )?;
            }
        }
        Ok(reading)
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            vigil_common::VigilError::Serialization(format!("unparsable clock state: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApproverIdentity, CapabilityAsk};
    use crate::{LocalAction, NewSession};
    use std::path::PathBuf;

    fn session() -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-clock-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let created = store
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
            .mark_running(&created.id, std::process::id())
            .expect("activate");
        (root, store, created.id)
    }

    /// Push the stored high-water mark into the future, which is what a backwards clock jump
    /// looks like from the database's point of view.
    fn set_high_water(store: &LocalStore, at: DateTime<Utc>) {
        store
            .connection
            .execute(
                "INSERT INTO clock_state (id, high_water) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET high_water = ?1",
                params![at.to_rfc3339()],
            )
            .expect("set high water");
    }

    #[test]
    fn effective_time_never_moves_backwards() {
        let (root, store, _session) = session();
        let first = store.observe_now().expect("read").now;
        let second = store.observe_now().expect("read").now;
        assert!(second >= first);

        // Simulate the clock jumping an hour backwards.
        set_high_water(&store, Utc::now() + Duration::hours(1));
        let after = store.observe_now().expect("read");
        assert!(
            after.now > after.wall,
            "effective time followed the wall clock backwards"
        );
        assert!(after.is_significant_regression());
        assert!(after.regressed_by_seconds >= 3500);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The property the whole module exists for: turning the clock back must not make an
    /// expired lease usable again.
    #[test]
    fn a_backwards_clock_cannot_resurrect_an_expired_lease() {
        let (root, store, session) = session();
        let issued_at = Utc::now();
        let approval = store
            .request_approval(
                &CapabilityAsk {
                    session_id: &session,
                    action: LocalAction::ProcessExec,
                    requested_resource: "/usr/bin/uname",
                    resolved_resource: "/usr/bin/uname",
                    determining_policy: "approve-process-exec",
                    reason: "test",
                },
                issued_at,
            )
            .expect("request");
        let operator = ApproverIdentity::from_cli_operator("operator").expect("identity");
        store
            .grant_approval(
                &approval.request().approval_id,
                &operator,
                5,
                1,
                None,
                issued_at,
            )
            .expect("grant");

        // The lease has expired.
        let after_expiry = issued_at + Duration::seconds(30);
        set_high_water(&store, after_expiry);
        assert!(store
            .consume_lease(
                &session,
                LocalAction::ProcessExec,
                "/usr/bin/uname",
                store.observe_now().expect("read").now
            )
            .expect("consume")
            .is_none());

        // Now the clock is turned back to before the lease was issued. Reading time through
        // the store still yields the high-water mark, so the lease stays expired.
        let reading = store.observe_now().expect("read");
        assert!(reading.now >= after_expiry);
        assert!(
            store
                .consume_lease(
                    &session,
                    LocalAction::ProcessExec,
                    "/usr/bin/uname",
                    reading.now
                )
                .expect("consume")
                .is_none(),
            "turning the clock back resurrected an expired lease"
        );

        // And for contrast: passing the raw wall clock — what the code did before this module
        // existed — would have accepted it. That is the bug this closes.
        assert!(
            issued_at < after_expiry,
            "the fixture must place the wall clock before expiry"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Ordinary NTP correction must not produce a detection several times a day.
    #[test]
    fn a_small_correction_is_absorbed_without_a_finding() {
        let (root, store, _session) = session();
        set_high_water(
            &store,
            Utc::now() + Duration::seconds(CLOCK_REGRESSION_TOLERANCE_SECONDS - 2),
        );
        let reading = store.observe_now().expect("read");
        assert!(
            !reading.is_significant_regression(),
            "a correction inside the tolerance was reported"
        );
        // Still monotone, even when not reported.
        assert!(reading.now >= reading.wall);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_material_regression_is_recorded_against_the_session() {
        let (root, store, session) = session();
        set_high_water(&store, Utc::now() + Duration::hours(2));
        store
            .observe_now_reporting(&session)
            .expect("read reporting");
        let detections = store.detections_for_session(&session).expect("detections");
        assert!(
            detections
                .iter()
                .any(|detection| detection.rule_id == "VIGIL-L032"),
            "a two-hour clock regression produced no detection: {detections:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
