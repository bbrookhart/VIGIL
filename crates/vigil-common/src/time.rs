//! Time, behind a trait.
//!
//! # Why
//!
//! Capability expiry, approval expiry and replay windows are all time comparisons. Tests
//! that prove "an expired capability never executes" must be able to move time
//! deterministically rather than sleeping, and chaos tests must be able to introduce clock
//! skew. Reading the wall clock directly in the enforcement path makes both impossible.
//!
//! # Failure mode
//!
//! There is no fallback clock. A component is constructed with a clock or it does not
//! start; there is no code path where a missing clock degrades into "treat as unexpired".

use chrono::{DateTime, Duration, Utc};
use std::sync::Mutex;

/// All VIGIL timestamps are UTC and serialized as RFC 3339.
pub type Timestamp = DateTime<Utc>;

/// Source of the current time for a component.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Timestamp;
}

/// The real clock. Used everywhere outside tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Utc::now()
    }
}

/// A clock tests can move, used to prove expiry and replay behaviour without sleeping.
#[derive(Debug)]
pub struct FixedClock {
    now: Mutex<Timestamp>,
}

impl FixedClock {
    pub fn new(now: Timestamp) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// A stable, arbitrary instant for test fixtures.
    pub fn at_epoch() -> Self {
        Self::new(DateTime::from_timestamp(1_700_000_000, 0).unwrap_or_else(Utc::now))
    }

    pub fn advance(&self, by: Duration) {
        if let Ok(mut guard) = self.now.lock() {
            *guard += by;
        }
    }

    pub fn set(&self, to: Timestamp) {
        if let Ok(mut guard) = self.now.lock() {
            *guard = to;
        }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        match self.now.lock() {
            Ok(g) => *g,
            // A poisoned clock mutex means another thread panicked mid-update. Returning a
            // fabricated "now" could silently un-expire a capability, so we take the value
            // that was there at poison time, which is never later than the true now.
            Err(poisoned) => *poisoned.into_inner(),
        }
    }
}

/// Milliseconds between two instants, saturating at zero. Used for latency metrics.
pub fn elapsed_ms(start: Timestamp, end: Timestamp) -> u64 {
    (end - start).num_milliseconds().max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_only_moves_when_told_to() {
        let clock = FixedClock::at_epoch();
        let t0 = clock.now();
        assert_eq!(t0, clock.now());
        clock.advance(Duration::seconds(30));
        assert_eq!(clock.now() - t0, Duration::seconds(30));
    }

    #[test]
    fn elapsed_never_goes_negative_under_clock_skew() {
        let clock = FixedClock::at_epoch();
        let later = clock.now();
        let earlier = later - Duration::seconds(5);
        assert_eq!(elapsed_ms(later, earlier), 0);
        assert_eq!(elapsed_ms(earlier, later), 5000);
    }
}
