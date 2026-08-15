//! Replay prevention.
//!
//! # Why
//!
//! A signature proves a capability was issued; it says nothing about how many times it has
//! been used. Without a consumption record, a capability captured from a log, a proxy or a
//! compromised agent can be replayed until it expires. The nonce store is the only component
//! that can answer "has this been redeemed before?", which makes its availability a security
//! property, not a performance one.
//!
//! # Failure mode
//!
//! [`NonceStore::consume`] returns `Err` when it cannot determine the answer. The verifier
//! treats that as a replay and rejects. An outage therefore blocks execution rather than
//! opening an unbounded replay window — the fail-closed choice required by Invariant 7 for
//! privileged actions.

use std::collections::HashMap;
use std::sync::Mutex;
use vigil_common::{Result, Timestamp, VigilError};

/// What happened when a nonce was presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceVerdict {
    /// This redemption is within the permitted use count.
    Accepted { use_number: u32 },
    /// The permitted use count is exhausted.
    Replay { previous_uses: u32 },
}

impl NonceVerdict {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// Records which capabilities have been redeemed.
///
/// Implementations must make [`Self::consume`] atomic: two concurrent redemptions of a
/// single-use capability must produce exactly one [`NonceVerdict::Accepted`]. A
/// check-then-set implementation is a TOCTOU vulnerability, and the concurrency test in this
/// module exists to catch one.
pub trait NonceStore: Send + Sync + std::fmt::Debug {
    /// Atomically record a redemption and report whether it is permitted.
    ///
    /// `expires_at` lets the store drop the record once replay is impossible anyway.
    fn consume(&self, nonce: &str, max_uses: u32, expires_at: Timestamp) -> Result<NonceVerdict>;

    /// Drop records that expired before `now`. Called periodically; never on the hot path.
    fn purge_expired(&self, now: Timestamp) -> Result<usize>;
}

#[derive(Debug)]
struct Entry {
    uses: u32,
    expires_at: Timestamp,
}

/// A single-process nonce store.
///
/// Correct for a single Core/Gateway process and for tests. A multi-replica deployment must
/// use a shared store (Redis with `INCR`, or Postgres with a unique constraint) — otherwise
/// a capability can be redeemed once per replica, which is a replay bug that only appears
/// under horizontal scaling. `deploy/helm` refuses to render a multi-replica gateway without
/// a shared store configured.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NonceStore for InMemoryNonceStore {
    fn consume(&self, nonce: &str, max_uses: u32, expires_at: Timestamp) -> Result<NonceVerdict> {
        // A poisoned lock means a previous holder panicked mid-update, so the use count may
        // be wrong. Reporting an error (which the verifier turns into a rejection) is the
        // only safe response; recovering the guard and continuing could permit a replay.
        let mut entries = self.entries.lock().map_err(|_| VigilError::Unavailable {
            component: "nonce_store",
            reason: "lock poisoned; replay state is unreliable".to_string(),
        })?;

        let entry = entries.entry(nonce.to_string()).or_insert(Entry {
            uses: 0,
            expires_at,
        });
        if entry.uses >= max_uses {
            return Ok(NonceVerdict::Replay {
                previous_uses: entry.uses,
            });
        }
        entry.uses += 1;
        Ok(NonceVerdict::Accepted {
            use_number: entry.uses,
        })
    }

    fn purge_expired(&self, now: Timestamp) -> Result<usize> {
        let mut entries = self.entries.lock().map_err(|_| VigilError::Unavailable {
            component: "nonce_store",
            reason: "lock poisoned".to_string(),
        })?;
        let before = entries.len();
        entries.retain(|_, e| e.expires_at > now);
        Ok(before - entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigil_common::{Clock, FixedClock};

    fn future() -> Timestamp {
        FixedClock::at_epoch().now() + chrono::Duration::seconds(60)
    }

    #[test]
    fn a_single_use_capability_is_accepted_once_and_then_rejected() {
        let store = InMemoryNonceStore::new();
        assert!(store.consume("n1", 1, future()).unwrap().is_accepted());
        assert_eq!(
            store.consume("n1", 1, future()).unwrap(),
            NonceVerdict::Replay { previous_uses: 1 }
        );
        assert_eq!(
            store.consume("n1", 1, future()).unwrap(),
            NonceVerdict::Replay { previous_uses: 1 }
        );
    }

    #[test]
    fn distinct_nonces_do_not_interfere() {
        let store = InMemoryNonceStore::new();
        assert!(store.consume("a", 1, future()).unwrap().is_accepted());
        assert!(store.consume("b", 1, future()).unwrap().is_accepted());
    }

    #[test]
    fn multi_use_capabilities_honour_their_limit_exactly() {
        let store = InMemoryNonceStore::new();
        for expected in 1..=3 {
            assert_eq!(
                store.consume("n", 3, future()).unwrap(),
                NonceVerdict::Accepted {
                    use_number: expected
                }
            );
        }
        assert!(!store.consume("n", 3, future()).unwrap().is_accepted());
    }

    #[test]
    fn concurrent_redemptions_of_one_capability_yield_exactly_one_acceptance() {
        // The TOCTOU test. A check-then-set implementation fails here intermittently, so it
        // runs enough iterations and threads to make that failure reliable.
        for _round in 0..50 {
            let store = Arc::new(InMemoryNonceStore::new());
            let expires = future();
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        store
                            .consume("contended", 1, expires)
                            .map(|v| v.is_accepted())
                            .unwrap_or(false)
                    })
                })
                .collect();
            let accepted = handles
                .into_iter()
                .filter_map(|h| h.join().ok())
                .filter(|accepted| *accepted)
                .count();
            assert_eq!(accepted, 1, "exactly one redemption must win");
        }
    }

    #[test]
    fn purging_removes_only_expired_records() {
        let clock = FixedClock::at_epoch();
        let store = InMemoryNonceStore::new();
        store
            .consume("short", 1, clock.now() + chrono::Duration::seconds(10))
            .unwrap();
        store
            .consume("long", 1, clock.now() + chrono::Duration::seconds(600))
            .unwrap();
        assert_eq!(store.len(), 2);
        clock.advance(chrono::Duration::seconds(60));
        assert_eq!(store.purge_expired(clock.now()).unwrap(), 1);
        assert_eq!(store.len(), 1);
        // The purged nonce is beyond its expiry, so re-accepting it cannot enable a replay:
        // the lifetime check rejects it before the store is ever consulted.
        assert!(store
            .consume("short", 1, clock.now())
            .unwrap()
            .is_accepted());
    }
}
