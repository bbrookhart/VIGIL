//! Shared primitives for every VIGIL component.
//!
//! This crate deliberately contains no policy, no detection and no I/O. It holds the
//! things that must behave *identically* everywhere in the system, because security
//! decisions are compared, hashed and replayed across process and language boundaries:
//!
//! * [`canonical`] — one byte-exact serialization of a request, so an approval issued in
//!   the control plane binds to the same bytes the data plane later verifies.
//! * [`hash`] — one hashing scheme with an algorithm prefix, so hashes stay interpretable
//!   after an algorithm migration.
//! * [`ids`] — validated identifier newtypes, so a tenant id can never be silently used
//!   where an agent id was meant.
//! * [`redact`] — the only sanctioned way to put evidence about a secret into a log.
//! * [`time`] — an injectable clock, so expiry and replay logic is testable.

#![forbid(unsafe_code)]
// Panicking constructs are forbidden in shipped code paths but permitted in tests, where a
// failed assertion is the intended outcome.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod canonical;
pub mod error;
pub mod hash;
pub mod ids;
pub mod path;
pub mod redact;
pub mod time;

pub use error::{Result, VigilError};
pub use hash::{ContentHash, HashAlgorithm};
pub use time::{Clock, FixedClock, SystemClock, Timestamp};
