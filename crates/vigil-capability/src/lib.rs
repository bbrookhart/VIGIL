//! Short-lived execution capabilities.
//!
//! # Why
//!
//! The product promise is that no high-impact action reaches the world without passing a
//! VIGIL decision. An agent holding a long-lived API key can always ignore VIGIL and call the
//! API directly, so in Protected Mode the agent holds *no* execution credential. What it
//! holds instead is a capability: proof that a specific action, for a specific agent, in a
//! specific session, was authorized moments ago — and nothing else.
//!
//! This is what makes Invariant 10 (replay resistance) and Invariant 5 (approval is
//! transaction-bound) enforceable at the gateway rather than trusted at the client.
//!
//! # What
//!
//! A capability is a signed assertion binding, at minimum:
//!
//! ```text
//! tenant + environment + agent + agent instance + session + principal
//!        + tool + operation + target resource
//!        + hash of the exact canonical action
//!        + remit version + policy bundle version + approval id
//!        + issued_at + expires_at + nonce + max_uses
//! ```
//!
//! Every one of those is checked at redemption. A capability minted for
//! `send_email(to=cfo@acme)` cannot execute `send_email(to=attacker@evil)`, cannot be used by
//! a different agent, cannot be used twice, and cannot be used after its (seconds-to-minutes)
//! lifetime.
//!
//! # Failure mode
//!
//! Every verification failure is a rejection. There is no code path in which a malformed,
//! unverifiable, expired or already-used capability results in execution. If the nonce store
//! is unavailable, redemption fails closed — an unavailable replay check is treated as a
//! replay, because the alternative is an unbounded replay window during an outage.
//!
//! # Evidence
//!
//! `tests/` in this crate cover forgery, expiry, replay, cross-tenant reuse, cross-agent
//! reuse and post-issue argument mutation. `tests/redteam/` drives the same attacks through
//! the full gateway.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod claims;
mod nonce;
mod signer;
mod token;

pub use claims::{CapabilityClaims, PresentedAction};
pub use nonce::{InMemoryNonceStore, NonceStore, NonceVerdict};
pub use signer::{CapabilityIssuer, CapabilityVerifier, KeyId, SigningKeyMaterial};
pub use token::{TokenHeader, CAPABILITY_TOKEN_PREFIX};

/// Default capability lifetime.
///
/// Long enough to survive a slow tool handshake, short enough that a leaked capability is
/// worthless by the time it is exfiltrated and reused. Tools may narrow this; policy may not
/// widen it beyond [`MAX_CAPABILITY_TTL_SECONDS`].
pub const DEFAULT_CAPABILITY_TTL_SECONDS: i64 = 60;

/// Hard ceiling on capability lifetime, enforced at issuance regardless of configuration.
pub const MAX_CAPABILITY_TTL_SECONDS: i64 = 900;

/// Clock skew tolerated between the issuer and the redeeming gateway.
///
/// Applied only to `issued_at` (accepting a capability that looks slightly future-dated),
/// never to `expires_at` — extending expiry by the leeway would hand an attacker a free
/// replay window on every clock disagreement.
pub const CLOCK_SKEW_LEEWAY_SECONDS: i64 = 30;
