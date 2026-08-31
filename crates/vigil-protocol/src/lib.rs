//! The VIGIL wire protocol.
//!
//! Everything that crosses a component boundary — SDK to Core, Core to Gateway, Core to the
//! audit log, Console to Control — is defined here, once. Instrumentation adapters differ
//! wildly (a LangGraph callback, an MCP `tools/call`, a shell hook); they all normalize into
//! the same [`ActionRequest`] before any security logic runs, because a pipeline that has to
//! understand six input shapes will eventually disagree with itself about what an action is.
//!
//! # Versioning
//!
//! [`SCHEMA_VERSION`] is carried on every envelope. Decisions must stay interpretable years
//! later (Invariant 9), so the rules are:
//!
//! * new fields are added optional, with a default
//! * existing fields never change meaning or type
//! * removals go through a deprecation window and a major version
//! * unknown fields are preserved by the audit path, not silently dropped
//!
//! Enums that can grow (reason codes, trust labels, taint kinds) parse unknown values into an
//! explicit `Other(String)` rather than failing, so an older reader can still process a newer
//! event; a *stricter* reader in the enforcement path rejects unknowns explicitly where that
//! matters, rather than treating them as benign.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod action;
pub mod decision;
pub mod detector;
pub mod event;
pub mod principal;
pub mod reason;
pub mod trust;

pub use action::{
    Action, ActionRequest, DatabaseOperation, Delegation, FileOperation, ImpactTier,
    MemoryOperation, ModelCall, NetworkRequest, ShellExecution, SideEffectClass, ToolCall,
    ToolProtocol,
};
pub use decision::{Constraint, Decision, DecisionResponse, Obligation, RedactionDirective};
pub use detector::{DetectorId, DetectorOutcome, DetectorResult};
pub use event::{EventType, IntegrityEnvelope, VigilSecurityEvent};
pub use principal::{Principal, PrincipalKind, TraceContext, WorkloadIdentity};
pub use reason::ReasonCode;
pub use trust::{ProvenanceRef, TaintKind, TrustLevel};

/// The schema version carried by every envelope in this crate.
pub const SCHEMA_VERSION: &str = "vigil.v1";

/// Assert at load time that a received envelope is one this build understands.
///
/// Fails closed: an envelope from an unknown major version is rejected rather than
/// best-effort parsed, because partial understanding of a security event is worse than
/// none — it produces a decision based on fields whose meaning may have changed.
pub fn check_schema_version(received: &str) -> vigil_common::Result<()> {
    if received == SCHEMA_VERSION || schema_major(received) == Some(schema_major_of_this_build()) {
        return Ok(());
    }
    Err(vigil_common::VigilError::InvalidRequest(format!(
        "unsupported schema version `{received}`; this build speaks `{SCHEMA_VERSION}`"
    )))
}

/// Parse `vigil.v<N>` into `N`.
///
/// Returns `None` for anything that is not a VIGIL schema version at all, which
/// [`check_schema_version`] then rejects — an unparsable version is never "close enough".
fn schema_major(version: &str) -> Option<u32> {
    let (namespace, major) = version.split_once('.')?;
    if namespace != "vigil" {
        return None;
    }
    // Only `vN` with nothing else; `v1beta` and `v1.2` are distinct versions, not v1.
    major.strip_prefix('v')?.parse::<u32>().ok()
}

fn schema_major_of_this_build() -> u32 {
    // SCHEMA_VERSION is a compile-time constant known to be well-formed; the fallback keeps
    // this function total rather than panicking inside the enforcement path.
    schema_major(SCHEMA_VERSION).unwrap_or(1)
}

/// The schema version used as a serde default on envelopes.
///
/// A separate function rather than a const because `#[serde(default = "...")]` needs a path
/// to a function; keeping it here means every envelope defaults consistently.
pub fn action_schema_version() -> String {
    SCHEMA_VERSION.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_major_versions_are_accepted_and_others_rejected() {
        assert!(check_schema_version("vigil.v1").is_ok());
        assert!(check_schema_version("vigil.v2").is_err());
        assert!(check_schema_version("vigil.v99").is_err());
        assert!(check_schema_version("something.else").is_err());
    }

    #[test]
    fn near_miss_versions_are_not_treated_as_the_current_one() {
        // Each of these previously risked parsing as "v1" under a looser scheme, which would
        // have meant interpreting an envelope whose field meanings may have changed.
        for bogus in [
            "vigil.v1beta",
            "vigil.v1.2",
            "VIGIL.v1",
            "vigilv1",
            "evil.vigil.v1",
            "vigil.",
            "vigil.v",
            "vigil.v-1",
            "vigil.v01x",
        ] {
            assert!(
                check_schema_version(bogus).is_err(),
                "`{bogus}` was accepted as the current schema"
            );
        }
        // Zero-padding is still numerically v1 and is accepted.
        assert!(check_schema_version("vigil.v01").is_ok());
    }
}
