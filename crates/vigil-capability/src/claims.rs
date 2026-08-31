//! What a capability asserts, and what must match at redemption.

use serde::{Deserialize, Serialize};
use vigil_common::ids::{
    AgentId, AgentInstanceId, ApprovalId, CapabilityId, EnvironmentId, PolicyBundleId, PrincipalId,
    SessionId, TenantId, ToolId,
};
use vigil_common::{ContentHash, Result, Timestamp, VigilError};
use vigil_protocol::decision::Constraint;

/// The claim set version, so a verifier can reject shapes it does not understand.
pub const CLAIMS_VERSION: &str = "vcap.v1";

/// The assertion VIGIL Core signs when it authorizes an action.
///
/// Every field here is a *binding*: something that must still be true when the capability is
/// redeemed. Adding a field to this struct without also checking it in
/// [`CapabilityClaims::check_binding`] would create a claim that looks authoritative but
/// constrains nothing, so the two live side by side in this file deliberately.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    pub version: String,
    pub capability_id: CapabilityId,

    // --- identity bindings ---
    pub tenant_id: TenantId,
    pub environment_id: EnvironmentId,
    pub agent_id: AgentId,
    pub agent_instance_id: AgentInstanceId,
    pub session_id: SessionId,
    pub principal_id: PrincipalId,

    // --- action bindings ---
    /// The action class (`tool_call`, `network`, `shell`, …).
    pub action_kind: String,
    /// The registered tool, when the action targets one.
    #[serde(default)]
    pub tool_id: Option<ToolId>,
    pub operation: String,
    #[serde(default)]
    pub target_resource: Option<String>,
    /// Hash of the canonical material projection of the exact authorized action.
    ///
    /// This single field is what makes argument mutation detectable: change one character of
    /// one recipient and the redeeming gateway computes a different hash.
    pub action_hash: ContentHash,

    // --- decision provenance ---
    pub remit_version: String,
    pub policy_bundle_version: PolicyBundleId,
    /// The approval this capability rests on, when the decision required one.
    #[serde(default)]
    pub approval_id: Option<ApprovalId>,
    /// Restrictions the gateway must additionally enforce at execution time.
    #[serde(default)]
    pub constraints: Vec<Constraint>,

    // --- lifetime and replay ---
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    /// Single-use randomness. The nonce store, not the token, is what prevents replay.
    pub nonce: String,
    /// How many times this capability may be redeemed. Normally 1.
    pub max_uses: u32,
}

/// The action actually presented at the gateway, to be checked against the claims.
///
/// Constructed by the gateway from the request it received — never from anything the client
/// asserts about what it was authorized to do.
#[derive(Debug, Clone)]
pub struct PresentedAction {
    pub tenant_id: TenantId,
    pub environment_id: EnvironmentId,
    pub agent_id: AgentId,
    pub agent_instance_id: AgentInstanceId,
    pub session_id: SessionId,
    pub principal_id: PrincipalId,
    pub action_kind: String,
    pub tool_id: Option<ToolId>,
    pub operation: String,
    pub target_resource: Option<String>,
    /// Recomputed by the gateway from the request body. Never copied from the token.
    pub action_hash: ContentHash,
}

impl CapabilityClaims {
    /// Check every binding against what was actually presented.
    ///
    /// Ordering note: this runs *after* signature verification, so the claims are known to be
    /// VIGIL's own. Checking bindings on an unverified token would let an attacker learn
    /// which field mismatched by watching error messages.
    pub fn check_binding(&self, presented: &PresentedAction) -> Result<()> {
        if self.version != CLAIMS_VERSION {
            return Err(VigilError::CapabilityRejected(format!(
                "unsupported claims version `{}`",
                self.version
            )));
        }

        // Tenant first: a cross-tenant redemption is the most serious mismatch and must be
        // reported as such even if other fields also differ.
        binding("tenant", &self.tenant_id, &presented.tenant_id)?;
        binding(
            "environment",
            &self.environment_id,
            &presented.environment_id,
        )?;
        binding("agent", &self.agent_id, &presented.agent_id)?;
        binding(
            "agent_instance",
            &self.agent_instance_id,
            &presented.agent_instance_id,
        )?;
        binding("session", &self.session_id, &presented.session_id)?;
        binding("principal", &self.principal_id, &presented.principal_id)?;
        binding("action_kind", &self.action_kind, &presented.action_kind)?;
        binding("operation", &self.operation, &presented.operation)?;

        if self.tool_id != presented.tool_id {
            return Err(VigilError::CapabilityRejected(
                "capability tool does not match presented tool".to_string(),
            ));
        }
        if self.target_resource != presented.target_resource {
            return Err(VigilError::CapabilityRejected(
                "capability target resource does not match presented target".to_string(),
            ));
        }

        // The action hash subsumes most of the above, but the individual checks stay: they
        // give an operator a precise reason code, and they keep the capability meaningful if
        // the material projection ever narrows.
        if !self.action_hash.ct_eq(&presented.action_hash) {
            return Err(VigilError::CapabilityRejected(
                "presented action does not match the authorized action".to_string(),
            ));
        }
        Ok(())
    }

    /// Check the capability's lifetime against a clock.
    ///
    /// `leeway` is applied only to the not-yet-valid check. Expiry is strict.
    pub fn check_lifetime(&self, now: Timestamp, leeway_seconds: i64) -> Result<()> {
        if now >= self.expires_at {
            return Err(VigilError::CapabilityRejected(format!(
                "capability expired at {}",
                self.expires_at.to_rfc3339()
            )));
        }
        let earliest = self.issued_at - chrono::Duration::seconds(leeway_seconds.max(0));
        if now < earliest {
            return Err(VigilError::CapabilityRejected(
                "capability is not yet valid".to_string(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(VigilError::CapabilityRejected(
                "capability lifetime is empty or inverted".to_string(),
            ));
        }
        if (self.expires_at - self.issued_at).num_seconds() > crate::MAX_CAPABILITY_TTL_SECONDS {
            return Err(VigilError::CapabilityRejected(
                "capability lifetime exceeds the permitted maximum".to_string(),
            ));
        }
        Ok(())
    }

    /// Seconds remaining before expiry, floored at zero.
    pub fn remaining_seconds(&self, now: Timestamp) -> i64 {
        (self.expires_at - now).num_seconds().max(0)
    }
}

fn binding<T: PartialEq + std::fmt::Display>(
    field: &str,
    claimed: &T,
    presented: &T,
) -> Result<()> {
    if claimed == presented {
        return Ok(());
    }
    // The claimed value is VIGIL's own and safe to log; the presented value is
    // attacker-influenced and is deliberately omitted from the message.
    Err(VigilError::CapabilityRejected(format!(
        "capability {field} binding does not match the presented request (capability: {claimed})"
    )))
}
