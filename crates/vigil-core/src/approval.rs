//! VIGIL Approve: transaction-bound human authorization.
//!
//! # Why
//!
//! Invariant 5. "The user approved sending an email" is not an authorization; "the user
//! approved sending *this* body to *these* recipients" is. The difference is the entire
//! attack surface of human-in-the-loop: an approval that binds to intent rather than to
//! bytes can be satisfied by a different action than the one the human saw.
//!
//! # What
//!
//! An approval request pins the canonical action hash at the moment it is raised. Granting
//! it produces a signed, single-use, short-lived token bound to that hash, the tenant, the
//! agent, the session and the approver. Redeeming it requires presenting an action whose
//! hash still matches.
//!
//! # Failure mode
//!
//! Every mismatch is a rejection: expired, replayed, mutated, wrong approver, self-approved,
//! wrong tenant. There is no path where an approval partially applies.
//!
//! # Evidence
//!
//! The tests in this module cover each of those, and `tests/redteam/` drives them through
//! the full pipeline.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vigil_common::ids::{AgentId, ApprovalId, PrincipalId, SessionId, TenantId};
use vigil_common::{Clock, ContentHash, Result, Timestamp, VigilError};
use vigil_protocol::principal::Principal;

/// What the approver is shown and what the approval binds to.
///
/// The preview and the binding come from the same source — the canonical material
/// projection — so what the human reads and what the token authorizes cannot diverge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: ApprovalId,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub session_id: SessionId,
    /// The principal the agent is acting for, and who may therefore *not* approve.
    pub requesting_principal: PrincipalId,
    /// Hash of the exact action.
    pub action_hash: ContentHash,
    /// Human-readable transaction preview, already redacted.
    pub preview: TransactionPreview,
    /// Roles permitted to approve.
    pub approver_roles: Vec<String>,
    pub requested_at: Timestamp,
    pub expires_at: Timestamp,
}

/// What the console shows the approver (spec §28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPreview {
    pub action_descriptor: String,
    pub target: Option<String>,
    /// Material parameters, with sensitive values already redacted.
    pub parameters: Vec<(String, String)>,
    /// Data classes that would cross the trust boundary.
    pub sensitive_data_crossing_boundary: Vec<String>,
    pub rationale: Option<String>,
    pub triggering_policies: Vec<String>,
    pub risk_score: f64,
    pub irreversible: bool,
    pub reason_codes: Vec<String>,
}

/// A granted approval, ready to be presented with the retried action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalGrant {
    pub approval_id: ApprovalId,
    pub approver: PrincipalId,
    pub granted_at: Timestamp,
    pub expires_at: Timestamp,
    /// Base64url token: `<base64(claims)>.<base64(signature)>`.
    pub token: String,
}

/// The signed body of an approval token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalClaims {
    approval_id: ApprovalId,
    tenant_id: TenantId,
    agent_id: AgentId,
    session_id: SessionId,
    action_hash: ContentHash,
    approver: PrincipalId,
    granted_at: Timestamp,
    expires_at: Timestamp,
    nonce: String,
}

/// State of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalState {
    Pending,
    Granted,
    /// The grant has been redeemed. Redeeming again is a replay.
    Consumed,
    Rejected,
}

#[derive(Debug)]
struct StoredApproval {
    request: ApprovalRequest,
    state: ApprovalState,
    approver: Option<PrincipalId>,
    nonce: Option<String>,
}

/// Approval lifecycle and verification.
#[derive(Debug)]
pub struct ApprovalService {
    approvals: Mutex<HashMap<String, StoredApproval>>,
    signing: SigningKey,
    key_id: String,
    clock: Arc<dyn Clock>,
}

/// Default lifetime of a granted approval before it must be re-obtained.
pub const DEFAULT_APPROVAL_TTL_SECONDS: i64 = 900;

impl ApprovalService {
    pub fn new(seed: &[u8], key_id: impl Into<String>, clock: Arc<dyn Clock>) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            VigilError::Config("approval signing seed must be exactly 32 bytes".to_string())
        })?;
        Ok(Self {
            approvals: Mutex::new(HashMap::new()),
            signing: SigningKey::from_bytes(&seed),
            key_id: key_id.into(),
            clock,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Raise an approval request for an action.
    ///
    /// The parameter list is wide because an approval binds to a wide tuple — every one of
    /// these is a binding checked at redemption. Collapsing them into a struct would hide
    /// which fields participate in the binding, which is the opposite of what this code
    /// needs to make obvious.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        tenant_id: TenantId,
        agent_id: AgentId,
        session_id: SessionId,
        requesting_principal: PrincipalId,
        action_hash: ContentHash,
        preview: TransactionPreview,
        approver_roles: Vec<String>,
        ttl_seconds: i64,
    ) -> Result<ApprovalRequest> {
        let now = self.clock.now();
        let request = ApprovalRequest {
            approval_id: ApprovalId::generate(),
            tenant_id,
            agent_id,
            session_id,
            requesting_principal,
            action_hash,
            preview,
            approver_roles,
            requested_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds.clamp(30, 86_400)),
        };

        let mut approvals = self.lock()?;
        approvals.insert(
            request.approval_id.to_string(),
            StoredApproval {
                request: request.clone(),
                state: ApprovalState::Pending,
                approver: None,
                nonce: None,
            },
        );
        Ok(request)
    }

    /// Look up a pending request, for the console to render.
    pub fn get(&self, approval_id: &ApprovalId) -> Result<Option<ApprovalRequest>> {
        Ok(self
            .lock()?
            .get(approval_id.as_str())
            .map(|a| a.request.clone()))
    }

    /// Grant an approval.
    ///
    /// The self-approval check is here rather than in the console, because a check that only
    /// exists in a UI is not a control — any API client would bypass it.
    pub fn grant(&self, approval_id: &ApprovalId, approver: &Principal) -> Result<ApprovalGrant> {
        let now = self.clock.now();
        let mut approvals = self.lock()?;
        let stored = approvals
            .get_mut(approval_id.as_str())
            .ok_or_else(|| VigilError::NotFound("approval request".to_string()))?;

        if stored.state != ApprovalState::Pending {
            return Err(VigilError::Unauthorized(
                "approval request is no longer pending".to_string(),
            ));
        }
        if now >= stored.request.expires_at {
            stored.state = ApprovalState::Rejected;
            return Err(VigilError::Unauthorized(
                "approval request has expired".to_string(),
            ));
        }
        if approver.tenant_id != stored.request.tenant_id {
            return Err(VigilError::Unauthorized(
                "approver belongs to a different tenant".to_string(),
            ));
        }
        // The monitored agent must never approve its own request.
        if approver.id == stored.request.requesting_principal {
            return Err(VigilError::Unauthorized(
                "an action's requester cannot approve it".to_string(),
            ));
        }
        if !approver.kind.is_accountable_human() {
            return Err(VigilError::Unauthorized(
                "only an accountable human principal can grant an approval".to_string(),
            ));
        }
        if !stored
            .request
            .approver_roles
            .iter()
            .any(|role| approver.has_role(role))
        {
            return Err(VigilError::Unauthorized(
                "approver does not hold a role permitted to approve this action".to_string(),
            ));
        }

        let nonce = {
            let mut bytes = [0u8; 24];
            rand_fill(&mut bytes);
            B64.encode(bytes)
        };
        let expires_at = now + chrono::Duration::seconds(DEFAULT_APPROVAL_TTL_SECONDS);
        let claims = ApprovalClaims {
            approval_id: stored.request.approval_id.clone(),
            tenant_id: stored.request.tenant_id.clone(),
            agent_id: stored.request.agent_id.clone(),
            session_id: stored.request.session_id.clone(),
            action_hash: stored.request.action_hash.clone(),
            approver: approver.id.clone(),
            granted_at: now,
            expires_at,
            nonce: nonce.clone(),
        };
        let body = vigil_common::canonical::canonical_bytes(&serde_json::to_value(&claims)?)?;
        let signature = self.signing.sign(&body);
        let token = format!("{}.{}", B64.encode(&body), B64.encode(signature.to_bytes()));

        stored.state = ApprovalState::Granted;
        stored.approver = Some(approver.id.clone());
        stored.nonce = Some(nonce);

        Ok(ApprovalGrant {
            approval_id: stored.request.approval_id.clone(),
            approver: approver.id.clone(),
            granted_at: now,
            expires_at,
            token,
        })
    }

    /// Reject an approval request.
    pub fn reject(&self, approval_id: &ApprovalId) -> Result<()> {
        let mut approvals = self.lock()?;
        let stored = approvals
            .get_mut(approval_id.as_str())
            .ok_or_else(|| VigilError::NotFound("approval request".to_string()))?;
        stored.state = ApprovalState::Rejected;
        Ok(())
    }

    /// Verify an approval token against the action actually being retried, and consume it.
    ///
    /// Order matters, as with capabilities: signature first (so an unauthenticated caller
    /// cannot probe), then binding, then expiry, then single-use consumption last.
    pub fn verify_and_consume(
        &self,
        token: &str,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        session_id: &SessionId,
        action_hash: &ContentHash,
    ) -> Result<ApprovalId> {
        let (body_b64, sig_b64) = token.split_once('.').ok_or_else(|| {
            VigilError::CapabilityRejected("approval token is malformed".to_string())
        })?;
        let body = B64.decode(body_b64).map_err(|_| {
            VigilError::CapabilityRejected("approval token body is not base64url".to_string())
        })?;
        let signature_bytes: [u8; 64] = B64
            .decode(sig_b64)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| {
                VigilError::CapabilityRejected("approval signature is malformed".to_string())
            })?;

        self.signing
            .verifying_key()
            .verify(&body, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| {
                VigilError::CapabilityRejected("approval signature is invalid".to_string())
            })?;

        let claims: ApprovalClaims = serde_json::from_slice(&body).map_err(|_| {
            VigilError::CapabilityRejected("approval claims are unreadable".to_string())
        })?;

        if &claims.tenant_id != tenant_id
            || &claims.agent_id != agent_id
            || &claims.session_id != session_id
        {
            return Err(VigilError::CapabilityRejected(
                "approval was granted for a different tenant, agent or session".to_string(),
            ));
        }
        // The check that makes approval transaction-bound.
        if !claims.action_hash.ct_eq(action_hash) {
            return Err(VigilError::CapabilityRejected(
                "the action changed after it was approved".to_string(),
            ));
        }
        if self.clock.now() >= claims.expires_at {
            return Err(VigilError::CapabilityRejected(
                "approval has expired".to_string(),
            ));
        }

        let mut approvals = self.lock()?;
        let stored = approvals
            .get_mut(claims.approval_id.as_str())
            .ok_or_else(|| VigilError::CapabilityRejected("unknown approval".to_string()))?;

        match stored.state {
            ApprovalState::Granted => {}
            ApprovalState::Consumed => {
                return Err(VigilError::CapabilityRejected(
                    "approval has already been used".to_string(),
                ))
            }
            _ => {
                return Err(VigilError::CapabilityRejected(
                    "approval was not granted".to_string(),
                ))
            }
        }
        // Guards against a token minted from a stale copy of the store.
        if stored.nonce.as_deref() != Some(claims.nonce.as_str()) {
            return Err(VigilError::CapabilityRejected(
                "approval nonce does not match the granted approval".to_string(),
            ));
        }

        stored.state = ApprovalState::Consumed;
        Ok(claims.approval_id)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, StoredApproval>>> {
        self.approvals.lock().map_err(|_| VigilError::Unavailable {
            component: "approval_service",
            reason: "lock poisoned; approval state is unreliable".to_string(),
        })
    }
}

/// Fill with OS randomness. Approval nonces must be unguessable so an attacker cannot
/// pre-compute a token for an approval that has not been granted yet.
fn rand_fill(dest: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, dest);
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_common::FixedClock;
    use vigil_protocol::principal::PrincipalKind;

    fn service(clock: Arc<FixedClock>) -> ApprovalService {
        ApprovalService::new(&[7u8; 32], "approval-k1", clock).unwrap()
    }

    fn hash(s: &str) -> ContentHash {
        ContentHash::sha256(s.as_bytes())
    }

    fn preview() -> TransactionPreview {
        TransactionPreview {
            action_descriptor: "send_email".to_string(),
            target: Some("cfo@acme.example".to_string()),
            parameters: vec![("to".to_string(), "cfo@acme.example".to_string())],
            sensitive_data_crossing_boundary: vec![],
            rationale: None,
            triggering_policies: vec!["support-remit-004".to_string()],
            risk_score: 0.5,
            irreversible: true,
            reason_codes: vec!["APPROVAL_REQUIRED".to_string()],
        }
    }

    fn approver(id: &str, roles: &[&str]) -> Principal {
        Principal::new(
            id.parse().unwrap(),
            PrincipalKind::Human,
            "acme".parse().unwrap(),
        )
        .with_roles(roles.iter().map(|r| r.to_string()))
    }

    fn raise(svc: &ApprovalService, action: &str) -> ApprovalRequest {
        svc.request(
            "acme".parse().unwrap(),
            "support".parse().unwrap(),
            "s-1".parse().unwrap(),
            "user-1".parse().unwrap(),
            hash(action),
            preview(),
            vec!["SupportLead".to_string()],
            DEFAULT_APPROVAL_TTL_SECONDS,
        )
        .unwrap()
    }

    fn consume(svc: &ApprovalService, token: &str, action: &str) -> Result<ApprovalId> {
        svc.verify_and_consume(
            token,
            &"acme".parse().unwrap(),
            &"support".parse().unwrap(),
            &"s-1".parse().unwrap(),
            &hash(action),
        )
    }

    #[test]
    fn a_granted_approval_authorizes_exactly_the_approved_action() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let grant = svc
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .unwrap();
        assert!(consume(&svc, &grant.token, "send to cfo").is_ok());
    }

    #[test]
    fn mutating_the_action_after_approval_invalidates_it() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let grant = svc
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .unwrap();
        let err = consume(&svc, &grant.token, "send to attacker").unwrap_err();
        assert!(
            err.to_string().contains("changed after it was approved"),
            "{err}"
        );
    }

    #[test]
    fn an_approval_cannot_be_replayed() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let grant = svc
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .unwrap();
        assert!(consume(&svc, &grant.token, "send to cfo").is_ok());
        let err = consume(&svc, &grant.token, "send to cfo").unwrap_err();
        assert!(err.to_string().contains("already been used"), "{err}");
    }

    #[test]
    fn an_expired_approval_is_rejected() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock.clone());
        let req = raise(&svc, "send to cfo");
        let grant = svc
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .unwrap();
        clock.advance(chrono::Duration::seconds(DEFAULT_APPROVAL_TTL_SECONDS + 1));
        let err = consume(&svc, &grant.token, "send to cfo").unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn the_requester_cannot_approve_their_own_action() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let err = svc
            .grant(&req.approval_id, &approver("user-1", &["SupportLead"]))
            .unwrap_err();
        assert!(err.to_string().contains("cannot approve"), "{err}");
    }

    #[test]
    fn a_non_human_principal_cannot_approve() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let mut robot = approver("svc-1", &["SupportLead"]);
        robot.kind = PrincipalKind::Service;
        assert!(svc.grant(&req.approval_id, &robot).is_err());

        let mut agent = approver("agent-1", &["SupportLead"]);
        agent.kind = PrincipalKind::Agent;
        assert!(
            svc.grant(&req.approval_id, &agent).is_err(),
            "an agent must never approve its own escalation"
        );
    }

    #[test]
    fn an_approver_without_the_required_role_is_rejected() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let err = svc
            .grant(&req.approval_id, &approver("lead-1", &["Viewer"]))
            .unwrap_err();
        assert!(err.to_string().contains("does not hold a role"), "{err}");
    }

    #[test]
    fn an_approver_from_another_tenant_is_rejected() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let mut outsider = approver("lead-1", &["SupportLead"]);
        outsider.tenant_id = "other-corp".parse().unwrap();
        assert!(svc.grant(&req.approval_id, &outsider).is_err());
    }

    #[test]
    fn an_approval_cannot_be_used_in_another_session_or_by_another_agent() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        let grant = svc
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .unwrap();
        let err = svc
            .verify_and_consume(
                &grant.token,
                &"acme".parse().unwrap(),
                &"other-agent".parse().unwrap(),
                &"s-1".parse().unwrap(),
                &hash("send to cfo"),
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("different tenant, agent or session"),
            "{err}"
        );
    }

    #[test]
    fn a_forged_approval_token_is_rejected() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock.clone());
        let other = ApprovalService::new(&[9u8; 32], "rogue", clock).unwrap();
        let req = other
            .request(
                "acme".parse().unwrap(),
                "support".parse().unwrap(),
                "s-1".parse().unwrap(),
                "user-1".parse().unwrap(),
                hash("send to attacker"),
                preview(),
                vec!["SupportLead".to_string()],
                900,
            )
            .unwrap();
        let grant = other
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .unwrap();
        let err = consume(&svc, &grant.token, "send to attacker").unwrap_err();
        assert!(err.to_string().contains("signature is invalid"), "{err}");
    }

    #[test]
    fn an_unapproved_request_cannot_be_consumed() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let _req = raise(&svc, "send to cfo");
        // No grant was issued, so no token exists; a hand-made one fails at the signature.
        assert!(consume(&svc, "bogus.token", "send to cfo").is_err());
    }

    #[test]
    fn granting_twice_is_refused() {
        let clock = Arc::new(FixedClock::at_epoch());
        let svc = service(clock);
        let req = raise(&svc, "send to cfo");
        assert!(svc
            .grant(&req.approval_id, &approver("lead-1", &["SupportLead"]))
            .is_ok());
        assert!(svc
            .grant(&req.approval_id, &approver("lead-2", &["SupportLead"]))
            .is_err());
    }
}
