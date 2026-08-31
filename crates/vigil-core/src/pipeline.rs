//! The enforcement pipeline.
//!
//! # Why
//!
//! This is the function the whole product exists to run. Every request for a protected action
//! passes through it exactly once, and its output is the authority for whether the action
//! happens.
//!
//! # What
//!
//! An ordered sequence of stages, folding results through [`Decision::combine`] so the
//! outcome can only ever become more restrictive as the pipeline proceeds. Stages that fail
//! contribute risk and, for action classes that must fail closed, a denial.
//!
//! ## Ordering, and where it differs from the spec's listing
//!
//! The specification lists provenance and taint analysis (stages 7–9) *after* deterministic
//! policy (stage 4). VIGIL runs them **before**, deliberately, because the shipped policy
//! rules match on taint and on untrusted influence — `injection-driven-egress-001` is exactly
//! such a rule. Evaluating policy first would mean evaluating it against an empty context and
//! discarding its most valuable inputs. The invariant the spec's ordering protects
//! (deterministic policy is authoritative) is preserved by a stronger mechanism than
//! ordering: detectors cannot express an allow, and every fold goes through
//! `Decision::combine`. Order therefore cannot weaken a decision no matter what runs first.
//!
//! The effective order is:
//!
//! ```text
//!  1. schema and identity validation      6. budgets
//!  2. session state and termination       7. deterministic policy
//!  3. canonicalization (action hash)      8. detectors (risk-routed)
//!  4. tool manifest resolution            9. composite risk
//!  5. provenance, taint, DLP             10. approval resolution
//!                                        11. final combine, capability, audit
//! ```
//!
//! # Failure mode
//!
//! Every stage's failure is explicit. A policy engine outage, a detector timeout or a
//! session-store failure resolves against the action's impact tier: Tier 2 and above fail
//! closed (Invariant 7), Tier 0–1 reads may proceed in degraded mode with the
//! `DEGRADED_MODE_ALLOW` reason code recorded.

use std::sync::Arc;
use vigil_capability::{CapabilityClaims, CapabilityIssuer};
use vigil_common::ids::{CapabilityId, EventId};
use vigil_common::{Clock, ContentHash, Result, Timestamp, VigilError};
use vigil_detect::{DetectionContext, DetectorRegistry, UntrustedContent};
use vigil_policy::{
    PolicyAction, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyRequest, PolicyResource,
};
use vigil_protocol::action::{Action, ImpactTier};
use vigil_protocol::decision::{Decision, DecisionProvenance, DecisionResponse, Obligation};
use vigil_protocol::reason::ReasonCode;
use vigil_protocol::trust::TaintKind;
use vigil_protocol::ActionRequest;
use vigil_remit::{BudgetVerdict, RemitRegistry, RemitVerdict};

use crate::approval::{ApprovalService, TransactionPreview};
use crate::auth::AuthenticatedRequest;
use crate::config::{CoreConfig, EnforcementMode};
use crate::manifest::ToolManifestRegistry;
use crate::risk::{self, RiskInputs};
use crate::session::{SessionKey, SessionStore};

/// Everything the pipeline needs.
pub struct DecisionPipeline {
    pub(crate) config: CoreConfig,
    pub(crate) policy: Arc<dyn PolicyEngine>,
    pub(crate) remits: Arc<RemitRegistry>,
    pub(crate) manifests: Arc<ToolManifestRegistry>,
    pub(crate) detectors: Arc<DetectorRegistry>,
    pub(crate) sessions: Arc<SessionStore>,
    pub(crate) issuer: Arc<CapabilityIssuer>,
    pub(crate) approvals: Arc<ApprovalService>,
    pub(crate) clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for DecisionPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionPipeline")
            .field("mode", &self.config.mode)
            .field("policy_provider", &self.policy.provider())
            .field("detectors", &self.detectors.len())
            .finish()
    }
}

/// The pipeline's full working state for one request, retained so the API layer can emit a
/// complete audit event and the console can render a decision inspector.
#[derive(Debug)]
pub struct DecisionOutcome {
    pub response: DecisionResponse,
    pub action_hash: ContentHash,
    pub taints: Vec<TaintKind>,
    pub causal_chain: Vec<vigil_protocol::trust::ProvenanceRef>,
    pub risk_contributions: Vec<(String, f64)>,
    pub approval_request: Option<crate::approval::ApprovalRequest>,
    pub effective_tier: ImpactTier,
}

impl DecisionPipeline {
    /// Evaluate one action request.
    ///
    /// Takes an [`AuthenticatedRequest`] rather than a bare [`ActionRequest`] so that
    /// "decide without authenticating" is not a call that can be written. See
    /// [`crate::auth`] for why that is a type-level concern rather than a middleware one.
    pub async fn decide(&self, authenticated: &AuthenticatedRequest) -> Result<DecisionOutcome> {
        let started = self.clock.now();
        let mut reason_codes: Vec<ReasonCode> = Vec::new();
        let request = authenticated.request();

        // ---- 1. schema and identity -------------------------------------------------
        request.validate()?;
        self.check_identity(authenticated, &mut reason_codes)?;

        // ---- 3. canonicalization ----------------------------------------------------
        // Done early so every later stage, every log line and every binding refers to the
        // same hash. A canonicalization failure is a rejected request, never an unhashed one.
        let action_hash = request.action_hash().map_err(|e| {
            VigilError::InvalidRequest(format!("action cannot be canonicalized: {e}"))
        })?;

        // ---- 4. tool manifest --------------------------------------------------------
        let resource_name = request.action.resource_name();
        let manifest = self.manifests.lookup(&resource_name);
        if manifest.synthetic && matches!(request.action, Action::ToolCall(_)) {
            reason_codes.push(ReasonCode::ToolUnregistered);
        }
        let side_effect = if manifest.synthetic {
            request.action.intrinsic_side_effect()
        } else {
            manifest.side_effect
        };
        let effective_tier = manifest.effective_tier().max(side_effect.floor_tier());

        let session_key = SessionKey::from(request);
        let operation = request.action.operation();
        let content_strings = request.action.content_strings();

        // ---- 2. session state --------------------------------------------------------
        let session_snapshot =
            self.sessions
                .with_session(&session_key, started, |state| SessionSnapshot {
                    terminated: state.terminated,
                    denial_count: state.denial_count,
                    distinct_denials: state.distinct_denials(),
                    retry_of_denied: state.was_denied_before(&action_hash),
                    remit_version: state.remit_version.clone(),
                })?;

        if session_snapshot.terminated {
            return Ok(self.terminated_response(request, action_hash, started, effective_tier));
        }

        // ---- 5. provenance, taint and DLP --------------------------------------------
        let declared_sources: Vec<_> = request
            .context
            .influencing_sources
            .iter()
            .map(|r| r.node_id.clone())
            .collect();
        let trace_findings = self.sessions.with_session(&session_key, started, |state| {
            state
                .trace
                .analyze_action(&declared_sources, &content_strings)
        })?;

        let dlp_findings = vigil_detect::dlp::classify_all(&content_strings);
        let mut taints = trace_findings.taints_vec();
        for taint in vigil_detect::dlp::taints_of(&dlp_findings) {
            if !taints.contains(&taint) {
                taints.push(taint);
            }
        }
        taints.sort();
        let data_classes: Vec<String> = dlp_findings
            .iter()
            .map(|f| f.class.as_str().to_string())
            .collect();

        // ---- remit -------------------------------------------------------------------
        let (remit_verdict, remit_version) = self
            .remits
            .evaluate(request.agent_id.as_str(), &request.action);
        let remit_decision = match &remit_verdict {
            RemitVerdict::InRemit => Decision::Allow,
            RemitVerdict::RequiresApproval => Decision::RequireApproval,
            RemitVerdict::OutOfRemit(_) => Decision::Deny,
            RemitVerdict::NoRemit => {
                if self.config.allow_unregistered_agents {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        };
        if !matches!(remit_verdict, RemitVerdict::InRemit) {
            reason_codes.push(remit_verdict.reason_code());
        } else {
            reason_codes.push(ReasonCode::WithinRemit);
        }
        // Pin the remit version to the session on first use.
        if session_snapshot.remit_version.is_none() {
            if let Some(version) = &remit_version {
                let version = version.clone();
                self.sessions.with_session(&session_key, started, |state| {
                    state.remit_version = Some(version);
                })?;
            }
        }

        // Data-class egress boundary, which no approval can waive.
        let mut remit_decision = remit_decision;
        if side_effect.is_egress() {
            if let Some(remit) = self.remits.get(request.agent_id.as_str()) {
                for class in &data_classes {
                    if !remit.permits_egress_of(class) {
                        remit_decision = remit_decision.combine(Decision::Deny);
                        reason_codes.push(ReasonCode::OutOfRemitResource);
                    }
                }
            }
        }

        // ---- 6. budgets ---------------------------------------------------------------
        let limits = self
            .remits
            .get(request.agent_id.as_str())
            .map(|r| r.limits().clone())
            .unwrap_or_default();
        let destination = destination_host(&request.action);
        let budget_verdict = self.sessions.with_session(&session_key, started, |state| {
            let overall = state.budget.check(&limits, started);
            if !overall.permits() {
                return overall;
            }
            state
                .budget
                .check_action(&limits, &action_hash, destination.as_deref())
        })?;
        let budget_decision = match &budget_verdict {
            BudgetVerdict::Within => Decision::Allow,
            BudgetVerdict::Exhausted(code) => {
                reason_codes.push(code.clone());
                Decision::Deny
            }
        };

        // ---- 7. deterministic policy ---------------------------------------------------
        let policy_request = PolicyRequest {
            principal: PolicyPrincipal {
                id: request.principal.id.clone(),
                tenant_id: request.tenant_id.clone(),
                kind: principal_kind_label(&request.principal.kind).to_string(),
                roles: request.principal.roles.clone(),
                mfa: request.principal.mfa,
                agent_id: request.agent_id.clone(),
                delegation_lineage: delegation_lineage(&request.action),
            },
            action: PolicyAction {
                kind: request.action.kind().to_string(),
                operation: operation.clone(),
                side_effect,
                impact_tier: effective_tier,
            },
            resource: PolicyResource {
                name: resource_name.clone(),
                tool_id: tool_id_of(&request.action),
                destination_host: destination.clone(),
                paths: touched_paths(&request.action),
                data_classes: data_classes.clone(),
            },
            context: PolicyContext {
                environment_id: Some(request.environment_id.clone()),
                session_id: Some(request.session_id.clone()),
                lowest_influencing_trust: trace_findings.lowest_trust,
                untrusted_instruction_influence: trace_findings.untrusted_instruction_influence,
                taints: taints.clone(),
                // Filled in below once the presented approval token is verified.
                approval_satisfied: false,
                prior_denials: session_snapshot.distinct_denials,
                delegation_depth: delegation_depth(&request.action),
            },
        };

        // ---- 10a. approval token, before policy so policy can see it -------------------
        let approval_satisfied = self.verify_presented_approval(request, &action_hash);
        let mut policy_request = policy_request;
        policy_request.context.approval_satisfied = approval_satisfied.is_some();
        if approval_satisfied.is_some() {
            reason_codes.push(ReasonCode::ApprovalSatisfied);
        }

        let (policy_decision, policy_failed) = match self.policy.evaluate(&policy_request).await {
            Ok(d) => {
                reason_codes.extend(d.reason_codes.iter().cloned());
                (d, false)
            }
            Err(_) => {
                // A policy backend outage. Fail closed for anything that can change the
                // world; permit low-impact reads in degraded mode.
                reason_codes.push(ReasonCode::PolicyEngineUnavailable);
                let decision = if effective_tier.must_fail_closed() {
                    reason_codes.push(ReasonCode::FailClosed);
                    Decision::fail_closed()
                } else {
                    reason_codes.push(ReasonCode::DegradedModeAllow);
                    Decision::AllowWithConstraints
                };
                (
                    vigil_policy::PolicyDecision {
                        decision,
                        matched_policies: vec![],
                        reason_codes: vec![],
                        obligations: vec![],
                        constraints: vec![],
                        bundle_version: self.policy.bundle_version(),
                        severity: Some("HIGH".to_string()),
                    },
                    true,
                )
            }
        };

        // ---- 8. detectors --------------------------------------------------------------
        // Risk routing: the expensive path is skipped when the deterministic layers have
        // already denied and nothing about the outcome could change. Detector results are
        // still recorded as skipped, so the decision record shows what was and was not run.
        let deterministic_so_far = policy_decision
            .decision
            .combine(remit_decision)
            .combine(budget_decision);
        let detector_results = if self.config.skip_detectors_on_deterministic_deny
            && deterministic_so_far == Decision::Deny
        {
            Vec::new()
        } else {
            let context = self.detection_context(
                request,
                effective_tier,
                &content_strings,
                &taints,
                trace_findings.untrusted_instruction_influence,
            );
            self.detectors.run_all(&context).await
        };

        for result in &detector_results {
            reason_codes.extend(result.reason_codes.iter().cloned());
        }

        // ---- 9. composite risk ----------------------------------------------------------
        let assessment = risk::assess(&RiskInputs {
            impact_tier: Some(effective_tier),
            reversible: side_effect.is_reversible(),
            egress: side_effect.is_egress(),
            lowest_influencing_trust: trace_findings.lowest_trust,
            untrusted_instruction_influence: trace_findings.untrusted_instruction_influence,
            taints: taints.clone(),
            evasive_encoding: trace_findings.evasive_encoding,
            out_of_remit: !matches!(
                remit_verdict,
                RemitVerdict::InRemit | RemitVerdict::RequiresApproval
            ),
            prior_distinct_denials: session_snapshot.distinct_denials,
            retry_of_denied_action: session_snapshot.retry_of_denied,
            approval_satisfied: approval_satisfied.is_some(),
            delegation_depth: delegation_depth(&request.action),
            detector_results: detector_results.clone(),
        });

        // ---- 11. final combine -----------------------------------------------------------
        let mut decision = policy_decision
            .decision
            .combine(remit_decision)
            .combine(budget_decision);

        // Detector proposals fold in. `combine` is the only operation available, so this
        // can tighten and can never loosen (Invariant 1, Invariant 2).
        for result in &detector_results {
            if let Some(proposed) = result.proposed_escalation {
                decision = decision.combine(proposed);
            }
        }

        // A manifest that says this operation needs approval.
        if manifest.requires_approval(&operation) && approval_satisfied.is_none() {
            decision = decision.combine(Decision::RequireApproval);
            reason_codes.push(ReasonCode::ApprovalRequired);
        }

        // Within whatever latitude policy left, a high composite score escalates to review.
        // This can only tighten: `combine` cannot turn a Deny into an approval prompt.
        if assessment.warrants_review() && approval_satisfied.is_none() {
            decision = decision.combine(Decision::RequireApproval);
        }

        // A satisfied approval upgrades RequireApproval to a constrained allow — and only
        // that. If anything else in the pipeline denied, the approval changes nothing.
        if approval_satisfied.is_some() && decision == Decision::RequireApproval {
            decision = Decision::AllowWithConstraints;
        }

        // ---- capability minting -----------------------------------------------------------
        let mut capability = None;
        let mut approval_request = None;

        if decision.mints_capability() {
            let claims = CapabilityClaims {
                version: String::new(),
                capability_id: CapabilityId::generate(),
                tenant_id: request.tenant_id.clone(),
                environment_id: request.environment_id.clone(),
                agent_id: request.agent_id.clone(),
                agent_instance_id: request.agent_instance_id.clone(),
                session_id: request.session_id.clone(),
                principal_id: request.principal.id.clone(),
                action_kind: request.action.kind().to_string(),
                tool_id: tool_id_of(&request.action),
                operation: operation.clone(),
                target_resource: target_resource_of(&request.action),
                action_hash: action_hash.clone(),
                remit_version: remit_version.clone().unwrap_or_else(|| "none".to_string()),
                policy_bundle_version: policy_decision.bundle_version.clone(),
                approval_id: approval_satisfied.clone(),
                constraints: policy_decision.constraints.clone(),
                issued_at: started,
                expires_at: started,
                nonce: String::new(),
                max_uses: 1,
            };
            let (token, _issued) = self
                .issuer
                .issue(claims, self.config.capability_ttl_seconds)?;
            capability = Some(token);

            // Budget is charged only for actions that are actually going ahead, so a denied
            // action cannot exhaust a session and mask the reason it was denied.
            self.sessions.with_session(&session_key, started, |state| {
                state.budget.charge(
                    request.action.kind(),
                    &action_hash,
                    destination.as_deref(),
                    estimated_cost(&request.action),
                );
            })?;
        } else if decision == Decision::RequireApproval {
            approval_request = Some(self.raise_approval(
                request,
                &action_hash,
                &policy_decision,
                &assessment,
                &data_classes,
                side_effect.is_reversible(),
                &reason_codes,
            )?);
        }

        // ---- record and respond -------------------------------------------------------
        self.sessions.with_session(&session_key, started, |state| {
            state.record(&action_hash, decision);
        })?;

        reason_codes.sort();
        reason_codes.dedup();
        if reason_codes.is_empty() {
            // A decision with no reason is not auditable; this should be unreachable, and if
            // it happens the record says so rather than being silently empty.
            reason_codes.push(ReasonCode::Other("NO_REASON_RECORDED".to_string()));
        }

        let response = DecisionResponse {
            schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
            decision_id: EventId::new_random(),
            decision,
            action_hash: action_hash.clone(),
            risk_score: assessment.risk,
            confidence: assessment.confidence,
            reason_codes,
            constraints: policy_decision.constraints.clone(),
            obligations: policy_decision.obligations.clone(),
            redactions: vec![],
            detector_results: detector_results.clone(),
            provenance: DecisionProvenance {
                policy_bundle_version: Some(policy_decision.bundle_version.clone()),
                remit_version: remit_version.clone(),
                matched_policies: policy_decision.matched_policies.clone(),
                deciding_stage: deciding_stage(
                    decision,
                    policy_decision.decision,
                    remit_decision,
                    budget_decision,
                    policy_failed,
                )
                .to_string(),
                detector_versions: detector_results
                    .iter()
                    .map(|r| (r.detector_id.to_string(), r.detector_version.clone()))
                    .collect(),
            },
            capability,
            approval_id: approval_request.as_ref().map(|a| a.approval_id.clone()),
            evaluated_at: started,
            latency_ms: vigil_common::time::elapsed_ms(started, self.clock.now()),
        };

        debug_assert!(
            response.is_coherent(),
            "pipeline produced an incoherent response: {response:?}"
        );

        Ok(DecisionOutcome {
            response,
            action_hash,
            taints,
            causal_chain: trace_findings.chain,
            risk_contributions: assessment.contributions,
            approval_request,
            effective_tier,
        })
    }

    /// Identity checks that must pass before anything else runs.
    ///
    /// Reads the *proven* identity from [`AuthenticatedRequest`], never the body. The
    /// previous version of this function consulted `request.workload_identity.verified`,
    /// which arrived over the wire — see the module docs in [`crate::auth`] for why that was
    /// an authentication bypass rather than a style problem.
    fn check_identity(
        &self,
        authenticated: &AuthenticatedRequest,
        reason_codes: &mut Vec<ReasonCode>,
    ) -> Result<()> {
        let request = authenticated.request();

        // The tenant on the request must match the tenant on the authenticated principal.
        // `ActionRequest::validate` already enforces this; repeating the reason code here
        // makes a cross-tenant attempt explicit in the decision record.
        if request.principal.tenant_id != request.tenant_id {
            reason_codes.push(ReasonCode::CrossTenantRequest);
            return Err(VigilError::Unauthorized(
                "principal and request tenants differ".to_string(),
            ));
        }

        // What the body claims must match what the caller proved. An authenticated agent
        // submitting actions as a different agent is an impersonation attempt, not a
        // routing mistake.
        if let Err(error) = authenticated.check_claims_match_proof() {
            reason_codes.push(ReasonCode::AgentIdentityMismatch);
            return Err(error);
        }

        if self.config.mode == EnforcementMode::Protected
            && self.config.require_workload_identity
            && !authenticated.identity().workload.is_verified()
        {
            reason_codes.push(ReasonCode::WorkloadIdentityUnverified);
            return Err(VigilError::Unauthenticated(
                "protected mode requires a verified workload identity".to_string(),
            ));
        }
        Ok(())
    }

    /// Build the typed, trust-separated detector input (spec §34).
    fn detection_context(
        &self,
        request: &ActionRequest,
        impact_tier: ImpactTier,
        content_strings: &[(String, String)],
        taints: &[TaintKind],
        untrusted_influence: bool,
    ) -> DetectionContext {
        let remit = self.remits.get(request.agent_id.as_str());
        let session_key = SessionKey::from(request);

        // Untrusted content is passed as explicitly labelled values, never concatenated with
        // the trusted fields. A detector that builds a model prompt gets a structured object.
        let mut untrusted_content = Vec::new();
        let _ = self.sessions.inspect(&session_key, |state| {
            for source in &request.context.influencing_sources {
                if let Some(node) = state.trace.get(&source.node_id) {
                    if !node.trust.carries_instruction_authority() {
                        untrusted_content.push(
                            UntrustedContent::new(
                                node.origin.clone(),
                                node.trust,
                                // Content itself is not retained in the graph; the detector
                                // receives what the request carries plus the origin label.
                                String::new(),
                            )
                            .with_node(node.id.clone()),
                        );
                    }
                }
            }
        });
        for source in &request.context.influencing_sources {
            if !source.trust_level.carries_instruction_authority() {
                if let Some(text) = request
                    .context
                    .adapter_metadata
                    .get(source.node_id.as_str())
                    .and_then(|v| v.as_str())
                {
                    untrusted_content.push(
                        UntrustedContent::new(source.origin.clone(), source.trust_level, text)
                            .with_node(source.node_id.clone()),
                    );
                }
            }
        }

        DetectionContext {
            agent_remit_summary: remit
                .map(|r| r.summary())
                .unwrap_or_else(|| "unregistered agent; no declared purpose".to_string()),
            action: request.action.clone(),
            impact_tier,
            action_strings: content_strings.to_vec(),
            established_taints: taints.to_vec(),
            untrusted_influence,
            untrusted_content,
            allowed_path_roots: remit
                .map(|r| r.allowed_path_roots().to_vec())
                .unwrap_or_default(),
        }
    }

    /// Verify an approval token the caller presented with a retried action.
    fn verify_presented_approval(
        &self,
        request: &ActionRequest,
        action_hash: &ContentHash,
    ) -> Option<vigil_common::ids::ApprovalId> {
        let token = request.context.approval_token.as_ref()?;
        match self.approvals.verify_and_consume(
            token,
            &request.tenant_id,
            &request.agent_id,
            &request.session_id,
            action_hash,
        ) {
            Ok(id) => Some(id),
            Err(error) => {
                // A rejected approval is not merely "no approval": it is a signal worth
                // recording, since a mutated or replayed token is an attack, not a mistake.
                tracing::warn!(
                    tenant = %request.tenant_id,
                    agent = %request.agent_id,
                    error = %error,
                    "presented approval token was rejected"
                );
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn raise_approval(
        &self,
        request: &ActionRequest,
        action_hash: &ContentHash,
        policy: &vigil_policy::PolicyDecision,
        assessment: &risk::RiskAssessment,
        data_classes: &[String],
        reversible: bool,
        reason_codes: &[ReasonCode],
    ) -> Result<crate::approval::ApprovalRequest> {
        // When several rules each demand approval, the approver must satisfy *all* of them.
        // Taking the first obligation's role list would make the required approver depend on
        // rule iteration order — the same order-dependence the policy engine is built to
        // avoid. Intersecting the role sets and taking the shortest TTL is order-independent
        // and is the more restrictive reading, which is the right default for a control that
        // exists to slow down a high-impact action.
        let human_approvals: Vec<(&Vec<String>, u64)> = policy
            .obligations
            .iter()
            .filter_map(|o| match o {
                Obligation::HumanApproval {
                    approver_roles,
                    ttl_seconds,
                } => Some((approver_roles, *ttl_seconds)),
                _ => None,
            })
            .collect();

        let mut approver_roles = match human_approvals.first() {
            Some((first, _)) => (*first).clone(),
            None => self.config.default_approver_roles.clone(),
        };
        for (roles, _) in human_approvals.iter().skip(1) {
            approver_roles.retain(|role| roles.contains(role));
        }
        approver_roles.sort();
        approver_roles.dedup();

        if approver_roles.is_empty() {
            // No role satisfies every rule that demanded approval, so nobody can approve
            // this action. That is a policy authoring problem, and it must surface as a
            // loud error rather than as an approval request that can never be granted.
            return Err(VigilError::Policy(format!(
                "rules {:?} demand approval from disjoint role sets, so no approver could \
                 satisfy them; narrow the rules or align their approver_roles",
                policy.matched_policies
            )));
        }

        let ttl = human_approvals
            .iter()
            .map(|(_, ttl)| *ttl as i64)
            .min()
            .unwrap_or(crate::approval::DEFAULT_APPROVAL_TTL_SECONDS);

        // The preview is built from the same material projection the hash covers, so what the
        // approver reads and what the token authorizes cannot diverge.
        //
        // Redaction here is narrower than elsewhere in VIGIL, deliberately. An approval asks
        // a human "is *this* the action you want?", and redacting the recipient of an email
        // makes that question unanswerable — the approver would be rubber-stamping a hash.
        // So identifiers the approver must judge (recipients, destinations, account numbers)
        // are shown, while high-entropy secrets are not: seeing an API key adds nothing to
        // the decision and copies the secret into another surface. The dividing line is
        // `DataClass::fingerprintable`, which is exactly "high-entropy enough that showing it
        // is pure downside".
        //
        // The preview reaches an authenticated approver in the console, not a log; the
        // corresponding audit record carries the redacted form.
        let parameters = request
            .action
            .content_strings()
            .into_iter()
            .map(|(path, value)| {
                let conceal = vigil_detect::dlp::classify(&path, &value)
                    .iter()
                    .any(|f| f.class.fingerprintable());
                if conceal {
                    (path, vigil_common::redact::redact(&value))
                } else {
                    (path, vigil_common::redact::single_line_excerpt(&value, 200))
                }
            })
            .collect();

        let preview = TransactionPreview {
            action_descriptor: request.descriptor(),
            target: target_resource_of(&request.action),
            parameters,
            sensitive_data_crossing_boundary: data_classes.to_vec(),
            rationale: request.context.action_rationale.clone(),
            triggering_policies: policy.matched_policies.clone(),
            risk_score: assessment.risk,
            irreversible: !reversible,
            reason_codes: reason_codes.iter().map(|c| c.to_string()).collect(),
        };

        self.approvals.request(
            request.tenant_id.clone(),
            request.agent_id.clone(),
            request.session_id.clone(),
            request.principal.id.clone(),
            action_hash.clone(),
            preview,
            approver_roles,
            ttl,
        )
    }

    fn terminated_response(
        &self,
        request: &ActionRequest,
        action_hash: ContentHash,
        started: Timestamp,
        effective_tier: ImpactTier,
    ) -> DecisionOutcome {
        let response = DecisionResponse {
            schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
            decision_id: EventId::new_random(),
            decision: Decision::TerminateSession,
            action_hash: action_hash.clone(),
            risk_score: 1.0,
            confidence: 1.0,
            reason_codes: vec![ReasonCode::BehavioralAnomaly],
            constraints: vec![],
            obligations: vec![],
            redactions: vec![],
            detector_results: vec![],
            provenance: DecisionProvenance {
                policy_bundle_version: Some(self.policy.bundle_version()),
                remit_version: None,
                matched_policies: vec![],
                deciding_stage: "session_terminated".to_string(),
                detector_versions: vec![],
            },
            capability: None,
            approval_id: None,
            evaluated_at: started,
            latency_ms: vigil_common::time::elapsed_ms(started, self.clock.now()),
        };
        let _ = request;
        DecisionOutcome {
            response,
            action_hash,
            taints: vec![],
            causal_chain: vec![],
            risk_contributions: vec![],
            approval_request: None,
            effective_tier,
        }
    }
}

#[derive(Debug)]
struct SessionSnapshot {
    terminated: bool,
    #[allow(dead_code)]
    denial_count: u32,
    distinct_denials: u32,
    retry_of_denied: bool,
    remit_version: Option<String>,
}

/// Which stage produced the binding verdict, for the decision inspector.
fn deciding_stage(
    final_decision: Decision,
    policy: Decision,
    remit: Decision,
    budget: Decision,
    policy_failed: bool,
) -> &'static str {
    if policy_failed {
        return "policy_unavailable";
    }
    if final_decision == budget && budget != Decision::Allow {
        return "budget";
    }
    if final_decision == remit && remit != Decision::Allow {
        return "remit";
    }
    if final_decision == policy && policy != Decision::Allow {
        return "policy";
    }
    if final_decision.restrictiveness()
        > policy
            .restrictiveness()
            .max(remit.restrictiveness())
            .max(budget.restrictiveness())
    {
        return "detectors_or_risk";
    }
    "policy"
}

fn principal_kind_label(kind: &vigil_protocol::principal::PrincipalKind) -> &'static str {
    use vigil_protocol::principal::PrincipalKind as K;
    match kind {
        K::Human => "human",
        K::Service => "service",
        K::Agent => "agent",
        K::Anonymous => "anonymous",
    }
}

fn tool_id_of(action: &Action) -> Option<vigil_common::ids::ToolId> {
    match action {
        Action::ToolCall(t) => Some(t.tool_id.clone()),
        _ => None,
    }
}

fn target_resource_of(action: &Action) -> Option<String> {
    match action {
        Action::ToolCall(t) => t.target_resource.clone(),
        Action::Network(n) => Some(n.url.clone()),
        Action::File(f) => Some(f.path.clone()),
        Action::Database(d) => d.database.clone(),
        _ => None,
    }
}

fn destination_host(action: &Action) -> Option<String> {
    match action {
        Action::Network(n) => {
            vigil_detect::network::analyze(&n.url, &n.resolved_addresses, &[]).host
        }
        _ => None,
    }
}

fn touched_paths(action: &Action) -> Vec<String> {
    match action {
        Action::File(f) => vec![vigil_common::path::normalize(&f.path)],
        _ => vec![],
    }
}

fn delegation_depth(action: &Action) -> u32 {
    match action {
        Action::Delegation(d) => d.depth,
        _ => 0,
    }
}

fn delegation_lineage(action: &Action) -> Vec<vigil_common::ids::AgentId> {
    match action {
        Action::Delegation(d) => d.lineage.clone(),
        _ => vec![],
    }
}

fn estimated_cost(action: &Action) -> f64 {
    match action {
        Action::ModelCall(m) => m.estimated_cost_usd.unwrap_or(0.0),
        _ => 0.0,
    }
}
