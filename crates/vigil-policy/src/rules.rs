//! The built-in deterministic rule language.
//!
//! # Why
//!
//! Invariant 1 requires that deterministic policy is the thing that wins. For that to mean
//! anything, "deterministic" must be literal: the same request against the same bundle must
//! produce the same decision on every replica, in every order, forever. That rules out
//! first-match-wins evaluation (where reordering a file changes outcomes), regex matchers
//! (where a pattern's cost depends on the input) and any implicit fallthrough.
//!
//! # What
//!
//! A bundle is an unordered *set* of rules. Evaluation matches every rule, then resolves the
//! matched effects by taking the most restrictive one. Consequences:
//!
//! * rule order in the file is irrelevant — a merge conflict cannot change a decision
//! * adding a rule can only ever make the system more restrictive, never less
//! * an operator cannot "shadow" a `deny` with an earlier `allow`
//!
//! # Assumptions
//!
//! Matchers are conjunctive: every condition present in a matcher must hold. Unknown fields
//! are a hard parse error, so a typo like `tool_ids:` instead of `tools:` fails validation
//! rather than silently producing a matcher that matches everything.
//!
//! # Failure mode
//!
//! A bundle that fails validation is never loaded; the previous bundle stays in force. A
//! bundle that fails to *parse* at startup prevents the process from starting.

use serde::{Deserialize, Serialize};
use vigil_common::ids::PolicyBundleId;
use vigil_common::{Result, VigilError};
use vigil_protocol::action::{ImpactTier, SideEffectClass};
use vigil_protocol::decision::{Constraint, Decision, Obligation};
use vigil_protocol::reason::ReasonCode;
use vigil_protocol::trust::{TaintKind, TrustLevel};

use crate::glob::{any_host_matches, glob_match};
use crate::request::PolicyRequest;

/// What a matched rule concludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    AllowWithConstraints,
    RequireApproval,
    Quarantine,
    Deny,
    TerminateSession,
}

impl PolicyEffect {
    pub fn to_decision(self) -> Decision {
        match self {
            Self::Allow => Decision::Allow,
            Self::AllowWithConstraints => Decision::AllowWithConstraints,
            Self::RequireApproval => Decision::RequireApproval,
            Self::Quarantine => Decision::Quarantine,
            Self::Deny => Decision::Deny,
            Self::TerminateSession => Decision::TerminateSession,
        }
    }
}

/// Alert-routing severity for a matched rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Conditions a request must satisfy for a rule to apply. All present conditions must hold.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatcher {
    /// Explicitly match every request. Required to write a catch-all, so that an
    /// accidentally-empty matcher is a validation error instead of a universal rule.
    #[serde(default)]
    pub match_all: bool,

    #[serde(default)]
    pub action_kinds: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    /// Glob patterns against the resource name (tool name, `net:host`, `file:read`).
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub side_effects: Vec<SideEffectClass>,
    #[serde(default)]
    pub min_impact_tier: Option<ImpactTier>,

    /// Destination host is in this list.
    #[serde(default)]
    pub destination_hosts: Vec<String>,
    /// Destination host is *not* in this list. The shape an egress allowlist rule takes:
    /// "deny external writes to anywhere except these".
    #[serde(default)]
    pub destination_not_in: Vec<String>,
    /// Any touched path matches one of these globs.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Any touched path is outside all of these roots.
    #[serde(default)]
    pub paths_outside: Vec<String>,

    /// Any of these taints is present.
    #[serde(default)]
    pub taints_any: Vec<TaintKind>,
    /// All of these taints are present.
    #[serde(default)]
    pub taints_all: Vec<TaintKind>,
    /// The action was, or was not, influenced by untrusted instruction-like content.
    #[serde(default)]
    pub untrusted_instruction_influence: Option<bool>,
    /// The lowest influencing trust level ranks below this one.
    #[serde(default)]
    pub influencing_trust_below: Option<TrustLevel>,
    #[serde(default)]
    pub data_classes_any: Vec<String>,

    #[serde(default)]
    pub principal_kinds: Vec<String>,
    #[serde(default)]
    pub principal_roles_any: Vec<String>,
    /// Match only when the principal's MFA status equals this.
    #[serde(default)]
    pub principal_mfa: Option<bool>,
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub approval_satisfied: Option<bool>,
    #[serde(default)]
    pub delegation_depth_min: Option<u32>,
    #[serde(default)]
    pub prior_denials_min: Option<u32>,
}

impl RuleMatcher {
    /// Whether this matcher constrains anything at all.
    fn is_empty(&self) -> bool {
        *self == RuleMatcher::default()
    }

    /// Evaluate the matcher against a request.
    fn matches(&self, req: &PolicyRequest) -> bool {
        if self.match_all {
            return true;
        }

        if !self.action_kinds.is_empty() && !self.action_kinds.contains(&req.action.kind) {
            return false;
        }
        if !self.operations.is_empty()
            && !self
                .operations
                .iter()
                .any(|o| o.eq_ignore_ascii_case(&req.action.operation))
        {
            return false;
        }
        if !self.resources.is_empty()
            && !self
                .resources
                .iter()
                .any(|p| glob_match(p, &req.resource.name))
        {
            return false;
        }
        if !self.side_effects.is_empty() && !self.side_effects.contains(&req.action.side_effect) {
            return false;
        }
        if let Some(min) = self.min_impact_tier {
            if req.action.impact_tier < min {
                return false;
            }
        }

        if !self.destination_hosts.is_empty() {
            match &req.resource.destination_host {
                Some(h) if any_host_matches(&self.destination_hosts, h) => {}
                _ => return false,
            }
        }
        if !self.destination_not_in.is_empty() {
            match &req.resource.destination_host {
                // An action with no identifiable destination cannot be proven to be inside
                // the allowlist, so it matches the "not in" condition. Failing open here
                // would make every allowlist bypassable by omitting the host.
                None => {}
                Some(h) if !any_host_matches(&self.destination_not_in, h) => {}
                Some(_) => return false,
            }
        }
        if !self.paths.is_empty()
            && !req
                .resource
                .paths
                .iter()
                .any(|path| self.paths.iter().any(|p| glob_match(p, path)))
        {
            return false;
        }
        if !self.paths_outside.is_empty() {
            let all_inside = req.resource.paths.iter().all(|path| {
                self.paths_outside
                    .iter()
                    .any(|root| path.starts_with(root.as_str()))
            });
            if req.resource.paths.is_empty() || all_inside {
                return false;
            }
        }

        if !self.taints_any.is_empty()
            && !self
                .taints_any
                .iter()
                .any(|t| req.context.taints.contains(t))
        {
            return false;
        }
        if !self.taints_all.is_empty()
            && !self
                .taints_all
                .iter()
                .all(|t| req.context.taints.contains(t))
        {
            return false;
        }
        if let Some(expected) = self.untrusted_instruction_influence {
            if req.context.untrusted_instruction_influence != expected {
                return false;
            }
        }
        if let Some(threshold) = self.influencing_trust_below {
            match req.context.lowest_influencing_trust {
                Some(actual) if actual.rank() < threshold.rank() => {}
                _ => return false,
            }
        }
        if !self.data_classes_any.is_empty()
            && !self
                .data_classes_any
                .iter()
                .any(|c| req.resource.data_classes.contains(c))
        {
            return false;
        }

        if !self.principal_kinds.is_empty() && !self.principal_kinds.contains(&req.principal.kind) {
            return false;
        }
        if !self.principal_roles_any.is_empty()
            && !self
                .principal_roles_any
                .iter()
                .any(|r| req.principal.roles.contains(r))
        {
            return false;
        }
        if let Some(expected) = self.principal_mfa {
            if req.principal.mfa != expected {
                return false;
            }
        }
        if !self.environments.is_empty() {
            match &req.context.environment_id {
                Some(env) if self.environments.iter().any(|e| e == env.as_str()) => {}
                _ => return false,
            }
        }
        if let Some(expected) = self.approval_satisfied {
            if req.context.approval_satisfied != expected {
                return false;
            }
        }
        if let Some(min) = self.delegation_depth_min {
            if req.context.delegation_depth < min {
                return false;
            }
        }
        if let Some(min) = self.prior_denials_min {
            if req.context.prior_denials < min {
                return false;
            }
        }
        true
    }
}

/// One policy rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable identifier, reported in every decision that matches it.
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub effect: PolicyEffect,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(rename = "when")]
    pub matcher: RuleMatcher,
    #[serde(default)]
    pub reason_codes: Vec<ReasonCode>,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    /// Whether this rule is enforced or only observed. Simulation and canary rollout set this.
    #[serde(default)]
    pub audit_only: bool,
}

fn default_severity() -> Severity {
    Severity::Medium
}

/// A versioned, self-contained set of rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub version: PolicyBundleId,
    #[serde(default)]
    pub description: String,
    /// What happens when no rule matches.
    ///
    /// Defaults to `deny`. A bundle that wants a permissive default has to say so in
    /// writing, in a file that goes through review.
    #[serde(default = "default_effect")]
    pub default_effect: PolicyEffect,
    pub rules: Vec<Rule>,
}

fn default_effect() -> PolicyEffect {
    PolicyEffect::Deny
}

impl PolicyBundle {
    /// Parse from YAML.
    pub fn from_yaml(src: &str) -> Result<Self> {
        let bundle: Self = serde_yaml_ng::from_str(src)
            .map_err(|e| VigilError::Policy(format!("policy bundle is not valid: {e}")))?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Parse from JSON.
    pub fn from_json(src: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(src)
            .map_err(|e| VigilError::Policy(format!("policy bundle is not valid: {e}")))?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Reject bundles that would behave surprisingly.
    ///
    /// Every check here corresponds to a way a well-meaning policy author can accidentally
    /// disable enforcement. Catching them at load time — and in CI, via `vigil policy
    /// validate` — is much cheaper than catching them in an incident review.
    pub fn validate(&self) -> Result<()> {
        if self.rules.is_empty() {
            return Err(VigilError::Policy(
                "policy bundle contains no rules".to_string(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(VigilError::Policy("a rule has an empty id".to_string()));
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(VigilError::Policy(format!(
                    "duplicate rule id `{}`; ids must be unique so decisions are attributable",
                    rule.id
                )));
            }
            if rule.matcher.is_empty() {
                return Err(VigilError::Policy(format!(
                    "rule `{}` has no conditions; set `match_all: true` if a catch-all is intended",
                    rule.id
                )));
            }
            if rule.matcher.match_all && matches!(rule.effect, PolicyEffect::Allow) {
                return Err(VigilError::Policy(format!(
                    "rule `{}` allows everything; a universal allow disables enforcement and \
                     must be expressed as narrower rules",
                    rule.id
                )));
            }
            if rule.matcher.destination_hosts.iter().any(|h| h == "*")
                || rule.matcher.destination_not_in.iter().any(|h| h == "*")
            {
                return Err(VigilError::Policy(format!(
                    "rule `{}` uses `*` as a host pattern, which never matches; use `match_all` \
                     or an explicit list",
                    rule.id
                )));
            }
        }
        Ok(())
    }

    /// Evaluate every rule and resolve the result.
    ///
    /// Order-independent by construction: matched effects are folded through
    /// [`Decision::combine`], which is commutative and associative.
    pub fn evaluate(&self, req: &PolicyRequest) -> ResolvedPolicy {
        let mut decision: Option<Decision> = None;
        let mut matched = Vec::new();
        let mut reason_codes = Vec::new();
        let mut obligations = Vec::new();
        let mut constraints = Vec::new();
        let mut severity: Option<Severity> = None;
        let mut audit_only_matches = Vec::new();

        for rule in &self.rules {
            if !rule.matcher.matches(req) {
                continue;
            }
            if rule.audit_only {
                // Recorded so simulation and canary rollout can report what *would* have
                // happened, but contributes nothing to the decision.
                audit_only_matches.push((rule.id.clone(), rule.effect));
                continue;
            }
            matched.push(rule.id.clone());
            let effect = rule.effect.to_decision();
            decision = Some(match decision {
                Some(d) => d.combine(effect),
                None => effect,
            });
            reason_codes.extend(rule.reason_codes.iter().cloned());
            obligations.extend(rule.obligations.iter().cloned());
            constraints.extend(rule.constraints.iter().cloned());
            severity = Some(severity.map_or(rule.severity, |s| s.max(rule.severity)));
        }

        let (decision, default_applied) = match decision {
            Some(d) => (d, false),
            None => (self.default_effect.to_decision(), true),
        };
        if default_applied && !decision.permits_execution() {
            reason_codes.push(ReasonCode::PolicyDefaultDeny);
        }
        if !default_applied && decision.permits_execution() && reason_codes.is_empty() {
            reason_codes.push(ReasonCode::PolicyAllow);
        }
        if !default_applied && !decision.permits_execution() && reason_codes.is_empty() {
            reason_codes.push(ReasonCode::PolicyDeny);
        }

        // Obligations and constraints attached to rules that lost the resolution still apply
        // when execution is permitted: a rule saying "if you allow this, require approval
        // evidence" must not be discarded because a stricter rule also matched.
        ResolvedPolicy {
            decision,
            matched_policies: matched,
            reason_codes,
            obligations,
            constraints,
            severity: severity.map(|s| s.as_str().to_string()),
            default_applied,
            audit_only_matches,
        }
    }
}

/// The result of evaluating a bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedPolicy {
    pub decision: Decision,
    pub matched_policies: Vec<String>,
    pub reason_codes: Vec<ReasonCode>,
    pub obligations: Vec<Obligation>,
    pub constraints: Vec<Constraint>,
    pub severity: Option<String>,
    /// Whether the bundle's default applied because nothing matched.
    pub default_applied: bool,
    /// Rules that matched but are in audit-only mode, for simulation reporting.
    pub audit_only_matches: Vec<(String, PolicyEffect)>,
}
