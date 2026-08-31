//! Deterministic authorization for VIGIL.
//!
//! # Why
//!
//! Everything else in VIGIL is evidence; this is the part that decides. Invariant 1 makes it
//! the authority no detector can overrule, which means its behaviour must be predictable
//! enough to reason about in an incident review months later.
//!
//! # What
//!
//! [`PolicyEngine`] is the provider abstraction (spec §9). Core depends on the trait, never
//! on an implementation, so Cedar or OPA can be substituted without touching the pipeline.
//! [`DeterministicPolicyEngine`] is the built-in provider: an order-independent rule set with
//! a default-deny posture.
//!
//! # Failure mode
//!
//! An engine that cannot answer returns `Err`, never a permissive default. Choosing what to
//! do about that failure belongs to the pipeline, which knows the action's impact tier and
//! applies Invariant 7 — a policy crate that guessed "allow" on error would make that choice
//! impossible to override.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod glob;
pub mod request;
pub mod rules;

pub use request::{
    PolicyAction, PolicyContext, PolicyDecision, PolicyPrincipal, PolicyRequest, PolicyResource,
};
pub use rules::{PolicyBundle, PolicyEffect, ResolvedPolicy, Rule, RuleMatcher, Severity};

use async_trait::async_trait;
use std::sync::Arc;
use vigil_common::ids::PolicyBundleId;
use vigil_common::Result;

/// A source of deterministic authorization decisions.
#[async_trait]
pub trait PolicyEngine: Send + Sync + std::fmt::Debug {
    /// Answer one authorization question.
    ///
    /// Implementations must be pure with respect to the request: the same request against
    /// the same bundle must always produce the same decision. Anything time-varying belongs
    /// in [`PolicyContext`], where it is visible to audit, rather than read from the
    /// environment inside the engine.
    async fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision>;

    /// The bundle version currently in force, recorded on every decision.
    fn bundle_version(&self) -> PolicyBundleId;

    /// Provider name for metrics and diagnostics.
    fn provider(&self) -> &'static str;
}

/// The built-in rule-based provider.
#[derive(Debug)]
pub struct DeterministicPolicyEngine {
    bundle: Arc<PolicyBundle>,
}

impl DeterministicPolicyEngine {
    pub fn new(bundle: PolicyBundle) -> Self {
        Self {
            bundle: Arc::new(bundle),
        }
    }

    /// Load a bundle from YAML source.
    pub fn from_yaml(src: &str) -> Result<Self> {
        Ok(Self::new(PolicyBundle::from_yaml(src)?))
    }

    /// Load and merge every `.yaml`/`.yml` bundle under a directory.
    ///
    /// Merging is a set union with duplicate-id rejection, so a policy repository can be
    /// organized into `base/`, `tools/`, `agents/` and `tenants/` without file order
    /// affecting the outcome.
    pub fn from_directory(dir: &std::path::Path, version: PolicyBundleId) -> Result<Self> {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "yaml" || e == "yml")
            })
            .collect();
        // Sorted purely so error messages are reproducible; evaluation does not depend on it.
        files.sort();

        let mut rules = Vec::new();
        let mut default_effect = PolicyEffect::Deny;
        for path in &files {
            let src = std::fs::read_to_string(path)?;
            let bundle = PolicyBundle::from_yaml(&src).map_err(|e| {
                vigil_common::VigilError::Policy(format!("{}: {e}", path.display()))
            })?;
            // The most restrictive default across merged files wins, so adding a file can
            // never loosen the fallback.
            if matches!(bundle.default_effect, PolicyEffect::Deny) {
                default_effect = PolicyEffect::Deny;
            }
            rules.extend(bundle.rules);
        }
        let merged = PolicyBundle {
            version,
            description: format!("merged from {}", dir.display()),
            default_effect,
            rules,
        };
        merged.validate()?;
        Ok(Self::new(merged))
    }

    pub fn bundle(&self) -> &PolicyBundle {
        &self.bundle
    }

    /// Evaluate synchronously. Used by the CLI's `policy test` and `policy simulate`.
    pub fn evaluate_sync(&self, request: &PolicyRequest) -> PolicyDecision {
        let resolved = self.bundle.evaluate(request);
        PolicyDecision {
            decision: resolved.decision,
            matched_policies: resolved.matched_policies,
            reason_codes: resolved.reason_codes,
            obligations: resolved.obligations,
            constraints: resolved.constraints,
            bundle_version: self.bundle.version.clone(),
            severity: resolved.severity,
        }
    }
}

#[async_trait]
impl PolicyEngine for DeterministicPolicyEngine {
    async fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision> {
        Ok(self.evaluate_sync(request))
    }

    fn bundle_version(&self) -> PolicyBundleId {
        self.bundle.version.clone()
    }

    fn provider(&self) -> &'static str {
        "deterministic"
    }
}
