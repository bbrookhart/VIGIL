//! VIGIL Remit: what an agent is *for*.
//!
//! # Why
//!
//! Policy answers "is this action permitted?". Remit answers a different question: "is this
//! the kind of thing this agent exists to do?". The distinction matters because goal hijack
//! (ASI01 in the OWASP Agentic Top 10, 2026) does not usually produce individually forbidden
//! actions — it produces a plausible sequence of permitted ones that add up to something the
//! agent was never meant to do. A support assistant reading a customer record is fine; a
//! support assistant that has started enumerating credentials is not, even if each read is
//! individually allowed.
//!
//! Remit is also the budget boundary, which is what makes denial-of-wallet and runaway loops
//! enforceable rather than merely observable.
//!
//! # What
//!
//! A human-authored YAML declaration, compiled to a lookup structure evaluated on the fast
//! path. Every decision records the exact remit version it was made under, and an agent
//! instance pins its remit version for its whole life so a mid-session edit cannot
//! retroactively legitimize earlier behaviour.
//!
//! # Failure mode
//!
//! An agent with no remit is not an unconstrained agent: [`RemitVerdict::NoRemit`] is
//! returned and the pipeline treats it as out-of-remit unless the deployment explicitly
//! enables unregistered agents (a development-only setting).

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod budget;
mod schema;

pub use budget::{BudgetLedger, BudgetSnapshot, BudgetVerdict};
pub use schema::{DataBoundary, Limits, Remit, ToolPermission};

use std::collections::HashMap;
use vigil_common::{Result, VigilError};
use vigil_protocol::reason::ReasonCode;

/// What the remit says about a candidate action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemitVerdict {
    /// The action is within the agent's declared purpose.
    InRemit,
    /// Within remit, but the remit itself requires approval for this operation.
    RequiresApproval,
    /// Outside the remit, with the reason code explaining which boundary was crossed.
    OutOfRemit(ReasonCode),
    /// The agent has no registered remit.
    NoRemit,
}

impl RemitVerdict {
    pub fn permits(&self) -> bool {
        matches!(self, Self::InRemit)
    }

    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::InRemit => ReasonCode::WithinRemit,
            Self::RequiresApproval => ReasonCode::ApprovalRequired,
            Self::OutOfRemit(code) => code.clone(),
            Self::NoRemit => ReasonCode::RemitMissing,
        }
    }
}

/// A remit compiled for evaluation.
#[derive(Debug, Clone)]
pub struct CompiledRemit {
    remit: Remit,
    tools: HashMap<String, ToolPermission>,
    /// Version string recorded on every decision, e.g. `customer-support-assistant@3`.
    version: String,
}

impl CompiledRemit {
    /// Compile a validated remit.
    pub fn compile(remit: Remit) -> Result<Self> {
        remit.validate()?;
        let version = format!("{}@{}", remit.agent, remit.version);
        let tools = remit
            .tools
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        Ok(Self {
            remit,
            tools,
            version,
        })
    }

    pub fn from_yaml(src: &str) -> Result<Self> {
        Self::compile(Remit::from_yaml(src)?)
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn agent(&self) -> &str {
        &self.remit.agent
    }

    pub fn limits(&self) -> &Limits {
        &self.remit.limits
    }

    pub fn allowed_path_roots(&self) -> &[String] {
        &self.remit.filesystem.allowed_roots
    }

    pub fn allowed_destinations(&self) -> &[String] {
        &self.remit.network.allowed_destinations
    }

    /// A one-line summary for detector context. Trusted content.
    pub fn summary(&self) -> String {
        format!(
            "Agent `{}` exists to: {}. It must never: {}.",
            self.remit.agent,
            self.remit.purpose.join("; "),
            self.remit.forbidden_goals.join("; ")
        )
    }

    /// Evaluate a candidate action against the remit.
    ///
    /// Checks are ordered from most specific to least, so the reason code an operator sees
    /// names the narrowest boundary that was crossed rather than a generic "out of remit".
    pub fn evaluate(&self, action: &vigil_protocol::action::Action) -> RemitVerdict {
        let resource = action.resource_name();
        let operation = action.operation();

        // A forbidden goal beats every allow: the remit's `forbidden_goals` are the things
        // that stay forbidden even if a tool entry would otherwise permit them.
        if self.matches_forbidden_goal(&resource, &operation) {
            return RemitVerdict::OutOfRemit(ReasonCode::ForbiddenGoal);
        }

        match action {
            vigil_protocol::action::Action::File(f) => {
                return self.evaluate_path(&f.path);
            }
            vigil_protocol::action::Action::Network(n) => {
                return self.evaluate_destination(n);
            }
            vigil_protocol::action::Action::Delegation(d) => {
                if d.depth >= self.remit.limits.max_delegation_depth {
                    return RemitVerdict::OutOfRemit(ReasonCode::DelegationDepthExceeded);
                }
            }
            _ => {}
        }

        let Some(permission) = self.tools.get(&resource) else {
            return RemitVerdict::OutOfRemit(ReasonCode::OutOfRemitTool);
        };
        if !permission.operations.iter().any(|o| o == &operation) {
            return RemitVerdict::OutOfRemit(ReasonCode::OutOfRemitOperation);
        }
        if permission
            .approval_required_operations
            .iter()
            .any(|o| o == &operation)
        {
            return RemitVerdict::RequiresApproval;
        }
        RemitVerdict::InRemit
    }

    fn evaluate_path(&self, path: &str) -> RemitVerdict {
        let roots = &self.remit.filesystem.allowed_roots;
        if roots.is_empty() {
            return RemitVerdict::OutOfRemit(ReasonCode::OutOfRemitResource);
        }
        if vigil_common::path::is_inside_any(path, roots) {
            RemitVerdict::InRemit
        } else {
            RemitVerdict::OutOfRemit(ReasonCode::PathOutsideAllowlist)
        }
    }

    fn evaluate_destination(
        &self,
        request: &vigil_protocol::action::NetworkRequest,
    ) -> RemitVerdict {
        let allowed = &self.remit.network.allowed_destinations;
        if allowed.is_empty() {
            return RemitVerdict::OutOfRemit(ReasonCode::EgressDestinationForbidden);
        }
        let host = url::host_of(&request.url).unwrap_or_default();
        if host.is_empty() {
            // An unidentifiable destination cannot be shown to be permitted.
            return RemitVerdict::OutOfRemit(ReasonCode::EgressDestinationForbidden);
        }
        if vigil_policy::glob::any_host_matches(allowed, &host) {
            RemitVerdict::InRemit
        } else {
            RemitVerdict::OutOfRemit(ReasonCode::EgressDestinationForbidden)
        }
    }

    /// Whether the resource or operation names something the remit explicitly forbids.
    ///
    /// Matching is on normalized substrings of the forbidden-goal text, which is coarse by
    /// design: `forbidden_goals` is written by a human describing intent, and a coarse match
    /// here produces a *deny*, so its failure mode is a false positive an operator can see
    /// and narrow, not a silent bypass.
    fn matches_forbidden_goal(&self, resource: &str, operation: &str) -> bool {
        let haystack = format!("{resource} {operation}").to_lowercase();
        self.remit.forbidden_goals.iter().any(|goal| {
            goal.to_lowercase()
                .split_whitespace()
                .filter(|w| w.len() > 4)
                .any(|keyword| haystack.contains(keyword))
        })
    }

    /// Whether a data class may leave the trust boundary under this remit.
    pub fn permits_egress_of(&self, data_class: &str) -> bool {
        !self
            .remit
            .data
            .forbidden_egress_classes
            .iter()
            .any(|c| c.eq_ignore_ascii_case(data_class))
    }
}

/// Remits for every registered agent.
#[derive(Debug, Default)]
pub struct RemitRegistry {
    remits: HashMap<String, CompiledRemit>,
}

impl RemitRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, remit: CompiledRemit) {
        self.remits.insert(remit.agent().to_string(), remit);
    }

    /// Load every `.yaml` remit in a directory.
    pub fn load_directory(dir: &std::path::Path) -> Result<Self> {
        let mut registry = Self::new();
        let entries = std::fs::read_dir(dir)?;
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "yaml" || e == "yml")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path)?;
            let remit = CompiledRemit::from_yaml(&src)
                .map_err(|e| VigilError::Remit(format!("{}: {e}", path.display())))?;
            registry.register(remit);
        }
        Ok(registry)
    }

    pub fn get(&self, agent: &str) -> Option<&CompiledRemit> {
        self.remits.get(agent)
    }

    pub fn len(&self) -> usize {
        self.remits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.remits.is_empty()
    }

    /// Evaluate an action for an agent, returning [`RemitVerdict::NoRemit`] when unregistered.
    pub fn evaluate(
        &self,
        agent: &str,
        action: &vigil_protocol::action::Action,
    ) -> (RemitVerdict, Option<String>) {
        match self.remits.get(agent) {
            Some(remit) => (remit.evaluate(action), Some(remit.version().to_string())),
            None => (RemitVerdict::NoRemit, None),
        }
    }
}

/// Minimal URL host extraction, kept local so this crate does not pull in a URL parser
/// solely to read a hostname.
mod url {
    pub fn host_of(url: &str) -> Option<String> {
        let rest = url.split_once("://")?.1;
        let authority = rest.split(['/', '?', '#']).next()?;
        // Everything before the last `@` is userinfo and is not the host.
        let host = authority.rsplit('@').next()?;
        let host = host.split(':').next()?;
        Some(host.trim_end_matches('.').to_ascii_lowercase())
    }
}
