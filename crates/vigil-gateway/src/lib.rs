//! VIGIL Gateway: the Policy Enforcement Point.
//!
//! # Why
//!
//! An SDK wrapper is not security. If the agent holds the mail provider's API key, it can
//! call the mail provider directly and VIGIL is a logging library. The Gateway is what makes
//! the product promise structural rather than cooperative: **it holds the credentials and the
//! agent does not**, so the only route to a protected tool runs through a capability check.
//!
//! ```text
//! agent ──(no credentials)──▶ Gateway ──(brokered credentials)──▶ real tool
//!                                │
//!                                └─ verify capability, or refuse
//! ```
//!
//! # What
//!
//! One entry point, [`Gateway::execute`], which:
//!
//! 1. **recomputes** the action hash from the request body it actually received
//! 2. verifies the capability against that recomputed hash
//! 3. consumes one use of the capability
//! 4. enforces the capability's constraints
//! 5. injects brokered credentials — never returning them to the caller
//! 6. dispatches to the real tool
//! 7. reports what actually happened
//!
//! Step 1 is the one that matters most. A gateway that trusted the hash *inside* the token,
//! or trusted a hash the client supplied, would authorize whatever the client claimed rather
//! than what it sent — which is the whole attack.
//!
//! # Failure mode
//!
//! There is no execution path that does not pass capability verification. Refusal is the
//! default in every error case: unparsable body, missing capability, unknown tool,
//! constraint violation. A tool backend that errors is reported as attempted-and-failed,
//! which is distinct from not-attempted, because an operator needs to know whether the side
//! effect may have occurred.
//!
//! # Evidence
//!
//! `tests/gateway_enforcement.rs` covers direct-call refusal, replay, mutation, expiry,
//! cross-agent reuse and constraint enforcement.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod api;
pub mod broker;
pub mod tools;

pub use broker::{CredentialBroker, CredentialRef};
pub use tools::{ToolBackend, ToolInvocation, ToolOutcome, ToolRegistry};
pub use vigil_identity::{Authenticator, CallerKind, VerifiedIdentity as GatewayCaller};

use std::sync::Arc;
use vigil_capability::{CapabilityVerifier, PresentedAction};
use vigil_common::{ContentHash, Result, VigilError};
use vigil_identity::VerifiedIdentity;
use vigil_protocol::decision::Constraint;
use vigil_protocol::reason::ReasonCode;
use vigil_protocol::ActionRequest;

/// The result of presenting an action at the gateway.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Whether the protected side effect actually happened.
    pub executed: bool,
    /// The tool's response, when it ran.
    pub output: Option<serde_json::Value>,
    /// Why it was refused, when it was.
    pub refusal: Option<ReasonCode>,
    /// The capability that authorized it.
    pub capability_id: Option<vigil_common::ids::CapabilityId>,
    /// Human-readable detail, already sanitized.
    pub detail: String,
}

impl ExecutionResult {
    fn refused(reason: ReasonCode, detail: impl Into<String>) -> Self {
        Self {
            executed: false,
            output: None,
            refusal: Some(reason),
            capability_id: None,
            detail: detail.into(),
        }
    }
}

/// The enforcement point.
pub struct Gateway {
    verifier: CapabilityVerifier,
    tools: Arc<ToolRegistry>,
    broker: Arc<CredentialBroker>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("tools", &self.tools.len())
            .finish()
    }
}

impl Gateway {
    pub fn new(
        verifier: CapabilityVerifier,
        tools: Arc<ToolRegistry>,
        broker: Arc<CredentialBroker>,
    ) -> Self {
        Self {
            verifier,
            tools,
            broker,
        }
    }

    /// Execute an action for an authenticated caller.
    ///
    /// `caller` is the identity the API layer established from the transport. Passing `None`
    /// is only correct for in-process callers already inside the trust boundary (the tests
    /// and the demo); the HTTP layer always supplies one.
    ///
    /// Why the caller matters when a capability is already required: a capability is a bearer
    /// token for the seconds it lives. If it leaks — a proxy log, a crash dump, a compromised
    /// sidecar — anything holding it could redeem it. Checking that the *presenter* is the
    /// agent the capability names turns theft into something that also requires stealing an
    /// SVID and a private key.
    pub async fn execute_as(
        &self,
        request: &ActionRequest,
        capability_token: Option<&str>,
        caller: Option<&VerifiedIdentity>,
    ) -> Result<ExecutionResult> {
        if let Some(caller) = caller {
            if let Err(reason) = check_caller_matches_request(caller, request) {
                return Ok(ExecutionResult::refused(
                    ReasonCode::AgentIdentityMismatch,
                    reason,
                ));
            }
        }
        self.execute_verified(request, capability_token, caller)
            .await
    }

    /// Execute for an in-process caller inside the trust boundary.
    ///
    /// Retained so tests and the demo read clearly. The HTTP layer uses
    /// [`Self::execute_as`], and `tests/gateway_authentication.rs` asserts that.
    pub async fn execute(
        &self,
        request: &ActionRequest,
        capability_token: Option<&str>,
    ) -> Result<ExecutionResult> {
        self.execute_as(request, capability_token, None).await
    }

    async fn execute_verified(
        &self,
        request: &ActionRequest,
        capability_token: Option<&str>,
        caller: Option<&VerifiedIdentity>,
    ) -> Result<ExecutionResult> {
        let _ = caller;
        // An action with no capability never reaches a tool. This is the case that makes
        // "the agent called the API directly" impossible in Protected mode: the agent has no
        // credentials, so its only route here is the gateway, and the gateway needs a token.
        let Some(token) = capability_token else {
            return Ok(ExecutionResult::refused(
                ReasonCode::CapabilityMissing,
                "no capability was presented",
            ));
        };

        // Recompute the hash from the body we actually received. Never read it from the
        // token, and never accept one from the client.
        let presented_hash: ContentHash = request.action_hash()?;

        let presented = PresentedAction {
            tenant_id: request.tenant_id.clone(),
            environment_id: request.environment_id.clone(),
            agent_id: request.agent_id.clone(),
            agent_instance_id: request.agent_instance_id.clone(),
            session_id: request.session_id.clone(),
            principal_id: request.principal.id.clone(),
            action_kind: request.action.kind().to_string(),
            tool_id: match &request.action {
                vigil_protocol::action::Action::ToolCall(t) => Some(t.tool_id.clone()),
                _ => None,
            },
            operation: request.action.operation(),
            target_resource: match &request.action {
                vigil_protocol::action::Action::ToolCall(t) => t.target_resource.clone(),
                vigil_protocol::action::Action::Network(n) => Some(n.url.clone()),
                vigil_protocol::action::Action::File(f) => Some(f.path.clone()),
                _ => None,
            },
            action_hash: presented_hash,
        };

        let verified = match self.verifier.verify_and_consume(token, &presented) {
            Ok(v) => v,
            Err(error) => {
                let reason = classify_capability_failure(&error);
                tracing::warn!(
                    tenant = %request.tenant_id,
                    agent = %request.agent_id,
                    reason = %reason,
                    "capability rejected at the gateway"
                );
                return Ok(ExecutionResult::refused(reason, error.to_string()));
            }
        };

        // Constraints ride on the capability and are enforced here, at the last moment
        // before the side effect, rather than trusted to have been applied earlier.
        if let Err(violation) = enforce_constraints(&verified.claims.constraints, request) {
            return Ok(ExecutionResult::refused(
                ReasonCode::ToolArgumentSchemaViolation,
                violation,
            ));
        }

        let tool_name = request.action.resource_name();
        let Some(backend) = self.tools.get(&tool_name) else {
            return Ok(ExecutionResult::refused(
                ReasonCode::ToolUnregistered,
                "no backend is registered for this tool",
            ));
        };

        // Credentials are resolved here and handed to the backend. They are never returned
        // to the caller and never appear in the response, so they cannot reach model context
        // (Invariant 6).
        let credentials = self.broker.resolve(&tool_name, &verified.claims)?;

        let invocation = ToolInvocation {
            tool: tool_name.clone(),
            operation: request.action.operation(),
            arguments: match &request.action {
                vigil_protocol::action::Action::ToolCall(t) => t.arguments.clone(),
                other => other.material_projection(),
            },
            credentials,
            capability_id: verified.claims.capability_id.clone(),
        };

        match backend.invoke(invocation).await {
            Ok(ToolOutcome { output }) => Ok(ExecutionResult {
                executed: true,
                output: Some(output),
                refusal: None,
                capability_id: Some(verified.claims.capability_id),
                detail: "executed".to_string(),
            }),
            Err(error) => Ok(ExecutionResult {
                // The capability was valid and the tool was called. Whether the side effect
                // landed is unknown, and reporting it as "not executed" would be a lie an
                // incident responder would act on.
                executed: true,
                output: None,
                refusal: None,
                capability_id: Some(verified.claims.capability_id),
                detail: format!(
                    "tool invocation failed after authorization: {}",
                    vigil_common::redact::single_line_excerpt(&error.to_string(), 200)
                ),
            }),
        }
    }
}

/// Check that the authenticated caller is the agent the request claims to be.
///
/// Returns the reason for refusal, already safe to log. The capability's own bindings are
/// checked separately by the verifier; this is the check that the *presenter* is who the
/// capability was minted for, which a capability alone cannot establish.
fn check_caller_matches_request(
    caller: &VerifiedIdentity,
    request: &ActionRequest,
) -> std::result::Result<(), String> {
    if caller.tenant_id != request.tenant_id {
        return Err(
            "the authenticated caller belongs to a different tenant than the request".to_string(),
        );
    }
    if let Some(agent) = &caller.agent_id {
        if agent != &request.agent_id {
            return Err(format!(
                "the authenticated caller is agent `{agent}`, which is not the agent this \
                 request claims to act as"
            ));
        }
    }
    Ok(())
}

/// Map a verification error to the reason code an operator will filter on.
fn classify_capability_failure(error: &VigilError) -> ReasonCode {
    let text = error.to_string();
    if text.contains("already redeemed") {
        ReasonCode::CapabilityReplay
    } else if text.contains("expired") {
        ReasonCode::CapabilityExpired
    } else if text.contains("does not match the authorized action") {
        ReasonCode::CapabilityActionMismatch
    } else if text.contains("binding does not match")
        || text.contains("does not match the presented")
    {
        ReasonCode::CapabilityBindingMismatch
    } else if text.contains("signature") || text.contains("untrusted key") {
        ReasonCode::CapabilitySignatureInvalid
    } else {
        ReasonCode::CapabilityBindingMismatch
    }
}

/// Enforce the constraints a decision attached to the capability.
fn enforce_constraints(
    constraints: &[Constraint],
    request: &ActionRequest,
) -> std::result::Result<(), String> {
    for constraint in constraints {
        match constraint {
            Constraint::AllowedHosts { hosts } => {
                if let vigil_protocol::action::Action::Network(n) = &request.action {
                    let host = n
                        .url
                        .split("://")
                        .nth(1)
                        .and_then(|r| r.split(['/', '?', '#']).next())
                        .and_then(|a| a.rsplit('@').next())
                        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
                        .unwrap_or_default();
                    if !hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
                        return Err("destination is not in the capability's host list".to_string());
                    }
                }
            }
            Constraint::ArgumentAllowlist { paths } => {
                for (path, _) in request.action.content_strings() {
                    if !paths.iter().any(|p| path.starts_with(p.as_str())) {
                        return Err(format!(
                            "argument `{}` is not permitted by the capability",
                            vigil_common::redact::single_line_excerpt(&path, 60)
                        ));
                    }
                }
            }
            Constraint::SqlOperations { operations } => {
                if let vigil_protocol::action::Action::Database(_) = &request.action {
                    let op = request.action.operation();
                    if !operations.iter().any(|o| o.eq_ignore_ascii_case(&op)) {
                        return Err("SQL operation is not permitted by the capability".to_string());
                    }
                }
            }
            Constraint::PathRoots { roots } => {
                if let vigil_protocol::action::Action::File(f) = &request.action {
                    // Lexical first: cheap, and it answers identically everywhere including
                    // where no filesystem is reachable.
                    if !vigil_common::path::is_inside_any(&f.path, roots) {
                        return Err("path is outside the capability's permitted roots".to_string());
                    }
                    // Then the real filesystem. A lexical check cannot see through a symlink,
                    // so `/workspace/link -> /etc` followed by `/workspace/link/passwd` passes
                    // the test above while landing outside the root. This can only add a
                    // denial: a path already rejected above never reaches here.
                    if vigil_common::path::is_inside_any_resolved(&f.path, roots)
                        == vigil_common::path::Containment::Outside
                    {
                        return Err(
                            "path resolves outside the capability's permitted roots".to_string()
                        );
                    }
                }
            }
            // Enforced by the capability's own use counter and by the backend's timeout.
            Constraint::MaxUses { .. }
            | Constraint::TimeoutMs { .. }
            | Constraint::MaxResponseBytes { .. } => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod path_constraint_tests {
    use super::*;
    use vigil_common::ids::{
        AgentId, AgentInstanceId, EnvironmentId, EventId, PrincipalId, SessionId, TenantId,
    };
    use vigil_protocol::action::{Action, ActionRequest, FileOperation};
    use vigil_protocol::principal::{Principal, PrincipalKind};

    /// A workspace containing `link`, a symlink to a directory outside it.
    struct Workspace {
        root: std::path::PathBuf,
        workspace: std::path::PathBuf,
    }

    impl Workspace {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "vigil-gw-path-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let workspace = root.join("workspace");
            let outside = root.join("outside");
            std::fs::create_dir_all(&workspace).expect("workspace");
            std::fs::create_dir_all(&outside).expect("outside");
            std::fs::write(outside.join("secret.txt"), "SENSITIVE").expect("secret");
            std::fs::write(workspace.join("ok.txt"), "fine").expect("ok");
            std::os::unix::fs::symlink(&outside, workspace.join("link")).expect("symlink");
            Self { root, workspace }
        }

        fn constraint(&self) -> Constraint {
            Constraint::PathRoots {
                roots: vec![self.workspace.display().to_string()],
            }
        }

        fn read(&self, relative: &str) -> ActionRequest {
            file_request(&self.workspace.join(relative).display().to_string())
        }
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn file_request(path: &str) -> ActionRequest {
        ActionRequest {
            schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
            request_id: EventId::new_random(),
            occurred_at: vigil_common::Timestamp::default(),
            tenant_id: TenantId::new("acme").expect("id"),
            environment_id: EnvironmentId::new("prod").expect("id"),
            session_id: SessionId::new("sess-1").expect("id"),
            agent_id: AgentId::new("agent").expect("id"),
            agent_instance_id: AgentInstanceId::new("inst-1").expect("id"),
            principal: Principal::new(
                PrincipalId::new("user-1").expect("id"),
                PrincipalKind::Human,
                TenantId::new("acme").expect("id"),
            ),
            workload_identity: None,
            trace: Default::default(),
            action: Action::File(FileOperation {
                operation: "read".to_string(),
                path: path.to_string(),
                content: None,
                mode: None,
            }),
            context: Default::default(),
        }
    }

    #[test]
    fn a_path_inside_the_root_is_permitted() {
        let workspace = Workspace::new();
        assert!(enforce_constraints(&[workspace.constraint()], &workspace.read("ok.txt")).is_ok());
    }

    #[test]
    fn a_lexically_outside_path_is_refused() {
        let workspace = Workspace::new();
        let error = enforce_constraints(&[workspace.constraint()], &file_request("/etc/passwd"))
            .expect_err("must refuse");
        assert!(
            error.contains("outside the capability's permitted roots"),
            "{error}"
        );
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        // The escape the threat model recorded as open: `/workspace/link -> /outside`, so
        // `/workspace/link/secret.txt` is lexically inside the root and really outside it.
        // Lexical normalization is a string operation and cannot see this; the decision must
        // not rest on it alone.
        let workspace = Workspace::new();
        let request = workspace.read("link/secret.txt");

        assert!(
            vigil_common::path::is_inside_any(
                &workspace
                    .workspace
                    .join("link/secret.txt")
                    .display()
                    .to_string(),
                &[workspace.workspace.display().to_string()],
            ),
            "the lexical check was expected to be fooled; this test proves the other one works"
        );

        let error = enforce_constraints(&[workspace.constraint()], &request)
            .expect_err("symlink escape must be refused");
        assert!(error.contains("resolves outside"), "{error}");
    }

    #[test]
    fn a_write_through_a_symlink_to_a_file_that_does_not_exist_is_refused() {
        // A create is judged before the leaf exists. The escape is in the ancestor.
        let workspace = Workspace::new();
        let error = enforce_constraints(
            &[workspace.constraint()],
            &workspace.read("link/brand-new.txt"),
        )
        .expect_err("must refuse");
        assert!(error.contains("resolves outside"), "{error}");
    }

    #[test]
    fn a_new_file_directly_in_the_workspace_is_permitted() {
        // The resolution must not deny ordinary creates, which is the way a containment
        // check most easily becomes useless: by denying everything.
        let workspace = Workspace::new();
        assert!(
            enforce_constraints(&[workspace.constraint()], &workspace.read("brand-new.txt"))
                .is_ok()
        );
    }
}
