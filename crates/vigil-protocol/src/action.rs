//! The normalized action — the single shape every security decision is made about.
//!
//! # Why
//!
//! An agent can reach the same real-world effect through a native tool call, an MCP
//! `tools/call`, a raw HTTP request or a shell pipeline. If the policy engine sees four
//! different shapes, it will have four different sets of bugs, and an attacker only needs
//! the weakest. Normalization at the edge means one place understands what an action *is*.
//!
//! # What
//!
//! [`ActionRequest`] is the envelope; [`Action`] is the discriminated union of things an
//! agent can attempt. Every variant carries the fields that determine impact — target,
//! operation, arguments — so that [`ActionRequest::material_projection`] can produce the
//! canonical bytes that approvals and capabilities bind to.
//!
//! # Assumptions
//!
//! The instrumentation layer is responsible for producing a *faithful* normalization. VIGIL
//! cannot detect a lying adapter from the data alone; that is what workload identity and
//! Protected Mode network isolation are for. Normalization fidelity is a property of the
//! deployment topology, not of this type.

use serde::{Deserialize, Serialize};
use vigil_common::ids::{
    AgentId, AgentInstanceId, EnvironmentId, EventId, SessionId, TenantId, ToolId,
};
use vigil_common::{ContentHash, Result, Timestamp};

use crate::principal::{Principal, TraceContext, WorkloadIdentity};
use crate::trust::{ProvenanceRef, TrustLevel};

/// How severe the worst realistic outcome of an action is (spec §20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactTier {
    /// Local computation with no observable external effect.
    Tier0Observational,
    /// Approved read-only access to non-sensitive data.
    Tier1LowRiskRead,
    /// Reversible mutation inside the trust boundary.
    Tier2ControlledMutation,
    /// External communication, production change, deletion, credential or financial change.
    Tier3HighImpact,
    /// IAM changes, disabling security controls, root shell, destructive infrastructure ops.
    Tier4Critical,
}

impl ImpactTier {
    /// Whether an unconfigured tool at this tier requires approval by default.
    ///
    /// Defaults escalate with tier because the cost of a wrong *allow* escalates with tier,
    /// while the cost of a wrong *deny* stays roughly constant (a blocked agent, a ticket).
    pub fn default_requires_approval(&self) -> bool {
        matches!(self, Self::Tier3HighImpact | Self::Tier4Critical)
    }

    /// Whether a dependency failure must fail closed for this tier (Invariant 7).
    pub fn must_fail_closed(&self) -> bool {
        matches!(
            self,
            Self::Tier2ControlledMutation | Self::Tier3HighImpact | Self::Tier4Critical
        )
    }

    /// Contribution to the composite risk score, normalized to 0.0–1.0.
    pub fn risk_weight(&self) -> f64 {
        match self {
            Self::Tier0Observational => 0.0,
            Self::Tier1LowRiskRead => 0.15,
            Self::Tier2ControlledMutation => 0.4,
            Self::Tier3HighImpact => 0.75,
            Self::Tier4Critical => 1.0,
        }
    }

    /// The tier to assume for a tool with no manifest.
    ///
    /// Unclassified tools are treated conservatively (spec §19): an unregistered tool that
    /// turns out to send email is far worse than an unregistered calculator needing a
    /// manifest entry.
    pub const fn conservative_default() -> Self {
        Self::Tier3HighImpact
    }
}

/// What kind of effect an action has on the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    /// No effect outside the agent's own process memory.
    Observational,
    /// Reads data inside the trust boundary.
    InternalRead,
    /// Writes data inside the trust boundary.
    InternalWrite,
    /// Reads data from outside the trust boundary.
    ExternalRead,
    /// Sends data outside the trust boundary. The exfiltration-relevant class.
    ExternalWrite,
    /// Executes code or commands.
    Execute,
    /// Changes identity, permissions or security configuration.
    PrivilegeChange,
    /// Removes or irreversibly alters data or infrastructure.
    Destructive,
    /// Moves money or incurs unbounded cost.
    Financial,
}

impl SideEffectClass {
    /// The lowest tier this side-effect class may be assigned.
    ///
    /// A manifest may classify a tool *higher* than this, never lower: an operator cannot
    /// declare `rm -rf` to be Tier 0 by editing YAML.
    pub fn floor_tier(&self) -> ImpactTier {
        match self {
            Self::Observational => ImpactTier::Tier0Observational,
            Self::InternalRead => ImpactTier::Tier1LowRiskRead,
            Self::InternalWrite => ImpactTier::Tier2ControlledMutation,
            Self::ExternalRead => ImpactTier::Tier1LowRiskRead,
            Self::ExternalWrite => ImpactTier::Tier3HighImpact,
            Self::Execute => ImpactTier::Tier3HighImpact,
            Self::PrivilegeChange => ImpactTier::Tier4Critical,
            Self::Destructive => ImpactTier::Tier4Critical,
            Self::Financial => ImpactTier::Tier3HighImpact,
        }
    }

    /// Whether the effect can be undone without an incident.
    pub fn is_reversible(&self) -> bool {
        matches!(
            self,
            Self::Observational | Self::InternalRead | Self::ExternalRead | Self::InternalWrite
        )
    }

    /// Whether this class moves data across the trust boundary outward.
    pub fn is_egress(&self) -> bool {
        matches!(self, Self::ExternalWrite | Self::Financial)
    }
}

/// The transport an agent used to reach a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolProtocol {
    /// An in-process function registered with the agent framework.
    Native,
    /// Model Context Protocol.
    Mcp,
    /// A2A agent-to-agent call.
    A2a,
    /// A plain HTTP API.
    Http,
    /// Local process execution.
    Shell,
    /// Local filesystem access.
    Filesystem,
    /// A database client.
    Sql,
}

/// An invocation of a named tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub protocol: ToolProtocol,
    /// The MCP server, API host or framework namespace providing the tool.
    #[serde(default)]
    pub server: Option<String>,
    /// Stable registered identifier used to look up the manifest.
    pub tool_id: ToolId,
    /// The name as the agent invoked it, which may differ from the registered name if a
    /// server renamed a tool — that difference is itself a signal.
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// The sub-operation, where a tool exposes several (`read`, `create_ticket`, `send`).
    #[serde(default)]
    pub operation: Option<String>,
    /// The arguments, exactly as they would reach the tool.
    pub arguments: serde_json::Value,
    /// The specific resource the call targets, when it is identifiable.
    #[serde(default)]
    pub target_resource: Option<String>,
    /// The side effect the *caller* claims. Advisory only: the manifest is authoritative and
    /// a mismatch between claim and manifest is recorded as a signal.
    #[serde(default)]
    pub declared_side_effect: Option<SideEffectClass>,
}

/// A model invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelCall {
    pub provider: String,
    pub model: String,
    /// What the call is for: `plan`, `respond`, `summarize`, `tool_selection`.
    #[serde(default)]
    pub purpose: Option<String>,
    /// Provenance of each context segment. This is how VIGIL knows an untrusted web page
    /// was in the context that produced a subsequent tool call.
    #[serde(default)]
    pub context_provenance: Vec<ProvenanceRef>,
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub estimated_cost_usd: Option<f64>,
}

/// An outbound network request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkRequest {
    pub method: String,
    /// The full URL. Stored redacted in evidence; used raw only inside the decision.
    pub url: String,
    #[serde(default)]
    pub content_type: Option<String>,
    /// Header *names* only. Values are never accepted here: an `Authorization` value in a
    /// security event is a credential leak into the audit store.
    #[serde(default)]
    pub header_names: Vec<String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Addresses the hostname resolved to, when the adapter resolved before requesting.
    /// Required to catch DNS rebinding, which a hostname allowlist alone cannot see.
    #[serde(default)]
    pub resolved_addresses: Vec<String>,
    /// Prior hops, when this request is a redirect continuation.
    #[serde(default)]
    pub redirect_chain: Vec<String>,
}

/// A filesystem operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileOperation {
    /// `read`, `write`, `append`, `delete`, `list`, `chmod`, `symlink`.
    pub operation: String,
    /// The path as requested, before normalization. VIGIL normalizes it itself rather than
    /// trusting a normalized value from the caller.
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
}

/// A shell or subprocess execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShellExecution {
    /// The full command line as it would be executed.
    pub command: String,
    /// The argv form, when the adapter has it. Argv is analyzable without shell parsing and
    /// is preferred; `command` is retained because many frameworks only expose a string.
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Whether a shell interpreter will process the string (enabling metacharacters).
    #[serde(default)]
    pub uses_shell: bool,
}

/// A database operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseOperation {
    /// `postgres`, `mysql`, `sqlite`, `mongodb`.
    pub engine: String,
    /// The statement as it would be sent.
    pub statement: String,
    /// Bound parameters, kept separate so VIGIL can tell parameterized from concatenated SQL.
    #[serde(default)]
    pub parameters: Vec<serde_json::Value>,
    #[serde(default)]
    pub database: Option<String>,
}

/// A memory read or write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryOperation {
    pub namespace: String,
    pub key: String,
    #[serde(default)]
    pub content: Option<String>,
    /// Trust label being asserted for the content. On write this is what the writer claims;
    /// VIGIL recomputes it from provenance and records both.
    #[serde(default)]
    pub asserted_trust: Option<TrustLevel>,
    /// Whether the memory is visible to other sessions, users or tenants. Cross-scope
    /// memory is how one user's poisoned content reaches another user's agent.
    #[serde(default)]
    pub scope: MemoryScope,
}

/// Who can later read a memory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScope {
    #[default]
    Session,
    User,
    Agent,
    Tenant,
}

/// A message sent to another agent, or a delegation of work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentMessage {
    pub to_agent: AgentId,
    pub content: String,
    #[serde(default)]
    pub content_provenance: Vec<ProvenanceRef>,
}

/// A delegation of authority from one agent to another.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delegation {
    pub delegate_to: AgentId,
    /// The task description handed over.
    pub task: String,
    /// Tools and operations the delegator is attempting to grant.
    #[serde(default)]
    pub granted_scope: Vec<String>,
    /// How many delegation hops precede this one.
    #[serde(default)]
    pub depth: u32,
    /// The chain of agents this work has passed through, oldest first.
    #[serde(default)]
    pub lineage: Vec<AgentId>,
}

/// Everything an agent can attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    ToolCall(ToolCall),
    ModelCall(ModelCall),
    Network(NetworkRequest),
    File(FileOperation),
    Shell(ShellExecution),
    Database(DatabaseOperation),
    MemoryRead(MemoryOperation),
    MemoryWrite(MemoryOperation),
    AgentMessage(AgentMessage),
    Delegation(Delegation),
}

impl Action {
    /// A stable, low-cardinality label for metrics and rule matching.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ToolCall(_) => "tool_call",
            Self::ModelCall(_) => "model_call",
            Self::Network(_) => "network",
            Self::File(_) => "file",
            Self::Shell(_) => "shell",
            Self::Database(_) => "database",
            Self::MemoryRead(_) => "memory_read",
            Self::MemoryWrite(_) => "memory_write",
            Self::AgentMessage(_) => "agent_message",
            Self::Delegation(_) => "delegation",
        }
    }

    /// The name policy rules match against: the tool name, or a synthetic name for the
    /// built-in action classes so one rule syntax covers everything.
    pub fn resource_name(&self) -> String {
        match self {
            Self::ToolCall(t) => t.name.clone(),
            Self::ModelCall(m) => format!("{}/{}", m.provider, m.model),
            Self::Network(n) => format!("net:{}", host_of(&n.url).unwrap_or_default()),
            Self::File(f) => format!("file:{}", f.operation),
            Self::Shell(_) => "shell:exec".to_string(),
            Self::Database(d) => format!("db:{}", d.engine),
            Self::MemoryRead(m) => format!("memory:{}", m.namespace),
            Self::MemoryWrite(m) => format!("memory:{}", m.namespace),
            Self::AgentMessage(a) => format!("agent:{}", a.to_agent),
            Self::Delegation(d) => format!("delegate:{}", d.delegate_to),
        }
    }

    /// The operation being performed, for rules that distinguish read from write.
    pub fn operation(&self) -> String {
        match self {
            Self::ToolCall(t) => t.operation.clone().unwrap_or_else(|| "invoke".to_string()),
            Self::ModelCall(m) => m.purpose.clone().unwrap_or_else(|| "invoke".to_string()),
            Self::Network(n) => n.method.to_ascii_uppercase(),
            Self::File(f) => f.operation.clone(),
            Self::Shell(_) => "exec".to_string(),
            Self::Database(d) => sql_operation(&d.statement),
            Self::MemoryRead(_) => "read".to_string(),
            Self::MemoryWrite(_) => "write".to_string(),
            Self::AgentMessage(_) => "send".to_string(),
            Self::Delegation(_) => "delegate".to_string(),
        }
    }

    /// The side effect class implied by the action's own shape, before the tool manifest is
    /// consulted. Used as the floor when no manifest exists.
    pub fn intrinsic_side_effect(&self) -> SideEffectClass {
        match self {
            Self::ToolCall(t) => t
                .declared_side_effect
                .unwrap_or(SideEffectClass::ExternalWrite),
            Self::ModelCall(_) => SideEffectClass::Observational,
            Self::Network(n) => {
                if matches!(n.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
                    SideEffectClass::ExternalRead
                } else {
                    SideEffectClass::ExternalWrite
                }
            }
            Self::File(f) => match f.operation.as_str() {
                "read" | "list" => SideEffectClass::InternalRead,
                "delete" => SideEffectClass::Destructive,
                "chmod" => SideEffectClass::PrivilegeChange,
                _ => SideEffectClass::InternalWrite,
            },
            Self::Shell(_) => SideEffectClass::Execute,
            Self::Database(d) => match sql_operation(&d.statement).as_str() {
                "SELECT" => SideEffectClass::InternalRead,
                "DROP" | "TRUNCATE" | "DELETE" => SideEffectClass::Destructive,
                "GRANT" | "REVOKE" | "ALTER" => SideEffectClass::PrivilegeChange,
                _ => SideEffectClass::InternalWrite,
            },
            Self::MemoryRead(_) => SideEffectClass::InternalRead,
            Self::MemoryWrite(_) => SideEffectClass::InternalWrite,
            Self::AgentMessage(_) => SideEffectClass::ExternalWrite,
            Self::Delegation(_) => SideEffectClass::PrivilegeChange,
        }
    }

    /// Every string in the action that could carry content: arguments, bodies, commands.
    ///
    /// Detectors and taint analysis consume this rather than reaching into variants, so a
    /// new action type cannot silently escape inspection by being forgotten in six places.
    pub fn content_strings(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        match self {
            Self::ToolCall(t) => {
                collect_strings("arguments", &t.arguments, &mut out);
                if let Some(r) = &t.target_resource {
                    out.push(("target_resource".to_string(), r.clone()));
                }
            }
            Self::ModelCall(_) => {}
            Self::Network(n) => {
                out.push(("url".to_string(), n.url.clone()));
                if let Some(b) = &n.body {
                    collect_strings("body", b, &mut out);
                }
            }
            Self::File(f) => {
                out.push(("path".to_string(), f.path.clone()));
                if let Some(c) = &f.content {
                    out.push(("content".to_string(), c.clone()));
                }
            }
            Self::Shell(s) => {
                out.push(("command".to_string(), s.command.clone()));
                for (i, a) in s.argv.iter().enumerate() {
                    out.push((format!("argv[{i}]"), a.clone()));
                }
            }
            Self::Database(d) => {
                out.push(("statement".to_string(), d.statement.clone()));
                for (i, p) in d.parameters.iter().enumerate() {
                    collect_strings(&format!("parameters[{i}]"), p, &mut out);
                }
            }
            Self::MemoryRead(m) | Self::MemoryWrite(m) => {
                out.push(("key".to_string(), m.key.clone()));
                if let Some(c) = &m.content {
                    out.push(("content".to_string(), c.clone()));
                }
            }
            Self::AgentMessage(a) => out.push(("content".to_string(), a.content.clone())),
            Self::Delegation(d) => {
                out.push(("task".to_string(), d.task.clone()));
                for (i, s) in d.granted_scope.iter().enumerate() {
                    out.push((format!("granted_scope[{i}]"), s.clone()));
                }
            }
        }
        out
    }

    /// The material fields — everything whose change would make this a different action.
    ///
    /// Deliberately excludes observed-at-runtime data (resolved addresses), caller claims
    /// (declared side effect) and anything non-semantic. Two requests with the same material
    /// projection are the same action for approval and capability purposes; if that is ever
    /// wrong, it is a security bug, so the exclusions are enumerated here rather than
    /// derived by `#[serde(skip)]` scattered across the structs.
    pub fn material_projection(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Self::ToolCall(t) => json!({
                "kind": "tool_call",
                "protocol": t.protocol,
                "server": t.server,
                "tool_id": t.tool_id,
                "name": t.name,
                "operation": t.operation,
                "arguments": t.arguments,
                "target_resource": t.target_resource,
            }),
            Self::ModelCall(m) => json!({
                "kind": "model_call",
                "provider": m.provider,
                "model": m.model,
                "purpose": m.purpose,
            }),
            Self::Network(n) => json!({
                "kind": "network",
                "method": n.method.to_ascii_uppercase(),
                "url": n.url,
                "content_type": n.content_type,
                "body": n.body,
            }),
            Self::File(f) => json!({
                "kind": "file",
                "operation": f.operation,
                "path": f.path,
                "content": f.content,
                "mode": f.mode,
            }),
            Self::Shell(s) => json!({
                "kind": "shell",
                "command": s.command,
                "argv": s.argv,
                "cwd": s.cwd,
                "uses_shell": s.uses_shell,
            }),
            Self::Database(d) => json!({
                "kind": "database",
                "engine": d.engine,
                "statement": d.statement,
                "parameters": d.parameters,
                "database": d.database,
            }),
            Self::MemoryRead(m) => json!({
                "kind": "memory_read",
                "namespace": m.namespace,
                "key": m.key,
                "scope": m.scope,
            }),
            Self::MemoryWrite(m) => json!({
                "kind": "memory_write",
                "namespace": m.namespace,
                "key": m.key,
                "content": m.content,
                "scope": m.scope,
            }),
            Self::AgentMessage(a) => json!({
                "kind": "agent_message",
                "to_agent": a.to_agent,
                "content": a.content,
            }),
            Self::Delegation(d) => json!({
                "kind": "delegation",
                "delegate_to": d.delegate_to,
                "task": d.task,
                "granted_scope": d.granted_scope,
                "depth": d.depth,
            }),
        }
    }
}

/// Non-security context the caller supplies alongside the action.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    /// The agent's declared objective for this step, when the framework emits one.
    ///
    /// This is *observable* reasoning telemetry (spec §5), never hidden chain-of-thought,
    /// and never a trust root: it is a signal compared against the remit, and the pipeline
    /// works identically when it is absent.
    #[serde(default)]
    pub declared_objective: Option<String>,
    /// Rationale the agent emitted for choosing this action, if any.
    #[serde(default)]
    pub action_rationale: Option<String>,
    /// The provenance of every context segment that was in scope when this action was chosen.
    #[serde(default)]
    pub influencing_sources: Vec<ProvenanceRef>,
    /// Step index within the session, for ordering and loop detection.
    #[serde(default)]
    pub step: u32,
    /// An approval token, when the caller is retrying an action that required one.
    #[serde(default)]
    pub approval_token: Option<String>,
    /// Free-form adapter metadata. Never consulted by policy; carried for forensics.
    #[serde(default)]
    pub adapter_metadata: serde_json::Map<String, serde_json::Value>,
}

/// A request for a security decision about one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRequest {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub request_id: EventId,
    pub occurred_at: Timestamp,
    pub tenant_id: TenantId,
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub agent_instance_id: AgentInstanceId,
    pub principal: Principal,
    /// The attested identity of the calling workload, when one was proven.
    #[serde(default)]
    pub workload_identity: Option<WorkloadIdentity>,
    #[serde(default)]
    pub trace: TraceContext,
    pub action: Action,
    #[serde(default)]
    pub context: RequestContext,
}

fn default_schema_version() -> String {
    crate::SCHEMA_VERSION.to_string()
}

impl ActionRequest {
    /// The canonical material form of this request: identity scope plus the action's
    /// material projection. This is what gets hashed.
    ///
    /// Tenant, environment and agent are included so a capability minted for one agent can
    /// never authorize the same action requested by another — the hash itself would differ.
    pub fn material_projection(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": crate::SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "principal_id": self.principal.id,
            "action": self.action.material_projection(),
        })
    }

    /// The hash approvals and capabilities bind to (Invariants 5 and 10).
    pub fn action_hash(&self) -> Result<ContentHash> {
        ContentHash::canonical_json(&self.material_projection())
    }

    /// Short descriptor for logs and console rows.
    pub fn descriptor(&self) -> String {
        format!("{}:{}", self.action.kind(), self.action.resource_name())
    }

    /// Validate structural invariants that must hold before any security logic runs.
    ///
    /// Cheap, total, and first in the pipeline: everything downstream may assume these.
    pub fn validate(&self) -> Result<()> {
        crate::check_schema_version(&self.schema_version)?;
        if self.principal.tenant_id != self.tenant_id {
            return Err(vigil_common::VigilError::InvalidRequest(
                "principal tenant does not match request tenant".to_string(),
            ));
        }
        if let Action::Network(n) = &self.action {
            if n.header_names.iter().any(|h| h.contains(':')) {
                return Err(vigil_common::VigilError::InvalidRequest(
                    "network header_names must not contain values".to_string(),
                ));
            }
        }
        if let Action::Delegation(d) = &self.action {
            if d.lineage.len() > 64 {
                return Err(vigil_common::VigilError::InvalidRequest(
                    "delegation lineage exceeds maximum length".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Extract the host from a URL without a full parse, for labelling only.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    Some(host.split(':').next()?.to_ascii_lowercase())
}

/// The leading keyword of a SQL statement, uppercased.
///
/// Comment prefixes are stripped first so `/*x*/DROP` does not read as an unknown verb.
fn sql_operation(statement: &str) -> String {
    let mut s = statement.trim_start();
    loop {
        if let Some(rest) = s.strip_prefix("--") {
            s = rest
                .split_once('\n')
                .map(|(_, r)| r)
                .unwrap_or("")
                .trim_start();
        } else if let Some(rest) = s.strip_prefix("/*") {
            s = rest
                .split_once("*/")
                .map(|(_, r)| r)
                .unwrap_or("")
                .trim_start();
        } else if let Some(rest) = s.strip_prefix('(') {
            s = rest.trim_start();
        } else {
            break;
        }
    }
    s.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| !c.is_ascii_alphabetic())
        .to_ascii_uppercase()
}

/// Flatten every string leaf of a JSON value with a dotted path.
fn collect_strings(prefix: &str, value: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::String(s) => out.push((prefix.to_string(), s.clone())),
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                collect_strings(&format!("{prefix}[{i}]"), item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_strings(&format!("{prefix}.{k}"), v, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;

    fn tool_call(args: serde_json::Value) -> Action {
        Action::ToolCall(ToolCall {
            protocol: ToolProtocol::Native,
            server: None,
            tool_id: ToolId::from_str("send_email").unwrap(),
            name: "send_email".to_string(),
            version: None,
            operation: Some("send".to_string()),
            arguments: args,
            target_resource: None,
            declared_side_effect: None,
        })
    }

    #[test]
    fn material_projection_is_insensitive_to_argument_key_order() {
        let a = tool_call(json!({"to": "x@example.com", "body": "hi"}));
        let b = tool_call(json!({"body": "hi", "to": "x@example.com"}));
        let ha = ContentHash::canonical_json(&a.material_projection()).unwrap();
        let hb = ContentHash::canonical_json(&b.material_projection()).unwrap();
        assert!(ha.ct_eq(&hb));
    }

    #[test]
    fn material_projection_changes_when_a_recipient_changes() {
        let a = tool_call(json!({"to": "cfo@acme.example"}));
        let b = tool_call(json!({"to": "attacker@evil.example"}));
        let ha = ContentHash::canonical_json(&a.material_projection()).unwrap();
        let hb = ContentHash::canonical_json(&b.material_projection()).unwrap();
        assert!(!ha.ct_eq(&hb));
    }

    #[test]
    fn caller_claims_are_excluded_from_the_material_projection() {
        // A caller must not be able to change the action hash by changing an advisory field,
        // which would let a mutated request masquerade as an approved one.
        let mut base = tool_call(json!({"to": "a@b.example"}));
        let h1 = ContentHash::canonical_json(&base.material_projection()).unwrap();
        if let Action::ToolCall(t) = &mut base {
            t.declared_side_effect = Some(SideEffectClass::Observational);
            t.version = Some("9.9.9".to_string());
        }
        let h2 = ContentHash::canonical_json(&base.material_projection()).unwrap();
        assert!(h1.ct_eq(&h2));
    }

    #[test]
    fn manifest_cannot_classify_a_destructive_tool_below_its_floor() {
        assert_eq!(
            SideEffectClass::Destructive.floor_tier(),
            ImpactTier::Tier4Critical
        );
        assert!(!SideEffectClass::Destructive.is_reversible());
        assert!(SideEffectClass::ExternalWrite.is_egress());
    }

    #[test]
    fn unclassified_tools_default_to_high_impact() {
        assert_eq!(
            ImpactTier::conservative_default(),
            ImpactTier::Tier3HighImpact
        );
        assert!(ImpactTier::conservative_default().default_requires_approval());
        assert!(ImpactTier::conservative_default().must_fail_closed());
    }

    #[test]
    fn sql_operation_survives_comment_and_paren_prefixes() {
        assert_eq!(sql_operation("SELECT 1"), "SELECT");
        assert_eq!(sql_operation("  select * from t"), "SELECT");
        assert_eq!(sql_operation("/* hide */ DROP TABLE users"), "DROP");
        assert_eq!(sql_operation("-- c\nDELETE FROM t"), "DELETE");
        assert_eq!(sql_operation("(SELECT 1)"), "SELECT");
    }

    #[test]
    fn destructive_sql_is_classified_destructive_even_when_disguised() {
        let action = Action::Database(DatabaseOperation {
            engine: "postgres".to_string(),
            statement: "/* routine */ DROP TABLE customers".to_string(),
            parameters: vec![],
            database: None,
        });
        assert_eq!(action.operation(), "DROP");
        assert_eq!(action.intrinsic_side_effect(), SideEffectClass::Destructive);
    }

    #[test]
    fn content_strings_reach_nested_argument_values() {
        let action = tool_call(json!({
            "to": ["a@x.example", "b@y.example"],
            "meta": {"note": "hidden secret here"}
        }));
        let strings = action.content_strings();
        let joined: Vec<&str> = strings.iter().map(|(_, v)| v.as_str()).collect();
        assert!(joined.contains(&"a@x.example"));
        assert!(joined.contains(&"hidden secret here"));
        let paths: Vec<&str> = strings.iter().map(|(k, _)| k.as_str()).collect();
        assert!(paths.contains(&"arguments.meta.note"));
    }

    #[test]
    fn host_extraction_ignores_userinfo_which_can_forge_a_hostname() {
        // `https://trusted.example@evil.example/` fetches from evil.example.
        assert_eq!(
            host_of("https://trusted.example@evil.example/path"),
            Some("evil.example".to_string())
        );
        assert_eq!(
            host_of("http://EXAMPLE.com:8080/x"),
            Some("example.com".to_string())
        );
    }
}
