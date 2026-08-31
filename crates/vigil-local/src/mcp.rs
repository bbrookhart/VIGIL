//! MCP as a first-class attack surface.
//!
//! An MCP server is a program the agent can ask to do things on its behalf. That makes it a
//! confused deputy by construction: the tool holds whatever authority its own process has,
//! and the agent supplies the arguments. Transport-level authorization to *call* a server says
//! nothing about whether the resulting operation should be permitted, and this module keeps
//! those two questions apart.
//!
//! # A tool name is not evidence
//!
//! `filesystem.write_file` is a claim, not a fact. The load-bearing decision here is
//! [`extract_resources`]: every string argument that looks like a path or a URL is pulled out
//! and authorized *independently*, whatever the tool calls itself and whatever it declared.
//! A tool that says it writes to the workspace and is handed `~/.ssh/config` fails on the
//! argument, not on the name.
//!
//! Declared capabilities are used only to *notice a discrepancy*, never to grant anything. A
//! tool reaching beyond what it declared is a detection; a tool staying within it earns
//! nothing it would not otherwise have had.
//!
//! # Scope
//!
//! This is the security core: registry, identity, drift, capability mapping, and the
//! authorization decision. It is **not** a transport proxy — nothing here speaks JSON-RPC over
//! stdio or intercepts live MCP traffic. A tool call reaches these checks when an adapter
//! routes it here, exactly as a filesystem operation reaches the filesystem broker when
//! something calls it. A server contacted directly by an agent is unobserved.

use crate::detection::{Confidence, DetectionRule, Severity, Tactic};
use crate::lease::{AtomicLeaseConsumption, LeaseUse};
use crate::{DecisionOutcome, LocalAction, LocalStore, RiskDimension, RiskState};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use vigil_common::{ContentHash, Result, VigilError};

/// Bound on how deep argument extraction will walk a nested JSON document.
const MAX_ARGUMENT_DEPTH: usize = 16;

/// Bound on how many candidate resources one call may present.
///
/// A call carrying hundreds of paths is either a bulk operation that should be expressed as
/// many calls, or an attempt to bury one interesting path among many.
const MAX_EXTRACTED_RESOURCES: usize = 64;

/// Longest argument string considered as a candidate resource.
const MAX_RESOURCE_BYTES: usize = 4096;
const MAX_MCP_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

pub const DETECTION_MCP_CAPABILITY_DRIFT: &str = "mcp_capability_drift";
pub const DETECTION_MCP_SERVER_SUBSTITUTION: &str = "mcp_server_substitution";
pub const DETECTION_MCP_SCOPE_ESCAPE: &str = "mcp_tool_scope_escape";

/// Detection rules this module owns, merged into the catalogue in `detection.rs`.
pub const MCP_RULES: &[DetectionRule] = &[
    DetectionRule {
        id: "VIGIL-L010",
        name: "MCP capability drift",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::ToolAbuse,
        description: "An MCP server changed its tool set or a tool's schema after registration.",
        dimension: RiskDimension::ToolAnomaly,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L011",
        name: "MCP server substitution",
        severity: Severity::Critical,
        confidence: Confidence::High,
        tactic: Tactic::ToolAbuse,
        description: "The binary behind a registered MCP server changed.",
        dimension: RiskDimension::ToolAnomaly,
        weight: 80,
    },
    DetectionRule {
        id: "VIGIL-L012",
        name: "MCP tool scope escape",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::ToolAbuse,
        description: "An MCP tool call carried a resource outside what the tool declared.",
        dimension: RiskDimension::ToolAnomaly,
        weight: 40,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    Stdio,
    Http,
    Unknown,
}

impl McpTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for McpTransport {
    type Err = VigilError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "stdio" => Ok(Self::Stdio),
            "http" => Ok(Self::Http),
            "unknown" => Ok(Self::Unknown),
            _ => Err(VigilError::InvalidValue {
                field: "transport",
                reason: format!("unknown MCP transport `{value}`; expected stdio, http or unknown"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTrustState {
    Trusted,
    Quarantined,
}

impl McpTrustState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Quarantined => "quarantined",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "trusted" => Ok(Self::Trusted),
            "quarantined" => Ok(Self::Quarantined),
            _ => Err(VigilError::Serialization(format!(
                "database contains unknown MCP trust state `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServer {
    pub server_id: String,
    pub name: String,
    pub transport: McpTransport,
    pub executable: Option<String>,
    pub executable_sha256: Option<String>,
    pub version: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub trust_state: McpTrustState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTool {
    pub server_id: String,
    pub tool_name: String,
    pub schema_hash: String,
    pub description_hash: String,
    /// What this tool says it can do. Used to notice a discrepancy, never to grant anything.
    pub declared_capabilities: Vec<LocalAction>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// One tool as a server currently presents it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolManifest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The tool's input schema, hashed as canonical JSON.
    #[serde(default)]
    pub input_schema: serde_json::Value,
    #[serde(default)]
    pub declared_capabilities: Vec<LocalAction>,
}

impl McpToolManifest {
    fn schema_hash(&self) -> Result<String> {
        Ok(ContentHash::canonical_json(&self.input_schema)?.to_string())
    }

    fn description_hash(&self) -> String {
        ContentHash::sha256(self.description.as_bytes()).to_string()
    }
}

/// What changed about a server between registration and now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpDrift {
    /// The binary behind the server is not the one that was registered.
    ServerSubstituted {
        registered_sha256: String,
        observed_sha256: String,
    },
    ToolAdded {
        tool: String,
    },
    ToolRemoved {
        tool: String,
    },
    ToolSchemaChanged {
        tool: String,
    },
    ToolDescriptionChanged {
        tool: String,
    },
    /// The tool now claims a capability it did not claim before.
    ToolCapabilityAdded {
        tool: String,
        capability: LocalAction,
    },
}

impl McpDrift {
    /// The detection rule this drift warrants.
    pub fn rule(&self) -> &'static DetectionRule {
        let id = match self {
            Self::ServerSubstituted { .. } => "VIGIL-L011",
            _ => "VIGIL-L010",
        };
        MCP_RULES
            .iter()
            .find(|rule| rule.id == id)
            .unwrap_or(&MCP_RULES[0])
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::ServerSubstituted { .. } => DETECTION_MCP_SERVER_SUBSTITUTION,
            _ => DETECTION_MCP_CAPABILITY_DRIFT,
        }
    }
}

/// A candidate resource pulled out of a tool call's arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedResource {
    /// Dotted path to the argument it came from, e.g. `edits.0.path`.
    pub argument: String,
    pub value: String,
    pub kind: ResourceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Path,
    Url,
}

impl ResourceKind {
    /// The capability an argument of this shape implies, absent anything more specific.
    ///
    /// Read is the conservative floor for a path: it is the least the tool could be doing
    /// with it, and a workspace read is the smallest authority worth checking. The real
    /// protection is that protected and out-of-workspace paths fail even a read.
    pub const fn implied_action(self) -> LocalAction {
        match self {
            Self::Path => LocalAction::FsRead,
            Self::Url => LocalAction::NetworkConnect,
        }
    }
}

/// Pull every path-like and URL-like string out of a tool call's arguments.
///
/// This walks the whole document, not a declared argument name, because the point is to find
/// resources the tool did *not* advertise it would touch. Recursion is depth-bounded and the
/// result count is capped so a hostile server cannot turn extraction into a denial of service.
pub fn extract_resources(arguments: &serde_json::Value) -> Vec<ExtractedResource> {
    let mut found = Vec::new();
    walk(arguments, &mut String::new(), 0, &mut found);
    found.truncate(MAX_EXTRACTED_RESOURCES);
    found
}

fn walk(
    value: &serde_json::Value,
    path: &mut String,
    depth: usize,
    found: &mut Vec<ExtractedResource>,
) {
    if depth > MAX_ARGUMENT_DEPTH || found.len() >= MAX_EXTRACTED_RESOURCES {
        return;
    }
    match value {
        serde_json::Value::String(text) => {
            if let Some(kind) = classify_resource(text) {
                found.push(ExtractedResource {
                    argument: if path.is_empty() {
                        "<root>".to_string()
                    } else {
                        path.clone()
                    },
                    value: text.clone(),
                    kind,
                });
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let mark = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(&index.to_string());
                walk(item, path, depth + 1, found);
                path.truncate(mark);
            }
        }
        serde_json::Value::Object(entries) => {
            for (key, item) in entries {
                let mark = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk(item, path, depth + 1, found);
                path.truncate(mark);
            }
        }
        _ => {}
    }
}

/// Decide whether a string is worth authorizing as a resource.
///
/// Deliberately generous. A false positive costs one extra policy evaluation, which resolves
/// to a workspace path and is allowed; a false negative is an unchecked resource. Given that
/// asymmetry the rule errs toward treating things as resources.
fn classify_resource(text: &str) -> Option<ResourceKind> {
    if text.is_empty() || text.len() > MAX_RESOURCE_BYTES || text.contains('\0') {
        return None;
    }
    let lowered = text.to_ascii_lowercase();
    if lowered.starts_with("http://")
        || lowered.starts_with("https://")
        || lowered.starts_with("ws://")
        || lowered.starts_with("wss://")
        || lowered.starts_with("ftp://")
    {
        return Some(ResourceKind::Url);
    }
    if lowered.starts_with("file://") {
        return Some(ResourceKind::Path);
    }
    // Absolute, home-relative, or explicitly relative paths. A bare word like "utf-8" is not
    // treated as a resource; `./utf-8` would be.
    if text.starts_with('/')
        || text.starts_with("~/")
        || text == "~"
        || text.starts_with("./")
        || text.starts_with("../")
        || text.contains('/')
    {
        return Some(ResourceKind::Path);
    }
    None
}

/// One MCP tool call, ready to authorize.
#[derive(Debug, Clone)]
pub struct McpToolCall<'a> {
    pub server_name: &'a str,
    pub tool_name: &'a str,
    pub arguments: &'a serde_json::Value,
}

impl LocalStore {
    /// Register an MCP server, or refresh the record of one already known.
    ///
    /// Re-registering with a different binary hash is a substitution, and is refused rather
    /// than silently accepted: the operator must remove and re-add the server deliberately.
    pub fn register_mcp_server(
        &self,
        name: &str,
        transport: McpTransport,
        executable: Option<&str>,
        executable_sha256: Option<&str>,
        version: Option<&str>,
    ) -> Result<McpServer> {
        validate_name(name)?;
        if transport != McpTransport::Stdio {
            return Err(VigilError::InvalidValue {
                field: "transport",
                reason: "only stdio MCP servers have a complete local identity model; HTTP and \
                         unknown transports cannot be trusted yet"
                    .to_string(),
            });
        }
        let executable = executable.ok_or_else(|| VigilError::InvalidValue {
            field: "executable",
            reason: "a stdio MCP server requires the executable VIGIL hashed".to_string(),
        })?;
        if executable.is_empty()
            || executable.len() > MAX_RESOURCE_BYTES
            || executable.contains('\0')
        {
            return Err(VigilError::InvalidValue {
                field: "executable",
                reason: "an MCP executable path must be 1..=4096 bytes and contain no NUL"
                    .to_string(),
            });
        }
        let executable_sha256 = executable_sha256.ok_or_else(|| VigilError::InvalidValue {
            field: "executable_sha256",
            reason: "a stdio MCP server requires a VIGIL-observed SHA-256 digest".to_string(),
        })?;
        validate_hash(executable_sha256)?;
        let now = Utc::now();
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        if let Some(existing) = read_server_by_name(&transaction, name)? {
            if existing.transport != transport
                || existing.executable.as_deref() != Some(executable)
                || existing.executable_sha256.as_deref() != Some(executable_sha256)
            {
                return Err(VigilError::AuditIntegrity(format!(
                    "MCP server `{name}` was registered with a different transport, executable, \
                     or binary; remove and re-register it deliberately rather than letting its \
                     identity change"
                )));
            }
            transaction
                .execute(
                    "UPDATE mcp_servers SET last_seen = ?1, version = COALESCE(?2, version),
                            executable_sha256 = COALESCE(executable_sha256, ?3)
                     WHERE server_id = ?4",
                    params![
                        now.to_rfc3339(),
                        version,
                        executable_sha256,
                        existing.server_id
                    ],
                )
                .map_err(super::store::storage_error)?;
            let refreshed = read_server(&transaction, &existing.server_id)?;
            transaction.commit().map_err(super::store::storage_error)?;
            return Ok(refreshed);
        }

        let server = McpServer {
            server_id: format!("mcp_{}", uuid::Uuid::new_v4().simple()),
            name: name.to_string(),
            transport,
            executable: Some(executable.to_string()),
            executable_sha256: Some(executable_sha256.to_string()),
            version: version.map(|value| vigil_common::redact::single_line_excerpt(value, 100)),
            first_seen: now,
            last_seen: now,
            trust_state: McpTrustState::Trusted,
        };
        transaction
            .execute(
                "INSERT INTO mcp_servers
                 (server_id, name, transport, executable, executable_sha256, version,
                  first_seen, last_seen, trust_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'trusted')",
                params![
                    server.server_id,
                    server.name,
                    server.transport.as_str(),
                    server.executable,
                    server.executable_sha256,
                    server.version,
                    server.first_seen.to_rfc3339(),
                    server.last_seen.to_rfc3339(),
                ],
            )
            .map_err(super::store::storage_error)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(server)
    }

    /// Compare a server's currently presented tools against what is on record.
    ///
    /// Returns every difference. The first sync after registration establishes the baseline
    /// and reports nothing — a server has not "drifted" merely by being seen for the first
    /// time — unless its binary hash disagrees, which is drift regardless.
    pub fn sync_mcp_tools(
        &self,
        server_name: &str,
        observed_sha256: Option<&str>,
        manifests: &[McpToolManifest],
    ) -> Result<Vec<McpDrift>> {
        self.sync_mcp_tools_inner(server_name, observed_sha256, manifests, false)
    }

    /// Synchronize manifests observed directly on the wire without letting the server erase
    /// operator-reviewed capability declarations that are deliberately absent from MCP traffic.
    pub fn sync_live_mcp_tools(
        &self,
        server_name: &str,
        manifests: &[McpToolManifest],
    ) -> Result<Vec<McpDrift>> {
        self.sync_mcp_tools_inner(server_name, None, manifests, true)
    }

    fn sync_mcp_tools_inner(
        &self,
        server_name: &str,
        observed_sha256: Option<&str>,
        manifests: &[McpToolManifest],
        preserve_recorded_capabilities: bool,
    ) -> Result<Vec<McpDrift>> {
        let now = Utc::now();
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(super::store::storage_error)?;
        let server = read_server_by_name(&transaction, server_name)?
            .ok_or_else(|| VigilError::NotFound(format!("MCP server `{server_name}`")))?;
        let known = read_tools(&transaction, &server.server_id)?;
        let baseline = known.is_empty();
        let mut drift = Vec::new();

        if let (Some(registered), Some(observed)) = (&server.executable_sha256, observed_sha256) {
            if registered != observed {
                drift.push(McpDrift::ServerSubstituted {
                    registered_sha256: registered.clone(),
                    observed_sha256: observed.to_string(),
                });
            }
        }

        let observed_names: BTreeSet<&str> =
            manifests.iter().map(|tool| tool.name.as_str()).collect();
        for tool in &known {
            if !observed_names.contains(tool.tool_name.as_str()) {
                drift.push(McpDrift::ToolRemoved {
                    tool: tool.tool_name.clone(),
                });
            }
        }

        for manifest in manifests {
            validate_name(&manifest.name)?;
            let schema_hash = manifest.schema_hash()?;
            let description_hash = manifest.description_hash();
            match known.iter().find(|tool| tool.tool_name == manifest.name) {
                None => {
                    let declared = serde_json::to_string(&manifest.declared_capabilities)?;
                    if !baseline {
                        drift.push(McpDrift::ToolAdded {
                            tool: manifest.name.clone(),
                        });
                    }
                    transaction
                        .execute(
                            "INSERT INTO mcp_tools
                             (server_id, tool_name, schema_hash, description_hash,
                              declared_capabilities_json, first_seen, last_seen)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                            params![
                                server.server_id,
                                manifest.name,
                                schema_hash,
                                description_hash,
                                declared,
                                now.to_rfc3339(),
                            ],
                        )
                        .map_err(super::store::storage_error)?;
                }
                Some(existing) => {
                    let declared = if preserve_recorded_capabilities {
                        serde_json::to_string(&existing.declared_capabilities)?
                    } else {
                        serde_json::to_string(&manifest.declared_capabilities)?
                    };
                    if existing.schema_hash != schema_hash {
                        drift.push(McpDrift::ToolSchemaChanged {
                            tool: manifest.name.clone(),
                        });
                    }
                    if existing.description_hash != description_hash {
                        // Description text is what an agent reads to decide whether to call a
                        // tool. Changing it after trust is established is how a tool gets
                        // repurposed without its schema moving.
                        drift.push(McpDrift::ToolDescriptionChanged {
                            tool: manifest.name.clone(),
                        });
                    }
                    for capability in &manifest.declared_capabilities {
                        if !existing.declared_capabilities.contains(capability) {
                            drift.push(McpDrift::ToolCapabilityAdded {
                                tool: manifest.name.clone(),
                                capability: *capability,
                            });
                        }
                    }
                    transaction
                        .execute(
                            "UPDATE mcp_tools
                             SET schema_hash = ?1, description_hash = ?2,
                                 declared_capabilities_json = ?3, last_seen = ?4
                             WHERE server_id = ?5 AND tool_name = ?6",
                            params![
                                schema_hash,
                                description_hash,
                                declared,
                                now.to_rfc3339(),
                                server.server_id,
                                manifest.name,
                            ],
                        )
                        .map_err(super::store::storage_error)?;
                }
            }
        }
        if drift.is_empty() {
            transaction.commit().map_err(super::store::storage_error)?;
        } else {
            // A drift observation is evidence about the trusted baseline, not permission to
            // replace it. Roll back every staged insert/update so the same observation remains
            // drift on the next sync. A future explicit rebaseline operation must carry its
            // own operator authentication and audit semantics.
            transaction
                .rollback()
                .map_err(super::store::storage_error)?;
        }
        Ok(drift)
    }

    pub fn list_mcp_servers(&self) -> Result<Vec<McpServer>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT server_id, name, transport, executable, executable_sha256, version,
                        first_seen, last_seen, trust_state
                 FROM mcp_servers ORDER BY name",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([], server_from_row)
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }

    /// Resolve and re-hash the registered stdio executable immediately before proxy launch.
    /// A trusted server name must never authorize a different caller-supplied process.
    pub fn verify_mcp_proxy_executable(
        &self,
        server_name: &str,
        requested_executable: &Path,
    ) -> Result<PathBuf> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(super::store::storage_error)?;
        let server = read_server_by_name(&transaction, server_name)?
            .ok_or_else(|| VigilError::NotFound(format!("MCP server `{server_name}`")))?;
        transaction.commit().map_err(super::store::storage_error)?;
        if server.trust_state != McpTrustState::Trusted || !has_complete_identity(&server) {
            return Err(VigilError::Unauthorized(
                "the MCP proxy requires a trusted server with complete executable identity"
                    .to_string(),
            ));
        }
        let registered = PathBuf::from(server.executable.as_deref().ok_or_else(|| {
            VigilError::AuditIntegrity("trusted MCP server has no executable path".to_string())
        })?);
        let registered =
            std::fs::canonicalize(&registered).map_err(|error| VigilError::Unavailable {
                component: "mcp_proxy_identity",
                reason: format!("registered executable cannot be resolved: {error}"),
            })?;
        let requested = std::fs::canonicalize(requested_executable).map_err(|error| {
            VigilError::Unavailable {
                component: "mcp_proxy_identity",
                reason: format!("requested executable cannot be resolved: {error}"),
            }
        })?;
        if requested != registered {
            return Err(VigilError::Unauthorized(
                "the proxy command is not the executable registered for this MCP server"
                    .to_string(),
            ));
        }
        let file = std::fs::File::open(&registered)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.len() > MAX_MCP_EXECUTABLE_BYTES
        {
            return Err(VigilError::Unauthorized(
                "the registered MCP executable is not a bounded executable file".to_string(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_MCP_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MCP_EXECUTABLE_BYTES {
            return Err(VigilError::Unauthorized(
                "the registered MCP executable exceeds the hashing size bound".to_string(),
            ));
        }
        let observed = ContentHash::sha256(&bytes).to_string();
        let expected = server.executable_sha256.as_deref().ok_or_else(|| {
            VigilError::AuditIntegrity("trusted MCP server has no executable hash".to_string())
        })?;
        if observed != expected {
            return Err(VigilError::AuditIntegrity(format!(
                "MCP server `{server_name}` changed binary identity; refusing proxy launch"
            )));
        }
        Ok(registered)
    }

    pub fn mcp_tools(&self, server_name: &str) -> Result<Vec<McpTool>> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(super::store::storage_error)?;
        let server = read_server_by_name(&transaction, server_name)?
            .ok_or_else(|| VigilError::NotFound(format!("MCP server `{server_name}`")))?;
        let tools = read_tools(&transaction, &server.server_id)?;
        transaction.commit().map_err(super::store::storage_error)?;
        Ok(tools)
    }

    pub fn quarantine_mcp_server(&self, server_name: &str, quarantined: bool) -> Result<()> {
        let state = if quarantined {
            McpTrustState::Quarantined
        } else {
            McpTrustState::Trusted
        };
        let changed = self
            .connection
            .execute(
                "UPDATE mcp_servers SET trust_state = ?1 WHERE name = ?2",
                params![state.as_str(), server_name],
            )
            .map_err(super::store::storage_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(VigilError::NotFound(format!("MCP server `{server_name}`")))
        }
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
    {
        return Err(VigilError::InvalidValue {
            field: "name",
            reason: "an MCP server or tool name must be 1..=128 characters of letters, digits \
                     and `._:-`"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<()> {
    let digest = hash.strip_prefix("sha256:").unwrap_or(hash);
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VigilError::InvalidValue {
            field: "executable_sha256",
            reason: "expected a SHA-256 digest as 64 hex characters".to_string(),
        });
    }
    Ok(())
}

fn has_complete_identity(server: &McpServer) -> bool {
    server.transport == McpTransport::Stdio
        && server
            .executable
            .as_deref()
            .is_some_and(|path| !path.is_empty() && !path.contains('\0'))
        && server
            .executable_sha256
            .as_deref()
            .is_some_and(|hash| validate_hash(hash).is_ok())
}

fn read_server(transaction: &Transaction<'_>, server_id: &str) -> Result<McpServer> {
    transaction
        .query_row(
            "SELECT server_id, name, transport, executable, executable_sha256, version,
                    first_seen, last_seen, trust_state
             FROM mcp_servers WHERE server_id = ?1",
            [server_id],
            server_from_row,
        )
        .map_err(super::store::storage_error)?
}

fn read_server_by_name(transaction: &Transaction<'_>, name: &str) -> Result<Option<McpServer>> {
    let row = transaction
        .query_row(
            "SELECT server_id, name, transport, executable, executable_sha256, version,
                    first_seen, last_seen, trust_state
             FROM mcp_servers WHERE name = ?1",
            [name],
            server_from_row,
        )
        .optional()
        .map_err(super::store::storage_error)?;
    row.transpose()
}

fn read_tools(transaction: &Transaction<'_>, server_id: &str) -> Result<Vec<McpTool>> {
    let mut statement = transaction
        .prepare(
            "SELECT server_id, tool_name, schema_hash, description_hash,
                    declared_capabilities_json, first_seen, last_seen
             FROM mcp_tools WHERE server_id = ?1 ORDER BY tool_name",
        )
        .map_err(super::store::storage_error)?;
    let rows = statement
        .query_map([server_id], tool_from_row)
        .map_err(super::store::storage_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(super::store::storage_error)?;
    rows.into_iter().collect()
}

fn server_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<McpServer>> {
    let server_id: String = row.get(0)?;
    let name: String = row.get(1)?;
    let transport: String = row.get(2)?;
    let executable: Option<String> = row.get(3)?;
    let executable_sha256: Option<String> = row.get(4)?;
    let version: Option<String> = row.get(5)?;
    let first_seen: String = row.get(6)?;
    let last_seen: String = row.get(7)?;
    let trust_state: String = row.get(8)?;

    Ok((|| {
        Ok(McpServer {
            server_id,
            name,
            transport: transport.parse()?,
            executable,
            executable_sha256,
            version,
            first_seen: parse_time(&first_seen)?,
            last_seen: parse_time(&last_seen)?,
            trust_state: McpTrustState::parse(&trust_state)?,
        })
    })())
}

fn tool_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<McpTool>> {
    let server_id: String = row.get(0)?;
    let tool_name: String = row.get(1)?;
    let schema_hash: String = row.get(2)?;
    let description_hash: String = row.get(3)?;
    let declared: String = row.get(4)?;
    let first_seen: String = row.get(5)?;
    let last_seen: String = row.get(6)?;

    Ok((|| {
        Ok(McpTool {
            server_id,
            tool_name,
            schema_hash,
            description_hash,
            declared_capabilities: serde_json::from_str(&declared)?,
            first_seen: parse_time(&first_seen)?,
            last_seen: parse_time(&last_seen)?,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| VigilError::Serialization(format!("unparsable MCP timestamp: {error}")))
}

/// The verdict on one MCP tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthorization {
    pub server_name: String,
    pub tool_name: String,
    /// Whether the call may proceed. False if *any* resource in it was refused.
    pub permitted: bool,
    /// One entry per resource found in the arguments, each independently decided.
    pub resources: Vec<McpResourceDecision>,
    /// Resources outside what the tool declared it would touch.
    pub scope_escapes: Vec<String>,
    pub risk_state: RiskState,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResourceDecision {
    pub argument: String,
    pub requested: String,
    pub kind: ResourceKind,
    pub action: LocalAction,
    pub outcome: DecisionOutcome,
    pub determining_policy: String,
    pub reason: String,
    pub approval_id: Option<String>,
}

impl LocalStore {
    /// Authorize one MCP tool call for a session.
    ///
    /// Every resource in the arguments is decided independently through the same path a
    /// direct broker request takes, so an MCP call gets no authority a direct call would not.
    /// **One refusal refuses the call**: a tool that touches four allowed paths and one
    /// protected one does not get to perform the four.
    ///
    /// The tool's declared capabilities are consulted only to notice that it reached beyond
    /// them. They never widen what is permitted.
    pub fn authorize_mcp_call(
        &self,
        session_id: &str,
        call: &McpToolCall<'_>,
    ) -> Result<McpAuthorization> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        let profile: crate::LocalProfile = session.profile.parse()?;
        let workspace = std::path::PathBuf::from(&session.workspace);
        let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());

        // A quarantined server is refused before any of its arguments are considered.
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(super::store::storage_error)?;
        let server = read_server_by_name(&transaction, call.server_name)?;
        let tool = match &server {
            Some(server) => read_tools(&transaction, &server.server_id)?
                .into_iter()
                .find(|tool| tool.tool_name == call.tool_name),
            None => None,
        };
        transaction.commit().map_err(super::store::storage_error)?;

        if let Some(server) = &server {
            if server.trust_state == McpTrustState::Quarantined {
                let authorization = McpAuthorization {
                    server_name: call.server_name.to_string(),
                    tool_name: call.tool_name.to_string(),
                    permitted: false,
                    resources: Vec::new(),
                    scope_escapes: Vec::new(),
                    risk_state: self.session_risk_state(session_id)?,
                    reason: "the MCP server is quarantined".to_string(),
                };
                self.record_mcp_event(session_id, &correlation_id, &authorization)?;
                return Ok(authorization);
            }
        }

        let extracted = extract_resources(call.arguments);
        let identity_failure = match (&server, &tool) {
            (None, _) => Some("the MCP server is not registered"),
            (Some(server), _) if !has_complete_identity(server) => {
                Some("the MCP server has no complete trusted identity")
            }
            (Some(_), None) => Some("the MCP tool is not registered for this server"),
            (Some(_), Some(_)) => None,
        };

        // Identity is a prerequisite, not another vote in the resource fold. An unknown
        // server or tool must not become executable merely because its arguments happen to
        // contain no path or URL. Preserve the extracted resources in the decision so the
        // attempted reach is still attributable, but do not spend leases or raise approvals
        // for a call whose principal is not trusted.
        if let Some(reason) = identity_failure {
            let resources = extracted
                .iter()
                .map(|resource| McpResourceDecision {
                    argument: resource.argument.clone(),
                    requested: resource.value.clone(),
                    kind: resource.kind,
                    action: resource.kind.implied_action(),
                    outcome: DecisionOutcome::Deny,
                    determining_policy: "mcp-registered-identity".to_string(),
                    reason: reason.to_string(),
                    approval_id: None,
                })
                .collect();
            let authorization = McpAuthorization {
                server_name: call.server_name.to_string(),
                tool_name: call.tool_name.to_string(),
                permitted: false,
                resources,
                scope_escapes: extracted
                    .iter()
                    .map(|resource| resource.value.clone())
                    .collect(),
                risk_state: self.session_risk_state(session_id)?,
                reason: reason.to_string(),
            };
            self.record_mcp_event(session_id, &correlation_id, &authorization)?;
            return Ok(authorization);
        }

        let declared = tool
            .as_ref()
            .map(|tool| tool.declared_capabilities.clone())
            .unwrap_or_default();

        // Resource extraction is the positive authorization evidence for this slice. A call
        // containing none has not identified an action/resource pair policy can authorize,
        // so default deny instead of treating an empty loop as unanimous approval.
        if extracted.is_empty() {
            let authorization = McpAuthorization {
                server_name: call.server_name.to_string(),
                tool_name: call.tool_name.to_string(),
                permitted: false,
                resources: Vec::new(),
                scope_escapes: Vec::new(),
                risk_state: self.session_risk_state(session_id)?,
                reason: "the MCP call contains no resource VIGIL can authorize".to_string(),
            };
            self.record_mcp_event(session_id, &correlation_id, &authorization)?;
            return Ok(authorization);
        }

        let scope_escapes: Vec<String> = extracted
            .iter()
            .filter(|resource| !declared.contains(&resource.kind.implied_action()))
            .map(|resource| resource.value.clone())
            .collect();
        if !scope_escapes.is_empty() {
            let mut risk_state = self.session_risk_state(session_id)?;
            if let Some(rule) = crate::detection::rule_for_label(DETECTION_MCP_SCOPE_ESCAPE) {
                self.record_detection(
                    session_id,
                    rule,
                    serde_json::json!({
                        "server": call.server_name,
                        "tool": call.tool_name,
                        "declared_capabilities": declared,
                        "resources_outside_declaration": scope_escapes,
                    }),
                    None,
                )?;
                risk_state = self.record_risk_signal(
                    session_id,
                    rule.dimension,
                    rule.weight,
                    None,
                    rule.description,
                )?;
            }
            let reason = "the MCP call reaches beyond the tool's declared capabilities";
            let resources = extracted
                .iter()
                .map(|resource| McpResourceDecision {
                    argument: resource.argument.clone(),
                    requested: resource.value.clone(),
                    kind: resource.kind,
                    action: resource.kind.implied_action(),
                    outcome: DecisionOutcome::Deny,
                    determining_policy: "mcp-declared-capability".to_string(),
                    reason: reason.to_string(),
                    approval_id: None,
                })
                .collect();
            let authorization = McpAuthorization {
                server_name: call.server_name.to_string(),
                tool_name: call.tool_name.to_string(),
                permitted: false,
                resources,
                scope_escapes,
                risk_state,
                reason: reason.to_string(),
            };
            self.record_mcp_event(session_id, &correlation_id, &authorization)?;
            return Ok(authorization);
        }

        let mut risk_state = self.session_risk_state(session_id)?;
        let mut preflight = Vec::with_capacity(extracted.len());
        for resource in extracted {
            let action = resource.kind.implied_action();
            let decision = match resource.kind {
                ResourceKind::Path => crate::evaluate_in_context(&crate::LocalRequest {
                    profile,
                    workspace: &workspace,
                    action,
                    resource: &resource.value,
                    risk: risk_state,
                    lease: crate::LeaseStatus::Absent,
                }),
                ResourceKind::Url => {
                    // A URL is decided as a destination, not as a path, so it goes through the
                    // network vocabulary rather than being resolved against the workspace.
                    crate::evaluate_in_context(&crate::LocalRequest {
                        profile,
                        workspace: &workspace,
                        action,
                        resource: &resource.value,
                        risk: risk_state,
                        lease: crate::LeaseStatus::Absent,
                    })
                }
            };
            preflight.push((resource, decision));
        }

        // A deterministic denial aborts the whole call before any approval-bound resource can
        // spend a lease. Detection-bearing denials still take their normal evidence/risk path.
        if preflight
            .iter()
            .any(|(_, decision)| decision.outcome == DecisionOutcome::Deny)
        {
            let mut resources = Vec::with_capacity(preflight.len());
            for (resource, base) in preflight {
                let action = resource.kind.implied_action();
                let (decision, approval_id) = if base.outcome == DecisionOutcome::Deny {
                    let authorization = self.authorize_decision(
                        session_id,
                        action,
                        &resource.value,
                        base,
                        |decision| decision.resolved_resource.clone(),
                    )?;
                    risk_state = authorization.risk_state;
                    (authorization.decision, None)
                } else {
                    (base, None)
                };
                resources.push(McpResourceDecision {
                    argument: resource.argument,
                    requested: resource.value,
                    kind: resource.kind,
                    action,
                    outcome: decision.outcome,
                    determining_policy: decision.determining_policy,
                    reason: decision.reason,
                    approval_id,
                });
            }
            let authorization = McpAuthorization {
                server_name: call.server_name.to_string(),
                tool_name: call.tool_name.to_string(),
                permitted: false,
                resources,
                scope_escapes: Vec::new(),
                risk_state,
                reason: "at least one resource in the call was denied during preflight".to_string(),
            };
            self.record_mcp_event(session_id, &correlation_id, &authorization)?;
            return Ok(authorization);
        }

        let approval_bound: Vec<(usize, LocalAction, String)> = preflight
            .iter()
            .enumerate()
            .filter(|(_, (_, decision))| decision.outcome == DecisionOutcome::RequireApproval)
            .map(|(resource_index, (resource, decision))| {
                (
                    resource_index,
                    resource.kind.implied_action(),
                    decision
                        .resolved_resource
                        .clone()
                        .unwrap_or_else(|| resource.value.clone()),
                )
            })
            .collect();
        let lease_uses: Vec<_> = approval_bound
            .iter()
            .map(|(_, action, resource)| LeaseUse {
                action: *action,
                resource,
            })
            .collect();
        let consumption = self.consume_leases_atomically(session_id, &lease_uses, Utc::now())?;
        let missing = match consumption {
            AtomicLeaseConsumption::Consumed(_) => Vec::new(),
            AtomicLeaseConsumption::Missing(indexes) => indexes,
        };
        let missing_resource_indexes: BTreeSet<usize> = missing
            .into_iter()
            .filter_map(|lease_index| {
                approval_bound
                    .get(lease_index)
                    .map(|(resource_index, _, _)| *resource_index)
            })
            .collect();

        let mut resources = Vec::with_capacity(preflight.len());
        for (resource_index, (resource, base)) in preflight.into_iter().enumerate() {
            let action = resource.kind.implied_action();
            let mut approval_id = None;
            let decision = if base.outcome == DecisionOutcome::RequireApproval
                && missing_resource_indexes.is_empty()
            {
                crate::policy::apply_session_state(
                    base,
                    action,
                    risk_state,
                    crate::LeaseStatus::Present,
                )
            } else {
                if missing_resource_indexes.contains(&resource_index) {
                    let resolved = base
                        .resolved_resource
                        .as_deref()
                        .unwrap_or(resource.value.as_str());
                    let outcome = self.request_approval(
                        &crate::CapabilityAsk {
                            session_id,
                            action,
                            requested_resource: &resource.value,
                            resolved_resource: resolved,
                            determining_policy: &base.determining_policy,
                            reason: &base.reason,
                        },
                        Utc::now(),
                    )?;
                    approval_id = Some(outcome.request().approval_id.clone());
                    if let crate::ApprovalOutcome::PreviouslyDenied {
                        risk_state: after, ..
                    } = outcome
                    {
                        risk_state = after;
                    }
                }
                base
            };
            resources.push(McpResourceDecision {
                argument: resource.argument,
                requested: resource.value,
                kind: resource.kind,
                action,
                outcome: decision.outcome,
                determining_policy: decision.determining_policy,
                reason: decision.reason,
                approval_id,
            });
        }

        let permitted = missing_resource_indexes.is_empty();
        let reason = if permitted {
            "every resource in the call is permitted and required leases were consumed atomically"
                .to_string()
        } else {
            "at least one resource lacks a lease; no lease was consumed".to_string()
        };
        let authorization = McpAuthorization {
            server_name: call.server_name.to_string(),
            tool_name: call.tool_name.to_string(),
            permitted,
            resources,
            scope_escapes: Vec::new(),
            risk_state,
            reason,
        };
        self.record_mcp_event(session_id, &correlation_id, &authorization)?;
        Ok(authorization)
    }

    /// Record drift as detections against a session.
    pub fn record_mcp_drift(
        &self,
        session_id: &str,
        server_name: &str,
        drift: &[McpDrift],
    ) -> Result<RiskState> {
        let mut risk_state = self.session_risk_state(session_id)?;
        for change in drift {
            let rule = change.rule();
            self.record_detection(
                session_id,
                rule,
                serde_json::json!({ "server": server_name, "drift": change }),
                None,
            )?;
            risk_state = self.record_risk_signal(
                session_id,
                rule.dimension,
                rule.weight,
                None,
                rule.description,
            )?;
            if rule.severity >= Severity::Critical || risk_state.revokes_leases() {
                let incident = self.open_incident(
                    session_id,
                    rule.severity,
                    &format!("{} on MCP server `{server_name}`", rule.name),
                )?;
                self.attach_detections(&incident.incident_id, session_id)?;
            }
        }
        Ok(risk_state)
    }

    fn record_mcp_event(
        &self,
        session_id: &str,
        correlation_id: &str,
        authorization: &McpAuthorization,
    ) -> Result<()> {
        self.append_event(
            session_id,
            "mcp",
            "mcp.tool_call",
            Some(if authorization.permitted {
                "ALLOW"
            } else {
                "DENY"
            }),
            correlation_id,
            &serde_json::json!({
                "server": authorization.server_name,
                "tool": authorization.tool_name,
                "resources": authorization.resources,
                "scope_escapes": authorization.scope_escapes,
                "risk_state": authorization.risk_state.as_str(),
                "reason": authorization.reason,
                // Argument values reach evidence only as the resources policy decided about.
                "argument_content_captured": false,
            }),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::NewSession;
    use std::path::PathBuf;

    fn active_session() -> (PathBuf, LocalStore, String, PathBuf) {
        let root = std::env::temp_dir().join(format!("vigil-mcp-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: "developer-standard".to_string(),
                workspace: workspace.clone(),
                executable: "vigil-test".to_string(),
                argv: vec!["vigil-test".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .mark_running(&session.id, std::process::id())
            .expect("activate");
        (root, store, session.id, workspace)
    }

    fn manifest(name: &str, description: &str, declared: &[LocalAction]) -> McpToolManifest {
        McpToolManifest {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: serde_json::json!({ "type": "object" }),
            declared_capabilities: declared.to_vec(),
        }
    }

    fn register_test_server(store: &LocalStore, name: &str) {
        store
            .register_mcp_server(
                name,
                McpTransport::Stdio,
                Some(&format!("/test/{name}")),
                Some(&"a".repeat(64)),
                None,
            )
            .expect("register");
    }

    #[test]
    fn proxy_launch_is_bound_to_the_registered_binary_and_current_hash() {
        let (root, store, _session, workspace) = active_session();
        let executable = workspace.join("server");
        std::fs::write(&executable, b"registered server").expect("write executable");
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).expect("make executable");
        let digest = ContentHash::sha256(&std::fs::read(&executable).expect("read")).to_string();
        store
            .register_mcp_server(
                "bound",
                McpTransport::Stdio,
                Some(&executable.display().to_string()),
                Some(&digest),
                None,
            )
            .expect("register");

        let verified = store
            .verify_mcp_proxy_executable("bound", &executable)
            .expect("verify registered binary");
        assert_eq!(
            verified,
            std::fs::canonicalize(&executable).expect("canonical")
        );

        let substitute = workspace.join("substitute");
        std::fs::write(&substitute, b"other program").expect("write substitute");
        assert!(matches!(
            store.verify_mcp_proxy_executable("bound", &substitute),
            Err(VigilError::Unauthorized(_))
        ));

        std::fs::write(&executable, b"replaced server").expect("replace executable");
        assert!(matches!(
            store.verify_mcp_proxy_executable("bound", &executable),
            Err(VigilError::AuditIntegrity(_))
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn live_tool_sync_preserves_operator_reviewed_capabilities() {
        let (root, store, _session, _workspace) = active_session();
        register_test_server(&store, "live-capabilities");
        let reviewed = manifest("write_file", "Writes.", &[LocalAction::FsWrite]);
        store
            .sync_mcp_tools("live-capabilities", None, std::slice::from_ref(&reviewed))
            .expect("establish reviewed baseline");

        let mut observed = reviewed;
        observed.declared_capabilities.clear();
        let drift = store
            .sync_live_mcp_tools("live-capabilities", &[observed])
            .expect("sync live listing");
        assert!(drift.is_empty());
        assert_eq!(
            store.mcp_tools("live-capabilities").expect("tools")[0].declared_capabilities,
            vec![LocalAction::FsWrite]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Prompt Demo 5. The same tool, called twice; only the argument differs.
    #[test]
    fn a_tool_permitted_in_the_workspace_is_refused_outside_it() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "filesystem");
        store
            .sync_mcp_tools(
                "filesystem",
                None,
                &[manifest(
                    "write_file",
                    "Writes a workspace file.",
                    &[LocalAction::FsRead],
                )],
            )
            .expect("sync");

        let inside = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "filesystem",
                    tool_name: "write_file",
                    arguments: &serde_json::json!({ "path": "./notes.md" }),
                },
            )
            .expect("authorize");
        assert!(inside.permitted, "{inside:?}");

        let outside = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "filesystem",
                    tool_name: "write_file",
                    arguments: &serde_json::json!({ "path": "~/.ssh/config" }),
                },
            )
            .expect("authorize");
        assert!(
            !outside.permitted,
            "the same tool must fail on the argument"
        );
        assert_eq!(outside.resources.len(), 1);
        assert_eq!(outside.resources[0].outcome, DecisionOutcome::Deny);
        let _ = std::fs::remove_dir_all(root);
    }

    /// One refusal refuses the call. A tool that touches four allowed paths and one protected
    /// one does not get to perform the four.
    #[test]
    fn one_refused_resource_refuses_the_whole_call() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "filesystem");
        store
            .sync_mcp_tools(
                "filesystem",
                None,
                &[manifest(
                    "bulk_edit",
                    "Reads several resources.",
                    &[LocalAction::FsRead],
                )],
            )
            .expect("sync");
        let authorization = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "filesystem",
                    tool_name: "bulk_edit",
                    arguments: &serde_json::json!({
                        "edits": [
                            { "path": "./a.rs" },
                            { "path": "./b.rs" },
                            { "path": "~/.aws/credentials" },
                            { "path": "./c.rs" }
                        ]
                    }),
                },
            )
            .expect("authorize");
        assert!(!authorization.permitted);
        assert_eq!(authorization.resources.len(), 4);
        assert_eq!(
            authorization
                .resources
                .iter()
                .filter(|resource| resource.outcome == DecisionOutcome::Deny)
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// An unregistered server is not a principal and can never execute, even when its
    /// arguments would otherwise describe an allowed workspace resource.
    #[test]
    fn an_unregistered_server_is_refused_before_resource_authority() {
        let (root, store, session, _workspace) = active_session();
        let authorization = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "never-registered",
                    tool_name: "anything",
                    arguments: &serde_json::json!({ "path": "./notes.md" }),
                },
            )
            .expect("authorize");
        assert!(!authorization.permitted);
        assert!(authorization.reason.contains("not registered"));
        assert_eq!(authorization.resources.len(), 1);
        assert_eq!(authorization.resources[0].outcome, DecisionOutcome::Deny);
        assert_eq!(authorization.scope_escapes, vec!["./notes.md"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unknown_tool_and_a_resource_free_call_fail_closed() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "filesystem");
        store
            .sync_mcp_tools(
                "filesystem",
                None,
                &[manifest("read_file", "Reads.", &[LocalAction::FsRead])],
            )
            .expect("sync");

        let unknown = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "filesystem",
                    tool_name: "not_registered",
                    arguments: &serde_json::json!({ "path": "./notes.md" }),
                },
            )
            .expect("authorize unknown tool");
        assert!(!unknown.permitted);
        assert!(unknown.reason.contains("tool is not registered"));

        let resource_free = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "filesystem",
                    tool_name: "read_file",
                    arguments: &serde_json::json!({ "encoding": "utf-8" }),
                },
            )
            .expect("authorize resource-free call");
        assert!(!resource_free.permitted);
        assert!(resource_free.reason.contains("no resource"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_quarantined_server_is_refused_before_its_arguments_are_considered() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "filesystem");
        store
            .quarantine_mcp_server("filesystem", true)
            .expect("quarantine");
        let authorization = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "filesystem",
                    tool_name: "write_file",
                    // A perfectly ordinary workspace path, which would otherwise be allowed.
                    arguments: &serde_json::json!({ "path": "./notes.md" }),
                },
            )
            .expect("authorize");
        assert!(!authorization.permitted);
        assert!(authorization.resources.is_empty());
        assert!(authorization.reason.contains("quarantined"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// The first sync is a baseline, not drift. A server has not misbehaved by being seen.
    #[test]
    fn the_first_sync_establishes_a_baseline_without_reporting_drift() {
        let (root, store, _session, _workspace) = active_session();
        register_test_server(&store, "filesystem");
        let drift = store
            .sync_mcp_tools(
                "filesystem",
                None,
                &[
                    manifest("read_file", "Reads.", &[LocalAction::FsRead]),
                    manifest("write_file", "Writes.", &[LocalAction::FsWrite]),
                ],
            )
            .expect("sync");
        assert!(drift.is_empty(), "{drift:?}");
        assert_eq!(store.mcp_tools("filesystem").expect("tools").len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unstable_numeric_schema_is_refused_before_it_can_become_a_baseline() {
        let (root, store, _session, _workspace) = active_session();
        register_test_server(&store, "unstable-schema");
        let manifests: Vec<McpToolManifest> =
            serde_json::from_str("[[\"calculate\",\"\",[2e-066]]]").expect("parse wire manifest");

        let error = store
            .sync_mcp_tools("unstable-schema", None, &manifests)
            .expect_err("an unstable schema must fail before baseline insertion");
        assert!(format!("{error}").contains("exponent"), "{error}");
        assert!(
            store
                .mcp_tools("unstable-schema")
                .expect("stored tools")
                .is_empty(),
            "a refused schema reached the trusted baseline"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn every_shape_of_drift_is_reported_after_the_baseline() {
        let (root, store, _session, _workspace) = active_session();
        register_test_server(&store, "filesystem");
        store
            .sync_mcp_tools(
                "filesystem",
                None,
                &[
                    manifest("read_file", "Reads.", &[LocalAction::FsRead]),
                    manifest("old_tool", "Goes away.", &[]),
                ],
            )
            .expect("baseline");

        let mut changed = manifest(
            "read_file",
            "Reads ANYTHING.",
            &[LocalAction::FsRead, LocalAction::ProcessExec],
        );
        changed.input_schema = serde_json::json!({ "type": "object", "properties": { "x": {} } });
        let observed = vec![changed, manifest("new_tool", "Appeared.", &[])];
        let drift = store
            .sync_mcp_tools("filesystem", None, &observed)
            .expect("sync");

        let kinds: Vec<_> = drift
            .iter()
            .map(|change| serde_json::to_value(change).expect("json")["kind"].clone())
            .collect();
        for expected in [
            "tool_removed",
            "tool_schema_changed",
            "tool_description_changed",
            "tool_capability_added",
            "tool_added",
        ] {
            assert!(
                kinds.iter().any(|kind| kind == expected),
                "missing {expected} in {kinds:?}"
            );
        }
        let repeated = store
            .sync_mcp_tools("filesystem", None, &observed)
            .expect("repeat sync");
        assert_eq!(
            serde_json::to_value(&repeated).expect("repeat JSON"),
            serde_json::to_value(&drift).expect("drift JSON"),
            "observing drift must not overwrite the trusted baseline"
        );
        let stored_names: Vec<_> = store
            .mcp_tools("filesystem")
            .expect("baseline tools")
            .into_iter()
            .map(|tool| tool.tool_name)
            .collect();
        assert_eq!(stored_names, ["old_tool", "read_file"]);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Swapping the binary behind a trusted name is the substitution the hash exists to catch.
    #[test]
    fn a_changed_binary_is_reported_as_substitution() {
        let (root, store, session, _workspace) = active_session();
        let registered = "a".repeat(64);
        store
            .register_mcp_server(
                "filesystem",
                McpTransport::Stdio,
                Some("/opt/fs-server"),
                Some(&registered),
                None,
            )
            .expect("register");
        let drift = store
            .sync_mcp_tools("filesystem", Some(&"b".repeat(64)), &[])
            .expect("sync");
        assert!(matches!(
            drift.as_slice(),
            [McpDrift::ServerSubstituted { .. }]
        ));

        // Recording it quarantines the session outright: L011 alone carries enough weight.
        let risk = store
            .record_mcp_drift(&session, "filesystem", &drift)
            .expect("record");
        assert_eq!(risk, RiskState::Quarantined);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Re-registering over a different binary must not silently accept the new one.
    #[test]
    fn re_registering_with_a_different_binary_is_refused() {
        let (root, store, _session, _workspace) = active_session();
        store
            .register_mcp_server(
                "filesystem",
                McpTransport::Stdio,
                Some("/opt/fs-server"),
                Some(&"a".repeat(64)),
                None,
            )
            .expect("register");
        let error = store
            .register_mcp_server(
                "filesystem",
                McpTransport::Stdio,
                Some("/opt/fs-server"),
                Some(&"b".repeat(64)),
                None,
            )
            .expect_err("substitution must not be accepted silently");
        assert!(matches!(error, VigilError::AuditIntegrity(_)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incomplete_or_unsupported_server_identity_is_refused() {
        let (root, store, _session, _workspace) = active_session();
        assert!(store
            .register_mcp_server("no-binary", McpTransport::Stdio, None, None, None)
            .is_err());
        assert!(store
            .register_mcp_server(
                "no-hash",
                McpTransport::Stdio,
                Some("/opt/server"),
                None,
                None,
            )
            .is_err());
        assert!(store
            .register_mcp_server(
                "remote",
                McpTransport::Http,
                Some("https://example.invalid/mcp"),
                Some(&"a".repeat(64)),
                None,
            )
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_legacy_server_with_no_hash_cannot_authorize_calls() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "legacy");
        store
            .sync_mcp_tools(
                "legacy",
                None,
                &[manifest("read_file", "Reads.", &[LocalAction::FsRead])],
            )
            .expect("sync");
        store
            .connection
            .execute(
                "UPDATE mcp_servers SET executable_sha256 = NULL WHERE name = 'legacy'",
                [],
            )
            .expect("simulate legacy identity");

        let authorization = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "legacy",
                    tool_name: "read_file",
                    arguments: &serde_json::json!({ "path": "./notes.md" }),
                },
            )
            .expect("authorize");
        assert!(!authorization.permitted);
        assert!(authorization
            .reason
            .contains("no complete trusted identity"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// Reaching beyond a declared capability is a detection, but declaring a capability is
    /// never what grants it: the declared-everything call is still refused on its argument.
    #[test]
    fn declaring_a_capability_does_not_grant_it() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "greedy");
        store
            .sync_mcp_tools(
                "greedy",
                None,
                &[manifest(
                    "do_anything",
                    "Claims everything.",
                    &[
                        LocalAction::FsRead,
                        LocalAction::FsWrite,
                        LocalAction::NetworkConnect,
                        LocalAction::SystemPrivileged,
                    ],
                )],
            )
            .expect("sync");
        let authorization = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "greedy",
                    tool_name: "do_anything",
                    arguments: &serde_json::json!({ "path": "~/.ssh/id_ed25519" }),
                },
            )
            .expect("authorize");
        assert!(
            !authorization.permitted,
            "a declaration must not widen what policy permits"
        );
        // It stayed within its declaration, so this is not a scope escape — it is simply denied.
        assert!(authorization.scope_escapes.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reaching_beyond_a_tools_declaration_is_detected_and_refused() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "narrow");
        store
            .sync_mcp_tools(
                "narrow",
                None,
                &[manifest("read_file", "Claims no file access.", &[])],
            )
            .expect("sync");

        let authorization = store
            .authorize_mcp_call(
                &session,
                &McpToolCall {
                    server_name: "narrow",
                    tool_name: "read_file",
                    arguments: &serde_json::json!({
                        "path": "./notes.md",
                        "callback": "https://example.com/upload"
                    }),
                },
            )
            .expect("authorize");
        assert!(!authorization.permitted);
        assert_eq!(authorization.scope_escapes.len(), 2);
        assert!(authorization.reason.contains("declared capabilities"));
        assert!(
            store
                .list_approvals(Some(&session), None, 100)
                .expect("approvals")
                .is_empty(),
            "a scope failure must happen before a network approval is created"
        );
        assert!(store
            .detections_for_session(&session)
            .expect("detections")
            .iter()
            .any(|detection| detection.rule_id == "VIGIL-L012"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_multi_resource_call_consumes_all_required_leases_or_none() {
        let (root, store, session, _workspace) = active_session();
        register_test_server(&store, "browser");
        store
            .sync_mcp_tools(
                "browser",
                None,
                &[manifest(
                    "fetch_many",
                    "Fetches declared destinations.",
                    &[LocalAction::NetworkConnect],
                )],
            )
            .expect("sync");
        let arguments = serde_json::json!({
            "primary": "https://one.example/data",
            "secondary": "https://two.example/data"
        });
        let call = McpToolCall {
            server_name: "browser",
            tool_name: "fetch_many",
            arguments: &arguments,
        };

        let initial = store
            .authorize_mcp_call(&session, &call)
            .expect("initial authorization");
        assert!(!initial.permitted);
        let approvals = store
            .list_approvals(Some(&session), Some(crate::ApprovalStatus::Pending), 10)
            .expect("approvals");
        assert_eq!(approvals.len(), 2);
        let operator = crate::ApproverIdentity::from_cli_operator("operator").expect("operator");
        let first = approvals
            .iter()
            .find(|approval| approval.resolved_resource.contains("one.example"))
            .expect("first approval");
        store
            .grant_approval(&first.approval_id, &operator, 1, 900, None, Utc::now())
            .expect("grant first");

        let partial = store
            .authorize_mcp_call(&session, &call)
            .expect("partial authorization");
        assert!(!partial.permitted);
        let leases = store.leases_for_session(&session).expect("leases");
        assert_eq!(leases.len(), 1);
        assert_eq!(
            leases[0].uses_remaining, 1,
            "the covered lease must roll back when another resource has no lease"
        );

        let second = store
            .list_approvals(Some(&session), Some(crate::ApprovalStatus::Pending), 10)
            .expect("pending approvals")
            .into_iter()
            .find(|approval| approval.resolved_resource.contains("two.example"))
            .expect("second approval");
        store
            .grant_approval(&second.approval_id, &operator, 1, 900, None, Utc::now())
            .expect("grant second");
        let complete = store
            .authorize_mcp_call(&session, &call)
            .expect("complete authorization");
        assert!(complete.permitted, "{complete:?}");
        assert!(store
            .leases_for_session(&session)
            .expect("spent leases")
            .iter()
            .all(|lease| lease.uses_remaining == 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn extraction_finds_resources_the_tool_did_not_advertise() {
        let arguments = serde_json::json!({
            "path": "src/main.rs",
            "encoding": "utf-8",
            "edits": [
                { "file": "~/.ssh/config", "text": "Host evil" },
                { "file": "./notes.md" }
            ],
            "callback": "https://attacker.example/collect",
            "count": 3
        });
        let found = extract_resources(&arguments);
        let values: Vec<_> = found.iter().map(|item| item.value.as_str()).collect();

        // The advertised argument, the buried one, and the URL are all found.
        assert!(values.contains(&"~/.ssh/config"), "{values:?}");
        assert!(values.contains(&"./notes.md"), "{values:?}");
        assert!(
            values.contains(&"https://attacker.example/collect"),
            "{values:?}"
        );
        // A bare word is not a resource; `utf-8` must not become a path to authorize.
        assert!(!values.contains(&"utf-8"), "{values:?}");
        // Nested arguments are reported with the route that reached them, so an operator can
        // see where in the call the resource appeared.
        let nested = found
            .iter()
            .find(|item| item.value == "~/.ssh/config")
            .expect("nested resource");
        assert_eq!(nested.argument, "edits.0.file");
        assert_eq!(nested.kind, ResourceKind::Path);
    }

    /// Relative paths containing a separator are resources too. Treating only paths with an
    /// explicit `./` marker as resources would let `src/main.rs` bypass authorization.
    #[test]
    fn strings_that_could_escape_are_always_treated_as_resources() {
        for escaping in [
            "/etc/passwd",
            "~/.aws/credentials",
            "../../secrets",
            "workspace/../../../etc/hosts",
            "src/main.rs",
            "https://example.com",
            "file:///etc/passwd",
        ] {
            assert!(
                classify_resource(escaping).is_some(),
                "`{escaping}` must be authorized"
            );
        }
        for inert in ["", "utf-8", "read", "3", "a-plain-name"] {
            assert!(
                classify_resource(inert).is_none(),
                "`{inert}` should not be treated as a resource"
            );
        }
    }

    #[test]
    fn extraction_is_bounded_against_a_hostile_server() {
        // A deeply nested document must not recurse without limit.
        let mut deep = serde_json::json!("/tmp/x");
        for _ in 0..200 {
            deep = serde_json::json!({ "next": deep });
        }
        assert!(extract_resources(&deep).is_empty());

        // A wide document is capped rather than producing unbounded work downstream.
        let wide = serde_json::Value::Array(
            (0..500)
                .map(|index| serde_json::json!(format!("/tmp/file{index}")))
                .collect(),
        );
        assert_eq!(extract_resources(&wide).len(), MAX_EXTRACTED_RESOURCES);
    }

    #[test]
    fn a_hash_must_be_a_real_digest() {
        assert!(validate_hash(&"a".repeat(64)).is_ok());
        assert!(validate_hash(&format!("sha256:{}", "b".repeat(64))).is_ok());
        assert!(validate_hash("deadbeef").is_err());
        assert!(validate_hash(&"z".repeat(64)).is_err());
    }

    #[test]
    fn drift_maps_substitution_to_the_critical_rule() {
        let substituted = McpDrift::ServerSubstituted {
            registered_sha256: "a".repeat(64),
            observed_sha256: "b".repeat(64),
        };
        assert_eq!(substituted.rule().id, "VIGIL-L011");
        assert_eq!(substituted.rule().severity, Severity::Critical);
        assert_eq!(substituted.label(), DETECTION_MCP_SERVER_SUBSTITUTION);

        let added = McpDrift::ToolAdded {
            tool: "x".to_string(),
        };
        assert_eq!(added.rule().id, "VIGIL-L010");
        assert_eq!(added.label(), DETECTION_MCP_CAPABILITY_DRIFT);
    }
}
