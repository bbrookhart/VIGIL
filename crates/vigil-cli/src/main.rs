//! The `vigil` command-line tool.
//!
//! Every subcommand here is implemented against a real API. Commands from the design that
//! cannot be implemented against what exists today — `policy simulate`, `session inspect`,
//! `incident export` — are deliberately absent rather than present and stubbed: a CLI that
//! prints "not yet implemented" teaches operators to distrust its output.

use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use vigil_audit::AuditBundle;
use vigil_common::ids::PolicyBundleId;
use vigil_policy::DeterministicPolicyEngine;
use vigil_remit::RemitRegistry;

#[derive(Parser)]
#[command(
    name = "vigil",
    version,
    about = "Operational tooling for VIGIL runtime agent security"
)]
struct Cli {
    /// SQLite database used for local sessions and events.
    #[arg(long, global = true, value_name = "PATH")]
    state_db: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the effective local protection posture.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Launch a command as a durable VIGIL agent session.
    Run {
        #[arg(long, default_value = "developer-standard")]
        profile: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        task: Option<String>,
        /// Command and arguments, following `--`.
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// List durable local agent sessions.
    Sessions {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Inspect one durable local agent session.
    #[command(subcommand)]
    Session(SessionCommand),
    /// Perform filesystem operations through the semantic enforcement broker.
    #[command(subcommand)]
    Fs(FsCommand),
    /// Execute a structured process request through policy and budget enforcement.
    #[command(subcommand)]
    Process(ProcessCommand),
    /// Probe a TCP destination through hostname, resolution, and budget policy.
    #[command(subcommand)]
    Network(NetworkCommand),
    /// Review and decide the capability escalations a session has asked for.
    #[command(subcommand)]
    Approvals(ApprovalsCommand),
    /// Show the capability leases a session holds.
    Capabilities {
        session: String,
        #[arg(long)]
        json: bool,
    },
    /// Show a session's risk state and every dimension behind it.
    Risk {
        session: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the process lineage VIGIL recorded for a session.
    Processes {
        session: String,
        #[arg(long)]
        json: bool,
    },
    /// Register and police MCP servers and their tools.
    #[command(subcommand)]
    Mcp(McpCommand),
    /// Compare what a session declared against what an OS observer saw.
    ///
    /// With no observer, this reports NO_OBSERVER rather than success: an unwatched session
    /// is not a clean one.
    Reconcile {
        session: String,
        /// JSON file of observed operations. Produced by the Endpoint Security simulator or,
        /// when one exists, by the installed extension.
        #[arg(long)]
        observed: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Undo a session's broker-mediated writes.
    ///
    /// Covers only writes that went through VIGIL. Anything a process wrote directly was
    /// never held by VIGIL and cannot be restored.
    Rollback {
        session: String,
        /// Restore only this resolved path.
        #[arg(long)]
        path: Option<String>,
        /// Report what would be restored without touching anything.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Place and manage synthetic assets that exist only to be touched.
    #[command(subcommand)]
    Canary(CanaryCommand),
    /// Run Git through the broker, with repository configuration neutralized.
    #[command(subcommand)]
    Git(GitCommand),
    /// Analyze stored evidence for shapes that need more than one event to see.
    ///
    /// Retrospective: every step in a sequence was already decided, so this explains what a
    /// session turned out to be doing rather than stopping it. Idempotent.
    Analyze {
        session: String,
        #[arg(long)]
        json: bool,
    },
    /// Show detections, newest first.
    Detections {
        #[arg(long)]
        session: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Review incidents and the responses applied to them.
    #[command(subcommand)]
    Incidents(IncidentsCommand),
    /// Contain a session: revoke its capabilities and withhold everything but reads.
    ///
    /// This is not process termination. See `vigil incidents show` for what it did.
    Contain {
        session: String,
        /// Withhold every capability, not only mutating ones.
        #[arg(long)]
        quarantine: bool,
        /// End the session after containing it.
        #[arg(long)]
        seal: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show a session's normalized event timeline.
    Events {
        session: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Replay a semantic action through local policy and persist the evidence.
    Simulate {
        #[arg(long, default_value = "developer-standard")]
        profile: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        action: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate and inspect policy bundles.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Validate agent remits.
    #[command(subcommand)]
    Remit(RemitCommand),
    /// Validate tool security manifests.
    #[command(subcommand)]
    Manifest(ManifestCommand),
    /// Verify tamper-evident audit evidence.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Signing key material.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Check that a deployment's configuration is coherent.
    Doctor {
        /// Directory holding policies, remits and manifests.
        #[arg(default_value = "policies")]
        policy_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Parse and validate every bundle under a directory.
    Validate {
        #[arg(default_value = "policies")]
        dir: PathBuf,
    },
    /// Print every rule with its effect, so a reviewer can read the whole posture at once.
    List {
        #[arg(default_value = "policies")]
        dir: PathBuf,
    },
    /// Evaluate a local capability against a workspace profile.
    Evaluate {
        #[arg(long, default_value = "developer-standard")]
        profile: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        action: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Create a reusable semantic-enforcement session.
    Start {
        #[arg(long, default_value = "developer-standard")]
        profile: String,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show one session and its normalized event timeline.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show durable blast-radius counters for one session.
    Budget {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Seal a reusable semantic-enforcement session.
    Close {
        id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum FsCommand {
    /// Read a workspace file through policy and budget enforcement.
    Read { session: String, path: String },
    /// Atomically write standard input to a workspace file through the broker.
    Write { session: String, path: String },
    /// Remove a workspace file through policy, budget, and a restorable preimage.
    ///
    /// Regular files only. Undo with `vigil rollback`.
    Delete { session: String, path: String },
    /// Move a workspace file. Both paths are authorized; one refusal refuses the rename.
    Rename {
        session: String,
        from: String,
        to: String,
    },
    /// List a workspace directory through policy and budget.
    List { session: String, path: String },
}

#[derive(Subcommand)]
enum ProcessCommand {
    /// Execute an absolute program path without shell interpretation.
    Exec {
        session: String,
        /// Absolute executable path. PATH lookup is deliberately unsupported.
        #[arg(long)]
        program: PathBuf,
        /// Working directory; defaults to the session workspace and must remain inside it.
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Allowlisted environment assignment (`KEY=VALUE`). Repeatable.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        environment: Vec<String>,
        /// Direct-child timeout in milliseconds, capped at 30000.
        #[arg(long, default_value_t = 5_000)]
        timeout_ms: u64,
        /// Execute without returning child output. Required when stdout is a terminal.
        #[arg(long)]
        discard_output: bool,
        /// Structured arguments, following `--`. No shell parsing is performed.
        #[arg(last = true)]
        arguments: Vec<String>,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// Open and immediately close a payload-free TCP connection.
    Probe {
        session: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 3_000)]
        timeout_ms: u64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ApprovalsCommand {
    /// List approval requests, newest first.
    List {
        #[arg(long)]
        session: Option<String>,
        /// Narrow to `pending`, `granted` or `denied`.
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show one approval request in full, so a decision is made on the facts.
    Show {
        approval_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Grant one approval, minting a lease bound to its exact action and resource.
    Grant {
        approval_id: String,
        /// Identity of the human making this decision. Recorded on the approval.
        #[arg(long)]
        approver: String,
        /// How many times the resulting lease may be used.
        #[arg(long, default_value_t = 1)]
        max_uses: u32,
        /// Lease lifetime in seconds. A longer request is refused, never clamped.
        #[arg(long, default_value_t = vigil_local::DEFAULT_LEASE_TTL_SECONDS)]
        ttl_seconds: i64,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Refuse one approval. Asking again afterwards is recorded as boundary probing.
    Deny {
        approval_id: String,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GitCommand {
    /// Working-tree status.
    Status { session: String },
    /// Recent history.
    Log {
        session: String,
        #[arg(long, default_value_t = 20)]
        max_count: u32,
    },
    /// Unstaged, or with `--staged`, staged changes.
    Diff {
        session: String,
        #[arg(long)]
        staged: bool,
    },
    /// Stage paths. No path may begin with `-` or contain `..`.
    Stage {
        session: String,
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Record a commit. Hooks do not run.
    Commit {
        session: String,
        #[arg(long)]
        message: String,
    },
    /// Push a branch. Needs a scoped approval, and the remote host must pass network policy.
    Push {
        session: String,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        branch: String,
    },
}

#[derive(Subcommand)]
enum CanaryCommand {
    /// Place a synthetic asset inside a session's workspace.
    ///
    /// Refused outside the workspace and in every protected location: deception must never
    /// contaminate the credential directories whose integrity matters most.
    Place {
        session: String,
        /// One of cloud-credentials, ssh-key, api-token, environment-file.
        #[arg(long)]
        kind: String,
        /// Filename inside the workspace. Defaults to something plausible for the kind.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List a session's canaries.
    List {
        session: String,
        #[arg(long)]
        json: bool,
    },
    /// Remove a canary from disk, so bait does not outlive the session that placed it.
    Remove { canary_id: String },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Register an MCP server, recording the binary behind it.
    ///
    /// Recording the hash is what lets a later substitution be noticed; without it, "the same
    /// server" means only "the same name", which an attacker controls.
    Register {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "stdio")]
        transport: String,
        #[arg(long)]
        executable: Option<PathBuf>,
        /// Observed SHA-256 when no local executable is available. A local executable is
        /// always hashed directly and this value is ignored.
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List registered MCP servers.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show the tools a server has presented.
    Tools {
        server: String,
        #[arg(long)]
        json: bool,
    },
    /// Compare a server's current tools against what is on record.
    Sync {
        server: String,
        /// JSON file holding the tool manifests the server currently presents.
        #[arg(long)]
        manifest: PathBuf,
        /// Observed SHA-256 of the executable, to detect substitution.
        #[arg(long)]
        sha256: Option<String>,
        /// Record any drift as detections against this session.
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Authorize one MCP tool call without performing it.
    Authorize {
        session: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        tool: String,
        /// The call's arguments as a JSON object.
        #[arg(long, default_value = "{}")]
        arguments: String,
        #[arg(long)]
        json: bool,
    },
    /// Stand between an agent and an MCP server, authorizing each tool call.
    ///
    /// Speaks the newline-delimited JSON-RPC stdio transport. A refused call never reaches the
    /// server and the agent gets a JSON-RPC error rather than a hang. An agent that talks to
    /// the server directly is still unmediated.
    Proxy {
        session: String,
        #[arg(long)]
        server: String,
        /// The MCP server command, following `--`. Its first element must be the exact
        /// executable registered for this server; arguments may follow it.
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// Refuse every call to a server until it is released.
    Quarantine {
        server: String,
        /// Return the server to service.
        #[arg(long)]
        release: bool,
    },
}

#[derive(Subcommand)]
enum IncidentsCommand {
    /// List incidents, newest first.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show one incident as a readable timeline over its underlying evidence.
    Show {
        incident_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Write a self-contained evidence bundle for one incident.
    ///
    /// Metadata only: hashes, decisions, and counts. No file contents are collected.
    Export {
        incident_id: String,
        /// Destination file. Defaults to `<incident-id>.vigilincident` in the current directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Seal an incident, freezing it as investigated.
    Seal {
        incident_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RemitCommand {
    Validate {
        #[arg(default_value = "policies/remits")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ManifestCommand {
    Validate {
        #[arg(default_value = "policies/tools/manifests.yaml")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify an exported audit bundle against trusted checkpoint keys.
    Verify {
        /// Path to a JSON audit bundle.
        bundle: PathBuf,
        /// Trusted checkpoint key as `key_id=hex`. Repeatable.
        #[arg(long = "key", value_name = "KEY_ID=HEX")]
        keys: Vec<String>,
    },
    /// Recompute the local event chain and report the first record that disagrees.
    ///
    /// Without `--key` this makes an edit evident but not a rewrite: anything that can write
    /// the database can recompute every link. Pass the public half of the checkpoint key to
    /// hold the chain against its signed commitments as well.
    VerifyLocal {
        #[arg(long)]
        json: bool,
        /// Trusted checkpoint key as `key_id=hex`. Repeatable.
        #[arg(long = "key", value_name = "KEY_ID=HEX")]
        keys: Vec<String>,
    },
    /// Sign the current local chain head, pinning everything at or before it.
    ///
    /// A checkpoint is what makes a wholesale rewrite detectable: without the signing key an
    /// attacker cannot produce one that matches their rewritten history. Take one on a
    /// schedule; each covers everything up to the moment it was taken.
    Checkpoint {
        /// File holding the 32-byte hex seed, as written by `vigil keys generate`.
        /// Defaults to the `VIGIL_AUDIT_KEY` environment variable.
        #[arg(long)]
        seed: Option<PathBuf>,
        /// Identifier recorded in the checkpoint, so a verifier knows which key to use.
        #[arg(long, default_value = "local")]
        key_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Generate the three distinct signing seeds a Core needs.
    Generate {
        /// Directory to write `capability.key`, `approval.key` and `audit.key` into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Print the public key for a seed.
    ///
    /// This is how a Gateway is configured to trust a Core without ever being given the
    /// private seed — which is the whole point of the two holding different key material.
    Public {
        /// Path to a file containing a hex-encoded 32-byte seed.
        seed: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vigil: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> vigil_common::Result<()> {
    let state_db = cli.state_db;
    match cli.command {
        Command::Status { json } => local_status(state_db.as_deref(), json),
        Command::Run {
            profile,
            workspace,
            task,
            command,
        } => run_local_session(
            state_db.as_deref(),
            &profile,
            &workspace,
            task.as_deref(),
            &command,
        ),
        Command::Sessions { limit, json } => list_local_sessions(state_db.as_deref(), limit, json),
        Command::Session(SessionCommand::Start {
            profile,
            workspace,
            task,
            json,
        }) => start_semantic_session(
            state_db.as_deref(),
            &profile,
            &workspace,
            task.as_deref(),
            json,
        ),
        Command::Session(SessionCommand::Show { id, json }) => {
            show_local_session(state_db.as_deref(), &id, json)
        }
        Command::Session(SessionCommand::Budget { id, json }) => {
            show_local_budget(state_db.as_deref(), &id, json)
        }
        Command::Session(SessionCommand::Close { id, json }) => {
            close_semantic_session(state_db.as_deref(), &id, json)
        }
        Command::Fs(FsCommand::Read { session, path }) => {
            broker_file_read(state_db.as_deref(), &session, &path)
        }
        Command::Fs(FsCommand::Write { session, path }) => {
            broker_file_write(state_db.as_deref(), &session, &path)
        }
        Command::Fs(FsCommand::Delete { session, path }) => {
            broker_file_delete(state_db.as_deref(), &session, &path)
        }
        Command::Fs(FsCommand::Rename { session, from, to }) => {
            broker_file_rename(state_db.as_deref(), &session, &from, &to)
        }
        Command::Fs(FsCommand::List { session, path }) => {
            broker_file_list(state_db.as_deref(), &session, &path)
        }
        Command::Process(ProcessCommand::Exec {
            session,
            program,
            cwd,
            environment,
            timeout_ms,
            discard_output,
            arguments,
        }) => broker_process_execute(
            state_db.as_deref(),
            &session,
            program,
            cwd,
            &environment,
            timeout_ms,
            discard_output,
            arguments,
        ),
        Command::Network(NetworkCommand::Probe {
            session,
            host,
            port,
            timeout_ms,
            json,
        }) => broker_network_probe(state_db.as_deref(), &session, host, port, timeout_ms, json),
        Command::Approvals(ApprovalsCommand::List {
            session,
            status,
            limit,
            json,
        }) => list_approvals(
            state_db.as_deref(),
            session.as_deref(),
            status.as_deref(),
            limit,
            json,
        ),
        Command::Approvals(ApprovalsCommand::Show { approval_id, json }) => {
            show_approval(state_db.as_deref(), &approval_id, json)
        }
        Command::Approvals(ApprovalsCommand::Grant {
            approval_id,
            approver,
            max_uses,
            ttl_seconds,
            note,
            json,
        }) => grant_approval(
            state_db.as_deref(),
            &approval_id,
            &approver,
            max_uses,
            ttl_seconds,
            note.as_deref(),
            json,
        ),
        Command::Approvals(ApprovalsCommand::Deny {
            approval_id,
            approver,
            note,
            json,
        }) => deny_approval(
            state_db.as_deref(),
            &approval_id,
            &approver,
            note.as_deref(),
            json,
        ),
        Command::Capabilities { session, json } => {
            show_capabilities(state_db.as_deref(), &session, json)
        }
        Command::Risk { session, json } => show_risk(state_db.as_deref(), &session, json),
        Command::Processes { session, json } => show_processes(state_db.as_deref(), &session, json),
        Command::Events {
            session,
            limit,
            json,
        } => show_events(state_db.as_deref(), &session, limit, json),
        Command::Mcp(McpCommand::Register {
            name,
            transport,
            executable,
            sha256,
            version,
            json,
        }) => register_mcp_server(
            state_db.as_deref(),
            &name,
            &transport,
            executable.as_deref(),
            sha256.as_deref(),
            version.as_deref(),
            json,
        ),
        Command::Mcp(McpCommand::List { json }) => list_mcp_servers(state_db.as_deref(), json),
        Command::Mcp(McpCommand::Tools { server, json }) => {
            list_mcp_tools(state_db.as_deref(), &server, json)
        }
        Command::Mcp(McpCommand::Sync {
            server,
            manifest,
            sha256,
            session,
            json,
        }) => sync_mcp_server(
            state_db.as_deref(),
            &server,
            &manifest,
            sha256.as_deref(),
            session.as_deref(),
            json,
        ),
        Command::Mcp(McpCommand::Authorize {
            session,
            server,
            tool,
            arguments,
            json,
        }) => authorize_mcp_call(
            state_db.as_deref(),
            &session,
            &server,
            &tool,
            &arguments,
            json,
        ),
        Command::Mcp(McpCommand::Proxy {
            session,
            server,
            command,
        }) => proxy_mcp_server(state_db.as_deref(), &session, &server, &command),
        Command::Mcp(McpCommand::Quarantine { server, release }) => {
            quarantine_mcp_server(state_db.as_deref(), &server, !release)
        }
        Command::Reconcile {
            session,
            observed,
            json,
        } => reconcile_session(state_db.as_deref(), &session, observed.as_deref(), json),
        Command::Rollback {
            session,
            path,
            dry_run,
            json,
        } => rollback_session(
            state_db.as_deref(),
            &session,
            path.as_deref(),
            dry_run,
            json,
        ),
        Command::Canary(CanaryCommand::Place {
            session,
            kind,
            name,
            json,
        }) => place_canary(state_db.as_deref(), &session, &kind, name.as_deref(), json),
        Command::Canary(CanaryCommand::List { session, json }) => {
            list_canaries(state_db.as_deref(), &session, json)
        }
        Command::Canary(CanaryCommand::Remove { canary_id }) => {
            remove_canary(state_db.as_deref(), &canary_id)
        }
        Command::Git(command) => run_git(state_db.as_deref(), command),
        Command::Analyze { session, json } => analyze_session(state_db.as_deref(), &session, json),
        Command::Detections {
            session,
            limit,
            json,
        } => show_detections(state_db.as_deref(), session.as_deref(), limit, json),
        Command::Incidents(IncidentsCommand::List { limit, json }) => {
            list_incidents(state_db.as_deref(), limit, json)
        }
        Command::Incidents(IncidentsCommand::Show { incident_id, json }) => {
            show_incident(state_db.as_deref(), &incident_id, json)
        }
        Command::Incidents(IncidentsCommand::Export { incident_id, out }) => {
            export_incident(state_db.as_deref(), &incident_id, out.as_deref())
        }
        Command::Incidents(IncidentsCommand::Seal { incident_id, json }) => {
            seal_incident(state_db.as_deref(), &incident_id, json)
        }
        Command::Contain {
            session,
            quarantine,
            seal,
            json,
        } => contain_session(state_db.as_deref(), &session, quarantine, seal, json),
        Command::Simulate {
            profile,
            workspace,
            action,
            resource,
            json,
        } => simulate_local_action(
            state_db.as_deref(),
            &profile,
            &workspace,
            &action,
            &resource,
            json,
        ),
        Command::Policy(PolicyCommand::Validate { dir }) => validate_policies(&dir),
        Command::Policy(PolicyCommand::List { dir }) => list_policies(&dir),
        Command::Policy(PolicyCommand::Evaluate {
            profile,
            workspace,
            action,
            resource,
            json,
        }) => evaluate_local_policy(&profile, &workspace, &action, &resource, json),
        Command::Remit(RemitCommand::Validate { dir }) => validate_remits(&dir),
        Command::Manifest(ManifestCommand::Validate { file }) => validate_manifests(&file),
        Command::Audit(AuditCommand::Verify { bundle, keys }) => verify_audit(&bundle, &keys),
        Command::Audit(AuditCommand::VerifyLocal { json, keys }) => {
            verify_local_chain(state_db.as_deref(), json, &keys)
        }
        Command::Audit(AuditCommand::Checkpoint { seed, key_id, json }) => {
            checkpoint_local_chain(state_db.as_deref(), seed.as_deref(), &key_id, json)
        }
        Command::Keys(KeysCommand::Generate { out }) => generate_keys(&out),
        Command::Keys(KeysCommand::Public { seed }) => print_public_key(&seed),
        Command::Doctor { policy_dir } => doctor(&policy_dir, state_db.as_deref()),
    }
}

fn default_state_database() -> vigil_common::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            vigil_common::VigilError::Config("HOME is not an absolute path".to_string())
        })?;
    Ok(home.join("Library/Application Support/VIGIL/vigil.db"))
}

fn local_store(path: Option<&Path>) -> vigil_common::Result<vigil_local::LocalStore> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => default_state_database()?,
    };
    vigil_local::LocalStore::open(&path)
}

fn start_semantic_session(
    state_db: Option<&Path>,
    profile: &str,
    workspace: &Path,
    task: Option<&str>,
    json: bool,
) -> vigil_common::Result<()> {
    use std::str::FromStr;
    let profile = vigil_local::LocalProfile::from_str(profile)?;
    let workspace = vigil_local::normalize_workspace(workspace)?;
    let store = local_store(state_db)?;
    let session = store.create_session(&vigil_local::NewSession {
        profile: profile.as_str().to_string(),
        workspace: workspace.clone(),
        executable: "vigil-semantic-brokers".to_string(),
        argv: vec!["vigil-semantic-brokers".to_string()],
        task: task.map(str::to_string),
        enforcement_posture: "semantic_enforced".to_string(),
    })?;
    store.activate_semantic_session(&session.id)?;
    let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
    store.append_event(
        &session.id,
        "session",
        "session.start",
        Some("SEMANTIC_ENFORCEMENT"),
        &correlation_id,
        &serde_json::json!({
            "profile": profile.as_str(),
            "workspace": workspace,
            "semantic_brokers": ["filesystem", "process", "network_probe"],
            "secret_broker": "interface_and_simulator_only",
            "os_enforcement": false,
        }),
    )?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "session_id": session.id,
                "profile": profile.as_str(),
                "workspace": workspace,
                "posture": "SEMANTIC ENFORCEMENT",
                "os_enforcement": false,
            }))?
        );
    } else {
        println!("Session       {}", session.id);
        println!("Profile       {}", profile.as_str());
        println!("Workspace     {}", workspace.display());
        println!("Posture       SEMANTIC ENFORCEMENT");
        println!("OS boundary   OBSERVE ONLY");
        println!();
        println!("Use `vigil fs`, `vigil process exec`, and `vigil network probe` with this ID.");
    }
    Ok(())
}

fn show_local_budget(
    state_db: Option<&Path>,
    session_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let counters = local_store(state_db)?.budget_snapshot(session_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&counters)?);
        return Ok(());
    }
    println!(
        "{:<26} {:>12} {:>12} {:>12} {:>12}",
        "DIMENSION", "LIMIT", "CONSUMED", "RESERVED", "REMAINING"
    );
    for counter in counters {
        println!(
            "{:<26} {:>12} {:>12} {:>12} {:>12}",
            counter.dimension.as_str(),
            counter.limit,
            counter.consumed,
            counter.reserved,
            counter.remaining
        );
    }
    Ok(())
}

fn close_semantic_session(
    state_db: Option<&Path>,
    session_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let session = store
        .get_session(session_id)?
        .ok_or_else(|| vigil_common::VigilError::NotFound("local session".to_string()))?;
    if session.enforcement_posture != "semantic_enforced"
        || session.status != vigil_local::SessionStatus::Running
    {
        return Err(vigil_common::VigilError::InvalidRequest(
            "only a running semantic-enforced session can be closed".to_string(),
        ));
    }
    let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
    store.append_event(
        session_id,
        "session",
        "session.end",
        None,
        &correlation_id,
        &serde_json::json!({"reason": "operator_close"}),
    )?;
    store.finish_session(session_id, Some(0))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "session_id": session_id,
                "status": "completed",
            }))?
        );
    } else {
        println!("Session {session_id} sealed successfully.");
    }
    Ok(())
}

fn list_approvals(
    state_db: Option<&Path>,
    session_id: Option<&str>,
    status: Option<&str>,
    limit: usize,
    json: bool,
) -> vigil_common::Result<()> {
    let status = status.map(parse_approval_status).transpose()?;
    let approvals = local_store(state_db)?.list_approvals(session_id, status, limit)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&approvals)?);
        return Ok(());
    }
    if approvals.is_empty() {
        println!("No approval requests recorded.");
        return Ok(());
    }
    println!(
        "{:<40} {:<26} {:<10} {:<16} RESOURCE",
        "APPROVAL", "SESSION", "STATUS", "ACTION"
    );
    for approval in approvals {
        println!(
            "{:<40} {:<26} {:<10} {:<16} {}",
            approval.approval_id,
            approval.session_id,
            approval.status.as_str(),
            approval.action.as_str(),
            approval.resolved_resource,
        );
    }
    Ok(())
}

fn parse_approval_status(value: &str) -> vigil_common::Result<vigil_local::ApprovalStatus> {
    match value {
        "pending" => Ok(vigil_local::ApprovalStatus::Pending),
        "granted" => Ok(vigil_local::ApprovalStatus::Granted),
        "denied" => Ok(vigil_local::ApprovalStatus::Denied),
        other => Err(vigil_common::VigilError::InvalidValue {
            field: "status",
            reason: format!(
                "unknown approval status `{other}`; expected pending, granted or denied"
            ),
        }),
    }
}

fn load_approval(
    store: &vigil_local::LocalStore,
    approval_id: &str,
) -> vigil_common::Result<vigil_local::ApprovalRequest> {
    store
        .get_approval(approval_id)?
        .ok_or_else(|| vigil_common::VigilError::NotFound(format!("approval {approval_id}")))
}

/// Render everything a human needs to decide, without making them read raw events.
fn show_approval(
    state_db: Option<&Path>,
    approval_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let approval = load_approval(&store, approval_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&approval)?);
        return Ok(());
    }
    let session = store.get_session(&approval.session_id)?;
    let now = chrono::Utc::now();
    println!("Approval          {}", approval.approval_id);
    println!("Session           {}", approval.session_id);
    if let Some(session) = &session {
        println!("Profile           {}", session.profile);
        println!("Workspace         {}", session.workspace);
        if let Some(task) = &session.task {
            println!("Task              {task}");
        }
    }
    println!("Requested action  {}", approval.action.as_str());
    println!("Requested target  {}", approval.requested_resource);
    println!("Resolved target   {}", approval.resolved_resource);
    println!("Triggered by      {}", approval.determining_policy);
    println!("Reason            {}", approval.reason);
    println!(
        "Risk at request   {}",
        approval.risk_state_at_request.as_str()
    );
    println!("Status            {}", approval.status.as_str());
    println!(
        "Expires           {} ({})",
        approval.expires_at.to_rfc3339(),
        if approval.is_actionable(now) {
            "actionable"
        } else if approval.status == vigil_local::ApprovalStatus::Pending {
            "expired; the session must ask again"
        } else {
            "already decided"
        }
    );
    if let Some(decided_by) = &approval.decided_by {
        println!("Decided by        {decided_by}");
    }
    if let Some(note) = &approval.note {
        println!("Note              {note}");
    }
    if let Some(lease_id) = &approval.lease_id {
        println!("Lease             {lease_id}");
    }
    println!();
    println!(
        "Granting authorizes exactly this action on exactly this resolved target, for the \
         uses and lifetime you choose. It grants nothing else."
    );
    Ok(())
}

fn grant_approval(
    state_db: Option<&Path>,
    approval_id: &str,
    approver: &str,
    max_uses: u32,
    ttl_seconds: i64,
    note: Option<&str>,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let approver = vigil_local::ApproverIdentity::from_cli_operator(approver)?;
    // Monotone: a backwards clock must not make an expired approval grantable again.
    let now = store.observe_now()?.now;
    let lease = store.grant_approval(approval_id, &approver, max_uses, ttl_seconds, note, now)?;
    let approval = load_approval(&store, approval_id)?;
    store.append_event(
        &lease.session_id,
        "approval",
        "approval.granted",
        Some("GRANTED"),
        approval_id,
        &serde_json::json!({
            "approval_id": approval_id,
            "lease_id": lease.lease_id,
            "action": lease.action.as_str(),
            "resolved_resource": lease.resource,
            "max_uses": lease.max_uses,
            "expires_at": lease.expires_at.to_rfc3339(),
            "approver": approver.as_str(),
            "determining_policy": approval.determining_policy,
        }),
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&lease)?);
        return Ok(());
    }
    println!("Approval {approval_id} granted.");
    println!("  lease       {}", lease.lease_id);
    println!("  action      {}", lease.action.as_str());
    println!("  resource    {}", lease.resource);
    println!("  uses        {}", lease.max_uses);
    println!("  expires     {}", lease.expires_at.to_rfc3339());
    Ok(())
}

fn deny_approval(
    state_db: Option<&Path>,
    approval_id: &str,
    approver: &str,
    note: Option<&str>,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let approver = vigil_local::ApproverIdentity::from_cli_operator(approver)?;
    let now = store.observe_now()?.now;
    let approval = store.deny_approval(approval_id, &approver, note, now)?;
    store.append_event(
        &approval.session_id,
        "approval",
        "approval.denied",
        Some("DENY"),
        approval_id,
        &serde_json::json!({
            "approval_id": approval_id,
            "action": approval.action.as_str(),
            "resolved_resource": approval.resolved_resource,
            "approver": approver.as_str(),
            "determining_policy": approval.determining_policy,
        }),
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&approval)?);
        return Ok(());
    }
    println!("Approval {approval_id} denied.");
    println!("A further identical request from this session is recorded as boundary probing.");
    Ok(())
}

fn show_capabilities(
    state_db: Option<&Path>,
    session_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let leases = local_store(state_db)?.leases_for_session(session_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&leases)?);
        return Ok(());
    }
    if leases.is_empty() {
        println!("Session {session_id} holds no capability leases.");
        println!("A session starts with none; every lease comes from a granted approval.");
        return Ok(());
    }
    let now = chrono::Utc::now();
    println!(
        "{:<40} {:<16} {:<10} {:<7} {:<26} RESOURCE",
        "LEASE", "ACTION", "STATE", "USES", "EXPIRES"
    );
    for lease in leases {
        // An expired lease is inert whatever its stored status says, so report what it can
        // actually do rather than what the column happens to hold.
        let state = if lease.is_usable(now) {
            lease.status.as_str()
        } else if lease.status == vigil_local::LeaseState::Active {
            "expired"
        } else {
            lease.status.as_str()
        };
        println!(
            "{:<40} {:<16} {:<10} {:<7} {:<26} {}",
            lease.lease_id,
            lease.action.as_str(),
            state,
            format!("{}/{}", lease.uses_remaining, lease.max_uses),
            lease.expires_at.to_rfc3339(),
            lease.resource,
        );
    }
    Ok(())
}

fn show_risk(state_db: Option<&Path>, session_id: &str, json: bool) -> vigil_common::Result<()> {
    let assessment = local_store(state_db)?.risk_assessment(session_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&assessment)?);
        return Ok(());
    }
    println!("Risk state        {}", assessment.state.as_str());
    println!();
    if assessment.dimensions.is_empty() {
        println!("No risk signals recorded.");
    } else {
        println!("{:<28} {:>6}", "DIMENSION", "SCORE");
        for dimension in &assessment.dimensions {
            println!(
                "{:<28} {:>6}",
                dimension.dimension.as_str(),
                dimension.score
            );
        }
    }
    if !assessment.transitions.is_empty() {
        println!();
        println!("Transitions");
        for transition in &assessment.transitions {
            println!(
                "  {}  {} -> {}",
                transition.at.to_rfc3339(),
                transition.previous_state.as_str(),
                transition.new_state.as_str(),
            );
        }
    }
    Ok(())
}

fn show_processes(
    state_db: Option<&Path>,
    session_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let graph = local_store(state_db)?.process_graph(session_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&graph)?);
        return Ok(());
    }
    if graph.nodes.is_empty() {
        println!("No processes recorded for session {session_id}.");
        return Ok(());
    }
    println!(
        "{:<40} {:<8} {:<5} {:<12} EXECUTABLE",
        "NODE", "PID", "GEN", "STATUS"
    );
    for node in &graph.nodes {
        println!(
            "{:<40} {:<8} {:<5} {:<12} {}",
            node.node_id,
            node.pid,
            node.generation,
            node.status.as_str(),
            node.executable,
        );
    }
    println!();
    println!(
        "This records what VIGIL launched. It does not observe grandchildren or any process \
         VIGIL did not start, so an absence here is not evidence of absence."
    );
    Ok(())
}

fn show_events(
    state_db: Option<&Path>,
    session_id: &str,
    limit: usize,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    if store.get_session(session_id)?.is_none() {
        return Err(vigil_common::VigilError::NotFound(format!(
            "local session {session_id}"
        )));
    }
    let mut events = store.events_for_session(session_id)?;
    if events.len() > limit {
        // Keep the most recent, which is what an operator following an incident wants.
        events.drain(..events.len() - limit);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }
    if events.is_empty() {
        println!("No events recorded for session {session_id}.");
        return Ok(());
    }
    println!(
        "{:<8} {:<26} {:<12} {:<26} DECISION",
        "SEQ", "TIMESTAMP", "CATEGORY", "ACTION"
    );
    for event in events {
        println!(
            "{:<8} {:<26} {:<12} {:<26} {}",
            event.sequence,
            event.timestamp.to_rfc3339(),
            event.category,
            event.action,
            event.decision.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

/// Hash an executable so a later substitution is detectable.
fn hash_executable(path: &Path) -> vigil_common::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(vigil_common::ContentHash::sha256(&bytes).to_string())
}

#[allow(clippy::too_many_arguments)]
fn register_mcp_server(
    state_db: Option<&Path>,
    name: &str,
    transport: &str,
    executable: Option<&Path>,
    sha256: Option<&str>,
    version: Option<&str>,
    json: bool,
) -> vigil_common::Result<()> {
    use std::str::FromStr;
    let transport = vigil_local::McpTransport::from_str(transport)?;
    // Prefer a hash computed here over one the caller asserts: a supplied hash is a claim,
    // and the whole point of recording it is to have something the caller did not choose.
    let computed = match executable {
        Some(path) => Some(hash_executable(path)?),
        None => sha256.map(str::to_string),
    };
    let server = local_store(state_db)?.register_mcp_server(
        name,
        transport,
        executable.map(|path| path.display().to_string()).as_deref(),
        computed.as_deref(),
        version,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&server)?);
        return Ok(());
    }
    println!("Registered MCP server {}", server.name);
    println!("  id          {}", server.server_id);
    println!("  transport   {}", server.transport.as_str());
    if let Some(hash) = &server.executable_sha256 {
        println!("  binary      {hash}");
    } else {
        println!("  binary      (not recorded — substitution cannot be detected)");
    }
    Ok(())
}

fn list_mcp_servers(state_db: Option<&Path>, json: bool) -> vigil_common::Result<()> {
    let servers = local_store(state_db)?.list_mcp_servers()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&servers)?);
        return Ok(());
    }
    if servers.is_empty() {
        println!("No MCP servers registered.");
        return Ok(());
    }
    println!("{:<28} {:<10} {:<13} BINARY", "NAME", "TRANSPORT", "TRUST");
    for server in servers {
        println!(
            "{:<28} {:<10} {:<13} {}",
            server.name,
            server.transport.as_str(),
            server.trust_state.as_str(),
            server
                .executable_sha256
                .as_deref()
                .unwrap_or("(not recorded)"),
        );
    }
    Ok(())
}

fn list_mcp_tools(state_db: Option<&Path>, server: &str, json: bool) -> vigil_common::Result<()> {
    let tools = local_store(state_db)?.mcp_tools(server)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&tools)?);
        return Ok(());
    }
    if tools.is_empty() {
        println!("No tools recorded for `{server}`. Run `vigil mcp sync` to establish a baseline.");
        return Ok(());
    }
    println!("{:<32} {:<24} SCHEMA", "TOOL", "DECLARED CAPABILITIES");
    for tool in tools {
        let declared: Vec<_> = tool
            .declared_capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        println!(
            "{:<32} {:<24} {}",
            tool.tool_name,
            if declared.is_empty() {
                "(none declared)".to_string()
            } else {
                declared.join(",")
            },
            tool.schema_hash,
        );
    }
    Ok(())
}

fn sync_mcp_server(
    state_db: Option<&Path>,
    server: &str,
    manifest: &Path,
    sha256: Option<&str>,
    session: Option<&str>,
    json: bool,
) -> vigil_common::Result<()> {
    let manifests: Vec<vigil_local::McpToolManifest> =
        serde_json::from_slice(&std::fs::read(manifest)?)?;
    let store = local_store(state_db)?;
    let drift = store.sync_mcp_tools(server, sha256, &manifests)?;
    let risk = match session {
        Some(session) if !drift.is_empty() => {
            Some(store.record_mcp_drift(session, server, &drift)?)
        }
        _ => None,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "server": server,
                "tools_observed": manifests.len(),
                "drift": drift,
                "risk_state": risk.map(|state| state.as_str()),
            }))?
        );
        return Ok(());
    }
    if drift.is_empty() {
        println!(
            "{} tool(s) recorded for `{server}`. No drift.",
            manifests.len()
        );
        return Ok(());
    }
    println!("Drift on `{server}`:");
    for change in &drift {
        println!("  {}", serde_json::to_string(change)?);
    }
    if let Some(risk) = risk {
        println!();
        println!("Session risk is now {}.", risk.as_str());
    } else {
        println!();
        println!("Pass --session to record this drift as detections against a session.");
    }
    Ok(())
}

fn authorize_mcp_call(
    state_db: Option<&Path>,
    session: &str,
    server: &str,
    tool: &str,
    arguments: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let arguments: serde_json::Value = serde_json::from_str(arguments)?;
    let authorization = local_store(state_db)?.authorize_mcp_call(
        session,
        &vigil_local::McpToolCall {
            server_name: server,
            tool_name: tool,
            arguments: &arguments,
        },
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&authorization)?);
    } else {
        println!(
            "Decision: {}",
            if authorization.permitted {
                "ALLOW"
            } else {
                "DENY"
            }
        );
        println!("Reason:   {}", authorization.reason);
        println!("Risk:     {}", authorization.risk_state.as_str());
        if authorization.resources.is_empty() {
            println!();
            println!("No path or URL arguments were present in this call.");
        } else {
            println!();
            println!(
                "{:<22} {:<16} {:<18} RESOURCE",
                "ARGUMENT", "ACTION", "OUTCOME"
            );
            for resource in &authorization.resources {
                println!(
                    "{:<22} {:<16} {:<18} {}",
                    resource.argument,
                    resource.action.as_str(),
                    format!("{:?}", resource.outcome).to_uppercase(),
                    resource.requested,
                );
            }
        }
        if !authorization.scope_escapes.is_empty() {
            println!();
            println!("Outside what the tool declared:");
            for escape in &authorization.scope_escapes {
                println!("  {escape}");
            }
        }
    }
    if authorization.permitted {
        Ok(())
    } else {
        Err(vigil_common::VigilError::Unauthorized(authorization.reason))
    }
}

fn quarantine_mcp_server(
    state_db: Option<&Path>,
    server: &str,
    quarantined: bool,
) -> vigil_common::Result<()> {
    local_store(state_db)?.quarantine_mcp_server(server, quarantined)?;
    if quarantined {
        println!("MCP server `{server}` is quarantined; every call to it is refused.");
    } else {
        println!("MCP server `{server}` returned to service.");
    }
    Ok(())
}

/// Reconcile declared intent against observed execution.
///
/// The exit code is meaningful: non-zero when the two disagree, and also non-zero when there
/// was nothing watching, so a script cannot mistake an unobserved session for a clean one.
fn reconcile_session(
    state_db: Option<&Path>,
    session_id: &str,
    observed: Option<&Path>,
    json: bool,
) -> vigil_common::Result<()> {
    let observations: Vec<vigil_local::ObservedOperation> = match observed {
        Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
        None => Vec::new(),
    };
    let store = local_store(state_db)?;
    let (report, risk) = store.reconcile_session(session_id, &observations)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "report": report,
                "risk_state": risk.as_str(),
                "consistent": report.consistent(),
            }))?
        );
    } else {
        println!("Session       {session_id}");
        println!("Declared      {} intent(s)", report.declared.len());
        println!(
            "Observed      {} operation(s)",
            report.observations_considered
        );
        println!("Matched       {}", report.matched);
        println!("Mismatches    {}", report.mismatches.len());
        println!("Risk          {}", risk.as_str());
        println!();
        match report.coverage {
            vigil_local::Coverage::NoObserver => {
                println!("NO OBSERVER.");
                println!(
                    "No operations were supplied, so nothing was compared. This is not a \
                     clean result — it means nothing was watching. Endpoint Security is not \
                     installed, so VIGIL cannot observe execution on its own."
                );
            }
            vigil_local::Coverage::Observed if report.mismatches.is_empty() => {
                println!("CONSISTENT — every observed operation was declared.");
            }
            vigil_local::Coverage::Observed => {
                println!("MISMATCH");
                for mismatch in &report.mismatches {
                    println!();
                    println!("  {}", mismatch.class.as_str());
                    println!(
                        "    observed  {} {}",
                        mismatch.observed.kind.as_str(),
                        mismatch.observed.path
                    );
                    if let Some(declared) = &mismatch.declared {
                        println!("    declared  {} {}", declared.action, declared.resource);
                    }
                    println!("    {}", mismatch.explanation);
                }
            }
        }
    }
    if report.consistent() {
        Ok(())
    } else if report.coverage == vigil_local::Coverage::NoObserver {
        Err(vigil_common::VigilError::Unavailable {
            component: "endpoint_observer",
            reason: "no observed operations were supplied; execution was not verified".to_string(),
        })
    } else {
        Err(vigil_common::VigilError::AuditIntegrity(format!(
            "{} observed operation(s) did not match what the session declared",
            report.mismatches.len()
        )))
    }
}

fn rollback_session(
    state_db: Option<&Path>,
    session_id: &str,
    path: Option<&str>,
    dry_run: bool,
    json: bool,
) -> vigil_common::Result<()> {
    let report = local_store(state_db)?.rollback_session(session_id, path, dry_run)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        if dry_run {
            println!("Dry run — nothing was changed.");
            println!();
        }
        println!("Considered  {}", report.considered);
        println!("Restored    {}", report.restored);
        println!("Removed     {}", report.removed);
        println!("Refused     {}", report.refused);
        if !report.outcomes.is_empty() {
            println!();
            for outcome in &report.outcomes {
                match outcome {
                    vigil_local::RestoreOutcome::Restored { resource } => {
                        println!("  restored      {resource}")
                    }
                    vigil_local::RestoreOutcome::Removed { resource } => {
                        println!("  removed       {resource}")
                    }
                    vigil_local::RestoreOutcome::WouldRestore { resource } => {
                        println!("  would restore {resource}")
                    }
                    vigil_local::RestoreOutcome::Refused { resource, reason } => {
                        println!("  REFUSED       {resource}");
                        println!("                {reason}");
                    }
                }
            }
        }
        println!();
        println!("{}", report.coverage_note);
    }
    // A refusal is not a failure of the command — it is the command declining to clobber
    // something — but it must not read as a clean success either.
    if report.refused == 0 {
        Ok(())
    } else {
        Err(vigil_common::VigilError::InvalidRequest(format!(
            "{} change(s) could not be restored; see the reasons above",
            report.refused
        )))
    }
}

fn place_canary(
    state_db: Option<&Path>,
    session_id: &str,
    kind: &str,
    name: Option<&str>,
    json: bool,
) -> vigil_common::Result<()> {
    use std::str::FromStr;
    let kind = vigil_local::CanaryKind::from_str(kind)?;
    let canary = local_store(state_db)?.place_canary(session_id, kind, name)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&canary)?);
        return Ok(());
    }
    println!("Placed {} canary", canary.kind.as_str());
    println!("  id     {}", canary.canary_id);
    println!("  path   {}", canary.path);
    println!();
    println!(
        "Its contents are synthetic and marked `{}`. They authorize nothing anywhere.",
        vigil_local::CANARY_MARKER
    );
    Ok(())
}

fn list_canaries(
    state_db: Option<&Path>,
    session_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let canaries = local_store(state_db)?.canaries_for_session(session_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&canaries)?);
        return Ok(());
    }
    if canaries.is_empty() {
        println!("No canaries placed for session {session_id}.");
        return Ok(());
    }
    println!("{:<40} {:<20} {:<9} PATH", "CANARY", "KIND", "STATE");
    for canary in canaries {
        println!(
            "{:<40} {:<20} {:<9} {}",
            canary.canary_id,
            canary.kind.as_str(),
            if canary.removed_at.is_some() {
                "removed"
            } else {
                "live"
            },
            canary.path,
        );
    }
    Ok(())
}

fn remove_canary(state_db: Option<&Path>, canary_id: &str) -> vigil_common::Result<()> {
    local_store(state_db)?.remove_canary(canary_id)?;
    println!("Canary {canary_id} removed.");
    Ok(())
}

fn run_git(state_db: Option<&Path>, command: GitCommand) -> vigil_common::Result<()> {
    use vigil_local::GitRequest;
    let (session, request) = match command {
        GitCommand::Status { session } => (session, GitRequest::Status),
        GitCommand::Log { session, max_count } => (session, GitRequest::Log { max_count }),
        GitCommand::Diff { session, staged } => (session, GitRequest::Diff { staged }),
        GitCommand::Stage { session, paths } => (session, GitRequest::Stage { paths }),
        GitCommand::Commit { session, message } => (session, GitRequest::Commit { message }),
        GitCommand::Push {
            session,
            remote,
            branch,
        } => (session, GitRequest::Push { remote, branch }),
    };
    let store = local_store(state_db)?;
    let result = vigil_local::GitBroker::new(&store).run(&session, &request)?;

    if !result.neutralized_config.is_empty() {
        eprintln!(
            "vigil: this repository configures Git to run programs; VIGIL overrode them so \
             nothing executed."
        );
        for key in &result.neutralized_config {
            eprintln!("vigil:   {key}");
        }
    }
    print!("{}", result.stdout);
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    if result.truncated {
        eprintln!("vigil: output was truncated at the broker's bound.");
    }
    match result.exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(vigil_common::VigilError::Unavailable {
            component: "git",
            reason: format!("git exited with status {code}"),
        }),
        None => Err(vigil_common::VigilError::Unavailable {
            component: "git",
            reason: "git was terminated by a signal".to_string(),
        }),
    }
}

fn analyze_session(
    state_db: Option<&Path>,
    session_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let report = local_store(state_db)?.analyze_session(session_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("Session      {}", report.session_id);
    println!("Events       {}", report.events_considered);
    println!("Processes    {}", report.processes_considered);
    println!("Findings     {}", report.findings.len());
    if report.already_recorded > 0 {
        println!("Already known {}", report.already_recorded);
    }
    println!("Risk         {}", report.risk_state.as_str());
    println!();
    if report.findings.is_empty() && report.already_recorded == 0 {
        println!("No multi-event patterns found.");
        println!(
            "This looks only at what VIGIL recorded. A session that went around the brokers \
             leaves nothing here to analyze."
        );
        return Ok(());
    }
    for finding in &report.findings {
        println!("{}  {}", finding.rule_id, finding.name);
        for (index, step) in finding.steps.iter().enumerate() {
            println!("  {}. {step}", index + 1);
        }
        println!();
    }
    println!(
        "These are retrospective. Each step was individually permitted at the time, which is \
         why the shape is worth naming."
    );
    Ok(())
}

/// Stand between an agent and an MCP server.
///
/// Two pumps: the agent's stdin toward the server, authorizing every `tools/call` on the way,
/// and the server's stdout back toward the agent, capturing tool listings so drift is noticed
/// live rather than at the next manual sync.
fn proxy_mcp_server(
    state_db: Option<&Path>,
    session_id: &str,
    server: &str,
    command: &[OsString],
) -> vigil_common::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command as ChildCommand, Stdio};
    use vigil_local::{ClientIntent, ServerIntent};

    let store = local_store(state_db)?;
    if store.get_session(session_id)?.is_none() {
        return Err(vigil_common::VigilError::NotFound(format!(
            "local session {session_id}"
        )));
    }
    let program = command.first().ok_or_else(|| {
        vigil_common::VigilError::InvalidRequest("proxy requires a command after `--`".to_string())
    })?;
    let verified_program = store.verify_mcp_proxy_executable(server, Path::new(program))?;

    let mut child = ChildCommand::new(&verified_program)
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut to_server =
        child
            .stdin
            .take()
            .ok_or_else(|| vigil_common::VigilError::Unavailable {
                component: "mcp_proxy",
                reason: "the server's stdin was not created".to_string(),
            })?;
    let from_server = child
        .stdout
        .take()
        .ok_or_else(|| vigil_common::VigilError::Unavailable {
            component: "mcp_proxy",
            reason: "the server's stdout was not created".to_string(),
        })?;

    // Server-to-agent runs on its own thread so a chatty server cannot block the direction
    // that carries authorization decisions.
    let correlation = std::sync::Arc::new(vigil_local::McpProxyCorrelation::default());
    let listener = {
        let database = store.path().to_path_buf();
        let session = session_id.to_string();
        let server = server.to_string();
        let correlation = std::sync::Arc::clone(&correlation);
        std::thread::spawn(move || -> vigil_common::Result<()> {
            let store = vigil_local::LocalStore::open(&database)?;
            let mut stdout = std::io::stdout();
            for line in BufReader::new(from_server).lines() {
                let line = line?;
                if let ServerIntent::ToolListing { id, tools } =
                    vigil_local::inspect_server_message(&line)
                {
                    if correlation.consume_tool_list_response(&id) {
                        // Live drift: only a response to a tools/list request can update the
                        // observation. An unrelated result containing a `tools` member is data,
                        // not a tool-list protocol message.
                        if let Ok(drift) = store.sync_live_mcp_tools(&server, &tools) {
                            if !drift.is_empty() {
                                let _ = store.record_mcp_drift(&session, &server, &drift);
                                eprintln!(
                                    "vigil: `{server}` changed its tool set mid-session ({} change(s))",
                                    drift.len()
                                );
                            }
                        }
                    }
                }
                writeln!(stdout, "{line}")?;
                stdout.flush()?;
            }
            Ok(())
        })
    };

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        match vigil_local::inspect_client_message(&line) {
            ClientIntent::Forward => {
                writeln!(to_server, "{line}")?;
                to_server.flush()?;
            }
            ClientIntent::ToolListRequest { id } => {
                if !correlation.record_tool_list_request(&id) {
                    eprintln!(
                        "vigil: tools/list correlation capacity was exhausted; its response \
                         will not alter the trusted baseline"
                    );
                }
                writeln!(to_server, "{line}")?;
                to_server.flush()?;
            }
            ClientIntent::Malformed { reason } => {
                // Never forwarded on the hope it is harmless. There is no id to answer, so
                // the refusal goes to stderr where an operator sees it.
                eprintln!("vigil: refused an unusable MCP message: {reason}");
            }
            ClientIntent::ToolCall {
                id,
                server_tool,
                arguments,
            } => {
                let authorization = store.authorize_mcp_call(
                    session_id,
                    &vigil_local::McpToolCall {
                        server_name: server,
                        tool_name: &server_tool,
                        arguments: &arguments,
                    },
                )?;
                if authorization.permitted {
                    writeln!(to_server, "{line}")?;
                    to_server.flush()?;
                    continue;
                }
                eprintln!(
                    "vigil: refused `{server}`.`{server_tool}` — {}",
                    authorization.reason
                );
                match &id {
                    // A refused request gets an answer, so the agent does not hang waiting
                    // for one that will never arrive.
                    Some(id) => {
                        let response = vigil_local::refusal_response(id, &authorization.reason)?;
                        writeln!(stdout, "{response}")?;
                        stdout.flush()?;
                    }
                    // A notification expects no response and cannot be refused politely, so
                    // it is dropped. A tool call that does not want an answer is itself odd.
                    None => eprintln!(
                        "vigil: the refused call was a notification and was dropped silently"
                    ),
                }
            }
        }
    }

    // Closing the server's stdin is how it learns the agent is done.
    drop(to_server);
    let status = child.wait()?;
    let _ = listener.join();
    if status.success() {
        Ok(())
    } else {
        Err(vigil_common::VigilError::Unavailable {
            component: "mcp_server",
            reason: format!("the MCP server exited with status {status}"),
        })
    }
}

fn show_detections(
    state_db: Option<&Path>,
    session_id: Option<&str>,
    limit: usize,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let detections = match session_id {
        Some(session) => store.detections_for_session(session)?,
        None => store.list_detections(limit)?,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&detections)?);
        return Ok(());
    }
    if detections.is_empty() {
        println!("No detections recorded.");
        return Ok(());
    }
    println!(
        "{:<14} {:<10} {:<11} {:<26} {:<28} RESOURCE",
        "RULE", "SEVERITY", "CONFIDENCE", "TACTIC", "NAME"
    );
    for detection in detections {
        let resource = detection
            .evidence
            .get("resolved_resource")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        println!(
            "{:<14} {:<10} {:<11} {:<26} {:<28} {}",
            detection.rule_id,
            detection.severity.as_str(),
            detection.confidence.as_str(),
            detection.tactic,
            detection.name,
            resource,
        );
    }
    Ok(())
}

fn list_incidents(state_db: Option<&Path>, limit: usize, json: bool) -> vigil_common::Result<()> {
    let incidents = local_store(state_db)?.list_incidents(limit)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&incidents)?);
        return Ok(());
    }
    if incidents.is_empty() {
        println!("No incidents recorded.");
        return Ok(());
    }
    println!(
        "{:<40} {:<26} {:<10} {:<8} REASON",
        "INCIDENT", "SESSION", "SEVERITY", "STATUS"
    );
    for incident in incidents {
        println!(
            "{:<40} {:<26} {:<10} {:<8} {}",
            incident.incident_id,
            incident.session_id,
            incident.severity.as_str(),
            incident.status.as_str(),
            incident.reason,
        );
    }
    Ok(())
}

fn load_incident(
    store: &vigil_local::LocalStore,
    incident_id: &str,
) -> vigil_common::Result<vigil_local::Incident> {
    store
        .get_incident(incident_id)?
        .ok_or_else(|| vigil_common::VigilError::NotFound(format!("incident {incident_id}")))
}

/// Render an incident as a timeline.
///
/// Every line is backed by a stored record — an event, a detection, a risk transition, a
/// response — rather than being narrated prose. `--json` returns those records directly.
fn show_incident(
    state_db: Option<&Path>,
    incident_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let incident = load_incident(&store, incident_id)?;
    let detections = store.detections_for_session(&incident.session_id)?;
    let responses = store.responses_for_incident(incident_id)?;
    let assessment = store.risk_assessment(&incident.session_id)?;
    let events = store.events_for_session(&incident.session_id)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "incident": incident,
                "detections": detections,
                "responses": responses,
                "risk": assessment,
                "events": events,
            }))?
        );
        return Ok(());
    }

    println!("Incident      {}", incident.incident_id);
    println!("Session       {}", incident.session_id);
    println!("Severity      {}", incident.severity.as_str());
    println!("Status        {}", incident.status.as_str());
    println!("Reason        {}", incident.reason);
    println!("Risk now      {}", assessment.state.as_str());
    println!();
    println!("Timeline");

    // One ordered stream, so cause and effect read in the order they happened.
    let mut timeline: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
    timeline.push((
        incident.opened_at,
        format!("incident opened ({})", incident.severity.as_str()),
    ));
    for event in &events {
        timeline.push((
            event.timestamp,
            format!(
                "{} {} {}",
                event.category,
                event.action,
                event.decision.as_deref().unwrap_or("")
            )
            .trim_end()
            .to_string(),
        ));
    }
    for detection in &detections {
        timeline.push((
            detection.at,
            format!(
                "detection {} {} ({}/{})",
                detection.rule_id,
                detection.name,
                detection.severity.as_str(),
                detection.confidence.as_str()
            ),
        ));
    }
    for transition in &assessment.transitions {
        timeline.push((
            transition.at,
            format!(
                "risk {} -> {}",
                transition.previous_state.as_str(),
                transition.new_state.as_str()
            ),
        ));
    }
    for response in &responses {
        timeline.push((
            response.at,
            format!(
                "response {} ({})",
                response.action.as_str(),
                response.outcome.as_str()
            ),
        ));
    }
    if let Some(sealed_at) = incident.sealed_at {
        timeline.push((sealed_at, "incident sealed".to_string()));
    }
    timeline.sort_by(|left, right| left.0.cmp(&right.0));
    for (at, line) in timeline {
        println!("  {}  {line}", at.format("%H:%M:%S"));
    }
    Ok(())
}

/// Write a self-contained evidence bundle.
///
/// Metadata only: decisions, hashes, counts, and state transitions. No file content, argument
/// value, or secret material is collected, because collecting it would make the bundle itself
/// a thing worth stealing.
fn export_incident(
    state_db: Option<&Path>,
    incident_id: &str,
    out: Option<&Path>,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let incident = load_incident(&store, incident_id)?;
    let session = store
        .get_session(&incident.session_id)?
        .ok_or_else(|| vigil_common::VigilError::NotFound("local session".to_string()))?;
    let chain = store.verify_event_chain()?;

    let bundle = serde_json::json!({
        "format": "vigil.incident-bundle/v1",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "content_captured": false,
        "incident": incident,
        "session": session,
        "detections": store.detections_for_session(&incident.session_id)?,
        "responses": store.responses_for_incident(incident_id)?,
        "risk": store.risk_assessment(&incident.session_id)?,
        "capabilities": store.leases_for_session(&incident.session_id)?,
        "approvals": store.list_approvals(Some(&incident.session_id), None, 1000)?,
        "budget": store.budget_snapshot(&incident.session_id)?,
        "process_graph": store.process_graph(&incident.session_id)?,
        "events": store.events_for_session(&incident.session_id)?,
        "integrity": {
            "event_chain": chain,
            "ruleset_version": vigil_local::RULESET_VERSION,
        },
        "enforcement": {
            "os_enforcement": false,
            "note": "Semantic broker enforcement only. Endpoint Security and Network Extension \
                     are not installed, so a process that bypassed the brokers produced no \
                     records here.",
        },
    });

    let destination = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(format!("{incident_id}.vigilincident")));
    let rendered = serde_json::to_vec_pretty(&bundle)?;
    std::fs::write(&destination, &rendered)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))?;
    }
    println!(
        "Wrote {} ({} bytes).",
        destination.display(),
        rendered.len()
    );
    if !chain.verified {
        println!("WARNING: the event chain does not verify; see `integrity.event_chain`.");
    }
    Ok(())
}

fn seal_incident(
    state_db: Option<&Path>,
    incident_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let incident = local_store(state_db)?.seal_incident(incident_id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&incident)?);
    } else {
        println!("Incident {incident_id} sealed.");
    }
    Ok(())
}

/// Apply containment responses to a session.
///
/// Deliberately not named `kill`: nothing here terminates a process. Confirming that a PID
/// still belongs to the process VIGIL recorded needs an OS-verified process identity this
/// build does not have, and killing the wrong process is worse than not containing an agent.
fn contain_session(
    state_db: Option<&Path>,
    session_id: &str,
    quarantine: bool,
    seal: bool,
    json: bool,
) -> vigil_common::Result<()> {
    use vigil_local::ResponseAction;

    let store = local_store(state_db)?;
    if store.get_session(session_id)?.is_none() {
        return Err(vigil_common::VigilError::NotFound(format!(
            "local session {session_id}"
        )));
    }
    let incident = store.open_incident(
        session_id,
        vigil_local::Severity::High,
        "operator containment",
    )?;
    store.attach_detections(&incident.incident_id, session_id)?;

    let mut actions = vec![
        ResponseAction::RevokeCapabilities,
        if quarantine {
            ResponseAction::QuarantineSession
        } else {
            ResponseAction::RestrictSession
        },
    ];
    if seal {
        actions.push(ResponseAction::SealSession);
    }
    let mut applied = Vec::new();
    for action in actions {
        applied.push(store.apply_response(&incident.incident_id, action)?);
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "incident_id": incident.incident_id,
                "responses": applied,
                "process_termination": "not performed",
            }))?
        );
        return Ok(());
    }
    println!("Incident {}", incident.incident_id);
    for response in &applied {
        println!(
            "  {:<22} {}",
            response.action.as_str(),
            response.outcome.as_str()
        );
    }
    println!();
    println!(
        "No process was terminated. Containment withholds authority from brokered requests; a \
         process that bypasses the brokers is unaffected."
    );
    Ok(())
}

fn verify_local_chain(
    state_db: Option<&Path>,
    json: bool,
    keys: &[String],
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let checkpoints = store.checkpoints()?;

    let verification = if keys.is_empty() {
        store.verify_event_chain()?
    } else {
        let mut verifier = vigil_local::LocalCheckpointVerifier::new();
        for entry in keys {
            let (key_id, hex_key) = entry.split_once('=').ok_or_else(|| {
                vigil_common::VigilError::Config("--key must be given as key_id=hex".to_string())
            })?;
            let bytes: [u8; 32] = hex::decode(hex_key)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| {
                    vigil_common::VigilError::Config(
                        "checkpoint key must be 32 hex-encoded bytes".to_string(),
                    )
                })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                vigil_common::VigilError::Config("not a valid Ed25519 public key".to_string())
            })?;
            verifier = verifier.trust_key(key_id, key);
        }
        store.verify_event_chain_with_checkpoints(&verifier)?
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        if verification.verified {
            println!(
                "Event chain verified: {} event(s), head {}.",
                verification.events_checked,
                verification.head.as_deref().unwrap_or("(empty log)")
            );
        } else if let Some(failure) = &verification.failure {
            println!(
                "Event chain FAILED at sequence {}: {}",
                failure.at_sequence, failure.reason
            );
        }
        for (sequence, failure) in &verification.checkpoint_failures {
            println!("Checkpoint at sequence {sequence} FAILED: {failure}");
        }

        // Say plainly what this run did and did not establish. A chain that verifies against
        // no checkpoints is a weaker statement than one that verifies against a signed head,
        // and reporting them identically would overstate the first.
        if keys.is_empty() {
            println!();
            println!(
                "Checked links only. This makes an edit evident, not a rewrite: anything that \
                 can write the database can recompute every link."
            );
            if checkpoints.is_empty() {
                println!(
                    "No checkpoints have been taken. Run `vigil audit checkpoint` to pin the \
                     current head."
                );
            } else {
                println!(
                    "{} checkpoint(s) exist but were not checked. Pass --key key_id=hex to \
                     hold the chain against them.",
                    checkpoints.len()
                );
            }
        } else if verification.verified {
            println!();
            println!(
                "Checked {} event(s) against {} signed checkpoint(s). A rewrite would have to \
                 forge one to pass.",
                verification.events_checked, verification.checkpoints_checked
            );
        }
    }

    if verification.verified {
        Ok(())
    } else {
        Err(vigil_common::VigilError::AuditIntegrity(
            "the local event chain does not verify".to_string(),
        ))
    }
}

fn checkpoint_local_chain(
    state_db: Option<&Path>,
    seed_path: Option<&Path>,
    key_id: &str,
    json: bool,
) -> vigil_common::Result<()> {
    let raw = match seed_path {
        Some(path) => std::fs::read_to_string(path)?,
        None => std::env::var("VIGIL_AUDIT_KEY").map_err(|_| {
            vigil_common::VigilError::Config(
                "no signing seed: pass --seed <file> or set VIGIL_AUDIT_KEY".to_string(),
            )
        })?,
    };
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            vigil_common::VigilError::Config("seed must be 32 hex-encoded bytes".to_string())
        })?;
    let signer = vigil_local::LocalCheckpointSigner::from_seed(key_id, &bytes)?;

    let store = local_store(state_db)?;
    let checkpoint = store.write_checkpoint(&signer, chrono::Utc::now())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&checkpoint)?);
    } else {
        println!(
            "Checkpoint written at sequence {}, head {}.",
            checkpoint.sequence, checkpoint.head_hash
        );
        println!("Signed by key `{}`.", checkpoint.key_id);
        println!();
        println!(
            "Everything at or before sequence {} is now pinned. Verify with:",
            checkpoint.sequence
        );
        println!(
            "  vigil audit verify-local --key {}=<public hex>",
            checkpoint.key_id
        );
        println!();
        println!(
            "This holds only while the seed stays out of reach of whatever can write the \
             database. A seed sitting beside it on the same host raises the bar; it does not \
             close the door."
        );
    }
    Ok(())
}

fn broker_file_delete(
    state_db: Option<&Path>,
    session_id: &str,
    path: &str,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let result = vigil_local::FilesystemBroker::new(&store).delete(session_id, path)?;
    eprintln!(
        "vigil: removed {} ({} bytes, event {})",
        result.resolved_resource.display(),
        result.bytes,
        result.event_id
    );
    eprintln!("vigil: restore it with `vigil rollback {session_id}`");
    Ok(())
}

fn broker_file_rename(
    state_db: Option<&Path>,
    session_id: &str,
    from: &str,
    to: &str,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let result = vigil_local::FilesystemBroker::new(&store).rename(session_id, from, to)?;
    eprintln!(
        "vigil: moved to {} ({} bytes, event {})",
        result.resolved_resource.display(),
        result.bytes,
        result.event_id
    );
    eprintln!("vigil: undo it with `vigil rollback {session_id}`");
    Ok(())
}

fn broker_file_list(
    state_db: Option<&Path>,
    session_id: &str,
    path: &str,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let result = vigil_local::FilesystemBroker::new(&store).list(session_id, path)?;
    for entry in &result.value {
        println!("{entry}");
    }
    eprintln!(
        "vigil: listed {} ({} entries, event {})",
        result.resolved_resource.display(),
        result.value.len(),
        result.event_id
    );
    Ok(())
}

fn broker_file_read(
    state_db: Option<&Path>,
    session_id: &str,
    path: &str,
) -> vigil_common::Result<()> {
    if std::io::stdout().is_terminal() {
        return Err(vigil_common::VigilError::Config(
            "refusing to render untrusted file content to a terminal; pipe stdout to a file or process"
                .to_string(),
        ));
    }
    let store = local_store(state_db)?;
    let result = vigil_local::FilesystemBroker::new(&store).read(session_id, path)?;
    std::io::stdout().lock().write_all(&result.value)?;
    eprintln!(
        "vigil: brokered {} bytes from {} (event {})",
        result.bytes,
        result.resolved_resource.display(),
        result.event_id
    );
    Ok(())
}

fn broker_file_write(
    state_db: Option<&Path>,
    session_id: &str,
    path: &str,
) -> vigil_common::Result<()> {
    if std::io::stdin().is_terminal() {
        return Err(vigil_common::VigilError::Config(
            "filesystem writes accept content only from piped standard input".to_string(),
        ));
    }
    // The broadest shipped profile permits 25 MB in one write. Read at most one byte beyond
    // that so hostile input cannot force unbounded allocation before profile policy runs.
    let mut content = Vec::new();
    std::io::stdin()
        .lock()
        .take(25_000_001)
        .read_to_end(&mut content)?;
    let store = local_store(state_db)?;
    let result = vigil_local::FilesystemBroker::new(&store).write(session_id, path, &content)?;
    println!(
        "Wrote {} bytes to {}",
        result.bytes,
        result.resolved_resource.display()
    );
    println!("Event: {}", result.event_id);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn broker_process_execute(
    state_db: Option<&Path>,
    session_id: &str,
    program: PathBuf,
    cwd: Option<PathBuf>,
    environment: &[String],
    timeout_ms: u64,
    discard_output: bool,
    arguments: Vec<String>,
) -> vigil_common::Result<()> {
    if std::io::stdout().is_terminal() && !discard_output {
        return Err(vigil_common::VigilError::Config(
            "refusing to render untrusted process output to a terminal; pipe stdout or use \
             --discard-output"
                .to_string(),
        ));
    }
    let environment = parse_process_environment(environment)?;
    let request = vigil_local::ProcessRequest {
        program,
        arguments,
        cwd,
        environment,
        timeout_ms,
    };
    let store = local_store(state_db)?;
    let result = vigil_local::ProcessBroker::new(&store).execute(session_id, &request)?;

    if !discard_output {
        std::io::stdout().lock().write_all(&result.stdout)?;
        if !result.stderr.is_empty() && !std::io::stderr().is_terminal() {
            std::io::stderr().lock().write_all(&result.stderr)?;
        }
        eprintln!(
            "vigil: process {} exited {:?}; timeout={} stdout_truncated={} stderr_truncated={} \
             (event {})",
            result.pid,
            result.exit_code,
            result.timed_out,
            result.stdout_truncated,
            result.stderr_truncated,
            result.event_id
        );
    } else {
        println!("Process: {}", result.pid);
        println!("Executable: {}", result.executable.display());
        println!("Class: {}", result.executable_class.as_str());
        println!("Exit code: {:?}", result.exit_code);
        println!("Timed out: {}", result.timed_out);
        println!("Event: {}", result.event_id);
    }
    if result.timed_out {
        return Err(vigil_common::VigilError::Timeout {
            component: "brokered_process",
            elapsed_ms: timeout_ms,
        });
    }
    if result.exit_code != Some(0) {
        return Err(vigil_common::VigilError::InvalidRequest(
            "brokered process exited unsuccessfully".to_string(),
        ));
    }
    Ok(())
}

fn parse_process_environment(entries: &[String]) -> vigil_common::Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    for entry in entries {
        let (key, value) =
            entry
                .split_once('=')
                .ok_or_else(|| vigil_common::VigilError::InvalidValue {
                    field: "environment",
                    reason: "environment entries must use KEY=VALUE syntax".to_string(),
                })?;
        if key.is_empty()
            || environment
                .insert(key.to_string(), value.to_string())
                .is_some()
        {
            return Err(vigil_common::VigilError::InvalidValue {
                field: "environment",
                reason: "environment keys must be non-empty and unique".to_string(),
            });
        }
    }
    Ok(environment)
}

fn broker_network_probe(
    state_db: Option<&Path>,
    session_id: &str,
    host: String,
    port: u16,
    timeout_ms: u64,
    json: bool,
) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let source = vigil_local::SystemNetworkSource;
    let request = vigil_local::NetworkProbeRequest {
        host,
        port,
        timeout_ms,
    };
    let result = vigil_local::NetworkBroker::new(&store, &source).probe(session_id, &request)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Destination: {}", result.destination);
        println!("Connected: {}", result.connected_address);
        println!("Resolved: {} address(es)", result.resolved_addresses.len());
        println!("Payload: 0 bytes sent, 0 bytes received");
        println!("Event: {}", result.event_id);
        println!("Network Extension: NOT INSTALLED");
    }
    Ok(())
}

fn local_status(state_db: Option<&Path>, json: bool) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    store.health_check()?;
    let sessions = store.list_sessions(1000)?;
    let active = sessions
        .iter()
        .filter(|session| {
            matches!(
                session.status,
                vigil_local::SessionStatus::Starting | vigil_local::SessionStatus::Running
            )
        })
        .count();
    let status = serde_json::json!({
        "posture": "OBSERVE ONLY",
        "local_policy": "ACTIVE",
        "filesystem_broker": "AVAILABLE",
        "process_broker": "AVAILABLE",
        "network_probe_broker": "AVAILABLE",
        "secret_broker": "INTERFACE_AND_SIMULATOR_ONLY",
        "endpoint_fast_path": "SIMULATOR_AVAILABLE",
        "blast_radius_manager": "ACTIVE",
        "session_database": "HEALTHY",
        "database_path": store.path(),
        "database_schema": store.schema_version()?,
        "active_sessions": active,
        "endpoint_security": "NOT INSTALLED",
        "network_extension": "NOT INSTALLED",
        "daemon": "NOT INSTALLED",
        "os_enforcement": false,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("VIGIL local security posture");
        println!("────────────────────────────");
        println!("Posture              OBSERVE ONLY");
        println!("Local policy         ACTIVE");
        println!("Filesystem broker    AVAILABLE (semantic enforcement)");
        println!("Process broker       AVAILABLE (structured semantic enforcement)");
        println!("Network probe broker AVAILABLE (payload-free semantic mediation)");
        println!("Secret broker        INTERFACE + SIMULATOR ONLY (no native provider)");
        println!("Endpoint fast path   SIMULATOR AVAILABLE (native adapter not installed)");
        println!("Blast-radius budget  ACTIVE");
        println!(
            "Session database     HEALTHY (schema {})",
            store.schema_version()?
        );
        println!("Active sessions      {active}");
        println!("Endpoint Security    NOT INSTALLED");
        println!("Network Extension    NOT INSTALLED");
        println!("vigild               NOT INSTALLED");
        println!();
        println!("Processes launched by this build retain the user's ambient macOS authority.");
    }
    Ok(())
}

fn run_local_session(
    state_db: Option<&Path>,
    profile: &str,
    workspace: &Path,
    task: Option<&str>,
    command: &[OsString],
) -> vigil_common::Result<()> {
    use std::process::Command as ProcessCommand;
    use std::str::FromStr;

    let profile = vigil_local::LocalProfile::from_str(profile)?;
    let workspace = vigil_local::normalize_workspace(workspace)?;
    let executable = command.first().ok_or_else(|| {
        vigil_common::VigilError::InvalidRequest("run requires a command after `--`".to_string())
    })?;
    let store = local_store(state_db)?;
    let argv: Vec<String> = command
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let session = store.create_session(&vigil_local::NewSession {
        profile: profile.as_str().to_string(),
        workspace: workspace.clone(),
        executable: executable.to_string_lossy().into_owned(),
        argv,
        task: task.map(str::to_string),
        enforcement_posture: "observe_only".to_string(),
    })?;
    let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
    store.append_event(
        &session.id,
        "session",
        "session.start",
        None,
        &correlation_id,
        &serde_json::json!({
            "profile": profile.as_str(),
            "workspace": workspace,
            "enforcement_posture": "observe_only",
        }),
    )?;

    println!("VIGIL Control Plane");
    println!("────────────────────────────────────────");
    println!("Session       {}", session.id);
    println!("Profile       {}", profile.as_str());
    println!("Workspace     {}", workspace.display());
    println!("Enforcement   OBSERVE ONLY");
    println!();
    println!("WARNING: Endpoint Security and Network Extension enforcement are not installed.");
    println!("This process retains the launching user's ambient macOS authority.");
    println!();

    let mut process = ProcessCommand::new(executable);
    process
        .args(&command[1..])
        .current_dir(&workspace)
        // Correlation hint only. VIGIL never accepts this value as authoritative identity.
        .env("VIGIL_CORRELATION_SESSION_ID", &session.id);
    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => {
            store.finish_session(&session.id, None)?;
            store.append_event(
                &session.id,
                "process",
                "process.spawn_failed",
                Some("ERROR"),
                &correlation_id,
                &serde_json::json!({"error_class": error.kind().to_string()}),
            )?;
            return Err(error.into());
        }
    };
    store.mark_running(&session.id, child.id())?;
    // The root of this session's process lineage. Recording it is observation, not
    // enforcement: the child still holds the launching user's ambient authority.
    // Identify the root of this session's lineage by content, not only by name. The graph
    // records what ran, so a later question about which binary it was has an answer.
    let root_digest = std::fs::read(PathBuf::from(executable))
        .ok()
        .filter(|bytes| bytes.len() <= 64 * 1024 * 1024)
        .map(|bytes| vigil_common::ContentHash::sha256(&bytes).to_string());
    let root = store.record_process_start(
        &session.id,
        None,
        child.id(),
        &executable.to_string_lossy(),
        &session.argv,
        root_digest.as_deref(),
    )?;
    store.append_event(
        &session.id,
        "process",
        "process.exec",
        Some("OBSERVED"),
        &correlation_id,
        &serde_json::json!({
            "pid": child.id(),
            "argv": &session.argv,
            "process_node_id": root.node_id,
        }),
    )?;
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            // The node is closed as `unknown` rather than left open: an open node keeps its
            // PID claimed, and "we stopped watching" is the honest record of what happened.
            store.record_process_exit(&root.node_id, None, vigil_local::ProcessStatus::Unknown)?;
            store.finish_session(&session.id, None)?;
            return Err(error.into());
        }
    };
    store.record_process_exit(
        &root.node_id,
        status.code(),
        vigil_local::ProcessStatus::Exited,
    )?;
    store.finish_session(&session.id, status.code())?;
    store.append_event(
        &session.id,
        "session",
        "session.end",
        None,
        &correlation_id,
        &serde_json::json!({"exit_code": status.code(), "success": status.success()}),
    )?;
    println!("Session {} ended (exit {:?}).", session.id, status.code());
    if status.success() {
        Ok(())
    } else {
        Err(vigil_common::VigilError::Unavailable {
            component: "agent_process",
            reason: format!("agent exited with status {status}"),
        })
    }
}

fn list_local_sessions(
    state_db: Option<&Path>,
    limit: usize,
    json: bool,
) -> vigil_common::Result<()> {
    let sessions = local_store(state_db)?.list_sessions(limit)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }
    if sessions.is_empty() {
        println!("No local sessions recorded.");
        return Ok(());
    }
    println!(
        "{:<37} {:<20} {:<18} POSTURE",
        "SESSION", "STATUS", "PROFILE"
    );
    for session in sessions {
        println!(
            "{:<37} {:<20} {:<18} {}",
            session.id,
            format!("{:?}", session.status).to_ascii_uppercase(),
            session.profile,
            session.enforcement_posture.to_ascii_uppercase()
        );
    }
    Ok(())
}

fn show_local_session(state_db: Option<&Path>, id: &str, json: bool) -> vigil_common::Result<()> {
    let store = local_store(state_db)?;
    let session = store
        .get_session(id)?
        .ok_or_else(|| vigil_common::VigilError::NotFound("local session".to_string()))?;
    let events = store.events_for_session(id)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "session": session,
                "events": events,
            }))?
        );
        return Ok(());
    }
    println!("Session       {}", session.id);
    println!("Status        {:?}", session.status);
    println!("Profile       {}", session.profile);
    println!(
        "Posture       {}",
        session.enforcement_posture.to_ascii_uppercase()
    );
    println!("Workspace     {}", session.workspace);
    println!("Executable    {}", session.executable);
    println!("Risk          {}", session.risk_state);
    println!("Created       {}", session.created_at.to_rfc3339());
    if let Some(ended) = session.ended_at {
        println!("Ended         {}", ended.to_rfc3339());
    }
    println!();
    println!("Timeline");
    for event in events {
        println!(
            "  {}  {:<22} {}",
            event.timestamp.format("%H:%M:%S"),
            event.action,
            event.decision.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn evaluate_local_policy(
    profile: &str,
    workspace: &Path,
    action: &str,
    resource: &str,
    json: bool,
) -> vigil_common::Result<()> {
    use std::str::FromStr;
    let profile = vigil_local::LocalProfile::from_str(profile)?;
    let action = vigil_local::LocalAction::from_str(action)?;
    let workspace = vigil_local::normalize_workspace(workspace)?;
    let decision = vigil_local::evaluate(profile, &workspace, action, resource);
    print_local_decision(&decision, json)
}

fn simulate_local_action(
    state_db: Option<&Path>,
    profile: &str,
    workspace: &Path,
    action: &str,
    resource: &str,
    json: bool,
) -> vigil_common::Result<()> {
    use std::str::FromStr;
    let profile = vigil_local::LocalProfile::from_str(profile)?;
    let action = vigil_local::LocalAction::from_str(action)?;
    let workspace = vigil_local::normalize_workspace(workspace)?;
    let decision = vigil_local::evaluate(profile, &workspace, action, resource);
    let store = local_store(state_db)?;
    let session = store.create_session(&vigil_local::NewSession {
        profile: profile.as_str().to_string(),
        workspace,
        executable: "vigil-simulator".to_string(),
        argv: vec![action.as_str().to_string(), resource.to_string()],
        task: Some("simulated authorization request".to_string()),
        enforcement_posture: "simulation".to_string(),
    })?;
    let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
    let payload = serde_json::to_value(&decision)?;
    store.append_event(
        &session.id,
        "policy",
        action.as_str(),
        Some(&format!("{:?}", decision.outcome).to_ascii_uppercase()),
        &correlation_id,
        &payload,
    )?;
    store.seal_session(
        &session.id,
        &format!("{:?}", decision.risk_after).to_ascii_uppercase(),
    )?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "session_id": session.id,
                "decision": decision,
            }))?
        );
        return Ok(());
    }
    print_local_decision(&decision, false)?;
    println!("Evidence session: {}", session.id);
    Ok(())
}

fn print_local_decision(
    decision: &vigil_local::LocalDecision,
    json: bool,
) -> vigil_common::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(decision)?);
        return Ok(());
    }
    println!(
        "Decision: {}",
        format!("{:?}", decision.outcome).to_ascii_uppercase()
    );
    println!();
    println!("Reason: {}", decision.reason);
    println!("Determining policy: {}", decision.determining_policy);
    if let Some(resolved) = &decision.resolved_resource {
        println!("Resolved resource: {resolved}");
    }
    if let Some(detection) = &decision.detection {
        println!("Detection: {detection}");
    }
    println!(
        "Risk: {:?} → {:?}",
        decision.risk_before, decision.risk_after
    );
    Ok(())
}

/// Merge every bundle under a directory, the way the server does.
fn load_rules(dir: &Path) -> vigil_common::Result<Vec<vigil_policy::Rule>> {
    let mut rules = Vec::new();
    let mut found_any = false;
    for subdirectory in ["base", "agents", "tenants", "environments"] {
        let path = dir.join(subdirectory);
        if !path.is_dir() {
            continue;
        }
        found_any = true;
        let engine =
            DeterministicPolicyEngine::from_directory(&path, PolicyBundleId::new("check")?)?;
        rules.extend(engine.bundle().rules.clone());
    }
    if !found_any {
        // Also accept a directory of bundles directly, which is how a single-tenant
        // deployment often lays them out.
        let engine = DeterministicPolicyEngine::from_directory(dir, PolicyBundleId::new("check")?)?;
        rules.extend(engine.bundle().rules.clone());
    }
    Ok(rules)
}

fn merged_bundle(dir: &Path) -> vigil_common::Result<vigil_policy::PolicyBundle> {
    let bundle = vigil_policy::PolicyBundle {
        version: PolicyBundleId::new("merged")?,
        description: format!("merged from {}", dir.display()),
        default_effect: vigil_policy::PolicyEffect::Deny,
        rules: load_rules(dir)?,
    };
    bundle.validate()?;
    Ok(bundle)
}

fn validate_policies(dir: &Path) -> vigil_common::Result<()> {
    let bundle = merged_bundle(dir)?;
    println!(
        "✓ {} rules valid, merged from {}",
        bundle.rules.len(),
        dir.display()
    );
    println!("  default effect: {:?}", bundle.default_effect);

    // The merged set is what actually runs, so a duplicate id across files is the failure
    // mode worth reporting loudly — decisions must be attributable to exactly one rule.
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for rule in &bundle.rules {
        *counts.entry(rule.id.as_str()).or_default() += 1;
    }
    for (id, count) in counts.iter().filter(|(_, c)| **c > 1) {
        println!("  ! rule `{id}` appears {count} times");
    }
    Ok(())
}

fn list_policies(dir: &Path) -> vigil_common::Result<()> {
    let bundle = merged_bundle(dir)?;
    let mut rules = bundle.rules.clone();
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    println!("{:<34} {:<22} SEVERITY", "RULE", "EFFECT");
    for rule in rules {
        println!(
            "{:<34} {:<22} {}{}",
            rule.id,
            format!("{:?}", rule.effect),
            rule.severity.as_str(),
            if rule.audit_only {
                "  (audit-only)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn validate_remits(dir: &Path) -> vigil_common::Result<()> {
    let registry = RemitRegistry::load_directory(dir)?;
    println!("✓ {} remit(s) valid in {}", registry.len(), dir.display());
    Ok(())
}

fn validate_manifests(file: &Path) -> vigil_common::Result<()> {
    let registry = vigil_core::ToolManifestRegistry::load_file(file)?;
    println!(
        "✓ {} tool manifest(s) valid in {}",
        registry.len(),
        file.display()
    );
    Ok(())
}

fn verify_audit(bundle_path: &Path, keys: &[String]) -> vigil_common::Result<()> {
    let raw = std::fs::read_to_string(bundle_path)?;
    let bundle: AuditBundle = serde_json::from_str(&raw)?;

    let mut trusted = HashMap::new();
    for entry in keys {
        let (key_id, hex_key) = entry.split_once('=').ok_or_else(|| {
            vigil_common::VigilError::Config("--key must be given as key_id=hex".to_string())
        })?;
        let bytes: [u8; 32] = hex::decode(hex_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| {
                vigil_common::VigilError::Config(
                    "checkpoint key must be 32 hex-encoded bytes".to_string(),
                )
            })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
            vigil_common::VigilError::Config("not a valid Ed25519 public key".to_string())
        })?;
        trusted.insert(key_id.to_string(), key);
    }

    let report = bundle.verify(&trusted);
    println!(
        "entries: {}  checkpoints: {}",
        report.entries_checked, report.checkpoints_checked
    );

    if report.is_valid() {
        println!("✓ audit chain verified");
        return Ok(());
    }

    // A failed verification exits non-zero so it can gate a pipeline.
    println!("✗ {} integrity failure(s):", report.failures.len());
    for failure in &report.failures {
        println!("  {failure:?}");
    }
    Err(vigil_common::VigilError::AuditIntegrity(format!(
        "{} failure(s)",
        report.failures.len()
    )))
}

fn generate_keys(out: &Path) -> vigil_common::Result<()> {
    std::fs::create_dir_all(out)?;
    for name in ["capability", "approval", "audit"] {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let path = out.join(format!("{name}.key"));
        std::fs::write(&path, hex::encode(seed))?;

        // The seeds are private key material. Anyone who can read them can mint
        // capabilities or forge audit checkpoints.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        println!("wrote {}", path.display());
    }
    println!();
    println!("Three distinct keys, deliberately: compromise of the audit key must not allow");
    println!("minting capabilities, and compromise of the approval key must not allow forging");
    println!("checkpoints. Give the Gateway only the *public* half:");
    println!();
    println!("  vigil keys public {}/capability.key", out.display());
    Ok(())
}

fn print_public_key(seed_path: &Path) -> vigil_common::Result<()> {
    let raw = std::fs::read_to_string(seed_path)?;
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            vigil_common::VigilError::Config("seed must be 32 hex-encoded bytes".to_string())
        })?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&bytes);
    println!("{}", hex::encode(signing.verifying_key().to_bytes()));
    Ok(())
}

fn doctor(policy_dir: &Path, state_db: Option<&Path>) -> vigil_common::Result<()> {
    let mut problems = 0;

    println!("VIGIL configuration check");
    println!("─────────────────────────");

    println!(
        "✓ platform: {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    match local_store(state_db).and_then(|store| {
        store.health_check()?;
        Ok((store.path().to_path_buf(), store.schema_version()?))
    }) {
        Ok((path, version)) => println!("✓ local database: {} (schema {version})", path.display()),
        Err(error) => {
            println!("✗ local database: {error}");
            problems += 1;
        }
    }
    println!("  ! Endpoint Security: not installed (OS enforcement unavailable)");
    println!("  ! Network Extension: not installed (network enforcement unavailable)");

    // Approvals waiting on a human are not a fault, but an operator who does not know they
    // are there will read a stalled agent as a broken one.
    match local_store(state_db).and_then(|store| {
        store.list_approvals(None, Some(vigil_local::ApprovalStatus::Pending), 1000)
    }) {
        Ok(pending) if pending.is_empty() => println!("✓ approvals: none waiting"),
        Ok(pending) => {
            let now = chrono::Utc::now();
            let actionable = pending
                .iter()
                .filter(|approval| approval.is_actionable(now))
                .count();
            println!(
                "  ! approvals: {} waiting for a decision ({} still actionable)",
                pending.len(),
                actionable
            );
            println!("    review them with `vigil approvals list --status pending`");
        }
        Err(error) => {
            println!("✗ approvals: {error}");
            problems += 1;
        }
    }

    match merged_bundle(policy_dir) {
        Ok(bundle) => {
            println!("✓ policy: {} rules", bundle.rules.len());
            if bundle.rules.iter().any(|r| {
                r.matcher.match_all && matches!(r.effect, vigil_policy::PolicyEffect::Allow)
            }) {
                println!("  ! a universal allow rule is present, which disables enforcement");
                problems += 1;
            }
        }
        Err(error) => {
            println!("✗ policy: {error}");
            problems += 1;
        }
    }

    match RemitRegistry::load_directory(&policy_dir.join("remits")) {
        Ok(registry) if registry.is_empty() => {
            println!("  ! no remits registered: every agent will be treated as unregistered");
        }
        Ok(registry) => println!("✓ remits: {}", registry.len()),
        Err(error) => {
            println!("✗ remits: {error}");
            problems += 1;
        }
    }

    match vigil_core::ToolManifestRegistry::load_file(&policy_dir.join("tools/manifests.yaml")) {
        Ok(registry) => println!("✓ tool manifests: {}", registry.len()),
        Err(error) => {
            println!("✗ tool manifests: {error}");
            problems += 1;
        }
    }

    for variable in [
        "VIGIL_CAPABILITY_KEY",
        "VIGIL_APPROVAL_KEY",
        "VIGIL_AUDIT_KEY",
    ] {
        if std::env::var(variable).is_ok() {
            println!("✓ {variable} is set");
        } else {
            println!("  ! {variable} is not set; Protected Mode will refuse to start");
        }
    }

    println!();
    if problems == 0 {
        println!("No blocking problems found.");
        Ok(())
    } else {
        Err(vigil_common::VigilError::Config(format!(
            "{problems} problem(s) found"
        )))
    }
}
