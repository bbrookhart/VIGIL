//! Experimental authority IPC. Decisions are not executable capabilities.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![cfg(unix)]

#[cfg(target_os = "linux")]
mod confined_read;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, Duration};
use vigil_local::{
    ApproverIdentity, LocalAction, LocalCheckpointSigner, LocalProfile, LocalStore, NewSession,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const MAX_FRAME: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub agent_uid: u32,
    pub operator_uid: u32,
    pub workspace: PathBuf,
    pub profile: LocalProfile,
}

impl Config {
    pub fn validate(&self, service_uid: u32) -> Result<()> {
        if service_uid == 0
            || self.agent_uid == 0
            || self.operator_uid == 0
            || self.agent_uid == service_uid
            || self.operator_uid == service_uid
            || self.agent_uid == self.operator_uid
        {
            return Err("service, agent and operator must have distinct non-root UIDs".into());
        }
        if self.profile == LocalProfile::Observe {
            return Err("observe is not an enforcement profile".into());
        }
        if !self.workspace.is_absolute()
            || fs::canonicalize(&self.workspace)? != self.workspace
            || !self.workspace.is_dir()
        {
            return Err("workspace must be an existing canonical absolute directory".into());
        }
        Ok(())
    }

    fn may_call(&self, uid: u32, request: &Request) -> bool {
        match request {
            Request::Status {} => uid == self.agent_uid || uid == self.operator_uid,
            Request::Authorize { .. } | Request::Read { .. } => uid == self.agent_uid,
            Request::Approvals {}
            | Request::Grant { .. }
            | Request::Deny { .. }
            | Request::Checkpoint {} => uid == self.operator_uid,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {},
    Read {
        resource: String,
    },
    Authorize {
        action: LocalAction,
        resource: String,
    },
    Approvals {},
    Grant {
        approval_id: String,
        max_uses: u32,
        ttl_seconds: i64,
    },
    Deny {
        approval_id: String,
    },
    Checkpoint {},
}

/// Require every ancestor to be a real, non-writable-by-others directory owned
/// by root or the service. Reject symlinks, including trusted-looking prefixes.
pub fn check_directory(path: &Path, owner: u32, private: bool) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err("directory must be canonical and absolute".into());
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        if !meta.is_dir() || (meta.uid() != 0 && meta.uid() != owner) || meta.mode() & 0o022 != 0 {
            return Err(format!("untrusted directory: {}", ancestor.display()).into());
        }
    }
    let meta = fs::symlink_metadata(path)?;
    if meta.uid() != owner || (private && meta.mode() & 0o077 != 0) {
        return Err("service directory has incorrect ownership or permissions".into());
    }
    Ok(())
}

fn check_file(path: &Path, owner: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(format!("unsafe state file: {}", path.display()).into());
    }
    Ok(())
}

fn create_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    config: Config,
    session_id: String,
}

pub struct Authority {
    read_enabled: bool,
    #[cfg(target_os = "linux")]
    workspace: confined_read::ConfinedWorkspace,
    config: Config,
    session_id: String,
    store: LocalStore,
    signer: LocalCheckpointSigner,
    _lock: fs::File,
}

impl Authority {
    pub fn open(state: &Path, config: Config) -> Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        config.validate(uid)?;
        #[cfg(target_os = "linux")]
        let workspace =
            confined_read::ConfinedWorkspace::open(&config.workspace, config.agent_uid)?;
        check_directory(state, uid, true)?;
        // Inspect ALL existing entries before SQLite or key loading follows a path.
        // Only the service can subsequently change this directory.
        for entry in fs::read_dir(state)? {
            check_file(&entry?.path(), uid)?;
        }
        let lock_path = state.join("authority.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let binding_path = state.join("binding.json");
        let key_path = state.join("checkpoint.seed");
        let db_path = state.join("authority.db");
        let binding: Option<Binding> = if binding_path.exists() {
            let binding: Binding = serde_json::from_slice(&fs::read(&binding_path)?)?;
            if binding.config != config {
                return Err("authority binding changed; use a new state directory".into());
            }
            if !key_path.exists() || !db_path.exists() {
                return Err("incomplete existing authority state".into());
            }
            Some(binding)
        } else {
            if fs::read_dir(state)?
                .any(|entry| entry.map(|e| e.path() != lock_path).unwrap_or(true))
            {
                return Err("refusing to initialize nonempty unbound state".into());
            }
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.try_fill_bytes(&mut seed)?;
            create_private(&key_path, &seed)?;
            None
        };
        let signer =
            LocalCheckpointSigner::from_seed("vigild-checkpoint-v1", &fs::read(key_path)?)?;
        let store = LocalStore::open(&db_path)?;
        let session_id = if let Some(binding) = binding {
            let session = store
                .get_session(&binding.session_id)?
                .ok_or("bound session missing")?;
            if session.profile != config.profile.as_str()
                || Path::new(&session.workspace) != config.workspace
            {
                return Err("bound session differs from service configuration".into());
            }
            binding.session_id
        } else {
            let session = store.create_session(&NewSession {
                profile: config.profile.as_str().into(),
                workspace: config.workspace.clone(),
                executable: "vigild-authority-only".into(),
                argv: vec![],
                task: None,
                enforcement_posture: if cfg!(target_os = "linux") {
                    "semantic_enforced"
                } else {
                    "authority-ipc-only"
                }
                .into(),
            })?;
            #[cfg(target_os = "linux")]
            store.activate_semantic_session(&session.id)?;
            create_private(
                &binding_path,
                &serde_json::to_vec(&Binding {
                    config: config.clone(),
                    session_id: session.id.clone(),
                })?,
            )?;
            // Persist the directory entries as well as the files before serving.
            fs::File::open(state)?.sync_all()?;
            session.id
        };
        let session = store
            .get_session(&session_id)?
            .ok_or("bound session missing")?;
        let read_enabled = cfg!(target_os = "linux")
            && session.enforcement_posture == "semantic_enforced"
            && session.status == vigil_local::SessionStatus::Running;
        Ok(Self {
            read_enabled,
            #[cfg(target_os = "linux")]
            workspace,
            config,
            session_id,
            store,
            signer,
            _lock: lock,
        })
    }

    fn dispatch(&self, uid: u32, request: Request) -> Result<Value> {
        if !self.config.may_call(uid, &request) {
            return Err("forbidden".into());
        }
        let operation = match &request {
            Request::Status {} => "status",
            Request::Authorize { .. } => "authorize",
            Request::Read { .. } => "read",
            Request::Approvals {} => "approvals",
            Request::Grant { .. } => "grant",
            Request::Deny { .. } => "deny",
            Request::Checkpoint {} => "checkpoint",
        };
        // Record authenticated intent before any authority mutation. No resource
        // contents or caller-provided identity are written to this event.
        let intent = self.store.append_event(
            &self.session_id,
            "authority",
            operation,
            Some("REQUESTED"),
            "vigild-ipc",
            &json!({"peer_uid": uid,
                "request_sha256": vigil_common::ContentHash::sha256(&serde_json::to_vec(&request)?).to_string()}),
        )?;
        let result = match request {
            Request::Status {} => {
                json!({"session_id": self.session_id, "agent_uid": self.config.agent_uid,
                "profile": self.config.profile, "execution_supported": self.read_enabled,
                "execution_actions": if self.read_enabled { vec!["fs.read"] } else { vec![] },
                "checkpoint_public_key": self.signer.verifying_key().to_bytes()})
            }
            Request::Authorize { action, resource } => {
                // Other action families require their own specialised evaluators.
                if !matches!(
                    action,
                    LocalAction::FsRead
                        | LocalAction::FsWrite
                        | LocalAction::FsCreate
                        | LocalAction::FsDelete
                        | LocalAction::FsList
                        | LocalAction::FsMetadata
                ) {
                    return Err("unsupported action family".into());
                }
                let auth = self.store.authorize_local(
                    &self.session_id,
                    self.config.profile,
                    &self.config.workspace,
                    action,
                    &resource,
                )?;
                json!({"decision": auth.decision, "approval": auth.approval,
                    "risk_state": auth.risk_state, "execution_supported": false})
            }
            Request::Read { resource } => self.execute_read(&resource, &intent.event_id)?,
            Request::Approvals {} => serde_json::to_value(self.store.list_approvals(
                Some(&self.session_id),
                None,
                20,
            )?)?,
            Request::Grant {
                approval_id,
                max_uses,
                ttl_seconds,
            } => {
                self.require_bound_approval(&approval_id)?;
                let identity = ApproverIdentity::from_cli_operator(&format!("unix-uid:{uid}"))?;
                serde_json::to_value(self.store.grant_approval(
                    &approval_id,
                    &identity,
                    max_uses,
                    ttl_seconds,
                    None,
                    chrono::Utc::now(),
                )?)?
            }
            Request::Deny { approval_id } => {
                self.require_bound_approval(&approval_id)?;
                let identity = ApproverIdentity::from_cli_operator(&format!("unix-uid:{uid}"))?;
                serde_json::to_value(self.store.deny_approval(
                    &approval_id,
                    &identity,
                    None,
                    chrono::Utc::now(),
                )?)?
            }
            Request::Checkpoint {} => serde_json::to_value(
                self.store
                    .write_checkpoint(&self.signer, chrono::Utc::now())?,
            )?,
        };
        self.store.append_event(
            &self.session_id,
            "authority",
            operation,
            Some("COMPLETED"),
            &intent.event_id,
            &json!({"peer_uid": uid, "execution_performed": operation == "read",
                "result_sha256": vigil_common::ContentHash::sha256(&serde_json::to_vec(&result)?).to_string()}),
        )?;
        Ok(json!({"ok": true, "result": result}))
    }

    fn require_bound_approval(&self, id: &str) -> Result<()> {
        let request = self.store.get_approval(id)?.ok_or("approval missing")?;
        if request.session_id != self.session_id {
            return Err("approval belongs to another session".into());
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn execute_read(&self, _resource: &str, _correlation: &str) -> Result<Value> {
        Err("descriptor-bound execution is currently Linux-only".into())
    }

    #[cfg(target_os = "linux")]
    fn execute_read(&self, resource: &str, correlation: &str) -> Result<Value> {
        use base64::Engine;
        use vigil_local::{BudgetCharge, BudgetDimension};
        if !self.read_enabled {
            return Err("this session has no read execution authority".into());
        }
        let opened = self.workspace.prepare(resource, self.config.agent_uid)?;
        // Fresh authorization in this call; an earlier ALLOW or caller-supplied
        // decision cannot be replayed to the executor. Hold the descriptor throughout.
        let auth = self.store.authorize_local(
            &self.session_id,
            self.config.profile,
            &self.config.workspace,
            LocalAction::FsRead,
            resource,
        )?;
        if !auth.permits_execution() {
            return Err("read denied by policy or risk".into());
        }
        let reservation = self.store.reserve_budget(
            &self.session_id,
            correlation,
            &[BudgetCharge::new(BudgetDimension::FileReads, 1)],
        )?;
        // Charge the attempt before reading. A crash, read failure or disconnected
        // client never refunds a possibly performed operation.
        self.store.commit_budget(&reservation.id)?;
        let (device, inode) = (opened.device, opened.inode);
        let bytes = opened.read()?;
        let event = self.store.append_event(
            &self.session_id,
            "filesystem",
            "fs.read",
            Some("EXECUTED"),
            correlation,
            &json!({"device": device, "inode": inode,
                "bytes": bytes.len(), "reservation_id": reservation.id, "content_captured": false}),
        )?;
        Ok(json!({"action": "fs.read", "event_id": event.event_id,
            "device": device, "inode": inode, "bytes": bytes.len(),
            "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes)}))
    }
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("invalid frame length".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err("response exceeds frame limit".into());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

/// One bounded frame per connection; no claim in JSON can select a principal.
pub async fn serve(socket: &Path, authority: Authority) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    check_directory(socket.parent().ok_or("socket parent missing")?, uid, false)?;
    // Never unlink an existing endpoint (even a stale socket).
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o666))?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let peer = match stream.peer_cred() {
            Ok(peer) => peer.uid(),
            Err(_) => continue,
        };
        if peer != authority.config.agent_uid && peer != authority.config.operator_uid {
            continue;
        }
        let bytes = match timeout(DEADLINE, read_frame(&mut stream)).await {
            Ok(Ok(bytes)) => bytes,
            _ => continue,
        };
        let result = serde_json::from_slice::<Request>(&bytes)
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
            .and_then(|request| authority.dispatch(peer, request));
        // Keep state paths and raw SQLite details out of the untrusted channel.
        let response = result.unwrap_or_else(|_| json!({"ok": false, "error": "request_denied"}));
        let mut bytes = serde_json::to_vec(&response)?;
        if bytes.len() > MAX_FRAME {
            bytes = serde_json::to_vec(&json!({"ok": false, "error": "response_too_large"}))?;
        }
        let _ = timeout(DEADLINE, write_frame(&mut stream, &bytes)).await;
    }
}

/// Authenticate the server with kernel credentials before transmitting a request.
pub async fn call(socket: &Path, service_uid: u32, request: &Request) -> Result<Value> {
    if service_uid == 0 {
        return Err("root service is not supported".into());
    }
    timeout(DEADLINE, async {
        let mut stream = UnixStream::connect(socket).await?;
        if stream.peer_cred()?.uid() != service_uid {
            return Err("server UID mismatch".into());
        }
        write_frame(&mut stream, &serde_json::to_vec(request)?).await?;
        Ok(serde_json::from_slice(&read_frame(&mut stream).await?)?)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authority request timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            agent_uid: 1001,
            operator_uid: 1002,
            workspace: PathBuf::from("/"),
            profile: LocalProfile::DeveloperRestricted,
        }
    }

    #[test]
    fn distinct_accounts_are_required() {
        assert!(config().validate(1003).is_ok());
        for uid in [0, 1001, 1002] {
            assert!(config().validate(uid).is_err());
        }
        let mut c = config();
        c.operator_uid = c.agent_uid;
        assert!(c.validate(1003).is_err());
        c = config();
        c.agent_uid = 0;
        assert!(c.validate(1003).is_err());
    }

    #[test]
    fn agent_cannot_approve_or_sign() {
        for request in [
            Request::Approvals {},
            Request::Checkpoint {},
            Request::Grant {
                approval_id: "x".into(),
                max_uses: 1,
                ttl_seconds: 30,
            },
            Request::Deny {
                approval_id: "x".into(),
            },
        ] {
            assert!(!config().may_call(1001, &request));
            assert!(!config().may_call(9999, &request));
            assert!(config().may_call(1002, &request));
        }
    }

    #[test]
    fn claimed_identity_and_policy_are_rejected() {
        for input in [
            r#"{"method":"status","uid":1002}"#,
            r#"{"method":"authorize","action":"fs.read","resource":"x","profile":"observe"}"#,
            r#"{"method":"grant","approval_id":"x","max_uses":1,"ttl_seconds":30,"approver":"operator"}"#,
            r#"{"method":"read","resource":"x","decision":"ALLOW"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(input).is_err());
        }
    }

    #[tokio::test]
    async fn credentials_come_from_the_kernel() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(
            a.peer_cred().unwrap().uid(),
            rustix::process::geteuid().as_raw()
        );
        assert_eq!(
            b.peer_cred().unwrap().uid(),
            rustix::process::geteuid().as_raw()
        );
    }

    #[tokio::test]
    async fn oversized_and_truncated_frames_fail() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_u32(MAX_FRAME as u32 + 1).await.unwrap();
        assert!(read_frame(&mut b).await.is_err());
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_u32(10).await.unwrap();
        a.write_all(b"short").await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }
}
