//! Deception: synthetic assets that exist only to be touched.
//!
//! A canary is a file with no legitimate purpose. Nothing in a real workflow reads it, so a
//! read is information — not proof of malice, but a strong signal that something is enumerating
//! rather than working.
//!
//! # Two rules that are not negotiable
//!
//! **No canary is ever placed in a real credential location.** Not `~/.ssh`, not `~/.aws`, not
//! anywhere `protected_category` recognises. Salting a user's actual credential directories
//! with decoys risks a real tool picking up a fake key and failing in a way that is hard to
//! diagnose, and it contaminates the exact locations whose integrity matters most.
//! [`LocalStore::place_canary`] enforces this by refusing, not by convention.
//!
//! **No canary contains a real secret.** Content is generated from a fixed synthetic pattern
//! carrying the marker `VIGILCANARY`, so anyone who finds one — in a log, in a paste, in an
//! attacker's exfiltration — can tell immediately that it grants nothing.
//!
//! # Why the confidence is MEDIUM, not HIGH
//!
//! A workspace-scoped canary can be swept by an entirely legitimate recursive tool: a search,
//! a linter, a test that walks the tree, a backup. That is a real false-positive path and
//! pretending otherwise would make the detection untrustworthy the first time it fired on a
//! `grep -r`. So the rule is `CRITICAL` severity with `MEDIUM` confidence and a weight that
//! contains a session rather than quarantining it. It is a strong reason to look, not a
//! verdict.

use crate::detection::{Confidence, DetectionRule, Severity, Tactic};
use crate::{LocalStore, RiskDimension};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vigil_common::{ContentHash, Result, VigilError};

pub const DETECTION_CANARY_ACCESS: &str = "deception_resource_access";

/// The marker every synthetic credential carries.
///
/// Present so that a canary found anywhere — a log, an exfiltrated archive, a support ticket —
/// is immediately identifiable as granting nothing.
pub const CANARY_MARKER: &str = "VIGILCANARY";

pub const CANARY_RULES: &[DetectionRule] = &[DetectionRule {
    id: "VIGIL-L018",
    name: "Deception resource access",
    severity: Severity::Critical,
    // Medium, not high: a legitimate recursive tool can sweep a workspace canary. See the
    // module documentation.
    confidence: Confidence::Medium,
    tactic: Tactic::DataCollection,
    description: "A synthetic asset that exists only as bait was accessed.",
    dimension: RiskDimension::DeceptionInteraction,
    weight: 60,
}];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanaryKind {
    CloudCredentials,
    SshKey,
    ApiToken,
    EnvironmentFile,
}

impl CanaryKind {
    pub const ALL: [Self; 4] = [
        Self::CloudCredentials,
        Self::SshKey,
        Self::ApiToken,
        Self::EnvironmentFile,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudCredentials => "cloud-credentials",
            Self::SshKey => "ssh-key",
            Self::ApiToken => "api-token",
            Self::EnvironmentFile => "environment-file",
        }
    }

    /// A plausible-looking filename for this kind of bait.
    pub const fn default_filename(self) -> &'static str {
        match self {
            Self::CloudCredentials => "aws-credentials.bak",
            Self::SshKey => "deploy_key",
            Self::ApiToken => "service-token.txt",
            Self::EnvironmentFile => ".env.production",
        }
    }

    /// Synthetic content. Every variant carries [`CANARY_MARKER`] and grants nothing.
    ///
    /// These are shaped to look like the real thing to a scanner without being usable: the
    /// key material is a repeated marker, not a valid key, so a tool that actually tried to
    /// use one would fail immediately rather than authenticating anywhere.
    pub fn synthetic_content(self) -> String {
        match self {
            Self::CloudCredentials => format!(
                "[default]\n\
                 aws_access_key_id = AKIA{CANARY_MARKER}0000\n\
                 aws_secret_access_key = {CANARY_MARKER}-not-a-real-secret-grants-nothing\n\
                 # Synthetic VIGIL canary. This credential authorizes nothing anywhere.\n"
            ),
            Self::SshKey => format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                 {CANARY_MARKER}ThisIsNotAKeyItIsBaitAndAuthorizesNothingAnywhereAtAll\n\
                 -----END OPENSSH PRIVATE KEY-----\n\
                 # Synthetic VIGIL canary.\n"
            ),
            Self::ApiToken => {
                format!("{CANARY_MARKER}_pat_this_token_is_synthetic_and_grants_nothing\n")
            }
            Self::EnvironmentFile => format!(
                "# Synthetic VIGIL canary. Nothing here is real.\n\
                 DATABASE_URL=postgres://{CANARY_MARKER}:{CANARY_MARKER}@localhost/nowhere\n\
                 API_KEY={CANARY_MARKER}-grants-nothing\n"
            ),
        }
    }
}

impl std::str::FromStr for CanaryKind {
    type Err = VigilError;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| VigilError::InvalidValue {
                field: "kind",
                reason: format!(
                    "unknown canary kind `{value}`; expected one of {}",
                    Self::ALL
                        .iter()
                        .map(|kind| kind.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Canary {
    pub canary_id: String,
    pub session_id: String,
    pub path: String,
    pub kind: CanaryKind,
    pub content_sha256: String,
    pub placed_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
}

impl LocalStore {
    /// Place a synthetic asset inside a session's workspace.
    ///
    /// Refuses any location outside the workspace and any protected category. Deception is a
    /// tool for watching an agent, not a reason to write fake credentials into the places a
    /// user's real ones live.
    pub fn place_canary(
        &self,
        session_id: &str,
        kind: CanaryKind,
        filename: Option<&str>,
    ) -> Result<Canary> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        let workspace = PathBuf::from(&session.workspace);
        let workspace = std::fs::canonicalize(&workspace).map_err(|error| {
            VigilError::Config(format!(
                "workspace `{}` cannot be resolved: {error}",
                workspace.display()
            ))
        })?;

        let filename = filename.unwrap_or_else(|| kind.default_filename());
        validate_filename(filename)?;
        let path = workspace.join(filename);

        // Resolve the deepest existing ancestor so a symlinked subdirectory cannot place the
        // canary outside the workspace, then confirm containment by component.
        let resolved = crate::policy::resolve_resource(&path.display().to_string(), &workspace)?;
        if !resolved.starts_with(&workspace) {
            return Err(VigilError::InvalidRequest(format!(
                "a canary must be inside the session workspace; `{}` resolves outside it",
                resolved.display()
            )));
        }
        if let Some(category) = crate::policy::protected_category_of(&resolved) {
            return Err(VigilError::InvalidRequest(format!(
                "refusing to place a canary in a protected location ({category}); deception \
                 must never contaminate real credential storage"
            )));
        }
        if resolved.exists() {
            return Err(VigilError::InvalidRequest(format!(
                "`{}` already exists; refusing to overwrite it with bait",
                resolved.display()
            )));
        }

        let content = kind.synthetic_content();
        debug_assert!(content.contains(CANARY_MARKER));
        write_canary(&resolved, content.as_bytes())?;

        let canary = Canary {
            canary_id: format!("can_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.to_string(),
            path: resolved.display().to_string(),
            kind,
            content_sha256: ContentHash::sha256(content.as_bytes()).to_string(),
            placed_at: Utc::now(),
            removed_at: None,
        };
        self.connection
            .execute(
                "INSERT INTO canaries
                 (canary_id, session_id, path, kind, content_sha256, placed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    canary.canary_id,
                    canary.session_id,
                    canary.path,
                    canary.kind.as_str(),
                    canary.content_sha256,
                    canary.placed_at.to_rfc3339(),
                ],
            )
            .map_err(super::store::storage_error)?;
        self.append_event(
            session_id,
            "deception",
            "canary.placed",
            None,
            &canary.canary_id,
            &serde_json::json!({
                "canary_id": canary.canary_id,
                "kind": canary.kind.as_str(),
                "path": canary.path,
                "synthetic": true,
            }),
        )?;
        Ok(canary)
    }

    /// Whether a resolved path is a live canary for this session.
    pub(crate) fn canary_at(&self, session_id: &str, resolved: &str) -> Result<Option<Canary>> {
        let row = self
            .connection
            .query_row(
                "SELECT canary_id, session_id, path, kind, content_sha256, placed_at, removed_at
                 FROM canaries WHERE session_id = ?1 AND path = ?2 AND removed_at IS NULL",
                params![session_id, resolved],
                canary_from_row,
            )
            .optional()
            .map_err(super::store::storage_error)?;
        row.transpose()
    }

    pub fn canaries_for_session(&self, session_id: &str) -> Result<Vec<Canary>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT canary_id, session_id, path, kind, content_sha256, placed_at, removed_at
                 FROM canaries WHERE session_id = ?1 ORDER BY placed_at, canary_id",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map([session_id], canary_from_row)
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        rows.into_iter().collect()
    }

    /// Remove a canary from disk and mark it retired.
    ///
    /// Leaving bait behind after a session ends would turn a diagnostic into litter that a
    /// later, unrelated tool trips over.
    pub fn remove_canary(&self, canary_id: &str) -> Result<()> {
        let path: Option<String> = self
            .connection
            .query_row(
                "SELECT path FROM canaries WHERE canary_id = ?1 AND removed_at IS NULL",
                [canary_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(super::store::storage_error)?;
        let Some(path) = path else {
            return Ok(());
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.connection
            .execute(
                "UPDATE canaries SET removed_at = ?1 WHERE canary_id = ?2",
                params![Utc::now().to_rfc3339(), canary_id],
            )
            .map_err(super::store::storage_error)?;
        Ok(())
    }
}

fn validate_filename(filename: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > 128
        || filename.contains('/')
        || filename.contains('\0')
        || filename == "."
        || filename == ".."
    {
        return Err(VigilError::InvalidValue {
            field: "filename",
            reason: "a canary filename must be a single path component of 1..=128 bytes"
                .to_string(),
        });
    }
    Ok(())
}

fn write_canary(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600, like a real credential file would be. Bait that is world-readable when the
        // thing it imitates never is looks wrong to anything paying attention.
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

fn canary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Canary>> {
    let canary_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let path: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let content_sha256: String = row.get(4)?;
    let placed_at: String = row.get(5)?;
    let removed_at: Option<String> = row.get(6)?;

    Ok((|| {
        Ok(Canary {
            canary_id,
            session_id,
            path,
            kind: kind.parse()?,
            content_sha256,
            placed_at: parse_time(&placed_at)?,
            removed_at: removed_at.as_deref().map(parse_time).transpose()?,
        })
    })())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| VigilError::Serialization(format!("unparsable canary timestamp: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{FilesystemBroker, NewSession, RiskState};
    use std::path::PathBuf;

    fn session() -> (PathBuf, LocalStore, String, PathBuf) {
        let root = std::env::temp_dir().join(format!("vigil-canary-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let workspace = std::fs::canonicalize(&workspace).expect("canonical workspace");
        let store = LocalStore::open(&root.join("state/vigil.db")).expect("open store");
        let created = store
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
            .mark_running(&created.id, std::process::id())
            .expect("activate");
        (root, store, created.id, workspace)
    }

    /// The point of the whole subsystem: a canary read is *permitted* — it is an ordinary
    /// workspace file — and is still the event worth knowing about. A design that only
    /// inspected denials would miss every canary hit.
    #[test]
    fn reading_bait_is_allowed_and_still_fires_a_detection() {
        let (root, store, id, _workspace) = session();
        store
            .place_canary(&id, CanaryKind::CloudCredentials, None)
            .expect("place");

        let result = FilesystemBroker::new(&store)
            .read(&id, CanaryKind::CloudCredentials.default_filename())
            .expect("the read itself must succeed");
        assert!(String::from_utf8_lossy(&result.value).contains(CANARY_MARKER));

        let detections = store.detections_for_session(&id).expect("detections");
        assert!(
            detections
                .iter()
                .any(|detection| detection.rule_id == "VIGIL-L018"),
            "reading a canary must fire VIGIL-L018: {detections:?}"
        );
        // Contained, not quarantined: a recursive tool could have done this.
        assert_eq!(
            store.session_risk_state(&id).expect("risk"),
            RiskState::Contained
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// The rule that is not negotiable: bait never goes near a real credential location.
    #[test]
    fn a_canary_is_refused_outside_the_workspace_and_in_protected_locations() {
        let (root, store, id, workspace) = session();

        // Traversal out of the workspace.
        for escape in ["../escape", "nested/path", ".."] {
            assert!(
                store
                    .place_canary(&id, CanaryKind::SshKey, Some(escape))
                    .is_err(),
                "`{escape}` must be refused"
            );
        }

        // A symlinked subdirectory pointing at a protected location must not become a way in.
        #[cfg(unix)]
        {
            let home = std::env::var("HOME").expect("HOME");
            let ssh = PathBuf::from(&home).join(".ssh");
            if ssh.exists() {
                let link = workspace.join("sneaky");
                if std::os::unix::fs::symlink(&ssh, &link).is_ok() {
                    let error = store.place_canary(&id, CanaryKind::SshKey, Some("sneaky"));
                    assert!(
                        error.is_err(),
                        "a symlink into a protected location must be refused"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_canary_never_overwrites_an_existing_file() {
        let (root, store, id, workspace) = session();
        std::fs::write(workspace.join("notes.md"), b"REAL WORK").expect("seed");
        assert!(store
            .place_canary(&id, CanaryKind::ApiToken, Some("notes.md"))
            .is_err());
        assert_eq!(
            std::fs::read(workspace.join("notes.md")).expect("read"),
            b"REAL WORK"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn removing_a_canary_takes_it_off_disk_and_is_idempotent() {
        let (root, store, id, _workspace) = session();
        let canary = store
            .place_canary(&id, CanaryKind::EnvironmentFile, None)
            .expect("place");
        assert!(PathBuf::from(&canary.path).exists());

        store.remove_canary(&canary.canary_id).expect("remove");
        assert!(!PathBuf::from(&canary.path).exists());
        store.remove_canary(&canary.canary_id).expect("idempotent");

        // A retired canary no longer fires; leaving it live would keep alarming on a path
        // that is now an ordinary absent file.
        assert!(store
            .canary_at(&id, &canary.path)
            .expect("lookup")
            .is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn every_kind_produces_marked_synthetic_content_with_no_usable_material() {
        for kind in CanaryKind::ALL {
            let content = kind.synthetic_content();
            assert!(
                content.contains(CANARY_MARKER),
                "{} content lacks the marker",
                kind.as_str()
            );
            // Nothing that could be mistaken for real key material.
            assert!(!content.contains("PRIVATE KEY-----\nMII"));
            assert!(content.len() < 4096);
        }
    }

    #[test]
    fn a_filename_must_be_a_single_component() {
        assert!(validate_filename("aws-credentials.bak").is_ok());
        assert!(validate_filename(".env.production").is_ok());
        assert!(validate_filename("../escape").is_err());
        assert!(validate_filename("nested/path").is_err());
        assert!(validate_filename("").is_err());
        assert!(validate_filename("..").is_err());
        assert!(validate_filename(&"a".repeat(129)).is_err());
    }

    #[test]
    fn the_rule_is_severe_but_not_certain() {
        let rule = CANARY_RULES[0];
        assert_eq!(rule.severity, Severity::Critical);
        // Medium confidence is the whole point: a recursive tool can sweep a workspace canary,
        // so this must contain rather than quarantine on its own evidence.
        assert_eq!(rule.confidence, Confidence::Medium);
        assert!(rule.weight < 80, "a canary alone must not quarantine");
    }
}
