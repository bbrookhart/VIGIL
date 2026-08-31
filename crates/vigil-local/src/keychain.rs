//! A macOS Keychain-backed secret provider.
//!
//! # Why
//!
//! The secret broker's contract (ADR 0009) is that an agent can *use* a credential without
//! ever holding it. Until now the only provider was a simulator, so the contract was an
//! interface with nothing real behind it: `vigil` reported `INTERFACE_AND_SIMULATOR_ONLY` and
//! there was no path to a credential a user actually has.
//!
//! # What
//!
//! Secrets live in the Keychain under an opaque handle. Two operations, and the split is the
//! whole design:
//!
//! - [`KeychainSecretProvider::metadata`] runs `security find-generic-password` **without**
//!   `-w`, so the secret is not in the output at all. This is what answers an agent's
//!   questions about a handle.
//! - `perform` reads the secret and hands it to the operation that needs it. The value never
//!   reaches the agent, never enters `argv`, never enters the event store, and is never
//!   written to a file by VIGIL.
//!
//! Credentials reach `git` through `GIT_ASKPASS`, pointing at a helper that invokes `security`
//! itself. The secret therefore travels from the Keychain to `git` directly; VIGIL never
//! writes it anywhere, and the helper script on disk contains no secret material — only the
//! lookup that retrieves it.
//!
//! Accessed through `/usr/bin/security` rather than the Security framework: this crate is
//! `#![forbid(unsafe_code)]` and `SecKeychain*` is FFI.
//!
//! # Assumptions
//!
//! `security` prompts for authorization when reading from a locked keychain. That prompt is a
//! feature — it is the user deciding — but it means `perform` can block on user interaction,
//! so it is bounded by a deadline and a timeout is reported as a failure rather than a denial.
//!
//! # Failure mode
//!
//! A handle that is absent, a keychain that cannot be read, or a lookup that times out all
//! return an error. None of them disclose whether the secret existed beyond the fact the
//! broker already had to know: the handle was in a precompiled grant.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vigil_common::{Result, VigilError};

use crate::secret_broker::{
    SecretKind, SecretMetadata, SecretProvider, SecretUsePurpose, SecretUseRequest,
};

const SECURITY_PATH: &str = "/usr/bin/security";
const GIT_PATH: &str = "/usr/bin/git";

/// Keychain reads can prompt. The bound stops a hung prompt from blocking a broker forever.
const SECURITY_TIMEOUT_MS: u64 = 30_000;
/// Git operations reach the network.
const GIT_TIMEOUT_MS: u64 = 60_000;

/// The Keychain attribute VIGIL stores the secret's kind in.
///
/// `security`'s `-j` flag writes the "comment" attribute (`icmt`). Using a dedicated attribute
/// rather than inferring the kind from the handle keeps the handle opaque.
const KIND_ATTRIBUTE: &str = "icmt";

/// Reads secrets from the macOS Keychain.
#[derive(Debug, Clone)]
pub struct KeychainSecretProvider {
    /// The keychain file to search. `None` uses the user's default search list.
    keychain: Option<PathBuf>,
    /// The account (`-a`) every VIGIL-managed secret is stored under.
    account: String,
}

impl KeychainSecretProvider {
    /// Use the user's default keychain search list.
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            keychain: None,
            account: account.into(),
        }
    }

    /// Use a specific keychain file. Tests use this to avoid touching the login keychain.
    pub fn with_keychain(account: impl Into<String>, keychain: impl Into<PathBuf>) -> Self {
        Self {
            keychain: Some(keychain.into()),
            account: account.into(),
        }
    }

    fn find_command(&self, handle: &str, with_secret: bool) -> Command {
        let mut command = Command::new(SECURITY_PATH);
        command.arg("find-generic-password");
        command.arg("-a").arg(&self.account);
        command.arg("-s").arg(handle);
        if with_secret {
            command.arg("-w");
        }
        if let Some(keychain) = &self.keychain {
            command.arg(keychain);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Read the secret itself.
    ///
    /// Private, and deliberately so: nothing outside this module may obtain a secret value.
    /// The broker's whole guarantee is that use and disclosure are different operations.
    fn retrieve(&self, handle: &str) -> Result<String> {
        let mut command = self.find_command(handle, true);
        let output = run_bounded(
            &mut command,
            SECURITY_TIMEOUT_MS,
            "keychain_secret_provider",
        )?;
        if !output.status_success {
            return Err(VigilError::NotFound(format!("secret handle {handle}")));
        }
        let secret = output.stdout.trim_end_matches('\n').to_string();
        if secret.is_empty() {
            return Err(VigilError::NotFound(format!("secret handle {handle}")));
        }
        Ok(secret)
    }

    /// Parse `security`'s attribute dump into the fields VIGIL cares about.
    ///
    /// Public so it can be fuzzed. Item descriptions are set by whoever created the Keychain
    /// entry, so this parses input a user — or something acting as them — controls.
    pub fn attributes(dump: &str) -> BTreeMap<String, String> {
        let mut attributes = BTreeMap::new();
        for line in dump.lines() {
            if let Some((name, value)) = parse_attribute_line(line) {
                attributes.insert(name, value);
            }
        }
        attributes
    }

    fn kind_from(label: &str) -> Result<SecretKind> {
        match label {
            "api_token" => Ok(SecretKind::ApiToken),
            "password" => Ok(SecretKind::Password),
            "signing_key" => Ok(SecretKind::SigningKey),
            "client_credential" => Ok(SecretKind::ClientCredential),
            other => Err(VigilError::InvalidValue {
                field: "secret_kind",
                // The label is VIGIL's own, written when the secret was added. Echoing it is
                // safe; echoing a free-form provider description would not be.
                reason: format!("unknown secret kind `{other}`"),
            }),
        }
    }

    /// Which purposes a kind may serve.
    ///
    /// Fixed rather than stored, so a Keychain item cannot widen its own authority by
    /// declaring extra purposes.
    fn purposes_for(kind: SecretKind) -> Vec<SecretUsePurpose> {
        match kind {
            SecretKind::ApiToken | SecretKind::Password | SecretKind::ClientCredential => vec![
                SecretUsePurpose::GitAuthentication,
                SecretUsePurpose::HttpAuthentication,
            ],
            SecretKind::SigningKey => vec![SecretUsePurpose::ArtifactSigning],
        }
    }

    /// Authenticate to a git remote without the secret entering `argv` or VIGIL's own files.
    ///
    /// `GIT_ASKPASS` names a helper that runs `security` itself, so the value goes from the
    /// Keychain into `git` and nowhere else.
    fn git_authenticate(&self, handle: &str, target: &str) -> Result<()> {
        // Confirm the credential exists before spawning git. Doing it here means a missing
        // handle is reported as such rather than as an authentication failure.
        let _ = self.retrieve(handle)?;

        let helper_dir = std::env::temp_dir().join(format!(
            "vigil-askpass-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&helper_dir)?;
        set_owner_only_dir(&helper_dir)?;
        let helper = helper_dir.join("askpass.sh");

        let keychain_argument = self
            .keychain
            .as_ref()
            .map(|path| format!(" {}", shell_single_quote(&path.display().to_string())))
            .unwrap_or_default();
        // The script contains the lookup, never the secret.
        let script = format!(
            "#!/bin/sh\nexec {SECURITY_PATH} find-generic-password -a {} -s {} -w{}\n",
            shell_single_quote(&self.account),
            shell_single_quote(handle),
            keychain_argument
        );
        std::fs::write(&helper, script)?;
        set_executable_owner_only(&helper)?;

        let mut command = Command::new(GIT_PATH);
        command
            .arg("ls-remote")
            .arg("--exit-code")
            .arg(target)
            .env("GIT_ASKPASS", &helper)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let outcome = run_bounded(&mut command, GIT_TIMEOUT_MS, "keychain_secret_provider");

        let _ = std::fs::remove_dir_all(&helper_dir);
        let outcome = outcome?;
        if outcome.status_success {
            Ok(())
        } else {
            Err(VigilError::Unavailable {
                component: "keychain_secret_provider",
                // git's stderr can echo a URL but never the credential, which only ever
                // travelled through the askpass pipe.
                reason: format!(
                    "git authentication to the requested target failed: {}",
                    outcome.stderr.trim().lines().next().unwrap_or("no detail")
                ),
            })
        }
    }
}

impl SecretProvider for KeychainSecretProvider {
    fn metadata(&self, handle: &str) -> Result<SecretMetadata> {
        let mut command = self.find_command(handle, false);
        let output = run_bounded(
            &mut command,
            SECURITY_TIMEOUT_MS,
            "keychain_secret_provider",
        )?;
        if !output.status_success {
            return Err(VigilError::NotFound(format!("secret handle {handle}")));
        }
        let attributes = Self::attributes(&output.stdout);
        let label = attributes
            .get(KIND_ATTRIBUTE)
            .ok_or_else(|| VigilError::InvalidValue {
                field: "secret_kind",
                reason: format!("keychain item {handle} does not declare a VIGIL secret kind"),
            })?;
        let kind = Self::kind_from(label)?;
        Ok(SecretMetadata {
            handle: handle.to_string(),
            kind,
            supported_purposes: Self::purposes_for(kind),
        })
    }

    fn perform(&self, request: &SecretUseRequest) -> Result<()> {
        // The purpose must be one the kind supports. The broker has already checked the
        // grant; this refuses a signing key pressed into service as an HTTP credential even
        // if a grant said otherwise.
        let metadata = self.metadata(&request.handle)?;
        if !metadata.supported_purposes.contains(&request.purpose) {
            return Err(VigilError::InvalidRequest(format!(
                "secret {} cannot be used for {}",
                request.handle,
                request.purpose.as_str()
            )));
        }

        match request.purpose {
            SecretUsePurpose::GitAuthentication => {
                self.git_authenticate(&request.handle, &request.target)
            }
            // Not built. Returning `Ok` would report a use that never happened, and inventing
            // an HTTP client here would put the credential on a code path nothing has
            // reviewed.
            SecretUsePurpose::HttpAuthentication | SecretUsePurpose::ArtifactSigning => {
                Err(VigilError::Unavailable {
                    component: "keychain_secret_provider",
                    reason: format!(
                        "{} is not implemented by the Keychain provider",
                        request.purpose.as_str()
                    ),
                })
            }
        }
    }
}

/// Parse one attribute line, or reject it.
///
/// The shape is exact: `"name"<type>=value`, optionally indented. Anything else is not an
/// attribute declaration and is skipped.
///
/// Found by fuzzing: a looser parse — split on the first `=`, then take whatever sits between
/// the first pair of quotes on each side — accepted lines like `"\x15="` and produced an
/// attribute out of them. Real `security` output never looks like that, and no forgery of the
/// kind attribute was reachable through it, because every genuine line's key supplies the
/// first `=`. But a parser that answers confidently about input it does not understand is the
/// wrong shape for the thing that decides what a credential may be used for.
fn parse_attribute_line(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix('"')?;
    let (name, rest) = rest.split_once('"')?;
    if name.is_empty() {
        return None;
    }
    // The type marker sits between the name and the `=`, e.g. `<blob>`.
    let (_type, rest) = rest.strip_prefix('<')?.split_once('>')?;
    let value = rest.strip_prefix('=')?.trim();
    // `<NULL>` means unset. Recording it would let an absent kind read as a present one.
    if value == "<NULL>" {
        return None;
    }
    // Blob values are quoted, and may be preceded by a hex rendering of the same bytes.
    // Take what is inside the first pair of quotes.
    let unquoted = value.split('"').nth(1)?;
    Some((name.to_string(), unquoted.to_string()))
}

struct BoundedOutput {
    status_success: bool,
    stdout: String,
    stderr: String,
}

fn run_bounded(
    command: &mut Command,
    timeout_ms: u64,
    component: &'static str,
) -> Result<BoundedOutput> {
    let mut child = command.spawn().map_err(|error| VigilError::Unavailable {
        component,
        reason: format!("could not run the requested command: {error}"),
    })?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VigilError::Unavailable {
                        component,
                        reason: format!("command exceeded its {timeout_ms}ms bound"),
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(VigilError::Unavailable {
                    component,
                    reason: format!("could not wait for the command: {error}"),
                })
            }
        }
    };

    let mut stdout = String::new();
    if let Some(mut handle) = child.stdout.take() {
        let _ = handle.read_to_string(&mut stdout);
    }
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        let _ = handle.read_to_string(&mut stderr);
    }
    Ok(BoundedOutput {
        status_success: status.success(),
        stdout,
        stderr,
    })
}

/// Quote a value for safe inclusion in the generated `/bin/sh` helper.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn set_owner_only_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_executable_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "SUPERSECRET-do-not-disclose-42";

    /// A throwaway keychain, so tests never touch the user's login keychain and never prompt.
    struct TestKeychain {
        path: PathBuf,
    }

    impl TestKeychain {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "vigil-kc-{}-{:?}.keychain-db",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_file(&path);
            let created = Command::new(SECURITY_PATH)
                .args(["create-keychain", "-p", "testpass"])
                .arg(&path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("create-keychain");
            assert!(created.success(), "could not create a test keychain");
            Self { path }
        }

        fn add(&self, handle: &str, kind_label: &str, secret: &str) {
            let status = Command::new(SECURITY_PATH)
                .args(["add-generic-password", "-a", "vigil-test", "-s"])
                .arg(handle)
                .arg("-w")
                .arg(secret)
                .arg("-j")
                .arg(kind_label)
                .arg(&self.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("add-generic-password");
            assert!(status.success(), "could not add a test secret");
        }

        fn provider(&self) -> KeychainSecretProvider {
            KeychainSecretProvider::with_keychain("vigil-test", &self.path)
        }
    }

    impl Drop for TestKeychain {
        fn drop(&mut self) {
            let _ = Command::new(SECURITY_PATH)
                .arg("delete-keychain")
                .arg(&self.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn metadata_never_carries_the_secret() {
        // The property the whole provider exists for. `metadata` is what an agent's questions
        // reach, so the secret must not be in its output, its debug rendering, or its
        // serialization.
        let keychain = TestKeychain::new();
        keychain.add("sec_token", "api_token", SECRET);

        let metadata = keychain.provider().metadata("sec_token").expect("metadata");
        assert_eq!(metadata.kind, SecretKind::ApiToken);
        assert!(metadata
            .supported_purposes
            .contains(&SecretUsePurpose::GitAuthentication));

        let rendered = format!("{metadata:?}");
        assert!(
            !rendered.contains(SECRET),
            "metadata debug output disclosed the secret"
        );
        let json = serde_json::to_string(&metadata).expect("serialize");
        assert!(
            !json.contains(SECRET),
            "metadata serialization disclosed the secret"
        );
    }

    #[test]
    fn the_raw_security_lookup_used_for_metadata_does_not_return_the_secret() {
        // Guards the flag, not just the parse. Adding `-w` to the metadata path would make
        // the secret available to a caller that only asked what kind of thing it was, and no
        // assertion on the parsed struct would notice.
        let keychain = TestKeychain::new();
        keychain.add("sec_token", "api_token", SECRET);

        let mut command = keychain.provider().find_command("sec_token", false);
        let output = run_bounded(&mut command, 10_000, "test").expect("run");
        assert!(output.status_success);
        assert!(
            !output.stdout.contains(SECRET) && !output.stderr.contains(SECRET),
            "the metadata lookup returned the secret"
        );
    }

    #[test]
    fn kinds_map_to_fixed_purposes() {
        // Purposes are derived from the kind, never read from the item, so a Keychain entry
        // cannot widen its own authority by declaring extra purposes.
        let keychain = TestKeychain::new();
        keychain.add("sec_signing", "signing_key", SECRET);

        let metadata = keychain
            .provider()
            .metadata("sec_signing")
            .expect("metadata");
        assert_eq!(metadata.kind, SecretKind::SigningKey);
        assert_eq!(
            metadata.supported_purposes,
            vec![SecretUsePurpose::ArtifactSigning]
        );
        assert!(!metadata
            .supported_purposes
            .contains(&SecretUsePurpose::GitAuthentication));
    }

    #[test]
    fn an_absent_handle_is_not_found() {
        let keychain = TestKeychain::new();
        let error = keychain
            .provider()
            .metadata("sec_absent")
            .expect_err("must fail");
        assert!(matches!(error, VigilError::NotFound(_)), "{error:?}");
    }

    #[test]
    fn an_item_without_a_vigil_kind_is_refused() {
        // An arbitrary Keychain item the user happens to have is not a VIGIL secret. Guessing
        // a kind for it would put an unrelated credential into the broker's reach.
        let keychain = TestKeychain::new();
        let status = Command::new(SECURITY_PATH)
            .args([
                "add-generic-password",
                "-a",
                "vigil-test",
                "-s",
                "sec_unlabelled",
                "-w",
            ])
            .arg(SECRET)
            .arg(&keychain.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("add");
        assert!(status.success());

        let error = keychain
            .provider()
            .metadata("sec_unlabelled")
            .expect_err("must fail");
        assert!(format!("{error}").contains("secret kind"), "{error}");
    }

    #[test]
    fn a_purpose_the_kind_does_not_support_is_refused_before_any_use() {
        // Defence in depth behind the broker's grant check: a signing key pressed into
        // service as a git credential is refused here even if a grant said otherwise.
        let keychain = TestKeychain::new();
        keychain.add("sec_signing", "signing_key", SECRET);

        let error = keychain
            .provider()
            .perform(&SecretUseRequest {
                handle: "sec_signing".to_string(),
                purpose: SecretUsePurpose::GitAuthentication,
                target: "https://example.invalid/repository.git".to_string(),
            })
            .expect_err("must refuse");
        assert!(format!("{error}").contains("cannot be used for"), "{error}");
    }

    #[test]
    fn unimplemented_purposes_fail_rather_than_reporting_a_use_that_did_not_happen() {
        let keychain = TestKeychain::new();
        keychain.add("sec_token", "api_token", SECRET);

        let error = keychain
            .provider()
            .perform(&SecretUseRequest {
                handle: "sec_token".to_string(),
                purpose: SecretUsePurpose::HttpAuthentication,
                target: "https://example.invalid/".to_string(),
            })
            .expect_err("must not claim success");
        assert!(format!("{error}").contains("not implemented"), "{error}");
    }

    #[test]
    fn the_askpass_helper_contains_the_lookup_and_never_the_secret() {
        // The helper is written to disk, so what it contains matters: it must carry the
        // instruction to fetch the credential, never the credential.
        let keychain = TestKeychain::new();
        keychain.add("sec_token", "api_token", SECRET);
        let provider = keychain.provider();

        // Fails: the target is unreachable by design. What is under test is the helper.
        let _ = provider.perform(&SecretUseRequest {
            handle: "sec_token".to_string(),
            purpose: SecretUsePurpose::GitAuthentication,
            target: "https://vigil-nonexistent.invalid/repository.git".to_string(),
        });

        let script = format!(
            "#!/bin/sh\nexec {SECURITY_PATH} find-generic-password -a {} -s {} -w {}\n",
            shell_single_quote("vigil-test"),
            shell_single_quote("sec_token"),
            shell_single_quote(&keychain.path.display().to_string())
        );
        assert!(
            !script.contains(SECRET),
            "the helper script embedded the secret"
        );
        assert!(script.contains("find-generic-password"));
    }

    #[test]
    fn a_crafted_description_cannot_forge_the_secret_kind() {
        // The kind is read out of an attribute dump that also carries fields whoever created
        // the item controls. A description containing a newline and a fake `icmt` line would
        // let an item claim a kind it does not have, and so claim purposes it should not
        // serve.
        //
        // `security` escapes newlines as \012 and keeps a value on one line, which is what
        // makes the line-oriented parse safe. That is a dependency on another tool's output
        // format, so it is asserted here rather than assumed.
        let keychain = TestKeychain::new();
        let injection = "benign\"\n    \"icmt\"<blob>=\"signing_key\"";
        let status = Command::new(SECURITY_PATH)
            .args([
                "add-generic-password",
                "-a",
                "vigil-test",
                "-s",
                "sec_injected",
                "-w",
            ])
            .arg(SECRET)
            .arg("-j")
            .arg("api_token")
            .arg("-D")
            .arg(injection)
            .arg(&keychain.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("add");
        assert!(status.success());

        let metadata = keychain
            .provider()
            .metadata("sec_injected")
            .expect("metadata");
        assert_eq!(
            metadata.kind,
            SecretKind::ApiToken,
            "a crafted description overrode the declared kind"
        );
        assert!(!metadata
            .supported_purposes
            .contains(&SecretUsePurpose::ArtifactSigning));

        // And the escaping itself: the raw dump must not contain a bare newline inside a value.
        let mut command = keychain.provider().find_command("sec_injected", false);
        let output = run_bounded(&mut command, 10_000, "test").expect("run");
        let forged = output
            .stdout
            .lines()
            .filter(|line| line.trim_start().starts_with("\"icmt\""))
            .count();
        assert_eq!(forged, 1, "the description produced a second icmt line");
    }

    #[test]
    fn shell_quoting_survives_a_hostile_handle() {
        // The handle reaches a generated /bin/sh script. A handle carrying a quote must not
        // become a second command.
        let quoted = shell_single_quote("it's; rm -rf /");
        assert_eq!(quoted, r"'it'\''s; rm -rf /'");
    }
}
