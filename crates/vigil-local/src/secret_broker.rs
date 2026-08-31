//! Secret-use boundary for entitlement-independent development and simulation.
//!
//! The broker deliberately has no API that returns secret bytes. A provider receives a
//! structured, exactly authorized operation and performs it behind the boundary. Provider
//! failures are collapsed to safe error classes because an untrusted provider could otherwise
//! place secret material in an error string. Native Keychain-backed providers belong in a later
//! macOS integration phase; this module defines and tests the contract they must satisfy.

use crate::{BudgetCharge, BudgetDimension, LocalProfile, LocalSession, LocalStore, SessionStatus};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use vigil_common::{Result, VigilError};

const MAX_SECRET_HANDLE_BYTES: usize = 96;
const MAX_TARGET_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
    Password,
    SigningKey,
    ClientCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretUsePurpose {
    GitAuthentication,
    HttpAuthentication,
    ArtifactSigning,
}

impl SecretUsePurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitAuthentication => "git_authentication",
            Self::HttpAuthentication => "http_authentication",
            Self::ArtifactSigning => "artifact_signing",
        }
    }
}

/// Non-secret facts a provider may disclose about an opaque handle.
///
/// The fixed enums are intentional: free-form provider labels and descriptions could become a
/// covert path for secret material into agent output or the event store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub handle: String,
    pub kind: SecretKind,
    pub supported_purposes: Vec<SecretUsePurpose>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretUseRequest {
    pub handle: String,
    pub purpose: SecretUsePurpose,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretUseGrant {
    pub profile: LocalProfile,
    pub handle: String,
    pub purpose: SecretUsePurpose,
    pub target: String,
}

/// Trusted, precompiled secret-use policy.
///
/// Callers cannot add grants through the broker. A later daemon will load this state from signed
/// policy and distribute only the compact exact-match representation to the enforcement path.
#[derive(Debug, Clone, Default)]
pub struct SecretBrokerPolicy {
    grants: Vec<SecretUseGrant>,
}

impl SecretBrokerPolicy {
    pub fn new(mut grants: Vec<SecretUseGrant>) -> Result<Self> {
        for grant in &grants {
            validate_handle(&grant.handle)?;
            validate_target(grant.purpose, &grant.target)?;
        }
        grants.sort_by(|left, right| {
            (
                left.profile.as_str(),
                &left.handle,
                left.purpose,
                &left.target,
            )
                .cmp(&(
                    right.profile.as_str(),
                    &right.handle,
                    right.purpose,
                    &right.target,
                ))
        });
        grants.dedup();
        Ok(Self { grants })
    }

    pub fn deny_all() -> Self {
        Self::default()
    }

    fn permits(&self, profile: LocalProfile, request: &SecretUseRequest) -> bool {
        self.grants.iter().any(|grant| {
            grant.profile == profile
                && grant.handle == request.handle
                && grant.purpose == request.purpose
                && grant.target == request.target
        })
    }

    fn permits_metadata(&self, profile: LocalProfile, handle: &str) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.profile == profile && grant.handle == handle)
    }
}

/// Provider boundary: use happens here, but secret bytes never cross back into the broker.
pub trait SecretProvider: Send + Sync {
    fn metadata(&self, handle: &str) -> Result<SecretMetadata>;
    fn perform(&self, request: &SecretUseRequest) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMetadataResult {
    pub event_id: String,
    pub correlation_id: String,
    pub metadata: SecretMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretUseResult {
    pub event_id: String,
    pub reservation_id: String,
    pub correlation_id: String,
    pub handle: String,
    pub purpose: SecretUsePurpose,
    pub target: String,
    pub secret_bytes_disclosed: u64,
}

pub struct SecretBroker<'a> {
    store: &'a LocalStore,
    provider: &'a dyn SecretProvider,
    policy: &'a SecretBrokerPolicy,
}

impl<'a> SecretBroker<'a> {
    pub fn new(
        store: &'a LocalStore,
        provider: &'a dyn SecretProvider,
        policy: &'a SecretBrokerPolicy,
    ) -> Self {
        Self {
            store,
            provider,
            policy,
        }
    }

    pub fn metadata(&self, session_id: &str, handle: &str) -> Result<SecretMetadataResult> {
        let correlation_id = new_correlation_id();
        let (_, profile) = self.session_context(session_id)?;
        if let Err(error) = validate_handle(handle) {
            self.record_denial(session_id, &correlation_id, "secret.metadata", None, &error)?;
            return Err(error);
        }
        if !self.policy.permits_metadata(profile, handle) {
            let error = VigilError::Unauthorized(
                "secret metadata requires a trusted profile-scoped grant".to_string(),
            );
            self.record_denial(
                session_id,
                &correlation_id,
                "secret.metadata",
                Some(handle),
                &error,
            )?;
            return Err(error);
        }
        let metadata = match self.provider.metadata(handle) {
            Ok(metadata) => metadata,
            Err(provider_error) => {
                let error = sanitize_provider_error(provider_error);
                self.record_failure(
                    session_id,
                    &correlation_id,
                    "secret.metadata",
                    Some(handle),
                    None,
                    &error,
                )?;
                return Err(error);
            }
        };
        if let Err(error) = validate_metadata(handle, &metadata) {
            self.record_failure(
                session_id,
                &correlation_id,
                "secret.metadata",
                Some(handle),
                None,
                &error,
            )?;
            return Err(error);
        }
        let event = self.store.append_event(
            session_id,
            "secret",
            "secret.metadata",
            Some("DISCLOSED_METADATA"),
            &correlation_id,
            &json!({
                "handle": metadata.handle,
                "kind": metadata.kind,
                "supported_purposes": metadata.supported_purposes,
                "secret_material_disclosed": false,
            }),
        )?;
        Ok(SecretMetadataResult {
            event_id: event.event_id,
            correlation_id,
            metadata,
        })
    }

    pub fn use_secret(
        &self,
        session_id: &str,
        request: &SecretUseRequest,
    ) -> Result<SecretUseResult> {
        let correlation_id = new_correlation_id();
        let (_, profile) = self.session_context(session_id)?;
        if let Err(error) = validate_request(request) {
            self.record_denial(session_id, &correlation_id, "secret.use", None, &error)?;
            return Err(error);
        }
        if !self.policy.permits(profile, request) {
            let error = VigilError::Unauthorized(
                "secret use requires an exact trusted profile, purpose, and target grant"
                    .to_string(),
            );
            self.record_denial(
                session_id,
                &correlation_id,
                "secret.use",
                Some(&request.handle),
                &error,
            )?;
            return Err(error);
        }

        let metadata = match self.provider.metadata(&request.handle) {
            Ok(metadata) => metadata,
            Err(provider_error) => {
                let error = sanitize_provider_error(provider_error);
                self.record_failure(
                    session_id,
                    &correlation_id,
                    "secret.use",
                    Some(&request.handle),
                    None,
                    &error,
                )?;
                return Err(error);
            }
        };
        if let Err(error) = validate_metadata(&request.handle, &metadata) {
            self.record_failure(
                session_id,
                &correlation_id,
                "secret.use",
                Some(&request.handle),
                None,
                &error,
            )?;
            return Err(error);
        }
        if !metadata.supported_purposes.contains(&request.purpose) {
            let error = VigilError::Unauthorized(
                "secret provider does not support the authorized purpose".to_string(),
            );
            self.record_denial(
                session_id,
                &correlation_id,
                "secret.use",
                Some(&request.handle),
                &error,
            )?;
            return Err(error);
        }

        let reservation = match self.store.reserve_budget(
            session_id,
            &correlation_id,
            &[BudgetCharge::new(BudgetDimension::BrokeredSecretUses, 1)],
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.store.append_event(
                    session_id,
                    "budget",
                    "secret.use",
                    Some("DENY"),
                    &correlation_id,
                    &json!({"error_class": error.class()}),
                )?;
                return Err(error);
            }
        };

        if let Err(provider_error) = self.provider.perform(request) {
            self.store.refund_budget(&reservation.id)?;
            let error = sanitize_provider_error(provider_error);
            self.record_failure(
                session_id,
                &correlation_id,
                "secret.use",
                Some(&request.handle),
                Some(&reservation.id),
                &error,
            )?;
            return Err(error);
        }

        if let Err(error) = self.store.commit_budget(&reservation.id) {
            let _ = self.store.append_event(
                session_id,
                "budget",
                "budget.reconciliation_failed",
                Some("ERROR"),
                &correlation_id,
                &json!({
                    "reservation_id": reservation.id,
                    "operation_executed": true,
                    "error_class": error.class(),
                }),
            );
            return Err(error);
        }
        let event = self.store.append_event(
            session_id,
            "secret",
            "secret.use",
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "handle": request.handle,
                "purpose": request.purpose,
                "target": request.target,
                "reservation_id": reservation.id,
                "determining_policy": "permit-exact-brokered-secret-use",
                "secret_material_disclosed": false,
                "secret_bytes_disclosed": 0,
                "native_keychain_provider": false,
            }),
        )?;
        Ok(SecretUseResult {
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            handle: request.handle.clone(),
            purpose: request.purpose,
            target: request.target.clone(),
            secret_bytes_disclosed: 0,
        })
    }

    /// Raw export is a distinct capability and is not implemented by this Phase 2 interface.
    pub fn export(&self, session_id: &str, handle: &str) -> Result<()> {
        let correlation_id = new_correlation_id();
        self.session_context(session_id)?;
        let safe_handle = validate_handle(handle).ok().map(|()| handle);
        let error = VigilError::Unauthorized(
            "raw secret export is unavailable to local agent sessions".to_string(),
        );
        self.record_denial(
            session_id,
            &correlation_id,
            "secret.export",
            safe_handle,
            &error,
        )?;
        Err(error)
    }

    fn session_context(&self, session_id: &str) -> Result<(LocalSession, LocalProfile)> {
        let session = self
            .store
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        if session.status != SessionStatus::Running
            || session.enforcement_posture != "semantic_enforced"
        {
            return Err(VigilError::Unauthorized(
                "secret broker requires a running semantic-enforced session".to_string(),
            ));
        }
        let profile = session.profile.parse()?;
        Ok((session, profile))
    }

    fn record_denial(
        &self,
        session_id: &str,
        correlation_id: &str,
        action: &str,
        handle: Option<&str>,
        error: &VigilError,
    ) -> Result<()> {
        self.store.append_event(
            session_id,
            "secret",
            action,
            Some("DENY"),
            correlation_id,
            &json!({
                "handle": handle,
                "error_class": error.class(),
                "secret_material_disclosed": false,
            }),
        )?;
        Ok(())
    }

    fn record_failure(
        &self,
        session_id: &str,
        correlation_id: &str,
        action: &str,
        handle: Option<&str>,
        reservation_id: Option<&str>,
        error: &VigilError,
    ) -> Result<()> {
        self.store.append_event(
            session_id,
            "secret",
            action,
            Some("FAILED"),
            correlation_id,
            &json!({
                "handle": handle,
                "reservation_id": reservation_id,
                "error_class": error.class(),
                "secret_material_disclosed": false,
            }),
        )?;
        Ok(())
    }
}

fn validate_request(request: &SecretUseRequest) -> Result<()> {
    validate_handle(&request.handle)?;
    validate_target(request.purpose, &request.target)
}

fn validate_handle(handle: &str) -> Result<()> {
    if !handle.starts_with("sec_")
        || handle.len() <= "sec_".len()
        || handle.len() > MAX_SECRET_HANDLE_BYTES
        || !handle.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
    {
        return Err(VigilError::InvalidValue {
            field: "secret_handle",
            reason: "handle must be a bounded opaque `sec_` identifier".to_string(),
        });
    }
    Ok(())
}

fn validate_target(purpose: SecretUsePurpose, target: &str) -> Result<()> {
    if target.is_empty()
        || target.len() > MAX_TARGET_BYTES
        || !target.is_ascii()
        || target.chars().any(char::is_control)
    {
        return Err(VigilError::InvalidValue {
            field: "target",
            reason: "target must be non-empty, bounded, ASCII, and contain no controls".to_string(),
        });
    }
    match purpose {
        SecretUsePurpose::GitAuthentication | SecretUsePurpose::HttpAuthentication => {
            let parsed = url::Url::parse(target).map_err(|_| VigilError::InvalidValue {
                field: "target",
                reason: "authentication target must be an absolute HTTPS URL".to_string(),
            })?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(VigilError::InvalidValue {
                    field: "target",
                    reason: "authentication target must be HTTPS and contain no userinfo, query, or fragment"
                        .to_string(),
                });
            }
            Ok(())
        }
        SecretUsePurpose::ArtifactSigning => {
            let Some(digest) = target.strip_prefix("sha256:") else {
                return Err(VigilError::InvalidValue {
                    field: "target",
                    reason: "signing target must be a lowercase SHA-256 digest".to_string(),
                });
            };
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(VigilError::InvalidValue {
                    field: "target",
                    reason: "signing target must be a lowercase SHA-256 digest".to_string(),
                });
            }
            Ok(())
        }
    }
}

fn validate_metadata(expected_handle: &str, metadata: &SecretMetadata) -> Result<()> {
    validate_handle(&metadata.handle)?;
    if metadata.handle != expected_handle {
        return Err(VigilError::AuditIntegrity(
            "secret provider returned metadata for a different handle".to_string(),
        ));
    }
    if metadata.supported_purposes.is_empty() || metadata.supported_purposes.len() > 8 {
        return Err(VigilError::InvalidValue {
            field: "supported_purposes",
            reason: "provider returned an empty or oversized purpose set".to_string(),
        });
    }
    Ok(())
}

fn sanitize_provider_error(error: VigilError) -> VigilError {
    VigilError::Unavailable {
        component: "secret_provider",
        reason: format!("provider operation failed ({})", error.class()),
    }
}

fn new_correlation_id() -> String {
    format!("cor_{}", uuid::Uuid::new_v4().simple())
}

#[derive(Debug, Clone)]
struct SimulatedSecret {
    kind: SecretKind,
    supported_purposes: Vec<SecretUsePurpose>,
}

#[derive(Debug, Default)]
struct SimulatedState {
    secrets: BTreeMap<String, SimulatedSecret>,
    metadata_attempts: usize,
    use_attempts: usize,
    fail_use: bool,
}

/// Deterministic provider for CI. It models availability and use, never secret bytes.
#[derive(Debug, Clone, Default)]
pub struct SimulatedSecretProvider {
    state: Arc<Mutex<SimulatedState>>,
}

impl SimulatedSecretProvider {
    pub fn register(
        &self,
        handle: &str,
        kind: SecretKind,
        mut supported_purposes: Vec<SecretUsePurpose>,
    ) -> Result<()> {
        validate_handle(handle)?;
        if supported_purposes.is_empty() || supported_purposes.len() > 8 {
            return Err(VigilError::InvalidValue {
                field: "supported_purposes",
                reason: "simulated secret needs one to eight supported purposes".to_string(),
            });
        }
        supported_purposes.sort_unstable();
        supported_purposes.dedup();
        self.lock()?.secrets.insert(
            handle.to_string(),
            SimulatedSecret {
                kind,
                supported_purposes,
            },
        );
        Ok(())
    }

    pub fn set_use_failure(&self, fail: bool) -> Result<()> {
        self.lock()?.fail_use = fail;
        Ok(())
    }

    pub fn attempts(&self) -> Result<(usize, usize)> {
        let state = self.lock()?;
        Ok((state.metadata_attempts, state.use_attempts))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SimulatedState>> {
        self.state.lock().map_err(|_| VigilError::Unavailable {
            component: "simulated_secret_provider",
            reason: "simulator state is unavailable".to_string(),
        })
    }
}

impl SecretProvider for SimulatedSecretProvider {
    fn metadata(&self, handle: &str) -> Result<SecretMetadata> {
        let mut state = self.lock()?;
        state.metadata_attempts += 1;
        let secret = state
            .secrets
            .get(handle)
            .cloned()
            .ok_or_else(|| VigilError::NotFound("secret handle".to_string()))?;
        Ok(SecretMetadata {
            handle: handle.to_string(),
            kind: secret.kind,
            supported_purposes: secret.supported_purposes,
        })
    }

    fn perform(&self, request: &SecretUseRequest) -> Result<()> {
        let mut state = self.lock()?;
        state.use_attempts += 1;
        if state.fail_use {
            return Err(VigilError::Unavailable {
                component: "simulated_secret_provider",
                reason: "simulated secret use failed".to_string(),
            });
        }
        if state.secrets.contains_key(&request.handle) {
            Ok(())
        } else {
            Err(VigilError::NotFound("secret handle".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewSession;
    use std::path::PathBuf;

    const HANDLE: &str = "sec_github_readonly";
    const TARGET: &str = "https://github.com/example/repository.git";

    fn fixture(profile: LocalProfile) -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-secret-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: profile.as_str().to_string(),
                workspace,
                executable: "vigil-secret-broker".to_string(),
                argv: vec!["vigil-secret-broker".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .activate_semantic_session(&session.id)
            .expect("activate session");
        (root, store, session.id)
    }

    fn policy(profile: LocalProfile) -> SecretBrokerPolicy {
        SecretBrokerPolicy::new(vec![SecretUseGrant {
            profile,
            handle: HANDLE.to_string(),
            purpose: SecretUsePurpose::GitAuthentication,
            target: TARGET.to_string(),
        }])
        .expect("policy")
    }

    fn provider() -> SimulatedSecretProvider {
        let provider = SimulatedSecretProvider::default();
        provider
            .register(
                HANDLE,
                SecretKind::ApiToken,
                vec![SecretUsePurpose::GitAuthentication],
            )
            .expect("register secret");
        provider
    }

    fn consumed(store: &LocalStore, session: &str) -> u64 {
        store
            .budget_snapshot(session)
            .expect("budget")
            .into_iter()
            .find(|counter| counter.dimension == BudgetDimension::BrokeredSecretUses)
            .expect("secret counter")
            .consumed
    }

    #[test]
    fn metadata_discloses_only_fixed_non_secret_fields() {
        let (root, store, session) = fixture(LocalProfile::DeveloperStandard);
        let provider = provider();
        let policy = policy(LocalProfile::DeveloperStandard);
        let result = SecretBroker::new(&store, &provider, &policy)
            .metadata(&session, HANDLE)
            .expect("metadata");
        assert_eq!(result.metadata.kind, SecretKind::ApiToken);
        assert_eq!(consumed(&store, &session), 0);
        assert_eq!(provider.attempts().expect("attempts"), (1, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_grant_performs_brokered_use_and_consumes_budget() {
        let (root, store, session) = fixture(LocalProfile::DeveloperStandard);
        let provider = provider();
        let policy = policy(LocalProfile::DeveloperStandard);
        let request = SecretUseRequest {
            handle: HANDLE.to_string(),
            purpose: SecretUsePurpose::GitAuthentication,
            target: TARGET.to_string(),
        };
        let result = SecretBroker::new(&store, &provider, &policy)
            .use_secret(&session, &request)
            .expect("secret use");
        assert_eq!(result.secret_bytes_disclosed, 0);
        assert_eq!(consumed(&store, &session), 1);
        assert_eq!(provider.attempts().expect("attempts"), (1, 1));
        let events = serde_json::to_string(&store.events_for_session(&session).expect("events"))
            .expect("serialize events");
        assert!(events.contains("secret_material_disclosed\":false"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn target_or_profile_mutation_denies_before_provider_access() {
        let (root, store, session) = fixture(LocalProfile::Research);
        let provider = provider();
        let policy = policy(LocalProfile::DeveloperStandard);
        let request = SecretUseRequest {
            handle: HANDLE.to_string(),
            purpose: SecretUsePurpose::GitAuthentication,
            target: format!("{TARGET}.attacker.example"),
        };
        let error = SecretBroker::new(&store, &provider, &policy)
            .use_secret(&session, &request)
            .expect_err("mutated request must deny");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        assert_eq!(provider.attempts().expect("attempts"), (0, 0));
        assert_eq!(consumed(&store, &session), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn provider_failure_refunds_budget_and_sanitizes_error() {
        struct LeakyProvider;
        const SECRET: &str = "vigil-provider-secret-marker";
        impl SecretProvider for LeakyProvider {
            fn metadata(&self, handle: &str) -> Result<SecretMetadata> {
                Ok(SecretMetadata {
                    handle: handle.to_string(),
                    kind: SecretKind::ApiToken,
                    supported_purposes: vec![SecretUsePurpose::GitAuthentication],
                })
            }

            fn perform(&self, _request: &SecretUseRequest) -> Result<()> {
                Err(VigilError::Unavailable {
                    component: "leaky_provider",
                    reason: format!("failed while using {SECRET}"),
                })
            }
        }

        let (root, store, session) = fixture(LocalProfile::DeveloperStandard);
        let policy = policy(LocalProfile::DeveloperStandard);
        let request = SecretUseRequest {
            handle: HANDLE.to_string(),
            purpose: SecretUsePurpose::GitAuthentication,
            target: TARGET.to_string(),
        };
        let error = SecretBroker::new(&store, &LeakyProvider, &policy)
            .use_secret(&session, &request)
            .expect_err("provider must fail");
        assert!(!error.to_string().contains(SECRET));
        assert_eq!(consumed(&store, &session), 0);
        let events = serde_json::to_string(&store.events_for_session(&session).expect("events"))
            .expect("serialize events");
        assert!(!events.contains(SECRET));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn raw_export_is_always_denied_without_provider_access_or_budget() {
        let (root, store, session) = fixture(LocalProfile::DeveloperStandard);
        let provider = provider();
        let policy = policy(LocalProfile::DeveloperStandard);
        let error = SecretBroker::new(&store, &provider, &policy)
            .export(&session, HANDLE)
            .expect_err("raw export must deny");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        assert_eq!(provider.attempts().expect("attempts"), (0, 0));
        assert_eq!(consumed(&store, &session), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn zero_budget_profile_fails_before_secret_use() {
        let (root, store, session) = fixture(LocalProfile::DeveloperRestricted);
        let provider = provider();
        let policy = policy(LocalProfile::DeveloperRestricted);
        let request = SecretUseRequest {
            handle: HANDLE.to_string(),
            purpose: SecretUsePurpose::GitAuthentication,
            target: TARGET.to_string(),
        };
        let error = SecretBroker::new(&store, &provider, &policy)
            .use_secret(&session, &request)
            .expect_err("zero budget must deny");
        assert!(matches!(error, VigilError::BudgetExhausted(_)));
        assert_eq!(provider.attempts().expect("attempts"), (1, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn credential_bearing_or_ambiguous_targets_cannot_enter_policy() {
        for target in [
            "https://user:vigil-secret-marker@github.com/example/repository.git",
            "https://github.com/example/repository.git?token=vigil-secret-marker",
            "http://github.com/example/repository.git",
        ] {
            let result = SecretBrokerPolicy::new(vec![SecretUseGrant {
                profile: LocalProfile::DeveloperStandard,
                handle: HANDLE.to_string(),
                purpose: SecretUsePurpose::GitAuthentication,
                target: target.to_string(),
            }]);
            assert!(result.is_err(), "unsafe target accepted: {target}");
        }
    }
}
