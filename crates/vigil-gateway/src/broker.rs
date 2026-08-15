//! VIGIL Broker: credential custody.
//!
//! # Why
//!
//! Invariant 6: privileged credentials never become normal model context. The reason is
//! blunt — anything in an agent's context can be exfiltrated by anything that can influence
//! that agent, and indirect prompt injection means a web page can influence it. A credential
//! the agent never sees cannot be leaked by the agent.
//!
//! # What
//!
//! The broker holds credentials, hands them to a tool backend *inside* an authorized
//! transaction, and never returns them to the caller. [`ResolvedCredential`] deliberately has
//! no `Display`, no `Serialize` and a `Debug` that prints a reference rather than a value, so
//! putting one in a log or a response requires deliberately reaching for
//! [`ResolvedCredential::expose`].
//!
//! # Failure mode
//!
//! A tool that declares brokered credentials but has none registered fails the execution
//! rather than proceeding unauthenticated — an unauthenticated call to a protected API is
//! either an error or a much worse security event, and neither should be silent.

use std::collections::HashMap;
use std::sync::Mutex;
use vigil_capability::CapabilityClaims;
use vigil_common::{Result, VigilError};

/// A reference to a credential, safe to put anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CredentialRef(pub String);

/// A credential value, resolved for exactly one transaction.
///
/// No `Serialize`, no `Display`. The only way to read the value is [`Self::expose`], which is
/// named so a review notices it.
#[derive(Clone)]
pub struct ResolvedCredential {
    reference: CredentialRef,
    value: String,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("reference", &self.reference)
            .field("value", &"[redacted]")
            .finish()
    }
}

impl ResolvedCredential {
    /// Read the secret. Call sites are audited; do not add convenience wrappers.
    pub fn expose(&self) -> &str {
        &self.value
    }

    pub fn reference(&self) -> &CredentialRef {
        &self.reference
    }

    /// A non-reversible identifier for logging which credential was used.
    pub fn usage_fingerprint(&self) -> String {
        vigil_common::redact::fingerprint(&self.value)
    }
}

/// Which credential a tool uses.
#[derive(Debug, Clone)]
struct Registration {
    reference: CredentialRef,
    value: String,
}

/// Credential custody for the gateway.
#[derive(Debug, Default)]
pub struct CredentialBroker {
    by_tool: Mutex<HashMap<String, Registration>>,
    usage_log: Mutex<Vec<CredentialUsage>>,
}

/// A record that a credential was used — without the credential.
#[derive(Debug, Clone)]
pub struct CredentialUsage {
    pub tool: String,
    pub reference: CredentialRef,
    pub capability_id: String,
    pub agent_id: String,
    pub fingerprint: String,
}

impl CredentialBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a credential for a tool.
    ///
    /// In production this is a handle to a KMS, an OAuth client, or a workload-identity
    /// exchange that mints a short-lived token per transaction. The in-memory form here is
    /// what `make dev` and the tests use; the interface is the same either way.
    pub fn register(
        &self,
        tool: impl Into<String>,
        reference: CredentialRef,
        value: impl Into<String>,
    ) -> Result<()> {
        let mut by_tool = self.by_tool.lock().map_err(|_| VigilError::Unavailable {
            component: "credential_broker",
            reason: "lock poisoned".to_string(),
        })?;
        by_tool.insert(
            tool.into(),
            Registration {
                reference,
                value: value.into(),
            },
        );
        Ok(())
    }

    /// Resolve the credential for an authorized transaction.
    ///
    /// Takes the capability claims rather than a bare tool name so the usage record ties a
    /// credential use to the exact authorization that permitted it. A credential used without
    /// a corresponding capability is the signature of a compromised gateway, and this makes
    /// that visible in the log.
    pub fn resolve(
        &self,
        tool: &str,
        claims: &CapabilityClaims,
    ) -> Result<Option<ResolvedCredential>> {
        let by_tool = self.by_tool.lock().map_err(|_| VigilError::Unavailable {
            component: "credential_broker",
            reason: "lock poisoned".to_string(),
        })?;
        let Some(registration) = by_tool.get(tool) else {
            return Ok(None);
        };

        let resolved = ResolvedCredential {
            reference: registration.reference.clone(),
            value: registration.value.clone(),
        };

        if let Ok(mut log) = self.usage_log.lock() {
            log.push(CredentialUsage {
                tool: tool.to_string(),
                reference: resolved.reference.clone(),
                capability_id: claims.capability_id.to_string(),
                agent_id: claims.agent_id.to_string(),
                fingerprint: resolved.usage_fingerprint(),
            });
        }

        Ok(Some(resolved))
    }

    /// Credential usage records, for the console and for incident review.
    pub fn usage_log(&self) -> Vec<CredentialUsage> {
        self.usage_log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn is_registered(&self, tool: &str) -> bool {
        self.by_tool
            .lock()
            .map(|t| t.contains_key(tool))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> CapabilityClaims {
        CapabilityClaims {
            version: "vcap.v1".to_string(),
            capability_id: "cap-1".parse().unwrap(),
            tenant_id: "acme".parse().unwrap(),
            environment_id: "prod".parse().unwrap(),
            agent_id: "support".parse().unwrap(),
            agent_instance_id: "inst-1".parse().unwrap(),
            session_id: "s-1".parse().unwrap(),
            principal_id: "user-1".parse().unwrap(),
            action_kind: "tool_call".to_string(),
            tool_id: Some("send_email".parse().unwrap()),
            operation: "send".to_string(),
            target_resource: None,
            action_hash: vigil_common::ContentHash::sha256(b"a"),
            remit_version: "support@3".to_string(),
            policy_bundle_version: "bundle-1".parse().unwrap(),
            approval_id: None,
            constraints: vec![],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
            nonce: "n".to_string(),
            max_uses: 1,
        }
    }

    #[test]
    fn a_resolved_credential_never_renders_its_value() {
        let broker = CredentialBroker::new();
        broker
            .register(
                "send_email",
                CredentialRef("mail-provider-api-key".to_string()),
                "sk-live-supersecretvalue",
            )
            .unwrap();
        let resolved = broker.resolve("send_email", &claims()).unwrap().unwrap();

        let rendered = format!("{resolved:?}");
        assert!(!rendered.contains("supersecretvalue"), "{rendered}");
        assert!(rendered.contains("[redacted]"));
        // The value is reachable only through the explicitly named accessor.
        assert_eq!(resolved.expose(), "sk-live-supersecretvalue");
    }

    #[test]
    fn credential_use_is_logged_without_the_credential() {
        let broker = CredentialBroker::new();
        broker
            .register(
                "send_email",
                CredentialRef("k".to_string()),
                "sk-live-abc123def456",
            )
            .unwrap();
        broker.resolve("send_email", &claims()).unwrap();

        let log = broker.usage_log();
        assert_eq!(log.len(), 1);
        let rendered = format!("{log:?}");
        assert!(!rendered.contains("sk-live-abc123def456"));
        assert!(rendered.contains("fp:"));
        // The usage ties back to the capability that authorized it.
        assert_eq!(log[0].capability_id, "cap-1");
        assert_eq!(log[0].agent_id, "support");
    }

    #[test]
    fn an_unregistered_tool_resolves_to_no_credential_rather_than_a_default() {
        let broker = CredentialBroker::new();
        assert!(broker.resolve("unknown_tool", &claims()).unwrap().is_none());
        assert!(!broker.is_registered("unknown_tool"));
    }
}
