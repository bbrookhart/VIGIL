//! Tool backends.
//!
//! A backend is the thing that actually performs the side effect. The registry is what the
//! gateway dispatches to *after* a capability has verified, and it is deliberately the only
//! place in the system that can reach a real tool.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vigil_common::ids::CapabilityId;
use vigil_common::Result;

/// What the gateway hands a backend.
#[derive(Debug)]
pub struct ToolInvocation {
    pub tool: String,
    pub operation: String,
    pub arguments: serde_json::Value,
    /// Credentials resolved by the broker. Present only for tools that declare brokering.
    pub credentials: Option<crate::broker::ResolvedCredential>,
    pub capability_id: CapabilityId,
}

/// What a backend returns.
#[derive(Debug)]
pub struct ToolOutcome {
    pub output: serde_json::Value,
}

/// Something that performs a real side effect.
#[async_trait]
pub trait ToolBackend: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    async fn invoke(&self, invocation: ToolInvocation) -> Result<ToolOutcome>;
}

/// Every tool the gateway can reach.
#[derive(Debug, Default)]
pub struct ToolRegistry {
    backends: HashMap<String, Arc<dyn ToolBackend>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(mut self, backend: Arc<dyn ToolBackend>) -> Self {
        self.backends.insert(backend.name().to_string(), backend);
        self
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ToolBackend>> {
        self.backends.get(name).cloned()
    }

    pub fn len(&self) -> usize {
        self.backends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }
}

/// A recording tool backend used by the demos, examples and end-to-end tests.
///
/// It exists so a test can assert the thing that actually matters: **was the real tool
/// invoked at all?** A blocked action that still reached the mail provider is a failure even
/// if VIGIL logged a `DENY`, and only a backend that counts its own invocations can prove
/// the difference.
#[derive(Debug)]
pub struct RecordingBackend {
    name: String,
    invocations: Mutex<Vec<RecordedInvocation>>,
    response: serde_json::Value,
}

/// One invocation, as the backend saw it.
#[derive(Debug, Clone)]
pub struct RecordedInvocation {
    pub operation: String,
    pub arguments: serde_json::Value,
    pub had_credentials: bool,
}

impl RecordingBackend {
    pub fn new(name: impl Into<String>, response: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            invocations: Mutex::new(Vec::new()),
            response,
        }
    }

    /// How many times the real side effect happened.
    pub fn invocation_count(&self) -> usize {
        self.invocations.lock().map(|i| i.len()).unwrap_or(0)
    }

    pub fn invocations(&self) -> Vec<RecordedInvocation> {
        self.invocations
            .lock()
            .map(|i| i.clone())
            .unwrap_or_default()
    }

    /// Whether the tool was ever reached. The assertion Gate 1 turns on.
    pub fn was_never_invoked(&self) -> bool {
        self.invocation_count() == 0
    }
}

#[async_trait]
impl ToolBackend for RecordingBackend {
    fn name(&self) -> &str {
        &self.name
    }

    async fn invoke(&self, invocation: ToolInvocation) -> Result<ToolOutcome> {
        if let Ok(mut log) = self.invocations.lock() {
            log.push(RecordedInvocation {
                operation: invocation.operation,
                arguments: invocation.arguments,
                had_credentials: invocation.credentials.is_some(),
            });
        }
        Ok(ToolOutcome {
            output: self.response.clone(),
        })
    }
}

/// A backend that always fails, for testing the attempted-but-failed reporting path.
#[derive(Debug)]
pub struct FailingBackend {
    name: String,
}

impl FailingBackend {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl ToolBackend for FailingBackend {
    fn name(&self) -> &str {
        &self.name
    }

    async fn invoke(&self, _invocation: ToolInvocation) -> Result<ToolOutcome> {
        Err(vigil_common::VigilError::Unavailable {
            component: "tool_backend",
            reason: "simulated backend failure".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_recording_backend_counts_real_invocations() {
        let backend = Arc::new(RecordingBackend::new("t", serde_json::json!({"ok": true})));
        assert!(backend.was_never_invoked());
        backend
            .invoke(ToolInvocation {
                tool: "t".to_string(),
                operation: "send".to_string(),
                arguments: serde_json::json!({"to": "a@b.example"}),
                credentials: None,
                capability_id: CapabilityId::generate(),
            })
            .await
            .unwrap();
        assert_eq!(backend.invocation_count(), 1);
        assert!(!backend.was_never_invoked());
    }

    #[test]
    fn the_registry_resolves_by_name_only() {
        let registry = ToolRegistry::new().register(Arc::new(RecordingBackend::new(
            "send_email",
            serde_json::json!({}),
        )));
        assert!(registry.get("send_email").is_some());
        assert!(registry.get("send_email_v2").is_none());
        assert_eq!(registry.len(), 1);
    }
}
