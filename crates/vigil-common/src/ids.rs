//! Validated identifier newtypes.
//!
//! # Why
//!
//! Tenant isolation (a GA blocker) is enforced by comparing identifiers. If every id is a
//! `String`, nothing stops a refactor from comparing an agent id against a tenant id, or
//! from threading an attacker-chosen id into a log line, a file path or a metrics label.
//! Distinct types make those mistakes compile errors.
//!
//! # What
//!
//! Each id is a newtype over a validated `String`: 1–128 characters drawn from
//! `[A-Za-z0-9._:-]`. The charset is deliberately narrow — it is safe to interpolate into
//! log lines, metric labels, URL path segments and file names without further escaping,
//! which removes a whole class of injection through identifier fields.
//!
//! # Failure mode
//!
//! Construction is fallible and never silently truncates or sanitizes. A malformed id is an
//! invalid request, rejected before it reaches policy evaluation.

use crate::error::{Result, VigilError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

const MAX_ID_LEN: usize = 128;

/// Validate an identifier string against the shared VIGIL id grammar.
pub fn validate_id(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(VigilError::InvalidValue {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    if value.len() > MAX_ID_LEN {
        return Err(VigilError::InvalidValue {
            field,
            reason: format!("must be at most {MAX_ID_LEN} bytes"),
        });
    }
    if let Some(bad) = value
        .bytes()
        .find(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')))
    {
        return Err(VigilError::InvalidValue {
            field,
            reason: format!("contains disallowed byte 0x{bad:02x}; allowed set is [A-Za-z0-9._:-]"),
        });
    }
    Ok(())
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Construct after validation.
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_id($field, &value)?;
                Ok(Self(value))
            }

            /// Generate a fresh random identifier.
            pub fn generate() -> Self {
                Self(format!("{}-{}", $field, uuid::Uuid::new_v4().simple()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = VigilError;
            fn from_str(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_type!(
    /// The isolation boundary. Every stored row and every decision is scoped by this.
    TenantId,
    "tenant"
);
id_type!(
    /// A deployment stage (`prod`, `staging`) within a tenant. Policy differs per environment.
    EnvironmentId,
    "env"
);
id_type!(
    /// A registered agent definition — the thing that has a remit.
    AgentId,
    "agent"
);
id_type!(
    /// One running instance of an agent. Budgets and behavioural envelopes attach here.
    AgentInstanceId,
    "instance"
);
id_type!(
    /// A conversation/task scope across which provenance and taint propagate.
    SessionId,
    "session"
);
id_type!(
    /// A single security event.
    EventId,
    "event"
);
id_type!(
    /// A human or machine principal on whose behalf an agent acts.
    PrincipalId,
    "principal"
);
id_type!(
    /// A registered tool, as named in a tool manifest.
    ToolId,
    "tool"
);
id_type!(
    /// A minted execution capability.
    CapabilityId,
    "cap"
);
id_type!(
    /// A human approval record.
    ApprovalId,
    "approval"
);
id_type!(
    /// A policy bundle version.
    PolicyBundleId,
    "bundle"
);
id_type!(
    /// A correlated incident.
    IncidentId,
    "incident"
);
id_type!(
    /// A node in the provenance graph.
    ProvenanceNodeId,
    "prov"
);

impl EventId {
    /// Event ids are always generated, never client-supplied, so a caller cannot
    /// overwrite or collide with an existing audit record.
    pub fn new_random() -> Self {
        Self::generate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_conventional_identifiers() {
        assert!(TenantId::new("acme-corp").is_ok());
        assert!(AgentId::new("customer-support-assistant").is_ok());
        assert!(ToolId::new("mcp:mail.example:send_email").is_ok());
    }

    #[test]
    fn rejects_identifiers_that_are_unsafe_to_interpolate() {
        // path traversal, newline injection into logs, and label breaking
        assert!(TenantId::new("../other-tenant").is_err());
        assert!(TenantId::new("acme\nfake-line").is_err());
        assert!(TenantId::new("acme corp").is_err());
        assert!(TenantId::new("acme\"}").is_err());
        assert!(TenantId::new("").is_err());
        assert!(TenantId::new("a".repeat(129)).is_err());
    }

    #[test]
    fn ids_of_different_kinds_are_not_interchangeable() {
        // Compile-time property: this test documents it, the type system enforces it.
        let tenant = TenantId::new("acme").unwrap();
        let agent = AgentId::new("acme").unwrap();
        assert_eq!(tenant.as_str(), agent.as_str());
        // `tenant == agent` does not compile, which is the point.
    }

    #[test]
    fn deserialization_validates() {
        assert!(serde_json::from_str::<TenantId>("\"ok-1\"").is_ok());
        assert!(serde_json::from_str::<TenantId>("\"../etc/passwd\"").is_err());
    }

    #[test]
    fn generated_ids_are_valid_and_unique() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a, b);
        assert!(validate_id("session", a.as_str()).is_ok());
    }
}
