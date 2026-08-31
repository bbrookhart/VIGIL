use super::{FastPathState, SessionEnforcementPolicy, MAX_PROTECTED_PREFIXES, MAX_SESSIONS};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vigil_common::{Result, VigilError};

pub const ENDPOINT_POLICY_SCHEMA: &str = "vigil.endpoint-policy/v1";
pub const ENDPOINT_POLICY_FORMAT: &str = "vigil.signed-envelope/v1";
pub const ENDPOINT_POLICY_ALGORITHM: &str = "Ed25519";

const SIGNING_DOMAIN: &[u8] = b"VIGIL_ENDPOINT_POLICY_V1\0";
const MAX_ENVELOPE_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_PAYLOAD_BYTES: usize = 1_024 * 1_024;
const MAX_KEY_ID_BYTES: usize = 64;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const MAX_TRUSTED_KEYS: usize = 16;
const MAX_SNAPSHOT_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS: i64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicySnapshot {
    pub schema_version: String,
    pub target_instance_id: String,
    pub generation: u64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub sessions: Vec<SessionEnforcementPolicy>,
    pub protected_prefixes: Vec<String>,
}

impl EndpointPolicySnapshot {
    pub fn new(
        target_instance_id: impl Into<String>,
        generation: u64,
        issued_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        mut sessions: Vec<SessionEnforcementPolicy>,
        mut protected_prefixes: Vec<String>,
    ) -> Result<Self> {
        sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        protected_prefixes.sort();
        protected_prefixes.dedup();
        let snapshot = Self {
            schema_version: ENDPOINT_POLICY_SCHEMA.to_string(),
            target_instance_id: target_instance_id.into(),
            generation,
            issued_at_unix_ms,
            expires_at_unix_ms,
            sessions,
            protected_prefixes,
        };
        snapshot.validate_structure()?;
        Ok(snapshot)
    }

    pub fn compile(&self, deadline_safety_margin_ns: u64) -> Result<FastPathState> {
        self.validate_structure()?;
        FastPathState::new(
            self.sessions.clone(),
            self.protected_prefixes.clone(),
            deadline_safety_margin_ns,
        )
    }

    fn validate_structure(&self) -> Result<()> {
        if self.schema_version != ENDPOINT_POLICY_SCHEMA {
            return rejected("unsupported endpoint policy schema");
        }
        validate_identifier(
            "target_instance_id",
            &self.target_instance_id,
            MAX_INSTANCE_ID_BYTES,
        )?;
        if self.generation == 0 {
            return rejected("endpoint policy generation must be positive");
        }
        if self.issued_at_unix_ms < 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self
                .expires_at_unix_ms
                .saturating_sub(self.issued_at_unix_ms)
                > MAX_SNAPSHOT_LIFETIME_MS
        {
            return rejected("endpoint policy validity window is invalid");
        }
        if self.sessions.len() > MAX_SESSIONS {
            return rejected("endpoint policy session bound exceeded");
        }
        if self.protected_prefixes.len() > MAX_PROTECTED_PREFIXES {
            return rejected("endpoint policy protected-prefix bound exceeded");
        }
        let mut session_ids = BTreeSet::new();
        for policy in &self.sessions {
            policy.validate()?;
            if !session_ids.insert(&policy.session_id) {
                return rejected("endpoint policy contains a duplicate session");
            }
        }
        // Construction validates every protected path and all remaining state bounds.
        let _ = FastPathState::new(self.sessions.clone(), self.protected_prefixes.clone(), 0)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEndpointPolicyEnvelope {
    pub format: String,
    pub algorithm: String,
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}

pub struct EndpointPolicySigningKey {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for EndpointPolicySigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointPolicySigningKey")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl EndpointPolicySigningKey {
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let key_id = key_id.into();
        validate_identifier("key_id", &key_id, MAX_KEY_ID_BYTES)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            VigilError::Config("endpoint policy signing seed must be 32 bytes".into())
        })?;
        Ok(Self {
            key_id,
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, snapshot: &EndpointPolicySnapshot) -> Result<SignedEndpointPolicyEnvelope> {
        snapshot.validate_structure()?;
        let value = serde_json::to_value(snapshot)?;
        let payload = vigil_common::canonical::canonical_bytes(&value)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return rejected("endpoint policy payload bound exceeded");
        }
        let signature = self.key.sign(&signing_input(&payload));
        Ok(SignedEndpointPolicyEnvelope {
            format: ENDPOINT_POLICY_FORMAT.to_string(),
            algorithm: ENDPOINT_POLICY_ALGORITHM.to_string(),
            key_id: self.key_id.clone(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EndpointPolicyVerifier {
    expected_instance_id: String,
    keys: BTreeMap<String, VerifyingKey>,
}

impl EndpointPolicyVerifier {
    pub fn new(expected_instance_id: impl Into<String>) -> Result<Self> {
        let expected_instance_id = expected_instance_id.into();
        validate_identifier(
            "target_instance_id",
            &expected_instance_id,
            MAX_INSTANCE_ID_BYTES,
        )?;
        Ok(Self {
            expected_instance_id,
            keys: BTreeMap::new(),
        })
    }

    pub fn trust_key(mut self, key_id: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let key_id = key_id.into();
        validate_identifier("key_id", &key_id, MAX_KEY_ID_BYTES)?;
        if self.keys.len() >= MAX_TRUSTED_KEYS && !self.keys.contains_key(&key_id) {
            return Err(VigilError::Config(
                "endpoint policy trusted-key bound exceeded".into(),
            ));
        }
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            VigilError::Config("endpoint policy public key must be 32 bytes".into())
        })?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| VigilError::Config("endpoint policy public key is invalid".into()))?;
        self.keys.insert(key_id, key);
        Ok(self)
    }

    pub fn verify_json(
        &self,
        envelope_json: &[u8],
        now_unix_ms: i64,
    ) -> Result<EndpointPolicySnapshot> {
        if envelope_json.len() > MAX_ENVELOPE_BYTES {
            return rejected("endpoint policy envelope bound exceeded");
        }
        let envelope: SignedEndpointPolicyEnvelope = serde_json::from_slice(envelope_json)
            .map_err(|_| {
                VigilError::CapabilityRejected("malformed endpoint policy envelope".into())
            })?;
        self.verify(&envelope, now_unix_ms)
    }

    pub fn verify(
        &self,
        envelope: &SignedEndpointPolicyEnvelope,
        now_unix_ms: i64,
    ) -> Result<EndpointPolicySnapshot> {
        if envelope.format != ENDPOINT_POLICY_FORMAT
            || envelope.algorithm != ENDPOINT_POLICY_ALGORITHM
        {
            return rejected("unsupported endpoint policy envelope");
        }
        validate_identifier("key_id", &envelope.key_id, MAX_KEY_ID_BYTES)
            .map_err(|_| VigilError::CapabilityRejected("invalid endpoint policy key id".into()))?;
        let key = self.keys.get(&envelope.key_id).ok_or_else(|| {
            VigilError::CapabilityRejected("untrusted endpoint policy key".into())
        })?;
        if envelope.payload.len() > encoded_len_bound(MAX_PAYLOAD_BYTES)
            || envelope.signature.len() > encoded_len_bound(64)
        {
            return rejected("endpoint policy encoding bound exceeded");
        }
        let payload = decode_base64url(&envelope.payload, "payload")?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return rejected("endpoint policy payload bound exceeded");
        }
        let signature = decode_base64url(&envelope.signature, "signature")?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| {
            VigilError::CapabilityRejected("invalid endpoint policy signature".into())
        })?;
        key.verify_strict(&signing_input(&payload), &Signature::from_bytes(&signature))
            .map_err(|_| {
                VigilError::CapabilityRejected("invalid endpoint policy signature".into())
            })?;

        // Parse only after authentication so attacker-controlled JSON never reaches policy decoding.
        let snapshot: EndpointPolicySnapshot = serde_json::from_slice(&payload).map_err(|_| {
            VigilError::CapabilityRejected("malformed endpoint policy payload".into())
        })?;
        snapshot.validate_structure()?;
        if snapshot.target_instance_id != self.expected_instance_id {
            return rejected("endpoint policy targets another extension instance");
        }
        if now_unix_ms < 0
            || snapshot.issued_at_unix_ms > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || snapshot.expires_at_unix_ms <= now_unix_ms
        {
            return rejected("endpoint policy is not currently valid");
        }
        Ok(snapshot)
    }
}

fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNING_DOMAIN.len() + payload.len());
    input.extend_from_slice(SIGNING_DOMAIN);
    input.extend_from_slice(payload);
    input
}

fn decode_base64url(value: &str, field: &'static str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(VigilError::CapabilityRejected(format!(
            "invalid endpoint policy {field} encoding"
        )));
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        VigilError::CapabilityRejected(format!("invalid endpoint policy {field} encoding"))
    })
}

const fn encoded_len_bound(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

fn validate_identifier(field: &'static str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(VigilError::InvalidValue {
            field,
            reason: "identifier is empty, oversized, or contains unsafe characters".into(),
        });
    }
    Ok(())
}

fn rejected<T>(reason: &str) -> Result<T> {
    Err(VigilError::CapabilityRejected(reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const INSTANCE: &str = "endpoint-instance-1";

    fn policy() -> SessionEnforcementPolicy {
        SessionEnforcementPolicy::new(
            "session-1",
            vec!["/Users/test/workspace".into()],
            BTreeSet::from(["/usr/bin/env".into()]),
        )
        .expect("policy")
    }

    fn snapshot() -> EndpointPolicySnapshot {
        EndpointPolicySnapshot::new(
            INSTANCE,
            7,
            NOW - 1_000,
            NOW + 60_000,
            vec![policy()],
            vec!["/Users/test/.ssh".into()],
        )
        .expect("snapshot")
    }

    fn signing() -> EndpointPolicySigningKey {
        EndpointPolicySigningKey::from_seed("endpoint-test-k1", &[7; 32]).expect("key")
    }

    fn verifier(signing: &EndpointPolicySigningKey) -> EndpointPolicyVerifier {
        EndpointPolicyVerifier::new(INSTANCE)
            .expect("verifier")
            .trust_key("endpoint-test-k1", &signing.verifying_key_bytes())
            .expect("trust key")
    }

    #[test]
    fn a_valid_signed_snapshot_verifies_and_compiles() {
        let signing = signing();
        let envelope = signing.sign(&snapshot()).expect("sign");
        let verified = verifier(&signing).verify(&envelope, NOW).expect("verify");
        assert_eq!(verified, snapshot());
        assert!(verified.compile(5_000_000).is_ok());
    }

    #[test]
    fn payload_or_signature_tampering_is_rejected_before_decode() {
        let signing = signing();
        let mut envelope = signing.sign(&snapshot()).expect("sign");
        envelope.payload.replace_range(..1, "A");
        assert!(verifier(&signing).verify(&envelope, NOW).is_err());

        let mut envelope = signing.sign(&snapshot()).expect("sign");
        envelope.signature.replace_range(..1, "A");
        assert!(verifier(&signing).verify(&envelope, NOW).is_err());
    }

    #[test]
    fn wrong_instance_unknown_key_expiry_and_future_issue_are_rejected() {
        let signing = signing();
        let envelope = signing.sign(&snapshot()).expect("sign");
        assert!(EndpointPolicyVerifier::new("different-instance")
            .expect("verifier")
            .trust_key("endpoint-test-k1", &signing.verifying_key_bytes())
            .expect("key")
            .verify(&envelope, NOW)
            .is_err());
        assert!(EndpointPolicyVerifier::new(INSTANCE)
            .expect("verifier")
            .verify(&envelope, NOW)
            .is_err());
        assert!(verifier(&signing).verify(&envelope, NOW + 60_000).is_err());

        let future = EndpointPolicySnapshot::new(
            INSTANCE,
            8,
            NOW + MAX_CLOCK_SKEW_MS + 1,
            NOW + MAX_CLOCK_SKEW_MS + 60_000,
            vec![policy()],
            vec![],
        )
        .expect("future snapshot");
        assert!(verifier(&signing)
            .verify(&signing.sign(&future).expect("sign"), NOW)
            .is_err());
    }

    #[test]
    fn envelope_and_payload_unknown_fields_are_rejected() {
        let signing = signing();
        let envelope = signing.sign(&snapshot()).expect("sign");
        let mut envelope_value = serde_json::to_value(&envelope).expect("json");
        envelope_value["surprise"] = serde_json::json!(true);
        assert!(verifier(&signing)
            .verify_json(&serde_json::to_vec(&envelope_value).expect("json"), NOW)
            .is_err());

        let mut payload_value = serde_json::to_value(snapshot()).expect("json");
        payload_value["surprise"] = serde_json::json!(true);
        let payload = vigil_common::canonical::canonical_bytes(&payload_value).expect("canonical");
        let signature = signing.key.sign(&signing_input(&payload));
        let envelope = SignedEndpointPolicyEnvelope {
            format: ENDPOINT_POLICY_FORMAT.into(),
            algorithm: ENDPOINT_POLICY_ALGORITHM.into(),
            key_id: "endpoint-test-k1".into(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        assert!(verifier(&signing).verify(&envelope, NOW).is_err());
    }

    #[test]
    fn deserialized_policy_fields_are_revalidated() {
        let invalid = EndpointPolicySnapshot {
            schema_version: ENDPOINT_POLICY_SCHEMA.into(),
            target_instance_id: INSTANCE.into(),
            generation: 1,
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 1_000,
            sessions: vec![SessionEnforcementPolicy {
                session_id: "session-1".into(),
                workspace_roots: vec!["relative/workspace".into()],
                allowed_executables: BTreeSet::new(),
            }],
            protected_prefixes: vec![],
        };
        assert!(signing().sign(&invalid).is_err());
        assert!(invalid.compile(5_000_000).is_err());
    }

    #[test]
    fn committed_swift_fixture_is_the_exact_rust_signed_contract() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../extensions/endpoint-security/Tests/VigilEndpointAdapterTests/Resources/endpoint_policy_v1.json"
        ))
        .expect("fixture json");
        let signing = EndpointPolicySigningKey::from_seed("endpoint-fixture-k1", &[7; 32])
            .expect("fixture key");
        let snapshot = EndpointPolicySnapshot::new(
            "endpoint-instance-fixture",
            42,
            NOW - 1_000,
            NOW + 60_000,
            vec![SessionEnforcementPolicy::new(
                "session-fixture-1",
                vec!["/Users/test/workspace".into()],
                BTreeSet::from(["/usr/bin/env".into()]),
            )
            .expect("policy")],
            vec!["/Users/test/.ssh".into(), "/Users/test/.aws".into()],
        )
        .expect("snapshot");
        assert_eq!(
            fixture["trusted_public_key"],
            serde_json::json!(URL_SAFE_NO_PAD.encode(signing.verifying_key_bytes()))
        );
        assert_eq!(
            fixture["envelope"],
            serde_json::to_value(signing.sign(&snapshot).expect("sign")).expect("json")
        );
    }
}
