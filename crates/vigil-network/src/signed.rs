use super::{validate_identifier, NetworkPolicySnapshot};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vigil_common::{Result, VigilError};

pub const NETWORK_POLICY_FORMAT: &str = "vigil.signed-envelope/v1";
pub const NETWORK_POLICY_ALGORITHM: &str = "Ed25519";
const SIGNING_DOMAIN: &[u8] = b"VIGIL_NETWORK_POLICY_V1\0";
const MAX_ENVELOPE_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_PAYLOAD_BYTES: usize = 1_024 * 1_024;
const MAX_TRUSTED_KEYS: usize = 16;
const MAX_CLOCK_SKEW_MS: i64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkPolicyEnvelope {
    pub format: String,
    pub algorithm: String,
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}

pub struct NetworkPolicySigningKey {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for NetworkPolicySigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkPolicySigningKey")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl NetworkPolicySigningKey {
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let key_id = key_id.into();
        validate_identifier("key_id", &key_id, 64)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            VigilError::Config("network policy signing seed must be 32 bytes".into())
        })?;
        Ok(Self {
            key_id,
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, snapshot: &NetworkPolicySnapshot) -> Result<SignedNetworkPolicyEnvelope> {
        snapshot.validate()?;
        let payload = vigil_common::canonical::canonical_bytes(&serde_json::to_value(snapshot)?)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return rejected("network policy payload bound exceeded");
        }
        let signature = self.key.sign(&signing_input(&payload));
        Ok(SignedNetworkPolicyEnvelope {
            format: NETWORK_POLICY_FORMAT.to_string(),
            algorithm: NETWORK_POLICY_ALGORITHM.to_string(),
            key_id: self.key_id.clone(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPolicyVerifier {
    expected_instance_id: String,
    keys: BTreeMap<String, VerifyingKey>,
}

impl NetworkPolicyVerifier {
    pub fn new(expected_instance_id: impl Into<String>) -> Result<Self> {
        let expected_instance_id = expected_instance_id.into();
        validate_identifier("target_instance_id", &expected_instance_id, 128)?;
        Ok(Self {
            expected_instance_id,
            keys: BTreeMap::new(),
        })
    }

    pub fn trust_key(mut self, key_id: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let key_id = key_id.into();
        validate_identifier("key_id", &key_id, 64)?;
        if self.keys.len() >= MAX_TRUSTED_KEYS && !self.keys.contains_key(&key_id) {
            return Err(VigilError::Config(
                "network policy trusted-key bound exceeded".into(),
            ));
        }
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VigilError::Config("network policy public key must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| VigilError::Config("network policy public key is invalid".into()))?;
        self.keys.insert(key_id, key);
        Ok(self)
    }

    pub fn verify_json(&self, json: &[u8], now_unix_ms: i64) -> Result<NetworkPolicySnapshot> {
        if json.is_empty() || json.len() > MAX_ENVELOPE_BYTES {
            return rejected("network policy envelope bound exceeded");
        }
        let envelope: SignedNetworkPolicyEnvelope = serde_json::from_slice(json).map_err(|_| {
            VigilError::CapabilityRejected("malformed network policy envelope".into())
        })?;
        self.verify(&envelope, now_unix_ms)
    }

    pub fn verify(
        &self,
        envelope: &SignedNetworkPolicyEnvelope,
        now_unix_ms: i64,
    ) -> Result<NetworkPolicySnapshot> {
        if envelope.format != NETWORK_POLICY_FORMAT
            || envelope.algorithm != NETWORK_POLICY_ALGORITHM
        {
            return rejected("unsupported network policy envelope");
        }
        validate_identifier("key_id", &envelope.key_id, 64)
            .map_err(|_| VigilError::CapabilityRejected("invalid network policy key id".into()))?;
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or_else(|| VigilError::CapabilityRejected("untrusted network policy key".into()))?;
        if envelope.payload.len() > encoded_len_bound(MAX_PAYLOAD_BYTES)
            || envelope.signature.len() > encoded_len_bound(64)
        {
            return rejected("network policy encoding bound exceeded");
        }
        let payload = decode(&envelope.payload, "payload")?;
        let signature: [u8; 64] = decode(&envelope.signature, "signature")?
            .try_into()
            .map_err(|_| {
                VigilError::CapabilityRejected("invalid network policy signature".into())
            })?;
        key.verify_strict(&signing_input(&payload), &Signature::from_bytes(&signature))
            .map_err(|_| {
                VigilError::CapabilityRejected("invalid network policy signature".into())
            })?;

        // Authenticate bytes before parsing attacker-controlled policy JSON.
        let snapshot: NetworkPolicySnapshot = serde_json::from_slice(&payload).map_err(|_| {
            VigilError::CapabilityRejected("malformed network policy payload".into())
        })?;
        snapshot.validate()?;
        if snapshot.target_instance_id != self.expected_instance_id {
            return rejected("network policy targets another extension instance");
        }
        if now_unix_ms < 0
            || snapshot.issued_at_unix_ms > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || snapshot.expires_at_unix_ms <= now_unix_ms
        {
            return rejected("network policy is not currently valid");
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

fn decode(value: &str, field: &'static str) -> Result<Vec<u8>> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(VigilError::CapabilityRejected(format!(
            "invalid network policy {field} encoding"
        )));
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        VigilError::CapabilityRejected(format!("invalid network policy {field} encoding"))
    })
}

const fn encoded_len_bound(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

fn rejected<T>(reason: &str) -> Result<T> {
    Err(VigilError::CapabilityRejected(reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DestinationRule, NetworkAttribution, NetworkMode, NetworkProtocol, SessionNetworkPolicy,
        NETWORK_POLICY_SCHEMA,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;
    use vigil_endpoint::ProcessKey;

    fn snapshot() -> NetworkPolicySnapshot {
        let session = SessionNetworkPolicy {
            session_id: "ags_signed".to_string(),
            mode: NetworkMode::Enforce,
            destinations: vec![DestinationRule {
                hostname: "github.com".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: BTreeSet::from([443]),
                resolved_addresses: BTreeSet::from(["140.82.112.4".parse::<IpAddr>().expect("IP")]),
                valid_until_unix_ms: 2_000,
            }],
            max_total_flows: 10,
            max_distinct_destinations: 3,
        };
        NetworkPolicySnapshot {
            schema_version: NETWORK_POLICY_SCHEMA.to_string(),
            target_instance_id: "network-instance-signed".to_string(),
            generation: 9,
            issued_at_unix_ms: 500,
            expires_at_unix_ms: 2_000,
            sessions: BTreeMap::from([(session.session_id.clone(), session)]),
            attributions: vec![NetworkAttribution {
                process: ProcessKey::synthetic(3),
                session_id: "ags_signed".to_string(),
            }],
        }
    }

    #[test]
    fn signed_policy_round_trips_and_tampering_fails() {
        let signing = NetworkPolicySigningKey::from_seed("network-k1", &[8; 32]).expect("key");
        let verifier = NetworkPolicyVerifier::new("network-instance-signed")
            .expect("verifier")
            .trust_key("network-k1", &signing.verifying_key_bytes())
            .expect("trust");
        let envelope = signing.sign(&snapshot()).expect("sign");
        assert_eq!(
            verifier
                .verify(&envelope, 1_000)
                .expect("verify")
                .generation,
            9
        );

        let mut tampered = envelope;
        tampered.payload.replace_range(..1, "A");
        assert!(verifier.verify(&tampered, 1_000).is_err());
    }

    #[test]
    fn instance_expiry_unknown_fields_and_key_are_refused() {
        let signing = NetworkPolicySigningKey::from_seed("network-k1", &[8; 32]).expect("key");
        let envelope = signing.sign(&snapshot()).expect("sign");
        let verifier = NetworkPolicyVerifier::new("other-instance")
            .expect("verifier")
            .trust_key("network-k1", &signing.verifying_key_bytes())
            .expect("trust");
        assert!(verifier.verify(&envelope, 1_000).is_err());
        let verifier = NetworkPolicyVerifier::new("network-instance-signed")
            .expect("verifier")
            .trust_key("network-k1", &signing.verifying_key_bytes())
            .expect("trust");
        assert!(verifier.verify(&envelope, 2_000).is_err());

        let mut value = serde_json::to_value(&envelope).expect("value");
        value["unknown"] = serde_json::json!(true);
        assert!(verifier
            .verify_json(&serde_json::to_vec(&value).expect("json"), 1_000)
            .is_err());
        assert!(NetworkPolicyVerifier::new("network-instance-signed")
            .expect("verifier")
            .verify(&envelope, 1_000)
            .is_err());
    }
}
