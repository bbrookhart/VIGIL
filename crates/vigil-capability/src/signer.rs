//! Issuing and verifying capabilities.
//!
//! The two halves are deliberately separate types with separate key material: Core holds a
//! [`CapabilityIssuer`] with a private key, the Gateway holds a [`CapabilityVerifier`] with
//! only public keys. A compromised gateway therefore cannot mint capabilities for itself —
//! privilege separation (spec §57) expressed in the type system.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::sync::Arc;
use vigil_common::{Clock, Result, Timestamp, VigilError};

use crate::claims::{CapabilityClaims, PresentedAction, CLAIMS_VERSION};
use crate::nonce::{NonceStore, NonceVerdict};
use crate::token::{self, TokenHeader, ALG_ED25519};

/// Identifier for a signing key, carried in the token header so keys can rotate.
pub type KeyId = String;

/// Private signing material.
///
/// Deliberately not `Clone` and not `Debug`-printable in a way that reveals bytes: the seed
/// is the root of the whole enforcement chain.
pub struct SigningKeyMaterial {
    key_id: KeyId,
    key: SigningKey,
}

impl std::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyMaterial")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl SigningKeyMaterial {
    /// Load from a 32-byte seed.
    pub fn from_seed(key_id: impl Into<KeyId>, seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            VigilError::Config("capability signing seed must be exactly 32 bytes".to_string())
        })?;
        Ok(Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Generate fresh key material.
    ///
    /// Intended for tests and for `make dev`. Production deployments load a seed from a KMS
    /// or secret store so that restarting Core does not invalidate in-flight capabilities and
    /// so the key can be rotated and audited.
    pub fn generate(key_id: impl Into<KeyId>) -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The public half, for distribution to verifiers.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

/// Mints capabilities. Lives in VIGIL Core.
#[derive(Debug)]
pub struct CapabilityIssuer {
    signing: SigningKeyMaterial,
    clock: Arc<dyn Clock>,
}

impl CapabilityIssuer {
    pub fn new(signing: SigningKeyMaterial, clock: Arc<dyn Clock>) -> Self {
        Self { signing, clock }
    }

    pub fn key_id(&self) -> &str {
        self.signing.key_id()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Mint a capability for an authorized action.
    ///
    /// `ttl_seconds` is clamped to [`crate::MAX_CAPABILITY_TTL_SECONDS`] rather than
    /// rejected, so a misconfiguration produces a short capability instead of an outage —
    /// but it can never produce a long-lived one.
    pub fn issue(
        &self,
        mut claims: CapabilityClaims,
        ttl_seconds: i64,
    ) -> Result<(String, CapabilityClaims)> {
        let now = self.clock.now();
        let ttl = ttl_seconds.clamp(1, crate::MAX_CAPABILITY_TTL_SECONDS);

        claims.version = CLAIMS_VERSION.to_string();
        claims.issued_at = now;
        claims.expires_at = now + chrono::Duration::seconds(ttl);
        claims.nonce = generate_nonce();
        if claims.max_uses == 0 {
            claims.max_uses = 1;
        }

        // Canonical claim bytes so an issuer and a verifier on different platforms agree,
        // and so the claims hash is stable for audit correlation.
        let claims_json =
            vigil_common::canonical::canonical_bytes(&serde_json::to_value(&claims)?)?;
        let header = TokenHeader {
            alg: ALG_ED25519.to_string(),
            kid: self.signing.key_id.clone(),
        };
        let header_b64 = base64_url(&serde_json::to_vec(&header)?);
        let claims_b64 = base64_url(&claims_json);
        let signature = self
            .signing
            .key
            .sign(&token::signing_input(&header_b64, &claims_b64));

        // Encoded through the shared helper so the issuer and the parser can never drift
        // apart on the token layout.
        let token = token::encode(&header, &claims_json, &signature.to_bytes())?;
        debug_assert!(token::parse(&token).is_ok(), "issued token must parse");
        Ok((token, claims))
    }
}

/// Verifies capabilities. Lives in VIGIL Gateway. Holds no private key.
#[derive(Debug)]
pub struct CapabilityVerifier {
    keys: HashMap<KeyId, VerifyingKey>,
    clock: Arc<dyn Clock>,
    nonces: Arc<dyn NonceStore>,
    leeway_seconds: i64,
}

impl CapabilityVerifier {
    pub fn new(clock: Arc<dyn Clock>, nonces: Arc<dyn NonceStore>) -> Self {
        Self {
            keys: HashMap::new(),
            clock,
            nonces,
            leeway_seconds: crate::CLOCK_SKEW_LEEWAY_SECONDS,
        }
    }

    /// Trust a public key. Multiple keys may be trusted at once to permit rotation.
    pub fn trust_key(mut self, key_id: impl Into<KeyId>, key: VerifyingKey) -> Self {
        self.keys.insert(key_id.into(), key);
        self
    }

    /// Verify a capability and consume one use of it.
    ///
    /// The order of operations is itself a security control:
    ///
    /// 1. parse (bounded work)
    /// 2. algorithm allowlist and key lookup
    /// 3. **signature** — so unauthenticated callers cannot probe binding checks or burn
    ///    nonces belonging to real capabilities
    /// 4. claims deserialization
    /// 5. lifetime
    /// 6. bindings against what was actually presented
    /// 7. **nonce consumption last** — a capability rejected for any other reason must not
    ///    have a use deducted, or an attacker could exhaust a legitimate capability by
    ///    replaying it against the wrong action
    pub fn verify_and_consume(
        &self,
        token_str: &str,
        presented: &PresentedAction,
    ) -> Result<VerifiedCapability> {
        let parsed = token::parse(token_str)?;

        if parsed.header.alg != ALG_ED25519 {
            return Err(VigilError::CapabilityRejected(
                "unsupported capability signature algorithm".to_string(),
            ));
        }
        let key = self.keys.get(&parsed.header.kid).ok_or_else(|| {
            VigilError::CapabilityRejected("capability signed by an untrusted key".to_string())
        })?;

        let signature_bytes: [u8; 64] = parsed.signature.as_slice().try_into().map_err(|_| {
            VigilError::CapabilityRejected("capability signature has the wrong length".to_string())
        })?;
        let signature = Signature::from_bytes(&signature_bytes);
        // `verify_strict` rejects small-order and non-canonical public keys, which plain
        // `verify` accepts and which permit signature malleability.
        key.verify_strict(&parsed.signed_payload, &signature)
            .map_err(|_| {
                VigilError::CapabilityRejected("capability signature is invalid".to_string())
            })?;

        let claims: CapabilityClaims =
            serde_json::from_slice(&parsed.claims_json).map_err(|e| {
                VigilError::CapabilityRejected(format!("capability claims are unreadable: {e}"))
            })?;

        let now = self.clock.now();
        claims.check_lifetime(now, self.leeway_seconds)?;
        claims.check_binding(presented)?;

        match self
            .nonces
            .consume(&claims.nonce, claims.max_uses, claims.expires_at)?
        {
            NonceVerdict::Accepted { use_number } => Ok(VerifiedCapability {
                claims,
                use_number,
                verified_at: now,
            }),
            NonceVerdict::Replay { previous_uses } => Err(VigilError::CapabilityRejected(format!(
                "capability already redeemed ({previous_uses} prior use(s))"
            ))),
        }
    }

    /// Verify without consuming, for previewing a capability in the console.
    ///
    /// Never used on the execution path: a preview that consumed a use would let an
    /// operator's inspection break a live action.
    pub fn inspect(&self, token_str: &str) -> Result<CapabilityClaims> {
        let parsed = token::parse(token_str)?;
        let key = self.keys.get(&parsed.header.kid).ok_or_else(|| {
            VigilError::CapabilityRejected("capability signed by an untrusted key".to_string())
        })?;
        let signature_bytes: [u8; 64] = parsed.signature.as_slice().try_into().map_err(|_| {
            VigilError::CapabilityRejected("capability signature has the wrong length".to_string())
        })?;
        key.verify_strict(
            &parsed.signed_payload,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| {
            VigilError::CapabilityRejected("capability signature is invalid".to_string())
        })?;
        Ok(serde_json::from_slice(&parsed.claims_json)?)
    }
}

/// A capability that verified and whose use was recorded.
#[derive(Debug, Clone)]
pub struct VerifiedCapability {
    pub claims: CapabilityClaims,
    /// Which use this was, 1-based.
    pub use_number: u32,
    pub verified_at: Timestamp,
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 256 bits of OS randomness. Nonces must be unguessable so an attacker cannot pre-burn a
/// capability that has not been issued yet.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    base64_url(&bytes)
}
