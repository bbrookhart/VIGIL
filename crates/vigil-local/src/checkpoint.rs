//! Signed commitments to the local event chain.
//!
//! # Why
//!
//! The hash chain in [`crate::store`] makes an *edit* evident: change one record and every
//! record after it stops linking. It does not make a *rewrite* evident. An attacker who can
//! write the database can recompute every link hash from their own version of history and
//! reset `sqlite_sequence` to match, producing a shorter or altered log that verifies
//! perfectly. `vigil audit verify-local` has always said so in its own output.
//!
//! A checkpoint is a signature over `(sequence, head_hash)` made with a key that lives
//! outside the database. Rewriting the chain changes the head hash at every covered
//! sequence, and without the key the attacker cannot produce a checkpoint that matches
//! their rewrite. The last checkpoint therefore pins everything at or before it.
//!
//! # Assumptions
//!
//! This closes exactly one hole: an attacker with **database** write access. It does not
//! help against one who also holds the signing key. On a host where the seed sits in a
//! `0600` file beside the database, that raises the bar from "write the database" to "write
//! the database and read the key file" — real, but not the same as holding the key off-host,
//! which is what actually closes it. See ADR 0040.
//!
//! # Failure mode
//!
//! [`LocalCheckpointSigner::sign`] is only ever reached after the chain verifies. Signing a
//! chain that already fails would launder a rewrite into a signed commitment, which is worse
//! than having no checkpoint at all.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vigil_common::{Result, Timestamp, VigilError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Domain separator for local chain checkpoints.
///
/// Distinct from `vigil-audit`'s portable checkpoints so that a signature over one can never
/// be replayed as the other, even when both are made with the same seed.
const CHECKPOINT_DOMAIN: &[u8] = b"VIGIL_LOCAL_CHAIN_CHECKPOINT_V1\0";

/// A signed commitment to the chain head at one sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCheckpoint {
    /// Sequence of the last event this checkpoint covers.
    pub sequence: i64,
    /// The recomputed chain head at that sequence.
    pub head_hash: String,
    pub signed_at: Timestamp,
    pub key_id: String,
    /// Base64url Ed25519 signature over the canonical body.
    pub signature: String,
}

impl LocalCheckpoint {
    /// The bytes that are signed. Excludes the signature itself.
    fn signing_payload(
        sequence: i64,
        head_hash: &str,
        signed_at: Timestamp,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        let body = serde_json::json!({
            "sequence": sequence,
            "head_hash": head_hash,
            "signed_at": signed_at.to_rfc3339(),
            "key_id": key_id,
        });
        let mut bytes = CHECKPOINT_DOMAIN.to_vec();
        bytes.extend_from_slice(&vigil_common::canonical::canonical_bytes(&body)?);
        Ok(bytes)
    }
}

/// Private key material for signing checkpoints.
pub struct LocalCheckpointSigner {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for LocalCheckpointSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCheckpointSigner")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl LocalCheckpointSigner {
    /// Load from a 32-byte seed, matching the seeds `vigil keys generate` writes.
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            VigilError::Config("checkpoint signing seed must be exactly 32 bytes".to_string())
        })?;
        Ok(Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign a chain head.
    ///
    /// Callers must have verified the chain first; [`crate::LocalStore::write_checkpoint`] is
    /// the only path that does, and is the only intended caller.
    pub(crate) fn sign(
        &self,
        sequence: i64,
        head_hash: &str,
        signed_at: Timestamp,
    ) -> Result<LocalCheckpoint> {
        let payload =
            LocalCheckpoint::signing_payload(sequence, head_hash, signed_at, &self.key_id)?;
        Ok(LocalCheckpoint {
            sequence,
            head_hash: head_hash.to_string(),
            signed_at,
            key_id: self.key_id.clone(),
            signature: B64.encode(self.key.sign(&payload).to_bytes()),
        })
    }
}

/// The public halves a verifier trusts.
///
/// Verification is only meaningful against keys supplied from outside the database. A
/// verifier trusting no keys reports every checkpoint as unknown rather than skipping it,
/// because silently passing an unverifiable checkpoint would report a rewritten chain as
/// clean.
#[derive(Debug, Default, Clone)]
pub struct LocalCheckpointVerifier {
    keys: HashMap<String, VerifyingKey>,
}

impl LocalCheckpointVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust_key(mut self, key_id: impl Into<String>, key: VerifyingKey) -> Self {
        self.keys.insert(key_id.into(), key);
        self
    }

    /// Trust the public half of a seed, the common case for a single-host install.
    pub fn trust_seed(self, key_id: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let signer = LocalCheckpointSigner::from_seed("verify-only", seed)?;
        Ok(self.trust_key(key_id, signer.verifying_key()))
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check one checkpoint's signature.
    ///
    /// Returns the reason it failed, or `None` when it verified.
    pub(crate) fn check(&self, checkpoint: &LocalCheckpoint) -> Option<CheckpointFailure> {
        let Some(key) = self.keys.get(&checkpoint.key_id) else {
            return Some(CheckpointFailure::UnknownKey {
                key_id: checkpoint.key_id.clone(),
            });
        };
        let Ok(raw) = B64.decode(&checkpoint.signature) else {
            return Some(CheckpointFailure::InvalidSignature);
        };
        let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
            return Some(CheckpointFailure::InvalidSignature);
        };
        let Ok(payload) = LocalCheckpoint::signing_payload(
            checkpoint.sequence,
            &checkpoint.head_hash,
            checkpoint.signed_at,
            &checkpoint.key_id,
        ) else {
            return Some(CheckpointFailure::InvalidSignature);
        };
        match key.verify(&payload, &Signature::from_bytes(&bytes)) {
            Ok(()) => None,
            Err(_) => Some(CheckpointFailure::InvalidSignature),
        }
    }
}

/// Why a checkpoint did not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckpointFailure {
    /// Signed by a key the verifier was not given.
    UnknownKey { key_id: String },
    /// The signature did not verify: the checkpoint itself was altered or forged.
    InvalidSignature,
    /// The signature is genuine but commits to a different head than the events produce.
    /// This is the tell-tale of a rewritten log.
    HeadMismatch { signed: String, recomputed: String },
    /// The log ends before a sequence a genuine checkpoint covers: the tail was removed.
    TruncatedBelowCheckpoint { last_sequence: i64 },
}

impl std::fmt::Display for CheckpointFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey { key_id } => {
                write!(f, "signed by untrusted key {key_id}")
            }
            Self::InvalidSignature => write!(f, "signature did not verify"),
            Self::HeadMismatch { signed, recomputed } => write!(
                f,
                "commits to head {signed} but the events produce {recomputed}; \
                 the log was rewritten"
            ),
            Self::TruncatedBelowCheckpoint { last_sequence } => write!(
                f,
                "covers a sequence past the end of the log, which stops at {last_sequence}; \
                 the tail was removed"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn signer() -> LocalCheckpointSigner {
        LocalCheckpointSigner::from_seed("local-1", &seed(7)).expect("signer")
    }

    #[test]
    fn a_genuine_checkpoint_verifies() {
        let signer = signer();
        let checkpoint = signer
            .sign(4, "abc123", Timestamp::default())
            .expect("sign");
        let verifier =
            LocalCheckpointVerifier::new().trust_key(signer.key_id(), signer.verifying_key());
        assert_eq!(verifier.check(&checkpoint), None);
    }

    #[test]
    fn an_altered_head_breaks_the_signature() {
        let signer = signer();
        let mut checkpoint = signer
            .sign(4, "abc123", Timestamp::default())
            .expect("sign");
        checkpoint.head_hash = "rewritten".to_string();
        let verifier =
            LocalCheckpointVerifier::new().trust_key(signer.key_id(), signer.verifying_key());
        assert_eq!(
            verifier.check(&checkpoint),
            Some(CheckpointFailure::InvalidSignature)
        );
    }

    #[test]
    fn an_altered_sequence_breaks_the_signature() {
        // The sequence is inside the signed body, so a checkpoint cannot be moved to cover a
        // different point in the log.
        let signer = signer();
        let mut checkpoint = signer
            .sign(4, "abc123", Timestamp::default())
            .expect("sign");
        checkpoint.sequence = 9;
        let verifier =
            LocalCheckpointVerifier::new().trust_key(signer.key_id(), signer.verifying_key());
        assert_eq!(
            verifier.check(&checkpoint),
            Some(CheckpointFailure::InvalidSignature)
        );
    }

    #[test]
    fn another_key_cannot_forge_a_checkpoint() {
        let attacker = LocalCheckpointSigner::from_seed("local-1", &seed(9)).expect("signer");
        let forged = attacker
            .sign(4, "abc123", Timestamp::default())
            .expect("sign");
        // Same key_id, different key: the verifier must reject on the signature, not be
        // fooled by the label.
        let verifier =
            LocalCheckpointVerifier::new().trust_key("local-1", signer().verifying_key());
        assert_eq!(
            verifier.check(&forged),
            Some(CheckpointFailure::InvalidSignature)
        );
    }

    #[test]
    fn an_untrusted_key_id_is_reported_not_skipped() {
        let signer = signer();
        let checkpoint = signer
            .sign(4, "abc123", Timestamp::default())
            .expect("sign");
        let verifier = LocalCheckpointVerifier::new();
        assert_eq!(
            verifier.check(&checkpoint),
            Some(CheckpointFailure::UnknownKey {
                key_id: "local-1".to_string()
            })
        );
    }

    #[test]
    fn a_portable_audit_signature_cannot_be_replayed_here() {
        // Both checkpoint kinds may be made with the same seed. The domain separator is what
        // stops a signature over one being presented as the other.
        let signer = signer();
        let checkpoint = signer
            .sign(4, "abc123", Timestamp::default())
            .expect("sign");
        let body = serde_json::json!({
            "sequence": 4,
            "head_hash": "abc123",
            "signed_at": Timestamp::default().to_rfc3339(),
            "key_id": "local-1",
        });
        let undomained = vigil_common::canonical::canonical_bytes(&body).expect("canonical");
        let signed = LocalCheckpoint::signing_payload(4, "abc123", Timestamp::default(), "local-1")
            .expect("payload");
        assert_ne!(signed, undomained);
        assert!(signed.starts_with(CHECKPOINT_DOMAIN));
        assert_eq!(checkpoint.sequence, 4);
    }
}
