//! Content hashing with an explicit algorithm label.
//!
//! Hashes appear in approvals, capabilities and audit chains, all of which outlive any
//! particular algorithm choice. Every hash therefore carries its algorithm inline
//! (`sha256:1a2b…`) so a historical decision stays verifiable after a migration, and so a
//! verifier can refuse an algorithm it no longer trusts rather than guessing from length.

use crate::error::{Result, VigilError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Hash algorithms VIGIL can produce or verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = VigilError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "sha256" => Ok(Self::Sha256),
            other => Err(VigilError::InvalidValue {
                field: "hash_algorithm",
                reason: format!("unsupported algorithm `{other}`"),
            }),
        }
    }
}

/// An algorithm-tagged content hash, rendered as `<alg>:<lowercase hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash {
    algorithm: HashAlgorithm,
    hex: String,
}

impl ContentHash {
    /// Hash raw bytes with the current default algorithm.
    pub fn sha256(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self {
            algorithm: HashAlgorithm::Sha256,
            hex: hex::encode(digest),
        }
    }

    /// Hash a JSON value through the canonical form.
    ///
    /// This is the only correct way to hash a security-relevant document: hashing
    /// `serde_json::to_vec` directly would make the hash depend on key insertion order.
    pub fn canonical_json(value: &serde_json::Value) -> Result<Self> {
        Ok(Self::sha256(&crate::canonical::canonical_bytes(value)?))
    }

    /// Hash any serializable value through the canonical form.
    pub fn canonical<T: Serialize>(value: &T) -> Result<Self> {
        let value = serde_json::to_value(value)?;
        Self::canonical_json(&value)
    }

    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Constant-time equality.
    ///
    /// Hash comparison guards capability and approval binding, so it must not leak the
    /// position of the first differing byte through timing.
    pub fn ct_eq(&self, other: &Self) -> bool {
        if self.algorithm != other.algorithm || self.hex.len() != other.hex.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.hex.as_bytes().iter().zip(other.hex.as_bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Short prefix for display in a console or log line. Never use for comparison.
    pub fn short(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm.label(),
            &self.hex[..12.min(self.hex.len())]
        )
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm.label(), self.hex)
    }
}

impl FromStr for ContentHash {
    type Err = VigilError;
    fn from_str(s: &str) -> Result<Self> {
        let (alg, hex_part) = s.split_once(':').ok_or_else(|| VigilError::InvalidValue {
            field: "content_hash",
            reason: "expected `<algorithm>:<hex>`".to_string(),
        })?;
        let algorithm = HashAlgorithm::from_str(alg)?;
        let expected_len = match algorithm {
            HashAlgorithm::Sha256 => 64,
        };
        if hex_part.len() != expected_len
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(VigilError::InvalidValue {
                field: "content_hash",
                reason: "digest must be lowercase hex of the algorithm's length".to_string(),
            });
        }
        Ok(Self {
            algorithm,
            hex: hex_part.to_string(),
        })
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_hash_is_stable_across_key_order() {
        let a = ContentHash::canonical_json(&json!({"a": 1, "b": 2})).unwrap();
        let b = ContentHash::canonical_json(&json!({"b": 2, "a": 1})).unwrap();
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn canonical_hash_changes_when_a_value_changes() {
        let a = ContentHash::canonical_json(&json!({"amount": 100})).unwrap();
        let b = ContentHash::canonical_json(&json!({"amount": 1000})).unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn round_trips_through_string_form() {
        let h = ContentHash::sha256(b"vigil");
        let parsed: ContentHash = h.to_string().parse().unwrap();
        assert!(h.ct_eq(&parsed));
    }

    #[test]
    fn rejects_untagged_or_malformed_hashes() {
        assert!("deadbeef".parse::<ContentHash>().is_err());
        assert!("md5:deadbeef".parse::<ContentHash>().is_err());
        assert!("sha256:NOTHEX".parse::<ContentHash>().is_err());
        // uppercase hex is rejected so that string equality and ct_eq never disagree
        assert!(format!("sha256:{}", "A".repeat(64))
            .parse::<ContentHash>()
            .is_err());
    }

    #[test]
    fn known_answer_test_sha256_empty() {
        assert_eq!(
            ContentHash::sha256(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
