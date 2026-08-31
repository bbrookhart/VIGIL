//! VIGIL Audit: tamper-evident security evidence.
//!
//! # Why
//!
//! An audit log an attacker can edit is not evidence, it is a story. Since VIGIL's records
//! are what an incident review, a regulator or a court would rely on, the log has to make
//! modification *detectable* by someone who does not trust the system that produced it.
//!
//! # What
//!
//! A per-tenant hash chain: each entry commits to the previous entry's hash, so altering any
//! record invalidates every record after it. Periodic checkpoints sign the chain head, which
//! bounds how far back an attacker who compromises the writer can rewrite: without the
//! signing key, they cannot produce a checkpoint that covers a rewritten chain, and the
//! last valid checkpoint pins everything before it.
//!
//! # Assumptions
//!
//! A hash chain proves *integrity*, not *completeness on its own*: an attacker who truncates
//! the tail leaves a shorter but internally consistent chain. Signed checkpoints are what
//! close that gap, which is why [`AuditChain::verify`] reports a truncation below the last
//! checkpoint as a failure rather than a valid short chain.
//!
//! # Failure mode
//!
//! An append that cannot be chained fails loudly. There is no path where an event is written
//! without a chain link — an unchained record would be indistinguishable from an injected one.
//!
//! # Evidence
//!
//! `verify` is exercised against modification, reordering, deletion, truncation, insertion
//! and forged-checkpoint scenarios in this module's tests, and exposed as `vigil audit verify`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod sink;
pub use sink::{AuditSink, FileAuditSink, NonDurableSink, RecoveredState};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use vigil_common::ids::TenantId;
use vigil_common::{Clock, ContentHash, Result, Timestamp, VigilError};
use vigil_protocol::event::{IntegrityEnvelope, VigilSecurityEvent};

/// One committed record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub event: VigilSecurityEvent,
    /// Hash of this entry's content plus its link to the previous entry.
    pub chain_hash: ContentHash,
    pub previous_hash: Option<ContentHash>,
}

/// A signed commitment to the chain head at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub tenant_id: TenantId,
    /// Sequence of the last entry this checkpoint covers.
    pub sequence: u64,
    /// The chain hash at that sequence.
    pub chain_hash: ContentHash,
    pub signed_at: Timestamp,
    pub key_id: String,
    /// Base64url Ed25519 signature over the canonical checkpoint body.
    pub signature: String,
}

impl Checkpoint {
    /// The bytes that are signed. Excludes the signature itself.
    fn signing_payload(
        tenant_id: &TenantId,
        sequence: u64,
        chain_hash: &ContentHash,
        signed_at: Timestamp,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        let body = serde_json::json!({
            "tenant_id": tenant_id,
            "sequence": sequence,
            "chain_hash": chain_hash.to_string(),
            "signed_at": signed_at.to_rfc3339(),
            "key_id": key_id,
        });
        vigil_common::canonical::canonical_bytes(&body)
    }
}

/// What verification found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub entries_checked: u64,
    pub checkpoints_checked: u64,
    /// Problems found, in chain order. Empty means the chain verified.
    pub failures: Vec<IntegrityFailure>,
}

impl VerificationReport {
    pub fn is_valid(&self) -> bool {
        self.failures.is_empty()
    }
}

/// A specific integrity problem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntegrityFailure {
    /// An entry's recomputed hash does not match its recorded one: the content changed.
    ContentModified { sequence: u64 },
    /// An entry's `previous_hash` does not match the actual previous entry: something was
    /// inserted, removed or reordered here.
    ChainBroken { sequence: u64 },
    /// A sequence number is missing.
    SequenceGap { expected: u64, found: u64 },
    /// Two entries share a sequence number.
    DuplicateSequence { sequence: u64 },
    /// A checkpoint's signature did not verify.
    CheckpointSignatureInvalid { sequence: u64 },
    /// A checkpoint was signed by a key the verifier does not trust.
    CheckpointKeyUnknown { sequence: u64, key_id: String },
    /// A checkpoint commits to a chain state the entries do not show — the tell-tale of a
    /// rewritten or truncated log.
    CheckpointMismatch { sequence: u64 },
    /// The log ends before a checkpoint that covers later entries.
    TruncatedBelowCheckpoint {
        checkpoint_sequence: u64,
        last_sequence: u64,
    },
}

/// Private signing material for checkpoints.
pub struct CheckpointSigner {
    key_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for CheckpointSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointSigner")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl CheckpointSigner {
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            VigilError::Config("audit signing seed must be exactly 32 bytes".to_string())
        })?;
        Ok(Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Generate ephemeral key material.
    ///
    /// Development and tests only. Checkpoints signed with an ephemeral key cannot be
    /// verified after a restart, which defeats their entire purpose; production loads a
    /// seed from a KMS or secret store.
    pub fn generate(key_id: impl Into<String>) -> Self {
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

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

/// An append-only, hash-chained evidence log for one tenant.
#[derive(Debug)]
pub struct AuditChain {
    tenant_id: TenantId,
    inner: Mutex<ChainInner>,
    signer: CheckpointSigner,
    clock: std::sync::Arc<dyn Clock>,
    /// Durable storage. Defaults to [`NonDurableSink`], which keeps the chain in memory only.
    sink: std::sync::Arc<dyn AuditSink>,
}

#[derive(Debug, Default)]
struct ChainInner {
    entries: Vec<AuditEntry>,
    checkpoints: Vec<Checkpoint>,
    next_sequence: u64,
    head: Option<ContentHash>,
}

impl AuditChain {
    pub fn new(
        tenant_id: TenantId,
        signer: CheckpointSigner,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Self {
        Self {
            tenant_id,
            inner: Mutex::new(ChainInner::default()),
            signer,
            clock,
            sink: std::sync::Arc::new(NonDurableSink),
        }
    }

    /// Persist to a durable sink, resuming an existing chain if one is present.
    ///
    /// Recovery is the point. Without it a restart would begin a second chain at sequence 0,
    /// and the log would hold two independently-valid chains with no way to distinguish a
    /// legitimate restart from a truncation.
    pub fn with_sink(mut self, sink: std::sync::Arc<dyn AuditSink>) -> Result<Self> {
        let (entries, checkpoints) = sink.load()?;
        let last = entries.last();
        let next_sequence = last.map(|e| e.sequence + 1).unwrap_or(0);
        let head = last.map(|e| e.chain_hash.clone());

        if let Ok(mut inner) = self.inner.lock() {
            inner.entries = entries;
            inner.checkpoints = checkpoints;
            inner.next_sequence = next_sequence;
            inner.head = head;
        }
        self.sink = sink;
        Ok(self)
    }

    /// Compute the chain hash for an entry.
    ///
    /// Commits to the sequence number as well as the content and the previous hash, so an
    /// attacker cannot renumber entries while keeping their hashes valid.
    fn link_hash(
        sequence: u64,
        event_hash: &ContentHash,
        previous: Option<&ContentHash>,
    ) -> Result<ContentHash> {
        let body = serde_json::json!({
            "sequence": sequence,
            "event_hash": event_hash.to_string(),
            "previous_hash": previous.map(|h| h.to_string()),
        });
        ContentHash::canonical_json(&body)
    }

    /// Append an event, returning the integrity envelope to attach to it.
    pub fn append(&self, event: &VigilSecurityEvent) -> Result<IntegrityEnvelope> {
        let event_hash = event.content_hash()?;
        let mut inner = self.inner.lock().map_err(|_| {
            VigilError::AuditIntegrity(
                "audit chain lock poisoned; refusing to append an unchained record".to_string(),
            )
        })?;

        let sequence = inner.next_sequence;
        let previous = inner.head.clone();
        let chain_hash = Self::link_hash(sequence, &event_hash, previous.as_ref())?;

        let mut stored = event.clone();
        let envelope = IntegrityEnvelope {
            sequence,
            event_hash: event_hash.clone(),
            previous_hash: previous.clone(),
            checkpoint_signature: None,
        };
        stored.integrity = Some(envelope.clone());

        let entry = AuditEntry {
            sequence,
            event: stored,
            chain_hash: chain_hash.clone(),
            previous_hash: previous,
        };

        // Durability before acknowledgement. If the record cannot be persisted the append
        // fails, and the pipeline treats a failed audit write as a failed decision — a
        // system that keeps enforcing while losing its evidence is worse than one that stops.
        self.sink.append(&entry)?;

        inner.entries.push(entry);
        inner.next_sequence += 1;
        inner.head = Some(chain_hash);
        Ok(envelope)
    }

    /// Sign the current chain head.
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| VigilError::AuditIntegrity("audit chain lock poisoned".to_string()))?;
        let Some(head) = inner.head.clone() else {
            return Err(VigilError::AuditIntegrity(
                "cannot checkpoint an empty chain".to_string(),
            ));
        };
        let sequence = inner.next_sequence.saturating_sub(1);
        let signed_at = self.clock.now();
        let payload = Checkpoint::signing_payload(
            &self.tenant_id,
            sequence,
            &head,
            signed_at,
            self.signer.key_id(),
        )?;
        let signature = self.signer.key.sign(&payload);
        drop(inner);

        let checkpoint = Checkpoint {
            tenant_id: self.tenant_id.clone(),
            sequence,
            chain_hash: head,
            signed_at,
            key_id: self.signer.key_id().to_string(),
            signature: B64.encode(signature.to_bytes()),
        };

        self.sink.append_checkpoint(&checkpoint)?;
        if let Ok(mut inner) = self.inner.lock() {
            inner.checkpoints.push(checkpoint.clone());
        }
        Ok(checkpoint)
    }

    /// Export the chain for offline verification.
    pub fn export(&self) -> Result<AuditBundle> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| VigilError::AuditIntegrity("audit chain lock poisoned".to_string()))?;
        Ok(AuditBundle {
            tenant_id: self.tenant_id.clone(),
            entries: inner.entries.clone(),
            checkpoints: inner.checkpoints.clone(),
        })
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.entries.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

/// A portable, independently verifiable evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBundle {
    pub tenant_id: TenantId,
    pub entries: Vec<AuditEntry>,
    pub checkpoints: Vec<Checkpoint>,
}

impl AuditBundle {
    /// Verify a bundle against a set of trusted checkpoint keys.
    ///
    /// Independent by design: this function reads only the bundle and the public keys, so it
    /// runs in `vigil audit verify` on a machine that has never talked to the VIGIL that
    /// produced the log.
    pub fn verify(&self, trusted_keys: &HashMap<String, VerifyingKey>) -> VerificationReport {
        let mut report = VerificationReport {
            entries_checked: self.entries.len() as u64,
            checkpoints_checked: self.checkpoints.len() as u64,
            failures: Vec::new(),
        };

        let mut expected_sequence = 0u64;
        let mut previous_hash: Option<ContentHash> = None;
        let mut seen_sequences = std::collections::HashSet::new();
        // Chain hash at each sequence, so checkpoints can be matched to chain state.
        let mut hash_at: HashMap<u64, ContentHash> = HashMap::new();

        for entry in &self.entries {
            if !seen_sequences.insert(entry.sequence) {
                report.failures.push(IntegrityFailure::DuplicateSequence {
                    sequence: entry.sequence,
                });
            }
            if entry.sequence != expected_sequence {
                report.failures.push(IntegrityFailure::SequenceGap {
                    expected: expected_sequence,
                    found: entry.sequence,
                });
                // Resynchronize so one gap does not report every later entry as broken.
                expected_sequence = entry.sequence;
            }

            // Recompute the event hash from the stored event, excluding its envelope.
            match entry.event.content_hash() {
                Ok(recomputed) => {
                    let recorded = entry.event.integrity.as_ref().map(|i| i.event_hash.clone());
                    if recorded.as_ref().is_none_or(|r| !r.ct_eq(&recomputed)) {
                        report.failures.push(IntegrityFailure::ContentModified {
                            sequence: entry.sequence,
                        });
                    }

                    match AuditChain::link_hash(entry.sequence, &recomputed, previous_hash.as_ref())
                    {
                        Ok(expected_chain) => {
                            if !expected_chain.ct_eq(&entry.chain_hash) {
                                report.failures.push(IntegrityFailure::ChainBroken {
                                    sequence: entry.sequence,
                                });
                            }
                        }
                        Err(_) => report.failures.push(IntegrityFailure::ContentModified {
                            sequence: entry.sequence,
                        }),
                    }
                }
                Err(_) => report.failures.push(IntegrityFailure::ContentModified {
                    sequence: entry.sequence,
                }),
            }

            hash_at.insert(entry.sequence, entry.chain_hash.clone());
            previous_hash = Some(entry.chain_hash.clone());
            expected_sequence += 1;
        }

        let last_sequence = self.entries.last().map(|e| e.sequence);

        for checkpoint in &self.checkpoints {
            let Some(key) = trusted_keys.get(&checkpoint.key_id) else {
                report
                    .failures
                    .push(IntegrityFailure::CheckpointKeyUnknown {
                        sequence: checkpoint.sequence,
                        key_id: vigil_common::redact::single_line_excerpt(&checkpoint.key_id, 32),
                    });
                continue;
            };

            let payload = match Checkpoint::signing_payload(
                &checkpoint.tenant_id,
                checkpoint.sequence,
                &checkpoint.chain_hash,
                checkpoint.signed_at,
                &checkpoint.key_id,
            ) {
                Ok(p) => p,
                Err(_) => {
                    report
                        .failures
                        .push(IntegrityFailure::CheckpointSignatureInvalid {
                            sequence: checkpoint.sequence,
                        });
                    continue;
                }
            };

            let signature_ok = B64
                .decode(&checkpoint.signature)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
                .map(|b| Signature::from_bytes(&b))
                .is_some_and(|sig| {
                    use ed25519_dalek::Verifier;
                    key.verify(&payload, &sig).is_ok()
                });
            if !signature_ok {
                report
                    .failures
                    .push(IntegrityFailure::CheckpointSignatureInvalid {
                        sequence: checkpoint.sequence,
                    });
                continue;
            }

            // A valid signature over a chain state the entries do not exhibit means the
            // entries were changed after the checkpoint was made.
            match hash_at.get(&checkpoint.sequence) {
                Some(actual) if actual.ct_eq(&checkpoint.chain_hash) => {}
                Some(_) => report.failures.push(IntegrityFailure::CheckpointMismatch {
                    sequence: checkpoint.sequence,
                }),
                None => {
                    // The checkpoint covers a sequence the log no longer contains: truncation.
                    report
                        .failures
                        .push(IntegrityFailure::TruncatedBelowCheckpoint {
                            checkpoint_sequence: checkpoint.sequence,
                            last_sequence: last_sequence.unwrap_or(0),
                        });
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigil_common::ids::{
        AgentId, AgentInstanceId, EnvironmentId, EventId, PrincipalId, SessionId,
    };
    use vigil_common::FixedClock;
    use vigil_protocol::event::EventType;
    use vigil_protocol::principal::{Principal, PrincipalKind};

    pub(super) fn event(n: u32) -> VigilSecurityEvent {
        let tenant: TenantId = "acme".parse().unwrap();
        VigilSecurityEvent {
            schema_version: vigil_protocol::SCHEMA_VERSION.to_string(),
            event_id: EventId::new(format!("e-{n}")).unwrap(),
            timestamp: FixedClock::at_epoch().now(),
            event_type: EventType::DecisionRendered,
            trace: Default::default(),
            tenant_id: tenant.clone(),
            environment_id: EnvironmentId::new("prod").unwrap(),
            session_id: SessionId::new("s-1").unwrap(),
            agent_id: AgentId::new("agent-a").unwrap(),
            agent_instance_id: AgentInstanceId::new("inst-1").unwrap(),
            principal: Principal::new(
                PrincipalId::new("user-1").unwrap(),
                PrincipalKind::Human,
                tenant,
            ),
            workload_identity: None,
            source: "core".to_string(),
            trust_level: None,
            provenance: vec![],
            action: None,
            action_hash: None,
            data_classification: Default::default(),
            taint: Default::default(),
            remit_version: None,
            policy_bundle_version: None,
            detector_results: vec![],
            decision: Some(vigil_protocol::decision::Decision::Deny),
            reason_codes: vec![],
            risk_score: Some(0.5),
            enforcement: None,
            approval_id: None,
            incident_id: None,
            integrity: None,
            extensions: Default::default(),
        }
    }

    fn chain() -> AuditChain {
        AuditChain::new(
            "acme".parse().unwrap(),
            CheckpointSigner::generate("audit-k1"),
            Arc::new(FixedClock::at_epoch()),
        )
    }

    fn keys(chain: &AuditChain) -> HashMap<String, VerifyingKey> {
        HashMap::from([("audit-k1".to_string(), chain.verifying_key())])
    }

    #[test]
    fn an_untouched_chain_verifies() {
        let c = chain();
        for i in 0..10 {
            c.append(&event(i)).unwrap();
        }
        c.checkpoint().unwrap();
        let report = c.export().unwrap().verify(&keys(&c));
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.entries_checked, 10);
        assert_eq!(report.checkpoints_checked, 1);
    }

    #[test]
    fn modifying_an_events_content_is_detected() {
        let c = chain();
        for i in 0..5 {
            c.append(&event(i)).unwrap();
        }
        c.checkpoint().unwrap();
        let mut bundle = c.export().unwrap();

        // The classic cover-up: change a DENY to an ALLOW after the fact.
        bundle.entries[2].event.decision = Some(vigil_protocol::decision::Decision::Allow);

        let report = bundle.verify(&keys(&c));
        assert!(!report.is_valid());
        assert!(report
            .failures
            .contains(&IntegrityFailure::ContentModified { sequence: 2 }));
        // And every later link breaks too, which is what makes rewriting expensive.
        assert!(report
            .failures
            .iter()
            .any(|f| matches!(f, IntegrityFailure::ChainBroken { .. })));
    }

    #[test]
    fn deleting_an_event_is_detected() {
        let c = chain();
        for i in 0..5 {
            c.append(&event(i)).unwrap();
        }
        let mut bundle = c.export().unwrap();
        bundle.entries.remove(2);
        let report = bundle.verify(&keys(&c));
        assert!(!report.is_valid());
        assert!(report
            .failures
            .iter()
            .any(|f| matches!(f, IntegrityFailure::SequenceGap { .. })));
    }

    #[test]
    fn reordering_events_is_detected() {
        let c = chain();
        for i in 0..5 {
            c.append(&event(i)).unwrap();
        }
        let mut bundle = c.export().unwrap();
        bundle.entries.swap(1, 3);
        let report = bundle.verify(&keys(&c));
        assert!(!report.is_valid());
    }

    #[test]
    fn inserting_a_forged_event_is_detected() {
        let c = chain();
        for i in 0..3 {
            c.append(&event(i)).unwrap();
        }
        let mut bundle = c.export().unwrap();
        let mut forged = bundle.entries[1].clone();
        forged.event.event_id = EventId::new("e-forged").unwrap();
        bundle.entries.insert(2, forged);
        let report = bundle.verify(&keys(&c));
        assert!(!report.is_valid());
    }

    #[test]
    fn truncating_the_log_below_a_checkpoint_is_detected() {
        // A plain hash chain cannot catch this; the signed checkpoint is what does.
        let c = chain();
        for i in 0..10 {
            c.append(&event(i)).unwrap();
        }
        c.checkpoint().unwrap();
        let mut bundle = c.export().unwrap();
        bundle.entries.truncate(5);

        let report = bundle.verify(&keys(&c));
        assert!(!report.is_valid());
        assert!(report
            .failures
            .iter()
            .any(|f| matches!(f, IntegrityFailure::TruncatedBelowCheckpoint { .. })));
    }

    #[test]
    fn a_checkpoint_signed_by_an_unknown_key_is_rejected() {
        let c = chain();
        c.append(&event(0)).unwrap();
        c.checkpoint().unwrap();
        let bundle = c.export().unwrap();
        let report = bundle.verify(&HashMap::new());
        assert!(report
            .failures
            .iter()
            .any(|f| matches!(f, IntegrityFailure::CheckpointKeyUnknown { .. })));
    }

    #[test]
    fn a_forged_checkpoint_signature_is_rejected() {
        let c = chain();
        c.append(&event(0)).unwrap();
        c.checkpoint().unwrap();
        let mut bundle = c.export().unwrap();
        bundle.checkpoints[0].signature = B64.encode([9u8; 64]);
        let report = bundle.verify(&keys(&c));
        assert!(report
            .failures
            .iter()
            .any(|f| matches!(f, IntegrityFailure::CheckpointSignatureInvalid { .. })));
    }

    #[test]
    fn an_attacker_cannot_rewrite_history_and_re_checkpoint_without_the_key() {
        // Rewrite an entry, then recompute the chain honestly from that point. The chain
        // itself is now self-consistent — the old checkpoint is what exposes the change.
        let c = chain();
        for i in 0..5 {
            c.append(&event(i)).unwrap();
        }
        c.checkpoint().unwrap();
        let mut bundle = c.export().unwrap();

        bundle.entries[1].event.decision = Some(vigil_protocol::decision::Decision::Allow);
        // Re-link the whole chain as an attacker with write access would.
        let mut previous: Option<ContentHash> = None;
        for entry in bundle.entries.iter_mut() {
            let event_hash = entry.event.content_hash().unwrap();
            if let Some(i) = entry.event.integrity.as_mut() {
                i.event_hash = event_hash.clone();
                i.previous_hash = previous.clone();
            }
            entry.chain_hash =
                AuditChain::link_hash(entry.sequence, &event_hash, previous.as_ref()).unwrap();
            entry.previous_hash = previous.clone();
            previous = Some(entry.chain_hash.clone());
        }

        let report = bundle.verify(&keys(&c));
        assert!(
            !report.is_valid(),
            "a re-linked chain must still fail against the signed checkpoint"
        );
        assert!(report
            .failures
            .contains(&IntegrityFailure::CheckpointMismatch { sequence: 4 }));
    }

    #[test]
    fn appending_is_sequential_and_hash_linked() {
        let c = chain();
        let first = c.append(&event(0)).unwrap();
        let second = c.append(&event(1)).unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert!(first.previous_hash.is_none());
        assert!(second.previous_hash.is_some());
    }

    #[test]
    fn an_empty_chain_cannot_be_checkpointed() {
        assert!(chain().checkpoint().is_err());
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    use std::sync::Arc;
    use vigil_common::FixedClock;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vigil-chain-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn chain_at(dir: &std::path::Path, seed: [u8; 32]) -> AuditChain {
        AuditChain::new(
            "acme".parse().expect("tenant"),
            CheckpointSigner::from_seed("audit-k1", &seed).expect("seed"),
            Arc::new(FixedClock::at_epoch()),
        )
        .with_sink(Arc::new(FileAuditSink::open(dir).expect("sink")))
        .expect("recovers")
    }

    #[test]
    fn a_restart_continues_the_existing_chain_rather_than_forking_a_new_one() {
        // The property that makes durability meaningful. If a restart began again at
        // sequence 0, the log would contain two valid chains and truncation would be
        // indistinguishable from a reboot.
        let dir = tempdir("restart");
        let seed = [3u8; 32];

        let first = chain_at(&dir, seed);
        for i in 0..5 {
            first.append(&super::tests::event(i)).expect("append");
        }
        first.checkpoint().expect("checkpoint");
        drop(first);

        // "Restart": a brand-new chain object over the same directory.
        let resumed = chain_at(&dir, seed);
        assert_eq!(resumed.len(), 5, "the existing entries must be recovered");

        let envelope = resumed.append(&super::tests::event(99)).expect("append");
        assert_eq!(
            envelope.sequence, 5,
            "the chain must continue, not restart at zero"
        );
        assert!(
            envelope.previous_hash.is_some(),
            "the first post-restart entry must link to the pre-restart head"
        );

        // And the whole thing still verifies as one chain.
        let bundle = resumed.export().expect("export");
        let keys = HashMap::from([("audit-k1".to_string(), resumed.verifying_key())]);
        let report = bundle.verify(&keys);
        assert!(report.is_valid(), "{report:?}");
        assert_eq!(report.entries_checked, 6);
    }

    #[test]
    fn records_survive_on_disk_and_reload_identically() {
        let dir = tempdir("reload");
        let chain = chain_at(&dir, [4u8; 32]);
        chain.append(&super::tests::event(1)).expect("append");
        let exported = chain.export().expect("export");
        drop(chain);

        let sink = FileAuditSink::open(&dir).expect("sink");
        let (entries, _checkpoints) = sink.load().expect("load");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].chain_hash.ct_eq(&exported.entries[0].chain_hash));
    }

    #[test]
    fn a_sink_that_cannot_write_fails_the_append() {
        // Evidence loss must surface as a failed decision, not a silent gap.
        #[derive(Debug)]
        struct BrokenSink;
        impl AuditSink for BrokenSink {
            fn append(&self, _entry: &AuditEntry) -> Result<()> {
                Err(VigilError::Io("disk full".to_string()))
            }
            fn append_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<()> {
                Ok(())
            }
            fn load(&self) -> Result<(Vec<AuditEntry>, Vec<Checkpoint>)> {
                Ok((Vec::new(), Vec::new()))
            }
        }

        let chain = AuditChain::new(
            "acme".parse().expect("tenant"),
            CheckpointSigner::generate("audit-k1"),
            Arc::new(FixedClock::at_epoch()),
        )
        .with_sink(Arc::new(BrokenSink))
        .expect("constructs");

        assert!(
            chain.append(&super::tests::event(1)).is_err(),
            "an unwritable audit record must fail the append"
        );
    }
}
