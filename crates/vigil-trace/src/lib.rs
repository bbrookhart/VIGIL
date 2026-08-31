//! VIGIL Trace: provenance, trust propagation and causal taint.
//!
//! # Why
//!
//! The question that matters is not "does this text look like a prompt injection?" but
//! "did untrusted content causally influence the agent toward this action?" (spec §23).
//! Answering it requires remembering where every piece of content in a session came from and
//! how it combined — which is what this crate is.
//!
//! # What
//!
//! A per-session directed acyclic graph. Nodes are content with a trust label and taints;
//! edges are derivation. Trust flows downward only ([`TrustLevel::combine`] takes the
//! minimum), so a node derived from a system prompt and a hostile web page is web-grade.
//!
//! # Failure mode
//!
//! An action whose influencing sources cannot be determined is treated as influenced by the
//! session's *lowest-trust* content, not as uninfluenced. Missing provenance therefore makes
//! the system more cautious rather than blind — the opposite of the usual default.
//!
//! # Evidence
//!
//! `tests/` in this crate prove the Demo 1 chain end to end at the trace level: untrusted
//! page → model output → tool argument → egress, with a reconstructable causal chain.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod flow;

use std::collections::{BTreeSet, HashMap, VecDeque};
use vigil_common::ids::ProvenanceNodeId;
use vigil_common::{ContentHash, Timestamp};
use vigil_protocol::trust::{ProvenanceRef, TaintKind, TrustLevel};

pub use flow::{FlowEncoding, TrackedValue};

/// One piece of content in a session, with where it came from.
#[derive(Debug, Clone)]
pub struct ProvenanceNode {
    pub id: ProvenanceNodeId,
    /// Trust of this node after combining its parents.
    pub trust: TrustLevel,
    /// Redacted, human-meaningful origin: `web:https://example.com/a`, `tool:read_secret`.
    pub origin: String,
    pub content_hash: Option<ContentHash>,
    pub taints: BTreeSet<TaintKind>,
    /// Nodes this content was derived from.
    pub derived_from: Vec<ProvenanceNodeId>,
    pub created_at: Timestamp,
    /// Sensitive values that entered the session at this node.
    tracked_values: Vec<TrackedValue>,
}

impl ProvenanceNode {
    pub fn as_ref(&self) -> ProvenanceRef {
        ProvenanceRef {
            node_id: self.id.clone(),
            trust_level: self.trust,
            origin: self.origin.clone(),
            content_hash: self.content_hash.clone(),
        }
    }
}

/// What trace analysis concluded about a candidate action.
#[derive(Debug, Clone, Default)]
pub struct TraceFindings {
    /// Taints the action carries, unioned from every influencing node.
    pub taints: BTreeSet<TaintKind>,
    /// The causal chain, oldest first, ready to render in the console.
    pub chain: Vec<ProvenanceRef>,
    /// The least-trusted influence on this action.
    pub lowest_trust: Option<TrustLevel>,
    /// Whether untrusted, instruction-like content is among the influences.
    pub untrusted_instruction_influence: bool,
    /// Sensitive values detected flowing into this action, as (fingerprint, encoding).
    pub value_flows: Vec<(String, FlowEncoding)>,
    /// Whether any detected flow used an encoding that suggests deliberate evasion.
    pub evasive_encoding: bool,
}

impl TraceFindings {
    pub fn taints_vec(&self) -> Vec<TaintKind> {
        self.taints.iter().copied().collect()
    }
}

/// The provenance graph for one session.
#[derive(Debug, Default)]
pub struct SessionTrace {
    nodes: HashMap<ProvenanceNodeId, ProvenanceNode>,
    /// Insertion order, so chains render chronologically without sorting by timestamp
    /// (timestamps can collide at sub-millisecond resolution).
    order: Vec<ProvenanceNodeId>,
}

impl SessionTrace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get(&self, id: &ProvenanceNodeId) -> Option<&ProvenanceNode> {
        self.nodes.get(id)
    }

    /// Record content entering the session.
    ///
    /// `derived_from` names the nodes this content came out of. The resulting trust is the
    /// minimum of the declared trust and every parent's trust — content cannot become more
    /// trustworthy by passing through a model.
    pub fn ingest(
        &mut self,
        origin: impl Into<String>,
        declared_trust: TrustLevel,
        content: Option<&str>,
        taints: impl IntoIterator<Item = TaintKind>,
        derived_from: &[ProvenanceNodeId],
        now: Timestamp,
    ) -> ProvenanceNodeId {
        let id = ProvenanceNodeId::generate();

        let mut trust = declared_trust;
        let mut inherited_taints = BTreeSet::new();
        for parent in derived_from {
            if let Some(node) = self.nodes.get(parent) {
                trust = trust.combine(node.trust);
                inherited_taints.extend(node.taints.iter().copied());
            }
        }
        inherited_taints.extend(taints);

        let content_hash = content.map(|c| ContentHash::sha256(c.as_bytes()));

        self.nodes.insert(
            id.clone(),
            ProvenanceNode {
                id: id.clone(),
                trust,
                origin: origin.into(),
                content_hash,
                taints: inherited_taints,
                derived_from: derived_from.to_vec(),
                created_at: now,
                tracked_values: Vec::new(),
            },
        );
        self.order.push(id.clone());
        id
    }

    /// Mark a value as sensitive and watch for it in later actions.
    ///
    /// Returns whether the value was long enough to track; a caller that needs certainty
    /// (a vault read) should escalate on `false` rather than assume coverage.
    pub fn track_value(&mut self, node_id: &ProvenanceNodeId, value: &str) -> bool {
        let Some(node) = self.nodes.get_mut(node_id) else {
            return false;
        };
        match TrackedValue::new(value) {
            Some(tv) => {
                node.tracked_values.push(tv);
                true
            }
            None => false,
        }
    }

    /// Every node reachable backwards from `start`, oldest first.
    ///
    /// Cycle-safe: the graph should be acyclic, but a malformed adapter could submit a cycle,
    /// and an enforcement path that can be made to loop forever is a denial-of-service.
    pub fn causal_chain(&self, start: &ProvenanceNodeId) -> Vec<ProvenanceRef> {
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([start.clone()]);
        let mut collected: Vec<&ProvenanceNode> = Vec::new();

        while let Some(id) = queue.pop_front() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(node) = self.nodes.get(&id) {
                collected.push(node);
                for parent in &node.derived_from {
                    queue.push_back(parent.clone());
                }
            }
        }

        // Render in the order content entered the session, which is how an analyst reads it.
        let position: HashMap<&ProvenanceNodeId, usize> = self
            .order
            .iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect();
        collected.sort_by_key(|n| position.get(&n.id).copied().unwrap_or(usize::MAX));
        collected.iter().map(|n| n.as_ref()).collect()
    }

    /// The least-trusted node in the session. The fallback when influence is unknown.
    pub fn lowest_trust(&self) -> Option<TrustLevel> {
        self.nodes
            .values()
            .map(|n| n.trust)
            .min_by_key(|t| t.rank())
    }

    /// Analyze a candidate action.
    ///
    /// `declared_sources` are the nodes the instrumentation says were in context.
    /// `content_strings` is everything the action would carry.
    ///
    /// Two independent mechanisms contribute:
    ///
    /// 1. **Declared influence** — what the adapter reported was in the model's context.
    /// 2. **Value flow** — tracked sensitive values actually appearing in the action, which
    ///    holds even when the adapter under-reports, and which is what catches an agent that
    ///    read a secret in one step and sent it in another.
    ///
    /// When neither yields anything, the session's lowest trust is applied, so an action with
    /// no provenance information is treated as maximally influenced rather than clean.
    pub fn analyze_action(
        &self,
        declared_sources: &[ProvenanceNodeId],
        content_strings: &[(String, String)],
    ) -> TraceFindings {
        let mut findings = TraceFindings::default();
        let mut contributing: Vec<&ProvenanceNode> = Vec::new();

        for id in declared_sources {
            if let Some(node) = self.nodes.get(id) {
                contributing.push(node);
            }
        }

        // Value flow across every node, not just declared ones: the whole point is to catch
        // movement the adapter did not report.
        for node in self.nodes.values() {
            for tracked in &node.tracked_values {
                for (_path, content) in content_strings {
                    if let Some(encoding) = tracked.find_in(content) {
                        findings.value_flows.push((tracked.fingerprint(), encoding));
                        findings.evasive_encoding |= encoding.suggests_evasion();
                        if !contributing.iter().any(|n| n.id == node.id) {
                            contributing.push(node);
                        }
                        break;
                    }
                }
            }
        }

        if contributing.is_empty() {
            // No usable provenance. Assume the worst thing in the session influenced this.
            findings.lowest_trust = self.lowest_trust();
            findings.untrusted_instruction_influence = self
                .nodes
                .values()
                .any(|n| n.taints.contains(&TaintKind::UntrustedInstruction));
            if findings.untrusted_instruction_influence {
                findings.taints.insert(TaintKind::UntrustedInstruction);
            }
            return findings;
        }

        let mut chain_ids = Vec::new();
        for node in &contributing {
            findings.taints.extend(node.taints.iter().copied());
            findings.lowest_trust = Some(match findings.lowest_trust {
                Some(t) => t.combine(node.trust),
                None => node.trust,
            });
            chain_ids.push(node.id.clone());
        }

        findings.untrusted_instruction_influence = contributing.iter().any(|n| {
            n.taints.contains(&TaintKind::UntrustedInstruction)
                && !n.trust.carries_instruction_authority()
        });

        // Build one merged, de-duplicated chain over every contributing node.
        let mut seen = BTreeSet::new();
        for id in &chain_ids {
            for r in self.causal_chain(id) {
                if seen.insert(r.node_id.clone()) {
                    findings.chain.push(r);
                }
            }
        }
        let position: HashMap<&ProvenanceNodeId, usize> = self
            .order
            .iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect();
        findings
            .chain
            .sort_by_key(|r| position.get(&r.node_id).copied().unwrap_or(usize::MAX));

        findings
    }
}

/// Traces for every live session.
#[derive(Debug, Default)]
pub struct TraceStore {
    sessions: HashMap<String, SessionTrace>,
}

impl TraceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn session_mut(&mut self, session_id: &str) -> &mut SessionTrace {
        self.sessions.entry(session_id.to_string()).or_default()
    }

    pub fn session(&self, session_id: &str) -> Option<&SessionTrace> {
        self.sessions.get(session_id)
    }

    /// Drop a session's trace once it ends. Traces hold raw sensitive values, so they are
    /// released as soon as the session that needs them is over.
    pub fn end_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
