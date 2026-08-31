//! Detections that need more than one event to see.
//!
//! Every rule elsewhere in this crate fires on a single decision, at the moment it is made.
//! That misses the shapes that only exist across time: reading credentials and *then* opening
//! a connection, archiving before egress, a chain of interpreters, a session that suddenly
//! spawns forty processes. §34 calls these sequence, threshold, and graph detections.
//!
//! # These are retrospective, and that is a real difference
//!
//! A decision-time rule can refuse. These cannot — by the time a sequence is visible, every
//! step in it has already been decided. They run over the durable event log and the process
//! graph *after the fact*, and what they produce is an explanation and a risk contribution,
//! not a block.
//!
//! That is worth being clear about rather than blurring: `vigil analyze` tells you what a
//! session turned out to be doing. It does not stop it. The steps were each individually
//! permitted, which is precisely why the shape is worth naming.
//!
//! # Idempotence
//!
//! Analysis is expected to be run repeatedly — after a session ends, during triage, again when
//! new evidence arrives. Each finding is fingerprinted, and a fingerprint already recorded for
//! the session is not recorded again. Re-analyzing must not inflate risk.

use crate::detection::{Confidence, DetectionRule, Severity, Tactic};
use crate::{ExecutableClass, LocalStore, RiskDimension, RiskState};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use vigil_common::{ContentHash, Result};

/// How close together two steps must be to read as one sequence.
///
/// Long enough to cover an agent doing several things in a turn, short enough that unrelated
/// activity an hour apart is not narrated as a plot.
const SEQUENCE_WINDOW: i64 = 300;

/// How many processes in one window reads as fan-out rather than as work.
const FAN_OUT_THRESHOLD: usize = 20;
const FAN_OUT_WINDOW: i64 = 60;

/// How many sensitive reads before an archive step reads as collection.
const COLLECTION_THRESHOLD: usize = 3;

/// How long a refusal in one session stays relevant to another session's request.
///
/// An hour: long enough to cover an agent that gives up, a new session that starts, and the
/// same resource being tried again; short enough that yesterday's refusal does not implicate
/// today's unrelated work.
const LAUNDERING_WINDOW: i64 = 3600;

pub const DETECTION_SENSITIVE_READ_THEN_EGRESS: &str = "sensitive_read_then_egress";
pub const DETECTION_ARCHIVE_BEFORE_EGRESS: &str = "archive_before_egress";
pub const DETECTION_INTERPRETER_CASCADE: &str = "interpreter_cascade";
pub const DETECTION_PROCESS_FAN_OUT: &str = "process_fan_out";
pub const DETECTION_CAPABILITY_LAUNDERING: &str = "capability_laundering";

pub const SEQUENCE_RULES: &[DetectionRule] = &[
    DetectionRule {
        id: "VIGIL-L022",
        name: "Sensitive read followed by egress",
        severity: Severity::High,
        confidence: Confidence::Medium,
        tactic: Tactic::Exfiltration,
        description: "The session reached for a protected resource and then attempted an \
                      outbound connection.",
        dimension: RiskDimension::Exfiltration,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L023",
        name: "Archive before egress",
        severity: Severity::High,
        confidence: Confidence::Medium,
        tactic: Tactic::Exfiltration,
        description: "Several protected resources were reached for, then an archiving tool, \
                      then an outbound connection.",
        dimension: RiskDimension::Exfiltration,
        weight: 60,
    },
    DetectionRule {
        id: "VIGIL-L024",
        name: "Interpreter cascade",
        severity: Severity::High,
        confidence: Confidence::Medium,
        tactic: Tactic::ToolAbuse,
        description: "A chain of shells and interpreters was launched, each from the last.",
        dimension: RiskDimension::ProcessAnomaly,
        weight: 40,
    },
    // The only cross-*session* rule in the catalogue. Confidence is medium because two agents
    // legitimately working the same repository can both reach the same protected path without
    // one having laundered anything through the other.
    DetectionRule {
        id: "VIGIL-L026-LAUNDERING",
        name: "Capability laundering across sessions",
        severity: Severity::High,
        confidence: Confidence::Medium,
        tactic: Tactic::DelegationAbuse,
        description: "A resource refused to one session was then requested by a different one.",
        dimension: RiskDimension::CapabilityAnomaly,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L025",
        name: "Excessive process fan-out",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tactic: Tactic::DestructiveAction,
        description: "The session launched processes far faster than ordinary work requires.",
        dimension: RiskDimension::ProcessAnomaly,
        weight: 20,
    },
];

/// One step, normalized out of the event log so rules read a timeline rather than raw events.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    at: DateTime<Utc>,
    sequence: i64,
    kind: StepKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StepKind {
    /// A protected resource was reached for. Whether it was *permitted* is not the point —
    /// a refused attempt is as much a step in a sequence as a successful one.
    SensitiveReach { resource: String },
    /// An outbound connection was attempted.
    Egress { destination: String },
    /// A process was launched, with the class VIGIL assigns its executable.
    Exec {
        executable: String,
        class: ExecutableClass,
    },
}

/// Executables whose purpose is to bundle many files into one.
///
/// The step that turns "read several files" into "prepared a payload".
const ARCHIVE_TOOLS: &[&str] = &[
    "tar", "zip", "gzip", "bzip2", "xz", "7z", "7za", "zstd", "ditto", "hdiutil", "cpio", "pax",
];

fn is_archive_tool(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|name| ARCHIVE_TOOLS.contains(&name.as_str()))
}

/// One thing the analysis concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceFinding {
    pub rule_id: String,
    pub name: String,
    /// Ordered, human-readable steps. Every entry corresponds to a stored event.
    pub steps: Vec<String>,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub session_id: String,
    pub events_considered: usize,
    pub processes_considered: usize,
    pub findings: Vec<SequenceFinding>,
    /// Findings that were already on record from an earlier run.
    pub already_recorded: usize,
    pub risk_state: RiskState,
}

impl LocalStore {
    /// Analyze a session's stored evidence for shapes that need more than one event to see.
    ///
    /// Idempotent: a finding already recorded for this session is counted, not re-recorded.
    pub fn analyze_session(&self, session_id: &str) -> Result<AnalysisReport> {
        let events = self.events_for_session(session_id)?;
        let graph = self.process_graph(session_id)?;
        let steps = timeline(&events);

        let mut findings = Vec::new();
        findings.extend(sensitive_read_then_egress(&steps));
        findings.extend(archive_before_egress(&steps));
        findings.extend(process_fan_out(&steps));
        findings.extend(interpreter_cascade(&graph));
        findings.extend(self.capability_laundering(session_id, &steps)?);

        let existing: Vec<String> = self
            .detections_for_session(session_id)?
            .into_iter()
            .filter_map(|detection| {
                detection
                    .evidence
                    .get("fingerprint")
                    .and_then(|value| value.as_str().map(str::to_string))
            })
            .collect();

        let mut risk_state = self.session_risk_state(session_id)?;
        let mut already_recorded = 0usize;
        let mut recorded = Vec::new();

        for finding in findings {
            let Some(rule) = crate::rule_for_label(label_for(&finding.rule_id)) else {
                continue;
            };
            let fingerprint = fingerprint_of(session_id, &finding)?;
            if existing.contains(&fingerprint) {
                already_recorded += 1;
                continue;
            }
            let mut evidence = finding.evidence.clone();
            if let Some(object) = evidence.as_object_mut() {
                object.insert("fingerprint".to_string(), serde_json::json!(fingerprint));
                object.insert("steps".to_string(), serde_json::json!(finding.steps));
                // These conclusions are drawn after the fact and could not have blocked
                // anything; saying so in the record keeps the distinction from a
                // decision-time detection.
                object.insert("retrospective".to_string(), serde_json::json!(true));
            }
            self.record_detection(session_id, rule, evidence, None)?;
            risk_state = self.record_risk_signal(
                session_id,
                rule.dimension,
                rule.weight,
                None,
                rule.description,
            )?;
            if rule.severity >= Severity::Critical || risk_state.revokes_leases() {
                let incident = self.open_incident(session_id, rule.severity, &finding.name)?;
                self.attach_detections(&incident.incident_id, session_id)?;
            }
            recorded.push(finding);
        }

        self.append_event(
            session_id,
            "analysis",
            "analysis.completed",
            Some(if recorded.is_empty() {
                "CLEAR"
            } else {
                "FINDINGS"
            }),
            &format!("cor_{}", uuid::Uuid::new_v4().simple()),
            &serde_json::json!({
                "events_considered": events.len(),
                "processes_considered": graph.nodes.len(),
                "findings": recorded.len(),
                "already_recorded": already_recorded,
                "retrospective": true,
            }),
        )?;

        Ok(AnalysisReport {
            session_id: session_id.to_string(),
            events_considered: events.len(),
            processes_considered: graph.nodes.len(),
            findings: recorded,
            already_recorded,
            risk_state,
        })
    }
}

impl LocalStore {
    /// §35 — a resource one session was refused, requested by a different one.
    ///
    /// The pattern this names is an agent that cannot do something arranging for another
    /// principal to do it instead. The signal VIGIL can actually see is narrower than the
    /// concept: it cannot prove one session *caused* the other, only that a refusal in one was
    /// followed by the same request in another. That is why confidence is medium and why the
    /// evidence names both sessions rather than asserting a relationship between them.
    ///
    /// Only *detection-bearing* refusals count. A budget exhaustion or a transient failure is
    /// not a statement that the resource is forbidden, and treating it as one would implicate
    /// every session that later touched a file someone briefly ran out of budget on.
    fn capability_laundering(
        &self,
        session_id: &str,
        steps: &[Step],
    ) -> Result<Vec<SequenceFinding>> {
        let requested: Vec<&str> = steps
            .iter()
            .filter_map(|step| match &step.kind {
                StepKind::SensitiveReach { resource } => Some(resource.as_str()),
                _ => None,
            })
            .collect();
        if requested.is_empty() {
            return Ok(Vec::new());
        }

        let refused = self.resources_refused_to_other_sessions(session_id, LAUNDERING_WINDOW)?;
        let mut findings = Vec::new();
        for (resource, other_session) in refused {
            if !requested.contains(&resource.as_str()) {
                continue;
            }
            findings.push(SequenceFinding {
                rule_id: "VIGIL-L026-LAUNDERING".to_string(),
                name: "Capability laundering across sessions".to_string(),
                steps: vec![
                    format!("session {other_session} was refused {resource}"),
                    format!("session {session_id} then requested the same resource"),
                ],
                evidence: serde_json::json!({
                    "resource": resource,
                    "refused_in_session": other_session,
                    "requested_in_session": session_id,
                    "window_seconds": LAUNDERING_WINDOW,
                    // Stated so nobody reads this as proof of coordination.
                    "causation_established": false,
                }),
            });
            break;
        }
        Ok(findings)
    }

    /// Resources a *different* session was refused, with a detection naming why.
    fn resources_refused_to_other_sessions(
        &self,
        session_id: &str,
        window_seconds: i64,
    ) -> Result<Vec<(String, String)>> {
        let since = (Utc::now() - Duration::seconds(window_seconds)).to_rfc3339();
        let mut statement = self
            .connection
            .prepare(
                // The resource lives inside the evidence document, and different rules name
                // it differently. COALESCE over the keys actually used rather than assuming
                // one — a missing key yields NULL and is filtered out, so a rule whose
                // evidence has no resource simply does not participate.
                "SELECT DISTINCT
                     COALESCE(
                         json_extract(evidence_json, '$.resolved_resource'),
                         json_extract(evidence_json, '$.resource'),
                         json_extract(evidence_json, '$.path')
                     ) AS resource,
                     session_id
                 FROM detections
                 WHERE session_id != ?1 AND at > ?2 AND resource IS NOT NULL",
            )
            .map_err(super::store::storage_error)?;
        let rows = statement
            .query_map(rusqlite::params![session_id, since], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(super::store::storage_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(super::store::storage_error)?;
        Ok(rows)
    }
}

/// Map a rule id back to the label the catalogue is keyed on.
fn label_for(rule_id: &str) -> &'static str {
    match rule_id {
        "VIGIL-L022" => DETECTION_SENSITIVE_READ_THEN_EGRESS,
        "VIGIL-L023" => DETECTION_ARCHIVE_BEFORE_EGRESS,
        "VIGIL-L024" => DETECTION_INTERPRETER_CASCADE,
        "VIGIL-L026-LAUNDERING" => DETECTION_CAPABILITY_LAUNDERING,
        _ => DETECTION_PROCESS_FAN_OUT,
    }
}

/// Fingerprint a finding so re-analysis does not record it twice.
fn fingerprint_of(session_id: &str, finding: &SequenceFinding) -> Result<String> {
    let document = serde_json::json!({
        "session_id": session_id,
        "rule_id": finding.rule_id,
        "steps": finding.steps,
    });
    Ok(ContentHash::canonical_json(&document)?.to_string())
}

/// Normalize the event log into an ordered timeline of security-relevant steps.
fn timeline(events: &[crate::LocalEvent]) -> Vec<Step> {
    let mut steps = Vec::new();
    for event in events {
        let resource = event
            .payload
            .get("resolved_resource")
            .and_then(serde_json::Value::as_str);
        let detection = event
            .payload
            .get("detection")
            .and_then(serde_json::Value::as_str);

        let kind = match event.category.as_str() {
            // A reach for a protected resource, permitted or not. A refusal is still a step:
            // the sequence is about what the session was trying to do.
            "policy" | "filesystem"
                if matches!(
                    detection,
                    Some(crate::DETECTION_CREDENTIAL_ACCESS)
                        | Some(crate::DETECTION_PERSISTENCE_ATTEMPT)
                        | Some(crate::DETECTION_SECURITY_CONTROL_MODIFICATION)
                ) =>
            {
                Some(StepKind::SensitiveReach {
                    resource: resource.unwrap_or("<unknown>").to_string(),
                })
            }
            "network" | "policy" if event.action == "network.connect" => {
                Some(StepKind::Egress {
                    // A network decision carries the destination as the *requested*
                    // resource; `resolved_resource` is null because a destination is not a
                    // path that gets resolved. Reading only the resolved field reported
                    // `<unknown>` for every egress step.
                    destination: event
                        .payload
                        .get("destination")
                        .and_then(serde_json::Value::as_str)
                        .or(resource)
                        .or_else(|| {
                            event
                                .payload
                                .get("requested_resource")
                                .and_then(serde_json::Value::as_str)
                        })
                        .unwrap_or("<unknown>")
                        .to_string(),
                })
            }
            "process" if event.action == "process.spawn" || event.action == "process.exec" => {
                let executable = event
                    .payload
                    .get("executable")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Some(StepKind::Exec {
                    class: crate::classify_executable(Path::new(&executable)),
                    executable,
                })
            }
            _ => None,
        };
        if let Some(kind) = kind {
            steps.push(Step {
                at: event.timestamp,
                sequence: event.sequence,
                kind,
            });
        }
    }
    steps
}

fn within(earlier: &Step, later: &Step, seconds: i64) -> bool {
    later.at >= earlier.at && later.at - earlier.at <= Duration::seconds(seconds)
}

/// §35 — a protected resource reached for, then an outbound connection.
fn sensitive_read_then_egress(steps: &[Step]) -> Vec<SequenceFinding> {
    let mut findings = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let StepKind::SensitiveReach { resource } = &step.kind else {
            continue;
        };
        let egress = steps[index + 1..].iter().find(|later| {
            matches!(later.kind, StepKind::Egress { .. }) && within(step, later, SEQUENCE_WINDOW)
        });
        let Some(egress) = egress else { continue };
        let StepKind::Egress { destination } = &egress.kind else {
            continue;
        };
        findings.push(SequenceFinding {
            rule_id: "VIGIL-L022".to_string(),
            name: "Sensitive read followed by egress".to_string(),
            steps: vec![
                format!("reached for {resource}"),
                format!("attempted {destination}"),
            ],
            evidence: serde_json::json!({
                "resource": resource,
                "destination": destination,
                "window_seconds": SEQUENCE_WINDOW,
                "gap_seconds": (egress.at - step.at).num_seconds(),
            }),
        });
        // One finding per sequence, not one per pair: a session that read three credentials
        // and opened one connection is one story.
        break;
    }
    findings
}

/// §35 — several protected resources, then an archiving tool, then egress.
fn archive_before_egress(steps: &[Step]) -> Vec<SequenceFinding> {
    let reaches: Vec<&Step> = steps
        .iter()
        .filter(|step| matches!(step.kind, StepKind::SensitiveReach { .. }))
        .collect();
    if reaches.len() < COLLECTION_THRESHOLD {
        return Vec::new();
    }
    let first = reaches[0];

    let Some(archive) = steps.iter().find(|step| {
        matches!(&step.kind, StepKind::Exec { executable, .. } if is_archive_tool(executable))
            && step.sequence > first.sequence
    }) else {
        return Vec::new();
    };
    let Some(egress) = steps.iter().find(|step| {
        matches!(step.kind, StepKind::Egress { .. }) && step.sequence > archive.sequence
    }) else {
        return Vec::new();
    };

    let StepKind::Exec { executable, .. } = &archive.kind else {
        return Vec::new();
    };
    let StepKind::Egress { destination } = &egress.kind else {
        return Vec::new();
    };
    vec![SequenceFinding {
        rule_id: "VIGIL-L023".to_string(),
        name: "Archive before egress".to_string(),
        steps: vec![
            format!("reached for {} protected resources", reaches.len()),
            format!("ran {executable}"),
            format!("attempted {destination}"),
        ],
        evidence: serde_json::json!({
            "sensitive_reaches": reaches.len(),
            "archive_tool": executable,
            "destination": destination,
        }),
    }]
}

/// §35 — processes launched far faster than ordinary work requires.
fn process_fan_out(steps: &[Step]) -> Vec<SequenceFinding> {
    let execs: Vec<&Step> = steps
        .iter()
        .filter(|step| matches!(step.kind, StepKind::Exec { .. }))
        .collect();
    for (index, start) in execs.iter().enumerate() {
        let count = execs[index..]
            .iter()
            .take_while(|later| within(start, later, FAN_OUT_WINDOW))
            .count();
        if count >= FAN_OUT_THRESHOLD {
            return vec![SequenceFinding {
                rule_id: "VIGIL-L025".to_string(),
                name: "Excessive process fan-out".to_string(),
                steps: vec![format!(
                    "launched {count} processes within {FAN_OUT_WINDOW}s"
                )],
                evidence: serde_json::json!({
                    "processes": count,
                    "window_seconds": FAN_OUT_WINDOW,
                    "threshold": FAN_OUT_THRESHOLD,
                }),
            }];
        }
    }
    Vec::new()
}

/// §35 — a chain of shells and interpreters, each launched from the last.
///
/// A graph rule, not a sequence one: what matters is lineage, not adjacency in time. Two
/// interpreters started independently by the same session are ordinary; an interpreter started
/// *by* a shell started *by* an interpreter is a cascade.
fn interpreter_cascade(graph: &crate::ProcessGraph) -> Vec<SequenceFinding> {
    let by_id: BTreeMap<&str, &crate::ProcessNode> = graph
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect();

    let is_interpreting = |node: &crate::ProcessNode| {
        matches!(
            crate::classify_executable(Path::new(&node.executable)),
            ExecutableClass::Shell | ExecutableClass::Interpreter
        )
    };

    for node in &graph.nodes {
        if !is_interpreting(node) {
            continue;
        }
        // Walk up the recorded lineage counting consecutive interpreting ancestors.
        let mut chain = vec![node.executable.clone()];
        let mut current = node.parent_node_id.as_deref();
        let mut seen = vec![node.node_id.as_str()];
        while let Some(parent_id) = current {
            let Some(parent) = by_id.get(parent_id) else {
                break;
            };
            if seen.contains(&parent.node_id.as_str()) || !is_interpreting(parent) {
                break;
            }
            seen.push(parent.node_id.as_str());
            chain.push(parent.executable.clone());
            current = parent.parent_node_id.as_deref();
        }
        if chain.len() >= 3 {
            chain.reverse();
            return vec![SequenceFinding {
                rule_id: "VIGIL-L024".to_string(),
                name: "Interpreter cascade".to_string(),
                steps: chain.clone(),
                evidence: serde_json::json!({ "chain": chain, "depth": chain.len() }),
            }];
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).expect("timestamp")
    }

    fn reach(seconds: i64, sequence: i64, resource: &str) -> Step {
        Step {
            at: at(seconds),
            sequence,
            kind: StepKind::SensitiveReach {
                resource: resource.to_string(),
            },
        }
    }

    fn egress(seconds: i64, sequence: i64, destination: &str) -> Step {
        Step {
            at: at(seconds),
            sequence,
            kind: StepKind::Egress {
                destination: destination.to_string(),
            },
        }
    }

    fn exec(seconds: i64, sequence: i64, executable: &str) -> Step {
        Step {
            at: at(seconds),
            sequence,
            kind: StepKind::Exec {
                class: crate::classify_executable(Path::new(executable)),
                executable: executable.to_string(),
            },
        }
    }

    #[test]
    fn a_credential_reach_followed_by_egress_is_one_finding() {
        let steps = vec![
            reach(0, 1, "/home/u/.ssh/id_ed25519"),
            reach(5, 2, "/home/u/.aws/credentials"),
            egress(10, 3, "attacker.example:443"),
        ];
        let findings = sensitive_read_then_egress(&steps);
        assert_eq!(
            findings.len(),
            1,
            "one sequence is one story, not one per pair"
        );
        assert_eq!(findings[0].rule_id, "VIGIL-L022");
    }

    /// The ordering requirement is the whole rule: egress *then* a credential reach is not
    /// exfiltration, and reporting it as such would train an operator to ignore the finding.
    #[test]
    fn egress_before_the_reach_is_not_a_sequence() {
        let steps = vec![
            egress(0, 1, "github.com:443"),
            reach(10, 2, "/home/u/.ssh/id_ed25519"),
        ];
        assert!(sensitive_read_then_egress(&steps).is_empty());
    }

    /// Unrelated activity separated by an hour is not a plot.
    #[test]
    fn steps_outside_the_window_are_not_a_sequence() {
        let steps = vec![
            reach(0, 1, "/home/u/.ssh/id_ed25519"),
            egress(SEQUENCE_WINDOW + 60, 2, "attacker.example:443"),
        ];
        assert!(sensitive_read_then_egress(&steps).is_empty());
    }

    #[test]
    fn collection_then_archive_then_egress_is_reported() {
        let steps = vec![
            reach(0, 1, "/home/u/.ssh/id_ed25519"),
            reach(1, 2, "/home/u/.aws/credentials"),
            reach(2, 3, "/home/u/.kube/config"),
            exec(3, 4, "/usr/bin/tar"),
            egress(4, 5, "attacker.example:443"),
        ];
        let findings = archive_before_egress(&steps);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VIGIL-L023");

        // The archive step must come after the reaches; archiving first is ordinary work.
        let reordered = vec![
            exec(0, 1, "/usr/bin/tar"),
            reach(1, 2, "/home/u/.ssh/id_ed25519"),
            reach(2, 3, "/home/u/.aws/credentials"),
            reach(3, 4, "/home/u/.kube/config"),
            egress(4, 5, "attacker.example:443"),
        ];
        assert!(archive_before_egress(&reordered).is_empty());
    }

    #[test]
    fn fewer_reaches_than_the_threshold_is_not_collection() {
        let steps = vec![
            reach(0, 1, "/home/u/.ssh/id_ed25519"),
            exec(1, 2, "/usr/bin/tar"),
            egress(2, 3, "attacker.example:443"),
        ];
        assert!(archive_before_egress(&steps).is_empty());
    }

    #[test]
    fn fan_out_is_a_rate_not_a_total() {
        // Twenty processes spread over an hour is ordinary work.
        let slow: Vec<Step> = (0..25)
            .map(|index| exec(index * 120, index, "/bin/echo"))
            .collect();
        assert!(process_fan_out(&slow).is_empty());

        // Twenty in a minute is not.
        let fast: Vec<Step> = (0..25)
            .map(|index| exec(index, index, "/bin/echo"))
            .collect();
        let findings = process_fan_out(&fast);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VIGIL-L025");
    }

    fn node(id: &str, parent: Option<&str>, executable: &str) -> crate::ProcessNode {
        crate::ProcessNode {
            node_id: id.to_string(),
            session_id: "ags_1".to_string(),
            parent_node_id: parent.map(str::to_string),
            pid: 1,
            started_at: Utc::now(),
            exited_at: None,
            executable: executable.to_string(),
            executable_sha256: None,
            argv: Vec::new(),
            generation: 0,
            exit_code: None,
            status: crate::ProcessStatus::Running,
        }
    }

    fn graph(nodes: Vec<crate::ProcessNode>) -> crate::ProcessGraph {
        crate::ProcessGraph {
            session_id: "ags_1".to_string(),
            nodes,
            edges: Vec::new(),
        }
    }

    #[test]
    fn a_cascade_is_lineage_not_adjacency() {
        // shell → interpreter → shell, each launched from the last.
        let cascade = graph(vec![
            node("a", None, "/bin/sh"),
            node("b", Some("a"), "/usr/bin/python3"),
            node("c", Some("b"), "/bin/bash"),
        ]);
        let findings = interpreter_cascade(&cascade);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "VIGIL-L024");
        assert_eq!(findings[0].steps.len(), 3);

        // The same three interpreters started independently are not a cascade.
        let flat = graph(vec![
            node("a", None, "/bin/sh"),
            node("b", None, "/usr/bin/python3"),
            node("c", None, "/bin/bash"),
        ]);
        assert!(interpreter_cascade(&flat).is_empty());

        // A non-interpreter breaking the chain ends it.
        let broken = graph(vec![
            node("a", None, "/bin/sh"),
            node("b", Some("a"), "/bin/echo"),
            node("c", Some("b"), "/bin/bash"),
        ]);
        assert!(interpreter_cascade(&broken).is_empty());
    }

    #[test]
    fn a_cycle_in_lineage_terminates() {
        let cyclic = graph(vec![
            node("a", Some("b"), "/bin/sh"),
            node("b", Some("a"), "/bin/bash"),
        ]);
        // Must return rather than loop; two nodes cannot reach the depth-3 threshold.
        assert!(interpreter_cascade(&cyclic).is_empty());
    }
}
