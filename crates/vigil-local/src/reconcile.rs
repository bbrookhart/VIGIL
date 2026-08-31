//! Comparing what the agent said it would do with what the operating system saw.
//!
//! Every other control in this crate answers one question: *should this request be permitted?*
//! This one answers a different and harder question: *did the thing that actually happened
//! match the thing that was asked for?*
//!
//! That distinction is the whole reason VIGIL has two enforcement points. A semantic broker
//! knows the tool, the argument, and the intent, but only sees requests routed through it. An
//! OS observer knows the executable, the file, and the flow, but not why. Neither view alone
//! catches an agent that declares a benign intent and performs a different operation — the
//! declaration looks fine, and the operation looks like ordinary process activity.
//!
//! # What a mismatch means
//!
//! The strongest finding here is not "an unexpected file was touched". It is
//! [`MismatchClass::DeniedOperationObserved`]: VIGIL refused an operation and the OS saw it
//! happen anyway. That is proof the broker was bypassed, and it is the only finding in this
//! module that means the semantic layer was *defeated* rather than merely incomplete.
//!
//! # Where observations come from
//!
//! [`ObservedOperation`] is deliberately not tied to Endpoint Security. It is the shape an OS
//! observer reports, and today the only producers are `vigil-endpoint`'s deterministic
//! simulator and hand-written fixtures. When an entitled System Extension exists it becomes
//! the third producer and nothing in this engine changes.
//!
//! **Absence of observations is not evidence of absence.** With no installed extension, an
//! empty observation set means "nothing was watching", not "nothing happened", and
//! [`Reconciliation::coverage`] says which of those it was.

use crate::detection::{Confidence, DetectionRule, Severity, Tactic};
use crate::{LocalStore, RiskDimension, RiskState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vigil_common::{Result, VigilError};

/// Bound on how many observations one reconciliation will consider.
const MAX_OBSERVATIONS: usize = 100_000;

pub const DETECTION_DENIED_OPERATION_OBSERVED: &str = "denied_operation_observed";
pub const DETECTION_INTENT_RESOURCE_MISMATCH: &str = "intent_resource_mismatch";
pub const DETECTION_UNDECLARED_SIDE_EFFECT: &str = "undeclared_side_effect";
pub const DETECTION_UNDECLARED_CHILD_PROCESS: &str = "undeclared_child_process";
pub const DETECTION_SCOPE_EXPANSION: &str = "scope_expansion";

/// Detection rules this module owns, merged into the catalogue in `detection.rs`.
pub const RECONCILE_RULES: &[DetectionRule] = &[
    DetectionRule {
        id: "VIGIL-L013",
        name: "Denied operation observed",
        severity: Severity::Critical,
        confidence: Confidence::High,
        tactic: Tactic::PolicyEvasion,
        description: "VIGIL refused an operation and the operating system observed it happen.",
        dimension: RiskDimension::IntentExecutionMismatch,
        weight: 80,
    },
    DetectionRule {
        id: "VIGIL-L014",
        name: "Intent-execution resource mismatch",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::PolicyEvasion,
        description: "The operating system observed a resource the session never declared.",
        dimension: RiskDimension::IntentExecutionMismatch,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L015",
        name: "Undeclared side effect",
        severity: Severity::High,
        confidence: Confidence::High,
        tactic: Tactic::PolicyEvasion,
        description: "A resource declared for reading was observed being modified.",
        dimension: RiskDimension::IntentExecutionMismatch,
        weight: 40,
    },
    DetectionRule {
        id: "VIGIL-L016",
        name: "Undeclared child process",
        severity: Severity::High,
        confidence: Confidence::Medium,
        tactic: Tactic::ToolAbuse,
        description: "A process execution was observed that no brokered request declared.",
        dimension: RiskDimension::ProcessAnomaly,
        weight: 20,
    },
    DetectionRule {
        id: "VIGIL-L017",
        name: "Scope expansion",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        tactic: Tactic::DataCollection,
        description: "Undeclared workspace resources were touched beyond the declared set.",
        dimension: RiskDimension::IntentExecutionMismatch,
        weight: 20,
    },
];

/// The kind of operation an OS observer reports.
///
/// Deliberately coarser than the local capability vocabulary. An observer reports what the
/// kernel told it, which is an open with flags — not "the agent intended to edit a config".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedKind {
    Exec,
    Read,
    Write,
    Create,
    Delete,
    Rename,
}

impl ObservedKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Read => "read",
            Self::Write => "write",
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Rename => "rename",
        }
    }

    /// Whether this operation changes the resource.
    ///
    /// The read/mutate split is what makes an undeclared side effect distinguishable from an
    /// undeclared look: declaring a read and performing a write is a different failure from
    /// declaring a read and performing a different read.
    pub const fn mutates(self) -> bool {
        matches!(
            self,
            Self::Write | Self::Create | Self::Delete | Self::Rename
        )
    }
}

/// One operation an OS observer attributed to a managed session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedOperation {
    /// Opaque process identity from the observer — an audit-token digest, never a PID.
    pub process: String,
    pub kind: ObservedKind,
    /// The path the OS resolved, which is the object actually opened.
    pub path: String,
    /// What the OS-level enforcement point decided. A refused operation did not happen, so it
    /// is not a mismatch; only operations that took effect are reconciled.
    #[serde(default = "default_true")]
    pub allowed: bool,
}

const fn default_true() -> bool {
    true
}

/// One thing the session told VIGIL it was doing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeclaredIntent {
    pub action: String,
    pub resource: String,
    /// Whether VIGIL permitted it. A refused declaration is the strongest baseline of all:
    /// if the OS then saw it happen, the broker was bypassed.
    pub permitted: bool,
}

/// How a single observation failed to line up with what was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MismatchClass {
    /// VIGIL denied this exact resource and the OS observed it anyway.
    DeniedOperationObserved,
    /// A resource outside the declared set entirely.
    ResourceMismatch,
    /// Declared for reading, observed being modified.
    UndeclaredSideEffect,
    /// A process execution nothing declared.
    ChildProcessMismatch,
    /// Extra resources inside the workspace, beyond what was declared.
    ScopeExpansion,
}

impl MismatchClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeniedOperationObserved => "DENIED_OPERATION_OBSERVED",
            Self::ResourceMismatch => "RESOURCE_MISMATCH",
            Self::UndeclaredSideEffect => "UNDECLARED_SIDE_EFFECT",
            Self::ChildProcessMismatch => "CHILD_PROCESS_MISMATCH",
            Self::ScopeExpansion => "SCOPE_EXPANSION",
        }
    }

    pub const fn detection_label(self) -> &'static str {
        match self {
            Self::DeniedOperationObserved => DETECTION_DENIED_OPERATION_OBSERVED,
            Self::ResourceMismatch => DETECTION_INTENT_RESOURCE_MISMATCH,
            Self::UndeclaredSideEffect => DETECTION_UNDECLARED_SIDE_EFFECT,
            Self::ChildProcessMismatch => DETECTION_UNDECLARED_CHILD_PROCESS,
            Self::ScopeExpansion => DETECTION_SCOPE_EXPANSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mismatch {
    pub class: MismatchClass,
    pub observed: ObservedOperation,
    /// The declaration this observation was compared against, when there was one.
    pub declared: Option<DeclaredIntent>,
    pub explanation: String,
}

/// Whether the reconciliation had anything to reconcile against.
///
/// This exists so that "no mismatches" cannot be read as "nothing went wrong" when in fact
/// nothing was watching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Observations were supplied and compared.
    Observed,
    /// No observations were supplied. Silence here means nothing at all.
    NoObserver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    pub session_id: String,
    pub coverage: Coverage,
    pub declared: Vec<DeclaredIntent>,
    pub observations_considered: usize,
    /// Observations that lined up with something declared.
    pub matched: usize,
    pub mismatches: Vec<Mismatch>,
}

impl Reconciliation {
    /// Whether the observed execution is consistent with what was declared.
    ///
    /// Always false when there was no observer: an unwatched session is not a clean one.
    pub fn consistent(&self) -> bool {
        self.coverage == Coverage::Observed && self.mismatches.is_empty()
    }
}

/// Compare declared intents against observed operations.
///
/// Pure and deterministic: the same inputs always produce the same findings, in the same
/// order. Storage and risk are the caller's business, so this can be tested and replayed
/// without a database.
pub fn reconcile(
    session_id: &str,
    workspace: &str,
    declared: &[DeclaredIntent],
    observed: &[ObservedOperation],
) -> Reconciliation {
    let coverage = if observed.is_empty() {
        Coverage::NoObserver
    } else {
        Coverage::Observed
    };

    // Index declarations by resource. A resource may be declared more than once with
    // different actions, so keep every declaration for it.
    let mut by_resource: BTreeMap<&str, Vec<&DeclaredIntent>> = BTreeMap::new();
    for intent in declared {
        by_resource
            .entry(intent.resource.as_str())
            .or_default()
            .push(intent);
    }

    let mut matched = 0usize;
    let mut mismatches = Vec::new();
    let considered = observed.len().min(MAX_OBSERVATIONS);

    for operation in observed.iter().take(MAX_OBSERVATIONS) {
        // An operation the OS refused did not take effect. Reconciliation is about what
        // happened, not about what was attempted and stopped.
        if !operation.allowed {
            continue;
        }

        let declarations = by_resource.get(operation.path.as_str());

        // A refusal that happened anyway outranks everything else this function can find.
        if let Some(denied) =
            declarations.and_then(|found| found.iter().find(|intent| !intent.permitted))
        {
            mismatches.push(Mismatch {
                class: MismatchClass::DeniedOperationObserved,
                observed: operation.clone(),
                declared: Some((*denied).clone()),
                explanation: format!(
                    "VIGIL refused `{}` on this resource and the operating system observed a \
                     {} of it; the broker was bypassed",
                    denied.action,
                    operation.kind.as_str()
                ),
            });
            continue;
        }

        let permitted: Vec<&DeclaredIntent> = declarations
            .map(|found| {
                found
                    .iter()
                    .filter(|intent| intent.permitted)
                    .copied()
                    .collect()
            })
            .unwrap_or_default();

        if operation.kind == ObservedKind::Exec {
            if permitted.is_empty() {
                mismatches.push(Mismatch {
                    class: MismatchClass::ChildProcessMismatch,
                    observed: operation.clone(),
                    declared: None,
                    explanation:
                        "a process execution was observed that no brokered request declared"
                            .to_string(),
                });
            } else {
                matched += 1;
            }
            continue;
        }

        if permitted.is_empty() {
            // Undeclared. How bad depends on where it is: inside the workspace this is the
            // session doing more than it said; outside, it is the session going somewhere it
            // never mentioned at all.
            let class = if is_inside(&operation.path, workspace) {
                MismatchClass::ScopeExpansion
            } else {
                MismatchClass::ResourceMismatch
            };
            mismatches.push(Mismatch {
                class,
                observed: operation.clone(),
                declared: None,
                explanation: format!(
                    "a {} of this resource was observed but the session never declared it",
                    operation.kind.as_str()
                ),
            });
            continue;
        }

        // Declared. The remaining question is whether the operation stayed within what the
        // declaration implied: declaring a read and performing a write is a side effect the
        // semantic layer never authorized.
        let mutation_declared = permitted
            .iter()
            .any(|intent| declares_mutation(&intent.action));
        if operation.kind.mutates() && !mutation_declared {
            let read_only = permitted[0];
            mismatches.push(Mismatch {
                class: MismatchClass::UndeclaredSideEffect,
                observed: operation.clone(),
                declared: Some(read_only.clone()),
                explanation: format!(
                    "the session declared `{}` on this resource but a {} of it was observed",
                    read_only.action,
                    operation.kind.as_str()
                ),
            });
        } else {
            matched += 1;
        }
    }

    Reconciliation {
        session_id: session_id.to_string(),
        coverage,
        declared: declared.to_vec(),
        observations_considered: considered,
        matched,
        mismatches,
    }
}

/// Whether a declared action implies the resource may be changed.
fn declares_mutation(action: &str) -> bool {
    matches!(
        action,
        "fs.write" | "fs.create" | "fs.delete" | "fs.rename" | "process.exec"
    )
}

/// Path containment by component, so `/work-evil` is not inside `/work`.
fn is_inside(path: &str, workspace: &str) -> bool {
    if workspace.is_empty() {
        return false;
    }
    let workspace = workspace.trim_end_matches('/');
    path == workspace
        || path
            .strip_prefix(workspace)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl LocalStore {
    /// Everything this session told VIGIL it was doing, from the event log.
    ///
    /// Read back from stored evidence rather than accumulated in memory, so a reconciliation
    /// can be run long after the session ended and against a log whose integrity can be
    /// checked independently.
    pub fn declared_intents(&self, session_id: &str) -> Result<Vec<DeclaredIntent>> {
        let mut declared = Vec::new();
        for event in self.events_for_session(session_id)? {
            let permitted = match event.decision.as_deref() {
                Some("EXECUTED") | Some("ALLOW") | Some("OBSERVED") => true,
                Some("DENY") | Some("REQUIRE_APPROVAL") => false,
                _ => continue,
            };
            let resource = event
                .payload
                .get("resolved_resource")
                .or_else(|| event.payload.get("executable"))
                .and_then(serde_json::Value::as_str);
            let Some(resource) = resource else {
                continue;
            };
            // `policy` events carry the action inside the decision document; broker events
            // carry it as the event action.
            let action = event
                .payload
                .get("action")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&event.action);
            let action = match action {
                "process.spawn" | "process.exec" => "process.exec",
                other => other,
            };
            declared.push(DeclaredIntent {
                action: action.to_string(),
                resource: resource.to_string(),
                permitted,
            });
        }
        declared.sort();
        declared.dedup();
        Ok(declared)
    }

    /// Reconcile a session's declarations against observed operations, and record what it
    /// finds as detections.
    ///
    /// Returns the report together with the session's risk state afterwards.
    pub fn reconcile_session(
        &self,
        session_id: &str,
        observed: &[ObservedOperation],
    ) -> Result<(Reconciliation, RiskState)> {
        if observed.len() > MAX_OBSERVATIONS {
            return Err(VigilError::InvalidRequest(format!(
                "a reconciliation accepts at most {MAX_OBSERVATIONS} observations"
            )));
        }
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        let declared = self.declared_intents(session_id)?;
        let report = reconcile(session_id, &session.workspace, &declared, observed);

        let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
        let mut risk_state = self.session_risk_state(session_id)?;

        // One detection per distinct class, carrying every instance as evidence. A session
        // that touched forty undeclared files is one finding with forty examples, not forty
        // findings an operator has to page through.
        let mut by_class: BTreeMap<MismatchClass, Vec<&Mismatch>> = BTreeMap::new();
        for mismatch in &report.mismatches {
            by_class.entry(mismatch.class).or_default().push(mismatch);
        }
        for (class, instances) in &by_class {
            let Some(rule) = crate::detection::rule_for_label(class.detection_label()) else {
                continue;
            };
            let examples: Vec<_> = instances
                .iter()
                .take(32)
                .map(|mismatch| {
                    serde_json::json!({
                        "path": mismatch.observed.path,
                        "kind": mismatch.observed.kind.as_str(),
                        "process": mismatch.observed.process,
                        "declared": mismatch.declared,
                        "explanation": mismatch.explanation,
                    })
                })
                .collect();
            self.record_detection(
                session_id,
                rule,
                serde_json::json!({
                    "class": class.as_str(),
                    "instances": instances.len(),
                    "examples": examples,
                }),
                None,
            )?;
            risk_state = self.record_risk_signal(
                session_id,
                rule.dimension,
                rule.weight,
                None,
                rule.description,
            )?;
            if rule.severity >= Severity::Critical || risk_state.revokes_leases() {
                let incident = self.open_incident(
                    session_id,
                    rule.severity,
                    &format!("{} ({} instance(s))", rule.name, instances.len()),
                )?;
                self.attach_detections(&incident.incident_id, session_id)?;
            }
        }

        self.append_event(
            session_id,
            "reconcile",
            "reconcile.report",
            Some(if report.consistent() {
                "CONSISTENT"
            } else if report.coverage == Coverage::NoObserver {
                "NO_OBSERVER"
            } else {
                "MISMATCH"
            }),
            &correlation_id,
            &serde_json::json!({
                "coverage": report.coverage,
                "declared": report.declared.len(),
                "observations_considered": report.observations_considered,
                "matched": report.matched,
                "mismatches": report.mismatches.len(),
                "classes": by_class
                    .keys()
                    .map(|class| class.as_str())
                    .collect::<Vec<_>>(),
                "risk_state": risk_state.as_str(),
                // The observer is a simulator or a fixture until an entitled extension exists.
                "os_enforcement": false,
            }),
        )?;
        Ok((report, risk_state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(action: &str, resource: &str, permitted: bool) -> DeclaredIntent {
        DeclaredIntent {
            action: action.to_string(),
            resource: resource.to_string(),
            permitted,
        }
    }

    fn observed(kind: ObservedKind, path: &str) -> ObservedOperation {
        ObservedOperation {
            process: "prc-token-a".to_string(),
            kind,
            path: path.to_string(),
            allowed: true,
        }
    }

    /// Prompt Demo 8. The agent says it will read `package.json`; the OS sees a child process
    /// reach for an SSH key.
    #[test]
    fn a_declared_read_and_an_observed_credential_access_do_not_reconcile() {
        let report = reconcile(
            "ags_1",
            "/w",
            &[declared("fs.read", "/w/package.json", true)],
            &[
                observed(ObservedKind::Read, "/w/package.json"),
                observed(ObservedKind::Read, "/home/u/.ssh/id_ed25519"),
            ],
        );
        assert!(!report.consistent());
        assert_eq!(report.matched, 1);
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!(report.mismatches[0].class, MismatchClass::ResourceMismatch);
        assert_eq!(
            report.mismatches[0].observed.path,
            "/home/u/.ssh/id_ed25519"
        );
    }

    /// The strongest finding: VIGIL said no and it happened regardless.
    #[test]
    fn an_operation_vigil_denied_being_observed_outranks_every_other_class() {
        let report = reconcile(
            "ags_1",
            "/w",
            &[declared("fs.read", "/home/u/.ssh/id_ed25519", false)],
            &[observed(ObservedKind::Read, "/home/u/.ssh/id_ed25519")],
        );
        assert_eq!(
            report.mismatches[0].class,
            MismatchClass::DeniedOperationObserved
        );
        assert!(report.mismatches[0].explanation.contains("bypassed"));
        // The rule behind it is the only reconciliation rule severe enough to quarantine.
        let rule =
            crate::detection::rule_for_label(DETECTION_DENIED_OPERATION_OBSERVED).expect("rule");
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.weight, 80);
    }

    #[test]
    fn declaring_a_read_and_performing_a_write_is_an_undeclared_side_effect() {
        let report = reconcile(
            "ags_1",
            "/w",
            &[declared("fs.read", "/w/config.toml", true)],
            &[observed(ObservedKind::Write, "/w/config.toml")],
        );
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!(
            report.mismatches[0].class,
            MismatchClass::UndeclaredSideEffect
        );

        // Declaring the write makes the same observation consistent.
        let report = reconcile(
            "ags_1",
            "/w",
            &[declared("fs.write", "/w/config.toml", true)],
            &[observed(ObservedKind::Write, "/w/config.toml")],
        );
        assert!(report.consistent());
    }

    /// Extra files inside the workspace are a different, milder failure from reaching outside
    /// it. Both are findings; conflating them would make the severe one unactionable.
    #[test]
    fn undeclared_resources_are_classified_by_whether_they_escape_the_workspace() {
        let report = reconcile(
            "ags_1",
            "/w",
            &[declared("fs.read", "/w/a.rs", true)],
            &[
                observed(ObservedKind::Read, "/w/b.rs"),
                observed(ObservedKind::Read, "/etc/passwd"),
                // A lookalike sibling directory must not count as inside the workspace.
                observed(ObservedKind::Read, "/w-evil/c.rs"),
            ],
        );
        let classes: Vec<_> = report
            .mismatches
            .iter()
            .map(|mismatch| (mismatch.class, mismatch.observed.path.as_str()))
            .collect();
        assert!(classes.contains(&(MismatchClass::ScopeExpansion, "/w/b.rs")));
        assert!(classes.contains(&(MismatchClass::ResourceMismatch, "/etc/passwd")));
        assert!(classes.contains(&(MismatchClass::ResourceMismatch, "/w-evil/c.rs")));
    }

    #[test]
    fn an_undeclared_execution_is_a_child_process_mismatch() {
        let report = reconcile(
            "ags_1",
            "/w",
            &[declared("process.exec", "/bin/echo", true)],
            &[
                observed(ObservedKind::Exec, "/bin/echo"),
                observed(ObservedKind::Exec, "/bin/sh"),
            ],
        );
        assert_eq!(report.matched, 1);
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!(
            report.mismatches[0].class,
            MismatchClass::ChildProcessMismatch
        );
        assert_eq!(report.mismatches[0].observed.path, "/bin/sh");
    }

    /// An operation the OS refused did not take effect, so it is not a mismatch. Counting it
    /// would report the system working correctly as a failure.
    #[test]
    fn an_operation_the_os_refused_is_not_a_mismatch() {
        let report = reconcile(
            "ags_1",
            "/w",
            &[],
            &[ObservedOperation {
                allowed: false,
                ..observed(ObservedKind::Read, "/etc/shadow")
            }],
        );
        assert!(report.mismatches.is_empty());
        assert_eq!(report.matched, 0);
        // Coverage still reflects that an observer was present.
        assert_eq!(report.coverage, Coverage::Observed);
    }

    /// The trap this whole module has to avoid: with nothing watching, "no mismatches" must
    /// not read as "consistent".
    #[test]
    fn no_observations_is_reported_as_no_observer_rather_than_as_clean() {
        let report = reconcile("ags_1", "/w", &[declared("fs.read", "/w/a.rs", true)], &[]);
        assert!(report.mismatches.is_empty());
        assert_eq!(report.coverage, Coverage::NoObserver);
        assert!(
            !report.consistent(),
            "an unwatched session must never be reported as consistent"
        );
    }

    #[test]
    fn reconciliation_is_deterministic_and_bounded() {
        let declared_set: Vec<_> = (0..50)
            .map(|index| declared("fs.read", &format!("/w/file{index}"), true))
            .collect();
        let observed_set: Vec<_> = (0..50)
            .map(|index| observed(ObservedKind::Read, &format!("/w/file{index}")))
            .collect();
        let first = reconcile("ags_1", "/w", &declared_set, &observed_set);
        let second = reconcile("ags_1", "/w", &declared_set, &observed_set);
        assert_eq!(first, second);
        assert!(first.consistent());
        assert_eq!(first.matched, 50);
    }

    #[test]
    fn containment_is_by_component_not_by_prefix() {
        assert!(is_inside("/w/a", "/w"));
        assert!(is_inside("/w/a", "/w/"));
        assert!(is_inside("/w", "/w"));
        assert!(!is_inside("/w-evil/a", "/w"));
        assert!(!is_inside("/etc/passwd", "/w"));
        assert!(!is_inside("/w/a", ""));
    }
}
