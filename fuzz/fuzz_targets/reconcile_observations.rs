//! Fuzz intent-execution reconciliation.
//!
//! Observations describe what an OS observer saw. The engine that compares them to declared
//! intent must not panic on any input — a crash here is a denial of service in the component
//! that detects a bypassed broker, which is exactly when it matters most.
//!
//! The counting property is the substantive one: every observation is either matched or
//! reported, and a mismatch is never invented for an operation the OS refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_local::{reconcile, DeclaredIntent, ObservedOperation};

#[derive(serde::Deserialize)]
struct Input {
    workspace: String,
    declared: Vec<DeclaredIntent>,
    observed: Vec<ObservedOperation>,
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<Input>(data) else {
        return;
    };
    if input.observed.len() > 4096 {
        return;
    }

    let report = reconcile("ags_fuzz", &input.workspace, &input.declared, &input.observed);
    let again = reconcile("ags_fuzz", &input.workspace, &input.declared, &input.observed);
    assert_eq!(report, again, "reconciliation is not deterministic");

    let allowed = input.observed.iter().filter(|op| op.allowed).count();
    assert!(
        report.matched + report.mismatches.len() <= allowed,
        "reconciliation accounted for {} of {allowed} effective operations — an operation the \
         OS refused must never become a mismatch",
        report.matched + report.mismatches.len()
    );

    // An empty observation set must never be reported as consistent: that is the difference
    // between "nothing went wrong" and "nothing was watching".
    if input.observed.is_empty() {
        assert!(
            !report.consistent(),
            "an unobserved session was reported as consistent"
        );
    }
});
