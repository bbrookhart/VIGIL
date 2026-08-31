//! Fuzz policy bundle parsing.
//!
//! Bundles are operator-authored rather than attacker-supplied, so this is about robustness
//! rather than an attack surface: a malformed bundle must produce an error, never a panic and
//! never a bundle that silently permits more than it says.
//!
//! The property beyond "does not crash": any bundle that loads must survive validation, and
//! validation must reject the shapes that quietly disable enforcement.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_policy::{PolicyBundle, PolicyEffect};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(bundle) = PolicyBundle::from_yaml(text) else {
        return;
    };

    // `from_yaml` validates, so anything that loaded must still validate.
    bundle
        .validate()
        .expect("a bundle returned by from_yaml must satisfy validate");

    // The guards that stop a bundle from silently disabling enforcement.
    for rule in &bundle.rules {
        assert!(!rule.id.trim().is_empty(), "a rule with an empty id loaded");
        if rule.matcher.match_all {
            assert!(
                !matches!(rule.effect, PolicyEffect::Allow),
                "a universal allow rule loaded: `{}`",
                rule.id
            );
        }
    }

    // Rule ids must be unique, or a decision cannot be attributed to one rule.
    let mut seen = std::collections::HashSet::new();
    for rule in &bundle.rules {
        assert!(seen.insert(rule.id.as_str()), "duplicate rule id loaded");
    }
});
