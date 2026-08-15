//! Lexical path normalization.
//!
//! # Why
//!
//! Two components need to answer "is this path inside that root?" — the command-safety
//! detector and the remit evaluator. If they normalize differently, one of them is wrong,
//! and the disagreement is exploitable: an attacker picks the form that the *permitting*
//! check normalizes leniently and the *denying* check never sees.
//!
//! # Assumptions
//!
//! Lexical only. It cannot see through symlinks, so `/workspace/link -> /etc` defeats it.
//! The gateway resolves paths against the real filesystem before executing; this function
//! exists to reject the obvious cases early, cheaply, and identically everywhere.

/// Collapse `.` components and resolve `..` where possible.
///
/// A leading `..` in a relative path is *retained* rather than dropped, so an escape stays
/// visible to the caller instead of silently normalizing away.
pub fn normalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|c| *c != "..") {
                    stack.pop();
                } else if !absolute {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Whether a normalized path lies inside one of the permitted roots.
///
/// The trailing-separator comparison is the load-bearing detail: without it,
/// `/workspace-evil` passes a `/workspace` root check by simple prefix match.
pub fn is_inside_any(path: &str, roots: &[String]) -> bool {
    if roots.is_empty() {
        return false;
    }
    let normalized = normalize(path);
    roots.iter().any(|root| {
        let root = normalize(root);
        let root = root.trim_end_matches('/');
        normalized == root || normalized.starts_with(&format!("{root}/"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dots_are_resolved() {
        assert_eq!(normalize("/a/b/../c"), "/a/c");
        assert_eq!(normalize("/a/./b"), "/a/b");
        assert_eq!(normalize("/a/b/../../.."), "/");
        assert_eq!(normalize("a/b/../c"), "a/c");
    }

    #[test]
    fn a_relative_escape_stays_visible() {
        assert_eq!(normalize("../x"), "../x");
        assert_eq!(normalize("../../x"), "../../x");
    }

    #[test]
    fn root_containment_rejects_prefix_lookalikes() {
        let roots = vec!["/workspace".to_string()];
        assert!(is_inside_any("/workspace/a.txt", &roots));
        assert!(is_inside_any("/workspace", &roots));
        assert!(!is_inside_any("/workspace-evil/a.txt", &roots));
        assert!(!is_inside_any("/etc/passwd", &roots));
        assert!(!is_inside_any("/workspace/../etc/passwd", &roots));
    }

    #[test]
    fn no_roots_means_nothing_is_inside() {
        assert!(!is_inside_any("/anything", &[]));
    }
}
