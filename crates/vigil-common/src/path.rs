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
//! [`normalize`] and [`is_inside_any`] are **lexical only**. They cannot see through symlinks,
//! so `/workspace/link -> /etc` defeats them on its own. They exist to reject the obvious
//! cases early, cheaply, and identically everywhere, including where no filesystem is
//! reachable.
//!
//! [`is_inside_any_resolved`] answers the same question against the real filesystem. It is
//! applied *in addition to* the lexical check and never instead of it, so it can only add a
//! denial — the monotone-toward-restriction rule of ADR 0002 and ADR 0004. A path the lexical
//! check already rejects stays rejected whether or not it resolves.

/// Collapse `.` components and resolve `..` where possible.
///
/// A leading `..` in a relative path is *retained* rather than dropped, so an escape stays
/// visible to the caller instead of silently normalizing away.
pub fn normalize(path: &str) -> String {
    // Treat both separator spellings as structural. On Unix a backslash can be a literal
    // filename character, but accepting it here while the detector folds it to `/` makes the
    // permission and suspicion paths disagree. The conservative interpretation can only deny
    // an unusual Unix filename; it also closes the Windows-style traversal spelling.
    let absolute = path.starts_with('/') || path.starts_with('\\');
    let mut stack: Vec<&str> = Vec::new();
    for component in path.split(|character| character == '/' || character == '\\') {
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
        assert!(!is_inside_any(r"/workspace/x\..\../etc/passwd", &roots));
    }

    #[test]
    fn backslash_and_forward_slash_spellings_normalize_identically() {
        assert_eq!(
            normalize(r"\workspace\notes\..\secret.txt"),
            normalize("/workspace/notes/../secret.txt")
        );
    }

    #[test]
    fn no_roots_means_nothing_is_inside() {
        assert!(!is_inside_any("/anything", &[]));
    }
}

/// What the real filesystem says about containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// Resolves to somewhere inside one of the roots.
    Inside,
    /// Resolves to somewhere outside every root. This is the symlink escape.
    Outside,
    /// The question could not be answered here — no such path, or no filesystem access.
    /// Callers must fall back to the lexical check rather than treating this as permission.
    Unresolved,
}

/// Resolve `path` as far as the real filesystem allows.
///
/// Symlinks in the existing part of the path are followed. A path that does not exist yet —
/// a file about to be created — resolves its deepest existing ancestor and re-appends the
/// rest, because the escape lives in the ancestors: `/workspace/link/newfile` is outside the
/// workspace the moment `link` is, whether or not `newfile` exists.
///
/// Returns `None` only when nothing in the path can be resolved at all. For an absolute path
/// the walk bottoms out at `/`, which always exists, so in practice this returns `Some` and a
/// non-existent path is compared structurally against the root.
pub fn resolve(path: &str) -> Option<std::path::PathBuf> {
    let normalized = normalize(path);
    let normalized = std::path::PathBuf::from(&normalized);
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor: &std::path::Path = normalized.as_path();
    loop {
        if let Ok(real) = cursor.canonicalize() {
            let mut resolved = real;
            for component in tail.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
        match (cursor.parent(), cursor.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_owned());
                cursor = parent;
            }
            _ => return None,
        }
    }
}

/// Whether `path` really lands inside one of `roots`, following symlinks.
///
/// The roots are resolved too: on macOS `/var` is a symlink to `/private/var`, so comparing a
/// resolved path against an unresolved root would report every path as an escape.
///
/// Comparison is component-wise (`Path::starts_with`), so `/workspace-other` is not inside
/// `/workspace` — the prefix confusion a string comparison would admit.
pub fn is_inside_any_resolved(path: &str, roots: &[String]) -> Containment {
    if roots.is_empty() {
        return Containment::Unresolved;
    }
    let Some(resolved) = resolve(path) else {
        return Containment::Unresolved;
    };
    let mut any_root_resolved = false;
    for root in roots {
        let Some(real_root) = resolve(root) else {
            continue;
        };
        any_root_resolved = true;
        if resolved == real_root || resolved.starts_with(&real_root) {
            return Containment::Inside;
        }
    }
    // Only call it an escape if at least one root was real. Otherwise the comparison was
    // never meaningful and the lexical check has to stand alone.
    if any_root_resolved {
        Containment::Outside
    } else {
        Containment::Unresolved
    }
}

#[cfg(test)]
mod resolution_tests {
    use super::*;

    struct Fixture {
        root: std::path::PathBuf,
        workspace: std::path::PathBuf,
    }

    impl Fixture {
        /// A workspace containing `link`, a symlink to a sibling directory outside it.
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("vigil-path-{}", uuid::Uuid::new_v4()));
            let workspace = root.join("workspace");
            let outside = root.join("outside");
            std::fs::create_dir_all(&workspace).expect("workspace");
            std::fs::create_dir_all(&outside).expect("outside");
            std::fs::write(outside.join("secret.txt"), "SENSITIVE").expect("secret");
            std::fs::write(workspace.join("ok.txt"), "fine").expect("ok");
            std::os::unix::fs::symlink(&outside, workspace.join("link")).expect("symlink");
            Self { root, workspace }
        }

        fn roots(&self) -> Vec<String> {
            vec![self.workspace.display().to_string()]
        }

        fn path(&self, relative: &str) -> String {
            self.workspace.join(relative).display().to_string()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_symlink_escape_is_lexically_inside_but_really_outside() {
        // The gap this exists to close. The lexical check has to keep saying `true` here:
        // it is a string operation and cannot know better. What must not happen is the
        // decision resting on it alone.
        let fixture = Fixture::new();
        let escape = fixture.path("link/secret.txt");
        assert!(
            is_inside_any(&escape, &fixture.roots()),
            "lexical containment was expected to be fooled"
        );
        assert_eq!(
            is_inside_any_resolved(&escape, &fixture.roots()),
            Containment::Outside
        );
    }

    #[test]
    fn an_ordinary_path_inside_the_workspace_resolves_inside() {
        let fixture = Fixture::new();
        assert_eq!(
            is_inside_any_resolved(&fixture.path("ok.txt"), &fixture.roots()),
            Containment::Inside
        );
    }

    #[test]
    fn a_file_that_does_not_exist_yet_resolves_through_its_ancestors() {
        // A create must be judged before the file exists, and the escape lives in the
        // ancestors: `link/` is already outside whether or not the leaf is there.
        let fixture = Fixture::new();
        assert_eq!(
            is_inside_any_resolved(&fixture.path("new-file.txt"), &fixture.roots()),
            Containment::Inside
        );
        assert_eq!(
            is_inside_any_resolved(&fixture.path("link/new-file.txt"), &fixture.roots()),
            Containment::Outside
        );
    }

    #[test]
    fn the_root_itself_is_resolved_before_comparing() {
        // On macOS the temp directory lives under /var, which is a symlink to /private/var.
        // Comparing a resolved path against an unresolved root would call every path an
        // escape - the check would "work" by denying everything.
        let fixture = Fixture::new();
        assert!(
            fixture.workspace.display().to_string()
                != fixture
                    .workspace
                    .canonicalize()
                    .expect("canonical")
                    .display()
                    .to_string()
                || cfg!(not(target_os = "macos")),
            "fixture no longer exercises the unresolved-root case"
        );
        assert_eq!(
            is_inside_any_resolved(&fixture.path("ok.txt"), &fixture.roots()),
            Containment::Inside
        );
    }

    #[test]
    fn a_sibling_sharing_a_prefix_is_not_inside() {
        // Component-wise comparison: `/workspace-other` must not count as inside
        // `/workspace`, which a string prefix test would admit.
        let fixture = Fixture::new();
        let sibling = fixture.root.join("workspace-other");
        std::fs::create_dir_all(&sibling).expect("sibling");
        assert_eq!(
            is_inside_any_resolved(
                &sibling.join("f.txt").display().to_string(),
                &fixture.roots()
            ),
            Containment::Outside
        );
    }

    #[test]
    fn no_roots_is_unresolved_rather_than_permitted() {
        // A missing answer must never read as permission.
        assert_eq!(
            is_inside_any_resolved("/tmp/x", &[]),
            Containment::Unresolved
        );
    }

    #[test]
    fn a_path_under_a_root_that_does_not_exist_is_still_judged_correctly() {
        // Absolute paths always resolve, because the walk bottoms out at `/`. So a root that
        // does not exist yet is still compared structurally rather than abandoned - which
        // matters because the gateway may be asked about a path before anything creates it.
        assert_eq!(
            is_inside_any_resolved(
                "/nonexistent-xyz/workspace/file",
                &["/nonexistent-xyz/workspace".to_string()]
            ),
            Containment::Inside
        );
        assert_eq!(
            is_inside_any_resolved(
                "/nonexistent-xyz/elsewhere/file",
                &["/nonexistent-xyz/workspace".to_string()]
            ),
            Containment::Outside
        );
    }
}
