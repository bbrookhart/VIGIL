//! Pattern matching for resource and host rules.
//!
//! # Why
//!
//! Policy authors write `mail-provider.example` and `arn:aws:s3:::reports-*`. A regex engine
//! would be more expressive and considerably more dangerous: catastrophic backtracking in a
//! rule turns the enforcement path into a denial-of-service target, and a policy author's
//! typo becomes an availability incident. This matcher is linear-time by construction.
//!
//! # What
//!
//! `*` matches any run of characters within the value, `?` matches exactly one. There is no
//! alternation, no repetition operator and no backtracking blowup: the algorithm is the
//! standard two-pointer wildcard match, O(n·m) worst case with O(1) memory.
//!
//! # Assumptions
//!
//! Matching is case-sensitive except where the caller lowercases first. Hostname rules go
//! through [`host_matches`], which lowercases and rejects the subtle cases (a bare `*` never
//! matches, and a leading `*.` does not match the apex) that make host allowlists leak.

/// Match `value` against a `*`/`?` pattern.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();

    let (mut pi, mut vi) = (0usize, 0usize);
    // Position to resume from if the current `*` expansion turns out to be too short.
    let (mut star, mut resume) = (None::<usize>, 0usize);

    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = vi;
            pi += 1;
        } else if let Some(s) = star {
            // Backtrack: let the last `*` swallow one more character. Each character is
            // consumed at most once per star, so this stays linear rather than exponential.
            pi = s + 1;
            resume += 1;
            vi = resume;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match a hostname against an allowlist pattern.
///
/// Rules beyond plain globbing, each of which exists because its absence is a known
/// allowlist bypass:
///
/// * comparison is case-insensitive and a single trailing dot is stripped, because
///   `EVIL.example` and `evil.example.` resolve to the same host
/// * a bare `*` is rejected: an allowlist entry that matches everything is almost always a
///   mistake, and policy validation surfaces it instead of silently permitting all egress
/// * `*.example.com` matches subdomains but **not** `example.com` itself, matching how
///   operators read it — a wildcard entry should not silently grant the apex
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return false;
    }
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Subdomains only, and only real ones: `evilexample.com` must not match `*.example.com`.
        return host.ends_with(&format!(".{suffix}"));
    }
    glob_match(&pattern, &host)
}

/// Whether any pattern in the list matches the host.
pub fn any_host_matches(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| host_matches(p, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_wildcard_matching() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abd"));
        assert!(glob_match("a*c", "abbbbc"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match(
            "arn:aws:s3:::reports-*",
            "arn:aws:s3:::reports-2026"
        ));
        assert!(!glob_match(
            "arn:aws:s3:::reports-*",
            "arn:aws:s3:::secrets-2026"
        ));
    }

    #[test]
    fn empty_patterns_and_values() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn pathological_patterns_terminate_quickly() {
        // The input that makes a naive backtracking regex hang. Must return, fast.
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let value = "a".repeat(2000);
        let start = std::time::Instant::now();
        assert!(!glob_match(pattern, &value));
        assert!(
            start.elapsed().as_millis() < 500,
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        assert!(host_matches("mail.example", "MAIL.EXAMPLE"));
        assert!(host_matches("mail.example", "mail.example."));
    }

    #[test]
    fn a_bare_star_never_matches_a_host() {
        // An operator who writes `*` in an egress allowlist gets a validation error, not
        // unrestricted egress.
        assert!(!host_matches("*", "anything.example"));
        assert!(!any_host_matches(&["*".to_string()], "evil.example"));
    }

    #[test]
    fn wildcard_subdomains_do_not_match_the_apex_or_lookalikes() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        // The classic bypass: a suffix match without the dot boundary.
        assert!(!host_matches("*.example.com", "evilexample.com"));
        assert!(!host_matches("*.example.com", "example.com.evil.net"));
    }

    #[test]
    fn a_hostname_allowlist_is_not_fooled_by_a_prefix_or_suffix() {
        let allow = vec!["mail-provider.example".to_string()];
        assert!(any_host_matches(&allow, "mail-provider.example"));
        assert!(!any_host_matches(&allow, "mail-provider.example.evil.net"));
        assert!(!any_host_matches(&allow, "evil-mail-provider.example"));
    }
}
