//! Fuzz the Git remote host extractor.
//!
//! A remote URL comes from `.git/config`, which an agent that can write workspace files can
//! write. The extracted host is then checked against the profile's network allowlist, so
//! mistaking one part of a URL for the host is directly a policy bypass: if
//! `https://github.com@attacker.example/x` yielded `github.com`, an allowlisted destination
//! would authorize a push to an attacker.
//!
//! The properties asserted are about what a returned host may be, not about parsing every
//! exotic URL — returning `None` is always a safe answer, because the push is then refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_local::remote_host;

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else {
        return;
    };
    let Some(host) = remote_host(url) else {
        // Refusing to identify a host refuses the push. Always safe.
        return;
    };

    assert!(!host.is_empty(), "an empty host was returned");
    assert_eq!(host, host.to_ascii_lowercase(), "host was not normalized");

    // A host is a single authority component. Anything that still carries a delimiter means
    // some other part of the URL leaked into it, which is the bypass this exists to prevent.
    for delimiter in ['@', '/', '?', '#', ':', '\\'] {
        assert!(
            !host.contains(delimiter),
            "returned host `{host}` still contains `{delimiter}`, so part of the URL leaked \
             into the value checked against the allowlist (input: {url:?})"
        );
    }

    // Anything returned must be shaped like a hostname: non-empty labels, no leading or
    // trailing hyphen, ASCII alphanumeric and hyphen only. This is the property the allowlist
    // comparison depends on.
    for label in host.split('.') {
        assert!(!label.is_empty(), "empty label in host `{host}` (input: {url:?})");
        assert!(label.len() <= 63, "over-long label in host `{host}`");
        assert!(
            !label.starts_with('-') && !label.ends_with('-'),
            "label with a leading or trailing hyphen in host `{host}`"
        );
        assert!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "non-hostname character in host `{host}` (input: {url:?})"
        );
    }

    // Userinfo confusion — `https://github.com@attacker.example/x` must yield the attacker's
    // host, not GitHub's — is checked by name in `remote_hosts_are_extracted_from_every_form
    // _git_accepts`, where the expected answer can be stated exactly. An approximation of that
    // rule here produced false positives: in scp form, an `@` after the first colon belongs to
    // the path, not to userinfo, so `7:x@::` correctly yields `7`.
});
