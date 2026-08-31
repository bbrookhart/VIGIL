//! Fuzz URL/SSRF analysis.
//!
//! URLs reach this straight from agent-chosen tool arguments, so the input is fully
//! attacker-controlled. Beyond crash-freedom, the property that matters is that
//! classification never *downgrades*: a destination resolving to a metadata or private
//! address must never come back as `Public`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil_detect::network::{self, DestinationClass};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Split the input into a URL and some resolved addresses, so the rebinding path is
    // exercised too rather than only the parser.
    let mut parts = text.splitn(3, '\n');
    let url = parts.next().unwrap_or_default();
    let addresses: Vec<String> = parts
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let redirects: Vec<String> = parts
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let findings = network::analyze(url, &addresses, &redirects);

    // A resolved address that is not public must never yield a Public classification: that
    // is the DNS-rebinding check, and inverting it would wave through an SSRF.
    for address in &addresses {
        if let Ok(ip) = address.parse::<std::net::IpAddr>() {
            let class = network::classify_ip(ip);
            if class.is_ssrf() {
                assert_ne!(
                    findings.destination_class,
                    Some(DestinationClass::Public),
                    "a destination resolving to {ip} was classified Public"
                );
            }
        }
    }

    // Findings are rendered into logs and events, so they must never carry raw newlines.
    for issue in &findings.issues {
        assert!(!issue.contains('\n'), "an issue string could forge a log line");
    }
});
