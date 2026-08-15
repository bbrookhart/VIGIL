//! SSRF and egress destination analysis.
//!
//! # Why
//!
//! An agent that can fetch a URL chosen from content it read is an SSRF primitive pointed at
//! your internal network. The cloud metadata endpoint is the highest-value target: a single
//! `GET http://169.254.169.254/...` returns workload credentials that bypass every other
//! control VIGIL has.
//!
//! # What
//!
//! Classification of a destination by scheme, hostname shape and resolved address, plus
//! redirect-chain checking. Both the name and the resolved address matter: an allowlist on
//! names alone is defeated by DNS rebinding, and a check on addresses alone cannot express
//! "only this vendor".
//!
//! # Assumptions
//!
//! This crate classifies; it does not resolve DNS. The adapter supplies
//! `resolved_addresses`, and the gateway re-resolves and pins the connection at execution
//! time. Classification without that pinning is advisory only, because the address can change
//! between the check and the connect — the TOCTOU that makes rebinding work.

use std::net::{IpAddr, Ipv4Addr};
use url::Url;
use vigil_protocol::reason::ReasonCode;

/// What kind of destination this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationClass {
    /// A routable public address.
    Public,
    /// Loopback: reaches services that often trust anything local.
    Loopback,
    /// RFC 1918 / unique-local: the internal network.
    PrivateNetwork,
    /// Link-local, including the address cloud metadata lives on.
    LinkLocal,
    /// A known cloud instance metadata endpoint.
    CloudMetadata,
    /// Unspecified (0.0.0.0, ::), which many stacks route to localhost.
    Unspecified,
    /// A hostname that has not been resolved, so its class is unknown.
    Unresolved,
}

impl DestinationClass {
    /// Whether reaching this destination is an SSRF finding.
    pub fn is_ssrf(&self) -> bool {
        matches!(
            self,
            Self::Loopback
                | Self::PrivateNetwork
                | Self::LinkLocal
                | Self::CloudMetadata
                | Self::Unspecified
        )
    }

    pub fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::CloudMetadata => Some(ReasonCode::SsrfMetadataEndpoint),
            Self::Loopback | Self::PrivateNetwork | Self::LinkLocal | Self::Unspecified => {
                Some(ReasonCode::SsrfPrivateAddress)
            }
            _ => None,
        }
    }

    pub fn risk(&self) -> f64 {
        match self {
            Self::CloudMetadata => 1.0,
            Self::Loopback | Self::LinkLocal | Self::Unspecified => 0.85,
            Self::PrivateNetwork => 0.75,
            Self::Unresolved => 0.2,
            Self::Public => 0.0,
        }
    }
}

/// Hostnames that serve cloud instance credentials.
const METADATA_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "100.100.100.200", // Alibaba
    "169.254.169.253", // AWS (alternate)
    "fd00:ec2::254",   // AWS IMDSv2 over IPv6
];

/// Schemes an agent-initiated request may use.
///
/// Everything else — `file:`, `gopher:`, `dict:`, `ftp:`, `jar:` — is denied. Those schemes
/// are the classic SSRF escalation path from "fetch a URL" to "read local files" or "speak a
/// different protocol to an internal service".
const ALLOWED_SCHEMES: &[&str] = &["https", "http"];

/// What network analysis concluded.
#[derive(Debug, Clone, Default)]
pub struct NetworkFindings {
    pub reason_codes: Vec<ReasonCode>,
    pub risk: f64,
    /// Human-readable, already-redacted description of each issue.
    pub issues: Vec<String>,
    /// The classified destination, when a URL was parsed.
    pub destination_class: Option<DestinationClass>,
    /// The host, lowercased, for policy matching.
    pub host: Option<String>,
}

impl NetworkFindings {
    pub fn is_clean(&self) -> bool {
        self.reason_codes.is_empty()
    }
}

/// Classify one host or address string.
pub fn classify_host(host: &str) -> DestinationClass {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let bare = host.trim_start_matches('[').trim_end_matches(']');

    if METADATA_HOSTS.contains(&bare) {
        return DestinationClass::CloudMetadata;
    }
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    // Hostnames that conventionally resolve inward. Checked by name because the adapter may
    // not have resolved them, and because "localhost" is special-cased in many resolvers.
    if bare == "localhost"
        || bare.ends_with(".localhost")
        || bare.ends_with(".local")
        || bare.ends_with(".internal")
        || bare.ends_with(".localdomain")
    {
        return DestinationClass::Loopback;
    }
    DestinationClass::Unresolved
}

/// Classify a resolved IP address.
pub fn classify_ip(ip: IpAddr) -> DestinationClass {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped IPv6 address (::ffff:127.0.0.1) reaches the IPv4 destination,
            // so it must be classified as that destination and not as "some IPv6 address".
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return classify_ipv4(mapped);
            }
            if v6.is_loopback() {
                return DestinationClass::Loopback;
            }
            if v6.is_unspecified() {
                return DestinationClass::Unspecified;
            }
            let seg = v6.segments();
            // fe80::/10 link-local
            if seg[0] & 0xffc0 == 0xfe80 {
                return DestinationClass::LinkLocal;
            }
            // fc00::/7 unique local
            if seg[0] & 0xfe00 == 0xfc00 {
                return DestinationClass::PrivateNetwork;
            }
            DestinationClass::Public
        }
    }
}

/// Literal addresses that serve instance credentials, checked before the generic ranges.
///
/// `169.254.169.254` is inside the link-local range, so a classifier that checks ranges
/// first reports it as merely link-local and loses the fact that this specific address hands
/// out cloud credentials. That distinction drives a different policy rule and a different
/// alert severity, so it has to survive.
const METADATA_ADDRESSES: &[&str] = &["169.254.169.254", "169.254.169.253", "100.100.100.200"];

fn classify_ipv4(ip: Ipv4Addr) -> DestinationClass {
    if METADATA_ADDRESSES.contains(&ip.to_string().as_str()) {
        return DestinationClass::CloudMetadata;
    }
    if ip.is_unspecified() {
        return DestinationClass::Unspecified;
    }
    if ip.is_loopback() {
        return DestinationClass::Loopback;
    }
    if ip.is_link_local() {
        return DestinationClass::LinkLocal;
    }
    if ip.is_private() || ip.is_broadcast() || ip.is_documentation() {
        return DestinationClass::PrivateNetwork;
    }
    // 100.64.0.0/10 carrier-grade NAT, used for internal service meshes.
    let o = ip.octets();
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return DestinationClass::PrivateNetwork;
    }
    // 0.0.0.0/8
    if o[0] == 0 {
        return DestinationClass::Unspecified;
    }
    DestinationClass::Public
}

/// Analyze a URL, its resolved addresses and its redirect chain.
pub fn analyze(
    raw_url: &str,
    resolved_addresses: &[String],
    redirect_chain: &[String],
) -> NetworkFindings {
    let mut findings = NetworkFindings::default();

    let Ok(url) = Url::parse(raw_url) else {
        findings.reason_codes.push(ReasonCode::SchemaInvalid);
        findings.risk = 0.5;
        findings
            .issues
            .push("destination URL is unparsable".to_string());
        return findings;
    };

    if !ALLOWED_SCHEMES.contains(&url.scheme()) {
        findings
            .reason_codes
            .push(ReasonCode::ProtocolSchemeForbidden);
        findings.risk = findings.risk.max(0.9);
        findings.issues.push(format!(
            "scheme `{}` is not permitted for agent-initiated requests",
            vigil_common::redact::single_line_excerpt(url.scheme(), 16)
        ));
    }

    // Credentials in the URL are both a leak and a hostname-spoofing trick: a reader sees
    // `https://trusted.example@evil.example/` and reads the wrong host.
    if !url.username().is_empty() || url.password().is_some() {
        findings.risk = findings.risk.max(0.6);
        findings
            .issues
            .push("URL carries embedded credentials".to_string());
    }

    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    findings.host = if host.is_empty() {
        None
    } else {
        Some(host.clone())
    };

    let name_class = classify_host(&host);
    let resolved: Vec<DestinationClass> = resolved_addresses
        .iter()
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .map(classify_ip)
        .collect();

    // The resolved address is authoritative — that is the rebinding check — but only where
    // it actually tells us something. A name we could not classify stops being "unknown"
    // once we know what it resolves to, so `Unresolved` is dropped rather than allowed to
    // outrank a perfectly ordinary public address.
    let mut worst = if resolved.is_empty() {
        name_class
    } else if name_class == DestinationClass::Unresolved {
        DestinationClass::Public
    } else {
        name_class
    };
    for candidate in resolved {
        if candidate.risk() > worst.risk() {
            worst = candidate;
        }
    }
    findings.destination_class = Some(worst);
    if let Some(code) = worst.reason_code() {
        findings.reason_codes.push(code);
        findings.risk = findings.risk.max(worst.risk());
        findings.issues.push(format!(
            "destination resolves to a {} address",
            match worst {
                DestinationClass::CloudMetadata => "cloud instance metadata",
                DestinationClass::Loopback => "loopback",
                DestinationClass::PrivateNetwork => "private network",
                DestinationClass::LinkLocal => "link-local",
                DestinationClass::Unspecified => "unspecified",
                _ => "non-public",
            }
        ));
    }

    // Every hop of a redirect chain is a destination in its own right. A redirect from an
    // allowlisted host to the metadata endpoint is the standard allowlist bypass.
    for hop in redirect_chain {
        let hop_findings = analyze_hop(hop);
        if let Some(class) = hop_findings {
            if class.is_ssrf() {
                findings
                    .reason_codes
                    .push(ReasonCode::RedirectOutsidePolicy);
                if let Some(code) = class.reason_code() {
                    findings.reason_codes.push(code);
                }
                findings.risk = findings.risk.max(class.risk());
                findings.issues.push(format!(
                    "redirect hop reaches a non-public destination ({})",
                    vigil_common::redact::redact_url(hop)
                ));
            }
        }
    }

    findings.reason_codes.sort();
    findings.reason_codes.dedup();
    findings.risk = findings.risk.clamp(0.0, 1.0);
    findings
}

fn analyze_hop(hop: &str) -> Option<DestinationClass> {
    let url = Url::parse(hop).ok()?;
    Some(classify_host(url.host_str()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_metadata_endpoints_are_recognized() {
        for host in METADATA_HOSTS {
            assert_eq!(
                classify_host(host),
                DestinationClass::CloudMetadata,
                "{host}"
            );
        }
        let f = analyze("http://169.254.169.254/latest/meta-data/iam/", &[], &[]);
        assert!(f.reason_codes.contains(&ReasonCode::SsrfMetadataEndpoint));
        assert_eq!(f.risk, 1.0);
    }

    #[test]
    fn loopback_and_private_addresses_are_recognized() {
        assert_eq!(classify_host("127.0.0.1"), DestinationClass::Loopback);
        assert_eq!(classify_host("localhost"), DestinationClass::Loopback);
        assert_eq!(classify_host("[::1]"), DestinationClass::Loopback);
        assert_eq!(classify_host("10.1.2.3"), DestinationClass::PrivateNetwork);
        assert_eq!(
            classify_host("192.168.1.1"),
            DestinationClass::PrivateNetwork
        );
        assert_eq!(
            classify_host("172.16.0.1"),
            DestinationClass::PrivateNetwork
        );
        assert_eq!(
            classify_host("100.64.0.1"),
            DestinationClass::PrivateNetwork
        );
        assert_eq!(classify_host("0.0.0.0"), DestinationClass::Unspecified);
        assert_eq!(classify_host("169.254.1.1"), DestinationClass::LinkLocal);
    }

    #[test]
    fn ipv4_mapped_ipv6_does_not_launder_a_loopback_address() {
        // `::ffff:127.0.0.1` connects to 127.0.0.1. A classifier that treats it as "some
        // IPv6 address" waves through a loopback SSRF.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(classify_ip(mapped), DestinationClass::Loopback);
        // And the mapped form of the metadata address keeps its specific classification,
        // rather than degrading to generic link-local.
        let mapped_meta: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert_eq!(classify_ip(mapped_meta), DestinationClass::CloudMetadata);
        let mapped_linklocal: IpAddr = "::ffff:169.254.1.1".parse().unwrap();
        assert_eq!(classify_ip(mapped_linklocal), DestinationClass::LinkLocal);
    }

    #[test]
    fn a_public_destination_is_clean() {
        let f = analyze(
            "https://mail-provider.example/v1/send",
            &["93.184.216.34".into()],
            &[],
        );
        assert!(f.is_clean(), "{f:?}");
        assert_eq!(f.destination_class, Some(DestinationClass::Public));
        assert_eq!(f.host.as_deref(), Some("mail-provider.example"));
    }

    #[test]
    fn dns_rebinding_is_caught_by_the_resolved_address() {
        // The name looks fine; it resolves inward.
        let f = analyze(
            "https://totally-legit.example/data",
            &["169.254.169.254".into()],
            &[],
        );
        assert!(f.reason_codes.contains(&ReasonCode::SsrfMetadataEndpoint));
    }

    #[test]
    fn a_redirect_into_the_metadata_endpoint_is_caught() {
        let f = analyze(
            "https://allowed.example/start",
            &["93.184.216.34".into()],
            &["http://169.254.169.254/latest/meta-data/".into()],
        );
        assert!(f.reason_codes.contains(&ReasonCode::RedirectOutsidePolicy));
        assert!(f.reason_codes.contains(&ReasonCode::SsrfMetadataEndpoint));
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        for url in [
            "file:///etc/passwd",
            "gopher://internal:70/_GET",
            "dict://internal:2628/",
            "ftp://internal/x",
            "jar:http://x!/y",
        ] {
            let f = analyze(url, &[], &[]);
            assert!(
                f.reason_codes
                    .contains(&ReasonCode::ProtocolSchemeForbidden),
                "{url} was not rejected: {f:?}"
            );
        }
    }

    #[test]
    fn userinfo_spoofing_reports_the_real_host_not_the_decoy() {
        let f = analyze("https://mail-provider.example@evil.example/x", &[], &[]);
        assert_eq!(f.host.as_deref(), Some("evil.example"));
        assert!(f.issues.iter().any(|i| i.contains("embedded credentials")));
    }

    #[test]
    fn an_unparsable_url_is_a_finding_not_a_pass() {
        let f = analyze("not a url at all", &[], &[]);
        assert!(!f.is_clean());
    }

    #[test]
    fn issues_never_echo_credentials_from_the_url() {
        let f = analyze("https://user:hunter2@evil.example/x?token=abc123", &[], &[]);
        let rendered = format!("{f:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("abc123"));
    }
}
