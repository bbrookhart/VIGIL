//! Deterministic Network Extension flow-policy contract.
//!
//! This crate contains no Apple framework calls. It is the bounded decision core shared by a
//! future `NEFilterDataProvider` adapter and entitlement-free simulation. A native callback gives
//! it owned flow metadata and a kernel-derived process key; evaluation performs no DNS, network,
//! database, UI, model, or policy-compilation work.
//!
//! Hostname permission is never permission for an arbitrary address. Every rule carries the
//! currently approved address set and an exclusive expiry, so a mixed/private answer, rebinding,
//! direct-IP attempt, or stale resolution fails closed for a managed process. Unattributed host
//! traffic remains unaffected.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use vigil_common::{Result, VigilError};
use vigil_endpoint::ProcessKey;

mod signed;
pub use signed::{
    NetworkPolicySigningKey, NetworkPolicyVerifier, SignedNetworkPolicyEnvelope,
    NETWORK_POLICY_ALGORITHM, NETWORK_POLICY_FORMAT,
};

pub const NETWORK_POLICY_SCHEMA: &str = "vigil.network-policy/v1";
const MAX_SESSIONS: usize = 1_024;
const MAX_ATTRIBUTIONS: usize = 16_384;
const MAX_RULES_PER_SESSION: usize = 256;
const MAX_ADDRESSES_PER_RULE: usize = 32;
const MAX_PORTS_PER_RULE: usize = 64;
const MAX_HOSTNAME_BYTES: usize = 253;
const MAX_TOTAL_FLOWS: u64 = 1_000_000;
const MAX_DISTINCT_DESTINATIONS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Off,
    Observe,
    Prompt,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRule {
    pub hostname: String,
    pub protocol: NetworkProtocol,
    pub ports: BTreeSet<u16>,
    pub resolved_addresses: BTreeSet<IpAddr>,
    /// Exclusive wall-clock expiry for the approved resolution.
    pub valid_until_unix_ms: u64,
}

impl DestinationRule {
    fn validate(&self) -> Result<()> {
        let normalized = normalize_hostname(&self.hostname)?;
        if normalized != self.hostname {
            return Err(invalid("hostname", "hostname must already be normalized"));
        }
        if self.ports.is_empty() || self.ports.len() > MAX_PORTS_PER_RULE {
            return Err(invalid("ports", "one to sixty-four ports are required"));
        }
        if self.ports.contains(&0) {
            return Err(invalid("ports", "port zero is not a remote service"));
        }
        if self.resolved_addresses.is_empty()
            || self.resolved_addresses.len() > MAX_ADDRESSES_PER_RULE
        {
            return Err(invalid(
                "resolved_addresses",
                "one to thirty-two approved addresses are required",
            ));
        }
        if self.resolved_addresses.iter().any(|ip| !is_public_ip(*ip)) {
            return Err(invalid(
                "resolved_addresses",
                "approved hostname addresses must all be public unicast",
            ));
        }
        if self.valid_until_unix_ms == 0 {
            return Err(invalid(
                "valid_until_unix_ms",
                "resolution expiry is required",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionNetworkPolicy {
    pub session_id: String,
    pub mode: NetworkMode,
    pub destinations: Vec<DestinationRule>,
    pub max_total_flows: u64,
    pub max_distinct_destinations: usize,
}

impl SessionNetworkPolicy {
    fn validate(&self) -> Result<()> {
        if self.session_id.is_empty() || self.session_id.len() > 128 {
            return Err(invalid(
                "session_id",
                "session identifier is empty or exceeds its bound",
            ));
        }
        if self.destinations.len() > MAX_RULES_PER_SESSION {
            return Err(invalid(
                "destinations",
                "destination rule count exceeds its fast-path bound",
            ));
        }
        if self.max_total_flows == 0 || self.max_total_flows > MAX_TOTAL_FLOWS {
            return Err(invalid(
                "max_total_flows",
                "flow budget must be between one and one million",
            ));
        }
        if self.max_distinct_destinations == 0
            || self.max_distinct_destinations > MAX_DISTINCT_DESTINATIONS
        {
            return Err(invalid(
                "max_distinct_destinations",
                "destination budget is outside its bound",
            ));
        }
        let mut identities = BTreeSet::new();
        for rule in &self.destinations {
            rule.validate()?;
            if !identities.insert((rule.hostname.as_str(), rule.protocol)) {
                return Err(invalid(
                    "destinations",
                    "duplicate hostname/protocol rules are ambiguous",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicySnapshot {
    pub schema_version: String,
    pub target_instance_id: String,
    pub generation: u64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub sessions: BTreeMap<String, SessionNetworkPolicy>,
    /// Complete audit-token-derived process bindings. A list is used on the wire because a
    /// binary audit token cannot be represented as a JSON object key.
    pub attributions: Vec<NetworkAttribution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAttribution {
    pub process: ProcessKey,
    pub session_id: String,
}

impl NetworkPolicySnapshot {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != NETWORK_POLICY_SCHEMA {
            return Err(invalid(
                "schema_version",
                "unsupported network policy schema",
            ));
        }
        validate_identifier("target_instance_id", &self.target_instance_id, 128)?;
        if self.generation == 0 {
            return Err(invalid("generation", "generation zero is reserved"));
        }
        if self.issued_at_unix_ms < 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self
                .expires_at_unix_ms
                .saturating_sub(self.issued_at_unix_ms)
                > 24 * 60 * 60 * 1_000
        {
            return Err(invalid(
                "validity",
                "network policy validity window is invalid",
            ));
        }
        if self.sessions.len() > MAX_SESSIONS || self.attributions.len() > MAX_ATTRIBUTIONS {
            return Err(invalid(
                "snapshot",
                "network policy exceeds fast-path capacity",
            ));
        }
        for (id, policy) in &self.sessions {
            policy.validate()?;
            if id != &policy.session_id {
                return Err(invalid("sessions", "map key and session identity disagree"));
            }
            if policy.destinations.iter().any(|rule| {
                i64::try_from(rule.valid_until_unix_ms)
                    .map_or(true, |expiry| expiry > self.expires_at_unix_ms)
            }) {
                return Err(invalid(
                    "valid_until_unix_ms",
                    "destination resolution outlives its signed policy",
                ));
            }
        }
        let mut processes = BTreeSet::new();
        for attribution in &self.attributions {
            if attribution.process.0.iter().all(|byte| *byte == 0)
                || !self.sessions.contains_key(&attribution.session_id)
                || !processes.insert(attribution.process)
            {
                return Err(invalid(
                    "attributions",
                    "attribution is empty, duplicated, or names an unknown session",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlow {
    pub process: ProcessKey,
    pub direction: FlowDirection,
    pub protocol: NetworkProtocol,
    /// Hostname metadata supplied by the native flow, never synthesized from the remote IP.
    pub hostname: Option<String>,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    /// Wall clock is optional because failure to read it must be representable and testable.
    pub observed_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkVerdict {
    Allow,
    Deny,
    Observe,
    Prompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkReason {
    UnmanagedProcess,
    ModeOff,
    PermitPinnedDestination,
    DenyInboundFlow,
    DenyMissingHostname,
    DenyMalformedHostname,
    DenyDirectIp,
    DenyUnknownDestination,
    DenyProtocol,
    DenyPort,
    DenyPrivateOrLocalAddress,
    DenyResolutionMismatch,
    DenyResolutionExpired,
    DenyPolicyExpired,
    DenyClockUnavailable,
    DenyFlowBudget,
    DenyDestinationBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDecision {
    pub verdict: NetworkVerdict,
    /// Whether a native adapter should permit the flow immediately.
    pub allow: bool,
    pub reason: NetworkReason,
    pub session_id: Option<String>,
    pub policy_generation: Option<u64>,
}

#[derive(Debug, Default)]
struct SessionBudgetState {
    flows: u64,
    destinations: BTreeSet<(String, u16, NetworkProtocol)>,
}

#[derive(Debug, Default)]
pub struct NetworkFastPath {
    snapshot: Option<NetworkPolicySnapshot>,
    attributions: BTreeMap<ProcessKey, String>,
    budgets: BTreeMap<String, SessionBudgetState>,
}

impl NetworkFastPath {
    /// Atomically install a strictly newer validated snapshot.
    pub fn install(&mut self, snapshot: NetworkPolicySnapshot) -> Result<()> {
        snapshot.validate()?;
        if self
            .snapshot
            .as_ref()
            .is_some_and(|current| snapshot.generation <= current.generation)
        {
            return Err(VigilError::InvalidRequest(
                "network policy generation must increase monotonically".to_string(),
            ));
        }
        let attributions = snapshot
            .attributions
            .iter()
            .map(|binding| (binding.process, binding.session_id.clone()))
            .collect();
        // A policy refresh must not replenish authority. Preserve counters for sessions that
        // survive the generation change and discard only sessions no longer in policy.
        self.budgets
            .retain(|session, _| snapshot.sessions.contains_key(session));
        self.attributions = attributions;
        self.snapshot = Some(snapshot);
        Ok(())
    }

    pub fn generation(&self) -> Option<u64> {
        self.snapshot.as_ref().map(|snapshot| snapshot.generation)
    }

    /// Decide a new flow using only installed bounded state.
    pub fn decide(&mut self, flow: &NetworkFlow) -> NetworkDecision {
        let Some(snapshot) = &self.snapshot else {
            return unmanaged();
        };
        let generation = snapshot.generation;
        let Some(session_id) = self.attributions.get(&flow.process) else {
            return unmanaged();
        };
        let Some(policy) = snapshot.sessions.get(session_id) else {
            return managed_decision(
                NetworkMode::Enforce,
                NetworkReason::DenyUnknownDestination,
                session_id,
                generation,
            );
        };
        let Some(observed_at_unix_ms) = flow.observed_at_unix_ms else {
            return managed_decision(
                NetworkMode::Enforce,
                NetworkReason::DenyClockUnavailable,
                session_id,
                generation,
            );
        };
        if i64::try_from(observed_at_unix_ms)
            .map_or(true, |observed| observed >= snapshot.expires_at_unix_ms)
        {
            return managed_decision(
                NetworkMode::Enforce,
                NetworkReason::DenyPolicyExpired,
                session_id,
                generation,
            );
        }
        if policy.mode == NetworkMode::Off {
            return NetworkDecision {
                verdict: NetworkVerdict::Allow,
                allow: true,
                reason: NetworkReason::ModeOff,
                session_id: Some(session_id.clone()),
                policy_generation: Some(generation),
            };
        }

        let candidate = evaluate_destination(policy, flow);
        let reason = match candidate {
            DestinationEvaluation::Deny(reason) => reason,
            DestinationEvaluation::Permit { hostname } => {
                let budget = self.budgets.entry(session_id.clone()).or_default();
                if budget.flows >= policy.max_total_flows {
                    NetworkReason::DenyFlowBudget
                } else {
                    let destination = (hostname, flow.remote_port, flow.protocol);
                    if !budget.destinations.contains(&destination)
                        && budget.destinations.len() >= policy.max_distinct_destinations
                    {
                        NetworkReason::DenyDestinationBudget
                    } else {
                        budget.flows = budget.flows.saturating_add(1);
                        budget.destinations.insert(destination);
                        NetworkReason::PermitPinnedDestination
                    }
                }
            }
        };
        managed_decision(policy.mode, reason, session_id, generation)
    }
}

enum DestinationEvaluation {
    Permit { hostname: String },
    Deny(NetworkReason),
}

fn evaluate_destination(
    policy: &SessionNetworkPolicy,
    flow: &NetworkFlow,
) -> DestinationEvaluation {
    if flow.direction != FlowDirection::Outbound {
        return DestinationEvaluation::Deny(NetworkReason::DenyInboundFlow);
    }
    if !is_public_ip(flow.remote_ip) {
        return DestinationEvaluation::Deny(NetworkReason::DenyPrivateOrLocalAddress);
    }
    let Some(raw_hostname) = flow.hostname.as_deref() else {
        return DestinationEvaluation::Deny(NetworkReason::DenyMissingHostname);
    };
    if raw_hostname.parse::<IpAddr>().is_ok() {
        return DestinationEvaluation::Deny(NetworkReason::DenyDirectIp);
    }
    let hostname = match normalize_hostname(raw_hostname) {
        Ok(hostname) => hostname,
        Err(_) => return DestinationEvaluation::Deny(NetworkReason::DenyMalformedHostname),
    };
    let mut hostname_rules = policy
        .destinations
        .iter()
        .filter(|rule| rule.hostname == hostname);
    let Some(first_rule) = hostname_rules.next() else {
        return DestinationEvaluation::Deny(NetworkReason::DenyUnknownDestination);
    };
    let rule = if first_rule.protocol == flow.protocol {
        first_rule
    } else if let Some(rule) = hostname_rules.find(|rule| rule.protocol == flow.protocol) {
        rule
    } else {
        return DestinationEvaluation::Deny(NetworkReason::DenyProtocol);
    };
    if !rule.ports.contains(&flow.remote_port) {
        return DestinationEvaluation::Deny(NetworkReason::DenyPort);
    }
    let Some(now) = flow.observed_at_unix_ms else {
        return DestinationEvaluation::Deny(NetworkReason::DenyClockUnavailable);
    };
    if now >= rule.valid_until_unix_ms {
        return DestinationEvaluation::Deny(NetworkReason::DenyResolutionExpired);
    }
    if !rule.resolved_addresses.contains(&flow.remote_ip) {
        return DestinationEvaluation::Deny(NetworkReason::DenyResolutionMismatch);
    }
    DestinationEvaluation::Permit { hostname }
}

fn managed_decision(
    mode: NetworkMode,
    reason: NetworkReason,
    session_id: &str,
    generation: u64,
) -> NetworkDecision {
    let permitted = reason == NetworkReason::PermitPinnedDestination;
    let (verdict, allow) = if permitted {
        (NetworkVerdict::Allow, true)
    } else {
        match mode {
            NetworkMode::Off => (NetworkVerdict::Allow, true),
            NetworkMode::Observe => (NetworkVerdict::Observe, true),
            NetworkMode::Prompt => (NetworkVerdict::Prompt, false),
            NetworkMode::Enforce => (NetworkVerdict::Deny, false),
        }
    };
    NetworkDecision {
        verdict,
        allow,
        reason,
        session_id: Some(session_id.to_string()),
        policy_generation: Some(generation),
    }
}

fn unmanaged() -> NetworkDecision {
    NetworkDecision {
        verdict: NetworkVerdict::Allow,
        allow: true,
        reason: NetworkReason::UnmanagedProcess,
        session_id: None,
        policy_generation: None,
    }
}

fn normalize_hostname(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > MAX_HOSTNAME_BYTES || raw.contains(['\0', '/', '@', ':']) {
        return Err(invalid(
            "hostname",
            "hostname is malformed or exceeds its bound",
        ));
    }
    let normalized = raw.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.parse::<IpAddr>().is_ok()
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid("hostname", "hostname is not a valid DNS name"));
    }
    Ok(normalized)
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let octets = ip.octets();
    let segments = ip.segments();
    (octets[0] & 0xe0) == 0x20 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn invalid(field: &'static str, reason: &str) -> VigilError {
    VigilError::InvalidValue {
        field,
        reason: reason.to_string(),
    }
}

fn validate_identifier(field: &'static str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(
            field,
            "identifier is malformed or exceeds its bound",
        ));
    }
    Ok(())
}

pub trait NetworkEventSource {
    fn next_flow(&mut self) -> Result<Option<NetworkFlow>>;
}

#[derive(Debug, Default)]
pub struct SimulatedNetworkSource {
    flows: VecDeque<NetworkFlow>,
    fail_next: bool,
}

impl SimulatedNetworkSource {
    pub fn new(flows: impl IntoIterator<Item = NetworkFlow>) -> Self {
        Self {
            flows: flows.into_iter().collect(),
            fail_next: false,
        }
    }

    pub fn fail_next(&mut self) {
        self.fail_next = true;
    }
}

impl NetworkEventSource for SimulatedNetworkSource {
    fn next_flow(&mut self) -> Result<Option<NetworkFlow>> {
        if self.fail_next {
            self.fail_next = false;
            return Err(VigilError::Unavailable {
                component: "network_event_source",
                reason: "simulated source failure".to_string(),
            });
        }
        Ok(self.flows.pop_front())
    }
}

pub fn replay_source(
    fast_path: &mut NetworkFastPath,
    source: &mut impl NetworkEventSource,
) -> Result<Vec<NetworkDecision>> {
    let mut decisions = Vec::new();
    while let Some(flow) = source.next_flow()? {
        decisions.push(fast_path.decide(&flow));
    }
    Ok(decisions)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;
    const EXPIRY: u64 = 2_000;

    fn key(value: u8) -> ProcessKey {
        ProcessKey::synthetic(value)
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test IP")
    }

    fn policy(mode: NetworkMode, max_flows: u64, max_destinations: usize) -> NetworkPolicySnapshot {
        let session = SessionNetworkPolicy {
            session_id: "ags_test".to_string(),
            mode,
            destinations: vec![DestinationRule {
                hostname: "github.com".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: BTreeSet::from([443]),
                resolved_addresses: BTreeSet::from([ip("140.82.112.4"), ip("2606:50c0:8000::154")]),
                valid_until_unix_ms: EXPIRY,
            }],
            max_total_flows: max_flows,
            max_distinct_destinations: max_destinations,
        };
        NetworkPolicySnapshot {
            schema_version: NETWORK_POLICY_SCHEMA.to_string(),
            target_instance_id: "network-instance-test".to_string(),
            generation: 7,
            issued_at_unix_ms: 500,
            expires_at_unix_ms: 3_000,
            sessions: BTreeMap::from([(session.session_id.clone(), session)]),
            attributions: vec![NetworkAttribution {
                process: key(1),
                session_id: "ags_test".to_string(),
            }],
        }
    }

    fn flow(hostname: Option<&str>, remote_ip: &str, port: u16) -> NetworkFlow {
        NetworkFlow {
            process: key(1),
            direction: FlowDirection::Outbound,
            protocol: NetworkProtocol::Tcp,
            hostname: hostname.map(str::to_string),
            remote_ip: ip(remote_ip),
            remote_port: port,
            observed_at_unix_ms: Some(NOW),
        }
    }

    fn path(snapshot: NetworkPolicySnapshot) -> NetworkFastPath {
        let mut path = NetworkFastPath::default();
        path.install(snapshot).expect("install policy");
        path
    }

    #[test]
    fn exact_host_port_and_pinned_ipv4_are_allowed() {
        let decision = path(policy(NetworkMode::Enforce, 10, 10)).decide(&flow(
            Some("GitHub.COM."),
            "140.82.112.4",
            443,
        ));
        assert_eq!(decision.verdict, NetworkVerdict::Allow);
        assert_eq!(decision.reason, NetworkReason::PermitPinnedDestination);
    }

    #[test]
    fn unknown_host_wrong_protocol_port_and_direction_are_denied() {
        let mut path = path(policy(NetworkMode::Enforce, 10, 10));
        assert_eq!(
            path.decide(&flow(Some("evil.example"), "93.184.216.34", 443))
                .reason,
            NetworkReason::DenyUnknownDestination
        );
        assert_eq!(
            path.decide(&flow(Some("github.com"), "140.82.112.4", 22))
                .reason,
            NetworkReason::DenyPort
        );
        let mut wrong_protocol = flow(Some("github.com"), "140.82.112.4", 443);
        wrong_protocol.protocol = NetworkProtocol::Udp;
        assert_eq!(
            path.decide(&wrong_protocol).reason,
            NetworkReason::DenyProtocol
        );
        let mut inbound = flow(Some("github.com"), "140.82.112.4", 443);
        inbound.direction = FlowDirection::Inbound;
        assert_eq!(path.decide(&inbound).reason, NetworkReason::DenyInboundFlow);
    }

    #[test]
    fn direct_ip_missing_hostname_and_loopback_are_denied() {
        let mut path = path(policy(NetworkMode::Enforce, 10, 10));
        assert_eq!(
            path.decide(&flow(Some("140.82.112.4"), "140.82.112.4", 443))
                .reason,
            NetworkReason::DenyDirectIp
        );
        assert_eq!(
            path.decide(&flow(None, "140.82.112.4", 443)).reason,
            NetworkReason::DenyMissingHostname
        );
        assert_eq!(
            path.decide(&flow(Some("github.com"), "127.0.0.1", 443))
                .reason,
            NetworkReason::DenyPrivateOrLocalAddress
        );
    }

    #[test]
    fn a_resolution_change_cannot_borrow_hostname_authority() {
        let decision = path(policy(NetworkMode::Enforce, 10, 10)).decide(&flow(
            Some("github.com"),
            "93.184.216.34",
            443,
        ));
        assert_eq!(decision.reason, NetworkReason::DenyResolutionMismatch);
        assert!(!decision.allow);
    }

    #[test]
    fn pinned_public_ipv6_is_allowed_but_local_ipv6_is_not() {
        let mut path = path(policy(NetworkMode::Enforce, 10, 10));
        assert!(
            path.decide(&flow(Some("github.com"), "2606:50c0:8000::154", 443))
                .allow
        );
        assert_eq!(
            path.decide(&flow(Some("github.com"), "::1", 443)).reason,
            NetworkReason::DenyPrivateOrLocalAddress
        );
    }

    #[test]
    fn expired_resolution_and_clock_failure_deny() {
        let mut path = path(policy(NetworkMode::Enforce, 10, 10));
        let mut expired = flow(Some("github.com"), "140.82.112.4", 443);
        expired.observed_at_unix_ms = Some(EXPIRY);
        assert_eq!(
            path.decide(&expired).reason,
            NetworkReason::DenyResolutionExpired
        );
        expired.observed_at_unix_ms = None;
        assert_eq!(
            path.decide(&expired).reason,
            NetworkReason::DenyClockUnavailable
        );
    }

    #[test]
    fn expired_policy_denies_even_when_the_last_mode_was_off() {
        let mut path = path(policy(NetworkMode::Off, 10, 10));
        let mut expired = flow(Some("github.com"), "140.82.112.4", 443);
        expired.observed_at_unix_ms = Some(3_000);
        let decision = path.decide(&expired);
        assert_eq!(decision.reason, NetworkReason::DenyPolicyExpired);
        assert_eq!(decision.verdict, NetworkVerdict::Deny);
        assert!(!decision.allow);
    }

    #[test]
    fn total_flow_budget_is_enforced_without_overrun() {
        let mut path = path(policy(NetworkMode::Enforce, 1, 10));
        assert!(
            path.decide(&flow(Some("github.com"), "140.82.112.4", 443))
                .allow
        );
        let exhausted = path.decide(&flow(Some("github.com"), "140.82.112.4", 443));
        assert_eq!(exhausted.reason, NetworkReason::DenyFlowBudget);
        assert!(!exhausted.allow);
    }

    #[test]
    fn a_policy_refresh_does_not_replenish_flow_budget() {
        let mut path = path(policy(NetworkMode::Enforce, 1, 10));
        let allowed = flow(Some("github.com"), "140.82.112.4", 443);
        assert!(path.decide(&allowed).allow);

        let mut refreshed = policy(NetworkMode::Enforce, 1, 10);
        refreshed.generation = 8;
        path.install(refreshed).expect("install newer generation");
        assert_eq!(
            path.decide(&allowed).reason,
            NetworkReason::DenyFlowBudget,
            "a policy refresh replenished spent network authority"
        );
    }

    #[test]
    fn distinct_destination_budget_is_enforced() {
        let mut snapshot = policy(NetworkMode::Enforce, 10, 1);
        snapshot
            .sessions
            .get_mut("ags_test")
            .expect("session")
            .destinations
            .push(DestinationRule {
                hostname: "example.com".to_string(),
                protocol: NetworkProtocol::Tcp,
                ports: BTreeSet::from([443]),
                resolved_addresses: BTreeSet::from([ip("93.184.216.34")]),
                valid_until_unix_ms: EXPIRY,
            });
        let mut path = path(snapshot);
        assert!(
            path.decide(&flow(Some("github.com"), "140.82.112.4", 443))
                .allow
        );
        assert_eq!(
            path.decide(&flow(Some("example.com"), "93.184.216.34", 443))
                .reason,
            NetworkReason::DenyDestinationBudget
        );
    }

    #[test]
    fn observe_prompt_and_off_have_distinct_failure_postures() {
        let denied = flow(Some("evil.example"), "93.184.216.34", 443);
        let observe = path(policy(NetworkMode::Observe, 10, 10)).decide(&denied);
        assert_eq!(observe.verdict, NetworkVerdict::Observe);
        assert!(observe.allow);
        let prompt = path(policy(NetworkMode::Prompt, 10, 10)).decide(&denied);
        assert_eq!(prompt.verdict, NetworkVerdict::Prompt);
        assert!(!prompt.allow);
        let off = path(policy(NetworkMode::Off, 10, 10)).decide(&denied);
        assert_eq!(off.reason, NetworkReason::ModeOff);
        assert!(off.allow);
    }

    #[test]
    fn unattributed_host_traffic_is_unaffected() {
        let mut flow = flow(Some("evil.example"), "127.0.0.1", 443);
        flow.process = key(9);
        let decision = path(policy(NetworkMode::Enforce, 10, 10)).decide(&flow);
        assert_eq!(decision.reason, NetworkReason::UnmanagedProcess);
        assert!(decision.allow);
    }

    #[test]
    fn invalid_or_rollback_snapshots_never_partially_install() {
        let mut path = path(policy(NetworkMode::Enforce, 10, 10));
        let mut invalid = policy(NetworkMode::Enforce, 10, 10);
        invalid.generation = 8;
        invalid
            .sessions
            .get_mut("ags_test")
            .expect("session")
            .destinations[0]
            .resolved_addresses = BTreeSet::from([ip("127.0.0.1")]);
        assert!(path.install(invalid).is_err());
        assert_eq!(path.generation(), Some(7));
        assert!(path.install(policy(NetworkMode::Enforce, 10, 10)).is_err());
        assert_eq!(path.generation(), Some(7));
    }

    #[test]
    fn simulator_replays_flows_and_propagates_source_failure() {
        let mut path = path(policy(NetworkMode::Enforce, 10, 10));
        let mut source = SimulatedNetworkSource::new([
            flow(Some("github.com"), "140.82.112.4", 443),
            flow(Some("evil.example"), "93.184.216.34", 443),
        ]);
        let decisions = replay_source(&mut path, &mut source).expect("replay");
        assert_eq!(decisions.len(), 2);
        assert!(decisions[0].allow);
        assert!(!decisions[1].allow);

        let mut failing = SimulatedNetworkSource::default();
        failing.fail_next();
        assert!(replay_source(&mut path, &mut failing).is_err());
    }

    #[test]
    fn malformed_and_ambiguous_rules_are_rejected() {
        let mut snapshot = policy(NetworkMode::Enforce, 10, 10);
        let duplicate = snapshot.sessions["ags_test"].destinations[0].clone();
        snapshot
            .sessions
            .get_mut("ags_test")
            .expect("session")
            .destinations
            .push(duplicate);
        assert!(snapshot.validate().is_err());

        let encoded = serde_json::to_string(&policy(NetworkMode::Enforce, 10, 10))
            .expect("serialize snapshot");
        let with_unknown = encoded.replacen('{', r#"{"unknown":true,"#, 1);
        assert!(serde_json::from_str::<NetworkPolicySnapshot>(&with_unknown).is_err());
    }
}
