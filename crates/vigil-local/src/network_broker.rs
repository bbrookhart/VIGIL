//! Destination-integrity network probe broker and simulator.
//!
//! This entitlement-independent slice resolves and opens a TCP connection, sends no payload, and
//! closes it immediately. Enforced profiles use exact hostname/port allowlists and reject direct
//! IPs plus private, local, metadata, documentation, multicast, and otherwise non-public resolved
//! addresses. It is semantic mediation, not a Network Extension or host firewall.

use crate::{
    DecisionOutcome, LocalAction, LocalDecision, LocalProfile, LocalSession, LocalStore, RiskState,
    SessionStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use vigil_common::{Result, VigilError};

const MAX_RESOLVED_ADDRESSES: usize = 32;
const MAX_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProbeRequest {
    pub host: String,
    pub port: u16,
    pub timeout_ms: u64,
}

impl NetworkProbeRequest {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            timeout_ms: 3_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProbeResult {
    pub event_id: String,
    pub reservation_id: String,
    pub correlation_id: String,
    pub destination: String,
    pub resolved_addresses: Vec<SocketAddr>,
    pub connected_address: SocketAddr,
}

pub trait NetworkEventSource: Send + Sync {
    fn resolve(&self, host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>>;
    fn connect(&self, addresses: &[SocketAddr], timeout: Duration) -> Result<SocketAddr>;
}

#[derive(Debug, Default)]
pub struct SystemNetworkSource;

impl NetworkEventSource for SystemNetworkSource {
    fn resolve(&self, host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
        let host = host.to_string();
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>());
            let _ = sender.send(result);
        });
        match receiver.recv_timeout(timeout) {
            Ok(Ok(addresses)) => Ok(addresses),
            Ok(Err(_)) => Err(VigilError::Unavailable {
                component: "dns_resolver",
                reason: "destination resolution failed".to_string(),
            }),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(VigilError::Timeout {
                component: "dns_resolver",
                elapsed_ms: duration_ms(timeout),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(VigilError::Unavailable {
                component: "dns_resolver",
                reason: "resolver worker stopped without a result".to_string(),
            }),
        }
    }

    fn connect(&self, addresses: &[SocketAddr], timeout: Duration) -> Result<SocketAddr> {
        let started = Instant::now();
        for address in addresses {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            if let Ok(stream) = TcpStream::connect_timeout(address, remaining) {
                let peer = stream.peer_addr().unwrap_or(*address);
                drop(stream);
                return Ok(peer);
            }
        }
        if started.elapsed() >= timeout {
            Err(VigilError::Timeout {
                component: "network_connect",
                elapsed_ms: duration_ms(timeout),
            })
        } else {
            Err(VigilError::Unavailable {
                component: "network_connect",
                reason: "no resolved destination accepted the connection".to_string(),
            })
        }
    }
}

#[derive(Debug, Default)]
struct SimulatedState {
    resolutions: BTreeMap<String, Vec<SocketAddr>>,
    resolution_attempts: usize,
    connection_attempts: usize,
    fail_connect: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SimulatedNetworkSource {
    state: Arc<Mutex<SimulatedState>>,
}

impl SimulatedNetworkSource {
    pub fn set_resolution(&self, host: &str, port: u16, addresses: Vec<SocketAddr>) -> Result<()> {
        self.lock()?
            .resolutions
            .insert(destination_key(&normalize_host(host)?, port), addresses);
        Ok(())
    }

    pub fn set_connect_failure(&self, fail: bool) -> Result<()> {
        self.lock()?.fail_connect = fail;
        Ok(())
    }

    pub fn attempts(&self) -> Result<(usize, usize)> {
        let state = self.lock()?;
        Ok((state.resolution_attempts, state.connection_attempts))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SimulatedState>> {
        self.state.lock().map_err(|_| VigilError::Unavailable {
            component: "simulated_network",
            reason: "simulator state is unavailable".to_string(),
        })
    }
}

impl NetworkEventSource for SimulatedNetworkSource {
    fn resolve(&self, host: &str, port: u16, _timeout: Duration) -> Result<Vec<SocketAddr>> {
        let mut state = self.lock()?;
        state.resolution_attempts += 1;
        state
            .resolutions
            .get(&destination_key(host, port))
            .cloned()
            .ok_or_else(|| VigilError::Unavailable {
                component: "simulated_network",
                reason: "no simulated resolution exists".to_string(),
            })
    }

    fn connect(&self, addresses: &[SocketAddr], _timeout: Duration) -> Result<SocketAddr> {
        let mut state = self.lock()?;
        state.connection_attempts += 1;
        if state.fail_connect {
            return Err(VigilError::Unavailable {
                component: "simulated_network",
                reason: "simulated connection failure".to_string(),
            });
        }
        addresses
            .first()
            .copied()
            .ok_or_else(|| VigilError::Unavailable {
                component: "simulated_network",
                reason: "no simulated address was supplied".to_string(),
            })
    }
}

pub struct NetworkBroker<'a> {
    store: &'a LocalStore,
    source: &'a dyn NetworkEventSource,
}

impl<'a> NetworkBroker<'a> {
    pub fn new(store: &'a LocalStore, source: &'a dyn NetworkEventSource) -> Self {
        Self { store, source }
    }

    pub fn probe(
        &self,
        session_id: &str,
        request: &NetworkProbeRequest,
    ) -> Result<NetworkProbeResult> {
        let correlation_id = format!("cor_{}", uuid::Uuid::new_v4().simple());
        let (_session, profile) = self.session_context(session_id)?;
        let destination = match ValidatedDestination::new(&request.host, request.port) {
            Ok(destination) if request.timeout_ms > 0 && request.timeout_ms <= MAX_TIMEOUT_MS => {
                destination
            }
            Ok(_) => {
                let error = VigilError::InvalidValue {
                    field: "timeout_ms",
                    reason: format!("timeout must be between 1 and {MAX_TIMEOUT_MS} milliseconds"),
                };
                self.record_invalid(session_id, &correlation_id, &error)?;
                return Err(error);
            }
            Err(error) => {
                self.record_invalid(session_id, &correlation_id, &error)?;
                return Err(error);
            }
        };
        let preflight = evaluate_network_preflight(profile, &destination);
        self.require_permit(session_id, &correlation_id, &destination.key, preflight)?;

        let timeout = Duration::from_millis(request.timeout_ms);
        let mut resolved = match self
            .source
            .resolve(&destination.host, destination.port, timeout)
        {
            Ok(addresses) => addresses,
            Err(error) => {
                self.record_failure(session_id, &correlation_id, "network.resolve", None, &error)?;
                return Err(error);
            }
        };
        resolved.sort_unstable();
        resolved.dedup();
        if resolved.is_empty()
            || resolved.len() > MAX_RESOLVED_ADDRESSES
            || resolved
                .iter()
                .any(|address| address.port() != destination.port)
        {
            let error = VigilError::InvalidValue {
                field: "resolved_addresses",
                reason: "resolution returned no addresses, exceeded its bound, or changed the port"
                    .to_string(),
            };
            self.record_failure(session_id, &correlation_id, "network.resolve", None, &error)?;
            return Err(error);
        }
        let resolution_decision = evaluate_network_resolution(profile, &destination, &resolved);
        let determining_policy = resolution_decision.determining_policy.clone();
        self.require_permit(
            session_id,
            &correlation_id,
            &destination.key,
            resolution_decision,
        )?;

        let reservation =
            match self
                .store
                .reserve_network_budget(session_id, &correlation_id, &destination.key)
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    self.store.append_event(
                        session_id,
                        "budget",
                        LocalAction::NetworkConnect.as_str(),
                        Some("DENY"),
                        &correlation_id,
                        &json!({"error_class": error.class()}),
                    )?;
                    return Err(error);
                }
            };
        let connected = match self.source.connect(&resolved, timeout) {
            Ok(address) => address,
            Err(error) => {
                self.store.refund_budget(&reservation.id)?;
                self.record_failure(
                    session_id,
                    &correlation_id,
                    "network.connect",
                    Some(&reservation.id),
                    &error,
                )?;
                return Err(error);
            }
        };
        if !resolved.contains(&connected) {
            self.store.refund_budget(&reservation.id)?;
            let error = VigilError::AuditIntegrity(
                "network source connected to an address outside the validated resolution"
                    .to_string(),
            );
            self.record_failure(
                session_id,
                &correlation_id,
                "network.connect",
                Some(&reservation.id),
                &error,
            )?;
            return Err(error);
        }
        if let Err(error) = self.store.commit_budget(&reservation.id) {
            let _ = self.store.append_event(
                session_id,
                "budget",
                "budget.reconciliation_failed",
                Some("ERROR"),
                &correlation_id,
                &json!({
                    "reservation_id": reservation.id,
                    "operation_executed": true,
                    "error_class": error.class(),
                }),
            );
            return Err(error);
        }
        let event = self.store.append_event(
            session_id,
            "network",
            LocalAction::NetworkConnect.as_str(),
            Some("EXECUTED"),
            &correlation_id,
            &json!({
                "destination": destination.key,
                "hostname": destination.host,
                "port": destination.port,
                "protocol": "tcp",
                "resolved_addresses": resolved,
                "connected_address": connected,
                "reservation_id": reservation.id,
                "determining_policy": determining_policy,
                "payload_bytes_sent": 0,
                "payload_bytes_received": 0,
                "network_extension_enforcement": false,
            }),
        )?;
        Ok(NetworkProbeResult {
            event_id: event.event_id,
            reservation_id: reservation.id,
            correlation_id,
            destination: destination.key,
            resolved_addresses: resolved,
            connected_address: connected,
        })
    }

    fn session_context(&self, session_id: &str) -> Result<(LocalSession, LocalProfile)> {
        let session = self
            .store
            .get_session(session_id)?
            .ok_or_else(|| VigilError::NotFound("local session".to_string()))?;
        if session.status != SessionStatus::Running
            || session.enforcement_posture != "semantic_enforced"
        {
            return Err(VigilError::Unauthorized(
                "network broker requires a running semantic-enforced session".to_string(),
            ));
        }
        let profile = session.profile.parse()?;
        Ok((session, profile))
    }

    /// Apply session state to a destination decision, record it, and refuse if it does not
    /// permit.
    ///
    /// Both the pre-resolution and post-resolution decisions come through here. Only the
    /// pre-resolution one can produce an approval, because only it can be
    /// `REQUIRE_APPROVAL`; a resolution that landed on a private or special-use address is a
    /// `DENY` and is not something a human is offered the chance to wave through. That also
    /// means at most one lease use is spent per probe.
    ///
    /// A use spent at preflight is not refunded if resolution then denies. That errs in the
    /// safe direction — the session ends up with less authority than it paid for, never more —
    /// and matches how an unreconcilable budget reservation stays held (ADR 0006).
    fn require_permit(
        &self,
        session_id: &str,
        correlation_id: &str,
        destination_key: &str,
        decision: LocalDecision,
    ) -> Result<()> {
        let authorization = self.store.authorize_decision(
            session_id,
            LocalAction::NetworkConnect,
            destination_key,
            decision,
            |_| Some(destination_key.to_string()),
        )?;
        let decision = &authorization.decision;
        if decision.permits_execution() {
            return Ok(());
        }
        let mut payload = serde_json::to_value(decision)?;
        if let Some(object) = payload.as_object_mut() {
            object.insert(
                "risk_state".to_string(),
                json!(authorization.risk_state.as_str()),
            );
            if let Some(outcome) = &authorization.approval {
                object.insert(
                    "approval_id".to_string(),
                    json!(outcome.request().approval_id),
                );
                if let Some(detection) = outcome.detection() {
                    object.insert("detection".to_string(), json!(detection));
                }
            }
        }
        self.store.append_event(
            session_id,
            "policy",
            &decision.action,
            Some(outcome_name(decision.outcome)),
            correlation_id,
            &payload,
        )?;
        let message = match &authorization.approval {
            Some(outcome) => format!(
                "{}; approval {} is required (grant it with `vigil approvals grant {}`)",
                decision.reason,
                outcome.request().approval_id,
                outcome.request().approval_id,
            ),
            None => decision.reason.clone(),
        };
        Err(VigilError::Unauthorized(message))
    }

    fn record_invalid(
        &self,
        session_id: &str,
        correlation_id: &str,
        error: &VigilError,
    ) -> Result<()> {
        self.store.append_event(
            session_id,
            "network",
            "network.request_invalid",
            Some("DENY"),
            correlation_id,
            &json!({"error_class": error.class()}),
        )?;
        Ok(())
    }

    fn record_failure(
        &self,
        session_id: &str,
        correlation_id: &str,
        action: &str,
        reservation_id: Option<&str>,
        error: &VigilError,
    ) -> Result<()> {
        self.store.append_event(
            session_id,
            "network",
            action,
            Some("FAILED"),
            correlation_id,
            &json!({
                "reservation_id": reservation_id,
                "error_class": error.class(),
            }),
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedDestination {
    host: String,
    port: u16,
    key: String,
    ip_literal: bool,
}

impl ValidatedDestination {
    fn new(host: &str, port: u16) -> Result<Self> {
        if port == 0 {
            return Err(VigilError::InvalidValue {
                field: "port",
                reason: "port zero is not a network destination".to_string(),
            });
        }
        let host = normalize_host(host)?;
        let ip_literal = IpAddr::from_str(&host).is_ok();
        let key = destination_key(&host, port);
        Ok(Self {
            host,
            port,
            key,
            ip_literal,
        })
    }
}

fn normalize_host(host: &str) -> Result<String> {
    if host.ends_with("..") {
        return Err(VigilError::InvalidValue {
            field: "host",
            reason: "hostname has more than one trailing root label".to_string(),
        });
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.chars().any(char::is_control)
    {
        return Err(VigilError::InvalidValue {
            field: "host",
            reason: "hostname is empty, non-ASCII, contains controls, or exceeds its bound"
                .to_string(),
        });
    }
    if IpAddr::from_str(&host).is_ok() {
        return Ok(host);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(VigilError::InvalidValue {
                field: "host",
                reason: "hostname labels are malformed".to_string(),
            });
        }
    }
    Ok(host)
}

fn destination_key(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn evaluate_network_preflight(
    profile: LocalProfile,
    destination: &ValidatedDestination,
) -> LocalDecision {
    if profile == LocalProfile::Observe {
        return network_decision(
            DecisionOutcome::Observe,
            destination,
            None,
            "observe-profile",
            "recorded only; this profile does not enforce network policy",
            RiskState::Normal,
            None,
        );
    }
    if destination.ip_literal {
        return network_decision(
            DecisionOutcome::Deny,
            destination,
            None,
            "deny-direct-ip-egress",
            "direct-IP egress is not permitted by protected profiles",
            RiskState::Elevated,
            Some(crate::DETECTION_DIRECT_IP_EGRESS),
        );
    }
    if !profile_destination_allowed(profile, &destination.host, destination.port) {
        return network_decision(
            DecisionOutcome::RequireApproval,
            destination,
            None,
            "approve-new-network-destination",
            "destination is not in the profile hostname/port allowlist",
            RiskState::Elevated,
            Some(crate::DETECTION_UNKNOWN_NETWORK_DESTINATION),
        );
    }
    network_decision(
        DecisionOutcome::Allow,
        destination,
        None,
        "permit-profile-network-destination",
        "hostname and port match the profile allowlist",
        RiskState::Normal,
        None,
    )
}

fn evaluate_network_resolution(
    profile: LocalProfile,
    destination: &ValidatedDestination,
    addresses: &[SocketAddr],
) -> LocalDecision {
    let resolved = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if profile == LocalProfile::Observe {
        return network_decision(
            DecisionOutcome::Observe,
            destination,
            Some(resolved),
            "observe-profile",
            "resolved destination recorded without enforcement",
            RiskState::Normal,
            None,
        );
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return network_decision(
            DecisionOutcome::Deny,
            destination,
            Some(resolved),
            "deny-private-or-special-resolution",
            "hostname resolved to a private, local, metadata, or special-use address",
            RiskState::Elevated,
            Some(crate::DETECTION_DNS_REBINDING),
        );
    }
    network_decision(
        DecisionOutcome::Allow,
        destination,
        Some(resolved),
        "permit-validated-public-resolution",
        "every resolved address passed destination-integrity checks",
        RiskState::Normal,
        None,
    )
}

fn profile_destination_allowed(profile: LocalProfile, host: &str, port: u16) -> bool {
    if port != 443 {
        return false;
    }
    match profile {
        LocalProfile::DeveloperStandard => matches!(
            host,
            "github.com" | "api.github.com" | "crates.io" | "index.crates.io" | "static.crates.io"
        ),
        LocalProfile::DeveloperRestricted => matches!(host, "github.com" | "api.github.com"),
        LocalProfile::Research => matches!(host, "arxiv.org" | "export.arxiv.org"),
        LocalProfile::UntrustedAgent | LocalProfile::Observe => false,
    }
}

fn network_decision(
    outcome: DecisionOutcome,
    destination: &ValidatedDestination,
    resolved_resource: Option<String>,
    policy: &str,
    reason: &str,
    risk_after: RiskState,
    detection: Option<&str>,
) -> LocalDecision {
    LocalDecision {
        outcome,
        action: LocalAction::NetworkConnect.as_str().to_string(),
        requested_resource: destination.key.clone(),
        resolved_resource,
        determining_policy: policy.to_string(),
        reason: reason.to_string(),
        risk_before: RiskState::Normal,
        risk_after,
        detection: detection.map(str::to_string),
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4() {
        return is_public_ipv4(ipv4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xe000) != 0x2000
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn outcome_name(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
        DecisionOutcome::RequireApproval => "REQUIRE_APPROVAL",
        DecisionOutcome::Observe => "OBSERVE",
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetDimension, NewSession};
    use std::path::PathBuf;

    fn fixture(profile: &str) -> (PathBuf, LocalStore, String) {
        let root = std::env::temp_dir().join(format!("vigil-network-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace");
        let store = LocalStore::open(&root.join("vigil.db")).expect("open store");
        let session = store
            .create_session(&NewSession {
                profile: profile.to_string(),
                workspace,
                executable: "vigil-network-broker".to_string(),
                argv: vec!["vigil-network-broker".to_string()],
                task: None,
                enforcement_posture: "semantic_enforced".to_string(),
            })
            .expect("create session");
        store
            .activate_semantic_session(&session.id)
            .expect("activate session");
        (root, store, session.id)
    }

    fn consumed(store: &LocalStore, session: &str, dimension: BudgetDimension) -> u64 {
        store
            .budget_snapshot(session)
            .expect("budget")
            .into_iter()
            .find(|counter| counter.dimension == dimension)
            .expect("counter")
            .consumed
    }

    fn public_address() -> SocketAddr {
        "93.184.216.34:443".parse().expect("public address")
    }

    #[test]
    fn an_allowlisted_public_destination_connects_and_is_charged_once() {
        let (root, store, session) = fixture("developer-standard");
        let source = SimulatedNetworkSource::default();
        source
            .set_resolution("github.com", 443, vec![public_address()])
            .expect("resolution");
        let broker = NetworkBroker::new(&store, &source);
        let request = NetworkProbeRequest::new("GitHub.COM.", 443);
        broker.probe(&session, &request).expect("first probe");
        broker.probe(&session, &request).expect("second probe");
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkConnections),
            2
        );
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkDestinations),
            1
        );
        assert_eq!(source.attempts().expect("attempts"), (2, 2));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_destination_is_denied_before_resolution() {
        let (root, store, session) = fixture("developer-standard");
        let source = SimulatedNetworkSource::default();
        let error = NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("attacker.example", 443))
            .expect_err("unknown host must deny");
        assert!(matches!(error, VigilError::Unauthorized(_)));
        assert_eq!(source.attempts().expect("attempts"), (0, 0));
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkConnections),
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn private_resolution_is_denied_as_rebinding_before_connect() {
        let (root, store, session) = fixture("developer-standard");
        let source = SimulatedNetworkSource::default();
        source
            .set_resolution(
                "github.com",
                443,
                vec!["127.0.0.1:443".parse().expect("loopback")],
            )
            .expect("resolution");
        assert!(NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("github.com", 443))
            .is_err());
        assert_eq!(source.attempts().expect("attempts"), (1, 0));
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkConnections),
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn direct_ip_and_wrong_port_deny_without_resolution() {
        let (root, store, session) = fixture("developer-standard");
        let source = SimulatedNetworkSource::default();
        assert!(NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("8.8.8.8", 443))
            .is_err());
        assert!(NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("github.com", 22))
            .is_err());
        assert!(NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("github.com..", 443))
            .is_err());
        assert_eq!(source.attempts().expect("attempts"), (0, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolver_cannot_change_the_authorized_port() {
        let (root, store, session) = fixture("developer-standard");
        let source = SimulatedNetworkSource::default();
        source
            .set_resolution(
                "github.com",
                443,
                vec!["93.184.216.34:80".parse().expect("wrong port")],
            )
            .expect("resolution");
        assert!(NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("github.com", 443))
            .is_err());
        assert_eq!(source.attempts().expect("attempts"), (1, 0));
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkConnections),
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_connect_refunds_both_connection_and_first_destination() {
        let (root, store, session) = fixture("developer-standard");
        let source = SimulatedNetworkSource::default();
        source
            .set_resolution("github.com", 443, vec![public_address()])
            .expect("resolution");
        source.set_connect_failure(true).expect("fail connections");
        assert!(NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("github.com", 443))
            .is_err());
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkConnections),
            0
        );
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkDestinations),
            0
        );
        source
            .set_connect_failure(false)
            .expect("allow connections");
        NetworkBroker::new(&store, &source)
            .probe(&session, &NetworkProbeRequest::new("github.com", 443))
            .expect("retry");
        assert_eq!(
            consumed(&store, &session, BudgetDimension::NetworkDestinations),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn special_ipv4_and_ipv6_ranges_are_not_public() {
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "198.51.100.1",
            "224.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().expect("IP literal")), "{ip}");
        }
        assert!(is_public_ip("8.8.8.8".parse().expect("public IP")));
        assert!(is_public_ip(
            "2606:4700:4700::1111".parse().expect("public IPv6")
        ));
    }
}
