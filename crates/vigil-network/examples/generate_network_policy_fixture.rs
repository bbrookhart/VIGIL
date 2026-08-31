//! Regenerates the non-secret Rust-to-Swift network policy contract fixture.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use vigil_endpoint::ProcessKey;
use vigil_network::{
    DestinationRule, NetworkAttribution, NetworkMode, NetworkPolicySigningKey,
    NetworkPolicySnapshot, NetworkProtocol, SessionNetworkPolicy, SignedNetworkPolicyEnvelope,
    NETWORK_POLICY_SCHEMA,
};

const FIXTURE_NOW_UNIX_MS: i64 = 1_800_000_000_000;

#[derive(Serialize)]
struct Fixture {
    verification_time_unix_ms: i64,
    expected_instance_id: &'static str,
    trusted_key_id: &'static str,
    trusted_public_key: String,
    envelope: SignedNetworkPolicyEnvelope,
}

fn main() -> vigil_common::Result<()> {
    // Deliberately public synthetic material. Never use this fixture key in a real build.
    let signing = NetworkPolicySigningKey::from_seed("network-fixture-k1", &[9; 32])?;
    let session = SessionNetworkPolicy {
        session_id: "session-network-fixture-1".to_string(),
        mode: NetworkMode::Enforce,
        destinations: vec![DestinationRule {
            hostname: "github.com".to_string(),
            protocol: NetworkProtocol::Tcp,
            ports: BTreeSet::from([443]),
            resolved_addresses: BTreeSet::from([
                "140.82.112.4".parse().expect("static IPv4 fixture"),
                "2606:50c0:8000::154".parse().expect("static IPv6 fixture"),
            ]),
            valid_until_unix_ms: (FIXTURE_NOW_UNIX_MS + 60_000) as u64,
        }],
        max_total_flows: 4,
        max_distinct_destinations: 2,
    };
    let snapshot = NetworkPolicySnapshot {
        schema_version: NETWORK_POLICY_SCHEMA.to_string(),
        target_instance_id: "network-instance-fixture".to_string(),
        generation: 12,
        issued_at_unix_ms: FIXTURE_NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: FIXTURE_NOW_UNIX_MS + 60_000,
        sessions: BTreeMap::from([(session.session_id.clone(), session)]),
        attributions: vec![NetworkAttribution {
            process: ProcessKey::synthetic(5),
            session_id: "session-network-fixture-1".to_string(),
        }],
    };
    let fixture = Fixture {
        verification_time_unix_ms: FIXTURE_NOW_UNIX_MS,
        expected_instance_id: "network-instance-fixture",
        trusted_key_id: "network-fixture-k1",
        trusted_public_key: URL_SAFE_NO_PAD.encode(signing.verifying_key_bytes()),
        envelope: signing.sign(&snapshot)?,
    };
    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}
