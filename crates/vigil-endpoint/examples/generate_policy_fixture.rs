//! Regenerates the non-secret Rust-to-Swift Endpoint policy contract fixture.

use serde::Serialize;
use std::collections::BTreeSet;
use vigil_endpoint::{
    EndpointPolicySigningKey, EndpointPolicySnapshot, SessionEnforcementPolicy,
    SignedEndpointPolicyEnvelope,
};

const FIXTURE_NOW_UNIX_MS: i64 = 1_800_000_000_000;

#[derive(Serialize)]
struct Fixture {
    verification_time_unix_ms: i64,
    expected_instance_id: &'static str,
    trusted_key_id: &'static str,
    trusted_public_key: String,
    envelope: SignedEndpointPolicyEnvelope,
}

fn main() -> vigil_common::Result<()> {
    // Deliberately public synthetic material. Never use this fixture key in a real build.
    let signing = EndpointPolicySigningKey::from_seed("endpoint-fixture-k1", &[7; 32])?;
    let policy = SessionEnforcementPolicy::new(
        "session-fixture-1",
        vec!["/Users/test/workspace".into()],
        BTreeSet::from(["/usr/bin/env".into()]),
    )?;
    let snapshot = EndpointPolicySnapshot::new(
        "endpoint-instance-fixture",
        42,
        FIXTURE_NOW_UNIX_MS - 1_000,
        FIXTURE_NOW_UNIX_MS + 60_000,
        vec![policy],
        vec!["/Users/test/.ssh".into(), "/Users/test/.aws".into()],
    )?;
    let fixture = Fixture {
        verification_time_unix_ms: FIXTURE_NOW_UNIX_MS,
        expected_instance_id: "endpoint-instance-fixture",
        trusted_key_id: "endpoint-fixture-k1",
        trusted_public_key: base64_url(&signing.verifying_key_bytes()),
        envelope: signing.sign(&snapshot)?,
    };
    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}
