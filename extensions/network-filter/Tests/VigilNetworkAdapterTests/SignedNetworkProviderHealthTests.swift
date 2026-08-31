import CryptoKit
import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class SignedNetworkProviderHealthTests: XCTestCase {
    private let now: Int64 = 1_000_000
    private let instanceID = "network-instance-1"
    private let providerID = "com.vigil.security.network"
    private let keyID = "provider-health-k1"

    func test_signed_provider_health_round_trips_exact_counters() throws {
        let fixture = try makeFixture()
        let verified = try fixture.verifier.verify(
            envelopeData: fixture.envelope,
            nowUnixMilliseconds: now
        )

        XCTAssertEqual(verified.policyGeneration, 42)
        XCTAssertEqual(verified.allowedFlows, 7)
        XCTAssertEqual(verified.droppedFlows, 3)
        XCTAssertEqual(verified.pausedFlows, 2)
        XCTAssertEqual(verified.totalFlows, 12)
    }

    func test_tampered_payload_is_rejected_before_it_is_trusted() throws {
        let fixture = try makeFixture()
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: fixture.envelope) as? [String: Any]
        )
        var payload = try XCTUnwrap(object["payload"] as? String)
        payload.replaceSubrange(payload.startIndex ... payload.startIndex, with: "A")
        object["payload"] = payload

        XCTAssertThrowsError(try fixture.verifier.verify(
            envelopeData: JSONSerialization.data(withJSONObject: object),
            nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .invalidSignature)
        }
    }

    func test_expired_provider_policy_cannot_report_ready() throws {
        let fixture = try makeFixture(policyExpiresAt: now)
        XCTAssertThrowsError(try fixture.verifier.verify(
            envelopeData: fixture.envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .notCurrentlyValid)
        }
    }

    func test_stale_health_cannot_be_replayed() throws {
        let fixture = try makeFixture(observedAt: now - 30_001)
        XCTAssertThrowsError(try fixture.verifier.verify(
            envelopeData: fixture.envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .notCurrentlyValid)
        }
    }

    func test_excessively_future_dated_health_is_rejected() throws {
        let fixture = try makeFixture(observedAt: now + 30_001, policyExpiresAt: now + 90_000)
        XCTAssertThrowsError(try fixture.verifier.verify(
            envelopeData: fixture.envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .notCurrentlyValid)
        }
    }

    func test_health_is_bound_to_one_installation_instance() throws {
        let fixture = try makeFixture(readingInstanceID: "another-instance")
        XCTAssertThrowsError(try fixture.verifier.verify(
            envelopeData: fixture.envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .wrongInstance)
        }
    }

    func test_health_is_bound_to_the_expected_provider_bundle() throws {
        let fixture = try makeFixture(readingProviderID: "com.attacker.network")
        XCTAssertThrowsError(try fixture.verifier.verify(
            envelopeData: fixture.envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .wrongProvider)
        }
    }

    func test_a_health_key_outside_the_trust_set_is_rejected() throws {
        let fixture = try makeFixture()
        let otherKey = Curve25519.Signing.PrivateKey()
        let verifier = try NativeSignedNetworkProviderHealthVerifier(
            expectedInstanceID: instanceID,
            expectedProviderBundleIdentifier: providerID,
            trustedKeys: ["other-k1": otherKey.publicKey.rawRepresentation]
        )
        XCTAssertThrowsError(try verifier.verify(
            envelopeData: fixture.envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .untrustedKey)
        }
    }

    func test_unknown_signed_payload_fields_are_rejected() throws {
        let key = Curve25519.Signing.PrivateKey()
        var payload = validPayload()
        payload["unreviewed_authority"] = true
        let envelope = try signRaw(payload, key: key)
        let verifier = try makeVerifier(key: key)

        XCTAssertThrowsError(try verifier.verify(
            envelopeData: envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .malformedPayload)
        }
    }

    func test_signed_counter_inconsistency_is_rejected() throws {
        let key = Curve25519.Signing.PrivateKey()
        var payload = validPayload()
        payload["total_flows"] = 999
        let envelope = try signRaw(payload, key: key)
        let verifier = try makeVerifier(key: key)

        XCTAssertThrowsError(try verifier.verify(
            envelopeData: envelope, nowUnixMilliseconds: now
        )) { error in
            XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .malformedPayload)
        }
    }

    func test_empty_or_oversized_envelopes_are_rejected_before_parsing() throws {
        let fixture = try makeFixture()
        for envelope in [Data(), Data(repeating: 0x41, count: 32 * 1_024 + 1)] {
            XCTAssertThrowsError(try fixture.verifier.verify(
                envelopeData: envelope, nowUnixMilliseconds: now
            )) { error in
                XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .malformedEnvelope)
            }
        }
    }

    private func makeFixture(
        observedAt: Int64? = nil,
        policyExpiresAt: Int64? = nil,
        readingInstanceID: String? = nil,
        readingProviderID: String? = nil
    ) throws -> (envelope: Data, verifier: NativeSignedNetworkProviderHealthVerifier) {
        let key = Curve25519.Signing.PrivateKey()
        let signer = try NativeNetworkProviderHealthSigner(
            keyID: keyID,
            privateKey: key.rawRepresentation
        )
        let reading = try NativeNetworkProviderHealthReading(
            targetInstanceID: readingInstanceID ?? instanceID,
            providerBundleIdentifier: readingProviderID ?? providerID,
            policyGeneration: 42,
            policyExpiresAtUnixMilliseconds: policyExpiresAt ?? now + 60_000,
            observedAtUnixMilliseconds: observedAt ?? now - 1_000,
            allowedFlows: 7,
            droppedFlows: 3,
            pausedFlows: 2
        )
        return (try signer.sign(reading), try makeVerifier(key: key))
    }

    private func makeVerifier(
        key: Curve25519.Signing.PrivateKey
    ) throws -> NativeSignedNetworkProviderHealthVerifier {
        try NativeSignedNetworkProviderHealthVerifier(
            expectedInstanceID: instanceID,
            expectedProviderBundleIdentifier: providerID,
            trustedKeys: [keyID: key.publicKey.rawRepresentation]
        )
    }

    private func validPayload() -> [String: Any] {
        [
            "schema_version": "vigil.network-provider-health/v1",
            "target_instance_id": instanceID,
            "provider_bundle_identifier": providerID,
            "policy_generation": 42,
            "policy_expires_at_unix_ms": now + 60_000,
            "observed_at_unix_ms": now - 1_000,
            "allowed_flows": 7,
            "dropped_flows": 3,
            "paused_flows": 2,
            "total_flows": 12,
        ]
    }

    private func signRaw(
        _ object: [String: Any],
        key: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        var signed = Data("VIGIL_NETWORK_PROVIDER_HEALTH_V1\0".utf8)
        signed.append(payload)
        let envelope: [String: Any] = [
            "format": "vigil.signed-envelope/v1",
            "algorithm": "Ed25519",
            "key_id": keyID,
            "payload": encodeNetworkBase64URL(payload),
            "signature": encodeNetworkBase64URL(try key.signature(for: signed)),
        ]
        return try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
    }
}
