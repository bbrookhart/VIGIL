import CryptoKit
import Foundation
import XCTest

@testable import VigilNetworkAdapter

/// Authentication of the signed policy envelope, before any of its content is trusted.
final class SignedNetworkPolicyTests: XCTestCase {
    func test_rust_fixture_verifies_against_the_network_signing_domain() throws {
        let fixture = try NetworkPolicyFixture.load()
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: fixture.publicKeyBytes)
        let payload = try XCTUnwrap(decodeBase64URL(fixture.envelope.payload))
        let signature = try XCTUnwrap(decodeBase64URL(fixture.envelope.signature))

        // The domain separator is part of the signed bytes, so a signature from another
        // VIGIL envelope type cannot be replayed into a network policy.
        var signed = Data("VIGIL_NETWORK_POLICY_V1\0".utf8)
        signed.append(payload)

        XCTAssertTrue(
            key.isValidSignature(signature, for: signed),
            "Rust fixture did not verify against the network signing domain"
        )
    }

    func test_generation_survives_swift_verification() throws {
        let fixture = try NetworkPolicyFixture.load()
        let verified = try fixture.verifier().verify(
            envelopeData: fixture.encode(fixture.envelope),
            nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
        )
        XCTAssertEqual(verified.generation, 12, "Rust fixture generation did not survive Swift verification")
    }

    func test_tampered_payload_is_refused() throws {
        let fixture = try NetworkPolicyFixture.load()
        var tampered = fixture.envelope
        tampered.payload.replaceSubrange(
            tampered.payload.startIndex ... tampered.payload.startIndex, with: "A"
        )

        XCTAssertThrowsError(
            try fixture.verifier().verify(
                envelopeData: fixture.encode(tampered),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            ),
            "tampered policy signature verified"
        )
    }

    func test_expired_envelope_is_refused() throws {
        let fixture = try NetworkPolicyFixture.load()
        XCTAssertThrowsError(
            try fixture.verifier().verify(
                envelopeData: fixture.encode(fixture.envelope),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds + 60_000
            ),
            "expired signed policy verified"
        )
    }

    func test_reinstalling_the_same_generation_is_refused() throws {
        let fixture = try NetworkPolicyFixture.load()
        let verified = try fixture.verifier().verify(
            envelopeData: fixture.encode(fixture.envelope),
            nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
        )
        let state = NativeNetworkPolicyState()
        try state.install(verified)

        // Generation is a high-water mark: an attacker replaying a captured envelope must not
        // be able to reinstate policy that has since been superseded.
        XCTAssertThrowsError(try state.install(verified), "policy generation rollback installed")
    }
}
