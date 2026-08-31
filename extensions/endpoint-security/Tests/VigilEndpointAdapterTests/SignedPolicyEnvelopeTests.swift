import Foundation
import XCTest

@testable import VigilEndpointAdapter

/// Authentication of the signed snapshot, before any of its content reaches policy state.
final class SignedPolicyEnvelopeTests: XCTestCase {
    private var fixture: EndpointPolicyFixture!

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try EndpointPolicyFixture.load()
    }

    func test_rust_snapshot_survives_swift_decoding() throws {
        let snapshot = try fixture.verifiedSnapshot()
        XCTAssertEqual(snapshot.version, 42, "Rust snapshot generation did not survive Swift decoding")
        XCTAssertEqual(snapshot.sessions.count, 1, "Rust snapshot sessions did not survive Swift decoding")
    }

    func test_tampered_signature_is_refused_before_decoding() throws {
        XCTAssertThrowsError(
            try fixture.verifier().verify(
                envelopeData: JSONSerialization.data(withJSONObject: fixture.tamperedEnvelopeObject),
                nowUnixMilliseconds: fixture.verificationTime
            )
        ) { error in
            XCTAssertEqual(error as? NativeSignedPolicyError, .invalidSignature)
        }
    }

    func test_snapshot_for_another_instance_is_refused() throws {
        // Signed state is installation-bound: a snapshot lifted from one host must not
        // authorize another, even though the signature over it is perfectly valid.
        let otherInstance = try NativeSignedPolicyVerifier(
            expectedInstanceID: "another-endpoint-instance",
            trustedKeys: [fixture.keyID: fixture.publicKey]
        )
        XCTAssertThrowsError(
            try otherInstance.verify(
                envelopeData: fixture.envelopeData, nowUnixMilliseconds: fixture.verificationTime
            )
        ) { error in
            XCTAssertEqual(error as? NativeSignedPolicyError, .wrongInstance)
        }
    }

    func test_expired_snapshot_is_refused() throws {
        XCTAssertThrowsError(
            try fixture.verifier().verify(
                envelopeData: fixture.envelopeData,
                nowUnixMilliseconds: fixture.verificationTime + 60_000
            )
        ) { error in
            XCTAssertEqual(error as? NativeSignedPolicyError, .notCurrentlyValid)
        }
    }
}
