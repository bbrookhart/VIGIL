import CryptoKit
import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class NetworkProviderHealthTransportTests: XCTestCase {
    private let now: Int64 = 1_000_000
    private let instanceID = "network-instance-1"
    private let providerID = "com.vigil.security.network"
    private let keyID = "provider-health-k1"

    func test_atomic_health_publication_round_trips_owner_only_bytes() throws {
        try withTemporaryDirectory { directory in
            let fixture = try makeFixture()
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            try store.publish(fixture.envelope)

            XCTAssertEqual(try store.read(), fixture.envelope)
            let path = directory.appendingPathComponent("network-provider-health-envelope.v1").path
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        }
    }

    func test_read_only_health_lookup_creates_no_shared_state() throws {
        try withTemporaryDirectory { directory in
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            XCTAssertThrowsError(try store.read()) { error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .healthUnavailable)
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
    }

    func test_symlinked_health_is_refused() throws {
        try withTemporaryDirectory { directory in
            let fixture = try makeFixture()
            let target = directory.appendingPathComponent("attacker-health")
            XCTAssertTrue(FileManager.default.createFile(
                atPath: target.path,
                contents: fixture.envelope,
                attributes: [.posixPermissions: 0o600]
            ))
            try FileManager.default.createSymbolicLink(
                at: directory.appendingPathComponent("network-provider-health-envelope.v1"),
                withDestinationURL: target
            )
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            XCTAssertThrowsError(try store.read()) { error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .corruptState)
            }
        }
    }

    func test_oversized_health_is_refused_before_allocation() throws {
        try withTemporaryDirectory { directory in
            let path = directory.appendingPathComponent("network-provider-health-envelope.v1")
            XCTAssertTrue(FileManager.default.createFile(
                atPath: path.path,
                contents: Data(repeating: 0x41, count: 32 * 1_024 + 1),
                attributes: [.posixPermissions: 0o600]
            ))
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            XCTAssertThrowsError(try store.read()) { error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .corruptState)
            }
        }
    }

    func test_publisher_to_reader_path_returns_only_verified_health() throws {
        try withTemporaryDirectory { directory in
            let fixture = try makeFixture()
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            try NativeNetworkProviderHealthPublisher(
                store: store,
                signer: fixture.signer
            ).publish(fixture.reading)

            let verified = try NativeNetworkProviderHealthReader(
                store: store,
                verifier: fixture.verifier
            ).read(nowUnixMilliseconds: now)
            XCTAssertEqual(verified.policyGeneration, 42)
            XCTAssertEqual(verified.totalFlows, 12)
        }
    }

    func test_transport_does_not_make_tampered_bytes_trusted() throws {
        try withTemporaryDirectory { directory in
            let fixture = try makeFixture()
            var envelope = try XCTUnwrap(
                JSONSerialization.jsonObject(with: fixture.envelope) as? [String: Any]
            )
            var payload = try XCTUnwrap(envelope["payload"] as? String)
            payload.replaceSubrange(payload.startIndex ... payload.startIndex, with: "A")
            envelope["payload"] = payload
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            try store.publish(JSONSerialization.data(withJSONObject: envelope))

            XCTAssertThrowsError(try NativeNetworkProviderHealthReader(
                store: store,
                verifier: fixture.verifier
            ).read(nowUnixMilliseconds: now)) { error in
                XCTAssertEqual(
                    error as? NativeSignedNetworkProviderHealthError,
                    .invalidSignature
                )
            }
        }
    }

    func test_insecure_health_directory_is_refused() throws {
        try withTemporaryDirectory { directory in
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o777],
                ofItemAtPath: directory.path
            )
            XCTAssertThrowsError(
                try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            ) { error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .insecureDirectory)
            }
        }
    }

    private func makeFixture() throws -> (
        envelope: Data,
        reading: NativeNetworkProviderHealthReading,
        signer: NativeNetworkProviderHealthSigner,
        verifier: NativeSignedNetworkProviderHealthVerifier
    ) {
        let key = Curve25519.Signing.PrivateKey()
        let signer = try NativeNetworkProviderHealthSigner(
            keyID: keyID,
            privateKey: key.rawRepresentation
        )
        let reading = try NativeNetworkProviderHealthReading(
            targetInstanceID: instanceID,
            providerBundleIdentifier: providerID,
            policyGeneration: 42,
            policyExpiresAtUnixMilliseconds: now + 60_000,
            observedAtUnixMilliseconds: now - 1_000,
            allowedFlows: 7,
            droppedFlows: 3,
            pausedFlows: 2
        )
        let verifier = try NativeSignedNetworkProviderHealthVerifier(
            expectedInstanceID: instanceID,
            expectedProviderBundleIdentifier: providerID,
            trustedKeys: [keyID: key.publicKey.rawRepresentation]
        )
        return (try signer.sign(reading), reading, signer, verifier)
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-health-transport-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
