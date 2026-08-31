import CryptoKit
import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class NetworkProviderHealthEnrollmentTests: XCTestCase {
    private let now: Int64 = 1_000_000
    private let instanceID = "network-instance-1"
    private let providerID = "com.vigil.security.network"

    func test_public_identity_round_trips_through_owner_only_atomic_transport() throws {
        try withTemporaryDirectory { directory in
            let fixture = try publishFixture(to: directory)
            let candidate = try NativeNetworkProviderHealthEnrollmentStore(
                directoryURL: directory
            ).read(
                expectedInstanceID: instanceID,
                expectedProviderBundleIdentifier: providerID
            )

            XCTAssertEqual(candidate.keyID, fixture.identity.keyID)
            XCTAssertEqual(candidate.publicKey, fixture.identity.publicKey)
            let path = directory.appendingPathComponent(
                "network-provider-health-enrollment.v1"
            ).path
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        }
    }

    func test_missing_enrollment_creates_no_shared_state() throws {
        try withTemporaryDirectory { directory in
            let store = try NativeNetworkProviderHealthEnrollmentStore(directoryURL: directory)
            XCTAssertThrowsError(try store.read(
                expectedInstanceID: instanceID,
                expectedProviderBundleIdentifier: providerID
            )) { error in
                XCTAssertEqual(
                    error as? NativeNetworkProviderHealthEnrollmentError,
                    .enrollmentUnavailable
                )
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
        }
    }

    func test_unknown_or_wrong_identity_enrollment_is_rejected() throws {
        try withTemporaryDirectory { directory in
            _ = try publishFixture(to: directory)
            let path = directory.appendingPathComponent("network-provider-health-enrollment.v1")
            var object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any]
            )
            object["unexpected"] = true
            try JSONSerialization.data(withJSONObject: object).write(to: path)
            let store = try NativeNetworkProviderHealthEnrollmentStore(directoryURL: directory)
            XCTAssertThrowsError(try store.read(
                expectedInstanceID: instanceID,
                expectedProviderBundleIdentifier: providerID
            )) { error in
                XCTAssertEqual(
                    error as? NativeNetworkProviderHealthEnrollmentError,
                    .malformedEnrollment
                )
            }
        }
        try withTemporaryDirectory { directory in
            _ = try publishFixture(to: directory)
            XCTAssertThrowsError(try NativeNetworkProviderHealthEnrollmentStore(
                directoryURL: directory
            ).read(
                expectedInstanceID: "another-instance",
                expectedProviderBundleIdentifier: providerID
            ))
        }
    }

    func test_candidate_is_verified_only_by_fresh_bound_provider_health() throws {
        try withTemporaryDirectory { directory in
            let fixture = try publishFixture(to: directory)
            let verified = try enrollmentVerifier(directory: directory).verify(
                nowUnixMilliseconds: now
            )

            XCTAssertEqual(verified.keyID, fixture.identity.keyID)
            XCTAssertEqual(verified.publicKey, fixture.identity.publicKey)
            XCTAssertEqual(verified.providerHealth.policyGeneration, 42)
        }
    }

    func test_candidate_key_that_did_not_sign_health_cannot_be_verified() throws {
        try withTemporaryDirectory { directory in
            let fixture = try publishFixture(to: directory)
            let attacker = try signingIdentity(keychain: EnrollmentMemoryKeychain())
            try NativeNetworkProviderHealthEnrollmentStore(directoryURL: directory).publish(
                identity: attacker,
                targetInstanceID: instanceID,
                providerBundleIdentifier: providerID
            )
            XCTAssertNotEqual(attacker.publicKey, fixture.identity.publicKey)

            XCTAssertThrowsError(try enrollmentVerifier(directory: directory).verify(
                nowUnixMilliseconds: now
            )) { error in
                XCTAssertEqual(error as? NativeSignedNetworkProviderHealthError, .untrustedKey)
            }
        }
    }

    func test_verified_identity_is_pinned_once_and_survives_restart() throws {
        try withTemporaryDirectory { directory in
            let fixture = try publishFixture(to: directory)
            let verified = try enrollmentVerifier(directory: directory).verify(
                nowUnixMilliseconds: now
            )
            let keychain = EnrollmentMemoryKeychain()
            let first = try trustStore(keychain: keychain).pin(verified)
            let second = try trustStore(keychain: keychain).pin(verified)

            XCTAssertEqual(first, .enrolled(keyID: fixture.identity.keyID))
            XCTAssertEqual(second, .alreadyPinned(keyID: fixture.identity.keyID))
            XCTAssertEqual(keychain.insertions, 1)
        }
    }

    func test_verified_key_change_is_not_automatically_rotated() throws {
        let keychain = EnrollmentMemoryKeychain()
        let first = try withVerifiedEnrollment { verified in
            try trustStore(keychain: keychain).pin(verified)
        }
        XCTAssertNotNil(first)

        try withVerifiedEnrollment { changed in
            XCTAssertThrowsError(try trustStore(keychain: keychain).pin(changed)) { error in
                XCTAssertEqual(
                    error as? NativeNetworkProviderHealthEnrollmentError,
                    .identityChanged
                )
            }
        }
        XCTAssertEqual(keychain.insertions, 1)
    }

    func test_corrupt_existing_pin_is_not_overwritten() throws {
        let keychain = EnrollmentMemoryKeychain(initial: Data("corrupt".utf8))
        try withVerifiedEnrollment { verified in
            XCTAssertThrowsError(try trustStore(keychain: keychain).pin(verified)) { error in
                XCTAssertEqual(
                    error as? NativeNetworkProviderHealthEnrollmentError,
                    .corruptTrustStore
                )
            }
        }
        XCTAssertEqual(keychain.insertions, 0)
    }

    private func publishFixture(to directory: URL) throws -> (
        identity: NativeNetworkProviderHealthSigningIdentity,
        keychain: EnrollmentMemoryKeychain
    ) {
        let keychain = EnrollmentMemoryKeychain()
        let identity = try signingIdentity(keychain: keychain)
        try NativeNetworkProviderHealthEnrollmentStore(directoryURL: directory).publish(
            identity: identity,
            targetInstanceID: instanceID,
            providerBundleIdentifier: providerID
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
        try NativeNetworkProviderHealthPublisher(
            store: try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory),
            signer: identity.signer
        ).publish(reading)
        return (identity, keychain)
    }

    private func enrollmentVerifier(
        directory: URL
    ) throws -> NativeNetworkProviderHealthEnrollmentVerifier {
        try NativeNetworkProviderHealthEnrollmentVerifier(
            enrollmentStore: try NativeNetworkProviderHealthEnrollmentStore(directoryURL: directory),
            healthStore: try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory),
            expectedInstanceID: instanceID,
            expectedProviderBundleIdentifier: providerID
        )
    }

    private func signingIdentity(
        keychain: EnrollmentMemoryKeychain
    ) throws -> NativeNetworkProviderHealthSigningIdentity {
        try NativeNetworkProviderHealthKeyStore(
            service: "com.vigil.security.network.provider-health",
            account: instanceID,
            keychain: keychain
        ).loadOrCreate()
    }

    private func trustStore(
        keychain: EnrollmentMemoryKeychain
    ) throws -> NativeNetworkProviderHealthTrustStore {
        try NativeNetworkProviderHealthTrustStore(
            service: "com.vigil.security.control-center.provider-health-trust",
            account: instanceID,
            keychain: keychain
        )
    }

    private func withVerifiedEnrollment<T>(
        _ body: (VerifiedNativeNetworkProviderHealthEnrollment) throws -> T
    ) throws -> T {
        var result: Result<T, Error>!
        try withTemporaryDirectory { directory in
            _ = try publishFixture(to: directory)
            let verified = try enrollmentVerifier(directory: directory).verify(
                nowUnixMilliseconds: now
            )
            result = Result { try body(verified) }
        }
        return try result.get()
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-health-enrollment-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

private final class EnrollmentMemoryKeychain: NativeNetworkProviderHealthKeychain,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var value: Data?
    private(set) var insertions = 0

    init(initial: Data? = nil) {
        value = initial
    }

    func read(service: String, account: String) throws -> Data? {
        _ = service
        _ = account
        return lock.withLock { value }
    }

    func insert(
        _ candidate: Data,
        service: String,
        account: String
    ) throws -> NativeNetworkProviderHealthKeychainInsertResult {
        _ = service
        _ = account
        return lock.withLock {
            insertions += 1
            guard value == nil else { return .duplicate }
            value = candidate
            return .inserted
        }
    }
}
