import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class NetworkPolicySigningTests: XCTestCase {
    private let now: Int64 = 1_000_000
    private let instanceID = "network-instance-1"

    func test_policy_signing_identity_is_stable_and_public_key_only_is_exported() throws {
        let keychain = PolicySigningMemoryKeychain()
        let store = try signingStore(keychain: keychain)

        let first = try store.loadOrCreate()
        let second = try store.loadOrCreate()

        XCTAssertEqual(first.keyID, second.keyID)
        XCTAssertEqual(first.publicKey, second.publicKey)
        XCTAssertEqual(first.publicKey.count, 32)
        XCTAssertTrue(first.keyID.hasPrefix("network-policy-"))
        XCTAssertEqual(keychain.insertions, 1)
    }

    func test_corrupt_policy_signing_key_is_not_rotated() throws {
        let keychain = PolicySigningMemoryKeychain(initial: Data(repeating: 0x41, count: 31))

        XCTAssertThrowsError(try signingStore(keychain: keychain).loadOrCreate()) { error in
            XCTAssertEqual(error as? NativeNetworkPolicySigningError, .corruptKey)
        }
        XCTAssertEqual(keychain.insertions, 0)
    }

    func test_bootstrap_policy_is_signed_published_and_bound_to_installation() throws {
        try withTemporaryDirectory { directory in
            let identity = try signingStore(
                keychain: PolicySigningMemoryKeychain()
            ).loadOrCreate()
            let result = try NativeNetworkBootstrapPolicyProvisioner(
                directoryURL: directory,
                targetInstanceID: instanceID,
                identity: identity
            ).prepare(nowUnixMilliseconds: now)

            XCTAssertEqual(result.generation, 1)
            XCTAssertTrue(result.publishedNewPolicy)
            XCTAssertEqual(result.keyID, identity.keyID)
            let verified = try NativeSignedNetworkPolicyVerifier(
                expectedInstanceID: instanceID,
                trustedKeys: [identity.keyID: identity.publicKey]
            ).verify(
                envelopeData: try NativeNetworkPolicyEnvelopeStore(
                    directoryURL: directory
                ).read(),
                nowUnixMilliseconds: now
            )
            XCTAssertEqual(verified.generation, 1)
            XCTAssertEqual(
                try NativeFileNetworkGenerationStore(directoryURL: directory)
                    .currentRecord()?.generation,
                1
            )
        }
    }

    func test_live_bootstrap_policy_is_reused_without_generation_churn() throws {
        try withTemporaryDirectory { directory in
            let identity = try signingStore(
                keychain: PolicySigningMemoryKeychain()
            ).loadOrCreate()
            let provisioner = try NativeNetworkBootstrapPolicyProvisioner(
                directoryURL: directory,
                targetInstanceID: instanceID,
                identity: identity
            )

            XCTAssertTrue(try provisioner.prepare(
                nowUnixMilliseconds: now
            ).publishedNewPolicy)
            let reused = try provisioner.prepare(nowUnixMilliseconds: now + 1_000)

            XCTAssertEqual(reused.generation, 1)
            XCTAssertFalse(reused.publishedNewPolicy)
        }
    }

    func test_near_expiry_bootstrap_advances_generation() throws {
        try withTemporaryDirectory { directory in
            let identity = try signingStore(
                keychain: PolicySigningMemoryKeychain()
            ).loadOrCreate()
            let provisioner = try NativeNetworkBootstrapPolicyProvisioner(
                directoryURL: directory,
                targetInstanceID: instanceID,
                identity: identity
            )
            _ = try provisioner.prepare(
                nowUnixMilliseconds: now,
                leaseMilliseconds: 6 * 60 * 1_000
            )

            let refreshed = try provisioner.prepare(
                nowUnixMilliseconds: now + 2 * 60 * 1_000
            )

            XCTAssertEqual(refreshed.generation, 2)
            XCTAssertTrue(refreshed.publishedNewPolicy)
        }
    }

    func test_bootstrap_policy_grants_no_process_network_authority() throws {
        try withTemporaryDirectory { directory in
            let identity = try signingStore(
                keychain: PolicySigningMemoryKeychain()
            ).loadOrCreate()
            _ = try NativeNetworkBootstrapPolicyProvisioner(
                directoryURL: directory,
                targetInstanceID: instanceID,
                identity: identity
            ).prepare(nowUnixMilliseconds: now)
            let verified = try NativeSignedNetworkPolicyVerifier(
                expectedInstanceID: instanceID,
                trustedKeys: [identity.keyID: identity.publicKey]
            ).verify(
                envelopeData: try NativeNetworkPolicyEnvelopeStore(
                    directoryURL: directory
                ).read(),
                nowUnixMilliseconds: now
            )
            let state = NativeNetworkPolicyState()
            try state.install(verified)

            let decision = state.decide(NativeNetworkFlow(
                process: [UInt8](repeating: 0x41, count: 32),
                direction: .outbound,
                networkProtocol: .tcp,
                hostname: "example.com",
                remoteIP: "93.184.216.34",
                remotePort: 443,
                observedAtUnixMilliseconds: now
            ))
            XCTAssertEqual(decision.action, .allow)
            XCTAssertEqual(decision.reason, .unmanagedProcess)
            XCTAssertNil(decision.policyGeneration)
        }
    }

    private func signingStore(
        keychain: PolicySigningMemoryKeychain
    ) throws -> NativeNetworkPolicySigningKeyStore {
        try NativeNetworkPolicySigningKeyStore(
            service: "com.vigil.security.control-center.network-policy",
            account: instanceID,
            keychain: keychain
        )
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-signing-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

private final class PolicySigningMemoryKeychain: NativeNetworkProviderHealthKeychain,
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
