import CryptoKit
import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class NetworkProviderHealthRuntimeTests: XCTestCase {
    func test_key_store_creates_stable_nonexporting_identity() throws {
        let keychain = MemoryHealthKeychain()
        let store = try NativeNetworkProviderHealthKeyStore(
            service: "com.vigil.security.network.provider-health",
            account: "network-instance-1",
            keychain: keychain
        )

        let first = try store.loadOrCreate()
        let second = try store.loadOrCreate()

        XCTAssertEqual(first.keyID, second.keyID)
        XCTAssertEqual(first.publicKey, second.publicKey)
        XCTAssertEqual(first.publicKey.count, 32)
        XCTAssertTrue(first.keyID.hasPrefix("provider-health-"))
        XCTAssertEqual(keychain.insertions, 1)
    }

    func test_key_store_reloads_winner_after_creation_race() throws {
        let winner = Curve25519.Signing.PrivateKey()
        let keychain = MemoryHealthKeychain(
            duplicateWinner: winner.rawRepresentation
        )
        let identity = try NativeNetworkProviderHealthKeyStore(
            service: "com.vigil.security.network.provider-health",
            account: "network-instance-1",
            keychain: keychain
        ).loadOrCreate()

        XCTAssertEqual(identity.publicKey, winner.publicKey.rawRepresentation)
        XCTAssertEqual(keychain.insertions, 1)
    }

    func test_key_store_refuses_corrupt_persisted_key_without_replacement() throws {
        let keychain = MemoryHealthKeychain(initial: Data(repeating: 0x41, count: 31))
        let store = try NativeNetworkProviderHealthKeyStore(
            service: "com.vigil.security.network.provider-health",
            account: "network-instance-1",
            keychain: keychain
        )

        XCTAssertThrowsError(try store.loadOrCreate()) { error in
            XCTAssertEqual(error as? NativeNetworkProviderHealthKeyStoreError, .corruptKey)
        }
        XCTAssertEqual(keychain.insertions, 0)
    }

    func test_publication_loop_emits_current_policy_and_flow_counts() throws {
        try withTemporaryDirectory { directory in
            let now: Int64 = 1_000_000
            let privateKey = Curve25519.Signing.PrivateKey()
            let signer = try NativeNetworkProviderHealthSigner(
                keyID: "provider-health-test",
                privateKey: privateKey.rawRepresentation
            )
            let store = try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory)
            let state = try installedState(expiresAt: now + 60_000)
            let counters = NativeNetworkProviderFlowCounters()
            counters.record(decision(.allow))
            counters.record(decision(.drop))
            counters.record(decision(.pause))
            counters.record(decision(.allow))
            let loop = try NativeNetworkProviderHealthPublicationLoop(
                targetInstanceID: "network-instance-1",
                providerBundleIdentifier: "com.vigil.security.network",
                policyState: state,
                counters: counters,
                publisher: NativeNetworkProviderHealthPublisher(store: store, signer: signer),
                clock: { now }
            )

            loop.publishOnce()

            let verified = try NativeNetworkProviderHealthReader(
                store: store,
                verifier: try NativeSignedNetworkProviderHealthVerifier(
                    expectedInstanceID: "network-instance-1",
                    expectedProviderBundleIdentifier: "com.vigil.security.network",
                    trustedKeys: ["provider-health-test": privateKey.publicKey.rawRepresentation]
                )
            ).read(nowUnixMilliseconds: now)
            XCTAssertEqual(verified.policyGeneration, 9)
            XCTAssertEqual(verified.allowedFlows, 2)
            XCTAssertEqual(verified.droppedFlows, 1)
            XCTAssertEqual(verified.pausedFlows, 1)
            XCTAssertEqual(verified.totalFlows, 4)
            XCTAssertEqual(
                loop.status,
                NativeNetworkProviderHealthPublicationStatus(
                    isRunning: false,
                    successfulPublications: 1,
                    failedPublications: 0,
                    lastPublicationUnixMilliseconds: now
                )
            )
        }
    }

    func test_publication_without_policy_or_clock_fails_closed() throws {
        try withTemporaryDirectory { directory in
            let key = Curve25519.Signing.PrivateKey()
            let loop = try NativeNetworkProviderHealthPublicationLoop(
                targetInstanceID: "network-instance-1",
                providerBundleIdentifier: "com.vigil.security.network",
                policyState: NativeNetworkPolicyState(),
                counters: NativeNetworkProviderFlowCounters(),
                publisher: NativeNetworkProviderHealthPublisher(
                    store: try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory),
                    signer: try NativeNetworkProviderHealthSigner(
                        keyID: "provider-health-test",
                        privateKey: key.rawRepresentation
                    )
                ),
                clock: { nil }
            )

            loop.publishOnce()

            XCTAssertEqual(loop.status.failedPublications, 1)
            XCTAssertEqual(loop.status.successfulPublications, 0)
            XCTAssertThrowsError(
                try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory).read()
            )
        }
    }

    func test_timer_interval_is_strictly_bounded_and_start_stop_are_idempotent() throws {
        try withTemporaryDirectory { directory in
            let key = Curve25519.Signing.PrivateKey()
            let publisher = NativeNetworkProviderHealthPublisher(
                store: try NativeNetworkProviderHealthEnvelopeStore(directoryURL: directory),
                signer: try NativeNetworkProviderHealthSigner(
                    keyID: "provider-health-test",
                    privateKey: key.rawRepresentation
                )
            )
            for interval in [0.5, 31, .infinity] {
                XCTAssertThrowsError(try NativeNetworkProviderHealthPublicationLoop(
                    interval: interval,
                    targetInstanceID: "network-instance-1",
                    providerBundleIdentifier: "com.vigil.security.network",
                    policyState: NativeNetworkPolicyState(),
                    counters: NativeNetworkProviderFlowCounters(),
                    publisher: publisher
                ))
            }
            let loop = try NativeNetworkProviderHealthPublicationLoop(
                interval: 30,
                targetInstanceID: "network-instance-1",
                providerBundleIdentifier: "com.vigil.security.network",
                policyState: NativeNetworkPolicyState(),
                counters: NativeNetworkProviderFlowCounters(),
                publisher: publisher
            )
            loop.start()
            loop.start()
            XCTAssertTrue(loop.status.isRunning)
            loop.stop()
            loop.stop()
            XCTAssertFalse(loop.status.isRunning)
        }
    }

    private func installedState(expiresAt: Int64) throws -> NativeNetworkPolicyState {
        let snapshot = NativeNetworkSnapshot(
            schemaVersion: "vigil.network-policy/v1",
            targetInstanceID: "network-instance-1",
            generation: 9,
            issuedAtUnixMilliseconds: expiresAt - 60_000,
            expiresAtUnixMilliseconds: expiresAt,
            sessions: [:],
            attributions: []
        )
        let state = NativeNetworkPolicyState()
        try state.install(VerifiedNativeNetworkSnapshot(snapshot: snapshot))
        return state
    }

    private func decision(_ action: NativeNetworkDecisionAction) -> NativeNetworkDecision {
        NativeNetworkDecision(
            action: action,
            reason: .unmanagedProcess,
            sessionID: nil,
            policyGeneration: nil
        )
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-health-runtime-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

private final class MemoryHealthKeychain: NativeNetworkProviderHealthKeychain, @unchecked Sendable {
    private let lock = NSLock()
    private var value: Data?
    private var duplicateWinner: Data?
    private(set) var insertions = 0

    init(initial: Data? = nil, duplicateWinner: Data? = nil) {
        value = initial
        self.duplicateWinner = duplicateWinner
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
            if let winner = duplicateWinner {
                value = winner
                duplicateWinner = nil
                return .duplicate
            }
            if value != nil { return .duplicate }
            value = candidate
            return .inserted
        }
    }
}
