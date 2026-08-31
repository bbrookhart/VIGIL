import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class NetworkProviderPolicyReloadLoopTests: XCTestCase {
    func test_reload_loop_installs_a_newly_published_generation() throws {
        try withTemporaryDirectory { directory in
            let keychain = ReloadLoopMemoryKeychain()
            let identity = try NativeNetworkPolicySigningKeyStore(
                service: "com.vigil.security.control-center.network-policy",
                account: "network-instance-1",
                keychain: keychain
            ).loadOrCreate()
            let provisioner = try NativeNetworkBootstrapPolicyProvisioner(
                directoryURL: directory,
                targetInstanceID: "network-instance-1",
                identity: identity
            )
            let initialTime: Int64 = 1_000_000
            _ = try provisioner.prepare(
                nowUnixMilliseconds: initialTime,
                leaseMilliseconds: 6 * 60 * 1_000
            )
            let state = NativeNetworkPolicyState()
            let lifecycle = NativeNetworkProviderLifecycle(state: state)
            _ = try lifecycle.start(
                vendorConfiguration: configuration(identity: identity),
                nowUnixMilliseconds: initialTime,
                containerResolver: { _ in directory }
            )
            XCTAssertEqual(state.generation, 1)

            let renewalTime = initialTime + 2 * 60 * 1_000
            XCTAssertEqual(
                try provisioner.prepare(nowUnixMilliseconds: renewalTime).generation,
                2
            )
            let loop = try NativeNetworkProviderPolicyReloadLoop(
                clock: { renewalTime },
                reload: { try lifecycle.reload(nowUnixMilliseconds: $0) }
            )
            loop.reloadOnce()

            XCTAssertEqual(state.generation, 2)
            XCTAssertEqual(loop.status.successfulReloads, 1)
            XCTAssertEqual(loop.status.failedReloads, 0)
            XCTAssertEqual(loop.status.lastObservedGeneration, 2)
        }
    }

    func test_reload_failure_retains_the_last_verified_generation() throws {
        let calls = ReloadCallCounter()
        let loop = try NativeNetworkProviderPolicyReloadLoop(
            clock: { 1_000_000 },
            reload: { _ in
                calls.increment()
                throw NativeNetworkProviderLifecycleError.policyUnavailable
            }
        )

        loop.reloadOnce()

        XCTAssertEqual(calls.value, 1)
        XCTAssertEqual(loop.status.successfulReloads, 0)
        XCTAssertEqual(loop.status.failedReloads, 1)
        XCTAssertNil(loop.status.lastObservedGeneration)
    }

    func test_missing_clock_is_a_failure_and_performs_no_reload() throws {
        let calls = ReloadCallCounter()
        let loop = try NativeNetworkProviderPolicyReloadLoop(
            clock: { nil },
            reload: { _ in
                calls.increment()
                return .installed(generation: 1)
            }
        )

        loop.reloadOnce()

        XCTAssertEqual(calls.value, 0)
        XCTAssertEqual(loop.status.failedReloads, 1)
    }

    func test_interval_is_bounded_and_start_stop_are_idempotent() throws {
        XCTAssertThrowsError(try NativeNetworkProviderPolicyReloadLoop(
            interval: 0.5,
            clock: { 1 },
            reload: { _ in .unchanged(generation: 1) }
        ))
        XCTAssertThrowsError(try NativeNetworkProviderPolicyReloadLoop(
            interval: 31,
            clock: { 1 },
            reload: { _ in .unchanged(generation: 1) }
        ))
        let loop = try NativeNetworkProviderPolicyReloadLoop(
            interval: 30,
            clock: { 1 },
            reload: { _ in .unchanged(generation: 1) }
        )
        loop.start()
        loop.start()
        XCTAssertTrue(loop.status.isRunning)
        loop.stop()
        loop.stop()
        XCTAssertFalse(loop.status.isRunning)
    }

    private func configuration(
        identity: NativeNetworkPolicySigningIdentity
    ) -> [String: Any] {
        [
            "schema_version": "vigil.network-provider/v1",
            "app_group_identifier": "group.com.vigil.security",
            "target_instance_id": "network-instance-1",
            "trusted_keys": [identity.keyID: encodeNetworkBase64URL(identity.publicKey)],
        ]
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-reload-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

private final class ReloadLoopMemoryKeychain: NativeNetworkProviderHealthKeychain,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var value: Data?

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
            guard value == nil else { return .duplicate }
            value = candidate
            return .inserted
        }
    }
}

private final class ReloadCallCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func increment() { lock.withLock { count += 1 } }
    var value: Int { lock.withLock { count } }
}
