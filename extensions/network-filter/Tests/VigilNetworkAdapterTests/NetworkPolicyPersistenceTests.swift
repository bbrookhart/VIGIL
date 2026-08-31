import Foundation
import XCTest

@testable import VigilNetworkAdapter

/// Out-of-band policy transport and restart replay resistance (ADR 0036).
final class NetworkPolicyPersistenceTests: XCTestCase {
    private var fixture: NetworkPolicyFixture!

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try NetworkPolicyFixture.load()
    }

    func test_atomic_publication_round_trips_owner_only_bytes() throws {
        try withTemporaryDirectory { directory in
            let store = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let envelope = fixture.encode(fixture.envelope)
            try store.publish(envelope)

            XCTAssertEqual(try store.read(), envelope)
            let attributes = try FileManager.default.attributesOfItem(
                atPath: directory.appendingPathComponent("network-policy-envelope.v1").path
            )
            XCTAssertEqual(
                (attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600,
                "published network policy was not owner-only"
            )
        }
    }

    func test_publication_lock_serializes_independent_store_instances() throws {
        try withTemporaryDirectory { directory in
            let first = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let second = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let firstEntered = expectation(description: "first publisher owns transaction")
            let secondAttempted = expectation(description: "second publisher attempted transaction")
            let secondCompleted = DispatchSemaphore(value: 0)
            let releaseFirst = DispatchSemaphore(value: 0)
            let envelope = fixture.encode(fixture.envelope)

            DispatchQueue.global().async {
                try? first.withExclusivePublication {
                    firstEntered.fulfill()
                    releaseFirst.wait()
                }
            }
            wait(for: [firstEntered], timeout: 2)
            DispatchQueue.global().async {
                secondAttempted.fulfill()
                try? second.publish(envelope)
                secondCompleted.signal()
            }
            wait(for: [secondAttempted], timeout: 2)
            XCTAssertEqual(
                secondCompleted.wait(timeout: .now() + 0.05), .timedOut,
                "a competing publisher entered the protected transaction"
            )
            releaseFirst.signal()
            XCTAssertEqual(secondCompleted.wait(timeout: .now() + 2), .success)
            XCTAssertEqual(try second.read(), envelope)
        }
    }

    func test_missing_or_symlinked_policy_is_refused() throws {
        try withTemporaryDirectory { directory in
            let store = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            XCTAssertThrowsError(try store.read()) { error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .policyUnavailable)
            }
            XCTAssertEqual(
                try FileManager.default.contentsOfDirectory(atPath: directory.path), [],
                "read-only policy lookup created shared-container state"
            )

            let target = directory.appendingPathComponent("attacker-policy")
            XCTAssertTrue(FileManager.default.createFile(
                atPath: target.path,
                contents: fixture.encode(fixture.envelope),
                attributes: [.posixPermissions: 0o600]
            ))
            try FileManager.default.createSymbolicLink(
                at: directory.appendingPathComponent("network-policy-envelope.v1"),
                withDestinationURL: target
            )
            XCTAssertThrowsError(try store.read()) { error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .corruptState)
            }
        }
    }

    func test_insecure_shared_directory_is_refused() throws {
        try withTemporaryDirectory { directory in
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o777], ofItemAtPath: directory.path
            )
            XCTAssertThrowsError(try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)) {
                error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .insecureDirectory)
            }
        }
    }

    func test_verified_policy_is_persisted_before_activation() throws {
        try withTemporaryDirectory { directory in
            let envelopeStore = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let generationStore = try NativeFileNetworkGenerationStore(directoryURL: directory)
            let state = NativeNetworkPolicyState()
            let publisher = NativeNetworkPolicyPublisher(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier()
            )
            _ = try publisher.publish(
                fixture.encode(fixture.envelope),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            )
            let coordinator = NativeNetworkPolicyCoordinator(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier(),
                state: state
            )

            XCTAssertEqual(
                try coordinator.reload(nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds),
                .installed(generation: 12)
            )
            XCTAssertEqual(try generationStore.currentRecord()?.generation, 12)
            XCTAssertEqual(state.generation, 12)
        }
    }

    func test_restart_restores_only_the_exact_durable_envelope() throws {
        try withTemporaryDirectory { directory in
            let envelopeStore = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let generationStore = try NativeFileNetworkGenerationStore(directoryURL: directory)
            _ = try NativeNetworkPolicyPublisher(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier()
            ).publish(
                fixture.encode(fixture.envelope),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            )
            let first = NativeNetworkPolicyCoordinator(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier(),
                state: NativeNetworkPolicyState()
            )
            _ = try first.reload(nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds)

            let restartedState = NativeNetworkPolicyState()
            let restarted = NativeNetworkPolicyCoordinator(
                envelopeStore: try NativeNetworkPolicyEnvelopeStore(directoryURL: directory),
                generationStore: try NativeFileNetworkGenerationStore(directoryURL: directory),
                verifier: try fixture.verifier(),
                state: restartedState
            )
            XCTAssertEqual(
                try restarted.reload(nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds),
                .installed(generation: 12)
            )
            XCTAssertEqual(restartedState.generation, 12)
        }
    }

    func test_same_generation_with_different_envelope_bytes_is_equivocation() throws {
        try withTemporaryDirectory { directory in
            let envelopeStore = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let generationStore = try NativeFileNetworkGenerationStore(directoryURL: directory)
            let state = NativeNetworkPolicyState()
            let coordinator = NativeNetworkPolicyCoordinator(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier(),
                state: state
            )
            _ = try NativeNetworkPolicyPublisher(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier()
            ).publish(
                fixture.encode(fixture.envelope),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            )
            _ = try coordinator.reload(nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds)

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try envelopeStore.publish(encoder.encode(fixture.envelope))
            XCTAssertThrowsError(
                try coordinator.reload(nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds)
            ) { error in
                XCTAssertEqual(
                    error as? NativeNetworkPolicyPersistenceError, .generationEquivocation
                )
            }
            XCTAssertEqual(state.generation, 12, "equivocation changed active policy")
        }
    }

    func test_competing_generation_store_cannot_reopen_rollback() throws {
        try withTemporaryDirectory { directory in
            let first = try NativeFileNetworkGenerationStore(directoryURL: directory)
            let staleView = try NativeFileNetworkGenerationStore(directoryURL: directory)
            let newer = try NativeNetworkGenerationRecord(
                generation: 12, envelopeSHA256: Data(repeating: 1, count: 32)
            )
            let older = try NativeNetworkGenerationRecord(
                generation: 11, envelopeSHA256: Data(repeating: 2, count: 32)
            )
            try first.commit(newer)
            XCTAssertThrowsError(try staleView.commit(older)) { error in
                XCTAssertEqual(
                    error as? NativeNetworkPolicyPersistenceError,
                    .rollback(current: 12, proposed: 11)
                )
            }
        }
    }

    func test_corrupt_generation_state_fails_closed() throws {
        try withTemporaryDirectory { directory in
            let path = directory.appendingPathComponent("network-generation.v1").path
            XCTAssertTrue(FileManager.default.createFile(
                atPath: path,
                contents: Data("vigil.network-generation/v1\n0012\nsha256:\(String(repeating: "0", count: 64))\n".utf8),
                attributes: [.posixPermissions: 0o600]
            ))
            XCTAssertThrowsError(try NativeFileNetworkGenerationStore(directoryURL: directory)) {
                error in
                XCTAssertEqual(error as? NativeNetworkPolicyPersistenceError, .corruptState)
            }
        }
    }

    func test_generation_persistence_failure_publishes_no_usable_policy() throws {
        try withTemporaryDirectory { directory in
            let envelopeStore = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let state = NativeNetworkPolicyState()
            let rejecting = RejectingNetworkGenerationStore()
            let publisher = NativeNetworkPolicyPublisher(
                envelopeStore: envelopeStore,
                generationStore: rejecting,
                verifier: try fixture.verifier()
            )
            XCTAssertThrowsError(try publisher.publish(
                fixture.encode(fixture.envelope),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            ))
            let coordinator = NativeNetworkPolicyCoordinator(
                envelopeStore: envelopeStore,
                generationStore: rejecting,
                verifier: try fixture.verifier(),
                state: state
            )
            XCTAssertThrowsError(
                try coordinator.reload(nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds)
            )
            XCTAssertNil(state.generation, "persistence failure partially activated policy")
        }
    }

    func test_provider_reload_creates_no_shared_container_files() throws {
        try withTemporaryDirectory { directory in
            let envelopeStore = try NativeNetworkPolicyEnvelopeStore(directoryURL: directory)
            let generationStore = try NativeFileNetworkGenerationStore(directoryURL: directory)
            _ = try NativeNetworkPolicyPublisher(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier()
            ).publish(
                fixture.encode(fixture.envelope),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            )
            try FileManager.default.removeItem(
                at: directory.appendingPathComponent(".network-policy-publication.lock")
            )
            try FileManager.default.removeItem(
                at: directory.appendingPathComponent(".network-generation.lock")
            )
            let before = try Set(FileManager.default.contentsOfDirectory(atPath: directory.path))
            let coordinator = NativeNetworkPolicyCoordinator(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: try fixture.verifier(),
                state: NativeNetworkPolicyState()
            )
            _ = try coordinator.reload(
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            )
            XCTAssertEqual(
                try Set(FileManager.default.contentsOfDirectory(atPath: directory.path)), before,
                "provider-side reload wrote into its read-only shared container"
            )
        }
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-policy-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

private final class RejectingNetworkGenerationStore: NativeNetworkGenerationStore, @unchecked Sendable {
    func currentRecord() throws -> NativeNetworkGenerationRecord? { nil }

    func commit(_: NativeNetworkGenerationRecord) throws {
        throw NativeNetworkPolicyPersistenceError.ioFailure
    }
}
