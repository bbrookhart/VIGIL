import Foundation
import XCTest

@testable import VigilEndpointAdapter

/// The durable generation high-water mark. This is what stops a captured policy envelope from
/// being replayed across an extension restart (ADR 0022).
final class GenerationStoreTests: XCTestCase {
    private var fixture: EndpointPolicyFixture!

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try EndpointPolicyFixture.load()
    }

    func test_a_new_store_is_empty() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            XCTAssertEqual(try store.currentGeneration(), 0, "new generation store was not empty")
        }
    }

    func test_installing_commits_the_generation() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            let control = try NativeEndpointControlService(
                policyVerifier: fixture.verifier(), generationStore: store
            )
            let reply = controlReply(control.handleForTesting(
                requestData: try controlRequest(
                    id: "durable-install-42", operation: "install_policy",
                    envelope: fixture.envelopeObject
                ),
                nowUnixMilliseconds: fixture.verificationTime
            ))
            XCTAssertReplyCode(reply, "ok", "durable install was rejected")
            XCTAssertEqual(try store.currentGeneration(), 42, "generation was not committed")
        }
    }

    func test_a_second_instance_cannot_overwrite_a_newer_generation() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            let competing = try NativeFileGenerationStore(directoryURL: directory)
            try store.commit(42)

            // Two live handles on one directory must not let the older view win.
            XCTAssertThrowsError(try competing.commit(41)) { error in
                guard case NativeGenerationStoreError.rollback(let current, let proposed) = error else {
                    return XCTFail("expected a rollback error, got \(error)")
                }
                XCTAssertEqual(current, 42, "cross-instance rollback lost generation context")
                XCTAssertEqual(proposed, 41, "cross-instance rollback lost generation context")
            }
        }
    }

    func test_a_non_increasing_commit_is_refused() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            try store.commit(42)
            // Equal is not greater: re-committing the same generation is a replay.
            XCTAssertThrowsError(try store.commit(42)) { error in
                guard case NativeGenerationStoreError.rollback(let current, let proposed) = error else {
                    return XCTFail("expected a rollback error, got \(error)")
                }
                XCTAssertEqual(current, 42)
                XCTAssertEqual(proposed, 42)
            }
        }
    }

    func test_state_file_is_owner_only() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            try store.commit(42)
            let attributes = try FileManager.default.attributesOfItem(
                atPath: directory.appendingPathComponent("endpoint-generation.v1").path
            )
            XCTAssertEqual(
                (attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600,
                "durable generation state did not retain owner-only permissions"
            )
        }
    }

    func test_corrupt_state_fails_closed_rather_than_resetting() throws {
        try fixture.withTemporaryDirectory { directory in
            // Silently resetting a damaged high-water mark would reopen the replay window.
            XCTAssertTrue(FileManager.default.createFile(
                atPath: directory.appendingPathComponent("endpoint-generation.v1").path,
                contents: Data("vigil.endpoint-generation/v1\n0042\n".utf8),
                attributes: [.posixPermissions: 0o600]
            ), "could not create corrupt generation fixture")

            XCTAssertThrowsError(try NativeFileGenerationStore(directoryURL: directory)) { error in
                guard case NativeGenerationStoreError.corruptState = error else {
                    return XCTFail("expected corruptState, got \(error)")
                }
            }
        }
    }

    // MARK: - Restart

    func test_restart_recovers_the_high_water_mark_without_restoring_policy() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            try store.commit(42)

            let restarted = try NativeFileGenerationStore(directoryURL: directory)
            XCTAssertEqual(
                try restarted.currentGeneration(), 42, "restart lost generation high-water mark"
            )

            let control = try NativeEndpointControlService(
                policyVerifier: fixture.verifier(), generationStore: restarted
            )
            let health = controlReply(control.handleForTesting(
                requestData: try controlRequest(id: "restart-health", operation: "health"),
                nowUnixMilliseconds: fixture.verificationTime
            ))
            // The mark survives; the policy does not. Enforcement must be re-established by
            // the control plane, not inferred from a number on disk.
            XCTAssertEqual(
                health?["ready"] as? Bool, false,
                "generation recovery falsely restored active policy"
            )
        }
    }

    func test_restart_refuses_a_replayed_snapshot() throws {
        try fixture.withTemporaryDirectory { directory in
            let store = try NativeFileGenerationStore(directoryURL: directory)
            try store.commit(42)
            let control = try NativeEndpointControlService(
                policyVerifier: fixture.verifier(),
                generationStore: try NativeFileGenerationStore(directoryURL: directory)
            )
            let replay = controlReply(control.handleForTesting(
                requestData: try controlRequest(
                    id: "durable-replay-42", operation: "install_policy",
                    envelope: fixture.envelopeObject
                ),
                nowUnixMilliseconds: fixture.verificationTime
            ))
            XCTAssertReplyCode(replay, "stale_generation", "restart accepted a policy generation replay")
        }
    }

    func test_persistence_failure_installs_no_policy() throws {
        let control = try NativeEndpointControlService(
            policyVerifier: fixture.verifier(), generationStore: RejectingGenerationStore()
        )
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "durability-failure", operation: "install_policy",
                envelope: fixture.envelopeObject
            ),
            nowUnixMilliseconds: fixture.verificationTime
        ))
        XCTAssertReplyCode(reply, "internal_failure", "persistence failure did not reject policy installation")
        // Partially installing would enforce policy the extension could not prove it had
        // recorded — a restart would then silently drop back to an older generation.
        XCTAssertNil(
            control.authorizationState(),
            "persistence failure partially installed authorization state"
        )
    }
}
