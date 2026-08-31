import Foundation
import XCTest

@testable import VigilNetworkAdapter

/// App Group configuration and provider startup remain strict and fail closed.
final class NetworkProviderLifecycleTests: XCTestCase {
    private var fixture: NetworkPolicyFixture!

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try NetworkPolicyFixture.load()
    }

    func test_startup_loads_the_durable_policy_from_the_resolved_app_group() throws {
        try withTemporaryDirectory { directory in
            try publishFixture(to: directory)
            let state = NativeNetworkPolicyState()
            let lifecycle = NativeNetworkProviderLifecycle(state: state)
            let result = try lifecycle.start(
                vendorConfiguration: configuration(),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds,
                containerResolver: { group in
                    group == "group.com.vigil.security" ? directory : nil
                }
            )
            XCTAssertEqual(result, .installed(generation: 12))
            XCTAssertEqual(state.generation, 12)
            XCTAssertEqual(
                try lifecycle.reload(
                    nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
                ),
                .unchanged(generation: 12)
            )
        }
    }

    func test_containing_app_factory_and_provider_parser_are_one_contract() throws {
        let filter = try VigilNetworkFilterConfigurationFactory.make(
            dataProviderBundleIdentifier: "com.vigil.security.network",
            appGroupIdentifier: "group.com.vigil.security",
            targetInstanceID: fixture.expectedInstanceID,
            trustedKeys: [fixture.trustedKeyID: fixture.publicKeyBytes]
        )
        XCTAssertTrue(filter.filterSockets)
        XCTAssertFalse(filter.filterPackets)
        XCTAssertEqual(
            filter.filterDataProviderBundleIdentifier, "com.vigil.security.network"
        )
        let parsed = try NativeNetworkProviderConfiguration(
            vendorConfiguration: try XCTUnwrap(filter.vendorConfiguration)
        )
        XCTAssertEqual(parsed.appGroupIdentifier, "group.com.vigil.security")
        XCTAssertEqual(parsed.targetInstanceID, fixture.expectedInstanceID)
        XCTAssertEqual(parsed.trustedKeys[fixture.trustedKeyID], try fixture.publicKeyBytes)
    }

    func test_containing_app_factory_rejects_ambiguous_or_empty_identity() throws {
        XCTAssertThrowsError(try VigilNetworkFilterConfigurationFactory.make(
            dataProviderBundleIdentifier: "network",
            appGroupIdentifier: "group.com.vigil.security",
            targetInstanceID: fixture.expectedInstanceID,
            trustedKeys: [fixture.trustedKeyID: fixture.publicKeyBytes]
        ))
        XCTAssertThrowsError(try VigilNetworkFilterConfigurationFactory.make(
            dataProviderBundleIdentifier: "com.vigil.security.network",
            appGroupIdentifier: "group.com.vigil.security",
            targetInstanceID: fixture.expectedInstanceID,
            trustedKeys: [:]
        ))
    }

    func test_unknown_app_group_fails_before_policy_access() throws {
        let lifecycle = NativeNetworkProviderLifecycle(state: NativeNetworkPolicyState())
        XCTAssertThrowsError(try lifecycle.start(
            vendorConfiguration: configuration(),
            nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds,
            containerResolver: { _ in nil }
        )) { error in
            XCTAssertEqual(error as? NativeNetworkProviderLifecycleError, .unavailableAppGroup)
        }
    }

    func test_missing_policy_or_replay_floor_refuses_startup() throws {
        try withTemporaryDirectory { directory in
            let state = NativeNetworkPolicyState()
            let lifecycle = NativeNetworkProviderLifecycle(state: state)
            XCTAssertThrowsError(try lifecycle.start(
                vendorConfiguration: configuration(),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds,
                containerResolver: { _ in directory }
            )) { error in
                XCTAssertEqual(error as? NativeNetworkProviderLifecycleError, .policyUnavailable)
            }
            XCTAssertNil(state.generation)
        }
    }

    func test_configuration_is_exact_and_rejects_noncanonical_keys() throws {
        var unknown = configuration()
        unknown["debug_allow"] = true
        var wrongSchema = configuration()
        wrongSchema["schema_version"] = "vigil.network-provider/v2"
        var wrongGroup = configuration()
        wrongGroup["app_group_identifier"] = "com.vigil.security"
        var paddedKey = configuration()
        paddedKey["trusted_keys"] = [fixture.trustedKeyID: fixture.trustedPublicKey + "="]

        for malformed in [unknown, wrongSchema, wrongGroup, paddedKey] {
            XCTAssertThrowsError(
                try NativeNetworkProviderConfiguration(vendorConfiguration: malformed)
            ) { error in
                XCTAssertEqual(
                    error as? NativeNetworkProviderLifecycleError, .malformedConfiguration
                )
            }
        }
    }

    func test_stopped_lifecycle_cannot_reload_stale_policy() throws {
        try withTemporaryDirectory { directory in
            try publishFixture(to: directory)
            let lifecycle = NativeNetworkProviderLifecycle(state: NativeNetworkPolicyState())
            _ = try lifecycle.start(
                vendorConfiguration: configuration(),
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds,
                containerResolver: { _ in directory }
            )
            lifecycle.stop()
            XCTAssertThrowsError(try lifecycle.reload(
                nowUnixMilliseconds: fixture.verificationTimeUnixMilliseconds
            )) { error in
                XCTAssertEqual(error as? NativeNetworkProviderLifecycleError, .policyUnavailable)
            }
        }
    }

    private func configuration() -> [String: Any] {
        [
            "schema_version": "vigil.network-provider/v1",
            "app_group_identifier": "group.com.vigil.security",
            "target_instance_id": fixture.expectedInstanceID,
            "trusted_keys": [fixture.trustedKeyID: fixture.trustedPublicKey],
        ]
    }

    private func publishFixture(to directory: URL) throws {
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
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vigil-network-lifecycle-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
