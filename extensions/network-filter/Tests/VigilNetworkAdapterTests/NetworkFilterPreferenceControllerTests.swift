import Foundation
import NetworkExtension
import XCTest

@testable import VigilNetworkAdapter

@MainActor
final class NetworkFilterPreferenceControllerTests: XCTestCase {
    func test_install_loads_before_save_and_verifies_the_round_trip() async throws {
        let preferences = FakeNetworkFilterPreferences()
        let controller = try NativeNetworkFilterPreferenceController(preferences: preferences)
        let desired = try configuration()

        let status = try await controller.installAndEnable(desired)
        XCTAssertEqual(status, .enabled)
        XCTAssertEqual(preferences.operations, [.load, .save, .load])
        XCTAssertTrue(preferences.isEnabled)
        XCTAssertEqual(preferences.grade, .firewall)
        XCTAssertEqual(preferences.localizedDescription, desired.localizedDescription)
        XCTAssertEqual(
            preferences.providerConfiguration?.filterDataProviderBundleIdentifier,
            desired.dataProviderBundleIdentifier
        )
    }

    func test_status_distinguishes_absent_disabled_enabled_and_drifted_preferences() async throws {
        let preferences = FakeNetworkFilterPreferences()
        let controller = try NativeNetworkFilterPreferenceController(preferences: preferences)
        let desired = try configuration()
        var status = try await controller.status(expected: desired)
        XCTAssertEqual(status, .absent)

        preferences.providerConfiguration = try desiredProviderConfiguration(desired)
        preferences.localizedDescription = desired.localizedDescription
        preferences.grade = .firewall
        status = try await controller.status(expected: desired)
        XCTAssertEqual(status, .disabled)
        preferences.isEnabled = true
        status = try await controller.status(expected: desired)
        XCTAssertEqual(status, .enabled)
        preferences.localizedDescription = "Unexpected filter"
        status = try await controller.status(expected: desired)
        XCTAssertEqual(status, .configurationDrifted(enabled: true))
    }

    func test_drift_in_provider_identity_is_not_reported_as_enabled_vigil_configuration() async throws {
        let preferences = FakeNetworkFilterPreferences()
        let controller = try NativeNetworkFilterPreferenceController(preferences: preferences)
        let desired = try configuration()
        preferences.providerConfiguration = try VigilNetworkFilterConfigurationFactory.make(
            dataProviderBundleIdentifier: "com.vigil.security.other-network",
            appGroupIdentifier: desired.appGroupIdentifier,
            targetInstanceID: desired.targetInstanceID,
            trustedKeys: desired.trustedKeys
        )
        preferences.localizedDescription = desired.localizedDescription
        preferences.grade = .firewall
        preferences.isEnabled = true

        let status = try await controller.status(expected: desired)
        XCTAssertEqual(status, .configurationDrifted(enabled: true))
    }

    func test_disable_and_remove_reload_and_verify_preferences() async throws {
        let preferences = FakeNetworkFilterPreferences()
        let desired = try configuration()
        preferences.providerConfiguration = try desiredProviderConfiguration(desired)
        preferences.localizedDescription = desired.localizedDescription
        preferences.isEnabled = true
        let controller = try NativeNetworkFilterPreferenceController(preferences: preferences)

        let disabled = try await controller.disable()
        let removed = try await controller.remove()
        XCTAssertEqual(disabled, .disabled)
        XCTAssertEqual(removed, .absent)
        XCTAssertNil(preferences.providerConfiguration)
        XCTAssertFalse(preferences.isEnabled)
        XCTAssertEqual(
            preferences.operations,
            [.load, .save, .load, .load, .remove, .load]
        )
    }

    func test_preference_errors_are_low_cardinality_and_do_not_claim_success() async throws {
        let preferences = FakeNetworkFilterPreferences()
        preferences.saveError = FakePreferenceError.refused
        let controller = try NativeNetworkFilterPreferenceController(preferences: preferences)

        do {
            _ = try await controller.installAndEnable(try configuration())
            XCTFail("failed preference save was reported as enabled")
        } catch {
            XCTAssertEqual(
                error as? NativeNetworkFilterPreferenceError, .operationFailed(.save)
            )
        }
    }

    func test_save_that_does_not_round_trip_is_not_reported_as_enabled() async throws {
        let preferences = FakeNetworkFilterPreferences()
        preferences.discardConfigurationOnSave = true
        let controller = try NativeNetworkFilterPreferenceController(preferences: preferences)

        do {
            _ = try await controller.installAndEnable(try configuration())
            XCTFail("discarded configuration was reported as enabled")
        } catch {
            XCTAssertEqual(
                error as? NativeNetworkFilterPreferenceError, .verificationFailed
            )
        }
        XCTAssertEqual(preferences.operations, [.load, .save, .load])
    }

    func test_timeout_invalidates_controller_instead_of_retrying_unknown_mutation() async throws {
        let preferences = FakeNetworkFilterPreferences()
        preferences.saveDelay = .milliseconds(250)
        let controller = try NativeNetworkFilterPreferenceController(
            preferences: preferences, operationTimeout: .milliseconds(100)
        )
        let desired = try configuration()

        do {
            _ = try await controller.installAndEnable(desired)
            XCTFail("timed-out save was reported as complete")
        } catch {
            XCTAssertEqual(
                error as? NativeNetworkFilterPreferenceError, .operationTimedOut(.save)
            )
        }
        do {
            _ = try await controller.status(expected: desired)
            XCTFail("controller retried after an outcome-unknown timeout")
        } catch {
            XCTAssertEqual(
                error as? NativeNetworkFilterPreferenceError, .verificationFailed
            )
        }
        XCTAssertEqual(preferences.operations, [.load, .save])
    }

    func test_concurrent_preference_sequences_are_refused_instead_of_interleaved() async throws {
        let preferences = FakeNetworkFilterPreferences()
        preferences.loadDelay = .milliseconds(150)
        let controller = try NativeNetworkFilterPreferenceController(
            preferences: preferences, operationTimeout: .seconds(1)
        )
        let desired = try configuration()
        let first = Task { try await controller.status(expected: desired) }
        while preferences.operations.isEmpty { await Task.yield() }

        do {
            _ = try await controller.disable()
            XCTFail("a second preference sequence interleaved with a pending load")
        } catch {
            XCTAssertEqual(
                error as? NativeNetworkFilterPreferenceError, .operationInProgress
            )
        }
        let firstStatus = try await first.value
        XCTAssertEqual(firstStatus, .absent)
        XCTAssertEqual(preferences.operations, [.load])
    }

    func test_invalid_description_and_timeout_are_rejected_before_preferences() throws {
        let fixture = try NetworkPolicyFixture.load()
        XCTAssertThrowsError(try NativeNetworkFilterDesiredConfiguration(
            localizedDescription: "VIGIL\nforged",
            dataProviderBundleIdentifier: "com.vigil.security.network",
            appGroupIdentifier: "group.com.vigil.security",
            targetInstanceID: fixture.expectedInstanceID,
            trustedKeys: [fixture.trustedKeyID: try fixture.publicKeyBytes]
        ))
        XCTAssertThrowsError(try NativeNetworkFilterPreferenceController(
            preferences: FakeNetworkFilterPreferences(),
            operationTimeout: .milliseconds(99)
        ))
    }

    private func configuration() throws -> NativeNetworkFilterDesiredConfiguration {
        let fixture = try NetworkPolicyFixture.load()
        return try NativeNetworkFilterDesiredConfiguration(
            dataProviderBundleIdentifier: "com.vigil.security.network",
            appGroupIdentifier: "group.com.vigil.security",
            targetInstanceID: fixture.expectedInstanceID,
            trustedKeys: [fixture.trustedKeyID: fixture.publicKeyBytes]
        )
    }

    private func desiredProviderConfiguration(
        _ desired: NativeNetworkFilterDesiredConfiguration
    ) throws -> NEFilterProviderConfiguration {
        try VigilNetworkFilterConfigurationFactory.make(
            dataProviderBundleIdentifier: desired.dataProviderBundleIdentifier,
            appGroupIdentifier: desired.appGroupIdentifier,
            targetInstanceID: desired.targetInstanceID,
            trustedKeys: desired.trustedKeys
        )
    }
}

private enum FakePreferenceError: Error {
    case refused
}

@MainActor
private final class FakeNetworkFilterPreferences: NativeNetworkFilterPreferences {
    var localizedDescription: String?
    var providerConfiguration: NEFilterProviderConfiguration?
    var isEnabled = false
    var grade: NEFilterManager.Grade = .firewall
    var operations: [NativeNetworkFilterPreferenceOperation] = []
    var loadDelay: Duration?
    var saveDelay: Duration?
    var loadError: (any Error)?
    var saveError: (any Error)?
    var removeError: (any Error)?
    var discardConfigurationOnSave = false

    func loadFromPreferences() async throws {
        operations.append(.load)
        if let loadDelay { try await Task.sleep(for: loadDelay) }
        if let loadError { throw loadError }
    }

    func saveToPreferences() async throws {
        operations.append(.save)
        if let saveDelay { try await Task.sleep(for: saveDelay) }
        if let saveError { throw saveError }
        if discardConfigurationOnSave { providerConfiguration = nil }
    }

    func removeFromPreferences() async throws {
        operations.append(.remove)
        if let removeError { throw removeError }
        providerConfiguration = nil
        localizedDescription = nil
        isEnabled = false
    }
}
