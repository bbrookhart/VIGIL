import Foundation
import NetworkExtension

public enum NativeNetworkFilterPreferenceOperation: Sendable {
    case load
    case save
    case remove
}

public enum NativeNetworkFilterPreferenceError: Error, Equatable, Sendable {
    case invalidConfiguration
    case operationInProgress
    case operationFailed(NativeNetworkFilterPreferenceOperation)
    case operationTimedOut(NativeNetworkFilterPreferenceOperation)
    case verificationFailed
}

public enum NativeNetworkFilterPreferenceStatus: Equatable, Sendable {
    case absent
    case disabled
    case enabled
    case configurationDrifted(enabled: Bool)
}

/// Exact containing-app configuration. Construction validates the same contract consumed by the
/// provider so malformed identity never reaches Network Extension preferences.
public struct NativeNetworkFilterDesiredConfiguration: Sendable {
    public let localizedDescription: String
    public let dataProviderBundleIdentifier: String
    public let appGroupIdentifier: String
    public let targetInstanceID: String
    public let trustedKeys: [String: Data]

    public init(
        localizedDescription: String = "VIGIL Network Enforcement",
        dataProviderBundleIdentifier: String,
        appGroupIdentifier: String,
        targetInstanceID: String,
        trustedKeys: [String: Data]
    ) throws {
        guard !localizedDescription.isEmpty,
              localizedDescription.utf8.count <= 128,
              localizedDescription.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
              })
        else {
            throw NativeNetworkFilterPreferenceError.invalidConfiguration
        }
        do {
            _ = try VigilNetworkFilterConfigurationFactory.make(
                dataProviderBundleIdentifier: dataProviderBundleIdentifier,
                appGroupIdentifier: appGroupIdentifier,
                targetInstanceID: targetInstanceID,
                trustedKeys: trustedKeys
            )
        } catch {
            throw NativeNetworkFilterPreferenceError.invalidConfiguration
        }
        self.localizedDescription = localizedDescription
        self.dataProviderBundleIdentifier = dataProviderBundleIdentifier
        self.appGroupIdentifier = appGroupIdentifier
        self.targetInstanceID = targetInstanceID
        self.trustedKeys = trustedKeys
    }

    fileprivate func providerConfiguration() throws -> NEFilterProviderConfiguration {
        do {
            return try VigilNetworkFilterConfigurationFactory.make(
                dataProviderBundleIdentifier: dataProviderBundleIdentifier,
                appGroupIdentifier: appGroupIdentifier,
                targetInstanceID: targetInstanceID,
                trustedKeys: trustedKeys
            )
        } catch {
            throw NativeNetworkFilterPreferenceError.invalidConfiguration
        }
    }
}

@MainActor
protocol NativeNetworkFilterPreferences: AnyObject {
    var localizedDescription: String? { get set }
    var providerConfiguration: NEFilterProviderConfiguration? { get set }
    var isEnabled: Bool { get set }
    var grade: NEFilterManager.Grade { get set }

    func loadFromPreferences() async throws
    func saveToPreferences() async throws
    func removeFromPreferences() async throws
}

@MainActor
private final class SystemNativeNetworkFilterPreferences: NativeNetworkFilterPreferences {
    private let manager: NEFilterManager

    init(manager: NEFilterManager = .shared()) {
        self.manager = manager
    }

    var localizedDescription: String? {
        get { manager.localizedDescription }
        set { manager.localizedDescription = newValue }
    }

    var providerConfiguration: NEFilterProviderConfiguration? {
        get { manager.providerConfiguration }
        set { manager.providerConfiguration = newValue }
    }

    var isEnabled: Bool {
        get { manager.isEnabled }
        set { manager.isEnabled = newValue }
    }

    var grade: NEFilterManager.Grade {
        get { manager.grade }
        set { manager.grade = newValue }
    }

    func loadFromPreferences() async throws {
        try await bridge(manager.loadFromPreferences)
    }

    func saveToPreferences() async throws {
        try await bridge(manager.saveToPreferences)
    }

    func removeFromPreferences() async throws {
        try await bridge(manager.removeFromPreferences)
    }

    /// Use NetworkExtension's completion-handler surface explicitly. Its async overlay sends
    /// the non-Sendable manager across an isolation boundary under Swift 6 strict concurrency.
    private func bridge(_ operation: (@escaping (Error?) -> Void) -> Void) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            operation { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }
}

private final class NativeNetworkPreferenceRace: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false

    @discardableResult
    func finish(
        _ result: Result<Void, NativeNetworkFilterPreferenceError>,
        continuation: CheckedContinuation<Void, any Error>
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !completed else { return false }
        completed = true
        continuation.resume(with: result)
        return true
    }
}

/// Containing-app preference lifecycle. An enabled preference is not reported as active OS
/// enforcement; activation and entitled-device health remain separate evidence.
@MainActor
public final class NativeNetworkFilterPreferenceController {
    private let preferences: any NativeNetworkFilterPreferences
    private let timeout: Duration
    private var outcomeUnknown = false
    private var operationInProgress = false

    public convenience init(operationTimeout: Duration = .seconds(15)) throws {
        try self.init(
            preferences: SystemNativeNetworkFilterPreferences(),
            operationTimeout: operationTimeout
        )
    }

    init(
        preferences: any NativeNetworkFilterPreferences,
        operationTimeout: Duration = .seconds(15)
    ) throws {
        guard operationTimeout >= .milliseconds(100), operationTimeout <= .seconds(60) else {
            throw NativeNetworkFilterPreferenceError.invalidConfiguration
        }
        self.preferences = preferences
        timeout = operationTimeout
    }

    public func status(
        expected: NativeNetworkFilterDesiredConfiguration
    ) async throws -> NativeNetworkFilterPreferenceStatus {
        try beginOperation()
        defer { endOperation() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        return inspect(expected: expected)
    }

    /// Loads before mutation to avoid stale saves, persists the exact configuration, reloads,
    /// and refuses to report success unless preferences round-trip exactly.
    public func installAndEnable(
        _ desired: NativeNetworkFilterDesiredConfiguration
    ) async throws -> NativeNetworkFilterPreferenceStatus {
        try beginOperation()
        defer { endOperation() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        preferences.localizedDescription = desired.localizedDescription
        preferences.providerConfiguration = try desired.providerConfiguration()
        preferences.grade = .firewall
        preferences.isEnabled = true
        try await perform(.save) { try await self.preferences.saveToPreferences() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        guard inspect(expected: desired) == .enabled else {
            throw NativeNetworkFilterPreferenceError.verificationFailed
        }
        return .enabled
    }

    public func disable() async throws -> NativeNetworkFilterPreferenceStatus {
        try beginOperation()
        defer { endOperation() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        guard preferences.providerConfiguration != nil else { return .absent }
        preferences.isEnabled = false
        try await perform(.save) { try await self.preferences.saveToPreferences() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        guard preferences.providerConfiguration != nil, !preferences.isEnabled else {
            throw NativeNetworkFilterPreferenceError.verificationFailed
        }
        return .disabled
    }

    public func remove() async throws -> NativeNetworkFilterPreferenceStatus {
        try beginOperation()
        defer { endOperation() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        guard preferences.providerConfiguration != nil else { return .absent }
        try await perform(.remove) { try await self.preferences.removeFromPreferences() }
        try await perform(.load) { try await self.preferences.loadFromPreferences() }
        guard preferences.providerConfiguration == nil, !preferences.isEnabled else {
            throw NativeNetworkFilterPreferenceError.verificationFailed
        }
        return .absent
    }

    private func inspect(
        expected: NativeNetworkFilterDesiredConfiguration
    ) -> NativeNetworkFilterPreferenceStatus {
        guard let actual = preferences.providerConfiguration else { return .absent }
        guard preferences.localizedDescription == expected.localizedDescription,
              preferences.grade == .firewall,
              exactProviderConfiguration(actual, matches: expected)
        else {
            return .configurationDrifted(enabled: preferences.isEnabled)
        }
        return preferences.isEnabled ? .enabled : .disabled
    }

    private func beginOperation() throws {
        guard !operationInProgress else {
            throw NativeNetworkFilterPreferenceError.operationInProgress
        }
        guard !outcomeUnknown else {
            throw NativeNetworkFilterPreferenceError.verificationFailed
        }
        operationInProgress = true
    }

    private func endOperation() {
        operationInProgress = false
    }

    private func exactProviderConfiguration(
        _ actual: NEFilterProviderConfiguration,
        matches expected: NativeNetworkFilterDesiredConfiguration
    ) -> Bool {
        guard actual.filterSockets, !actual.filterPackets,
              actual.filterDataProviderBundleIdentifier
              == expected.dataProviderBundleIdentifier,
              let vendorConfiguration = actual.vendorConfiguration,
              let parsed = try? NativeNetworkProviderConfiguration(
                  vendorConfiguration: vendorConfiguration
              )
        else { return false }
        return parsed.appGroupIdentifier == expected.appGroupIdentifier
            && parsed.targetInstanceID == expected.targetInstanceID
            && parsed.trustedKeys == expected.trustedKeys
    }

    private func perform(
        _ operation: NativeNetworkFilterPreferenceOperation,
        body: @escaping @MainActor () async throws -> Void
    ) async throws {
        let race = NativeNetworkPreferenceRace()
        let deadline = timeout
        try await withCheckedThrowingContinuation { continuation in
            Task { @MainActor in
                do {
                    try await body()
                    race.finish(.success(()), continuation: continuation)
                } catch {
                    race.finish(
                        .failure(.operationFailed(operation)), continuation: continuation
                    )
                }
            }
            Task {
                try? await Task.sleep(for: deadline)
                await MainActor.run {
                    if race.finish(
                        .failure(.operationTimedOut(operation)), continuation: continuation
                    ) {
                        self.outcomeUnknown = true
                    }
                }
            }
        }
    }
}
