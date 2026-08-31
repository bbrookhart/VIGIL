import Foundation
import NetworkExtension

private let providerConfigurationSchema = "vigil.network-provider/v1"

public enum NativeNetworkProviderLifecycleError: Int, Error, Equatable {
    case malformedConfiguration = 1
    case unavailableAppGroup = 2
    case policyUnavailable = 3
}

struct NativeNetworkProviderConfiguration {
    let appGroupIdentifier: String
    let targetInstanceID: String
    let trustedKeys: [String: Data]

    init(vendorConfiguration: [String: Any]) throws {
        guard Set(vendorConfiguration.keys) == [
            "schema_version", "app_group_identifier", "target_instance_id", "trusted_keys",
        ], vendorConfiguration["schema_version"] as? String == providerConfigurationSchema,
        let appGroupIdentifier = vendorConfiguration["app_group_identifier"] as? String,
        appGroupIdentifier.hasPrefix("group."),
        validIdentifier(appGroupIdentifier, maximumBytes: 128),
        let targetInstanceID = vendorConfiguration["target_instance_id"] as? String,
        validIdentifier(targetInstanceID, maximumBytes: 128),
        let encodedKeys = vendorConfiguration["trusted_keys"] as? [String: String],
        !encodedKeys.isEmpty, encodedKeys.count <= 16
        else {
            throw NativeNetworkProviderLifecycleError.malformedConfiguration
        }
        var keys: [String: Data] = [:]
        for (keyID, encoded) in encodedKeys {
            guard validIdentifier(keyID, maximumBytes: 64),
                  let bytes = decodeNetworkBase64URL(encoded), bytes.count == 32
            else {
                throw NativeNetworkProviderLifecycleError.malformedConfiguration
            }
            keys[keyID] = bytes
        }
        self.appGroupIdentifier = appGroupIdentifier
        self.targetInstanceID = targetInstanceID
        trustedKeys = keys
    }
}

/// Containing-app side configuration paired exactly with the provider's strict startup parser.
public enum VigilNetworkFilterConfigurationFactory {
    public static func make(
        dataProviderBundleIdentifier: String,
        appGroupIdentifier: String,
        targetInstanceID: String,
        trustedKeys: [String: Data]
    ) throws -> NEFilterProviderConfiguration {
        guard dataProviderBundleIdentifier.contains("."),
              validIdentifier(dataProviderBundleIdentifier, maximumBytes: 255),
              appGroupIdentifier.hasPrefix("group."),
              validIdentifier(appGroupIdentifier, maximumBytes: 128),
              validIdentifier(targetInstanceID, maximumBytes: 128),
              !trustedKeys.isEmpty, trustedKeys.count <= 16
        else {
            throw NativeNetworkProviderLifecycleError.malformedConfiguration
        }
        var encodedKeys: [String: String] = [:]
        for (keyID, key) in trustedKeys {
            guard validIdentifier(keyID, maximumBytes: 64), key.count == 32 else {
                throw NativeNetworkProviderLifecycleError.malformedConfiguration
            }
            encodedKeys[keyID] = encodeNetworkBase64URL(key)
        }
        let configuration = NEFilterProviderConfiguration()
        configuration.filterSockets = true
        configuration.filterPackets = false
        configuration.filterDataProviderBundleIdentifier = dataProviderBundleIdentifier
        configuration.vendorConfiguration = [
            "schema_version": providerConfigurationSchema,
            "app_group_identifier": appGroupIdentifier,
            "target_instance_id": targetInstanceID,
            "trusted_keys": encodedKeys,
        ]
        return configuration
    }
}

/// Provider startup boundary. File work happens here, never in `handleNewFlow`.
final class NativeNetworkProviderLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private let state: NativeNetworkPolicyState
    private var coordinator: NativeNetworkPolicyCoordinator?

    init(state: NativeNetworkPolicyState) {
        self.state = state
    }

    @discardableResult
    func start(
        vendorConfiguration: [String: Any],
        nowUnixMilliseconds: Int64,
        containerResolver: (String) -> URL?
    ) throws -> NativeNetworkPolicyReloadResult {
        let configuration = try NativeNetworkProviderConfiguration(
            vendorConfiguration: vendorConfiguration
        )
        guard let container = containerResolver(configuration.appGroupIdentifier) else {
            throw NativeNetworkProviderLifecycleError.unavailableAppGroup
        }
        let verifier: NativeSignedNetworkPolicyVerifier
        do {
            verifier = try NativeSignedNetworkPolicyVerifier(
                expectedInstanceID: configuration.targetInstanceID,
                trustedKeys: configuration.trustedKeys
            )
        } catch {
            throw NativeNetworkProviderLifecycleError.malformedConfiguration
        }
        let candidate: NativeNetworkPolicyCoordinator
        do {
            candidate = NativeNetworkPolicyCoordinator(
                envelopeStore: try NativeNetworkPolicyEnvelopeStore(directoryURL: container),
                generationStore: try NativeFileNetworkGenerationStore(directoryURL: container),
                verifier: verifier,
                state: state
            )
            let result = try candidate.reload(nowUnixMilliseconds: nowUnixMilliseconds)
            lock.withLock { coordinator = candidate }
            return result
        } catch let error as NativeNetworkProviderLifecycleError {
            throw error
        } catch {
            throw NativeNetworkProviderLifecycleError.policyUnavailable
        }
    }

    @discardableResult
    func reload(nowUnixMilliseconds: Int64) throws -> NativeNetworkPolicyReloadResult {
        guard let current = lock.withLock({ coordinator }) else {
            throw NativeNetworkProviderLifecycleError.policyUnavailable
        }
        do {
            return try current.reload(nowUnixMilliseconds: nowUnixMilliseconds)
        } catch {
            throw NativeNetworkProviderLifecycleError.policyUnavailable
        }
    }

    func stop() {
        lock.withLock { coordinator = nil }
    }
}
