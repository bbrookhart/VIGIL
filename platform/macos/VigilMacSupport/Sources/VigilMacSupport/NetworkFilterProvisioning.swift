import Foundation
import VigilNetworkAdapter

public enum NetworkFilterProvisioningFailureReason: String, Equatable, Sendable {
    case configurationUnavailable
    case extensionNotActive
    case policyUnavailable
    case preferencesUnavailable
    case outcomeUnknown
}

public enum NetworkFilterProvisioningState: Equatable, Sendable {
    case notAttempted
    case status(NativeNetworkFilterPreferenceStatus)
    case enabled(policyGeneration: UInt64)
    case refused(NetworkFilterProvisioningFailureReason)
}

public extension NetworkFilterProvisioningState {
    var preferenceEvidence: NetworkFilterPreferenceEvidence {
        switch self {
        case let .status(status): NetworkFilterPreferenceEvidence(status)
        case .enabled: NetworkFilterPreferenceEvidence(.enabled)
        case .notAttempted, .refused: .unavailable
        }
    }
}

@MainActor
protocol NetworkFilterProvisioningPerforming: AnyObject {
    func status() async throws -> NativeNetworkFilterPreferenceStatus
    func install(nowUnixMilliseconds: Int64) async throws
        -> (NativeNetworkFilterPreferenceStatus, UInt64)
    func maintain(nowUnixMilliseconds: Int64) async throws
        -> (NativeNetworkFilterPreferenceStatus, UInt64?)
}

@MainActor
private final class SystemNetworkFilterProvisioningPerformer:
    NetworkFilterProvisioningPerforming
{
    private let desired: NativeNetworkFilterDesiredConfiguration
    private let provisioner: NativeNetworkBootstrapPolicyProvisioner
    private let preferences: NativeNetworkFilterPreferenceController

    init(
        desired: NativeNetworkFilterDesiredConfiguration,
        provisioner: NativeNetworkBootstrapPolicyProvisioner,
        preferences: NativeNetworkFilterPreferenceController
    ) {
        self.desired = desired
        self.provisioner = provisioner
        self.preferences = preferences
    }

    func status() async throws -> NativeNetworkFilterPreferenceStatus {
        try await preferences.status(expected: desired)
    }

    func install(nowUnixMilliseconds: Int64) async throws
        -> (NativeNetworkFilterPreferenceStatus, UInt64)
    {
        let provisioner = provisioner
        let policy = try await Task.detached {
            try provisioner.prepare(nowUnixMilliseconds: nowUnixMilliseconds)
        }.value
        let status = try await preferences.installAndEnable(desired)
        return (status, policy.generation)
    }

    func maintain(nowUnixMilliseconds: Int64) async throws
        -> (NativeNetworkFilterPreferenceStatus, UInt64?)
    {
        let status = try await preferences.status(expected: desired)
        guard status == .enabled else { return (status, nil) }
        let provisioner = provisioner
        let policy = try await Task.detached {
            try provisioner.prepare(nowUnixMilliseconds: nowUnixMilliseconds)
        }.value
        return (status, policy.generation)
    }
}

/// Main-actor orchestration for the public `NEFilterManager` boundary. Policy publication happens
/// first on detached work; preferences are reported enabled only after save/reload exact-match.
@MainActor
public final class NetworkFilterProvisioningRuntime {
    public let installationInstanceID: String
    private let performer: any NetworkFilterProvisioningPerforming

    public convenience init(
        applicationGroupIdentifier: String,
        providerBundleIdentifier: String,
        installationInstanceID: String
    ) throws {
        guard applicationGroupIdentifier.hasPrefix("group."),
              let container = FileManager.default.containerURL(
                  forSecurityApplicationGroupIdentifier: applicationGroupIdentifier
              )
        else {
            throw NativeNetworkPolicySigningError.invalidConfiguration
        }
        let identity = try NativeNetworkPolicySigningKeyStore(
            service: "com.vigil.security.control-center.network-policy",
            account: installationInstanceID
        ).loadOrCreate()
        let desired = try NativeNetworkFilterDesiredConfiguration(
            dataProviderBundleIdentifier: providerBundleIdentifier,
            appGroupIdentifier: applicationGroupIdentifier,
            targetInstanceID: installationInstanceID,
            trustedKeys: [identity.keyID: identity.publicKey]
        )
        let provisioner = try NativeNetworkBootstrapPolicyProvisioner(
            directoryURL: container,
            targetInstanceID: installationInstanceID,
            identity: identity
        )
        self.init(
            installationInstanceID: installationInstanceID,
            performer: SystemNetworkFilterProvisioningPerformer(
                desired: desired,
                provisioner: provisioner,
                preferences: try NativeNetworkFilterPreferenceController()
            )
        )
    }

    init(
        installationInstanceID: String,
        performer: any NetworkFilterProvisioningPerforming
    ) {
        self.installationInstanceID = installationInstanceID
        self.performer = performer
    }

    public func refresh() async -> NetworkFilterProvisioningState {
        do {
            return .status(try await performer.status())
        } catch {
            return .refused(map(error))
        }
    }

    public func installAndEnable(
        activation: SystemExtensionActivationState,
        nowUnixMilliseconds: Int64
    ) async -> NetworkFilterProvisioningState {
        guard case .active = activation else {
            return .refused(.extensionNotActive)
        }
        do {
            let (status, generation) = try await performer.install(
                nowUnixMilliseconds: nowUnixMilliseconds
            )
            guard status == .enabled else {
                return .refused(.preferencesUnavailable)
            }
            return .enabled(policyGeneration: generation)
        } catch {
            return .refused(map(error))
        }
    }

    /// Renews the signed bootstrap lease only while the OS reports the extension active and the
    /// saved filter preferences still exactly match VIGIL's immutable provider configuration.
    /// The provisioner reuses a policy with more than five minutes remaining, so frequent calls
    /// do not churn generations.
    public func maintainPolicy(
        activation: SystemExtensionActivationState,
        nowUnixMilliseconds: Int64
    ) async -> NetworkFilterProvisioningState {
        guard case .active = activation else {
            return .refused(.extensionNotActive)
        }
        do {
            let (status, generation) = try await performer.maintain(
                nowUnixMilliseconds: nowUnixMilliseconds
            )
            guard status == .enabled else { return .status(status) }
            guard let generation else { return .refused(.policyUnavailable) }
            return .enabled(policyGeneration: generation)
        } catch {
            return .refused(map(error))
        }
    }

    private func map(_ error: any Error) -> NetworkFilterProvisioningFailureReason {
        if let preference = error as? NativeNetworkFilterPreferenceError {
            return switch preference {
            case .operationTimedOut: .outcomeUnknown
            case .invalidConfiguration: .configurationUnavailable
            case .operationInProgress, .operationFailed, .verificationFailed:
                .preferencesUnavailable
            }
        }
        if error is NativeNetworkPolicyPersistenceError
            || error is NativeSignedNetworkPolicyError
            || error is NativeNetworkPolicySigningError
        {
            return .policyUnavailable
        }
        return .configurationUnavailable
    }
}
