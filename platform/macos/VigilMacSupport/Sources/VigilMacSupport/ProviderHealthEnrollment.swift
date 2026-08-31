import Foundation
import VigilNetworkAdapter

public enum ProviderHealthEnrollmentFailureReason: String, Equatable, Sendable {
    case configurationUnavailable
    case extensionNotActive
    case evidenceRejected
    case identityChanged
    case trustStoreCorrupt
    case trustStoreUnavailable
}

public extension ProviderHealthEnrollmentState {
    var providerEvidence: NetworkProviderHealthEvidence {
        switch self {
        case let .enrolled(_, provider), let .alreadyPinned(_, provider): provider
        case .notAttempted, .refused: .unavailable
        }
    }
}

public enum ProviderHealthEnrollmentState: Equatable, Sendable {
    case notAttempted
    case enrolled(keyID: String, provider: NetworkProviderHealthEvidence)
    case alreadyPinned(keyID: String, provider: NetworkProviderHealthEvidence)
    case refused(ProviderHealthEnrollmentFailureReason)
}

protocol ProviderHealthEnrollmentPerforming: Sendable {
    func verifyAndPin(nowUnixMilliseconds: Int64) throws
        -> (NativeNetworkProviderHealthPinResult, VerifiedNativeNetworkProviderHealth)
}

private final class SystemProviderHealthEnrollmentPerformer: ProviderHealthEnrollmentPerforming,
    @unchecked Sendable
{
    private let verifier: NativeNetworkProviderHealthEnrollmentVerifier
    private let trustStore: NativeNetworkProviderHealthTrustStore

    init(
        verifier: NativeNetworkProviderHealthEnrollmentVerifier,
        trustStore: NativeNetworkProviderHealthTrustStore
    ) {
        self.verifier = verifier
        self.trustStore = trustStore
    }

    func verifyAndPin(nowUnixMilliseconds: Int64) throws
        -> (NativeNetworkProviderHealthPinResult, VerifiedNativeNetworkProviderHealth)
    {
        let enrollment = try verifier.verify(nowUnixMilliseconds: nowUnixMilliseconds)
        return (try trustStore.pin(enrollment), enrollment.providerHealth)
    }
}

/// The OS-reported active state is a prerequisite for first-install trust enrollment. Enrollment
/// never upgrades activation state and a refusal never becomes provider-ready evidence.
public final class ProviderHealthEnrollmentController: @unchecked Sendable {
    private let performer: any ProviderHealthEnrollmentPerforming

    public convenience init(
        verifier: NativeNetworkProviderHealthEnrollmentVerifier,
        trustStore: NativeNetworkProviderHealthTrustStore
    ) {
        self.init(performer: SystemProviderHealthEnrollmentPerformer(
            verifier: verifier,
            trustStore: trustStore
        ))
    }

    init(performer: any ProviderHealthEnrollmentPerforming) {
        self.performer = performer
    }

    public func enroll(
        activation: SystemExtensionActivationState,
        nowUnixMilliseconds: Int64
    ) -> ProviderHealthEnrollmentState {
        guard case .active = activation else {
            return .refused(.extensionNotActive)
        }
        do {
            let (result, health) = try performer.verifyAndPin(
                nowUnixMilliseconds: nowUnixMilliseconds
            )
            let evidence = NetworkProviderHealthEvidence(health)
            return switch result {
            case let .enrolled(keyID): .enrolled(keyID: keyID, provider: evidence)
            case let .alreadyPinned(keyID): .alreadyPinned(keyID: keyID, provider: evidence)
            }
        } catch let error as NativeNetworkProviderHealthEnrollmentError {
            return switch error {
            case .identityChanged: .refused(.identityChanged)
            case .corruptTrustStore: .refused(.trustStoreCorrupt)
            case .trustStoreUnavailable: .refused(.trustStoreUnavailable)
            case .invalidConfiguration, .enrollmentUnavailable, .malformedEnrollment:
                .refused(.evidenceRejected)
            }
        } catch let error as NativeNetworkProviderHealthKeyStoreError {
            return switch error {
            case .keychainUnavailable: .refused(.trustStoreUnavailable)
            case .invalidConfiguration, .corruptKey: .refused(.trustStoreCorrupt)
            }
        } catch {
            return .refused(.evidenceRejected)
        }
    }
}

/// Production host composition. It owns the durable installation identity and binds both
/// enrollment files and the host trust pin to that exact instance.
public final class ProviderHealthEnrollmentRuntime: @unchecked Sendable {
    public let installationInstanceID: String
    private let controller: ProviderHealthEnrollmentController

    public convenience init(
        applicationGroupIdentifier: String,
        providerBundleIdentifier: String
    ) throws {
        guard applicationGroupIdentifier.hasPrefix("group."),
              let container = FileManager.default.containerURL(
                  forSecurityApplicationGroupIdentifier: applicationGroupIdentifier
              )
        else {
            throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
        }
        let instanceID = try NativeNetworkInstallationIdentityStore(
            service: "com.vigil.security.control-center.installation",
            account: "network"
        ).loadOrCreate()
        let verifier = try NativeNetworkProviderHealthEnrollmentVerifier(
            enrollmentStore: try NativeNetworkProviderHealthEnrollmentStore(directoryURL: container),
            healthStore: try NativeNetworkProviderHealthEnvelopeStore(directoryURL: container),
            expectedInstanceID: instanceID,
            expectedProviderBundleIdentifier: providerBundleIdentifier
        )
        let trustStore = try NativeNetworkProviderHealthTrustStore(
            service: "com.vigil.security.control-center.provider-health-trust",
            account: instanceID
        )
        self.init(
            installationInstanceID: instanceID,
            controller: ProviderHealthEnrollmentController(
                verifier: verifier,
                trustStore: trustStore
            )
        )
    }

    init(
        installationInstanceID: String,
        controller: ProviderHealthEnrollmentController
    ) {
        self.installationInstanceID = installationInstanceID
        self.controller = controller
    }

    public func refresh(
        activation: SystemExtensionActivationState,
        nowUnixMilliseconds: Int64
    ) -> ProviderHealthEnrollmentState {
        controller.enroll(
            activation: activation,
            nowUnixMilliseconds: nowUnixMilliseconds
        )
    }
}
