import Foundation
import VigilNetworkAdapter

public enum NetworkEnforcementPosture: String, Equatable, Sendable {
    case fullyEnforced
    case degraded
    case observeOnly
    case broken
}

public enum NetworkEnforcementHealthReason: String, Equatable, Sendable {
    case healthy
    case extensionStatusUnknown
    case extensionTransitionInProgress
    case extensionInactive
    case extensionRequestFailed
    case preferenceEvidenceUnavailable
    case preferencesAbsent
    case preferencesDisabled
    case preferencesDrifted
    case providerEvidenceUnavailable
    case providerUnready
    case providerEvidenceFromFuture
    case providerEvidenceStale
    case providerPolicyExpired
    case flowEvidenceUnavailable
    case flowProbeFailed
    case flowEvidenceFromFuture
    case flowEvidenceStale
    case flowGenerationMismatch
    case allowedDestinationUnreachable
    case deniedDestinationReachable
}

public struct NetworkEnforcementHealth: Equatable, Sendable {
    public let posture: NetworkEnforcementPosture
    public let reason: NetworkEnforcementHealthReason
    public let verifiedPolicyGeneration: UInt64?

    public init(
        posture: NetworkEnforcementPosture,
        reason: NetworkEnforcementHealthReason,
        verifiedPolicyGeneration: UInt64? = nil
    ) {
        self.posture = posture
        self.reason = reason
        self.verifiedPolicyGeneration = verifiedPolicyGeneration
    }
}

public struct NetworkFilterPreferenceEvidence: Equatable, Sendable {
    fileprivate enum Storage: Equatable, Sendable {
        case unavailable
        case absent
        case disabled
        case enabled
        case configurationDrifted(enabled: Bool)
    }

    fileprivate let storage: Storage

    fileprivate init(storage: Storage) {
        self.storage = storage
    }

    public static let unavailable = Self(storage: .unavailable)

    static let absent = Self(storage: .absent)
    static let disabled = Self(storage: .disabled)
    static let enabled = Self(storage: .enabled)
    static func configurationDrifted(enabled: Bool) -> Self {
        Self(storage: .configurationDrifted(enabled: enabled))
    }

    public init(_ status: NativeNetworkFilterPreferenceStatus) {
        storage = switch status {
        case .absent: .absent
        case .disabled: .disabled
        case .enabled: .enabled
        case let .configurationDrifted(enabled): .configurationDrifted(enabled: enabled)
        }
    }
}

public enum NetworkProviderUnreadyReason: String, Equatable, Sendable {
    case startupFailed
    case policyUnavailable
    case policyExpired
    case clockUnavailable
    case callbackFailure
    case unknown
}

public struct NetworkProviderHealthEvidence: Equatable, Sendable {
    fileprivate enum Storage: Equatable, Sendable {
        case unavailable
        case unready(NetworkProviderUnreadyReason)
        case ready(policyGeneration: UInt64, policyExpiresAtMilliseconds: UInt64,
                   observedAtMilliseconds: UInt64)
    }

    fileprivate let storage: Storage

    fileprivate init(storage: Storage) {
        self.storage = storage
    }

    /// Absence is the only evidence an untrusted caller may construct. Ready evidence will be
    /// minted only after authenticated provider-health verification.
    public static let unavailable = Self(storage: .unavailable)

    /// The verified wrapper has no public initializer; only successful signature, identity,
    /// freshness, and policy-lease verification can reach this conversion.
    public init(_ verified: VerifiedNativeNetworkProviderHealth) {
        precondition(verified.policyExpiresAtUnixMilliseconds >= 0)
        precondition(verified.observedAtUnixMilliseconds >= 0)
        storage = .ready(
            policyGeneration: verified.policyGeneration,
            policyExpiresAtMilliseconds: UInt64(verified.policyExpiresAtUnixMilliseconds),
            observedAtMilliseconds: UInt64(verified.observedAtUnixMilliseconds)
        )
    }

    static func unready(_ reason: NetworkProviderUnreadyReason) -> Self {
        Self(storage: .unready(reason))
    }

    static func ready(
        policyGeneration: UInt64,
        policyExpiresAtMilliseconds: UInt64,
        observedAtMilliseconds: UInt64
    ) -> Self {
        Self(storage: .ready(
            policyGeneration: policyGeneration,
            policyExpiresAtMilliseconds: policyExpiresAtMilliseconds,
            observedAtMilliseconds: observedAtMilliseconds
        ))
    }
}

public struct NetworkFlowEnforcementEvidence: Equatable, Sendable {
    fileprivate enum Storage: Equatable, Sendable {
        case unavailable
        case probeFailed
        case observed(policyGeneration: UInt64, allowedDestinationReached: Bool,
                      deniedDestinationBlocked: Bool, observedAtMilliseconds: UInt64)
    }

    fileprivate let storage: Storage

    /// Absence is the only evidence an untrusted caller may construct. Observations will be minted
    /// inside this module by the future entitled allow/deny probe controller.
    public static let unavailable = Self(storage: .unavailable)

    static let probeFailed = Self(storage: .probeFailed)
    static func observed(
        policyGeneration: UInt64,
        allowedDestinationReached: Bool,
        deniedDestinationBlocked: Bool,
        observedAtMilliseconds: UInt64
    ) -> Self {
        Self(storage: .observed(
            policyGeneration: policyGeneration,
            allowedDestinationReached: allowedDestinationReached,
            deniedDestinationBlocked: deniedDestinationBlocked,
            observedAtMilliseconds: observedAtMilliseconds
        ))
    }
}

public enum NetworkEnforcementHealthEvaluator {
    /// Combines four independent evidence planes. The order is deliberate: VIGIL never evaluates
    /// downstream health as proof when the OS product itself is not confirmed active.
    public static func evaluate(
        activation: SystemExtensionActivationState,
        preferences: NetworkFilterPreferenceEvidence,
        provider: NetworkProviderHealthEvidence,
        flow: NetworkFlowEnforcementEvidence,
        nowMilliseconds: UInt64,
        maximumEvidenceAgeMilliseconds: UInt64 = 30_000
    ) -> NetworkEnforcementHealth {
        switch activation {
        case .active:
            break
        case .failed:
            return health(.broken, .extensionRequestFailed)
        case .inactive:
            return health(.observeOnly, .extensionInactive)
        case .unknown:
            return health(.observeOnly, .extensionStatusUnknown)
        case .submitting, .awaitingUserApproval, .uninstalling, .rebootRequired:
            return health(.observeOnly, .extensionTransitionInProgress)
        }

        switch preferences.storage {
        case .enabled:
            break
        case .unavailable:
            return health(.degraded, .preferenceEvidenceUnavailable)
        case .absent:
            return health(.degraded, .preferencesAbsent)
        case .disabled:
            return health(.degraded, .preferencesDisabled)
        case .configurationDrifted:
            return health(.broken, .preferencesDrifted)
        }

        let providerGeneration: UInt64
        switch provider.storage {
        case .unavailable:
            return health(.degraded, .providerEvidenceUnavailable)
        case .unready:
            return health(.broken, .providerUnready)
        case let .ready(generation, expiresAt, observedAt):
            guard observedAt <= nowMilliseconds else {
                return health(.broken, .providerEvidenceFromFuture)
            }
            guard nowMilliseconds - observedAt <= maximumEvidenceAgeMilliseconds else {
                return health(.broken, .providerEvidenceStale)
            }
            guard nowMilliseconds < expiresAt else {
                return health(.broken, .providerPolicyExpired)
            }
            providerGeneration = generation
        }

        switch flow.storage {
        case .unavailable:
            return health(.degraded, .flowEvidenceUnavailable)
        case .probeFailed:
            return health(.broken, .flowProbeFailed)
        case let .observed(generation, allowedReached, deniedBlocked, observedAt):
            guard observedAt <= nowMilliseconds else {
                return health(.broken, .flowEvidenceFromFuture)
            }
            guard nowMilliseconds - observedAt <= maximumEvidenceAgeMilliseconds else {
                return health(.broken, .flowEvidenceStale)
            }
            guard generation == providerGeneration else {
                return health(.broken, .flowGenerationMismatch)
            }
            guard allowedReached else {
                return health(.broken, .allowedDestinationUnreachable)
            }
            guard deniedBlocked else {
                return health(.broken, .deniedDestinationReachable)
            }
        }

        return health(.fullyEnforced, .healthy, generation: providerGeneration)
    }

    private static func health(
        _ posture: NetworkEnforcementPosture,
        _ reason: NetworkEnforcementHealthReason,
        generation: UInt64? = nil
    ) -> NetworkEnforcementHealth {
        NetworkEnforcementHealth(
            posture: posture,
            reason: reason,
            verifiedPolicyGeneration: generation
        )
    }
}
