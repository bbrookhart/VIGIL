import Foundation

public enum SystemExtensionOperation: String, Equatable, Sendable {
    case activate
    case deactivate
    case inspect
}

public struct SystemExtensionVersion: Equatable, Sendable {
    public let bundleIdentifier: String
    public let shortVersion: String
    public let buildVersion: String

    public init(bundleIdentifier: String, shortVersion: String, buildVersion: String) {
        self.bundleIdentifier = bundleIdentifier
        self.shortVersion = shortVersion
        self.buildVersion = buildVersion
    }

    public var displayVersion: String {
        "\(shortVersion) (\(buildVersion))"
    }
}

public enum SystemExtensionFailureReason: String, Equatable, Sendable {
    case missingEntitlement
    case unsupportedBundleLocation
    case extensionNotFound
    case invalidBundle
    case invalidCodeSignature
    case validationFailed
    case forbiddenBySystemPolicy
    case requestCancelled
    case requestSuperseded
    case authorizationRequired
    case ambiguousStatus
    case invalidConfiguration
    case unknown
}

public struct SystemExtensionFailure: Equatable, Sendable {
    public let reason: SystemExtensionFailureReason
    public let systemCode: Int?

    public init(reason: SystemExtensionFailureReason, systemCode: Int? = nil) {
        self.reason = reason
        self.systemCode = systemCode
    }
}

public enum SystemExtensionActivationState: Equatable, Sendable {
    case unknown
    case submitting(SystemExtensionOperation)
    case awaitingUserApproval
    case active(version: String?)
    case inactive
    case uninstalling
    case rebootRequired(SystemExtensionOperation)
    case failed(SystemExtensionFailure)

    public var requestInFlight: Bool {
        switch self {
        case .submitting, .awaitingUserApproval:
            true
        default:
            false
        }
    }
}

public enum SystemExtensionReplacementDecision: Equatable, Sendable {
    case replace
    case cancelIdentityMismatch
    case cancelDowngrade
    case cancelInvalidVersion
}

public enum SystemExtensionLifecycle {
    /// Replacement is fail-closed: both identities must match the configured extension and the
    /// candidate version must be equal to or newer than the installed version. Developer mode can
    /// request replacement even for identical versions, so equality remains permitted.
    public static func replacementDecision(
        expectedIdentifier: String,
        existing: SystemExtensionVersion,
        candidate: SystemExtensionVersion
    ) -> SystemExtensionReplacementDecision {
        guard existing.bundleIdentifier == expectedIdentifier,
              candidate.bundleIdentifier == expectedIdentifier
        else {
            return .cancelIdentityMismatch
        }

        guard let shortComparison = compareVersions(candidate.shortVersion, existing.shortVersion),
              let buildComparison = compareVersions(candidate.buildVersion, existing.buildVersion)
        else {
            return .cancelInvalidVersion
        }

        if shortComparison == .orderedAscending {
            return .cancelDowngrade
        }
        if shortComparison == .orderedSame, buildComparison == .orderedAscending {
            return .cancelDowngrade
        }
        return .replace
    }

    public static func failure(for error: NSError) -> SystemExtensionFailure {
        guard error.domain == "OSSystemExtensionErrorDomain" else {
            return SystemExtensionFailure(reason: .unknown)
        }

        let reason: SystemExtensionFailureReason = switch error.code {
        case 2: .missingEntitlement
        case 3: .unsupportedBundleLocation
        case 4: .extensionNotFound
        case 5, 6, 7: .invalidBundle
        case 8: .invalidCodeSignature
        case 9: .validationFailed
        case 10: .forbiddenBySystemPolicy
        case 11: .requestCancelled
        case 12: .requestSuperseded
        case 13: .authorizationRequired
        default: .unknown
        }
        return SystemExtensionFailure(reason: reason, systemCode: error.code)
    }

    private static func compareVersions(_ lhs: String, _ rhs: String) -> ComparisonResult? {
        guard isStrictVersion(lhs), isStrictVersion(rhs) else {
            return nil
        }
        return lhs.compare(rhs, options: [.numeric])
    }

    private static func isStrictVersion(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else {
            return false
        }
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.count <= 4 else {
            return false
        }
        return components.allSatisfy { component in
            !component.isEmpty && component.count <= 12 &&
                component.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
        }
    }
}
