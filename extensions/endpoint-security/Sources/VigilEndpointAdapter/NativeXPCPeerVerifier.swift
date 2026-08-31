import CoreFoundation
import Security
import XPC

public enum NativeXPCPeerVerificationError: Error, Equatable {
    case invalidRequirement
    case noProcessIdentity
    case codeRequirementFailed
}

/// Unforgeable outside this module; proves a message sender satisfied the configured requirement.
public struct VerifiedNativeXPCPeer: Sendable {
    fileprivate init() {}
}

/// Verifies the sender of an XPC dictionary using the audit token attached by the kernel.
///
/// `SecCodeCreateWithXPCMessage` avoids the PID-reuse race of looking up code identity from a
/// caller-provided or connection-reported PID. The requirement must bind the expected daemon
/// identifier and production signing identity. A successful result authenticates only this XPC
/// message's sender; operation-specific authorization still belongs in the control service.
public final class NativeXPCPeerVerifier: @unchecked Sendable {
    private let requirement: SecRequirement

    public init(requirementText: String) throws {
        guard !requirementText.isEmpty,
              requirementText.utf8.count <= 4_096,
              !requirementText.contains("\0")
        else {
            throw NativeXPCPeerVerificationError.invalidRequirement
        }
        var compiled: SecRequirement?
        let status = SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(rawValue: 0),
            &compiled
        )
        guard status == errSecSuccess, let compiled else {
            throw NativeXPCPeerVerificationError.invalidRequirement
        }
        requirement = compiled
    }

    public func verify(message: xpc_object_t) throws -> VerifiedNativeXPCPeer {
        var code: SecCode?
        let identityStatus = SecCodeCreateWithXPCMessage(
            message,
            SecCSFlags(rawValue: 0),
            &code
        )
        guard identityStatus == errSecSuccess, let code else {
            throw NativeXPCPeerVerificationError.noProcessIdentity
        }
        guard SecCodeCheckValidity(
            code,
            SecCSFlags(rawValue: 0),
            requirement
        ) == errSecSuccess else {
            throw NativeXPCPeerVerificationError.codeRequirementFailed
        }
        return VerifiedNativeXPCPeer()
    }
}
