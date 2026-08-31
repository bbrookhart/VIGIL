import CryptoKit
import Foundation

private let endpointPolicySchema = "vigil.endpoint-policy/v1"
private let signedEnvelopeFormat = "vigil.signed-envelope/v1"
private let signedEnvelopeAlgorithm = "Ed25519"
private let signingDomain = Data("VIGIL_ENDPOINT_POLICY_V1\0".utf8)
private let maximumEnvelopeBytes = 2 * 1_024 * 1_024
private let maximumPayloadBytes = 1_024 * 1_024
private let maximumTrustedKeys = 16
private let maximumSnapshotLifetimeMilliseconds: Int64 = 24 * 60 * 60 * 1_000
private let maximumClockSkewMilliseconds: Int64 = 30_000

public enum NativeSignedPolicyError: Error, Equatable {
    case malformedEnvelope
    case unsupportedEnvelope
    case invalidIdentifier
    case untrustedKey
    case invalidEncoding
    case invalidSignature
    case malformedPayload
    case unsupportedSchema
    case wrongInstance
    case invalidValidityWindow
    case notCurrentlyValid
    case invalidPolicy
}

/// Verifies a daemon-produced snapshot before any policy JSON is decoded.
///
/// The verifier holds public keys only. The caller must provision those keys through a trusted
/// installation channel; accepting a key from the same envelope would make the signature
/// meaningless. Successful output still passes through `NativeFastPathPolicyState` validation
/// before it can be installed in the authorization path.
public struct NativeSignedPolicyVerifier {
    private let expectedInstanceID: String
    private let trustedKeys: [String: Curve25519.Signing.PublicKey]

    public init(expectedInstanceID: String, trustedKeys: [String: Data]) throws {
        guard Self.validIdentifier(expectedInstanceID, maximumBytes: 128),
              trustedKeys.count <= maximumTrustedKeys
        else {
            throw NativeSignedPolicyError.invalidIdentifier
        }
        var compiled: [String: Curve25519.Signing.PublicKey] = [:]
        compiled.reserveCapacity(trustedKeys.count)
        for (keyID, bytes) in trustedKeys {
            guard Self.validIdentifier(keyID, maximumBytes: 64), bytes.count == 32 else {
                throw NativeSignedPolicyError.invalidIdentifier
            }
            do {
                compiled[keyID] = try Curve25519.Signing.PublicKey(rawRepresentation: bytes)
            } catch {
                throw NativeSignedPolicyError.invalidEncoding
            }
        }
        self.expectedInstanceID = expectedInstanceID
        self.trustedKeys = compiled
    }

    public func verify(
        envelopeData: Data,
        nowUnixMilliseconds: Int64
    ) throws -> VerifiedNativeFastPathSnapshot {
        guard !envelopeData.isEmpty, envelopeData.count <= maximumEnvelopeBytes,
              let envelope = Self.strictObject(
                  envelopeData,
                  keys: ["format", "algorithm", "key_id", "payload", "signature"]
              ),
              let format = envelope["format"] as? String,
              let algorithm = envelope["algorithm"] as? String,
              let keyID = envelope["key_id"] as? String,
              let encodedPayload = envelope["payload"] as? String,
              let encodedSignature = envelope["signature"] as? String
        else {
            throw NativeSignedPolicyError.malformedEnvelope
        }
        guard format == signedEnvelopeFormat, algorithm == signedEnvelopeAlgorithm else {
            throw NativeSignedPolicyError.unsupportedEnvelope
        }
        guard Self.validIdentifier(keyID, maximumBytes: 64) else {
            throw NativeSignedPolicyError.invalidIdentifier
        }
        guard let key = trustedKeys[keyID] else {
            throw NativeSignedPolicyError.untrustedKey
        }
        guard encodedPayload.utf8.count <= Self.encodedLengthBound(maximumPayloadBytes),
              encodedSignature.utf8.count <= Self.encodedLengthBound(64),
              let payload = Self.decodeBase64URL(encodedPayload),
              payload.count <= maximumPayloadBytes,
              let signature = Self.decodeBase64URL(encodedSignature),
              signature.count == 64
        else {
            throw NativeSignedPolicyError.invalidEncoding
        }

        var signed = signingDomain
        signed.append(payload)
        guard key.isValidSignature(signature, for: signed) else {
            throw NativeSignedPolicyError.invalidSignature
        }

        // Authentication deliberately precedes all payload parsing.
        try Self.validatePayloadShape(payload)
        let wire: WireSnapshot
        do {
            wire = try JSONDecoder().decode(WireSnapshot.self, from: payload)
        } catch {
            throw NativeSignedPolicyError.malformedPayload
        }
        guard wire.schemaVersion == endpointPolicySchema else {
            throw NativeSignedPolicyError.unsupportedSchema
        }
        guard wire.targetInstanceID == expectedInstanceID else {
            throw NativeSignedPolicyError.wrongInstance
        }
        guard wire.generation > 0,
              wire.issuedAtUnixMilliseconds >= 0,
              wire.expiresAtUnixMilliseconds > wire.issuedAtUnixMilliseconds,
              wire.expiresAtUnixMilliseconds - wire.issuedAtUnixMilliseconds
                  <= maximumSnapshotLifetimeMilliseconds
        else {
            throw NativeSignedPolicyError.invalidValidityWindow
        }
        let latestPermittedIssue = nowUnixMilliseconds.addingReportingOverflow(
            maximumClockSkewMilliseconds
        )
        guard nowUnixMilliseconds >= 0,
              !latestPermittedIssue.overflow,
              wire.issuedAtUnixMilliseconds <= latestPermittedIssue.partialValue,
              wire.expiresAtUnixMilliseconds > nowUnixMilliseconds
        else {
            throw NativeSignedPolicyError.notCurrentlyValid
        }

        do {
            let policies = try wire.sessions.map {
                try NativeSessionEnforcementPolicy(
                    sessionID: $0.sessionID,
                    workspaceRoots: $0.workspaceRoots,
                    allowedExecutables: Set($0.allowedExecutables)
                )
            }
            let snapshot = NativeFastPathSnapshot(
                version: wire.generation,
                expiresAtUnixMilliseconds: wire.expiresAtUnixMilliseconds,
                sessions: policies,
                protectedPrefixes: wire.protectedPrefixes
            )
            // Reuse the exact installation validator instead of maintaining a weaker decoder path.
            _ = try NativeFastPathPolicyState.validate(snapshot)
            return VerifiedNativeFastPathSnapshot(snapshot: snapshot)
        } catch {
            throw NativeSignedPolicyError.invalidPolicy
        }
    }

    private static func validatePayloadShape(_ payload: Data) throws {
        guard let root = strictObject(
            payload,
            keys: [
                "schema_version",
                "target_instance_id",
                "generation",
                "issued_at_unix_ms",
                "expires_at_unix_ms",
                "sessions",
                "protected_prefixes",
            ]
        ), let sessions = root["sessions"] as? [Any]
        else {
            throw NativeSignedPolicyError.malformedPayload
        }
        for session in sessions {
            guard let object = session as? [String: Any],
                  Set(object.keys) == ["session_id", "workspace_roots", "allowed_executables"]
            else {
                throw NativeSignedPolicyError.malformedPayload
            }
        }
    }

    private static func strictObject(
        _ data: Data,
        keys: Set<String>
    ) -> [String: Any]? {
        guard let value = try? JSONSerialization.jsonObject(with: data, options: []) else {
            return nil
        }
        guard let object = value as? [String: Any], Set(object.keys) == keys else {
            return nil
        }
        return object
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({ asciiAlphaNumeric($0) || $0 == 45 || $0 == 95 }),
              value.utf8.count % 4 != 1
        else {
            return nil
        }
        var standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard.append(String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4))
        guard let decoded = Data(base64Encoded: standard), encodeBase64URL(decoded) == value else {
            return nil
        }
        return decoded
    }

    private static func encodeBase64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func validIdentifier(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes && value.utf8.allSatisfy {
            asciiAlphaNumeric($0) || $0 == 46 || $0 == 95 || $0 == 45
        }
    }

    private static func asciiAlphaNumeric(_ byte: UInt8) -> Bool {
        (65 ... 90).contains(byte) || (97 ... 122).contains(byte) || (48 ... 57).contains(byte)
    }

    private static func encodedLengthBound(_ decodedBytes: Int) -> Int {
        ((decodedBytes + 2) / 3) * 4
    }
}

private struct WireSnapshot: Decodable {
    let schemaVersion: String
    let targetInstanceID: String
    let generation: UInt64
    let issuedAtUnixMilliseconds: Int64
    let expiresAtUnixMilliseconds: Int64
    let sessions: [WireSession]
    let protectedPrefixes: [String]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case targetInstanceID = "target_instance_id"
        case generation
        case issuedAtUnixMilliseconds = "issued_at_unix_ms"
        case expiresAtUnixMilliseconds = "expires_at_unix_ms"
        case sessions
        case protectedPrefixes = "protected_prefixes"
    }
}

private struct WireSession: Decodable {
    let sessionID: String
    let workspaceRoots: [String]
    let allowedExecutables: [String]

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case workspaceRoots = "workspace_roots"
        case allowedExecutables = "allowed_executables"
    }
}
