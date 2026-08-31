import CryptoKit
import Foundation

private let signedEnvelopeFormat = "vigil.signed-envelope/v1"
private let signedEnvelopeAlgorithm = "Ed25519"
private let signingDomain = Data("VIGIL_NETWORK_POLICY_V1\0".utf8)
private let maximumEnvelopeBytes = 2 * 1_024 * 1_024
private let maximumPayloadBytes = 1_024 * 1_024
private let maximumTrustedKeys = 16
private let maximumClockSkewMilliseconds: Int64 = 30_000

public enum NativeSignedNetworkPolicyError: Error, Equatable {
    case malformedEnvelope
    case unsupportedEnvelope
    case invalidIdentifier
    case untrustedKey
    case invalidEncoding
    case invalidSignature
    case malformedPayload
    case wrongInstance
    case notCurrentlyValid
    case invalidPolicy
}

public struct NativeSignedNetworkPolicyVerifier: Sendable {
    private let expectedInstanceID: String
    private let trustedKeys: [String: Curve25519.Signing.PublicKey]

    public init(expectedInstanceID: String, trustedKeys: [String: Data]) throws {
        guard validIdentifier(expectedInstanceID, maximumBytes: 128),
              trustedKeys.count <= maximumTrustedKeys
        else {
            throw NativeSignedNetworkPolicyError.invalidIdentifier
        }
        var compiled: [String: Curve25519.Signing.PublicKey] = [:]
        for (keyID, bytes) in trustedKeys {
            guard validIdentifier(keyID, maximumBytes: 64), bytes.count == 32 else {
                throw NativeSignedNetworkPolicyError.invalidIdentifier
            }
            do {
                compiled[keyID] = try Curve25519.Signing.PublicKey(rawRepresentation: bytes)
            } catch {
                throw NativeSignedNetworkPolicyError.invalidEncoding
            }
        }
        self.expectedInstanceID = expectedInstanceID
        self.trustedKeys = compiled
    }

    public func verify(
        envelopeData: Data,
        nowUnixMilliseconds: Int64
    ) throws -> VerifiedNativeNetworkSnapshot {
        guard !envelopeData.isEmpty, envelopeData.count <= maximumEnvelopeBytes,
              let envelope = strictObject(
                  envelopeData,
                  keys: ["format", "algorithm", "key_id", "payload", "signature"]
              ),
              let format = envelope["format"] as? String,
              let algorithm = envelope["algorithm"] as? String,
              let keyID = envelope["key_id"] as? String,
              let encodedPayload = envelope["payload"] as? String,
              let encodedSignature = envelope["signature"] as? String
        else {
            throw NativeSignedNetworkPolicyError.malformedEnvelope
        }
        guard format == signedEnvelopeFormat, algorithm == signedEnvelopeAlgorithm else {
            throw NativeSignedNetworkPolicyError.unsupportedEnvelope
        }
        guard validIdentifier(keyID, maximumBytes: 64) else {
            throw NativeSignedNetworkPolicyError.invalidIdentifier
        }
        guard let key = trustedKeys[keyID] else {
            throw NativeSignedNetworkPolicyError.untrustedKey
        }
        guard encodedPayload.utf8.count <= encodedLengthBound(maximumPayloadBytes),
              encodedSignature.utf8.count <= encodedLengthBound(64),
              let payload = decodeBase64URL(encodedPayload), payload.count <= maximumPayloadBytes,
              let signature = decodeBase64URL(encodedSignature), signature.count == 64
        else {
            throw NativeSignedNetworkPolicyError.invalidEncoding
        }
        var signed = signingDomain
        signed.append(payload)
        guard key.isValidSignature(signature, for: signed) else {
            throw NativeSignedNetworkPolicyError.invalidSignature
        }

        // Authentication deliberately precedes all policy JSON parsing.
        try validatePayloadShape(payload)
        let snapshot: NativeNetworkSnapshot
        do {
            snapshot = try JSONDecoder().decode(NativeNetworkSnapshot.self, from: payload)
        } catch {
            throw NativeSignedNetworkPolicyError.malformedPayload
        }
        guard snapshot.targetInstanceID == expectedInstanceID else {
            throw NativeSignedNetworkPolicyError.wrongInstance
        }
        let latestIssue = nowUnixMilliseconds.addingReportingOverflow(maximumClockSkewMilliseconds)
        guard nowUnixMilliseconds >= 0, !latestIssue.overflow,
              snapshot.issuedAtUnixMilliseconds <= latestIssue.partialValue,
              snapshot.expiresAtUnixMilliseconds > nowUnixMilliseconds
        else {
            throw NativeSignedNetworkPolicyError.notCurrentlyValid
        }
        do {
            try snapshot.validate()
        } catch {
            throw NativeSignedNetworkPolicyError.invalidPolicy
        }
        return VerifiedNativeNetworkSnapshot(snapshot: snapshot)
    }
}

private func validatePayloadShape(_ payload: Data) throws {
    guard let root = strictObject(
        payload,
        keys: [
            "schema_version", "target_instance_id", "generation", "issued_at_unix_ms",
            "expires_at_unix_ms", "sessions", "attributions",
        ]
    ), let sessions = root["sessions"] as? [String: Any],
    let attributions = root["attributions"] as? [Any]
    else {
        throw NativeSignedNetworkPolicyError.malformedPayload
    }
    for (_, value) in sessions {
        guard let session = value as? [String: Any],
              Set(session.keys) == [
                  "session_id", "mode", "destinations", "max_total_flows",
                  "max_distinct_destinations",
              ], let destinations = session["destinations"] as? [Any]
        else {
            throw NativeSignedNetworkPolicyError.malformedPayload
        }
        for value in destinations {
            guard let rule = value as? [String: Any],
                  Set(rule.keys) == [
                      "hostname", "protocol", "ports", "resolved_addresses",
                      "valid_until_unix_ms",
                  ]
            else {
                throw NativeSignedNetworkPolicyError.malformedPayload
            }
        }
    }
    for value in attributions {
        guard let attribution = value as? [String: Any],
              Set(attribution.keys) == ["process", "session_id"]
        else {
            throw NativeSignedNetworkPolicyError.malformedPayload
        }
    }
}

private func strictObject(_ data: Data, keys: Set<String>) -> [String: Any]? {
    guard let value = try? JSONSerialization.jsonObject(with: data),
          let object = value as? [String: Any], Set(object.keys) == keys
    else { return nil }
    return object
}

private func decodeBase64URL(_ value: String) -> Data? {
    guard !value.isEmpty,
          value.utf8.allSatisfy({ asciiAlphaNumeric($0) || $0 == 45 || $0 == 95 }),
          value.utf8.count % 4 != 1
    else { return nil }
    var standard = value.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    standard.append(String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4))
    guard let decoded = Data(base64Encoded: standard), encodeBase64URL(decoded) == value else {
        return nil
    }
    return decoded
}

private func encodeBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func encodedLengthBound(_ decodedBytes: Int) -> Int {
    ((decodedBytes + 2) / 3) * 4
}
