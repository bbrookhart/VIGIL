import CryptoKit
import Foundation

private let providerHealthEnvelopeFormat = "vigil.signed-envelope/v1"
private let providerHealthAlgorithm = "Ed25519"
private let providerHealthSigningDomain = Data("VIGIL_NETWORK_PROVIDER_HEALTH_V1\0".utf8)
private let providerHealthSchema = "vigil.network-provider-health/v1"
private let maximumProviderHealthEnvelopeBytes = 32 * 1_024
private let maximumProviderHealthPayloadBytes = 8 * 1_024
private let maximumProviderHealthClockSkewMilliseconds: Int64 = 30_000
private let maximumProviderHealthAgeMilliseconds: Int64 = 30_000

public enum NativeSignedNetworkProviderHealthError: Error, Equatable {
    case invalidConfiguration
    case malformedEnvelope
    case unsupportedEnvelope
    case untrustedKey
    case invalidEncoding
    case invalidSignature
    case malformedPayload
    case wrongInstance
    case wrongProvider
    case notCurrentlyValid
}

public struct NativeNetworkProviderHealthReading: Codable, Equatable, Sendable {
    let schemaVersion: String
    let targetInstanceID: String
    let providerBundleIdentifier: String
    let policyGeneration: UInt64
    let policyExpiresAtUnixMilliseconds: Int64
    let observedAtUnixMilliseconds: Int64
    let allowedFlows: UInt64
    let droppedFlows: UInt64
    let pausedFlows: UInt64
    let totalFlows: UInt64

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case targetInstanceID = "target_instance_id"
        case providerBundleIdentifier = "provider_bundle_identifier"
        case policyGeneration = "policy_generation"
        case policyExpiresAtUnixMilliseconds = "policy_expires_at_unix_ms"
        case observedAtUnixMilliseconds = "observed_at_unix_ms"
        case allowedFlows = "allowed_flows"
        case droppedFlows = "dropped_flows"
        case pausedFlows = "paused_flows"
        case totalFlows = "total_flows"
    }

    public init(
        targetInstanceID: String,
        providerBundleIdentifier: String,
        policyGeneration: UInt64,
        policyExpiresAtUnixMilliseconds: Int64,
        observedAtUnixMilliseconds: Int64,
        allowedFlows: UInt64,
        droppedFlows: UInt64,
        pausedFlows: UInt64
    ) throws {
        let first = allowedFlows.addingReportingOverflow(droppedFlows)
        let total = first.partialValue.addingReportingOverflow(pausedFlows)
        guard !first.overflow, !total.overflow else {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        schemaVersion = providerHealthSchema
        self.targetInstanceID = targetInstanceID
        self.providerBundleIdentifier = providerBundleIdentifier
        self.policyGeneration = policyGeneration
        self.policyExpiresAtUnixMilliseconds = policyExpiresAtUnixMilliseconds
        self.observedAtUnixMilliseconds = observedAtUnixMilliseconds
        self.allowedFlows = allowedFlows
        self.droppedFlows = droppedFlows
        self.pausedFlows = pausedFlows
        totalFlows = total.partialValue
        try validateStructure()
    }

    fileprivate func validateStructure() throws {
        let first = allowedFlows.addingReportingOverflow(droppedFlows)
        let total = first.partialValue.addingReportingOverflow(pausedFlows)
        guard schemaVersion == providerHealthSchema,
              validIdentifier(targetInstanceID, maximumBytes: 128),
              providerBundleIdentifier.contains("."),
              validIdentifier(providerBundleIdentifier, maximumBytes: 255),
              policyGeneration > 0,
              observedAtUnixMilliseconds >= 0,
              policyExpiresAtUnixMilliseconds > observedAtUnixMilliseconds,
              !first.overflow, !total.overflow, total.partialValue == totalFlows
        else {
            throw NativeSignedNetworkProviderHealthError.malformedPayload
        }
    }
}

public struct VerifiedNativeNetworkProviderHealth: Equatable, Sendable {
    private let reading: NativeNetworkProviderHealthReading

    fileprivate init(reading: NativeNetworkProviderHealthReading) {
        self.reading = reading
    }

    public var policyGeneration: UInt64 { reading.policyGeneration }
    public var policyExpiresAtUnixMilliseconds: Int64 { reading.policyExpiresAtUnixMilliseconds }
    public var observedAtUnixMilliseconds: Int64 { reading.observedAtUnixMilliseconds }
    public var allowedFlows: UInt64 { reading.allowedFlows }
    public var droppedFlows: UInt64 { reading.droppedFlows }
    public var pausedFlows: UInt64 { reading.pausedFlows }
    public var totalFlows: UInt64 { reading.totalFlows }
}

public struct NativeNetworkProviderHealthSigner: Sendable {
    private let keyID: String
    private let privateKey: Curve25519.Signing.PrivateKey

    public init(keyID: String, privateKey: Data) throws {
        guard validIdentifier(keyID, maximumBytes: 64), privateKey.count == 32 else {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        do {
            self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        } catch {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        self.keyID = keyID
    }

    public func sign(_ reading: NativeNetworkProviderHealthReading) throws -> Data {
        try reading.validateStructure()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let payload = try encoder.encode(reading)
        guard payload.count <= maximumProviderHealthPayloadBytes else {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        var signed = providerHealthSigningDomain
        signed.append(payload)
        let envelope = ProviderHealthEnvelope(
            format: providerHealthEnvelopeFormat,
            algorithm: providerHealthAlgorithm,
            keyID: keyID,
            payload: encodeNetworkBase64URL(payload),
            signature: encodeNetworkBase64URL(try privateKey.signature(for: signed))
        )
        let encoded = try encoder.encode(envelope)
        guard encoded.count <= maximumProviderHealthEnvelopeBytes else {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        return encoded
    }
}

public struct NativeSignedNetworkProviderHealthVerifier: Sendable {
    private let expectedInstanceID: String
    private let expectedProviderBundleIdentifier: String
    private let trustedKeys: [String: Curve25519.Signing.PublicKey]

    public init(
        expectedInstanceID: String,
        expectedProviderBundleIdentifier: String,
        trustedKeys: [String: Data]
    ) throws {
        guard validIdentifier(expectedInstanceID, maximumBytes: 128),
              expectedProviderBundleIdentifier.contains("."),
              validIdentifier(expectedProviderBundleIdentifier, maximumBytes: 255),
              !trustedKeys.isEmpty, trustedKeys.count <= 16
        else {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        var compiled: [String: Curve25519.Signing.PublicKey] = [:]
        for (keyID, bytes) in trustedKeys {
            guard validIdentifier(keyID, maximumBytes: 64), bytes.count == 32 else {
                throw NativeSignedNetworkProviderHealthError.invalidConfiguration
            }
            do {
                compiled[keyID] = try Curve25519.Signing.PublicKey(rawRepresentation: bytes)
            } catch {
                throw NativeSignedNetworkProviderHealthError.invalidConfiguration
            }
        }
        self.expectedInstanceID = expectedInstanceID
        self.expectedProviderBundleIdentifier = expectedProviderBundleIdentifier
        self.trustedKeys = compiled
    }

    public func verify(
        envelopeData: Data,
        nowUnixMilliseconds: Int64
    ) throws -> VerifiedNativeNetworkProviderHealth {
        guard !envelopeData.isEmpty, envelopeData.count <= maximumProviderHealthEnvelopeBytes,
              let envelopeObject = strictProviderHealthObject(
                  envelopeData, keys: ["format", "algorithm", "key_id", "payload", "signature"]
              ),
              let format = envelopeObject["format"] as? String,
              let algorithm = envelopeObject["algorithm"] as? String,
              let keyID = envelopeObject["key_id"] as? String,
              let encodedPayload = envelopeObject["payload"] as? String,
              let encodedSignature = envelopeObject["signature"] as? String
        else {
            throw NativeSignedNetworkProviderHealthError.malformedEnvelope
        }
        guard format == providerHealthEnvelopeFormat, algorithm == providerHealthAlgorithm else {
            throw NativeSignedNetworkProviderHealthError.unsupportedEnvelope
        }
        guard let key = trustedKeys[keyID] else {
            throw NativeSignedNetworkProviderHealthError.untrustedKey
        }
        guard encodedPayload.utf8.count <= providerHealthEncodedLengthBound(maximumProviderHealthPayloadBytes),
              encodedSignature.utf8.count <= providerHealthEncodedLengthBound(64),
              let payload = decodeNetworkBase64URL(encodedPayload),
              !payload.isEmpty, payload.count <= maximumProviderHealthPayloadBytes,
              let signature = decodeNetworkBase64URL(encodedSignature), signature.count == 64
        else {
            throw NativeSignedNetworkProviderHealthError.invalidEncoding
        }
        var signed = providerHealthSigningDomain
        signed.append(payload)
        guard key.isValidSignature(signature, for: signed) else {
            throw NativeSignedNetworkProviderHealthError.invalidSignature
        }

        guard strictProviderHealthObject(payload, keys: [
            "schema_version", "target_instance_id", "provider_bundle_identifier",
            "policy_generation", "policy_expires_at_unix_ms", "observed_at_unix_ms",
            "allowed_flows", "dropped_flows", "paused_flows", "total_flows",
        ]) != nil else {
            throw NativeSignedNetworkProviderHealthError.malformedPayload
        }
        let reading: NativeNetworkProviderHealthReading
        do {
            reading = try JSONDecoder().decode(NativeNetworkProviderHealthReading.self, from: payload)
            try reading.validateStructure()
        } catch {
            throw NativeSignedNetworkProviderHealthError.malformedPayload
        }
        guard reading.targetInstanceID == expectedInstanceID else {
            throw NativeSignedNetworkProviderHealthError.wrongInstance
        }
        guard reading.providerBundleIdentifier == expectedProviderBundleIdentifier else {
            throw NativeSignedNetworkProviderHealthError.wrongProvider
        }
        let latestObservation = nowUnixMilliseconds.addingReportingOverflow(
            maximumProviderHealthClockSkewMilliseconds
        )
        let oldestObservation = nowUnixMilliseconds.subtractingReportingOverflow(
            maximumProviderHealthAgeMilliseconds
        )
        guard nowUnixMilliseconds >= 0,
              !latestObservation.overflow, !oldestObservation.overflow,
              reading.observedAtUnixMilliseconds <= latestObservation.partialValue,
              reading.observedAtUnixMilliseconds >= oldestObservation.partialValue,
              reading.policyExpiresAtUnixMilliseconds > nowUnixMilliseconds
        else {
            throw NativeSignedNetworkProviderHealthError.notCurrentlyValid
        }
        return VerifiedNativeNetworkProviderHealth(reading: reading)
    }
}

private struct ProviderHealthEnvelope: Codable {
    let format: String
    let algorithm: String
    let keyID: String
    let payload: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case format
        case algorithm
        case keyID = "key_id"
        case payload
        case signature
    }
}

private func strictProviderHealthObject(_ data: Data, keys: Set<String>) -> [String: Any]? {
    guard let value = try? JSONSerialization.jsonObject(with: data),
          let object = value as? [String: Any], Set(object.keys) == keys
    else {
        return nil
    }
    return object
}

private func providerHealthEncodedLengthBound(_ decodedBytes: Int) -> Int {
    ((decodedBytes + 2) / 3) * 4
}
