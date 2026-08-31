import CryptoKit
import Foundation

private let bootstrapPolicyEnvelopeFormat = "vigil.signed-envelope/v1"
private let bootstrapPolicyEnvelopeAlgorithm = "Ed25519"
private let bootstrapPolicySigningDomain = Data("VIGIL_NETWORK_POLICY_V1\0".utf8)
private let maximumBootstrapPolicyLeaseMilliseconds: Int64 = 24 * 60 * 60 * 1_000
private let minimumReusablePolicyLeaseMilliseconds: Int64 = 5 * 60 * 1_000

public enum NativeNetworkPolicySigningError: Error, Equatable {
    case invalidConfiguration
    case keyUnavailable
    case corruptKey
    case generationExhausted
}

public struct NativeNetworkPolicySigningIdentity: Sendable {
    public let keyID: String
    public let publicKey: Data
    fileprivate let privateKey: Curve25519.Signing.PrivateKey
}

public struct NativeNetworkPolicyProvisioningResult: Equatable, Sendable {
    public let generation: UInt64
    public let publishedNewPolicy: Bool
    public let keyID: String
    public let publicKey: Data
}

/// Containing-app-only policy-signing key custody. The provider receives only this identity's
/// public key through its exact vendor configuration.
public final class NativeNetworkPolicySigningKeyStore: @unchecked Sendable {
    private let lock = NSLock()
    private let service: String
    private let account: String
    private let keychain: any NativeNetworkProviderHealthKeychain

    public convenience init(service: String, account: String) throws {
        try self.init(service: service, account: account, keychain: SystemProviderHealthKeychain())
    }

    init(
        service: String,
        account: String,
        keychain: any NativeNetworkProviderHealthKeychain
    ) throws {
        guard validIdentifier(service, maximumBytes: 255),
              validIdentifier(account, maximumBytes: 128)
        else {
            throw NativeNetworkPolicySigningError.invalidConfiguration
        }
        self.service = service
        self.account = account
        self.keychain = keychain
    }

    public func loadOrCreate() throws -> NativeNetworkPolicySigningIdentity {
        try lock.withLock {
            if let existing = try keychain.read(service: service, account: account) {
                return try identity(from: existing)
            }
            let generated = Curve25519.Signing.PrivateKey()
            switch try keychain.insert(
                generated.rawRepresentation,
                service: service,
                account: account
            ) {
            case .inserted:
                return makeIdentity(generated)
            case .duplicate:
                guard let winner = try keychain.read(service: service, account: account) else {
                    throw NativeNetworkPolicySigningError.keyUnavailable
                }
                return try identity(from: winner)
            }
        }
    }

    private func identity(from bytes: Data) throws -> NativeNetworkPolicySigningIdentity {
        guard bytes.count == 32,
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: bytes)
        else {
            throw NativeNetworkPolicySigningError.corruptKey
        }
        return makeIdentity(key)
    }

    private func makeIdentity(
        _ key: Curve25519.Signing.PrivateKey
    ) -> NativeNetworkPolicySigningIdentity {
        let publicKey = key.publicKey.rawRepresentation
        let digest = SHA256.hash(data: publicKey)
        let fingerprint = digest.prefix(16).map { String(format: "%02x", $0) }.joined()
        return NativeNetworkPolicySigningIdentity(
            keyID: "network-policy-\(fingerprint)",
            publicKey: publicKey,
            privateKey: key
        )
    }
}

/// Publishes a signed empty-session policy before filter preferences are enabled. Empty sessions
/// grant no managed process authority; they establish only a live provider bootstrap generation.
public final class NativeNetworkBootstrapPolicyProvisioner: @unchecked Sendable {
    private let lock = NSLock()
    private let targetInstanceID: String
    private let identity: NativeNetworkPolicySigningIdentity
    private let envelopeStore: NativeNetworkPolicyEnvelopeStore
    private let generationStore: NativeFileNetworkGenerationStore

    public init(
        directoryURL: URL,
        targetInstanceID: String,
        identity: NativeNetworkPolicySigningIdentity
    ) throws {
        guard validIdentifier(targetInstanceID, maximumBytes: 128) else {
            throw NativeNetworkPolicySigningError.invalidConfiguration
        }
        self.targetInstanceID = targetInstanceID
        self.identity = identity
        envelopeStore = try NativeNetworkPolicyEnvelopeStore(directoryURL: directoryURL)
        generationStore = try NativeFileNetworkGenerationStore(directoryURL: directoryURL)
    }

    public func prepare(
        nowUnixMilliseconds: Int64,
        leaseMilliseconds: Int64 = 60 * 60 * 1_000
    ) throws -> NativeNetworkPolicyProvisioningResult {
        try lock.withLock {
            guard nowUnixMilliseconds >= 0,
                  (1 ... maximumBootstrapPolicyLeaseMilliseconds).contains(leaseMilliseconds)
            else {
                throw NativeNetworkPolicySigningError.invalidConfiguration
            }
            let verifier = try NativeSignedNetworkPolicyVerifier(
                expectedInstanceID: targetInstanceID,
                trustedKeys: [identity.keyID: identity.publicKey]
            )
            let current = try generationStore.currentRecord()
            let reuseThreshold = nowUnixMilliseconds.addingReportingOverflow(
                minimumReusablePolicyLeaseMilliseconds
            )
            if let current, !reuseThreshold.overflow,
               let envelope = try? envelopeStore.read(),
               let verified = try? verifier.verify(
                   envelopeData: envelope,
                   nowUnixMilliseconds: nowUnixMilliseconds
               ), verified.generation == current.generation,
               Data(SHA256.hash(data: envelope)) == current.envelopeSHA256,
               verified.expiresAtUnixMilliseconds > reuseThreshold.partialValue
            {
                return result(generation: current.generation, published: false)
            }
            let generation: UInt64
            if let current {
                guard current.generation < .max else {
                    throw NativeNetworkPolicySigningError.generationExhausted
                }
                generation = current.generation + 1
            } else {
                generation = 1
            }
            let expiry = nowUnixMilliseconds.addingReportingOverflow(leaseMilliseconds)
            guard !expiry.overflow else {
                throw NativeNetworkPolicySigningError.invalidConfiguration
            }
            let snapshot = NativeNetworkSnapshot(
                schemaVersion: "vigil.network-policy/v1",
                targetInstanceID: targetInstanceID,
                generation: generation,
                issuedAtUnixMilliseconds: nowUnixMilliseconds,
                expiresAtUnixMilliseconds: expiry.partialValue,
                sessions: [:],
                attributions: []
            )
            try snapshot.validate()
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let payload = try encoder.encode(snapshot)
            var signed = bootstrapPolicySigningDomain
            signed.append(payload)
            let envelope = try encoder.encode(BootstrapPolicyEnvelope(
                format: bootstrapPolicyEnvelopeFormat,
                algorithm: bootstrapPolicyEnvelopeAlgorithm,
                keyID: identity.keyID,
                payload: encodeNetworkBase64URL(payload),
                signature: encodeNetworkBase64URL(try identity.privateKey.signature(for: signed))
            ))
            let publisher = NativeNetworkPolicyPublisher(
                envelopeStore: envelopeStore,
                generationStore: generationStore,
                verifier: verifier
            )
            _ = try publisher.publish(
                envelope,
                nowUnixMilliseconds: nowUnixMilliseconds
            )
            return result(generation: generation, published: true)
        }
    }

    private func result(
        generation: UInt64,
        published: Bool
    ) -> NativeNetworkPolicyProvisioningResult {
        NativeNetworkPolicyProvisioningResult(
            generation: generation,
            publishedNewPolicy: published,
            keyID: identity.keyID,
            publicKey: identity.publicKey
        )
    }
}

private struct BootstrapPolicyEnvelope: Codable {
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
