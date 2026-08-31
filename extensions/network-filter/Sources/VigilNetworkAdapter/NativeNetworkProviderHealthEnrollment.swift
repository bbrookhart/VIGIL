import Darwin
import Foundation

private let providerHealthEnrollmentSchema = "vigil.network-provider-health-enrollment/v1"
private let maximumProviderHealthEnrollmentBytes = 4 * 1_024

public enum NativeNetworkProviderHealthEnrollmentError: Error, Equatable {
    case invalidConfiguration
    case enrollmentUnavailable
    case malformedEnrollment
    case identityChanged
    case trustStoreUnavailable
    case corruptTrustStore
}

public struct NativeNetworkProviderHealthEnrollmentCandidate: Equatable, Sendable {
    public let targetInstanceID: String
    public let providerBundleIdentifier: String
    public let keyID: String
    public let publicKey: Data
}

/// An enrollment candidate becomes verified only after its key authenticates a fresh, correctly
/// bound provider-health envelope. Construction is intentionally private to the verifier.
public struct VerifiedNativeNetworkProviderHealthEnrollment: Sendable {
    fileprivate let candidate: NativeNetworkProviderHealthEnrollmentCandidate
    public let providerHealth: VerifiedNativeNetworkProviderHealth

    public var keyID: String { candidate.keyID }
    public var publicKey: Data { candidate.publicKey }
    public var targetInstanceID: String { candidate.targetInstanceID }
    public var providerBundleIdentifier: String { candidate.providerBundleIdentifier }
}

public enum NativeNetworkProviderHealthPinResult: Equatable, Sendable {
    case enrolled(keyID: String)
    case alreadyPinned(keyID: String)
}

/// Provider-write/host-read transport for untrusted public enrollment identity. The same hardened
/// file primitives as policy and health transport prevent partial, oversized, or symlinked reads.
public final class NativeNetworkProviderHealthEnrollmentStore: @unchecked Sendable {
    private let processLock = NSLock()
    private let directoryPath: String
    private let fileName: String

    public init(
        directoryURL: URL,
        fileName: String = "network-provider-health-enrollment.v1"
    ) throws {
        guard directoryURL.isFileURL,
              directoryURL.path.utf8.count <= Int(PATH_MAX),
              NativeSecureNetworkFiles.validFileName(fileName)
        else {
            throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
        }
        directoryPath = directoryURL.path
        self.fileName = fileName
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        close(directory)
    }

    public func publish(
        identity: NativeNetworkProviderHealthSigningIdentity,
        targetInstanceID: String,
        providerBundleIdentifier: String
    ) throws {
        let candidate = NativeNetworkProviderHealthEnrollmentCandidate(
            targetInstanceID: targetInstanceID,
            providerBundleIdentifier: providerBundleIdentifier,
            keyID: identity.keyID,
            publicKey: identity.publicKey
        )
        try validate(candidate)
        let record = ProviderHealthEnrollmentRecord(
            schemaVersion: providerHealthEnrollmentSchema,
            targetInstanceID: targetInstanceID,
            providerBundleIdentifier: providerBundleIdentifier,
            keyID: identity.keyID,
            publicKey: encodeNetworkBase64URL(identity.publicKey)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(record)
        guard !bytes.isEmpty, bytes.count <= maximumProviderHealthEnrollmentBytes else {
            throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
        }
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        let publicationLock = try NativeSecureNetworkFiles.lock(
            directory: directory,
            name: ".network-provider-health-enrollment.lock",
            operation: LOCK_EX
        )
        defer { NativeSecureNetworkFiles.unlockAndClose(publicationLock) }
        try NativeSecureNetworkFiles.atomicWrite(
            bytes,
            directory: directory,
            destination: fileName,
            temporaryPrefix: ".network-provider-health-enrollment"
        )
    }

    public func read(
        expectedInstanceID: String,
        expectedProviderBundleIdentifier: String
    ) throws -> NativeNetworkProviderHealthEnrollmentCandidate {
        guard validIdentifier(expectedInstanceID, maximumBytes: 128),
              expectedProviderBundleIdentifier.contains("."),
              validIdentifier(expectedProviderBundleIdentifier, maximumBytes: 255)
        else {
            throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
        }
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        let bytes: Data
        do {
            bytes = try NativeSecureNetworkFiles.read(
                directory: directory,
                name: fileName,
                maximumBytes: maximumProviderHealthEnrollmentBytes,
                missing: .healthUnavailable
            )
        } catch NativeNetworkPolicyPersistenceError.healthUnavailable {
            throw NativeNetworkProviderHealthEnrollmentError.enrollmentUnavailable
        }
        guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == [
                  "schema_version", "target_instance_id", "provider_bundle_identifier",
                  "key_id", "public_key",
              ],
              let record = try? JSONDecoder().decode(ProviderHealthEnrollmentRecord.self, from: bytes),
              record.schemaVersion == providerHealthEnrollmentSchema,
              let publicKey = decodeNetworkBase64URL(record.publicKey), publicKey.count == 32
        else {
            throw NativeNetworkProviderHealthEnrollmentError.malformedEnrollment
        }
        let candidate = NativeNetworkProviderHealthEnrollmentCandidate(
            targetInstanceID: record.targetInstanceID,
            providerBundleIdentifier: record.providerBundleIdentifier,
            keyID: record.keyID,
            publicKey: publicKey
        )
        do { try validate(candidate) } catch {
            throw NativeNetworkProviderHealthEnrollmentError.malformedEnrollment
        }
        guard candidate.targetInstanceID == expectedInstanceID,
              candidate.providerBundleIdentifier == expectedProviderBundleIdentifier
        else {
            throw NativeNetworkProviderHealthEnrollmentError.malformedEnrollment
        }
        return candidate
    }
}

/// Converts an untrusted public identity into a verified enrollment proof only when that identity
/// authenticates the current short-lived health envelope for the same installation and provider.
public final class NativeNetworkProviderHealthEnrollmentVerifier: @unchecked Sendable {
    private let enrollmentStore: NativeNetworkProviderHealthEnrollmentStore
    private let healthStore: NativeNetworkProviderHealthEnvelopeStore
    private let expectedInstanceID: String
    private let expectedProviderBundleIdentifier: String

    public init(
        enrollmentStore: NativeNetworkProviderHealthEnrollmentStore,
        healthStore: NativeNetworkProviderHealthEnvelopeStore,
        expectedInstanceID: String,
        expectedProviderBundleIdentifier: String
    ) throws {
        guard validIdentifier(expectedInstanceID, maximumBytes: 128),
              expectedProviderBundleIdentifier.contains("."),
              validIdentifier(expectedProviderBundleIdentifier, maximumBytes: 255)
        else {
            throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
        }
        self.enrollmentStore = enrollmentStore
        self.healthStore = healthStore
        self.expectedInstanceID = expectedInstanceID
        self.expectedProviderBundleIdentifier = expectedProviderBundleIdentifier
    }

    public func verify(
        nowUnixMilliseconds: Int64
    ) throws -> VerifiedNativeNetworkProviderHealthEnrollment {
        let candidate = try enrollmentStore.read(
            expectedInstanceID: expectedInstanceID,
            expectedProviderBundleIdentifier: expectedProviderBundleIdentifier
        )
        let verifier = try NativeSignedNetworkProviderHealthVerifier(
            expectedInstanceID: expectedInstanceID,
            expectedProviderBundleIdentifier: expectedProviderBundleIdentifier,
            trustedKeys: [candidate.keyID: candidate.publicKey]
        )
        let health = try NativeNetworkProviderHealthReader(
            store: healthStore,
            verifier: verifier
        ).read(nowUnixMilliseconds: nowUnixMilliseconds)
        return VerifiedNativeNetworkProviderHealthEnrollment(
            candidate: candidate,
            providerHealth: health
        )
    }
}

/// Host-side immutable public-key pin. Public keys are not secret, but the first accepted identity
/// must survive restart and must never rotate merely because shared-container bytes changed.
public final class NativeNetworkProviderHealthTrustStore: @unchecked Sendable {
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
            throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
        }
        self.service = service
        self.account = account
        self.keychain = keychain
    }

    public func pin(
        _ verified: VerifiedNativeNetworkProviderHealthEnrollment
    ) throws -> NativeNetworkProviderHealthPinResult {
        try lock.withLock {
            let encoded = try encodePin(verified.candidate)
            if let existing = try keychain.read(service: service, account: account) {
                let pinned = try decodePin(existing)
                guard pinned == verified.candidate else {
                    throw NativeNetworkProviderHealthEnrollmentError.identityChanged
                }
                return .alreadyPinned(keyID: pinned.keyID)
            }
            switch try keychain.insert(encoded, service: service, account: account) {
            case .inserted:
                return .enrolled(keyID: verified.keyID)
            case .duplicate:
                guard let existing = try keychain.read(service: service, account: account) else {
                    throw NativeNetworkProviderHealthEnrollmentError.trustStoreUnavailable
                }
                let pinned = try decodePin(existing)
                guard pinned == verified.candidate else {
                    throw NativeNetworkProviderHealthEnrollmentError.identityChanged
                }
                return .alreadyPinned(keyID: pinned.keyID)
            }
        }
    }

    private func encodePin(_ candidate: NativeNetworkProviderHealthEnrollmentCandidate) throws -> Data {
        let record = ProviderHealthEnrollmentRecord(
            schemaVersion: providerHealthEnrollmentSchema,
            targetInstanceID: candidate.targetInstanceID,
            providerBundleIdentifier: candidate.providerBundleIdentifier,
            keyID: candidate.keyID,
            publicKey: encodeNetworkBase64URL(candidate.publicKey)
        )
        return try JSONEncoder().encode(record)
    }

    private func decodePin(_ bytes: Data) throws -> NativeNetworkProviderHealthEnrollmentCandidate {
        guard bytes.count <= maximumProviderHealthEnrollmentBytes,
              let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == [
                  "schema_version", "target_instance_id", "provider_bundle_identifier",
                  "key_id", "public_key",
              ],
              let record = try? JSONDecoder().decode(ProviderHealthEnrollmentRecord.self, from: bytes),
              record.schemaVersion == providerHealthEnrollmentSchema,
              let key = decodeNetworkBase64URL(record.publicKey), key.count == 32
        else {
            throw NativeNetworkProviderHealthEnrollmentError.corruptTrustStore
        }
        let candidate = NativeNetworkProviderHealthEnrollmentCandidate(
            targetInstanceID: record.targetInstanceID,
            providerBundleIdentifier: record.providerBundleIdentifier,
            keyID: record.keyID,
            publicKey: key
        )
        do { try validate(candidate) } catch {
            throw NativeNetworkProviderHealthEnrollmentError.corruptTrustStore
        }
        return candidate
    }
}

private struct ProviderHealthEnrollmentRecord: Codable {
    let schemaVersion: String
    let targetInstanceID: String
    let providerBundleIdentifier: String
    let keyID: String
    let publicKey: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case targetInstanceID = "target_instance_id"
        case providerBundleIdentifier = "provider_bundle_identifier"
        case keyID = "key_id"
        case publicKey = "public_key"
    }
}

private func validate(_ candidate: NativeNetworkProviderHealthEnrollmentCandidate) throws {
    guard validIdentifier(candidate.targetInstanceID, maximumBytes: 128),
          candidate.providerBundleIdentifier.contains("."),
          validIdentifier(candidate.providerBundleIdentifier, maximumBytes: 255),
          validIdentifier(candidate.keyID, maximumBytes: 64),
          candidate.publicKey.count == 32
    else {
        throw NativeNetworkProviderHealthEnrollmentError.invalidConfiguration
    }
}
