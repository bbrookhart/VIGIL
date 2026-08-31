import Darwin
import Foundation

private let maximumStoredProviderHealthBytes = 32 * 1_024

/// Atomic, owner-controlled transport for short-lived signed provider-health attestations.
/// Publication is a lifecycle/timer operation and must never be called from `handleNewFlow`.
public final class NativeNetworkProviderHealthEnvelopeStore: @unchecked Sendable {
    private let processLock = NSLock()
    private let directoryPath: String
    private let fileName: String

    public init(
        directoryURL: URL,
        fileName: String = "network-provider-health-envelope.v1"
    ) throws {
        guard directoryURL.isFileURL,
              directoryURL.path.utf8.count <= Int(PATH_MAX),
              NativeSecureNetworkFiles.validFileName(fileName)
        else {
            throw NativeNetworkPolicyPersistenceError.invalidLocation
        }
        directoryPath = directoryURL.path
        self.fileName = fileName
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        close(directory)
    }

    public func publish(_ signedEnvelope: Data) throws {
        guard !signedEnvelope.isEmpty,
              signedEnvelope.count <= maximumStoredProviderHealthBytes
        else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        let publicationLock = try NativeSecureNetworkFiles.lock(
            directory: directory,
            name: ".network-provider-health-publication.lock",
            operation: LOCK_EX
        )
        defer { NativeSecureNetworkFiles.unlockAndClose(publicationLock) }
        try NativeSecureNetworkFiles.atomicWrite(
            signedEnvelope,
            directory: directory,
            destination: fileName,
            temporaryPrefix: ".network-provider-health-envelope"
        )
    }

    public func read() throws -> Data {
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        return try NativeSecureNetworkFiles.read(
            directory: directory,
            name: fileName,
            maximumBytes: maximumStoredProviderHealthBytes,
            missing: .healthUnavailable
        )
    }
}

/// Provider-side write path. The caller supplies an isolated signing key and invokes publication
/// outside the flow callback. Key generation/custody is intentionally not hidden in this type.
public final class NativeNetworkProviderHealthPublisher: @unchecked Sendable {
    private let lock = NSLock()
    private let store: NativeNetworkProviderHealthEnvelopeStore
    private let signer: NativeNetworkProviderHealthSigner

    public init(
        store: NativeNetworkProviderHealthEnvelopeStore,
        signer: NativeNetworkProviderHealthSigner
    ) {
        self.store = store
        self.signer = signer
    }

    public func publish(_ reading: NativeNetworkProviderHealthReading) throws {
        lock.lock()
        defer { lock.unlock() }
        try store.publish(signer.sign(reading))
    }
}

/// Containing-app read path. Bytes remain untrusted until the complete signed envelope verifies.
public final class NativeNetworkProviderHealthReader: @unchecked Sendable {
    private let lock = NSLock()
    private let store: NativeNetworkProviderHealthEnvelopeStore
    private let verifier: NativeSignedNetworkProviderHealthVerifier

    public init(
        store: NativeNetworkProviderHealthEnvelopeStore,
        verifier: NativeSignedNetworkProviderHealthVerifier
    ) {
        self.store = store
        self.verifier = verifier
    }

    public func read(nowUnixMilliseconds: Int64) throws -> VerifiedNativeNetworkProviderHealth {
        lock.lock()
        defer { lock.unlock() }
        return try verifier.verify(
            envelopeData: store.read(),
            nowUnixMilliseconds: nowUnixMilliseconds
        )
    }
}
