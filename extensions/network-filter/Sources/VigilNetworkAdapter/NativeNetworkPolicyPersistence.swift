import CryptoKit
import Darwin
import Foundation

private let maximumStoredEnvelopeBytes = 2 * 1_024 * 1_024
private let maximumGenerationRecordBytes = 160
private let generationRecordHeader = "vigil.network-generation/v1\n"

public enum NativeNetworkPolicyPersistenceError: Error, Equatable {
    case invalidLocation
    case insecureDirectory
    case policyUnavailable
    case corruptState
    case rollback(current: UInt64, proposed: UInt64)
    case generationEquivocation
    case ioFailure
}

/// The durable replay floor for a network policy. The digest permits one exact current envelope
/// to be restored after restart without permitting a different envelope at the same generation.
public struct NativeNetworkGenerationRecord: Equatable, Sendable {
    public let generation: UInt64
    public let envelopeSHA256: Data

    public init(generation: UInt64, envelopeSHA256: Data) throws {
        guard generation > 0, envelopeSHA256.count == SHA256.byteCount else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        self.generation = generation
        self.envelopeSHA256 = envelopeSHA256
    }
}

public protocol NativeNetworkGenerationStore: Sendable {
    func currentRecord() throws -> NativeNetworkGenerationRecord?
    func commit(_ record: NativeNetworkGenerationRecord) throws
}

/// Atomic policy-envelope transport for a protected shared container.
///
/// Publication uses a same-directory owner-only temporary file, file fsync, atomic rename, and
/// directory fsync. Reads never follow symlinks and accept only an owner-controlled regular file.
/// Signature verification remains the consumer's responsibility.
public final class NativeNetworkPolicyEnvelopeStore: @unchecked Sendable {
    private let processLock = NSLock()
    private let directoryPath: String
    private let fileName: String

    public init(
        directoryURL: URL,
        fileName: String = "network-policy-envelope.v1"
    ) throws {
        guard directoryURL.isFileURL,
              directoryURL.path.utf8.count <= Int(PATH_MAX),
              NativeSecureNetworkFiles.validFileName(fileName)
        else {
            throw NativeNetworkPolicyPersistenceError.invalidLocation
        }
        directoryPath = directoryURL.path
        self.fileName = fileName
        let descriptor = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        close(descriptor)
    }

    public func publish(_ envelope: Data) throws {
        guard !envelope.isEmpty, envelope.count <= maximumStoredEnvelopeBytes else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        try withExclusivePublication {
            try publishWhileLocked(envelope)
        }
    }

    /// Serializes the complete publisher transaction across processes. The trusted write side
    /// owns this lock; provider-side reads remain strictly read-only.
    func withExclusivePublication<T>(_ body: () throws -> T) throws -> T {
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        let lock = try NativeSecureNetworkFiles.lock(
            directory: directory, name: ".network-policy-publication.lock", operation: LOCK_EX
        )
        defer { NativeSecureNetworkFiles.unlockAndClose(lock) }
        return try body()
    }

    func publishWhileLocked(_ envelope: Data) throws {
        guard !envelope.isEmpty, envelope.count <= maximumStoredEnvelopeBytes else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        try NativeSecureNetworkFiles.atomicWrite(
            envelope,
            directory: directory,
            destination: fileName,
            temporaryPrefix: ".network-policy-envelope"
        )
    }

    public func read() throws -> Data {
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        // The filter data provider has read-only App Group access. Atomic rename makes one file
        // read coherent without creating or locking anything from the provider process.
        return try NativeSecureNetworkFiles.read(
            directory: directory,
            name: fileName,
            maximumBytes: maximumStoredEnvelopeBytes,
            missing: .policyUnavailable
        )
    }
}

/// Durable generation and envelope-identity storage for restart-safe replay prevention.
public final class NativeFileNetworkGenerationStore: NativeNetworkGenerationStore, @unchecked Sendable {
    private let processLock = NSLock()
    private let directoryPath: String
    private let fileName: String

    public init(
        directoryURL: URL,
        fileName: String = "network-generation.v1"
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
        defer { close(directory) }
        _ = try Self.readRecord(directory: directory, fileName: fileName)
    }

    public func currentRecord() throws -> NativeNetworkGenerationRecord? {
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        return try Self.readRecord(directory: directory, fileName: fileName)
    }

    public func commit(_ proposed: NativeNetworkGenerationRecord) throws {
        processLock.lock()
        defer { processLock.unlock() }
        let directory = try NativeSecureNetworkFiles.openDirectory(directoryPath)
        defer { close(directory) }
        let lock = try NativeSecureNetworkFiles.lock(
            directory: directory, name: ".network-generation.lock", operation: LOCK_EX
        )
        defer { NativeSecureNetworkFiles.unlockAndClose(lock) }
        if let current = try Self.readRecord(directory: directory, fileName: fileName),
           proposed.generation <= current.generation
        {
            throw NativeNetworkPolicyPersistenceError.rollback(
                current: current.generation, proposed: proposed.generation
            )
        }
        try NativeSecureNetworkFiles.atomicWrite(
            Self.encode(proposed),
            directory: directory,
            destination: fileName,
            temporaryPrefix: ".network-generation"
        )
    }

    private static func encode(_ record: NativeNetworkGenerationRecord) -> Data {
        let digest = record.envelopeSHA256.map { String(format: "%02x", $0) }.joined()
        return Data("\(generationRecordHeader)\(record.generation)\nsha256:\(digest)\n".utf8)
    }

    private static func readRecord(
        directory: Int32,
        fileName: String
    ) throws -> NativeNetworkGenerationRecord? {
        let descriptor = openat(directory, fileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0, errno == ENOENT {
            return nil
        }
        guard descriptor >= 0 else {
            throw errno == ELOOP
                ? NativeNetworkPolicyPersistenceError.corruptState
                : NativeNetworkPolicyPersistenceError.ioFailure
        }
        defer { close(descriptor) }
        let data = try NativeSecureNetworkFiles.read(
            descriptor: descriptor, maximumBytes: maximumGenerationRecordBytes
        )
        guard let text = String(data: data, encoding: .utf8), text.hasPrefix(generationRecordHeader) else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        let fields = text.dropFirst(generationRecordHeader.count).split(
            separator: "\n", omittingEmptySubsequences: false
        )
        guard fields.count == 3, fields[2].isEmpty,
              let generation = parseGeneration(String(fields[0])),
              fields[1].hasPrefix("sha256:")
        else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        let digestText = fields[1].dropFirst("sha256:".count)
        guard digestText.count == SHA256.byteCount * 2,
              digestText.utf8.allSatisfy({ (48 ... 57).contains($0) || (97 ... 102).contains($0) })
        else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        var digest = Data(capacity: SHA256.byteCount)
        var index = digestText.startIndex
        for _ in 0 ..< SHA256.byteCount {
            let next = digestText.index(index, offsetBy: 2)
            guard let byte = UInt8(digestText[index ..< next], radix: 16) else {
                throw NativeNetworkPolicyPersistenceError.corruptState
            }
            digest.append(byte)
            index = next
        }
        return try NativeNetworkGenerationRecord(generation: generation, envelopeSHA256: digest)
    }

    private static func parseGeneration(_ value: String) -> UInt64? {
        guard !value.isEmpty, value.count <= 20, value != "0",
              !(value.count > 1 && value.first == "0"),
              value.utf8.allSatisfy({ (48 ... 57).contains($0) })
        else { return nil }
        return UInt64(value)
    }
}

public enum NativeNetworkPolicyReloadResult: Equatable, Sendable {
    case installed(generation: UInt64)
    case unchanged(generation: UInt64)
}

/// Write-side transport owned by the trusted containing application or daemon.
///
/// The envelope is renamed first and the matching replay record second. A reader seeing the
/// intentional gap rejects the pair; a crash in the gap makes policy unavailable rather than
/// rolling authority back. Republishing the same exact generation completes the interrupted
/// transaction idempotently.
public final class NativeNetworkPolicyPublisher: @unchecked Sendable {
    private let lock = NSLock()
    private let envelopeStore: NativeNetworkPolicyEnvelopeStore
    private let generationStore: any NativeNetworkGenerationStore
    private let verifier: NativeSignedNetworkPolicyVerifier

    public init(
        envelopeStore: NativeNetworkPolicyEnvelopeStore,
        generationStore: any NativeNetworkGenerationStore,
        verifier: NativeSignedNetworkPolicyVerifier
    ) {
        self.envelopeStore = envelopeStore
        self.generationStore = generationStore
        self.verifier = verifier
    }

    @discardableResult
    public func publish(
        _ envelope: Data, nowUnixMilliseconds: Int64
    ) throws -> NativeNetworkPolicyReloadResult {
        lock.lock()
        defer { lock.unlock() }
        return try envelopeStore.withExclusivePublication {
            let verified = try verifier.verify(
                envelopeData: envelope, nowUnixMilliseconds: nowUnixMilliseconds
            )
            let record = try NativeNetworkGenerationRecord(
                generation: verified.generation,
                envelopeSHA256: Data(SHA256.hash(data: envelope))
            )
            if let current = try generationStore.currentRecord() {
                guard record.generation >= current.generation else {
                    throw NativeNetworkPolicyPersistenceError.rollback(
                        current: current.generation, proposed: record.generation
                    )
                }
                if record.generation == current.generation {
                    guard record.envelopeSHA256 == current.envelopeSHA256 else {
                        throw NativeNetworkPolicyPersistenceError.generationEquivocation
                    }
                    try envelopeStore.publishWhileLocked(envelope)
                    return .unchanged(generation: record.generation)
                }
            }
            try envelopeStore.publishWhileLocked(envelope)
            try generationStore.commit(record)
            return .installed(generation: record.generation)
        }
    }
}

/// Read-only provider-side loader. It does no work in `handleNewFlow` and writes nothing to the
/// filter data provider's restricted App Group view.
public final class NativeNetworkPolicyCoordinator: @unchecked Sendable {
    private let lock = NSLock()
    private let envelopeStore: NativeNetworkPolicyEnvelopeStore
    private let generationStore: any NativeNetworkGenerationStore
    private let verifier: NativeSignedNetworkPolicyVerifier
    private let state: NativeNetworkPolicyState

    public init(
        envelopeStore: NativeNetworkPolicyEnvelopeStore,
        generationStore: any NativeNetworkGenerationStore,
        verifier: NativeSignedNetworkPolicyVerifier,
        state: NativeNetworkPolicyState
    ) {
        self.envelopeStore = envelopeStore
        self.generationStore = generationStore
        self.verifier = verifier
        self.state = state
    }

    @discardableResult
    public func reload(nowUnixMilliseconds: Int64) throws -> NativeNetworkPolicyReloadResult {
        lock.lock()
        defer { lock.unlock() }
        guard let durableBefore = try generationStore.currentRecord() else {
            throw NativeNetworkPolicyPersistenceError.policyUnavailable
        }
        let envelope = try envelopeStore.read()
        guard let durableAfter = try generationStore.currentRecord(), durableBefore == durableAfter
        else {
            throw NativeNetworkPolicyPersistenceError.generationEquivocation
        }
        let verified = try verifier.verify(
            envelopeData: envelope, nowUnixMilliseconds: nowUnixMilliseconds
        )
        let record = try NativeNetworkGenerationRecord(
            generation: verified.generation,
            envelopeSHA256: Data(SHA256.hash(data: envelope))
        )
        guard record.generation == durableAfter.generation else {
            throw NativeNetworkPolicyPersistenceError.rollback(
                current: durableAfter.generation, proposed: record.generation
            )
        }
        guard record.envelopeSHA256 == durableAfter.envelopeSHA256 else {
            throw NativeNetworkPolicyPersistenceError.generationEquivocation
        }
        if let active = state.generation {
            guard record.generation >= active else {
                throw NativeNetworkPolicyPersistenceError.rollback(
                    current: active, proposed: record.generation
                )
            }
            if record.generation == active {
                return .unchanged(generation: active)
            }
        }
        try state.install(verified)
        return .installed(generation: record.generation)
    }
}

private enum NativeSecureNetworkFiles {
    static func openDirectory(_ path: String) throws -> Int32 {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw NativeNetworkPolicyPersistenceError.invalidLocation
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            close(descriptor)
            throw NativeNetworkPolicyPersistenceError.ioFailure
        }
        guard status.st_uid == geteuid(), status.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0 else {
            close(descriptor)
            throw NativeNetworkPolicyPersistenceError.insecureDirectory
        }
        return descriptor
    }

    static func lock(directory: Int32, name: String, operation: Int32) throws -> Int32 {
        let descriptor = openat(
            directory, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard descriptor >= 0 else {
            throw NativeNetworkPolicyPersistenceError.ioFailure
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              status.st_mode & mode_t(S_IRWXG | S_IRWXO) == 0,
              fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0
        else {
            close(descriptor)
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        while flock(descriptor, operation) != 0 {
            guard errno == EINTR else {
                close(descriptor)
                throw NativeNetworkPolicyPersistenceError.ioFailure
            }
        }
        return descriptor
    }

    static func unlockAndClose(_ descriptor: Int32) {
        _ = flock(descriptor, LOCK_UN)
        close(descriptor)
    }

    static func atomicWrite(
        _ data: Data,
        directory: Int32,
        destination: String,
        temporaryPrefix: String
    ) throws {
        let temporary = "\(temporaryPrefix)-\(UUID().uuidString).tmp"
        let descriptor = openat(
            directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard descriptor >= 0 else {
            throw NativeNetworkPolicyPersistenceError.ioFailure
        }
        var renamed = false
        defer {
            close(descriptor)
            if !renamed { _ = unlinkat(directory, temporary, 0) }
        }
        guard fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw NativeNetworkPolicyPersistenceError.ioFailure
        }
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                throw NativeNetworkPolicyPersistenceError.ioFailure
            }
            var offset = 0
            while offset < rawBuffer.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw NativeNetworkPolicyPersistenceError.ioFailure }
                offset += count
            }
        }
        guard fsync(descriptor) == 0,
              renameat(directory, temporary, directory, destination) == 0
        else {
            throw NativeNetworkPolicyPersistenceError.ioFailure
        }
        renamed = true
        guard fsync(directory) == 0 else {
            throw NativeNetworkPolicyPersistenceError.ioFailure
        }
    }

    static func read(
        directory: Int32,
        name: String,
        maximumBytes: Int,
        missing: NativeNetworkPolicyPersistenceError
    ) throws -> Data {
        let descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0, errno == ENOENT { throw missing }
        guard descriptor >= 0 else {
            throw errno == ELOOP
                ? NativeNetworkPolicyPersistenceError.corruptState
                : NativeNetworkPolicyPersistenceError.ioFailure
        }
        defer { close(descriptor) }
        return try read(descriptor: descriptor, maximumBytes: maximumBytes)
    }

    static func read(descriptor: Int32, maximumBytes: Int) throws -> Data {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              status.st_mode & mode_t(S_IRWXG | S_IRWXO) == 0,
              status.st_size > 0,
              status.st_size <= maximumBytes
        else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        var bytes = [UInt8](repeating: 0, count: Int(status.st_size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress?.advanced(by: offset), buffer.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw NativeNetworkPolicyPersistenceError.corruptState }
            offset += count
        }
        var trailing = UInt8(0)
        guard Darwin.read(descriptor, &trailing, 1) == 0 else {
            throw NativeNetworkPolicyPersistenceError.corruptState
        }
        return Data(bytes)
    }

    static func validFileName(_ value: String) -> Bool {
        guard let first = value.utf8.first, value.utf8.count <= 128,
              (65 ... 90).contains(first) || (97 ... 122).contains(first) || (48 ... 57).contains(first)
        else { return false }
        return value.utf8.allSatisfy {
            (65 ... 90).contains($0) || (97 ... 122).contains($0) || (48 ... 57).contains($0)
                || $0 == 45 || $0 == 46 || $0 == 95
        }
    }
}
