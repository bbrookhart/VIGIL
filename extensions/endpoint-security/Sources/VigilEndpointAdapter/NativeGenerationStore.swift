import Darwin
import Foundation

private let generationFileHeader = "vigil.endpoint-generation/v1\n"
private let maximumGenerationFileBytes = 128
private let generationLockFileName = ".endpoint-generation.lock"

public enum NativeGenerationStoreError: Error, Equatable {
    case invalidLocation
    case insecureDirectory
    case corruptState
    case rollback(current: UInt64, proposed: UInt64)
    case ioFailure
}

/// Monotonic storage used to prevent a signed endpoint-policy snapshot from being replayed after
/// the extension restarts. Implementations must make `commit` durable before it returns.
public protocol NativeGenerationStore: Sendable {
    func currentGeneration() throws -> UInt64
    func commit(_ generation: UInt64) throws
}

/// A strict, atomic file-backed generation high-water mark.
///
/// The containing directory must already exist, be owned by the effective user, and not be writable
/// by group or other users. Commits use a same-directory 0600 temporary file, fsync the file, rename
/// it over the destination, and fsync the directory. Existing state is opened without following
/// symlinks and parsed as one exact, bounded format.
public final class NativeFileGenerationStore: NativeGenerationStore, @unchecked Sendable {
    private let lock = NSLock()
    private let directoryPath: String
    private let fileName: String
    private var generation: UInt64

    public init(
        directoryURL: URL,
        fileName: String = "endpoint-generation.v1"
    ) throws {
        guard directoryURL.isFileURL,
              directoryURL.path.utf8.count <= Int(PATH_MAX),
              Self.validFileName(fileName)
        else {
            throw NativeGenerationStoreError.invalidLocation
        }
        directoryPath = directoryURL.path
        self.fileName = fileName

        let directoryDescriptor = try Self.openSecureDirectory(directoryPath)
        defer { close(directoryDescriptor) }
        let lockDescriptor = try Self.lockDirectory(directoryDescriptor)
        defer { Self.unlockAndClose(lockDescriptor) }
        generation = try Self.readGeneration(
            directoryDescriptor: directoryDescriptor,
            fileName: fileName
        )
    }

    public func currentGeneration() throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return generation
    }

    public func commit(_ proposed: UInt64) throws {
        lock.lock()
        defer { lock.unlock() }
        guard proposed > generation else {
            throw NativeGenerationStoreError.rollback(current: generation, proposed: proposed)
        }

        let directoryDescriptor = try Self.openSecureDirectory(directoryPath)
        defer { close(directoryDescriptor) }
        let lockDescriptor = try Self.lockDirectory(directoryDescriptor)
        defer { Self.unlockAndClose(lockDescriptor) }
        let diskGeneration = try Self.readGeneration(
            directoryDescriptor: directoryDescriptor,
            fileName: fileName
        )
        generation = max(generation, diskGeneration)
        guard proposed > generation else {
            throw NativeGenerationStoreError.rollback(current: generation, proposed: proposed)
        }
        let temporaryName = ".endpoint-generation-\(UUID().uuidString).tmp"
        let temporaryDescriptor = openat(
            directoryDescriptor,
            temporaryName,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard temporaryDescriptor >= 0 else {
            throw NativeGenerationStoreError.ioFailure
        }

        var renamed = false
        defer {
            close(temporaryDescriptor)
            if !renamed {
                _ = unlinkat(directoryDescriptor, temporaryName, 0)
            }
        }

        let bytes = Array("\(generationFileHeader)\(proposed)\n".utf8)
        do {
            guard fchmod(temporaryDescriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
                throw NativeGenerationStoreError.ioFailure
            }
            try bytes.withUnsafeBytes { rawBuffer in
                guard let baseAddress = rawBuffer.baseAddress else {
                    throw NativeGenerationStoreError.ioFailure
                }
                var offset = 0
                while offset < rawBuffer.count {
                    let count = Darwin.write(
                        temporaryDescriptor,
                        baseAddress.advanced(by: offset),
                        rawBuffer.count - offset
                    )
                    if count < 0, errno == EINTR {
                        continue
                    }
                    guard count > 0 else {
                        throw NativeGenerationStoreError.ioFailure
                    }
                    offset += count
                }
            }
            guard fsync(temporaryDescriptor) == 0,
                  renameat(directoryDescriptor, temporaryName, directoryDescriptor, fileName) == 0
            else {
                throw NativeGenerationStoreError.ioFailure
            }
            renamed = true
            // Once rename succeeds, never permit this process to reuse the generation even if the
            // directory fsync reports failure and durability is therefore uncertain.
            generation = proposed
            guard fsync(directoryDescriptor) == 0 else {
                throw NativeGenerationStoreError.ioFailure
            }
        } catch let error as NativeGenerationStoreError {
            throw error
        } catch {
            throw NativeGenerationStoreError.ioFailure
        }
    }

    private static func openSecureDirectory(_ path: String) throws -> Int32 {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw NativeGenerationStoreError.invalidLocation
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            close(descriptor)
            throw NativeGenerationStoreError.ioFailure
        }
        guard status.st_uid == geteuid(),
              status.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0
        else {
            close(descriptor)
            throw NativeGenerationStoreError.insecureDirectory
        }
        return descriptor
    }

    private static func lockDirectory(_ directoryDescriptor: Int32) throws -> Int32 {
        let descriptor = openat(
            directoryDescriptor,
            generationLockFileName,
            O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
            mode_t(S_IRUSR | S_IWUSR)
        )
        guard descriptor >= 0 else {
            throw NativeGenerationStoreError.ioFailure
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              status.st_mode & mode_t(S_IRWXG | S_IRWXO) == 0,
              fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0
        else {
            close(descriptor)
            throw NativeGenerationStoreError.corruptState
        }
        while flock(descriptor, LOCK_EX) != 0 {
            guard errno == EINTR else {
                close(descriptor)
                throw NativeGenerationStoreError.ioFailure
            }
        }
        return descriptor
    }

    private static func unlockAndClose(_ descriptor: Int32) {
        _ = flock(descriptor, LOCK_UN)
        close(descriptor)
    }

    private static func readGeneration(
        directoryDescriptor: Int32,
        fileName: String
    ) throws -> UInt64 {
        let descriptor = openat(directoryDescriptor, fileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0, errno == ENOENT {
            return 0
        }
        guard descriptor >= 0 else {
            throw errno == ELOOP
                ? NativeGenerationStoreError.corruptState
                : NativeGenerationStoreError.ioFailure
        }
        defer { close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              status.st_mode & mode_t(S_IRWXG | S_IRWXO) == 0,
              status.st_size > 0,
              status.st_size <= maximumGenerationFileBytes
        else {
            throw NativeGenerationStoreError.corruptState
        }

        var bytes = [UInt8](repeating: 0, count: Int(status.st_size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { rawBuffer in
                Darwin.read(
                    descriptor,
                    rawBuffer.baseAddress?.advanced(by: offset),
                    rawBuffer.count - offset
                )
            }
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else {
                throw NativeGenerationStoreError.corruptState
            }
            offset += count
        }
        var trailing = UInt8(0)
        guard Darwin.read(descriptor, &trailing, 1) == 0,
              let text = String(bytes: bytes, encoding: .utf8),
              text.hasPrefix(generationFileHeader),
              text.hasSuffix("\n")
        else {
            throw NativeGenerationStoreError.corruptState
        }
        let value = text.dropFirst(generationFileHeader.count).dropLast()
        guard !value.isEmpty,
              value.count <= 20,
              value != "0",
              !(value.count > 1 && value.first == "0"),
              value.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              let parsed = UInt64(value)
        else {
            throw NativeGenerationStoreError.corruptState
        }
        return parsed
    }

    private static func validFileName(_ value: String) -> Bool {
        guard let first = value.utf8.first,
              value.utf8.count <= 128,
              (65 ... 90).contains(first)
                || (97 ... 122).contains(first)
                || (48 ... 57).contains(first)
        else {
            return false
        }
        return value.utf8.allSatisfy {
            (65 ... 90).contains($0)
                || (97 ... 122).contains($0)
                || (48 ... 57).contains($0)
                || $0 == 45
                || $0 == 46
                || $0 == 95
        }
    }
}

/// Entitlement-free checks can use process-local monotonic state without implying restart safety.
final class NativeInMemoryGenerationStore: NativeGenerationStore, @unchecked Sendable {
    private let lock = NSLock()
    private var generation: UInt64

    public init(initialGeneration: UInt64 = 0) {
        generation = initialGeneration
    }

    public func currentGeneration() throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return generation
    }

    public func commit(_ proposed: UInt64) throws {
        lock.lock()
        defer { lock.unlock() }
        guard proposed > generation else {
            throw NativeGenerationStoreError.rollback(current: generation, proposed: proposed)
        }
        generation = proposed
    }
}
