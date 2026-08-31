import Foundation

public enum NativeNetworkInstallationIdentityError: Error, Equatable {
    case invalidConfiguration
    case identityUnavailable
    case corruptIdentity
}

/// Host-owned durable identifier binding policy, provider health, and trust enrollment to one
/// installation. Creation is insert-only and a racing creator reloads the winner.
public final class NativeNetworkInstallationIdentityStore: @unchecked Sendable {
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
            throw NativeNetworkInstallationIdentityError.invalidConfiguration
        }
        self.service = service
        self.account = account
        self.keychain = keychain
    }

    public func loadOrCreate() throws -> String {
        try lock.withLock {
            if let existing = try keychain.read(service: service, account: account) {
                return try decode(existing)
            }
            let generated = UUID().uuidString.lowercased()
            let bytes = Data(generated.utf8)
            switch try keychain.insert(bytes, service: service, account: account) {
            case .inserted:
                return generated
            case .duplicate:
                guard let winner = try keychain.read(service: service, account: account) else {
                    throw NativeNetworkInstallationIdentityError.identityUnavailable
                }
                return try decode(winner)
            }
        }
    }

    private func decode(_ bytes: Data) throws -> String {
        guard bytes.count == 36,
              let value = String(data: bytes, encoding: .utf8),
              value == value.lowercased(),
              let uuid = UUID(uuidString: value),
              uuid.uuidString.lowercased() == value,
              validIdentifier(value, maximumBytes: 128)
        else {
            throw NativeNetworkInstallationIdentityError.corruptIdentity
        }
        return value
    }
}
