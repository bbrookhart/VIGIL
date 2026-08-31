import CryptoKit
import Foundation
import Security

public enum NativeNetworkProviderHealthKeyStoreError: Error, Equatable {
    case invalidConfiguration
    case keychainUnavailable
    case corruptKey
}

/// Public identity plus a signing capability. The private key bytes are never exposed by this API.
public struct NativeNetworkProviderHealthSigningIdentity: Sendable {
    public let keyID: String
    public let publicKey: Data
    let signer: NativeNetworkProviderHealthSigner

    fileprivate init(
        keyID: String,
        publicKey: Data,
        signer: NativeNetworkProviderHealthSigner
    ) {
        self.keyID = keyID
        self.publicKey = publicKey
        self.signer = signer
    }
}

enum NativeNetworkProviderHealthKeychainInsertResult: Equatable {
    case inserted
    case duplicate
}

protocol NativeNetworkProviderHealthKeychain: Sendable {
    func read(service: String, account: String) throws -> Data?
    func insert(_ value: Data, service: String, account: String) throws
        -> NativeNetworkProviderHealthKeychainInsertResult
}

/// Provider-only Ed25519 key custody. Production storage uses the extension's default Keychain
/// access group; no App Group or containing-app Keychain group is requested.
public final class NativeNetworkProviderHealthKeyStore: @unchecked Sendable {
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
            throw NativeNetworkProviderHealthKeyStoreError.invalidConfiguration
        }
        self.service = service
        self.account = account
        self.keychain = keychain
    }

    /// Loads the stable provider identity or creates it exactly once. A concurrent creator wins;
    /// the losing caller reloads instead of replacing the winning key.
    public func loadOrCreate() throws -> NativeNetworkProviderHealthSigningIdentity {
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
                return try identity(from: generated.rawRepresentation)
            case .duplicate:
                guard let winner = try keychain.read(service: service, account: account) else {
                    throw NativeNetworkProviderHealthKeyStoreError.keychainUnavailable
                }
                return try identity(from: winner)
            }
        }
    }

    private func identity(from rawKey: Data) throws -> NativeNetworkProviderHealthSigningIdentity {
        guard rawKey.count == 32,
              let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: rawKey)
        else {
            throw NativeNetworkProviderHealthKeyStoreError.corruptKey
        }
        let publicKey = privateKey.publicKey.rawRepresentation
        let digest = SHA256.hash(data: publicKey)
        let fingerprint = digest.prefix(16).map { String(format: "%02x", $0) }.joined()
        let keyID = "provider-health-\(fingerprint)"
        guard let signer = try? NativeNetworkProviderHealthSigner(
            keyID: keyID,
            privateKey: rawKey
        ) else {
            throw NativeNetworkProviderHealthKeyStoreError.corruptKey
        }
        return NativeNetworkProviderHealthSigningIdentity(
            keyID: keyID,
            publicKey: publicKey,
            signer: signer
        )
    }
}

struct SystemProviderHealthKeychain: NativeNetworkProviderHealthKeychain {
    func read(service: String, account: String) throws -> Data? {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw NativeNetworkProviderHealthKeyStoreError.keychainUnavailable
        }
        return data
    }

    func insert(
        _ value: Data,
        service: String,
        account: String
    ) throws -> NativeNetworkProviderHealthKeychainInsertResult {
        var query = baseQuery(service: service, account: account)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecAttrSynchronizable as String] = kCFBooleanFalse
        query[kSecValueData as String] = value
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem { return .duplicate }
        guard status == errSecSuccess else {
            throw NativeNetworkProviderHealthKeyStoreError.keychainUnavailable
        }
        return .inserted
    }

    private func baseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}
