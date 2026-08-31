import Foundation
import XCTest

@testable import VigilNetworkAdapter

final class NetworkInstallationIdentityTests: XCTestCase {
    func test_installation_identity_is_canonical_and_stable() throws {
        let keychain = InstallationIdentityMemoryKeychain()
        let store = try makeStore(keychain: keychain)

        let first = try store.loadOrCreate()
        let second = try store.loadOrCreate()

        XCTAssertEqual(first, second)
        XCTAssertEqual(first, first.lowercased())
        XCTAssertEqual(UUID(uuidString: first)?.uuidString.lowercased(), first)
        XCTAssertEqual(keychain.insertions, 1)
    }

    func test_creation_race_reloads_the_winning_identity() throws {
        let winner = UUID().uuidString.lowercased()
        let keychain = InstallationIdentityMemoryKeychain(
            duplicateWinner: Data(winner.utf8)
        )

        XCTAssertEqual(try makeStore(keychain: keychain).loadOrCreate(), winner)
        XCTAssertEqual(keychain.insertions, 1)
    }

    func test_corrupt_identity_is_never_replaced() throws {
        let keychain = InstallationIdentityMemoryKeychain(initial: Data("not-a-uuid".utf8))

        XCTAssertThrowsError(try makeStore(keychain: keychain).loadOrCreate()) { error in
            XCTAssertEqual(
                error as? NativeNetworkInstallationIdentityError,
                .corruptIdentity
            )
        }
        XCTAssertEqual(keychain.insertions, 0)
    }

    func test_identity_store_rejects_ambiguous_keychain_coordinates() throws {
        XCTAssertThrowsError(try NativeNetworkInstallationIdentityStore(
            service: "bad service",
            account: "network",
            keychain: InstallationIdentityMemoryKeychain()
        ))
        XCTAssertThrowsError(try NativeNetworkInstallationIdentityStore(
            service: "com.vigil.security.installation",
            account: "",
            keychain: InstallationIdentityMemoryKeychain()
        ))
    }

    private func makeStore(
        keychain: InstallationIdentityMemoryKeychain
    ) throws -> NativeNetworkInstallationIdentityStore {
        try NativeNetworkInstallationIdentityStore(
            service: "com.vigil.security.installation",
            account: "network",
            keychain: keychain
        )
    }
}

private final class InstallationIdentityMemoryKeychain: NativeNetworkProviderHealthKeychain,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var value: Data?
    private var duplicateWinner: Data?
    private(set) var insertions = 0

    init(initial: Data? = nil, duplicateWinner: Data? = nil) {
        value = initial
        self.duplicateWinner = duplicateWinner
    }

    func read(service: String, account: String) throws -> Data? {
        _ = service
        _ = account
        return lock.withLock { value }
    }

    func insert(
        _ candidate: Data,
        service: String,
        account: String
    ) throws -> NativeNetworkProviderHealthKeychainInsertResult {
        _ = service
        _ = account
        return lock.withLock {
            insertions += 1
            if let winner = duplicateWinner {
                value = winner
                duplicateWinner = nil
                return .duplicate
            }
            if value != nil { return .duplicate }
            value = candidate
            return .inserted
        }
    }
}
