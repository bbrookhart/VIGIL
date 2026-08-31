import XCTest

@testable import VigilNetworkAdapter

final class ProviderLinkageTests: XCTestCase {
    /// Referencing the provider proves the public SDK subclass still compiles and links
    /// against NetworkExtension. It does not activate a filter or claim an entitlement —
    /// VIGIL holds neither on this machine.
    func test_data_provider_subclass_remains_buildable() {
        XCTAssertNotNil(VigilNetworkDataProvider.self)
    }
}
