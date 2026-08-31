import XCTest

@testable import VigilEndpointAdapter

/// The kernel gives an Endpoint Security client a deadline. Missing it is fatal to the client
/// and, worse, ambiguous for the user — so the guard denies while a safety margin remains.
final class DeadlineGuardTests: XCTestCase {
    private let guardrail = EndpointDeadlineGuard(safetyMarginTicks: 5)

    func test_allows_while_the_safety_margin_remains() {
        XCTAssertFalse(guardrail.requiresDenial(now: 10, deadline: 16))
    }

    func test_denies_once_inside_the_safety_margin() {
        XCTAssertTrue(guardrail.requiresDenial(now: 11, deadline: 16))
    }

    func test_does_not_fail_open_on_tick_overflow() {
        // A deadline near UInt64.max must not wrap into an apparently distant future.
        XCTAssertTrue(guardrail.requiresDenial(now: UInt64.max - 2, deadline: UInt64.max))
    }
}
