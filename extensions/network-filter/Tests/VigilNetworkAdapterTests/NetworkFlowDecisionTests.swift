import Foundation
import XCTest

@testable import VigilNetworkAdapter

/// Flow authority: which outbound connections an installed policy permits, and why.
final class NetworkFlowDecisionTests: XCTestCase {
    private var fixture: NetworkPolicyFixture!
    private var state: NativeNetworkPolicyState!
    private var now: Int64 { fixture.verificationTimeUnixMilliseconds }

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try NetworkPolicyFixture.load()
        state = try fixture.installedState()
    }

    func test_pinned_destination_is_allowed() {
        // Hostname comparison is case-insensitive and tolerates the trailing root label.
        let decision = state.decide(outboundFlow(
            hostname: "GitHub.COM.", remoteIP: "140.82.112.4", at: now
        ))
        XCTAssertEqual(decision.action, .allow)
        XCTAssertEqual(decision.reason, .permitPinnedDestination)
    }

    func test_resolution_change_cannot_borrow_hostname_authority() {
        // The allowlisted hostname resolving to an unpinned address is the DNS-rebinding
        // shape: the name is permitted, this address is not.
        let decision = state.decide(outboundFlow(
            hostname: "github.com", remoteIP: "93.184.216.34", at: now
        ))
        XCTAssertEqual(decision.action, .drop)
        XCTAssertEqual(decision.reason, .denyResolutionMismatch)
    }

    func test_loopback_destination_is_refused() {
        let decision = state.decide(outboundFlow(
            hostname: "github.com", remoteIP: "::1", at: now
        ))
        XCTAssertEqual(decision.action, .drop)
        XCTAssertEqual(decision.reason, .denyPrivateOrLocalAddress)
    }

    func test_unmanaged_process_traffic_is_untouched() {
        // VIGIL filters the agent, not the host. An unattributed process keeps full
        // connectivity even to an address the policy would refuse for a managed one.
        let decision = state.decide(outboundFlow(
            process: [UInt8](repeating: 7, count: 32),
            hostname: nil, remoteIP: "127.0.0.1", remotePort: 1, at: now
        ))
        XCTAssertEqual(decision.action, .allow)
        XCTAssertEqual(decision.reason, .unmanagedProcess)
    }

    func test_expired_policy_denies_a_managed_flow() {
        // Policy is a lease. Once it lapses the managed process loses authority rather than
        // inheriting the last known good answer.
        let decision = state.decide(outboundFlow(
            hostname: "github.com", remoteIP: "140.82.112.4", at: now + 60_000
        ))
        XCTAssertEqual(decision.action, .drop)
        XCTAssertEqual(decision.reason, .denyPolicyExpired)
    }
}
