import Foundation
import XCTest

@testable import VigilEndpointAdapter

/// The privileged control protocol the daemon speaks to the extension. Every request here is
/// attacker-reachable if the peer check is ever bypassed, so each one fails closed.
final class ControlProtocolTests: XCTestCase {
    private var fixture: EndpointPolicyFixture!
    private var now: Int64 { fixture.verificationTime }

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try EndpointPolicyFixture.load()
    }

    private func health(_ control: NativeEndpointControlService, id: String, at time: Int64) throws
        -> [String: Any]?
    {
        controlReply(control.handleForTesting(
            requestData: try controlRequest(id: id, operation: "health"),
            nowUnixMilliseconds: time
        ))
    }

    // MARK: - Health

    func test_cold_service_reports_healthy_but_not_ready() throws {
        let control = NativeEndpointControlService.inMemoryForTesting(
            policyVerifier: try fixture.verifier()
        )
        let reply = try health(control, id: "health-cold", at: now)
        XCTAssertReplyCode(reply, "ok", "cold health request failed")
        XCTAssertEqual(reply?["ready"] as? Bool, false, "cold service claimed policy readiness")
    }

    func test_health_carries_native_authorization_telemetry() throws {
        // Telemetry has to reach the operator through the control channel; counters that stay
        // inside the extension cannot be acted on.
        let control = NativeEndpointControlService.inMemoryForTesting(
            policyVerifier: try fixture.verifier(),
            authorizationMetrics: AuthorizationMetricsTests.populated()
        )
        let reply = try health(control, id: "health-metrics", at: now)
        let metrics = try XCTUnwrap(
            reply?["authorization_metrics"] as? [String: Any],
            "control health omitted native authorization metrics"
        )
        XCTAssertEqual(
            (metrics["deadline_guard_denials"] as? NSNumber)?.uint64Value, 1,
            "control health lost deadline-pressure telemetry"
        )
        XCTAssertEqual(
            (metrics["dropped_events"] as? NSNumber)?.uint64Value, 2,
            "control health lost sequence-gap telemetry"
        )
    }

    func test_expired_policy_reports_not_ready_but_keeps_its_generation() throws {
        let (control, _) = try fixture.installedControl()
        let reply = try health(control, id: "health-expired", at: now + 60_000)
        XCTAssertReplyCode(reply, "ok", "expired health request failed")
        XCTAssertEqual(reply?["ready"] as? Bool, false, "expired policy claimed readiness")
        XCTAssertEqual(
            (reply?["installed_generation"] as? NSNumber)?.uint64Value, 42,
            "expired health response lost the installed generation"
        )
    }

    // MARK: - Installation

    func test_concurrent_installs_of_one_generation_are_atomic() throws {
        let control = NativeEndpointControlService.inMemoryForTesting(
            policyVerifier: try fixture.verifier()
        )
        let requests = try (0 ..< 8).map {
            try controlRequest(
                id: "install-42-\($0)", operation: "install_policy", envelope: fixture.envelopeObject
            )
        }
        let collector = ReplyCollector()
        let installedAt = now
        DispatchQueue.concurrentPerform(iterations: requests.count) { index in
            if let decoded = controlReply(control.handleForTesting(
                requestData: requests[index], nowUnixMilliseconds: installedAt
            )) {
                collector.append(decoded)
            }
        }

        let replies = collector.snapshot()
        let accepted = replies.filter { $0["code"] as? String == "ok" }
        let rejected = replies.filter { $0["code"] as? String == "stale_generation" }
        XCTAssertEqual(accepted.count, 1, "concurrent policy install was not atomic")
        XCTAssertEqual(rejected.count, 7, "concurrent policy replays did not fail consistently")
        XCTAssertEqual(accepted.first?["ready"] as? Bool, true, "successful install did not become ready")
        XCTAssertEqual(
            (accepted.first?["installed_generation"] as? NSNumber)?.uint64Value, 42,
            "install acknowledgement reported the wrong generation"
        )
    }

    func test_replayed_install_is_refused_and_changes_nothing() throws {
        let (control, state) = try fixture.installedControl()
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "install-replay", operation: "install_policy", envelope: fixture.envelopeObject
            ),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "stale_generation", "control protocol accepted a generation replay")
        XCTAssertEqual(state.snapshotVersion(), 42, "generation replay changed installed state")
    }

    func test_forged_install_is_refused_and_changes_nothing() throws {
        let (control, state) = try fixture.installedControl()
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "install-tampered", operation: "install_policy",
                envelope: fixture.tamperedEnvelopeObject
            ),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "policy_rejected", "control protocol did not reject a forged policy")
        XCTAssertEqual(state.snapshotVersion(), 42, "forged update partially changed installed state")
    }

    func test_signed_expiry_reaches_fast_path_state() throws {
        let (_, state) = try fixture.installedControl()
        XCTAssertEqual(
            state.snapshotExpiryUnixMilliseconds(), now + 60_000,
            "signed policy expiry did not reach fast-path state"
        )
    }

    // MARK: - Malformed requests

    func test_unknown_operation_fails_safely() throws {
        let (control, _) = try fixture.installedControl()
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(id: "unknown-op", operation: "bind_claimed_pid"),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "unsupported_operation", "unknown privileged operation did not fail safely")
    }

    func test_unknown_security_relevant_field_is_refused() throws {
        // Ignoring unknown fields is how a privilege claim slips through a version skew.
        let (control, _) = try fixture.installedControl()
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "health-extra", operation: "health", extra: ["claimed_admin": true]
            ),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "malformed_request", "control request accepted an unknown security-relevant field")
    }

    // MARK: - Root binding

    func test_stale_generation_bind_is_refused() throws {
        let (control, state) = try fixture.installedControl()
        let root = identity(1)
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "bind-stale", operation: "bind_root",
                extra: [
                    "generation": "41",
                    "session_id": try fixture.sessionPolicy().sessionID,
                    "audit_token": encodeBase64URL(root.auditToken),
                ]
            ),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "stale_generation", "stale root bind succeeded")
        XCTAssertNil(state.attributedSession(auditToken: root.auditToken), "stale root bind changed attribution")
    }

    func test_coerced_generation_or_padded_token_is_refused() throws {
        let (control, _) = try fixture.installedControl()
        let root = identity(1)
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "bind-malformed", operation: "bind_root",
                extra: [
                    // A JSON number where a decimal string is required, and a token whose
                    // base64url encoding carries padding it should not have.
                    "generation": 42,
                    "session_id": try fixture.sessionPolicy().sessionID,
                    "audit_token": encodeBase64URL(root.auditToken) + "=",
                ]
            ),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "malformed_request", "root bind accepted coerced generation or padded audit token")
    }

    func test_caller_claimed_pid_is_refused() throws {
        // The pid must come from the kernel's audit token, never from the request body.
        let (control, _) = try fixture.installedControl()
        let root = identity(1)
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "bind-claimed-pid", operation: "bind_root",
                extra: [
                    "generation": "42",
                    "session_id": try fixture.sessionPolicy().sessionID,
                    "audit_token": encodeBase64URL(root.auditToken),
                    "pid": 1,
                ]
            ),
            nowUnixMilliseconds: now
        ))
        XCTAssertReplyCode(reply, "malformed_request", "root bind accepted a caller-claimed PID field")
    }

    func test_authenticated_bind_is_idempotent() throws {
        let (control, state) = try fixture.installedControl()
        let root = identity(1)
        let request = try controlRequest(
            id: "bind-root", operation: "bind_root",
            extra: [
                "generation": "42",
                "session_id": try fixture.sessionPolicy().sessionID,
                "audit_token": encodeBase64URL(root.auditToken),
            ]
        )

        let first = controlReply(control.handleForTesting(requestData: request, nowUnixMilliseconds: now))
        XCTAssertReplyCode(first, "ok", "authenticated root bind failed")
        XCTAssertEqual(state.attributionCount(), 1, "root bind did not create one attribution")

        // A retried bind after a dropped reply must not double-attribute.
        let replay = controlReply(control.handleForTesting(requestData: request, nowUnixMilliseconds: now))
        XCTAssertReplyCode(replay, "ok", "idempotent root bind replay failed")
        XCTAssertEqual(state.attributionCount(), 1, "root bind replay duplicated attribution")
    }

    func test_bind_under_expired_policy_fails_closed() throws {
        let (control, state) = try fixture.installedControl()
        let root = identity(6)
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "bind-expired", operation: "bind_root",
                extra: [
                    "generation": "42",
                    "session_id": try fixture.sessionPolicy().sessionID,
                    "audit_token": encodeBase64URL(root.auditToken),
                ]
            ),
            nowUnixMilliseconds: now + 60_000
        ))
        XCTAssertReplyCode(reply, "not_ready", "expired root bind failed open")
        XCTAssertNil(state.attributedSession(auditToken: root.auditToken), "expired root bind changed attribution")
    }
}
