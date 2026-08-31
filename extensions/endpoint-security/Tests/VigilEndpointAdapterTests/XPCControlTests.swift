import Foundation
import XCTest
import XPC

@testable import VigilEndpointAdapter

/// The XPC listener and client: configuration that must fail before activation, peer
/// authentication, and bounded request lifecycles (ADR 0014, ADR 0021).
final class XPCControlTests: XCTestCase {
    private var fixture: EndpointPolicyFixture!
    private var control: NativeEndpointControlService!
    private var now: Int64 { fixture.verificationTime }

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try EndpointPolicyFixture.load()
        (control, _) = try fixture.installedControl()
    }

    /// A handler that accepts this test bundle's own code identity.
    private func selfTrustingHandler() throws -> NativeXPCControlMessageHandler {
        NativeXPCControlMessageHandler(
            peerVerifier: try NativeXPCPeerVerifier(
                requirementText: currentDesignatedRequirementText()
            ),
            controlService: control
        )
    }

    /// A handler expecting the production daemon, which this bundle is not.
    private func daemonOnlyHandler() throws -> NativeXPCControlMessageHandler {
        NativeXPCControlMessageHandler(
            peerVerifier: try NativeXPCPeerVerifier(
                requirementText: "identifier \"com.vigil.security.daemon\" and anchor apple generic"
            ),
            controlService: control
        )
    }

    private func healthRequest() throws -> Data {
        try controlRequest(id: "health-live-xpc", operation: "health")
    }

    private func sendRaw(_ request: Data, to endpoint: xpc_endpoint_t)
        -> (connection: xpc_connection_t, response: XPCResponseWaiter, invalidation: XPCInvalidationWaiter)
    {
        let connection = xpc_connection_create_from_endpoint(endpoint)
        let invalidation = XPCInvalidationWaiter()
        xpc_connection_set_event_handler(connection) { invalidation.receive($0) }
        xpc_connection_activate(connection)

        let message = xpc_dictionary_create_empty()
        request.withUnsafeBytes { bytes in
            if let baseAddress = bytes.baseAddress {
                xpc_dictionary_set_data(message, "request", baseAddress, bytes.count)
            }
        }
        let response = XPCResponseWaiter()
        xpc_connection_send_message_with_reply(
            connection, message, DispatchQueue.global(qos: .userInitiated)
        ) { response.receive($0) }
        return (connection, response, invalidation)
    }

    // MARK: - Configuration fails before activation

    func test_invalid_mach_service_name_is_refused() throws {
        XCTAssertThrowsError(try NativeXPCControlListener(
            machServiceName: "invalid service name", messageHandler: try selfTrustingHandler()
        )) { error in
            XCTAssertEqual(error as? NativeXPCControlListenerError, .invalidMachServiceName)
        }
    }

    func test_subsecond_peer_idle_timeout_is_refused() throws {
        // A churn-prone timeout would evict healthy peers and mask a real connectivity fault.
        XCTAssertThrowsError(try NativeXPCControlListener(
            machServiceName: "com.vigil.security.endpoint.control",
            messageHandler: try selfTrustingHandler(), peerIdleTimeoutMilliseconds: 999
        )) { error in
            XCTAssertEqual(error as? NativeXPCControlListenerError, .invalidPeerIdleTimeout)
        }
    }

    func test_valid_production_listener_configuration_is_accepted() throws {
        XCTAssertNoThrow(try NativeXPCControlListener(
            machServiceName: "com.vigil.security.endpoint.control",
            messageHandler: try selfTrustingHandler()
        ))
    }

    func test_client_refuses_an_invalid_mach_service_name() {
        XCTAssertThrowsError(
            try NativeXPCControlClient(machServiceName: "invalid service name")
        ) { error in
            XCTAssertEqual(error as? NativeXPCControlClientError, .invalidMachServiceName)
        }
    }

    func test_client_refuses_a_near_zero_request_timeout() {
        XCTAssertThrowsError(try NativeXPCControlClient(
            machServiceName: "com.vigil.security.endpoint.control", requestTimeoutMilliseconds: 49
        )) { error in
            XCTAssertEqual(error as? NativeXPCControlClientError, .invalidRequestTimeout)
        }
    }

    // MARK: - Listener lifecycle

    func test_listener_start_and_stop_are_one_way_transitions() throws {
        let fixedNow = now
        let listener = try NativeXPCControlListener.anonymousForTesting(
            messageHandler: try selfTrustingHandler(),
            nowProvider: { fixedNow }, peerIdleTimeoutMilliseconds: 100
        )
        try listener.start()
        XCTAssertTrue(listener.isRunning(), "anonymous XPC listener did not start")

        XCTAssertThrowsError(try listener.start(), "XPC listener accepted a duplicate start") { error in
            XCTAssertEqual(error as? NativeXPCControlListenerError, .alreadyStarted)
        }

        try listener.stop()
        XCTAssertFalse(listener.isRunning(), "XPC listener remained active after stop")

        XCTAssertThrowsError(try listener.stop(), "XPC listener accepted a duplicate stop") { error in
            XCTAssertEqual(error as? NativeXPCControlListenerError, .notStarted)
        }
    }

    // MARK: - Authenticated request over a live connection

    func test_authenticated_peer_gets_a_live_health_reply_then_is_evicted_when_idle() throws {
        let fixedNow = now
        let listener = try NativeXPCControlListener.anonymousForTesting(
            messageHandler: try selfTrustingHandler(),
            nowProvider: { fixedNow }, peerIdleTimeoutMilliseconds: 100
        )
        try listener.start()
        defer { try? listener.stop() }
        let endpoint = try XCTUnwrap(listener.anonymousEndpointForTesting())

        let peer = sendRaw(try healthRequest(), to: endpoint)
        let data = try XCTUnwrap(peer.response.wait(seconds: 2), "live XPC health request timed out")
        let reply = controlReply(data)
        XCTAssertReplyCode(reply, "ok", "live XPC health request failed")
        XCTAssertEqual(reply?["ready"] as? Bool, true, "live XPC health lost policy readiness")

        // Idle peers are dropped so a stalled daemon cannot hold a slot indefinitely.
        XCTAssertTrue(
            peer.invalidation.wait(seconds: 2),
            "idle XPC peer was not evicted within its configured timeout"
        )
        xpc_connection_cancel(peer.connection)
    }

    func test_peer_failing_the_code_requirement_is_rejected_and_dropped() throws {
        let fixedNow = now
        let listener = try NativeXPCControlListener.anonymousForTesting(
            messageHandler: try daemonOnlyHandler(),
            nowProvider: { fixedNow }, peerIdleTimeoutMilliseconds: 1_000
        )
        try listener.start()
        defer { try? listener.stop() }
        let endpoint = try XCTUnwrap(listener.anonymousEndpointForTesting())

        let peer = sendRaw(try healthRequest(), to: endpoint)
        let data = try XCTUnwrap(peer.response.wait(seconds: 2), "rejected peer got no reply")
        XCTAssertReplyCode(
            controlReply(data), "unauthenticated_peer", "wrong-code-identity XPC peer was not rejected"
        )
        XCTAssertTrue(
            peer.invalidation.wait(seconds: 2),
            "unauthenticated XPC peer retained its listener slot"
        )
        xpc_connection_cancel(peer.connection)
    }

    // MARK: - Bounded client

    func test_bounded_client_completes_then_refuses_use_after_invalidation() throws {
        let fixedNow = now
        let listener = try NativeXPCControlListener.anonymousForTesting(
            messageHandler: try selfTrustingHandler(),
            nowProvider: { fixedNow }, peerIdleTimeoutMilliseconds: 1_000
        )
        try listener.start()
        defer { try? listener.stop() }
        let endpoint = try XCTUnwrap(listener.anonymousEndpointForTesting())

        let client = try NativeXPCControlClient.anonymousForTesting(
            endpoint: endpoint, requestTimeoutMilliseconds: 500
        )
        let waiter = NativeControlClientWaiter()
        client.send(requestData: try healthRequest()) { waiter.receive($0) }

        switch try XCTUnwrap(waiter.wait(seconds: 2), "bounded client never completed") {
        case let .success(response):
            XCTAssertReplyCode(
                controlReply(response), "ok", "bounded XPC client did not receive the live health reply"
            )
        case let .failure(error):
            XCTFail("bounded XPC client failed unexpectedly: \(error)")
        }

        client.invalidate()
        XCTAssertTrue(client.isInvalidated(), "bounded XPC client did not invalidate")

        let afterInvalidation = NativeControlClientWaiter()
        client.send(requestData: try healthRequest()) { afterInvalidation.receive($0) }
        guard case .failure(.clientInvalidated)? = afterInvalidation.wait(seconds: 2) else {
            return XCTFail("invalidated XPC client accepted another request")
        }
    }

    func test_silent_peer_times_out_once_with_an_unknown_outcome() throws {
        // A peer that never answers must not leave the caller hanging, must not be reported as
        // a denial (the request may well have been executed), and must not complete twice when
        // the late reply finally lands.
        let slowServer = XPCSlowServer()
        defer { slowServer.stop() }

        let client = try NativeXPCControlClient.anonymousForTesting(
            endpoint: slowServer.endpoint(), requestTimeoutMilliseconds: 20
        )
        let waiter = NativeControlClientWaiter()
        client.send(requestData: try healthRequest()) { waiter.receive($0) }

        let result = try XCTUnwrap(
            waiter.wait(seconds: 2), "silent XPC peer produced no bounded client completion"
        )
        guard case .failure(.deadlineExceededOutcomeUnknown) = result else {
            return XCTFail("silent XPC peer returned the wrong client result: \(result)")
        }
        XCTAssertTrue(client.isInvalidated(), "timed-out XPC client remained reusable")

        // The slow server answers at 200ms; wait past that to catch a second completion.
        usleep(300_000)
        XCTAssertEqual(waiter.count(), 1, "timed-out XPC request completed more than once")
    }
}
