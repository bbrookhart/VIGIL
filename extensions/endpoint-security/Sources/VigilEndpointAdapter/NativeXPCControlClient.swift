import Dispatch
import Foundation
import XPC

private let maximumNativeControlRequestBytes = 2 * 1_024 * 1_024
private let maximumNativeControlResponseBytes = 2 * 1_024 * 1_024
private let maximumOutstandingNativeControlRequests = 64
private let minimumProductionRequestTimeoutMilliseconds: UInt64 = 50
private let minimumTestingRequestTimeoutMilliseconds: UInt64 = 10
private let maximumRequestTimeoutMilliseconds: UInt64 = 30_000

public enum NativeXPCControlClientError: Error, Equatable, Sendable {
    case invalidMachServiceName
    case invalidRequestTimeout
    case invalidRequest
    case tooManyOutstandingRequests
    case deadlineExceededOutcomeUnknown
    case invalidResponse
    case connectionInvalidated
    case clientInvalidated
}

private final class NativeXPCPendingRequest: @unchecked Sendable {
    let timer: DispatchSourceTimer
    let completion: @Sendable (Result<Data, NativeXPCControlClientError>) -> Void

    init(
        timer: DispatchSourceTimer,
        completion: @escaping @Sendable (Result<Data, NativeXPCControlClientError>) -> Void
    ) {
        self.timer = timer
        self.completion = completion
    }
}

/// Bounded asynchronous client for the daemon-to-Endpoint control protocol.
///
/// Every request owns one deadline timer and completes exactly once. A timeout invalidates the
/// entire connection because XPC cannot prove that the remote operation did not execute before
/// the reply was lost; callers receive `deadlineExceededOutcomeUnknown` and must reconcile with a
/// fresh `health` request on a new client rather than blindly replaying a mutation. The client
/// caps outstanding requests and request/response bytes, and never waits on an Endpoint Security
/// authorization callback.
public final class NativeXPCControlClient: @unchecked Sendable {
    private let lock = NSLock()
    private let queue: DispatchQueue
    private let completionQueue: DispatchQueue
    private let connection: xpc_connection_t
    private let requestTimeoutMilliseconds: UInt64
    private var pending: [UUID: NativeXPCPendingRequest] = [:]
    private var invalidated = false

    public init(
        machServiceName: String,
        requestTimeoutMilliseconds: UInt64 = 2_000,
        completionQueue: DispatchQueue = .global(qos: .userInitiated)
    ) throws {
        guard Self.validMachServiceName(machServiceName) else {
            throw NativeXPCControlClientError.invalidMachServiceName
        }
        guard Self.validRequestTimeout(
            requestTimeoutMilliseconds,
            minimum: minimumProductionRequestTimeoutMilliseconds
        ) else {
            throw NativeXPCControlClientError.invalidRequestTimeout
        }
        let clientQueue = DispatchQueue(label: "com.vigil.security.daemon.endpoint-control-client")
        queue = clientQueue
        self.completionQueue = completionQueue
        self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
        connection = machServiceName.withCString {
            xpc_connection_create_mach_service($0, clientQueue, 0)
        }
        activate()
    }

    private init(
        testingEndpoint: xpc_endpoint_t,
        requestTimeoutMilliseconds: UInt64,
        completionQueue: DispatchQueue
    ) {
        queue = DispatchQueue(label: "com.vigil.security.daemon.endpoint-control-client.testing")
        self.completionQueue = completionQueue
        self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
        connection = xpc_connection_create_from_endpoint(testingEndpoint)
        activate()
    }

    public static func anonymousForTesting(
        endpoint: xpc_endpoint_t,
        requestTimeoutMilliseconds: UInt64 = 100,
        completionQueue: DispatchQueue = .global(qos: .userInitiated)
    ) throws -> NativeXPCControlClient {
        guard validRequestTimeout(
            requestTimeoutMilliseconds,
            minimum: minimumTestingRequestTimeoutMilliseconds
        ) else {
            throw NativeXPCControlClientError.invalidRequestTimeout
        }
        return NativeXPCControlClient(
            testingEndpoint: endpoint,
            requestTimeoutMilliseconds: requestTimeoutMilliseconds,
            completionQueue: completionQueue
        )
    }

    public func send(
        requestData: Data,
        completion: @escaping @Sendable (Result<Data, NativeXPCControlClientError>) -> Void
    ) {
        guard !requestData.isEmpty, requestData.count <= maximumNativeControlRequestBytes else {
            completionQueue.async { completion(.failure(.invalidRequest)) }
            return
        }

        let requestID = UUID()
        lock.lock()
        if invalidated {
            lock.unlock()
            completionQueue.async { completion(.failure(.clientInvalidated)) }
            return
        }
        if pending.count >= maximumOutstandingNativeControlRequests {
            lock.unlock()
            completionQueue.async { completion(.failure(.tooManyOutstandingRequests)) }
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let request = NativeXPCPendingRequest(timer: timer, completion: completion)
        timer.setEventHandler { [weak self] in
            self?.deadlineExceeded(requestID)
        }
        timer.schedule(
            deadline: .now() + .milliseconds(Int(requestTimeoutMilliseconds)),
            leeway: .milliseconds(1)
        )
        timer.activate()
        pending[requestID] = request
        lock.unlock()

        let message = xpc_dictionary_create_empty()
        requestData.withUnsafeBytes { bytes in
            xpc_dictionary_set_data(message, "request", bytes.baseAddress, bytes.count)
        }
        xpc_connection_send_message_with_reply(connection, message, queue) { [weak self] reply in
            self?.receive(reply, requestID: requestID)
        }
    }

    public func invalidate() {
        invalidateAll(primaryRequest: nil, primaryError: .clientInvalidated)
    }

    public func isInvalidated() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return invalidated
    }

    private func activate() {
        xpc_connection_set_event_handler(connection) { [weak self] event in
            guard xpc_get_type(event) == XPC_TYPE_ERROR else {
                return
            }
            self?.invalidateAll(primaryRequest: nil, primaryError: .connectionInvalidated)
        }
        xpc_connection_activate(connection)
    }

    private func receive(_ reply: xpc_object_t, requestID: UUID) {
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            invalidateAll(primaryRequest: requestID, primaryError: .connectionInvalidated)
            return
        }
        var length = 0
        guard let bytes = xpc_dictionary_get_data(reply, "response", &length),
              length > 0, length <= maximumNativeControlResponseBytes
        else {
            invalidateAll(primaryRequest: requestID, primaryError: .invalidResponse)
            return
        }
        complete(requestID, with: .success(Data(bytes: bytes, count: length)))
    }

    private func deadlineExceeded(_ requestID: UUID) {
        invalidateAll(
            primaryRequest: requestID,
            primaryError: .deadlineExceededOutcomeUnknown
        )
    }

    private func complete(
        _ requestID: UUID,
        with result: Result<Data, NativeXPCControlClientError>
    ) {
        lock.lock()
        let request = pending.removeValue(forKey: requestID)
        lock.unlock()
        guard let request else {
            return
        }
        request.timer.cancel()
        completionQueue.async { request.completion(result) }
    }

    private func invalidateAll(
        primaryRequest: UUID?,
        primaryError: NativeXPCControlClientError
    ) {
        let requests: [(UUID, NativeXPCPendingRequest)]
        lock.lock()
        guard !invalidated else {
            lock.unlock()
            return
        }
        invalidated = true
        requests = Array(pending)
        pending.removeAll(keepingCapacity: false)
        lock.unlock()

        xpc_connection_cancel(connection)
        for (requestID, request) in requests {
            request.timer.cancel()
            let error: NativeXPCControlClientError = requestID == primaryRequest
                ? primaryError
                : .connectionInvalidated
            completionQueue.async { request.completion(.failure(error)) }
        }
    }

    private static func validMachServiceName(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 255
            && value.contains(".")
            && !value.contains("..")
            && value.first != "."
            && value.last != "."
            && value.utf8.allSatisfy {
                (65 ... 90).contains($0)
                    || (97 ... 122).contains($0)
                    || (48 ... 57).contains($0)
                    || $0 == 45
                    || $0 == 46
            }
    }

    private static func validRequestTimeout(_ value: UInt64, minimum: UInt64) -> Bool {
        value >= minimum && value <= maximumRequestTimeoutMilliseconds
    }

    deinit {
        invalidateAll(primaryRequest: nil, primaryError: .clientInvalidated)
    }
}
