import Dispatch
import Foundation
import XPC

private let maximumNativeControlPeers = 64
private let minimumProductionPeerIdleTimeoutMilliseconds: UInt64 = 1_000
private let minimumTestingPeerIdleTimeoutMilliseconds: UInt64 = 10
private let maximumPeerIdleTimeoutMilliseconds: UInt64 = 300_000

private final class NativeXPCPeerHandle: @unchecked Sendable {
    let connection: xpc_connection_t
    let idleTimer: DispatchSourceTimer
    private let lock = NSLock()
    private var timerCancelled = false

    init(_ connection: xpc_connection_t, queue: DispatchQueue) {
        self.connection = connection
        idleTimer = DispatchSource.makeTimerSource(queue: queue)
    }

    func refreshIdleTimeout(milliseconds: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        guard !timerCancelled else {
            return
        }
        idleTimer.schedule(deadline: .now() + .milliseconds(Int(milliseconds)))
    }

    func cancelIdleTimer() {
        lock.lock()
        guard !timerCancelled else {
            lock.unlock()
            return
        }
        timerCancelled = true
        lock.unlock()
        idleTimer.cancel()
    }
}

public enum NativeXPCControlListenerError: Error, Equatable {
    case invalidMachServiceName
    case invalidPeerIdleTimeout
    case alreadyStarted
    case notStarted
}

/// Owns the listener and peer lifecycle for the native Endpoint control protocol.
///
/// Production constructs a Mach-service listener whose name must already be registered by the
/// signed System Extension target. Entitlement-free checks use an explicitly named anonymous
/// endpoint. Both paths dispatch the same kernel-associated XPC dictionaries through
/// `NativeXPCControlMessageHandler`; neither accepts caller-supplied process identity. Each peer
/// has a refreshable bounded idle timer, and only a successfully authenticated message refreshes
/// it. An unauthenticated peer receives one fixed rejection and is disconnected.
public final class NativeXPCControlListener: @unchecked Sendable {
    private enum Mode {
        case machService(String)
        case anonymousTesting
    }

    private let lock = NSLock()
    private let mode: Mode
    private let queue: DispatchQueue
    private let messageHandler: NativeXPCControlMessageHandler
    private let nowProvider: @Sendable () -> Int64?
    private let peerIdleTimeoutMilliseconds: UInt64
    private var listener: xpc_connection_t?
    private var peers: [NativeXPCPeerHandle] = []

    public init(
        machServiceName: String,
        messageHandler: NativeXPCControlMessageHandler,
        peerIdleTimeoutMilliseconds: UInt64 = 30_000
    ) throws {
        guard Self.validMachServiceName(machServiceName) else {
            throw NativeXPCControlListenerError.invalidMachServiceName
        }
        guard Self.validPeerIdleTimeout(
            peerIdleTimeoutMilliseconds,
            minimum: minimumProductionPeerIdleTimeoutMilliseconds
        ) else {
            throw NativeXPCControlListenerError.invalidPeerIdleTimeout
        }
        mode = .machService(machServiceName)
        queue = DispatchQueue(label: "com.vigil.security.endpoint.control")
        self.messageHandler = messageHandler
        nowProvider = NativeWallClock.nowUnixMilliseconds
        self.peerIdleTimeoutMilliseconds = peerIdleTimeoutMilliseconds
    }

    private init(
        testingMessageHandler: NativeXPCControlMessageHandler,
        nowProvider: @escaping @Sendable () -> Int64?,
        peerIdleTimeoutMilliseconds: UInt64
    ) {
        mode = .anonymousTesting
        queue = DispatchQueue(label: "com.vigil.security.endpoint.control.testing")
        messageHandler = testingMessageHandler
        self.nowProvider = nowProvider
        self.peerIdleTimeoutMilliseconds = peerIdleTimeoutMilliseconds
    }

    public static func anonymousForTesting(
        messageHandler: NativeXPCControlMessageHandler,
        nowProvider: @escaping @Sendable () -> Int64?,
        peerIdleTimeoutMilliseconds: UInt64 = 100
    ) throws -> NativeXPCControlListener {
        guard validPeerIdleTimeout(
            peerIdleTimeoutMilliseconds,
            minimum: minimumTestingPeerIdleTimeoutMilliseconds
        ) else {
            throw NativeXPCControlListenerError.invalidPeerIdleTimeout
        }
        return NativeXPCControlListener(
            testingMessageHandler: messageHandler,
            nowProvider: nowProvider,
            peerIdleTimeoutMilliseconds: peerIdleTimeoutMilliseconds
        )
    }

    public func start() throws {
        lock.lock()
        defer { lock.unlock() }
        guard listener == nil else {
            throw NativeXPCControlListenerError.alreadyStarted
        }

        let created: xpc_connection_t
        switch mode {
        case let .machService(name):
            created = name.withCString {
                xpc_connection_create_mach_service(
                    $0,
                    queue,
                    UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER)
                )
            }
        case .anonymousTesting:
            created = xpc_connection_create(nil, queue)
        }
        xpc_connection_set_event_handler(created) { [weak self] event in
            self?.accept(event)
        }
        listener = created
        xpc_connection_activate(created)
    }

    public func stop() throws {
        let activeListener: xpc_connection_t
        let activePeers: [NativeXPCPeerHandle]
        lock.lock()
        guard let listener else {
            lock.unlock()
            throw NativeXPCControlListenerError.notStarted
        }
        activeListener = listener
        activePeers = peers
        self.listener = nil
        peers.removeAll(keepingCapacity: false)
        lock.unlock()

        for peer in activePeers {
            peer.cancelIdleTimer()
            xpc_connection_cancel(peer.connection)
        }
        xpc_connection_cancel(activeListener)
    }

    public func anonymousEndpointForTesting() -> xpc_endpoint_t? {
        lock.lock()
        defer { lock.unlock() }
        guard case .anonymousTesting = mode, let listener else {
            return nil
        }
        return xpc_endpoint_create(listener)
    }

    public func isRunning() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return listener != nil
    }

    private func accept(_ event: xpc_object_t) {
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else {
            return
        }
        let peer = NativeXPCPeerHandle(event, queue: queue)
        peer.idleTimer.setEventHandler { [weak self, weak peer] in
            guard let self, let peer else {
                return
            }
            self.expire(peer)
        }
        peer.refreshIdleTimeout(milliseconds: peerIdleTimeoutMilliseconds)
        peer.idleTimer.activate()
        lock.lock()
        guard listener != nil, peers.count < maximumNativeControlPeers else {
            lock.unlock()
            peer.cancelIdleTimer()
            xpc_connection_cancel(peer.connection)
            return
        }
        peers.append(peer)
        lock.unlock()

        xpc_connection_set_event_handler(peer.connection) { [weak self, weak peer] message in
            guard let peer else {
                return
            }
            self?.receive(message, from: peer)
        }
        xpc_connection_activate(peer.connection)
    }

    private func receive(_ message: xpc_object_t, from peer: NativeXPCPeerHandle) {
        if xpc_get_type(message) == XPC_TYPE_DICTIONARY {
            let nowUnixMilliseconds = nowProvider() ?? -1
            if let result = messageHandler.handle(
                message,
                nowUnixMilliseconds: nowUnixMilliseconds
            ) {
                xpc_connection_send_message(peer.connection, result.reply)
                if result.peerAuthenticated {
                    peer.refreshIdleTimeout(milliseconds: peerIdleTimeoutMilliseconds)
                } else {
                    remove(peer)
                    xpc_connection_cancel(peer.connection)
                }
            } else {
                remove(peer)
                xpc_connection_cancel(peer.connection)
            }
            return
        }
        remove(peer)
        xpc_connection_cancel(peer.connection)
    }

    private func remove(_ peer: NativeXPCPeerHandle) {
        lock.lock()
        let wasPresent = peers.contains { $0 === peer }
        if wasPresent {
            peers.removeAll { $0 === peer }
        }
        lock.unlock()
        if wasPresent {
            peer.cancelIdleTimer()
        }
    }

    private func expire(_ peer: NativeXPCPeerHandle) {
        remove(peer)
        xpc_connection_cancel(peer.connection)
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

    private static func validPeerIdleTimeout(_ value: UInt64, minimum: UInt64) -> Bool {
        value >= minimum && value <= maximumPeerIdleTimeoutMilliseconds
    }

    deinit {
        lock.lock()
        let activeListener = listener
        let activePeers = peers
        listener = nil
        peers.removeAll(keepingCapacity: false)
        lock.unlock()
        for peer in activePeers {
            peer.cancelIdleTimer()
            xpc_connection_cancel(peer.connection)
        }
        if let activeListener {
            xpc_connection_cancel(activeListener)
        }
    }
}
