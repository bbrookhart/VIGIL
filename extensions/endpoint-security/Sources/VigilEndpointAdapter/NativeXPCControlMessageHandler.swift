import Foundation
import XPC

private let xpcControlRequestKey = "request"
private let xpcControlResponseKey = "response"
private let maximumXPCControlRequestBytes = 2 * 1_024 * 1_024

struct NativeXPCControlMessageResult {
    let reply: xpc_object_t
    let peerAuthenticated: Bool
}

/// Bridges one kernel-associated XPC dictionary to the strict control service.
///
/// The handler creates a reply from the original message, verifies the original sender through
/// `SecCodeCreateWithXPCMessage`, bounds the request before copying it, and places one opaque JSON
/// response in the reply dictionary. The native listener owns peer idle timeouts; the native
/// client separately owns end-to-end request deadlines. Mach-service registration and signed
/// target launch lifecycle remain packaging responsibilities.
public final class NativeXPCControlMessageHandler: @unchecked Sendable {
    private let peerVerifier: NativeXPCPeerVerifier
    private let controlService: NativeEndpointControlService

    public init(
        peerVerifier: NativeXPCPeerVerifier,
        controlService: NativeEndpointControlService
    ) {
        self.peerVerifier = peerVerifier
        self.controlService = controlService
    }

    public func reply(
        to message: xpc_object_t,
        nowUnixMilliseconds: Int64
    ) -> xpc_object_t? {
        handle(
            message,
            nowUnixMilliseconds: nowUnixMilliseconds
        )?.reply
    }

    func handle(
        _ message: xpc_object_t,
        nowUnixMilliseconds: Int64
    ) -> NativeXPCControlMessageResult? {
        guard let reply = xpc_dictionary_create_reply(message) else {
            return nil
        }

        let response: Data
        var peerAuthenticated = false
        do {
            let peer = try peerVerifier.verify(message: message)
            peerAuthenticated = true
            var requestLength = 0
            guard let requestBytes = xpc_dictionary_get_data(
                message,
                xpcControlRequestKey,
                &requestLength
            ), requestLength > 0, requestLength <= maximumXPCControlRequestBytes else {
                response = controlService.fixedRejection(
                    .malformedRequest,
                    nowUnixMilliseconds: nowUnixMilliseconds
                )
                return NativeXPCControlMessageResult(
                    reply: Self.attach(response: response, to: reply),
                    peerAuthenticated: true
                )
            }
            let request = Data(bytes: requestBytes, count: requestLength)
            response = controlService.handle(
                requestData: request,
                from: peer,
                nowUnixMilliseconds: nowUnixMilliseconds
            )
        } catch {
            response = controlService.fixedRejection(
                .unauthenticatedPeer,
                nowUnixMilliseconds: nowUnixMilliseconds
            )
        }
        return NativeXPCControlMessageResult(
            reply: Self.attach(response: response, to: reply),
            peerAuthenticated: peerAuthenticated
        )
    }

    private static func attach(response: Data, to reply: xpc_object_t) -> xpc_object_t {
        response.withUnsafeBytes { bytes in
            xpc_dictionary_set_data(
                reply,
                xpcControlResponseKey,
                bytes.baseAddress,
                bytes.count
            )
        }
        return reply
    }
}
