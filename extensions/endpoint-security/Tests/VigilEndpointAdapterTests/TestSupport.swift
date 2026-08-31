import Darwin
import Foundation
import Security
import XCTest
import XPC

@testable import VigilEndpointAdapter

// MARK: - Identities

/// A synthetic process identity. The audit token is the identity; the pid never is.
func identity(_ tokenByte: UInt8, executable: String = "/usr/bin/env") -> NativeProcessIdentity {
    NativeProcessIdentity(
        auditToken: [UInt8](repeating: tokenByte, count: 32),
        pid: Int32(tokenByte),
        parentPID: 1,
        executablePath: executable,
        executablePathTruncated: false,
        signingID: nil,
        teamID: nil,
        isPlatformBinary: false,
        isEndpointSecurityClient: false
    )
}

// MARK: - Encoding

func decodeBase64URL(_ value: String) -> Data? {
    var standard = value.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    standard.append(String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4))
    return Data(base64Encoded: standard)
}

func encodeBase64URL(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// MARK: - Control protocol

func controlRequest(
    id: String,
    operation: String,
    envelope: [String: Any]? = nil,
    extra: [String: Any] = [:]
) throws -> Data {
    var object: [String: Any] = [
        "protocol_version": "vigil.endpoint-control/v1",
        "request_id": id,
        "operation": operation,
    ]
    if let envelope {
        object["policy_envelope"] = envelope
    }
    for (key, value) in extra {
        object[key] = value
    }
    return try JSONSerialization.data(withJSONObject: object)
}

func controlReply(_ data: Data) -> [String: Any]? {
    try? JSONSerialization.jsonObject(with: data) as? [String: Any]
}

/// Assert the `code` of a control reply, reporting the whole reply when it does not match.
func XCTAssertReplyCode(
    _ reply: [String: Any]?,
    _ expected: String,
    _ message: String,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    XCTAssertEqual(
        reply?["code"] as? String, expected,
        "\(message) — reply was \(reply.map(String.init(describing:)) ?? "nil")",
        file: file, line: line
    )
}

// MARK: - Fixture

/// The Rust-generated signed snapshot both sides of the wire contract are checked against.
///
/// `make contract-fixtures` regenerates `Resources/endpoint_policy_v1.json` from
/// `vigil-endpoint`. These tests failing after an encoder change means the Rust and Swift
/// sides have diverged.
struct EndpointPolicyFixture {
    let verificationTime: Int64
    let instanceID: String
    let keyID: String
    let publicKey: Data
    let envelopeObject: [String: Any]

    static func load(file: StaticString = #filePath, line: UInt = #line) throws -> EndpointPolicyFixture {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "endpoint_policy_v1", withExtension: "json"),
            "endpoint policy fixture is missing from the test bundle",
            file: file, line: line
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any],
            "endpoint policy fixture is not a JSON object", file: file, line: line
        )
        return try EndpointPolicyFixture(
            verificationTime: XCTUnwrap(
                (object["verification_time_unix_ms"] as? NSNumber)?.int64Value, file: file, line: line
            ),
            instanceID: XCTUnwrap(object["expected_instance_id"] as? String, file: file, line: line),
            keyID: XCTUnwrap(object["trusted_key_id"] as? String, file: file, line: line),
            publicKey: XCTUnwrap(
                decodeBase64URL(XCTUnwrap(object["trusted_public_key"] as? String, file: file, line: line)),
                file: file, line: line
            ),
            envelopeObject: XCTUnwrap(object["envelope"] as? [String: Any], file: file, line: line)
        )
    }

    var envelopeData: Data {
        get throws { try JSONSerialization.data(withJSONObject: envelopeObject) }
    }

    /// The same envelope with a corrupted signature — authentication must fail before decoding.
    var tamperedEnvelopeObject: [String: Any] {
        var tampered = envelopeObject
        let signature = tampered["signature"] as? String ?? ""
        tampered["signature"] = "A" + signature.dropFirst()
        return tampered
    }

    func verifier() throws -> NativeSignedPolicyVerifier {
        try NativeSignedPolicyVerifier(
            expectedInstanceID: instanceID, trustedKeys: [keyID: publicKey]
        )
    }

    func verifiedSnapshot() throws -> VerifiedNativeFastPathSnapshot {
        try verifier().verify(envelopeData: envelopeData, nowUnixMilliseconds: verificationTime)
    }

    /// The single session the fixture's policy describes.
    func sessionPolicy() throws -> NativeSessionEnforcementPolicy {
        let snapshot = try verifiedSnapshot()
        return try XCTUnwrap(snapshot.sessions.first)
    }

    /// An in-memory control service with generation 42 already installed, plus its fast-path
    /// state. Each caller gets its own, so no test depends on another having run.
    func installedControl(
        metrics: NativeAuthorizationMetrics? = nil
    ) throws -> (control: NativeEndpointControlService, state: NativeFastPathPolicyState) {
        let policyVerifier = try verifier()
        let control: NativeEndpointControlService
        if let metrics {
            control = NativeEndpointControlService.inMemoryForTesting(
                policyVerifier: policyVerifier, authorizationMetrics: metrics
            )
        } else {
            control = NativeEndpointControlService.inMemoryForTesting(policyVerifier: policyVerifier)
        }
        let reply = controlReply(control.handleForTesting(
            requestData: try controlRequest(
                id: "install-42", operation: "install_policy", envelope: envelopeObject
            ),
            nowUnixMilliseconds: verificationTime
        ))
        XCTAssertReplyCode(reply, "ok", "fixture install failed")
        return (control, try XCTUnwrap(control.authorizationState()))
    }

    /// A temporary directory removed when `test` returns.
    func withTemporaryDirectory<T>(_ body: (URL) throws -> T) throws -> T {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "vigil-endpoint-test-\(UUID().uuidString)", isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        return try body(directory)
    }
}

// MARK: - Doubles

enum RejectingGenerationStoreError: Error {
    case rejected
}

/// A generation store whose commit always fails, standing in for a full or unwritable disk.
final class RejectingGenerationStore: NativeGenerationStore, @unchecked Sendable {
    func currentGeneration() throws -> UInt64 { 0 }
    func commit(_: UInt64) throws { throw RejectingGenerationStoreError.rejected }
}

// MARK: - Concurrency helpers

final class ReplyCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var replies: [[String: Any]] = []

    func append(_ reply: [String: Any]) {
        lock.lock()
        replies.append(reply)
        lock.unlock()
    }

    func snapshot() -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        return replies
    }
}

final class XPCResponseWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var response: Data?

    func receive(_ message: xpc_object_t) {
        var length = 0
        let copied: Data?
        if xpc_get_type(message) == XPC_TYPE_DICTIONARY,
           let bytes = xpc_dictionary_get_data(message, "response", &length), length > 0
        {
            copied = Data(bytes: bytes, count: length)
        } else {
            copied = nil
        }
        lock.lock()
        response = copied
        lock.unlock()
        semaphore.signal()
    }

    func wait(seconds: Double) -> Data? {
        guard semaphore.wait(timeout: .now() + seconds) == .success else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return response
    }
}

final class XPCInvalidationWaiter: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)

    func receive(_ message: xpc_object_t) {
        if xpc_get_type(message) == XPC_TYPE_ERROR { semaphore.signal() }
    }

    func wait(seconds: Double) -> Bool {
        semaphore.wait(timeout: .now() + seconds) == .success
    }
}

final class NativeControlClientWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var result: Result<Data, NativeXPCControlClientError>?
    private var completionCount = 0

    func receive(_ received: Result<Data, NativeXPCControlClientError>) {
        lock.lock()
        completionCount += 1
        if result == nil {
            result = received
            semaphore.signal()
        }
        lock.unlock()
    }

    func wait(seconds: Double) -> Result<Data, NativeXPCControlClientError>? {
        guard semaphore.wait(timeout: .now() + seconds) == .success else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return result
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return completionCount
    }
}

final class XPCTestPeerHandle: @unchecked Sendable {
    let connection: xpc_connection_t
    init(_ connection: xpc_connection_t) { self.connection = connection }
}

/// An XPC peer that answers only after the client's deadline has passed.
final class XPCSlowServer: @unchecked Sendable {
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "com.vigil.security.endpoint.black-hole-check")
    private let listener: xpc_connection_t
    private var peers: [XPCTestPeerHandle] = []

    init() {
        listener = xpc_connection_create(nil, queue)
        xpc_connection_set_event_handler(listener) { [weak self] event in
            self?.accept(event)
        }
        xpc_connection_activate(listener)
    }

    func endpoint() -> xpc_endpoint_t { xpc_endpoint_create(listener) }

    func stop() {
        lock.lock()
        let activePeers = peers
        peers.removeAll(keepingCapacity: false)
        lock.unlock()
        for peer in activePeers { xpc_connection_cancel(peer.connection) }
        xpc_connection_cancel(listener)
    }

    private func accept(_ event: xpc_object_t) {
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else { return }
        let peer = XPCTestPeerHandle(event)
        lock.lock()
        peers.append(peer)
        lock.unlock()
        xpc_connection_set_event_handler(event) { message in
            guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
                  let reply = xpc_dictionary_create_reply(message)
            else { return }
            // Deliberately reply after the client's deadline. The late response must not
            // produce a second completion or make the timed-out connection reusable.
            usleep(200_000)
            let response = Data("{}".utf8)
            response.withUnsafeBytes { bytes in
                xpc_dictionary_set_data(reply, "response", bytes.baseAddress, bytes.count)
            }
            xpc_connection_send_message(peer.connection, reply)
        }
        xpc_connection_activate(event)
    }

    deinit { stop() }
}

/// This test bundle's own designated requirement, so a listener can be pointed at a peer
/// identity that genuinely matches the caller.
func currentDesignatedRequirementText() throws -> String {
    let flags = SecCSFlags(rawValue: 0)
    var dynamicCode: SecCode?
    guard SecCodeCopySelf(flags, &dynamicCode) == errSecSuccess, let dynamicCode else {
        throw NativeXPCPeerVerificationError.noProcessIdentity
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(dynamicCode, flags, &staticCode) == errSecSuccess, let staticCode
    else {
        throw NativeXPCPeerVerificationError.noProcessIdentity
    }
    var requirement: SecRequirement?
    guard SecCodeCopyDesignatedRequirement(staticCode, flags, &requirement) == errSecSuccess,
          let requirement
    else {
        throw NativeXPCPeerVerificationError.invalidRequirement
    }
    var text: CFString?
    guard SecRequirementCopyString(requirement, flags, &text) == errSecSuccess, let text else {
        throw NativeXPCPeerVerificationError.invalidRequirement
    }
    return text as String
}
