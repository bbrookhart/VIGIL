import CryptoKit
import Foundation
import XCTest

@testable import VigilNetworkAdapter

/// The Rust-generated signed policy that both sides of the wire contract are checked against.
///
/// `make contract-fixtures` regenerates `Resources/network_policy_v1.json` from
/// `vigil-network`. If a change to the Rust encoder breaks these tests, the encoder and this
/// adapter have diverged — that is the point of checking the fixture in.
struct NetworkPolicyFixture: Decodable {
    let verificationTimeUnixMilliseconds: Int64
    let expectedInstanceID: String
    let trustedKeyID: String
    let trustedPublicKey: String
    let envelope: Envelope

    enum CodingKeys: String, CodingKey {
        case verificationTimeUnixMilliseconds = "verification_time_unix_ms"
        case expectedInstanceID = "expected_instance_id"
        case trustedKeyID = "trusted_key_id"
        case trustedPublicKey = "trusted_public_key"
        case envelope
    }

    struct Envelope: Codable {
        var format: String
        var algorithm: String
        var keyID: String
        var payload: String
        var signature: String

        enum CodingKeys: String, CodingKey {
            case format, algorithm, payload, signature
            case keyID = "key_id"
        }
    }

    static func load(file: StaticString = #filePath, line: UInt = #line) throws -> NetworkPolicyFixture {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "network_policy_v1", withExtension: "json"),
            "network policy fixture is missing from the test bundle",
            file: file, line: line
        )
        return try JSONDecoder().decode(NetworkPolicyFixture.self, from: Data(contentsOf: url))
    }

    var publicKeyBytes: Data {
        get throws { try XCTUnwrap(decodeBase64URL(trustedPublicKey)) }
    }

    /// A verifier trusting exactly the fixture's key, bound to the fixture's instance.
    func verifier() throws -> NativeSignedNetworkPolicyVerifier {
        try NativeSignedNetworkPolicyVerifier(
            expectedInstanceID: expectedInstanceID,
            trustedKeys: [trustedKeyID: publicKeyBytes]
        )
    }

    /// Policy state with the fixture's snapshot already installed.
    func installedState() throws -> NativeNetworkPolicyState {
        let verified = try verifier().verify(
            envelopeData: encode(envelope),
            nowUnixMilliseconds: verificationTimeUnixMilliseconds
        )
        let state = NativeNetworkPolicyState()
        try state.install(verified)
        return state
    }

    func encode(_ envelope: Envelope) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        // The fixture is a value we just decoded; re-encoding it cannot fail.
        return try! encoder.encode(envelope)
    }
}

func decodeBase64URL(_ value: String) -> Data? {
    var standard = value.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    standard.append(String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4))
    return Data(base64Encoded: standard)
}

/// The managed process the fixture's policy is written for.
let managedProcessToken = [UInt8](repeating: 5, count: 32)

func outboundFlow(
    process: [UInt8] = managedProcessToken,
    hostname: String?,
    remoteIP: String,
    remotePort: UInt16 = 443,
    at observedAt: Int64
) -> NativeNetworkFlow {
    NativeNetworkFlow(
        process: process,
        direction: .outbound,
        networkProtocol: .tcp,
        hostname: hostname,
        remoteIP: remoteIP,
        remotePort: remotePort,
        observedAtUnixMilliseconds: observedAt
    )
}
