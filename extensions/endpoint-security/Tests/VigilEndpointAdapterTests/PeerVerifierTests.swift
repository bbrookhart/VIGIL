import XCTest
import XPC

@testable import VigilEndpointAdapter

/// XPC peer identity. A Mach service name is not an identity — anything on the host can send
/// to it — so the listener authenticates the peer's code signature instead.
final class PeerVerifierTests: XCTestCase {
    func test_accepts_a_valid_code_requirement() throws {
        XCTAssertNoThrow(
            try NativeXPCPeerVerifier(
                requirementText: "identifier \"com.vigil.security.daemon\" and anchor apple generic"
            )
        )
    }

    func test_malformed_requirement_is_refused_at_construction() {
        // Failing here means production startup fails before accepting any XPC message,
        // rather than silently admitting every peer.
        XCTAssertThrowsError(
            try NativeXPCPeerVerifier(requirementText: "not a code requirement")
        ) { error in
            XCTAssertEqual(error as? NativeXPCPeerVerificationError, .invalidRequirement)
        }
    }

    func test_message_without_a_kernel_associated_sender_is_refused() throws {
        let verifier = try NativeXPCPeerVerifier(
            requirementText: "identifier \"com.vigil.security.daemon\" and anchor apple generic"
        )
        // A dictionary manufactured in-process carries no sender audit token. Trusting a
        // self-reported identity here would defeat the whole check.
        XCTAssertThrowsError(try verifier.verify(message: xpc_dictionary_create_empty())) { error in
            XCTAssertEqual(error as? NativeXPCPeerVerificationError, .noProcessIdentity)
        }
    }
}
