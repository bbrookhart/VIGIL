import CryptoKit
import Foundation
import Testing
import VigilNetworkAdapter
@testable import VigilMacSupport

@Suite("Provider health enrollment gate")
struct ProviderHealthEnrollmentTests {
    @Test("enrollment is impossible until the OS reports the extension active", arguments: [
        SystemExtensionActivationState.unknown,
        .inactive,
        .awaitingUserApproval,
        .rebootRequired(.activate),
        .failed(.init(reason: .missingEntitlement)),
    ])
    func inactiveStateRefusesEnrollment(state: SystemExtensionActivationState) {
        let performer = StubEnrollmentPerformer(result: .failure(TestEnrollmentError.rejected))
        let outcome = ProviderHealthEnrollmentController(performer: performer).enroll(
            activation: state,
            nowUnixMilliseconds: 1_000_000
        )
        #expect(outcome == .refused(.extensionNotActive))
        #expect(performer.calls == 0)
    }

    @Test("active state still cannot turn rejected evidence into a pin")
    func rejectedEvidenceStaysRefused() {
        let performer = StubEnrollmentPerformer(result: .failure(TestEnrollmentError.rejected))
        let outcome = ProviderHealthEnrollmentController(performer: performer).enroll(
            activation: .active(version: "1.0.0 (1)"),
            nowUnixMilliseconds: 1_000_000
        )
        #expect(outcome == .refused(.evidenceRejected))
        #expect(performer.calls == 1)
    }

    @Test("identity changes are surfaced as an explicit refusal")
    func identityChangeStaysRefused() {
        let performer = StubEnrollmentPerformer(result: .failure(
            NativeNetworkProviderHealthEnrollmentError.identityChanged
        ))
        let outcome = ProviderHealthEnrollmentController(performer: performer).enroll(
            activation: .active(version: nil),
            nowUnixMilliseconds: 1_000_000
        )
        #expect(outcome == .refused(.identityChanged))
    }

    @Test("refused enrollment exposes no provider-ready evidence")
    func refusedEnrollmentHasNoProviderEvidence() {
        #expect(
            ProviderHealthEnrollmentState.refused(.evidenceRejected).providerEvidence
                == .unavailable
        )
    }

    @Test("runtime preserves its durable installation identity and activation gate")
    func runtimeBindsInstallationIdentity() {
        let performer = StubEnrollmentPerformer(result: .failure(TestEnrollmentError.rejected))
        let controller = ProviderHealthEnrollmentController(performer: performer)
        let runtime = ProviderHealthEnrollmentRuntime(
            installationInstanceID: "11111111-1111-1111-1111-111111111111",
            controller: controller
        )

        #expect(runtime.installationInstanceID == "11111111-1111-1111-1111-111111111111")
        #expect(runtime.refresh(
            activation: .inactive,
            nowUnixMilliseconds: 1_000_000
        ) == .refused(.extensionNotActive))
        #expect(performer.calls == 0)
    }
}

private enum TestEnrollmentError: Error {
    case rejected
}

private final class StubEnrollmentPerformer: ProviderHealthEnrollmentPerforming,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let result: Result<(
        NativeNetworkProviderHealthPinResult,
        VerifiedNativeNetworkProviderHealth
    ), Error>
    private(set) var calls = 0

    init(result: Result<(
        NativeNetworkProviderHealthPinResult,
        VerifiedNativeNetworkProviderHealth
    ), Error>) {
        self.result = result
    }

    func verifyAndPin(nowUnixMilliseconds: Int64) throws
        -> (NativeNetworkProviderHealthPinResult, VerifiedNativeNetworkProviderHealth)
    {
        _ = nowUnixMilliseconds
        lock.withLock { calls += 1 }
        return try result.get()
    }
}
