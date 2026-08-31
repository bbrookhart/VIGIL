import Foundation
import Testing
import VigilNetworkAdapter
@testable import VigilMacSupport

@Suite("Network filter provisioning orchestration")
@MainActor
struct NetworkFilterProvisioningTests {
    @Test("preferences cannot be enabled before extension activation")
    func inactiveExtensionRefusesMutation() async {
        let performer = StubFilterProvisioningPerformer()
        let runtime = NetworkFilterProvisioningRuntime(
            installationInstanceID: "network-instance-1",
            performer: performer
        )

        let state = await runtime.installAndEnable(
            activation: .inactive,
            nowUnixMilliseconds: 1_000_000
        )

        #expect(state == .refused(.extensionNotActive))
        #expect(performer.installCalls == 0)
    }

    @Test("verified enabled preferences retain the published policy generation")
    func enabledPreferencesCarryGeneration() async {
        let performer = StubFilterProvisioningPerformer(
            installResult: .success((.enabled, 42))
        )
        let runtime = NetworkFilterProvisioningRuntime(
            installationInstanceID: "network-instance-1",
            performer: performer
        )

        let state = await runtime.installAndEnable(
            activation: .active(version: "1.0.0 (1)"),
            nowUnixMilliseconds: 1_000_000
        )

        #expect(state == .enabled(policyGeneration: 42))
        #expect(state.preferenceEvidence == NetworkFilterPreferenceEvidence(.enabled))
        #expect(performer.installCalls == 1)
    }

    @Test("a non-enabled round trip is never reported as configured")
    func disabledRoundTripIsRefused() async {
        let performer = StubFilterProvisioningPerformer(
            installResult: .success((.disabled, 42))
        )
        let runtime = NetworkFilterProvisioningRuntime(
            installationInstanceID: "network-instance-1",
            performer: performer
        )

        #expect(await runtime.installAndEnable(
            activation: .active(version: nil),
            nowUnixMilliseconds: 1_000_000
        ) == .refused(.preferencesUnavailable))
    }

    @Test("status refresh preserves absent disabled enabled and drifted states")
    func refreshPreservesExactStatus() async {
        for status in [
            NativeNetworkFilterPreferenceStatus.absent,
            .disabled,
            .enabled,
            .configurationDrifted(enabled: true),
        ] {
            let performer = StubFilterProvisioningPerformer(statusResult: .success(status))
            let runtime = NetworkFilterProvisioningRuntime(
                installationInstanceID: "network-instance-1",
                performer: performer
            )
            #expect(await runtime.refresh() == .status(status))
        }
    }

    @Test("automatic maintenance cannot publish while the extension is inactive")
    func inactiveMaintenanceRefusesPublication() async {
        let performer = StubFilterProvisioningPerformer()
        let runtime = NetworkFilterProvisioningRuntime(
            installationInstanceID: "network-instance-1",
            performer: performer
        )

        #expect(await runtime.maintainPolicy(
            activation: .inactive,
            nowUnixMilliseconds: 1_000_000
        ) == .refused(.extensionNotActive))
        #expect(performer.maintainCalls == 0)
    }

    @Test("automatic maintenance requires exact enabled preferences")
    func maintenancePreservesNonEnabledStatus() async {
        let performer = StubFilterProvisioningPerformer(
            maintainResult: .success((.configurationDrifted(enabled: true), nil))
        )
        let runtime = NetworkFilterProvisioningRuntime(
            installationInstanceID: "network-instance-1",
            performer: performer
        )

        #expect(await runtime.maintainPolicy(
            activation: .active(version: nil),
            nowUnixMilliseconds: 1_000_000
        ) == .status(.configurationDrifted(enabled: true)))
        #expect(performer.maintainCalls == 1)
    }

    @Test("automatic maintenance exposes the current signed policy generation")
    func maintenanceCarriesGeneration() async {
        let performer = StubFilterProvisioningPerformer(
            maintainResult: .success((.enabled, 43))
        )
        let runtime = NetworkFilterProvisioningRuntime(
            installationInstanceID: "network-instance-1",
            performer: performer
        )

        let state = await runtime.maintainPolicy(
            activation: .active(version: "1.0.0 (1)"),
            nowUnixMilliseconds: 1_000_000
        )
        #expect(state == .enabled(policyGeneration: 43))
        #expect(state.preferenceEvidence == NetworkFilterPreferenceEvidence(.enabled))
    }
}

@MainActor
private final class StubFilterProvisioningPerformer: NetworkFilterProvisioningPerforming {
    private let statusResult: Result<NativeNetworkFilterPreferenceStatus, Error>
    private let installResult: Result<(NativeNetworkFilterPreferenceStatus, UInt64), Error>
    private let maintainResult: Result<(NativeNetworkFilterPreferenceStatus, UInt64?), Error>
    private(set) var installCalls = 0
    private(set) var maintainCalls = 0

    init(
        statusResult: Result<NativeNetworkFilterPreferenceStatus, Error> = .success(.absent),
        installResult: Result<(
            NativeNetworkFilterPreferenceStatus, UInt64
        ), Error> = .success((.enabled, 1)),
        maintainResult: Result<(
            NativeNetworkFilterPreferenceStatus, UInt64?
        ), Error> = .success((.enabled, 1))
    ) {
        self.statusResult = statusResult
        self.installResult = installResult
        self.maintainResult = maintainResult
    }

    func status() async throws -> NativeNetworkFilterPreferenceStatus {
        try statusResult.get()
    }

    func install(nowUnixMilliseconds: Int64) async throws
        -> (NativeNetworkFilterPreferenceStatus, UInt64)
    {
        _ = nowUnixMilliseconds
        installCalls += 1
        return try installResult.get()
    }

    func maintain(nowUnixMilliseconds: Int64) async throws
        -> (NativeNetworkFilterPreferenceStatus, UInt64?)
    {
        _ = nowUnixMilliseconds
        maintainCalls += 1
        return try maintainResult.get()
    }
}
