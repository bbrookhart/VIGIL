import SwiftUI
import VigilMacSupport
import VigilNetworkAdapter

@main
struct VigilHostApp: App {
    @StateObject private var activationCoordinator: SystemExtensionActivationCoordinator
    private let enrollmentRuntime: ProviderHealthEnrollmentRuntime?
    private let provisioningRuntime: NetworkFilterProvisioningRuntime?

    init() {
        let identifier = Bundle.main.object(
            forInfoDictionaryKey: "VigilNetworkExtensionBundleIdentifier"
        ) as? String ?? ""
        _activationCoordinator = StateObject(
            wrappedValue: SystemExtensionActivationCoordinator(extensionIdentifier: identifier)
        )
        let appGroup = Bundle.main.object(
            forInfoDictionaryKey: "VigilApplicationGroupIdentifier"
        ) as? String ?? ""
        enrollmentRuntime = try? ProviderHealthEnrollmentRuntime(
            applicationGroupIdentifier: appGroup,
            providerBundleIdentifier: identifier
        )
        provisioningRuntime = if let enrollmentRuntime {
            try? NetworkFilterProvisioningRuntime(
                applicationGroupIdentifier: appGroup,
                providerBundleIdentifier: identifier,
                installationInstanceID: enrollmentRuntime.installationInstanceID
            )
        } else {
            nil
        }
    }

    var body: some Scene {
        WindowGroup {
            VigilReadinessView(
                activationCoordinator: activationCoordinator,
                enrollmentRuntime: enrollmentRuntime,
                provisioningRuntime: provisioningRuntime
            )
                .frame(minWidth: 680, minHeight: 430)
        }
        .windowStyle(.hiddenTitleBar)
    }
}

private struct VigilReadinessView: View {
    @ObservedObject var activationCoordinator: SystemExtensionActivationCoordinator
    let enrollmentRuntime: ProviderHealthEnrollmentRuntime?
    let provisioningRuntime: NetworkFilterProvisioningRuntime?
    @State private var enrollmentState = ProviderHealthEnrollmentState.notAttempted
    @State private var provisioningState = NetworkFilterProvisioningState.notAttempted
    @State private var provisioningInProgress = false
    @State private var policyMaintenanceCadence = NetworkPolicyMaintenanceCadence()

    // Linking this public boundary makes the containing app and adapter contract explicit.
    private let preferenceControllerType = NativeNetworkFilterPreferenceController.self

    private var health: NetworkEnforcementHealth {
        NetworkEnforcementHealthEvaluator.evaluate(
            activation: activationCoordinator.state,
            preferences: provisioningState.preferenceEvidence,
            provider: enrollmentState.providerEvidence,
            flow: .unavailable,
            nowMilliseconds: UInt64(Date().timeIntervalSince1970 * 1_000)
        )
    }

    private var presentation: HealthPresentation {
        HealthPresentation(health: health)
    }

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.025, green: 0.05, blue: 0.075),
                         Color(red: 0.04, green: 0.11, blue: 0.14)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(alignment: .leading, spacing: 24) {
                Text("LOCAL AGENT SECURITY CONTROL PLANE")
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .tracking(3.2)
                    .foregroundStyle(Color(red: 0.4, green: 0.85, blue: 0.77))
                Text("VIGIL")
                    .font(.system(size: 72, weight: .bold, design: .rounded))
                    .tracking(12)
                Rectangle()
                    .fill(Color(red: 0.4, green: 0.85, blue: 0.77))
                    .frame(height: 2)
                Text("System Extension control")
                    .font(.title2.weight(.semibold))
                Text("VIGIL combines System Extension state, exact filter preferences, authenticated provider readiness, and entitled allow/deny probes. Missing evidence can never become a healthy result.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Label(presentation.label, systemImage: presentation.symbol)
                    .font(.system(.callout, design: .monospaced, weight: .semibold))
                .foregroundStyle(presentation.color)

                Text("SYSTEM EXTENSION · \(activationCoordinator.state.summary.uppercased())")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)

                Text("PROVIDER TRUST · \(enrollmentState.summary.uppercased())")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)

                Text("FILTER PREFERENCES · \(provisioningState.summary.uppercased())")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)

                HStack(spacing: 12) {
                    Button("Refresh") {
                        activationCoordinator.refreshStatus()
                    }
                    Button("Request Activation") {
                        activationCoordinator.activate()
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Configure Filter") {
                        Task { await configureFilter() }
                    }
                    .disabled(
                        activationCoordinator.state.requestInFlight
                            || provisioningInProgress
                            || provisioningRuntime == nil
                    )
                    Button("Request Deactivation", role: .destructive) {
                        activationCoordinator.deactivate()
                    }
                }
                .disabled(activationCoordinator.state.requestInFlight)

                Spacer()
                Text("Preference boundary linked · \(String(describing: preferenceControllerType))")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .padding(52)
        }
        .preferredColorScheme(.dark)
        .task {
            activationCoordinator.refreshStatus()
            while !Task.isCancelled {
                await refreshProviderEnrollment()
                await refreshFilterPreferences()
                await maintainFilterPolicyIfNeeded()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    private func refreshProviderEnrollment() async {
        guard let enrollmentRuntime else {
            enrollmentState = .refused(.configurationUnavailable)
            return
        }
        let activation = activationCoordinator.state
        let now = Date().timeIntervalSince1970 * 1_000
        guard now.isFinite, now >= 0, now <= Double(Int64.max) else {
            enrollmentState = .refused(.evidenceRejected)
            return
        }
        enrollmentState = await Task.detached {
            enrollmentRuntime.refresh(
                activation: activation,
                nowUnixMilliseconds: Int64(now)
            )
        }.value
    }

    private func refreshFilterPreferences() async {
        guard let provisioningRuntime else {
            provisioningState = .refused(.configurationUnavailable)
            return
        }
        guard !provisioningInProgress else { return }
        provisioningState = await provisioningRuntime.refresh()
    }

    private func configureFilter() async {
        guard let provisioningRuntime else {
            provisioningState = .refused(.configurationUnavailable)
            return
        }
        let now = Date().timeIntervalSince1970 * 1_000
        guard now.isFinite, now >= 0, now <= Double(Int64.max) else {
            provisioningState = .refused(.policyUnavailable)
            return
        }
        provisioningInProgress = true
        defer { provisioningInProgress = false }
        provisioningState = await provisioningRuntime.installAndEnable(
            activation: activationCoordinator.state,
            nowUnixMilliseconds: Int64(now)
        )
        if case .enabled = provisioningState {
            _ = policyMaintenanceCadence.shouldAttempt(nowUnixMilliseconds: Int64(now))
        }
    }

    private func maintainFilterPolicyIfNeeded() async {
        guard let provisioningRuntime, !provisioningInProgress,
              case .active = activationCoordinator.state,
              provisioningState.preferenceEvidence == NetworkFilterPreferenceEvidence(.enabled)
        else { return }
        let now = Date().timeIntervalSince1970 * 1_000
        guard now.isFinite, now >= 0, now <= Double(Int64.max) else {
            provisioningState = .refused(.policyUnavailable)
            return
        }
        let milliseconds = Int64(now)
        guard policyMaintenanceCadence.shouldAttempt(nowUnixMilliseconds: milliseconds) else {
            return
        }
        provisioningInProgress = true
        defer { provisioningInProgress = false }
        provisioningState = await provisioningRuntime.maintainPolicy(
            activation: activationCoordinator.state,
            nowUnixMilliseconds: milliseconds
        )
    }
}

private struct HealthPresentation {
    let label: String
    let symbol: String
    let color: Color

    init(health: NetworkEnforcementHealth) {
        let reason = health.reason.rawValue.uppercased()
        switch health.posture {
        case .fullyEnforced:
            (label, symbol, color) = ("NETWORK · FULLY ENFORCED · GENERATION \(health.verifiedPolicyGeneration ?? 0)", "checkmark.shield.fill", .mint)
        case .degraded:
            (label, symbol, color) = ("NETWORK · DEGRADED · \(reason)", "exclamationmark.shield", .orange)
        case .observeOnly:
            (label, symbol, color) = ("NETWORK · OBSERVE ONLY · \(reason)", "shield.slash", .red)
        case .broken:
            (label, symbol, color) = ("NETWORK · BROKEN · \(reason)", "xmark.shield.fill", .red)
        }
    }
}

private extension SystemExtensionActivationState {
    var summary: String {
        switch self {
        case .unknown: "status unknown"
        case let .submitting(operation): "\(operation.rawValue) requested"
        case .awaitingUserApproval: "awaiting user approval"
        case let .active(version): "active\(version.map { " · \($0)" } ?? "") · enforcement unverified"
        case .inactive: "not installed"
        case .uninstalling: "deactivating"
        case let .rebootRequired(operation): "reboot required after \(operation.rawValue)"
        case let .failed(failure): "request failed · \(failure.reason.rawValue)"
        }
    }
}

private extension ProviderHealthEnrollmentState {
    var summary: String {
        switch self {
        case .notAttempted: "not attempted"
        case let .enrolled(keyID, _): "enrolled · \(keyID)"
        case let .alreadyPinned(keyID, _): "verified · \(keyID)"
        case let .refused(reason): "unavailable · \(reason.rawValue)"
        }
    }
}

private extension NetworkFilterProvisioningState {
    var summary: String {
        switch self {
        case .notAttempted: "not attempted"
        case let .status(status): String(describing: status)
        case let .enabled(generation): "enabled · generation \(generation)"
        case let .refused(reason): "unavailable · \(reason.rawValue)"
        }
    }
}
