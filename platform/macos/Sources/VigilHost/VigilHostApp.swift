import SwiftUI
import VigilNetworkAdapter

@main
struct VigilHostApp: App {
    var body: some Scene {
        WindowGroup {
            VigilReadinessView()
                .frame(minWidth: 680, minHeight: 430)
        }
        .windowStyle(.hiddenTitleBar)
    }
}

private struct VigilReadinessView: View {
    // Linking this public boundary makes the containing app and adapter contract explicit.
    private let preferenceControllerType = NativeNetworkFilterPreferenceController.self

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
                Text("Application boundary ready")
                    .font(.title2.weight(.semibold))
                Text("The containing app and Network System Extension targets compile. Signing, entitlement provisioning, activation, and device-observed enforcement are not yet available.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Label("NETWORK EXTENSION · NOT INSTALLED", systemImage: "shield.slash")
                    .font(.system(.callout, design: .monospaced, weight: .semibold))
                    .foregroundStyle(Color(red: 1.0, green: 0.48, blue: 0.48))
                Spacer()
                Text(String(describing: preferenceControllerType))
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .padding(52)
        }
        .preferredColorScheme(.dark)
    }
}
