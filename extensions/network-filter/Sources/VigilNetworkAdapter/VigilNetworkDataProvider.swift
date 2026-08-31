import Darwin
import Foundation
import Network
import NetworkExtension

/// Public Network Extension boundary for the bounded native policy state.
///
/// This class compiles against the installed public SDK. It is not an extension bundle and cannot
/// be activated by this Swift package. Policy must be verified before installation; no callback
/// performs file, DNS, database, XPC, UI, or logging work.
public final class VigilNetworkDataProvider: NEFilterDataProvider {
    private let policyState: NativeNetworkPolicyState
    private let lifecycle: NativeNetworkProviderLifecycle

    public override init() {
        let state = NativeNetworkPolicyState()
        policyState = state
        lifecycle = NativeNetworkProviderLifecycle(state: state)
        super.init()
    }

    public init(policyState: NativeNetworkPolicyState) {
        self.policyState = policyState
        lifecycle = NativeNetworkProviderLifecycle(state: policyState)
        super.init()
    }

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let now = currentUnixMilliseconds()
        guard let now else {
            completionHandler(startupError(.policyUnavailable))
            return
        }
        do {
            _ = try lifecycle.start(
                vendorConfiguration: filterConfiguration.vendorConfiguration ?? [:],
                nowUnixMilliseconds: now,
                containerResolver: {
                    FileManager.default.containerURL(
                        forSecurityApplicationGroupIdentifier: $0
                    )
                }
            )
            completionHandler(nil)
        } catch let error as NativeNetworkProviderLifecycleError {
            completionHandler(startupError(error))
        } catch {
            completionHandler(startupError(.policyUnavailable))
        }
    }

    public override func stopFilter(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        _ = reason
        lifecycle.stop()
        completionHandler()
    }

    public func installVerifiedPolicy(_ snapshot: VerifiedNativeNetworkSnapshot) throws {
        try policyState.install(snapshot)
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let token = processAuditToken(flow)
        let observedAt = currentUnixMilliseconds()
        guard let projected = project(flow: flow, processToken: token) else {
            return verdict(for: policyState.decideIncomplete(
                process: token, observedAtUnixMilliseconds: observedAt
            ))
        }
        return verdict(for: policyState.decide(projected))
    }

    private func verdict(for decision: NativeNetworkDecision) -> NEFilterNewFlowVerdict {
        switch decision.action {
        case .allow:
            return .allow()
        case .drop:
            return .drop()
        case .pause:
            return .pause()
        }
    }

    private func processAuditToken(_ flow: NEFilterFlow) -> Data? {
        // sourceProcessAuditToken identifies the process that created the flow. The application
        // token is only a compatibility fallback and is never replaced by a caller-supplied PID.
        flow.sourceProcessAuditToken ?? flow.sourceAppAuditToken
    }

    private func project(flow: NEFilterFlow, processToken: Data?) -> NativeNetworkFlow? {
        guard let processToken, processToken.count == 32,
              let socket = flow as? NEFilterSocketFlow,
              let networkProtocol = protocolForSocket(socket),
              let endpoint = remoteEndpoint(socket),
              case let .hostPort(host, port) = endpoint,
              let remoteIP = numericAddress(host)
        else {
            return nil
        }
        let direction: NativeFlowDirection = flow.direction == .outbound ? .outbound : .inbound
        return NativeNetworkFlow(
            process: [UInt8](processToken),
            direction: direction,
            networkProtocol: networkProtocol,
            hostname: socket.remoteHostname,
            remoteIP: remoteIP,
            remotePort: port.rawValue,
            observedAtUnixMilliseconds: currentUnixMilliseconds()
        )
    }

    private func currentUnixMilliseconds() -> Int64? {
        let now = Date().timeIntervalSince1970 * 1_000
        guard now.isFinite, now >= 0, now <= Double(Int64.max) else { return nil }
        return Int64(now)
    }

    private func startupError(_ error: NativeNetworkProviderLifecycleError) -> NSError {
        NSError(
            domain: "com.vigil.security.network.provider",
            code: error.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "VIGIL network policy is unavailable"]
        )
    }

    private func protocolForSocket(_ flow: NEFilterSocketFlow) -> NativeNetworkProtocol? {
        switch flow.socketProtocol {
        case IPPROTO_TCP: .tcp
        case IPPROTO_UDP: .udp
        default: nil
        }
    }

    private func remoteEndpoint(_ flow: NEFilterSocketFlow) -> NWEndpoint? {
        flow.remoteFlowEndpoint
    }

    private func numericAddress(_ host: NWEndpoint.Host) -> String? {
        switch host {
        case let .ipv4(address): address.debugDescription
        case let .ipv6(address): address.debugDescription
        case .name: nil
        @unknown default: nil
        }
    }
}
