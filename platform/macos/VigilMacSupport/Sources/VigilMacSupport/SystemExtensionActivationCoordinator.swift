@preconcurrency import Combine
import Foundation
@preconcurrency import SystemExtensions

@MainActor
public final class SystemExtensionActivationCoordinator: NSObject, ObservableObject {
    @Published public private(set) var state: SystemExtensionActivationState = .unknown

    public let extensionIdentifier: String

    private var currentRequest: OSSystemExtensionRequest?
    private var currentOperation: SystemExtensionOperation?

    public init(extensionIdentifier: String) {
        self.extensionIdentifier = extensionIdentifier
        super.init()
    }

    @discardableResult
    public func activate() -> Bool {
        submit(operation: .activate)
    }

    @discardableResult
    public func deactivate() -> Bool {
        submit(operation: .deactivate)
    }

    @discardableResult
    public func refreshStatus() -> Bool {
        submit(operation: .inspect)
    }

    private func submit(operation: SystemExtensionOperation) -> Bool {
        guard validIdentifier(extensionIdentifier) else {
            state = .failed(SystemExtensionFailure(reason: .invalidConfiguration))
            return false
        }
        guard currentRequest == nil else {
            return false
        }

        let request: OSSystemExtensionRequest
        switch operation {
        case .activate:
            request = .activationRequest(
                forExtensionWithIdentifier: extensionIdentifier,
                queue: .main
            )
        case .deactivate:
            request = .deactivationRequest(
                forExtensionWithIdentifier: extensionIdentifier,
                queue: .main
            )
        case .inspect:
            request = .propertiesRequest(
                forExtensionWithIdentifier: extensionIdentifier,
                queue: .main
            )
        }

        currentOperation = operation
        currentRequest = request
        request.delegate = self
        state = .submitting(operation)
        OSSystemExtensionManager.shared.submitRequest(request)
        return true
    }

    private func validIdentifier(_ identifier: String) -> Bool {
        !identifier.isEmpty && identifier.utf8.count <= 255 &&
            identifier.split(separator: ".").count >= 3 &&
            identifier.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }
    }

    private func finish(_ request: OSSystemExtensionRequest) -> SystemExtensionOperation? {
        guard currentRequest === request else {
            return nil
        }
        let operation = currentOperation
        currentRequest = nil
        currentOperation = nil
        return operation
    }
}

extension SystemExtensionActivationCoordinator: @preconcurrency OSSystemExtensionRequestDelegate {
    public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension candidate: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        guard currentRequest === request else {
            return .cancel
        }
        let decision = SystemExtensionLifecycle.replacementDecision(
            expectedIdentifier: extensionIdentifier,
            existing: SystemExtensionVersion(
                bundleIdentifier: existing.bundleIdentifier,
                shortVersion: existing.bundleShortVersion,
                buildVersion: existing.bundleVersion
            ),
            candidate: SystemExtensionVersion(
                bundleIdentifier: candidate.bundleIdentifier,
                shortVersion: candidate.bundleShortVersion,
                buildVersion: candidate.bundleVersion
            )
        )
        return decision == .replace ? .replace : .cancel
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        guard currentRequest === request, currentOperation == .activate else {
            return
        }
        state = .awaitingUserApproval
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        guard let operation = finish(request) else {
            return
        }
        switch result {
        case .completed:
            switch operation {
            case .activate: state = .active(version: nil)
            case .deactivate: state = .inactive
            case .inspect: break
            }
        case .willCompleteAfterReboot:
            state = .rebootRequired(operation)
        @unknown default:
            state = .failed(SystemExtensionFailure(reason: .unknown))
        }
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard finish(request) != nil else {
            return
        }
        state = .failed(SystemExtensionLifecycle.failure(for: error as NSError))
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        foundProperties properties: [OSSystemExtensionProperties]
    ) {
        guard finish(request) == .inspect else {
            return
        }
        let matches = properties.filter { $0.bundleIdentifier == extensionIdentifier }
        guard matches.count <= 1 else {
            state = .failed(SystemExtensionFailure(reason: .ambiguousStatus))
            return
        }
        guard let extensionProperties = matches.first else {
            state = .inactive
            return
        }
        if extensionProperties.isUninstalling {
            state = .uninstalling
        } else if extensionProperties.isAwaitingUserApproval {
            state = .awaitingUserApproval
        } else if extensionProperties.isEnabled {
            state = .active(
                version: "\(extensionProperties.bundleShortVersion) (\(extensionProperties.bundleVersion))"
            )
        } else {
            state = .inactive
        }
    }
}
