import Foundation

private let endpointControlProtocol = "vigil.endpoint-control/v1"
private let maximumControlRequestBytes = 2 * 1_024 * 1_024

public enum NativeEndpointControlCode: String, Sendable {
    case ok
    case unauthenticatedPeer = "unauthenticated_peer"
    case malformedRequest = "malformed_request"
    case unsupportedProtocol = "unsupported_protocol"
    case unsupportedOperation = "unsupported_operation"
    case policyRejected = "policy_rejected"
    case staleGeneration = "stale_generation"
    case notReady = "not_ready"
    case attributionConflict = "attribution_conflict"
    case internalFailure = "internal_failure"
}

/// Strict operation layer for the future daemon-to-extension XPC listener.
///
/// Transport code must first call `NativeXPCPeerVerifier.verify(message:)`; the production entry
/// point requires the resulting marker. Policy authentication, parsing, and compilation happen
/// before the state lock is acquired. Installation durably advances the generation high-water mark,
/// then swaps all compact state under one lock and emits an acknowledgement only after success.
/// Root attribution accepts only a full audit token bound to the installed generation; no external
/// production state-binding method exists. This service is not called from an ES callback.
public final class NativeEndpointControlService: @unchecked Sendable {
    private let lock = NSLock()
    private let policyVerifier: NativeSignedPolicyVerifier
    private let generationStore: any NativeGenerationStore
    public let authorizationMetrics: NativeAuthorizationMetrics
    private var persistedGeneration: UInt64
    private var state: NativeFastPathPolicyState?

    private init(
        policyVerifier: NativeSignedPolicyVerifier,
        generationStore: any NativeGenerationStore,
        authorizationMetrics: NativeAuthorizationMetrics,
        persistedGeneration: UInt64
    ) {
        self.policyVerifier = policyVerifier
        self.generationStore = generationStore
        self.authorizationMetrics = authorizationMetrics
        self.persistedGeneration = persistedGeneration
    }

    public convenience init(
        policyVerifier: NativeSignedPolicyVerifier,
        generationStore: any NativeGenerationStore,
        authorizationMetrics: NativeAuthorizationMetrics = NativeAuthorizationMetrics()
    ) throws {
        let persistedGeneration = try generationStore.currentGeneration()
        self.init(
            policyVerifier: policyVerifier,
            generationStore: generationStore,
            authorizationMetrics: authorizationMetrics,
            persistedGeneration: persistedGeneration
        )
    }

    /// Entitlement-free checks may opt into process-local state without implying restart safety.
    public static func inMemoryForTesting(
        policyVerifier: NativeSignedPolicyVerifier,
        authorizationMetrics: NativeAuthorizationMetrics = NativeAuthorizationMetrics()
    ) -> NativeEndpointControlService {
        NativeEndpointControlService(
            policyVerifier: policyVerifier,
            generationStore: NativeInMemoryGenerationStore(),
            authorizationMetrics: authorizationMetrics,
            persistedGeneration: 0
        )
    }

    public func handle(
        requestData: Data,
        from _: VerifiedNativeXPCPeer,
        nowUnixMilliseconds: Int64
    ) -> Data {
        handleAuthenticatedRequest(
            requestData,
            nowUnixMilliseconds: nowUnixMilliseconds
        )
    }

    /// Entitlement-free protocol checks cannot manufacture a kernel-associated XPC message.
    public func handleForTesting(
        requestData: Data,
        nowUnixMilliseconds: Int64
    ) -> Data {
        handleAuthenticatedRequest(
            requestData,
            nowUnixMilliseconds: nowUnixMilliseconds
        )
    }

    public func authorizationState() -> NativeFastPathPolicyState? {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    func fixedRejection(
        _ code: NativeEndpointControlCode,
        nowUnixMilliseconds: Int64
    ) -> Data {
        Self.reply(
            requestID: "invalid",
            code: code,
            ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
            generation: installedGeneration()
        )
    }

    private func handleAuthenticatedRequest(
        _ requestData: Data,
        nowUnixMilliseconds: Int64
    ) -> Data {
        guard !requestData.isEmpty, requestData.count <= maximumControlRequestBytes,
              let request = Self.object(requestData),
              let protocolVersion = request["protocol_version"] as? String,
              let requestID = request["request_id"] as? String,
              Self.validRequestID(requestID),
              let operation = request["operation"] as? String
        else {
            return Self.reply(
                requestID: "invalid",
                code: .malformedRequest,
                ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                generation: installedGeneration()
            )
        }
        guard protocolVersion == endpointControlProtocol else {
            return Self.reply(
                requestID: requestID,
                code: .unsupportedProtocol,
                ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                generation: installedGeneration()
            )
        }

        switch operation {
        case "health":
            guard Set(request.keys) == ["protocol_version", "request_id", "operation"] else {
                return Self.reply(
                    requestID: requestID,
                    code: .malformedRequest,
                    ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                    generation: installedGeneration()
                )
            }
            return Self.reply(
                requestID: requestID,
                code: .ok,
                ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                generation: installedGeneration(),
                metrics: authorizationMetrics.snapshot()
            )
        case "install_policy":
            guard Set(request.keys) == [
                "protocol_version", "request_id", "operation", "policy_envelope",
            ], let envelope = request["policy_envelope"] as? [String: Any],
            let envelopeData = try? JSONSerialization.data(withJSONObject: envelope)
            else {
                return Self.reply(
                    requestID: requestID,
                    code: .malformedRequest,
                    ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                    generation: installedGeneration()
                )
            }
            let verified: VerifiedNativeFastPathSnapshot
            do {
                verified = try policyVerifier.verify(
                    envelopeData: envelopeData,
                    nowUnixMilliseconds: nowUnixMilliseconds
                )
            } catch {
                return Self.reply(
                    requestID: requestID,
                    code: .policyRejected,
                    ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                    generation: installedGeneration()
                )
            }
            do {
                try install(verified)
                return Self.reply(
                    requestID: requestID,
                    code: .ok,
                    ready: true,
                    generation: verified.version
                )
            } catch NativeFastPathPolicyError.staleSnapshot {
                return Self.reply(
                    requestID: requestID,
                    code: .staleGeneration,
                    ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                    generation: installedGeneration()
                )
            } catch {
                return Self.reply(
                    requestID: requestID,
                    code: .internalFailure,
                    ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                    generation: installedGeneration()
                )
            }
        case "bind_root":
            guard Set(request.keys) == [
                "protocol_version", "request_id", "operation", "generation", "session_id",
                "audit_token",
            ], let generationText = request["generation"] as? String,
            let generation = Self.parseGeneration(generationText),
            let sessionID = request["session_id"] as? String,
            Self.validSessionID(sessionID),
            let encodedAuditToken = request["audit_token"] as? String,
            let auditToken = Self.decodeAuditToken(encodedAuditToken)
            else {
                return Self.reply(
                    requestID: requestID,
                    code: .malformedRequest,
                    ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                    generation: installedGeneration()
                )
            }
            let code = bindRoot(
                auditToken: auditToken,
                sessionID: sessionID,
                generation: generation,
                nowUnixMilliseconds: nowUnixMilliseconds
            )
            return Self.reply(
                requestID: requestID,
                code: code,
                ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                generation: installedGeneration()
            )
        default:
            return Self.reply(
                requestID: requestID,
                code: .unsupportedOperation,
                ready: isReady(nowUnixMilliseconds: nowUnixMilliseconds),
                generation: installedGeneration()
            )
        }
    }

    private func install(_ verified: VerifiedNativeFastPathSnapshot) throws {
        lock.lock()
        defer { lock.unlock() }
        guard verified.version > persistedGeneration else {
            throw NativeFastPathPolicyError.staleSnapshot(
                current: persistedGeneration,
                proposed: verified.version
            )
        }
        do {
            try generationStore.commit(verified.version)
            persistedGeneration = verified.version
        } catch NativeGenerationStoreError.rollback(let current, let proposed) {
            persistedGeneration = max(persistedGeneration, current)
            throw NativeFastPathPolicyError.staleSnapshot(
                current: current,
                proposed: proposed
            )
        }
        if let state {
            try state.install(verified)
        } else {
            state = try NativeFastPathPolicyState(verifiedSnapshot: verified)
        }
    }

    private func bindRoot(
        auditToken: [UInt8],
        sessionID: String,
        generation: UInt64,
        nowUnixMilliseconds: Int64
    ) -> NativeEndpointControlCode {
        lock.lock()
        defer { lock.unlock() }
        guard let state,
              state.isReady(nowUnixMilliseconds: nowUnixMilliseconds)
        else {
            return .notReady
        }
        guard state.snapshotVersion() == generation else {
            return .staleGeneration
        }
        do {
            try state.bindRootFromControl(
                auditToken: auditToken,
                sessionID: sessionID,
                nowUnixMilliseconds: nowUnixMilliseconds
            )
            return .ok
        } catch NativeFastPathPolicyError.attributionConflict {
            return .attributionConflict
        } catch NativeFastPathPolicyError.policyExpired {
            return .notReady
        } catch NativeFastPathPolicyError.missingSession {
            return .policyRejected
        } catch {
            return .internalFailure
        }
    }

    private func isReady(nowUnixMilliseconds: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return state?.isReady(nowUnixMilliseconds: nowUnixMilliseconds) ?? false
    }

    private func installedGeneration() -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return state?.snapshotVersion()
    }

    private static func object(_ data: Data) -> [String: Any]? {
        guard let value = try? JSONSerialization.jsonObject(with: data),
              let object = value as? [String: Any]
        else {
            return nil
        }
        return object
    }

    private static func validRequestID(_ requestID: String) -> Bool {
        !requestID.isEmpty && requestID.utf8.count <= 128 && requestID.utf8.allSatisfy {
            (65 ... 90).contains($0)
                || (97 ... 122).contains($0)
                || (48 ... 57).contains($0)
                || $0 == 45
                || $0 == 95
        }
    }

    private static func validSessionID(_ sessionID: String) -> Bool {
        !sessionID.isEmpty && sessionID.utf8.count <= 128
    }

    private static func parseGeneration(_ value: String) -> UInt64? {
        guard !value.isEmpty,
              value.utf8.count <= 20,
              value != "0",
              !(value.count > 1 && value.first == "0"),
              value.utf8.allSatisfy({ (48 ... 57).contains($0) })
        else {
            return nil
        }
        return UInt64(value)
    }

    private static func decodeAuditToken(_ value: String) -> [UInt8]? {
        guard value.utf8.count == 43,
              value.utf8.allSatisfy({
                  (65 ... 90).contains($0)
                      || (97 ... 122).contains($0)
                      || (48 ... 57).contains($0)
                      || $0 == 45
                      || $0 == 95
              })
        else {
            return nil
        }
        var standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard.append("=")
        guard let decoded = Data(base64Encoded: standard),
              decoded.count == 32,
              decoded.contains(where: { $0 != 0 })
        else {
            return nil
        }
        return [UInt8](decoded)
    }

    private static func reply(
        requestID: String,
        code: NativeEndpointControlCode,
        ready: Bool,
        generation: UInt64?,
        metrics: NativeAuthorizationMetricsSnapshot? = nil
    ) -> Data {
        var object: [String: Any] = [
            "protocol_version": endpointControlProtocol,
            "request_id": requestID,
            "status": code == .ok ? "accepted" : "rejected",
            "code": code.rawValue,
            "ready": ready,
            "installed_generation": generation.map { NSNumber(value: $0) } ?? NSNull(),
        ]
        if let metrics {
            object["authorization_metrics"] = [
                "events": NSNumber(value: metrics.events),
                "authorization_events": NSNumber(value: metrics.authorizationEvents),
                "notification_events": NSNumber(value: metrics.notificationEvents),
                "allows": NSNumber(value: metrics.allows),
                "denials": NSNumber(value: metrics.denials),
                "deadline_guard_denials": NSNumber(value: metrics.deadlineGuardDenials),
                "late_responses": NSNumber(value: metrics.lateResponses),
                "malformed_denials": NSNumber(value: metrics.malformedDenials),
                "response_failures": NSNumber(value: metrics.responseFailures),
                "dropped_events": NSNumber(value: metrics.droppedEvents),
                "global_sequence_gaps": NSNumber(value: metrics.globalSequenceGaps),
                "per_type_sequence_gaps": NSNumber(value: metrics.perTypeSequenceGaps),
                "sequence_regressions": NSNumber(value: metrics.sequenceRegressions),
                "maximum_authorization_latency_ns": NSNumber(
                    value: metrics.maximumAuthorizationLatencyNanoseconds
                ),
                "minimum_deadline_remaining_ns": metrics.minimumDeadlineRemainingNanoseconds.map {
                    NSNumber(value: $0)
                } ?? NSNull(),
            ]
        }
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
            ?? Data(
                "{\"code\":\"internal_failure\",\"installed_generation\":null,\"protocol_version\":\"vigil.endpoint-control/v1\",\"ready\":false,\"request_id\":\"invalid\",\"status\":\"rejected\"}"
                    .utf8
            )
    }
}
