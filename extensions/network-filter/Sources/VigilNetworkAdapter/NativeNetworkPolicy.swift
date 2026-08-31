import Foundation
import Network

private let maximumSessions = 1_024
private let maximumAttributions = 16_384
private let maximumRulesPerSession = 256
private let maximumAddressesPerRule = 32
private let maximumPortsPerRule = 64
private let maximumTotalFlows: UInt64 = 1_000_000
private let maximumDistinctDestinations = 4_096

public enum NativeNetworkMode: String, Codable, Sendable {
    case off
    case observe
    case prompt
    case enforce
}

public enum NativeNetworkProtocol: String, Codable, Hashable, Sendable {
    case tcp
    case udp
}

public enum NativeFlowDirection: String, Codable, Sendable {
    case outbound
    case inbound
}

public struct NativeNetworkFlow: Sendable {
    public let process: [UInt8]
    public let direction: NativeFlowDirection
    public let networkProtocol: NativeNetworkProtocol
    public let hostname: String?
    public let remoteIP: String
    public let remotePort: UInt16
    public let observedAtUnixMilliseconds: Int64?

    public init(
        process: [UInt8],
        direction: NativeFlowDirection,
        networkProtocol: NativeNetworkProtocol,
        hostname: String?,
        remoteIP: String,
        remotePort: UInt16,
        observedAtUnixMilliseconds: Int64?
    ) {
        self.process = process
        self.direction = direction
        self.networkProtocol = networkProtocol
        self.hostname = hostname
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.observedAtUnixMilliseconds = observedAtUnixMilliseconds
    }
}

public enum NativeNetworkDecisionAction: Equatable, Sendable {
    case allow
    case drop
    case pause
}

public enum NativeNetworkReason: String, Equatable, Sendable {
    case unmanagedProcess = "unmanaged_process"
    case modeOff = "mode_off"
    case permitPinnedDestination = "permit_pinned_destination"
    case denyInboundFlow = "deny_inbound_flow"
    case denyMissingHostname = "deny_missing_hostname"
    case denyMalformedHostname = "deny_malformed_hostname"
    case denyDirectIP = "deny_direct_ip"
    case denyUnknownDestination = "deny_unknown_destination"
    case denyProtocol = "deny_protocol"
    case denyPort = "deny_port"
    case denyPrivateOrLocalAddress = "deny_private_or_local_address"
    case denyResolutionMismatch = "deny_resolution_mismatch"
    case denyResolutionExpired = "deny_resolution_expired"
    case denyPolicyExpired = "deny_policy_expired"
    case denyClockUnavailable = "deny_clock_unavailable"
    case denyFlowBudget = "deny_flow_budget"
    case denyDestinationBudget = "deny_destination_budget"
    case denyIncompleteNativeFlow = "deny_incomplete_native_flow"
}

public struct NativeNetworkDecision: Equatable, Sendable {
    public let action: NativeNetworkDecisionAction
    public let reason: NativeNetworkReason
    public let sessionID: String?
    public let policyGeneration: UInt64?
}

enum NativeNetworkPolicyError: Error, Equatable {
    case invalidPolicy
    case generationRollback
}

struct NativeDestinationRule: Codable, Sendable {
    let hostname: String
    let networkProtocol: NativeNetworkProtocol
    let ports: [UInt16]
    let resolvedAddresses: [String]
    let validUntilUnixMilliseconds: UInt64

    enum CodingKeys: String, CodingKey {
        case hostname
        case networkProtocol = "protocol"
        case ports
        case resolvedAddresses = "resolved_addresses"
        case validUntilUnixMilliseconds = "valid_until_unix_ms"
    }
}

struct NativeSessionNetworkPolicy: Codable, Sendable {
    let sessionID: String
    let mode: NativeNetworkMode
    let destinations: [NativeDestinationRule]
    let maxTotalFlows: UInt64
    let maxDistinctDestinations: Int

    enum CodingKeys: String, CodingKey {
        case sessionID = "session_id"
        case mode
        case destinations
        case maxTotalFlows = "max_total_flows"
        case maxDistinctDestinations = "max_distinct_destinations"
    }
}

struct NativeNetworkAttribution: Codable, Sendable {
    let process: [UInt8]
    let sessionID: String

    enum CodingKeys: String, CodingKey {
        case process
        case sessionID = "session_id"
    }
}

struct NativeNetworkSnapshot: Codable, Sendable {
    let schemaVersion: String
    let targetInstanceID: String
    let generation: UInt64
    let issuedAtUnixMilliseconds: Int64
    let expiresAtUnixMilliseconds: Int64
    let sessions: [String: NativeSessionNetworkPolicy]
    let attributions: [NativeNetworkAttribution]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case targetInstanceID = "target_instance_id"
        case generation
        case issuedAtUnixMilliseconds = "issued_at_unix_ms"
        case expiresAtUnixMilliseconds = "expires_at_unix_ms"
        case sessions
        case attributions
    }

    func validate() throws {
        guard schemaVersion == "vigil.network-policy/v1",
              validIdentifier(targetInstanceID, maximumBytes: 128), generation > 0,
              issuedAtUnixMilliseconds >= 0,
              expiresAtUnixMilliseconds > issuedAtUnixMilliseconds,
              expiresAtUnixMilliseconds - issuedAtUnixMilliseconds <= 24 * 60 * 60 * 1_000,
              sessions.count <= maximumSessions,
              attributions.count <= maximumAttributions
        else {
            throw NativeNetworkPolicyError.invalidPolicy
        }
        for (key, session) in sessions {
            guard key == session.sessionID,
                  validIdentifier(session.sessionID, maximumBytes: 128),
                  session.destinations.count <= maximumRulesPerSession,
                  (1 ... maximumTotalFlows).contains(session.maxTotalFlows),
                  (1 ... maximumDistinctDestinations).contains(session.maxDistinctDestinations)
            else {
                throw NativeNetworkPolicyError.invalidPolicy
            }
            var ruleKeys = Set<String>()
            for rule in session.destinations {
                guard normalizeHostname(rule.hostname) == rule.hostname,
                      !rule.ports.isEmpty, rule.ports.count <= maximumPortsPerRule,
                      !rule.ports.contains(0), Set(rule.ports).count == rule.ports.count,
                      !rule.resolvedAddresses.isEmpty,
                      rule.resolvedAddresses.count <= maximumAddressesPerRule,
                      Set(rule.resolvedAddresses).count == rule.resolvedAddresses.count,
                      rule.resolvedAddresses.allSatisfy(isPublicIPAddress),
                      rule.validUntilUnixMilliseconds > 0,
                      rule.validUntilUnixMilliseconds <= UInt64(expiresAtUnixMilliseconds),
                      ruleKeys.insert("\(rule.hostname)\u{0}\(rule.networkProtocol.rawValue)").inserted
                else {
                    throw NativeNetworkPolicyError.invalidPolicy
                }
            }
        }
        var tokens = Set<Data>()
        for attribution in attributions {
            let token = Data(attribution.process)
            guard token.count == 32, token.contains(where: { $0 != 0 }),
                  sessions[attribution.sessionID] != nil, tokens.insert(token).inserted
            else {
                throw NativeNetworkPolicyError.invalidPolicy
            }
        }
    }
}

public struct VerifiedNativeNetworkSnapshot: Sendable {
    let snapshot: NativeNetworkSnapshot

    public var generation: UInt64 { snapshot.generation }
    public var expiresAtUnixMilliseconds: Int64 { snapshot.expiresAtUnixMilliseconds }
}

public struct NativeNetworkPolicyLease: Equatable, Sendable {
    public let generation: UInt64
    public let expiresAtUnixMilliseconds: Int64

    fileprivate init(generation: UInt64, expiresAtUnixMilliseconds: Int64) {
        self.generation = generation
        self.expiresAtUnixMilliseconds = expiresAtUnixMilliseconds
    }
}

private struct NativeBudgetState {
    var flows: UInt64 = 0
    var destinations = Set<String>()
}

public final class NativeNetworkPolicyState: @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: NativeNetworkSnapshot?
    private var attributionIndex: [Data: String] = [:]
    private var budgets: [String: NativeBudgetState] = [:]

    public init() {}

    public var generation: UInt64? {
        lock.withLock { snapshot?.generation }
    }

    /// A coherent policy lease snapshot for lifecycle health publication. This is intentionally
    /// separate from flow evaluation so signing and file I/O remain outside `handleNewFlow`.
    public var lease: NativeNetworkPolicyLease? {
        lock.withLock {
            snapshot.map {
                NativeNetworkPolicyLease(
                    generation: $0.generation,
                    expiresAtUnixMilliseconds: $0.expiresAtUnixMilliseconds
                )
            }
        }
    }

    public func install(_ verified: VerifiedNativeNetworkSnapshot) throws {
        try verified.snapshot.validate()
        try lock.withLock {
            if let current = snapshot, verified.snapshot.generation <= current.generation {
                throw NativeNetworkPolicyError.generationRollback
            }
            let activeSessions = Set(verified.snapshot.sessions.keys)
            budgets = budgets.filter { activeSessions.contains($0.key) }
            attributionIndex = Dictionary(
                uniqueKeysWithValues: verified.snapshot.attributions.map {
                    (Data($0.process), $0.sessionID)
                }
            )
            snapshot = verified.snapshot
        }
    }

    public func decide(_ flow: NativeNetworkFlow) -> NativeNetworkDecision {
        lock.withLock {
            decideLocked(flow)
        }
    }

    public func decideIncomplete(
        process: Data?, observedAtUnixMilliseconds: Int64?
    ) -> NativeNetworkDecision {
        lock.withLock {
            guard let snapshot, let process, let sessionID = attributionIndex[process],
                  let policy = snapshot.sessions[sessionID]
            else {
                return unmanagedDecision()
            }
            if let invalidLease = invalidPolicyLeaseReason(
                snapshot: snapshot, observedAtUnixMilliseconds: observedAtUnixMilliseconds
            ) {
                return managedDecision(
                    mode: .enforce, reason: invalidLease, sessionID: sessionID,
                    generation: snapshot.generation
                )
            }
            return managedDecision(
                mode: policy.mode,
                reason: .denyIncompleteNativeFlow,
                sessionID: sessionID,
                generation: snapshot.generation
            )
        }
    }

    private func decideLocked(_ flow: NativeNetworkFlow) -> NativeNetworkDecision {
        guard let snapshot,
              let sessionID = attributionIndex[Data(flow.process)],
              let policy = snapshot.sessions[sessionID]
        else {
            return unmanagedDecision()
        }
        if let invalidLease = invalidPolicyLeaseReason(
            snapshot: snapshot, observedAtUnixMilliseconds: flow.observedAtUnixMilliseconds
        ) {
            return managedDecision(
                mode: .enforce, reason: invalidLease, sessionID: sessionID,
                generation: snapshot.generation
            )
        }
        if policy.mode == .off {
            return NativeNetworkDecision(
                action: .allow, reason: .modeOff, sessionID: sessionID,
                policyGeneration: snapshot.generation
            )
        }
        let candidate = evaluate(policy: policy, flow: flow)
        var reason = candidate.reason
        if let hostname = candidate.permittedHostname {
            var budget = budgets[sessionID] ?? NativeBudgetState()
            if budget.flows >= policy.maxTotalFlows {
                reason = .denyFlowBudget
            } else {
                let destination = "\(hostname)\u{0}\(flow.remotePort)\u{0}\(flow.networkProtocol.rawValue)"
                if !budget.destinations.contains(destination),
                   budget.destinations.count >= policy.maxDistinctDestinations
                {
                    reason = .denyDestinationBudget
                } else {
                    budget.flows += 1
                    budget.destinations.insert(destination)
                    budgets[sessionID] = budget
                }
            }
        }
        return managedDecision(
            mode: policy.mode, reason: reason, sessionID: sessionID,
            generation: snapshot.generation
        )
    }
}

private func invalidPolicyLeaseReason(
    snapshot: NativeNetworkSnapshot, observedAtUnixMilliseconds: Int64?
) -> NativeNetworkReason? {
    guard let observedAtUnixMilliseconds, observedAtUnixMilliseconds >= 0 else {
        return .denyClockUnavailable
    }
    return observedAtUnixMilliseconds >= snapshot.expiresAtUnixMilliseconds
        ? .denyPolicyExpired : nil
}

private func evaluate(
    policy: NativeSessionNetworkPolicy,
    flow: NativeNetworkFlow
) -> (reason: NativeNetworkReason, permittedHostname: String?) {
    guard flow.direction == .outbound else { return (.denyInboundFlow, nil) }
    guard isPublicIPAddress(flow.remoteIP) else { return (.denyPrivateOrLocalAddress, nil) }
    guard let rawHostname = flow.hostname else { return (.denyMissingHostname, nil) }
    guard !isIPAddress(rawHostname) else { return (.denyDirectIP, nil) }
    guard let hostname = normalizeHostname(rawHostname) else { return (.denyMalformedHostname, nil) }
    let hostRules = policy.destinations.filter { $0.hostname == hostname }
    guard !hostRules.isEmpty else { return (.denyUnknownDestination, nil) }
    guard let rule = hostRules.first(where: { $0.networkProtocol == flow.networkProtocol }) else {
        return (.denyProtocol, nil)
    }
    guard rule.ports.contains(flow.remotePort) else { return (.denyPort, nil) }
    guard let now = flow.observedAtUnixMilliseconds, now >= 0 else {
        return (.denyClockUnavailable, nil)
    }
    guard UInt64(now) < rule.validUntilUnixMilliseconds else {
        return (.denyResolutionExpired, nil)
    }
    guard rule.resolvedAddresses.contains(flow.remoteIP) else {
        return (.denyResolutionMismatch, nil)
    }
    return (.permitPinnedDestination, hostname)
}

private func managedDecision(
    mode: NativeNetworkMode,
    reason: NativeNetworkReason,
    sessionID: String,
    generation: UInt64
) -> NativeNetworkDecision {
    let action: NativeNetworkDecisionAction
    if reason == .permitPinnedDestination {
        action = .allow
    } else {
        switch mode {
        case .off, .observe: action = .allow
        case .prompt: action = .pause
        case .enforce: action = .drop
        }
    }
    return NativeNetworkDecision(
        action: action, reason: reason, sessionID: sessionID, policyGeneration: generation
    )
}

private func unmanagedDecision() -> NativeNetworkDecision {
    NativeNetworkDecision(
        action: .allow, reason: .unmanagedProcess, sessionID: nil, policyGeneration: nil
    )
}

private func normalizeHostname(_ raw: String) -> String? {
    guard !raw.isEmpty, raw.utf8.count <= 253,
          !raw.contains("\0"), !raw.contains("/"), !raw.contains("@"), !raw.contains(":")
    else { return nil }
    let normalized = raw.hasSuffix(".") ? String(raw.dropLast()).lowercased() : raw.lowercased()
    guard !normalized.isEmpty, !isIPAddress(normalized) else { return nil }
    for label in normalized.split(separator: ".", omittingEmptySubsequences: false) {
        guard !label.isEmpty, label.utf8.count <= 63,
              label.first != "-", label.last != "-",
              label.utf8.allSatisfy({ asciiAlphaNumeric($0) || $0 == 45 })
        else { return nil }
    }
    return normalized
}

private func isIPAddress(_ value: String) -> Bool {
    IPv4Address(value) != nil || IPv6Address(value) != nil
}

private func isPublicIPAddress(_ value: String) -> Bool {
    if let address = IPv4Address(value) {
        return isPublicIPv4([UInt8](address.rawValue))
    }
    guard let address = IPv6Address(value) else { return false }
    let bytes = [UInt8](address.rawValue)
    if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 0xff, bytes[11] == 0xff {
        return isPublicIPv4(Array(bytes[12 ..< 16]))
    }
    return bytes.count == 16 && (bytes[0] & 0xe0) == 0x20
        && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
}

private func isPublicIPv4(_ bytes: [UInt8]) -> Bool {
    guard bytes.count == 4 else { return false }
    let (a, b, c) = (bytes[0], bytes[1], bytes[2])
    return !(a == 0 || a == 10 || a == 127 || (a == 100 && (64 ... 127).contains(b))
        || (a == 169 && b == 254) || (a == 172 && (16 ... 31).contains(b))
        || (a == 192 && b == 0 && (c == 0 || c == 2)) || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168) || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

func validIdentifier(_ value: String, maximumBytes: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= maximumBytes && value.utf8.allSatisfy {
        asciiAlphaNumeric($0) || $0 == 46 || $0 == 95 || $0 == 45
    }
}

func asciiAlphaNumeric(_ byte: UInt8) -> Bool {
    (65 ... 90).contains(byte) || (97 ... 122).contains(byte) || (48 ... 57).contains(byte)
}
