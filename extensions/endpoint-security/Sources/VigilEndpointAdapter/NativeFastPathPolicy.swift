import Darwin
import Foundation

private let maximumSessions = 1_024
private let maximumAttributions = 16_384
private let maximumWorkspacesPerSession = 16
private let maximumExecutablesPerSession = 256
private let maximumProtectedPrefixes = 128
private let maximumPathBytes = 16 * 1_024
private let auditTokenBytes = MemoryLayout<audit_token_t>.size

public enum NativeFastPathPolicyError: Error, Equatable {
    case invalidSessionID
    case invalidPath(String)
    case invalidAuditToken
    case missingSession(String)
    case duplicateSession(String)
    case sessionLimitExceeded
    case workspaceLimitExceeded
    case executableLimitExceeded
    case protectedPrefixLimitExceeded
    case attributionLimitExceeded
    case attributionConflict
    case invalidExpiry
    case policyExpired
    case clockUnavailable
    case staleSnapshot(current: UInt64, proposed: UInt64)
}

public struct NativeSessionEnforcementPolicy: Sendable {
    public let sessionID: String
    public let workspaceRoots: [String]
    public let allowedExecutables: Set<String>

    public init(
        sessionID: String,
        workspaceRoots: [String],
        allowedExecutables: Set<String>
    ) throws {
        guard !sessionID.isEmpty, sessionID.utf8.count <= 128 else {
            throw NativeFastPathPolicyError.invalidSessionID
        }
        guard !workspaceRoots.isEmpty,
              workspaceRoots.count <= maximumWorkspacesPerSession
        else {
            throw NativeFastPathPolicyError.workspaceLimitExceeded
        }
        guard allowedExecutables.count <= maximumExecutablesPerSession else {
            throw NativeFastPathPolicyError.executableLimitExceeded
        }
        for path in workspaceRoots + allowedExecutables {
            guard FastPathPath.isValid(path) else {
                throw NativeFastPathPolicyError.invalidPath(path)
            }
        }
        self.sessionID = sessionID
        self.workspaceRoots = workspaceRoots
        self.allowedExecutables = allowedExecutables
    }
}

/// Immutable, versioned policy payload suitable for transfer from a control process.
///
/// IPC transport and signature verification remain the caller's responsibility. Installation
/// validates all bounds before swapping this snapshot into the authorization path. Expiry is an
/// exclusive runtime lease boundary, not merely an installation-time freshness check.
public struct NativeFastPathSnapshot: Sendable {
    public let version: UInt64
    public let expiresAtUnixMilliseconds: Int64
    public let sessions: [NativeSessionEnforcementPolicy]
    public let protectedPrefixes: [String]

    public init(
        version: UInt64,
        expiresAtUnixMilliseconds: Int64,
        sessions: [NativeSessionEnforcementPolicy],
        protectedPrefixes: [String]
    ) {
        self.version = version
        self.expiresAtUnixMilliseconds = expiresAtUnixMilliseconds
        self.sessions = sessions
        self.protectedPrefixes = protectedPrefixes
    }
}

/// Marker returned only after signed-envelope verification and complete policy validation.
public struct VerifiedNativeFastPathSnapshot: Sendable {
    fileprivate let snapshot: NativeFastPathSnapshot

    public var version: UInt64 { snapshot.version }
    public var expiresAtUnixMilliseconds: Int64 { snapshot.expiresAtUnixMilliseconds }
    public var sessions: [NativeSessionEnforcementPolicy] { snapshot.sessions }
    public var protectedPrefixes: [String] { snapshot.protectedPrefixes }

    init(snapshot: NativeFastPathSnapshot) {
        self.snapshot = snapshot
    }
}

/// Bounded, audit-token keyed native policy state for Endpoint Security callbacks.
///
/// The lock covers only in-memory lookups, bounded path comparisons, and attribution transitions.
/// Snapshot parsing, filesystem access, database work, IPC, and logging must happen before calling
/// `install`. Unmanaged processes are permitted so an adapter failure cannot deny the whole host;
/// malformed authorization events, clock failure, expired policy, and stale mappings for managed
/// processes fail closed. Expiry never turns into a host-wide denial for unmanaged processes.
public final class NativeFastPathPolicyState: @unchecked Sendable {
    private let lock = NSLock()
    private var version: UInt64 = 0
    private var expiresAtUnixMilliseconds: Int64 = 0
    private var sessions: [String: NativeSessionEnforcementPolicy] = [:]
    private var protectedPrefixes: [String] = []
    private var attributions: [Data: String] = [:]

    public init(verifiedSnapshot: VerifiedNativeFastPathSnapshot) throws {
        try installSnapshot(verifiedSnapshot.snapshot)
    }

    /// Entitlement-free tests may construct compact state without production signing keys.
    /// Production extension code must use `init(verifiedSnapshot:)` and `install(_:)`.
    public init(testingSnapshot: NativeFastPathSnapshot) throws {
        try installSnapshot(testingSnapshot)
    }

    public func install(_ verifiedSnapshot: VerifiedNativeFastPathSnapshot) throws {
        try installSnapshot(verifiedSnapshot.snapshot)
    }

    public func installForTesting(_ snapshot: NativeFastPathSnapshot) throws {
        try installSnapshot(snapshot)
    }

    private func installSnapshot(_ snapshot: NativeFastPathSnapshot) throws {
        let compiledSessions = try Self.validate(snapshot)
        lock.lock()
        defer { lock.unlock() }
        guard snapshot.version > version else {
            throw NativeFastPathPolicyError.staleSnapshot(
                current: version,
                proposed: snapshot.version
            )
        }
        version = snapshot.version
        expiresAtUnixMilliseconds = snapshot.expiresAtUnixMilliseconds
        sessions = compiledSessions
        protectedPrefixes = snapshot.protectedPrefixes
        attributions = attributions.filter { sessions[$0.value] != nil }
    }

    public func bindRootForTesting(
        auditToken: [UInt8],
        sessionID: String,
        nowUnixMilliseconds: Int64
    ) throws {
        try bindRoot(
            auditToken: auditToken,
            sessionID: sessionID,
            nowUnixMilliseconds: nowUnixMilliseconds,
            readSystemClock: false
        )
    }

    private func bindRoot(
        auditToken: [UInt8],
        sessionID: String,
        nowUnixMilliseconds: Int64?,
        readSystemClock: Bool
    ) throws {
        guard let key = Self.processKey(auditToken) else {
            throw NativeFastPathPolicyError.invalidAuditToken
        }
        lock.lock()
        defer { lock.unlock() }
        let effectiveNow = readSystemClock
            ? NativeWallClock.nowUnixMilliseconds()
            : nowUnixMilliseconds
        guard let effectiveNow else {
            throw NativeFastPathPolicyError.clockUnavailable
        }
        guard effectiveNow >= 0,
              effectiveNow < expiresAtUnixMilliseconds
        else {
            throw NativeFastPathPolicyError.policyExpired
        }
        guard sessions[sessionID] != nil else {
            throw NativeFastPathPolicyError.missingSession(sessionID)
        }
        if let existing = attributions[key] {
            guard existing == sessionID else {
                throw NativeFastPathPolicyError.attributionConflict
            }
            return
        }
        guard attributions.count < maximumAttributions || attributions[key] != nil else {
            throw NativeFastPathPolicyError.attributionLimitExceeded
        }
        attributions[key] = sessionID
    }

    public func snapshotVersion() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return version
    }

    public func snapshotExpiryUnixMilliseconds() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        return expiresAtUnixMilliseconds
    }

    public func isReady(nowUnixMilliseconds: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return nowUnixMilliseconds >= 0
            && version > 0
            && nowUnixMilliseconds < expiresAtUnixMilliseconds
    }

    public func attributedSession(auditToken: [UInt8]) -> String? {
        guard let key = Self.processKey(auditToken) else {
            return nil
        }
        lock.lock()
        defer { lock.unlock() }
        return attributions[key]
    }

    public func attributionCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return attributions.count
    }

    func bindRootFromControl(
        auditToken: [UInt8],
        sessionID: String,
        nowUnixMilliseconds: Int64
    ) throws {
        try bindRoot(
            auditToken: auditToken,
            sessionID: sessionID,
            nowUnixMilliseconds: nowUnixMilliseconds,
            readSystemClock: false
        )
    }

    public func decide(_ event: NativeEndpointEvent) -> NativeAuthorizationDecision {
        decideLocked(event, nowUnixMilliseconds: nil, readSystemClock: true)
    }

    public func decideForTesting(
        _ event: NativeEndpointEvent,
        nowUnixMilliseconds: Int64
    ) -> NativeAuthorizationDecision {
        decideLocked(
            event,
            nowUnixMilliseconds: nowUnixMilliseconds,
            readSystemClock: false
        )
    }

    public func decideWithClockFailureForTesting(
        _ event: NativeEndpointEvent
    ) -> NativeAuthorizationDecision {
        decideLocked(event, nowUnixMilliseconds: nil, readSystemClock: false)
    }

    private func decideLocked(
        _ event: NativeEndpointEvent,
        nowUnixMilliseconds: Int64?,
        readSystemClock: Bool
    ) -> NativeAuthorizationDecision {
        lock.lock()
        defer { lock.unlock() }

        guard let actorKey = Self.processKey(event.actor.auditToken) else {
            return event.kind.isAuthorization
                ? NativeAuthorizationDecision(
                    allow: false,
                    reason: .denyMalformedProcessIdentity
                )
                : NativeAuthorizationDecision(allow: true, reason: .notificationOnly)
        }

        switch event.kind {
        case .notifyFork:
            inheritAttribution(parent: actorKey, child: event.targetProcess?.auditToken)
            return NativeAuthorizationDecision(allow: true, reason: .notificationOnly)
        case .notifyExit:
            attributions.removeValue(forKey: actorKey)
            return NativeAuthorizationDecision(allow: true, reason: .notificationOnly)
        case .authExec, .authOpen, .authCreate, .authRename, .authUnlink:
            break
        }

        guard let sessionID = attributions[actorKey] else {
            return NativeAuthorizationDecision(allow: true, reason: .unmanagedProcess)
        }
        let effectiveNow = readSystemClock
            ? NativeWallClock.nowUnixMilliseconds()
            : nowUnixMilliseconds
        guard let effectiveNow, effectiveNow >= 0 else {
            return NativeAuthorizationDecision(allow: false, reason: .denyPolicyClockFailure)
        }
        guard effectiveNow < expiresAtUnixMilliseconds else {
            return NativeAuthorizationDecision(allow: false, reason: .denyExpiredPolicy)
        }
        guard let policy = sessions[sessionID] else {
            return NativeAuthorizationDecision(allow: false, reason: .denyMissingSessionPolicy)
        }

        let decision: NativeAuthorizationDecision
        switch event.kind {
        case .authExec:
            decision = decideExec(event, policy: policy)
        case .authOpen:
            guard let flags = event.requestedOpenFlags,
                  flags != 0,
                  flags & ~UInt32(FREAD | FWRITE) == 0
            else {
                return NativeAuthorizationDecision(allow: false, reason: .denyUnknownOpenFlags)
            }
            decision = decidePath(
                event.path,
                truncated: event.pathTruncated,
                policy: policy
            )
        case .authCreate, .authUnlink:
            decision = decidePath(
                event.path,
                truncated: event.pathTruncated,
                policy: policy
            )
        case .authRename:
            let source = decidePath(
                event.path,
                truncated: event.pathTruncated,
                policy: policy
            )
            guard source.allow else {
                return source
            }
            decision = decidePath(
                event.destinationPath,
                truncated: event.destinationPathTruncated,
                policy: policy
            )
        case .notifyFork, .notifyExit:
            return NativeAuthorizationDecision(allow: true, reason: .notificationOnly)
        }

        if event.kind == .authExec, decision.allow,
           let targetKey = Self.processKey(event.targetProcess?.auditToken)
        {
            attributions.removeValue(forKey: actorKey)
            attributions[targetKey] = sessionID
        }
        return decision
    }

    private func decideExec(
        _ event: NativeEndpointEvent,
        policy: NativeSessionEnforcementPolicy
    ) -> NativeAuthorizationDecision {
        guard let target = event.targetProcess,
              Self.processKey(target.auditToken) != nil
        else {
            return NativeAuthorizationDecision(
                allow: false,
                reason: .denyMalformedProcessIdentity
            )
        }
        let pathDecision = pathStatus(
            target.executablePath,
            truncated: target.executablePathTruncated
        )
        if let denial = pathDecision {
            return denial
        }
        let allowed = policy.allowedExecutables.contains(target.executablePath)
        return NativeAuthorizationDecision(
            allow: allowed,
            reason: allowed ? .permitExactExecutable : .denyExecutable
        )
    }

    private func decidePath(
        _ path: String?,
        truncated: Bool,
        policy: NativeSessionEnforcementPolicy
    ) -> NativeAuthorizationDecision {
        guard let path else {
            return NativeAuthorizationDecision(allow: false, reason: .denyMalformedPath)
        }
        if let denial = pathStatus(path, truncated: truncated) {
            return denial
        }
        let allowed = policy.workspaceRoots.contains { FastPathPath.contains(root: $0, path: path) }
        return NativeAuthorizationDecision(
            allow: allowed,
            reason: allowed ? .permitWorkspacePath : .denyOutsideWorkspace
        )
    }

    private func pathStatus(
        _ path: String,
        truncated: Bool
    ) -> NativeAuthorizationDecision? {
        if truncated {
            return NativeAuthorizationDecision(allow: false, reason: .denyTruncatedPath)
        }
        guard FastPathPath.isValid(path) else {
            return NativeAuthorizationDecision(allow: false, reason: .denyMalformedPath)
        }
        if protectedPrefixes.contains(where: { FastPathPath.contains(root: $0, path: path) }) {
            return NativeAuthorizationDecision(allow: false, reason: .denyProtectedPath)
        }
        return nil
    }

    private func inheritAttribution(parent: Data, child: [UInt8]?) {
        guard let sessionID = attributions[parent],
              let child = Self.processKey(child),
              attributions.count < maximumAttributions || attributions[child] != nil
        else {
            return
        }
        attributions[child] = sessionID
    }

    private static func processKey(_ bytes: [UInt8]?) -> Data? {
        guard let bytes,
              bytes.count == auditTokenBytes,
              bytes.contains(where: { $0 != 0 })
        else {
            return nil
        }
        return Data(bytes)
    }

    static func validate(
        _ snapshot: NativeFastPathSnapshot
    ) throws -> [String: NativeSessionEnforcementPolicy] {
        guard snapshot.version > 0 else {
            throw NativeFastPathPolicyError.staleSnapshot(current: 0, proposed: 0)
        }
        guard snapshot.expiresAtUnixMilliseconds > 0 else {
            throw NativeFastPathPolicyError.invalidExpiry
        }
        guard snapshot.sessions.count <= maximumSessions else {
            throw NativeFastPathPolicyError.sessionLimitExceeded
        }
        guard snapshot.protectedPrefixes.count <= maximumProtectedPrefixes else {
            throw NativeFastPathPolicyError.protectedPrefixLimitExceeded
        }
        for path in snapshot.protectedPrefixes {
            guard FastPathPath.isValid(path) else {
                throw NativeFastPathPolicyError.invalidPath(path)
            }
        }
        var sessions: [String: NativeSessionEnforcementPolicy] = [:]
        sessions.reserveCapacity(snapshot.sessions.count)
        for policy in snapshot.sessions {
            guard sessions.updateValue(policy, forKey: policy.sessionID) == nil else {
                throw NativeFastPathPolicyError.duplicateSession(policy.sessionID)
            }
        }
        return sessions
    }
}

private enum FastPathPath {
    static func isValid(_ path: String) -> Bool {
        guard path.hasPrefix("/"),
              !path.isEmpty,
              path.utf8.count <= maximumPathBytes,
              !path.contains("\0")
        else {
            return false
        }
        return !path.split(separator: "/", omittingEmptySubsequences: true).contains {
            $0 == "." || $0 == ".."
        }
    }

    static func contains(root: String, path: String) -> Bool {
        if root == "/" {
            return true
        }
        let normalizedRoot = root.hasSuffix("/") ? String(root.dropLast()) : root
        guard path.hasPrefix(normalizedRoot) else {
            return false
        }
        let boundary = path.index(path.startIndex, offsetBy: normalizedRoot.count)
        return boundary == path.endIndex || path[boundary] == "/"
    }
}
