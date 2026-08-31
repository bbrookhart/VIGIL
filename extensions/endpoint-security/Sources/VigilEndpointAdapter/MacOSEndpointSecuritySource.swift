import Darwin
import EndpointSecurity
import Foundation

public enum NativeEndpointEventKind: Sendable, Equatable {
    case authExec
    case authOpen
    case authCreate
    case authRename
    case authUnlink
    case notifyFork
    case notifyExit
}

public struct NativeProcessIdentity: Sendable {
    public let auditToken: [UInt8]
    public let pid: Int32
    public let parentPID: Int32
    public let executablePath: String
    public let executablePathTruncated: Bool
    public let signingID: String?
    public let teamID: String?
    public let isPlatformBinary: Bool
    public let isEndpointSecurityClient: Bool

    public init(
        auditToken: [UInt8],
        pid: Int32,
        parentPID: Int32,
        executablePath: String,
        executablePathTruncated: Bool,
        signingID: String?,
        teamID: String?,
        isPlatformBinary: Bool,
        isEndpointSecurityClient: Bool
    ) {
        self.auditToken = auditToken
        self.pid = pid
        self.parentPID = parentPID
        self.executablePath = executablePath
        self.executablePathTruncated = executablePathTruncated
        self.signingID = signingID
        self.teamID = teamID
        self.isPlatformBinary = isPlatformBinary
        self.isEndpointSecurityClient = isEndpointSecurityClient
    }
}

/// A bounded projection of an `es_message_t` whose lifetime ends with the handler callback.
/// No raw pointer escapes this value.
public struct NativeEndpointEvent: Sendable {
    public let kind: NativeEndpointEventKind
    public let actor: NativeProcessIdentity
    public let targetProcess: NativeProcessIdentity?
    public let path: String?
    public let pathTruncated: Bool
    /// Rename destination. Other event kinds leave this nil.
    public let destinationPath: String?
    public let destinationPathTruncated: Bool
    public let requestedOpenFlags: UInt32?
    public let exitStatus: Int32?
    public let machTime: UInt64
    public let deadline: UInt64?
    public let sequence: UInt64?
    public let globalSequence: UInt64?

    public init(
        kind: NativeEndpointEventKind,
        actor: NativeProcessIdentity,
        targetProcess: NativeProcessIdentity? = nil,
        path: String? = nil,
        pathTruncated: Bool = false,
        destinationPath: String? = nil,
        destinationPathTruncated: Bool = false,
        requestedOpenFlags: UInt32? = nil,
        exitStatus: Int32? = nil,
        machTime: UInt64 = 0,
        deadline: UInt64? = nil,
        sequence: UInt64? = nil,
        globalSequence: UInt64? = nil
    ) {
        self.kind = kind
        self.actor = actor
        self.targetProcess = targetProcess
        self.path = path
        self.pathTruncated = pathTruncated
        self.destinationPath = destinationPath
        self.destinationPathTruncated = destinationPathTruncated
        self.requestedOpenFlags = requestedOpenFlags
        self.exitStatus = exitStatus
        self.machTime = machTime
        self.deadline = deadline
        self.sequence = sequence
        self.globalSequence = globalSequence
    }
}

public enum NativeDecisionReason: Sendable, Equatable {
    case unmanagedProcess
    case permitExactExecutable
    case denyExecutable
    case permitWorkspacePath
    case denyOutsideWorkspace
    case denyProtectedPath
    case denyTruncatedPath
    case denyMalformedPath
    case denyUnknownOpenFlags
    case denyMalformedProcessIdentity
    case denyMissingSessionPolicy
    case denyExpiredPolicy
    case denyPolicyClockFailure
    case deadlineGuard
    case malformedMessage
    case notificationOnly
}

public struct NativeAuthorizationDecision: Sendable, Equatable {
    public let allow: Bool
    public let reason: NativeDecisionReason

    public init(allow: Bool, reason: NativeDecisionReason) {
        self.allow = allow
        self.reason = reason
    }

    public static let denyMalformed = NativeAuthorizationDecision(
        allow: false,
        reason: .malformedMessage
    )
}

public struct EndpointDeadlineGuard: Sendable {
    public let safetyMarginTicks: UInt64

    public init(safetyMarginNanoseconds: UInt64) {
        var information = mach_timebase_info_data_t()
        let result = mach_timebase_info(&information)
        guard result == KERN_SUCCESS, information.numer != 0, information.denom != 0 else {
            safetyMarginTicks = UInt64.max
            return
        }
        let numerator = UInt64(information.numer)
        let denominator = UInt64(information.denom)
        let product = safetyMarginNanoseconds.multipliedReportingOverflow(by: denominator)
        safetyMarginTicks = product.overflow ? UInt64.max : product.partialValue / numerator
    }

    public init(safetyMarginTicks: UInt64) {
        self.safetyMarginTicks = safetyMarginTicks
    }

    public func requiresDenial(now: UInt64, deadline: UInt64) -> Bool {
        let guarded = now.addingReportingOverflow(safetyMarginTicks)
        return guarded.overflow || guarded.partialValue >= deadline
    }
}

public enum EndpointClientError: Error, Equatable {
    case alreadyStarted
    case notStarted
    case wrongStopThread
    case notEntitled
    case notPermitted
    case notPrivileged
    case tooManyClients
    case clientCreation(Int32)
    case subscription(Int32)
    case deletionFailed
}

/// Thin native source for the verified macOS Endpoint Security API.
///
/// The supplied handler is part of the authorization fast path. It must use only compact,
/// in-memory state and must not perform I/O, IPC, database work, UI work, policy compilation,
/// logging, or model inference. This adapter independently denies when its deadline margin is
/// reached. Authorization responses are deliberately never cached in this phase.
public final class MacOSEndpointSecuritySource: @unchecked Sendable {
    public typealias EventHandler = @Sendable (NativeEndpointEvent) -> NativeAuthorizationDecision

    private let eventHandler: EventHandler
    private let deadlineGuard: EndpointDeadlineGuard
    public let authorizationMetrics: NativeAuthorizationMetrics
    private var client: OpaquePointer?
    private var ownerThread: pthread_t?

    public init(
        deadlineSafetyMarginNanoseconds: UInt64 = 5_000_000,
        authorizationMetrics: NativeAuthorizationMetrics,
        eventHandler: @escaping EventHandler
    ) {
        deadlineGuard = EndpointDeadlineGuard(
            safetyMarginNanoseconds: deadlineSafetyMarginNanoseconds
        )
        self.authorizationMetrics = authorizationMetrics
        self.eventHandler = eventHandler
    }

    public func start() throws {
        guard client == nil else {
            throw EndpointClientError.alreadyStarted
        }

        var created: OpaquePointer?
        let result = es_new_client(&created) { [weak self] callbackClient, message in
            guard let self else {
                _ = Self.respondDeny(client: callbackClient, message: message)
                return
            }
            self.handle(client: callbackClient, message: message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let created else {
            throw Self.creationError(result)
        }

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        let subscription = events.withUnsafeBufferPointer { buffer in
            es_subscribe(created, buffer.baseAddress!, UInt32(buffer.count))
        }
        guard subscription == ES_RETURN_SUCCESS else {
            _ = es_delete_client(created)
            throw EndpointClientError.subscription(Int32(subscription.rawValue))
        }
        client = created
        ownerThread = pthread_self()
    }

    /// Endpoint Security requires deletion on the same thread that created the client.
    public func stop() throws {
        guard let client, let ownerThread else {
            throw EndpointClientError.notStarted
        }
        guard pthread_equal(ownerThread, pthread_self()) != 0 else {
            throw EndpointClientError.wrongStopThread
        }
        guard es_delete_client(client) == ES_RETURN_SUCCESS else {
            throw EndpointClientError.deletionFailed
        }
        self.client = nil
        self.ownerThread = nil
    }

    private func handle(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        let raw = message.pointee
        if let kind = Self.eventKind(raw.event_type) {
            authorizationMetrics.recordEvent(
                kind: kind,
                sequence: raw.version >= 2 ? raw.seq_num : nil,
                globalSequence: raw.version >= 4 ? raw.global_seq_num : nil
            )
        }
        if raw.action_type == ES_ACTION_TYPE_AUTH,
           deadlineGuard.requiresDenial(now: mach_absolute_time(), deadline: raw.deadline)
        {
            let responseSucceeded = Self.respondDeny(client: client, message: message)
            authorizationMetrics.recordAuthorization(
                allow: false,
                observedAtTicks: raw.mach_time,
                completedAtTicks: mach_absolute_time(),
                deadlineTicks: raw.deadline,
                deadlineGuarded: true,
                malformed: false,
                responseSucceeded: responseSucceeded
            )
            return
        }
        guard let event = Self.project(message) else {
            let responseSucceeded = Self.respondDeny(client: client, message: message)
            if raw.action_type == ES_ACTION_TYPE_AUTH {
                authorizationMetrics.recordAuthorization(
                    allow: false,
                    observedAtTicks: raw.mach_time,
                    completedAtTicks: mach_absolute_time(),
                    deadlineTicks: raw.deadline,
                    deadlineGuarded: false,
                    malformed: true,
                    responseSucceeded: responseSucceeded
                )
            }
            return
        }
        var decision = eventHandler(event)
        var deadlineGuarded = false
        if event.kind.isAuthorization,
           deadlineGuard.requiresDenial(now: mach_absolute_time(), deadline: raw.deadline)
        {
            decision = NativeAuthorizationDecision(allow: false, reason: .deadlineGuard)
            deadlineGuarded = true
        }
        let responseSucceeded: Bool
        switch event.kind {
        case .authOpen:
            let flags = decision.allow ? event.requestedOpenFlags ?? 0 : 0
            responseSucceeded = es_respond_flags_result(client, message, flags, false)
                == ES_RESPOND_RESULT_SUCCESS
        case .authExec, .authCreate, .authRename, .authUnlink:
            responseSucceeded = es_respond_auth_result(
                client,
                message,
                decision.allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY,
                false
            ) == ES_RESPOND_RESULT_SUCCESS
        case .notifyFork, .notifyExit:
            return
        }
        authorizationMetrics.recordAuthorization(
            allow: decision.allow,
            observedAtTicks: raw.mach_time,
            completedAtTicks: mach_absolute_time(),
            deadlineTicks: raw.deadline,
            deadlineGuarded: deadlineGuarded,
            malformed: false,
            responseSucceeded: responseSucceeded
        )
    }

    private static func project(
        _ message: UnsafePointer<es_message_t>
    ) -> NativeEndpointEvent? {
        let raw = message.pointee
        guard let actor = process(raw.process.pointee) else {
            return nil
        }
        let sequence = raw.version >= 2 ? raw.seq_num : nil
        let globalSequence = raw.version >= 4 ? raw.global_seq_num : nil
        let deadline = raw.action_type == ES_ACTION_TYPE_AUTH ? raw.deadline : nil

        switch raw.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            guard let target = process(raw.event.exec.target.pointee) else {
                return nil
            }
            return NativeEndpointEvent(
                kind: .authExec,
                actor: actor,
                targetProcess: target,
                path: target.executablePath,
                pathTruncated: target.executablePathTruncated,
                destinationPath: nil,
                destinationPathTruncated: false,
                requestedOpenFlags: nil,
                exitStatus: nil,
                machTime: raw.mach_time,
                deadline: deadline,
                sequence: sequence,
                globalSequence: globalSequence
            )
        case ES_EVENT_TYPE_AUTH_OPEN:
            let open = raw.event.open
            guard let path = token(open.file.pointee.path) else {
                return nil
            }
            return NativeEndpointEvent(
                kind: .authOpen,
                actor: actor,
                targetProcess: nil,
                path: path,
                pathTruncated: open.file.pointee.path_truncated,
                destinationPath: nil,
                destinationPathTruncated: false,
                requestedOpenFlags: UInt32(bitPattern: open.fflag),
                exitStatus: nil,
                machTime: raw.mach_time,
                deadline: deadline,
                sequence: sequence,
                globalSequence: globalSequence
            )
        case ES_EVENT_TYPE_AUTH_CREATE:
            guard let destination = destinationPath(raw.event.create) else {
                return nil
            }
            return NativeEndpointEvent(
                kind: .authCreate,
                actor: actor,
                targetProcess: nil,
                path: destination.path,
                pathTruncated: destination.truncated,
                destinationPath: nil,
                destinationPathTruncated: false,
                requestedOpenFlags: nil,
                exitStatus: nil,
                machTime: raw.mach_time,
                deadline: deadline,
                sequence: sequence,
                globalSequence: globalSequence
            )
        case ES_EVENT_TYPE_AUTH_RENAME:
            let rename = raw.event.rename
            guard let source = filePath(rename.source),
                  let destination = destinationPath(rename)
            else {
                return nil
            }
            return NativeEndpointEvent(
                kind: .authRename,
                actor: actor,
                targetProcess: nil,
                path: source.path,
                pathTruncated: source.truncated,
                destinationPath: destination.path,
                destinationPathTruncated: destination.truncated,
                requestedOpenFlags: nil,
                exitStatus: nil,
                machTime: raw.mach_time,
                deadline: deadline,
                sequence: sequence,
                globalSequence: globalSequence
            )
        case ES_EVENT_TYPE_AUTH_UNLINK:
            guard let target = filePath(raw.event.unlink.target) else {
                return nil
            }
            return NativeEndpointEvent(
                kind: .authUnlink,
                actor: actor,
                targetProcess: nil,
                path: target.path,
                pathTruncated: target.truncated,
                destinationPath: nil,
                destinationPathTruncated: false,
                requestedOpenFlags: nil,
                exitStatus: nil,
                machTime: raw.mach_time,
                deadline: deadline,
                sequence: sequence,
                globalSequence: globalSequence
            )
        case ES_EVENT_TYPE_NOTIFY_FORK:
            guard let child = process(raw.event.fork.child.pointee) else {
                return nil
            }
            return NativeEndpointEvent(
                kind: .notifyFork,
                actor: actor,
                targetProcess: child,
                path: nil,
                pathTruncated: false,
                destinationPath: nil,
                destinationPathTruncated: false,
                requestedOpenFlags: nil,
                exitStatus: nil,
                machTime: raw.mach_time,
                deadline: nil,
                sequence: sequence,
                globalSequence: globalSequence
            )
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return NativeEndpointEvent(
                kind: .notifyExit,
                actor: actor,
                targetProcess: nil,
                path: nil,
                pathTruncated: false,
                destinationPath: nil,
                destinationPathTruncated: false,
                requestedOpenFlags: nil,
                exitStatus: raw.event.exit.stat,
                machTime: raw.mach_time,
                deadline: nil,
                sequence: sequence,
                globalSequence: globalSequence
            )
        default:
            return nil
        }
    }

    private static func process(_ raw: es_process_t) -> NativeProcessIdentity? {
        guard let executablePath = token(raw.executable.pointee.path) else {
            return nil
        }
        return NativeProcessIdentity(
            auditToken: withUnsafeBytes(of: raw.audit_token) { Array($0) },
            pid: audit_token_to_pid(raw.audit_token),
            parentPID: raw.ppid,
            executablePath: executablePath,
            executablePathTruncated: raw.executable.pointee.path_truncated,
            signingID: token(raw.signing_id),
            teamID: token(raw.team_id),
            isPlatformBinary: raw.is_platform_binary,
            isEndpointSecurityClient: raw.is_es_client
        )
    }

    private static func filePath(
        _ file: UnsafePointer<es_file_t>
    ) -> (path: String, truncated: Bool)? {
        guard let path = token(file.pointee.path) else {
            return nil
        }
        return (path, file.pointee.path_truncated)
    }

    private static func destinationPath(
        _ create: es_event_create_t
    ) -> (path: String, truncated: Bool)? {
        switch create.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return filePath(create.destination.existing_file)
        case ES_DESTINATION_TYPE_NEW_PATH:
            return joinedPath(
                directory: create.destination.new_path.dir,
                filename: create.destination.new_path.filename
            )
        default:
            return nil
        }
    }

    private static func destinationPath(
        _ rename: es_event_rename_t
    ) -> (path: String, truncated: Bool)? {
        switch rename.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return filePath(rename.destination.existing_file)
        case ES_DESTINATION_TYPE_NEW_PATH:
            return joinedPath(
                directory: rename.destination.new_path.dir,
                filename: rename.destination.new_path.filename
            )
        default:
            return nil
        }
    }

    private static func joinedPath(
        directory: UnsafePointer<es_file_t>,
        filename: es_string_token_t
    ) -> (path: String, truncated: Bool)? {
        guard let directory = filePath(directory),
              let filename = token(filename),
              !filename.isEmpty,
              !filename.contains("/")
        else {
            return nil
        }
        let separator = directory.path == "/" || directory.path.hasSuffix("/") ? "" : "/"
        return (directory.path + separator + filename, directory.truncated)
    }

    private static func token(_ token: es_string_token_t) -> String? {
        guard let data = token.data else {
            return token.length == 0 ? "" : nil
        }
        let bytes = UnsafeRawBufferPointer(start: data, count: Int(token.length))
        return String(bytes: bytes, encoding: .utf8)
    }

    private static func respondDeny(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>
    ) -> Bool {
        guard message.pointee.action_type == ES_ACTION_TYPE_AUTH else {
            return true
        }
        if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            return es_respond_flags_result(client, message, 0, false)
                == ES_RESPOND_RESULT_SUCCESS
        } else {
            return es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
                == ES_RESPOND_RESULT_SUCCESS
        }
    }

    private static func eventKind(_ type: es_event_type_t) -> NativeEndpointEventKind? {
        switch type {
        case ES_EVENT_TYPE_AUTH_EXEC: .authExec
        case ES_EVENT_TYPE_AUTH_OPEN: .authOpen
        case ES_EVENT_TYPE_AUTH_CREATE: .authCreate
        case ES_EVENT_TYPE_AUTH_RENAME: .authRename
        case ES_EVENT_TYPE_AUTH_UNLINK: .authUnlink
        case ES_EVENT_TYPE_NOTIFY_FORK: .notifyFork
        case ES_EVENT_TYPE_NOTIFY_EXIT: .notifyExit
        default: nil
        }
    }

    private static func creationError(
        _ result: es_new_client_result_t
    ) -> EndpointClientError {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return .notEntitled
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return .notPermitted
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return .notPrivileged
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return .tooManyClients
        default:
            return .clientCreation(Int32(result.rawValue))
        }
    }
}
