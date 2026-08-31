import Darwin
import Foundation

public struct NativeAuthorizationMetricsSnapshot: Sendable, Equatable {
    public let events: UInt64
    public let authorizationEvents: UInt64
    public let notificationEvents: UInt64
    public let allows: UInt64
    public let denials: UInt64
    public let deadlineGuardDenials: UInt64
    public let lateResponses: UInt64
    public let malformedDenials: UInt64
    public let responseFailures: UInt64
    public let droppedEvents: UInt64
    public let globalSequenceGaps: UInt64
    public let perTypeSequenceGaps: UInt64
    public let sequenceRegressions: UInt64
    public let maximumAuthorizationLatencyNanoseconds: UInt64
    public let minimumDeadlineRemainingNanoseconds: UInt64?
}

/// Fixed-size, lock-protected health counters for the native Endpoint Security callback.
///
/// Recording performs no I/O, logging, JSON encoding, or collection growth. Snapshot conversion and
/// serialization happen on the control path, never inside the authorization callback.
public final class NativeAuthorizationMetrics: @unchecked Sendable {
    private let lock = NSLock()
    private let timebaseNumerator: UInt64
    private let timebaseDenominator: UInt64
    private var lastSequences: [UInt64?] = Array(repeating: nil, count: 7)
    private var lastGlobalSequence: UInt64?
    private var events: UInt64 = 0
    private var authorizationEvents: UInt64 = 0
    private var notificationEvents: UInt64 = 0
    private var allows: UInt64 = 0
    private var denials: UInt64 = 0
    private var deadlineGuardDenials: UInt64 = 0
    private var lateResponses: UInt64 = 0
    private var malformedDenials: UInt64 = 0
    private var responseFailures: UInt64 = 0
    private var droppedEvents: UInt64 = 0
    private var globalSequenceGaps: UInt64 = 0
    private var perTypeSequenceGaps: UInt64 = 0
    private var sequenceRegressions: UInt64 = 0
    private var maximumAuthorizationLatencyTicks: UInt64 = 0
    private var minimumDeadlineRemainingTicks: UInt64?

    public init() {
        var information = mach_timebase_info_data_t()
        if mach_timebase_info(&information) == KERN_SUCCESS,
           information.numer != 0,
           information.denom != 0
        {
            timebaseNumerator = UInt64(information.numer)
            timebaseDenominator = UInt64(information.denom)
        } else {
            // A broken timebase must not manufacture optimistic sub-nanosecond telemetry.
            timebaseNumerator = UInt64.max
            timebaseDenominator = 1
        }
    }

    /// Deterministic constructor for entitlement-free checks.
    public init(testingTimebaseNumerator: UInt32, denominator: UInt32) {
        precondition(testingTimebaseNumerator > 0 && denominator > 0)
        timebaseNumerator = UInt64(testingTimebaseNumerator)
        timebaseDenominator = UInt64(denominator)
    }

    func recordEvent(
        kind: NativeEndpointEventKind,
        sequence: UInt64?,
        globalSequence: UInt64?
    ) {
        lock.lock()
        defer { lock.unlock() }
        events = Self.increment(events)
        if kind.isAuthorization {
            authorizationEvents = Self.increment(authorizationEvents)
        } else {
            notificationEvents = Self.increment(notificationEvents)
        }

        let index = kind.metricsIndex
        let perTypeGap = Self.sequenceGap(previous: lastSequences[index], current: sequence)
        if perTypeGap.regressed {
            sequenceRegressions = Self.increment(sequenceRegressions)
        }
        perTypeSequenceGaps = Self.add(perTypeSequenceGaps, perTypeGap.missing)
        if let sequence {
            lastSequences[index] = sequence
        }

        let globalGap = Self.sequenceGap(previous: lastGlobalSequence, current: globalSequence)
        if globalGap.regressed {
            sequenceRegressions = Self.increment(sequenceRegressions)
        }
        globalSequenceGaps = Self.add(globalSequenceGaps, globalGap.missing)
        if let globalSequence {
            lastGlobalSequence = globalSequence
            droppedEvents = Self.add(droppedEvents, globalGap.missing)
        } else {
            droppedEvents = Self.add(droppedEvents, perTypeGap.missing)
        }
    }

    public func recordEventForTesting(
        kind: NativeEndpointEventKind,
        sequence: UInt64?,
        globalSequence: UInt64?
    ) {
        recordEvent(kind: kind, sequence: sequence, globalSequence: globalSequence)
    }

    func recordAuthorization(
        allow: Bool,
        observedAtTicks: UInt64,
        completedAtTicks: UInt64,
        deadlineTicks: UInt64,
        deadlineGuarded: Bool,
        malformed: Bool,
        responseSucceeded: Bool
    ) {
        lock.lock()
        defer { lock.unlock() }
        if allow {
            allows = Self.increment(allows)
        } else {
            denials = Self.increment(denials)
        }
        if deadlineGuarded {
            deadlineGuardDenials = Self.increment(deadlineGuardDenials)
        }
        if malformed {
            malformedDenials = Self.increment(malformedDenials)
        }
        if !responseSucceeded {
            responseFailures = Self.increment(responseFailures)
        }
        if completedAtTicks >= deadlineTicks {
            lateResponses = Self.increment(lateResponses)
        }
        maximumAuthorizationLatencyTicks = max(
            maximumAuthorizationLatencyTicks,
            completedAtTicks.saturatingSubtract(observedAtTicks)
        )
        let remaining = deadlineTicks.saturatingSubtract(completedAtTicks)
        minimumDeadlineRemainingTicks = min(minimumDeadlineRemainingTicks ?? remaining, remaining)
    }

    public func recordAuthorizationForTesting(
        allow: Bool,
        observedAtTicks: UInt64,
        completedAtTicks: UInt64,
        deadlineTicks: UInt64,
        deadlineGuarded: Bool,
        malformed: Bool,
        responseSucceeded: Bool
    ) {
        recordAuthorization(
            allow: allow,
            observedAtTicks: observedAtTicks,
            completedAtTicks: completedAtTicks,
            deadlineTicks: deadlineTicks,
            deadlineGuarded: deadlineGuarded,
            malformed: malformed,
            responseSucceeded: responseSucceeded
        )
    }

    public func snapshot() -> NativeAuthorizationMetricsSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return NativeAuthorizationMetricsSnapshot(
            events: events,
            authorizationEvents: authorizationEvents,
            notificationEvents: notificationEvents,
            allows: allows,
            denials: denials,
            deadlineGuardDenials: deadlineGuardDenials,
            lateResponses: lateResponses,
            malformedDenials: malformedDenials,
            responseFailures: responseFailures,
            droppedEvents: droppedEvents,
            globalSequenceGaps: globalSequenceGaps,
            perTypeSequenceGaps: perTypeSequenceGaps,
            sequenceRegressions: sequenceRegressions,
            maximumAuthorizationLatencyNanoseconds: nanoseconds(
                fromTicks: maximumAuthorizationLatencyTicks
            ),
            minimumDeadlineRemainingNanoseconds: minimumDeadlineRemainingTicks.map {
                nanoseconds(fromTicks: $0)
            }
        )
    }

    private func nanoseconds(fromTicks ticks: UInt64) -> UInt64 {
        let whole = (ticks / timebaseDenominator).multipliedReportingOverflow(
            by: timebaseNumerator
        )
        guard !whole.overflow else {
            return UInt64.max
        }
        let remainder = ticks % timebaseDenominator
        let fractionalProduct = remainder.multipliedReportingOverflow(by: timebaseNumerator)
        guard !fractionalProduct.overflow else {
            return UInt64.max
        }
        return Self.add(
            whole.partialValue,
            fractionalProduct.partialValue / timebaseDenominator
        )
    }

    private static func sequenceGap(
        previous: UInt64?,
        current: UInt64?
    ) -> (missing: UInt64, regressed: Bool) {
        guard let previous, let current else {
            return (0, false)
        }
        guard current > previous else {
            return (0, true)
        }
        return (current - previous - 1, false)
    }

    private static func increment(_ value: UInt64) -> UInt64 {
        value == UInt64.max ? UInt64.max : value + 1
    }

    private static func add(_ value: UInt64, _ amount: UInt64) -> UInt64 {
        let result = value.addingReportingOverflow(amount)
        return result.overflow ? UInt64.max : result.partialValue
    }
}

private extension UInt64 {
    func saturatingSubtract(_ other: UInt64) -> UInt64 {
        self >= other ? self - other : 0
    }
}

extension NativeEndpointEventKind {
    var isAuthorization: Bool {
        switch self {
        case .authExec, .authOpen, .authCreate, .authRename, .authUnlink:
            true
        case .notifyFork, .notifyExit:
            false
        }
    }

    fileprivate var metricsIndex: Int {
        switch self {
        case .authExec: 0
        case .authOpen: 1
        case .authCreate: 2
        case .authRename: 3
        case .authUnlink: 4
        case .notifyFork: 5
        case .notifyExit: 6
        }
    }
}
