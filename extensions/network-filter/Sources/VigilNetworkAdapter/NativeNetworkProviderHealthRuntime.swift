import Foundation

public struct NativeNetworkProviderFlowCounts: Equatable, Sendable {
    public let allowed: UInt64
    public let dropped: UInt64
    public let paused: UInt64

    public var total: UInt64 {
        allowed &+ dropped &+ paused
    }
}

/// Constant-space counters updated in the flow callback. Overflow saturates rather than wrapping.
public final class NativeNetworkProviderFlowCounters: @unchecked Sendable {
    private let lock = NSLock()
    private var allowed: UInt64 = 0
    private var dropped: UInt64 = 0
    private var paused: UInt64 = 0

    public init() {}

    public func record(_ decision: NativeNetworkDecision) {
        lock.withLock {
            switch decision.action {
            case .allow: allowed = saturatingIncrement(allowed)
            case .drop: dropped = saturatingIncrement(dropped)
            case .pause: paused = saturatingIncrement(paused)
            }
        }
    }

    public var snapshot: NativeNetworkProviderFlowCounts {
        lock.withLock {
            NativeNetworkProviderFlowCounts(allowed: allowed, dropped: dropped, paused: paused)
        }
    }
}

public struct NativeNetworkProviderHealthPublicationStatus: Equatable, Sendable {
    public let isRunning: Bool
    public let successfulPublications: UInt64
    public let failedPublications: UInt64
    public let lastPublicationUnixMilliseconds: Int64?
}

/// Builds and publishes short-lived attestations on a dedicated serial timer queue. The timer is
/// bounded to 1...30 seconds and its handler cannot overlap with itself.
public final class NativeNetworkProviderHealthPublicationLoop: @unchecked Sendable {
    public typealias Clock = @Sendable () -> Int64?

    private let lock = NSLock()
    private let queue: DispatchQueue
    private let interval: TimeInterval
    private let targetInstanceID: String
    private let providerBundleIdentifier: String
    private let policyState: NativeNetworkPolicyState
    private let counters: NativeNetworkProviderFlowCounters
    private let publisher: NativeNetworkProviderHealthPublisher
    private let clock: Clock
    private var timer: DispatchSourceTimer?
    private var successfulPublications: UInt64 = 0
    private var failedPublications: UInt64 = 0
    private var lastPublicationUnixMilliseconds: Int64?

    public init(
        interval: TimeInterval = 10,
        targetInstanceID: String,
        providerBundleIdentifier: String,
        policyState: NativeNetworkPolicyState,
        counters: NativeNetworkProviderFlowCounters,
        publisher: NativeNetworkProviderHealthPublisher,
        clock: @escaping Clock = NativeNetworkProviderHealthPublicationLoop.systemClock
    ) throws {
        guard interval.isFinite, (1 ... 30).contains(interval),
              validIdentifier(targetInstanceID, maximumBytes: 128),
              providerBundleIdentifier.contains("."),
              validIdentifier(providerBundleIdentifier, maximumBytes: 255)
        else {
            throw NativeSignedNetworkProviderHealthError.invalidConfiguration
        }
        self.interval = interval
        self.targetInstanceID = targetInstanceID
        self.providerBundleIdentifier = providerBundleIdentifier
        self.policyState = policyState
        self.counters = counters
        self.publisher = publisher
        self.clock = clock
        queue = DispatchQueue(label: "com.vigil.security.network.provider-health")
    }

    deinit { stop() }

    public func start() {
        lock.withLock {
            guard timer == nil else { return }
            let source = DispatchSource.makeTimerSource(queue: queue)
            source.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(250))
            source.setEventHandler { [weak self] in self?.publishOnce() }
            timer = source
            source.resume()
        }
    }

    public func stop() {
        let current = lock.withLock { () -> DispatchSourceTimer? in
            defer { timer = nil }
            return timer
        }
        current?.setEventHandler {}
        current?.cancel()
    }

    /// Deterministic lifecycle hook used by startup and tests. It performs no flow-callback work.
    public func publishOnce() {
        guard let now = clock(), now >= 0, let lease = policyState.lease else {
            recordFailure()
            return
        }
        let counts = counters.snapshot
        do {
            let reading = try NativeNetworkProviderHealthReading(
                targetInstanceID: targetInstanceID,
                providerBundleIdentifier: providerBundleIdentifier,
                policyGeneration: lease.generation,
                policyExpiresAtUnixMilliseconds: lease.expiresAtUnixMilliseconds,
                observedAtUnixMilliseconds: now,
                allowedFlows: counts.allowed,
                droppedFlows: counts.dropped,
                pausedFlows: counts.paused
            )
            try publisher.publish(reading)
            lock.withLock {
                successfulPublications = saturatingIncrement(successfulPublications)
                lastPublicationUnixMilliseconds = now
            }
        } catch {
            recordFailure()
        }
    }

    public var status: NativeNetworkProviderHealthPublicationStatus {
        lock.withLock {
            NativeNetworkProviderHealthPublicationStatus(
                isRunning: timer != nil,
                successfulPublications: successfulPublications,
                failedPublications: failedPublications,
                lastPublicationUnixMilliseconds: lastPublicationUnixMilliseconds
            )
        }
    }

    public static func systemClock() -> Int64? {
        let now = Date().timeIntervalSince1970 * 1_000
        guard now.isFinite, now >= 0, now <= Double(Int64.max) else { return nil }
        return Int64(now)
    }

    private func recordFailure() {
        lock.withLock { failedPublications = saturatingIncrement(failedPublications) }
    }
}

private func saturatingIncrement(_ value: UInt64) -> UInt64 {
    value == .max ? .max : value + 1
}
