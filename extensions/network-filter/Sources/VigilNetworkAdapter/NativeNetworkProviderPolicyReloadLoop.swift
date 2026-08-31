import Foundation

public struct NativeNetworkProviderPolicyReloadStatus: Equatable, Sendable {
    public let isRunning: Bool
    public let successfulReloads: UInt64
    public let failedReloads: UInt64
    public let lastObservedGeneration: UInt64?
}

/// Reloads the durable signed policy on a dedicated serial timer queue. No filesystem or
/// signature work reaches `handleNewFlow`; a failed reload leaves the last verified snapshot in
/// place, where its exclusive expiry continues to fail closed for attributed processes.
final class NativeNetworkProviderPolicyReloadLoop: @unchecked Sendable {
    typealias Clock = @Sendable () -> Int64?
    typealias Reload = @Sendable (Int64) throws -> NativeNetworkPolicyReloadResult

    private let lock = NSLock()
    private let queue: DispatchQueue
    private let interval: TimeInterval
    private let clock: Clock
    private let reload: Reload
    private var timer: DispatchSourceTimer?
    private var successfulReloads: UInt64 = 0
    private var failedReloads: UInt64 = 0
    private var lastObservedGeneration: UInt64?

    convenience init(
        interval: TimeInterval = 10,
        lifecycle: NativeNetworkProviderLifecycle,
        clock: @escaping Clock = NativeNetworkProviderHealthPublicationLoop.systemClock
    ) throws {
        try self.init(
            interval: interval,
            clock: clock,
            reload: { try lifecycle.reload(nowUnixMilliseconds: $0) }
        )
    }

    init(
        interval: TimeInterval = 10,
        clock: @escaping Clock,
        reload: @escaping Reload
    ) throws {
        guard interval.isFinite, (1 ... 30).contains(interval) else {
            throw NativeNetworkProviderLifecycleError.policyUnavailable
        }
        self.interval = interval
        self.clock = clock
        self.reload = reload
        queue = DispatchQueue(label: "com.vigil.security.network.policy-reload")
    }

    deinit { stop() }

    func start() {
        lock.withLock {
            guard timer == nil else { return }
            let source = DispatchSource.makeTimerSource(queue: queue)
            source.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(250))
            source.setEventHandler { [weak self] in self?.reloadOnce() }
            timer = source
            source.resume()
        }
    }

    func stop() {
        let current = lock.withLock { () -> DispatchSourceTimer? in
            defer { timer = nil }
            return timer
        }
        current?.setEventHandler {}
        current?.cancel()
    }

    func reloadOnce() {
        guard let now = clock(), now >= 0 else {
            recordFailure()
            return
        }
        do {
            let result = try reload(now)
            let generation = switch result {
            case let .installed(generation), let .unchanged(generation): generation
            }
            lock.withLock {
                successfulReloads = saturatingReloadIncrement(successfulReloads)
                lastObservedGeneration = generation
            }
        } catch {
            recordFailure()
        }
    }

    var status: NativeNetworkProviderPolicyReloadStatus {
        lock.withLock {
            NativeNetworkProviderPolicyReloadStatus(
                isRunning: timer != nil,
                successfulReloads: successfulReloads,
                failedReloads: failedReloads,
                lastObservedGeneration: lastObservedGeneration
            )
        }
    }

    private func recordFailure() {
        lock.withLock { failedReloads = saturatingReloadIncrement(failedReloads) }
    }
}

private func saturatingReloadIncrement(_ value: UInt64) -> UInt64 {
    value == .max ? .max : value + 1
}
