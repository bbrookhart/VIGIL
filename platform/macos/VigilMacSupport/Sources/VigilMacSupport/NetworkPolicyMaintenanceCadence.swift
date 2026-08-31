import Foundation

/// Deterministic one-minute gate for containing-app policy maintenance. A backwards wall-clock
/// movement permits an immediate attempt instead of suppressing renewal until time catches up.
public struct NetworkPolicyMaintenanceCadence: Equatable, Sendable {
    private static let intervalMilliseconds: Int64 = 60_000
    public private(set) var lastAttemptUnixMilliseconds: Int64?

    public init() {}

    public mutating func shouldAttempt(nowUnixMilliseconds: Int64) -> Bool {
        guard nowUnixMilliseconds >= 0 else { return false }
        if let lastAttemptUnixMilliseconds,
           nowUnixMilliseconds >= lastAttemptUnixMilliseconds,
           nowUnixMilliseconds - lastAttemptUnixMilliseconds < Self.intervalMilliseconds
        {
            return false
        }
        lastAttemptUnixMilliseconds = nowUnixMilliseconds
        return true
    }
}
