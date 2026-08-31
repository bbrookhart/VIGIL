import Testing
@testable import VigilMacSupport

@Suite("Network policy maintenance cadence")
struct NetworkPolicyMaintenanceCadenceTests {
    @Test("maintenance is attempted immediately and no more than once per minute")
    func boundsAttempts() {
        var cadence = NetworkPolicyMaintenanceCadence()

        let first = cadence.shouldAttempt(nowUnixMilliseconds: 1_000_000)
        let early = cadence.shouldAttempt(nowUnixMilliseconds: 1_059_999)
        let boundary = cadence.shouldAttempt(nowUnixMilliseconds: 1_060_000)
        #expect(first)
        #expect(!early)
        #expect(boundary)
    }

    @Test("an invalid clock cannot consume a maintenance attempt")
    func invalidClockDoesNotAdvance() {
        var cadence = NetworkPolicyMaintenanceCadence()

        let invalid = cadence.shouldAttempt(nowUnixMilliseconds: -1)
        #expect(!invalid)
        #expect(cadence.lastAttemptUnixMilliseconds == nil)
        let epoch = cadence.shouldAttempt(nowUnixMilliseconds: 0)
        #expect(epoch)
    }

    @Test("a backwards clock permits immediate fail-safe maintenance")
    func clockRegressionDoesNotSuppressRenewal() {
        var cadence = NetworkPolicyMaintenanceCadence()

        let first = cadence.shouldAttempt(nowUnixMilliseconds: 1_000_000)
        let regressed = cadence.shouldAttempt(nowUnixMilliseconds: 999_999)
        #expect(first)
        #expect(regressed)
        #expect(cadence.lastAttemptUnixMilliseconds == 999_999)
    }
}
