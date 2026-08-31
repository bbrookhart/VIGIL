import Foundation
import XCTest

@testable import VigilEndpointAdapter

/// Native telemetry. These counters are how an operator learns the extension is under
/// deadline pressure or dropping kernel events, so losing one is a silent blind spot.
final class AuthorizationMetricsTests: XCTestCase {
    /// Metrics carrying one guarded denial, one late malformed response, and a sequence gap.
    static func populated() -> NativeAuthorizationMetrics {
        let metrics = NativeAuthorizationMetrics(testingTimebaseNumerator: 2, denominator: 1)
        metrics.recordEventForTesting(kind: .authExec, sequence: 10, globalSequence: 100)
        metrics.recordAuthorizationForTesting(
            allow: true, observedAtTicks: 100, completedAtTicks: 130,
            deadlineTicks: 200, deadlineGuarded: false, malformed: false, responseSucceeded: true
        )
        // A global sequence jump of 3 means the kernel dropped events we never saw.
        metrics.recordEventForTesting(kind: .authExec, sequence: 13, globalSequence: 103)
        metrics.recordAuthorizationForTesting(
            allow: false, observedAtTicks: 140, completedAtTicks: 210,
            deadlineTicks: 200, deadlineGuarded: true, malformed: true, responseSucceeded: false
        )
        // Per-type sequence going backwards is a regression, not a gap.
        metrics.recordEventForTesting(kind: .notifyFork, sequence: 2, globalSequence: nil)
        metrics.recordEventForTesting(kind: .notifyFork, sequence: 1, globalSequence: nil)
        return metrics
    }

    private var snapshot: NativeAuthorizationMetricsSnapshot!

    override func setUp() {
        super.setUp()
        snapshot = Self.populated().snapshot()
    }

    func test_counts_every_callback_event() {
        XCTAssertEqual(snapshot.events, 4, "native metrics lost callback events")
        XCTAssertEqual(snapshot.authorizationEvents, 2, "native metrics miscounted auth events")
        XCTAssertEqual(snapshot.notificationEvents, 2, "native metrics lost notifications")
    }

    func test_records_both_verdicts() {
        XCTAssertEqual(snapshot.allows, 1)
        XCTAssertEqual(snapshot.denials, 1)
    }

    func test_records_deadline_pressure_and_response_failures() {
        XCTAssertEqual(snapshot.deadlineGuardDenials, 1, "deadline pressure was not counted")
        XCTAssertEqual(snapshot.lateResponses, 1, "late response was not counted")
        XCTAssertEqual(snapshot.malformedDenials, 1, "malformed denial was not counted")
        XCTAssertEqual(snapshot.responseFailures, 1, "ES response failure was not counted")
    }

    func test_distinguishes_dropped_events_from_sequence_regressions() {
        XCTAssertEqual(snapshot.droppedEvents, 2, "global sequence gap was miscounted")
        XCTAssertEqual(snapshot.globalSequenceGaps, 2, "global gap detail was lost")
        XCTAssertEqual(snapshot.perTypeSequenceGaps, 2, "per-type gap detail was lost")
        XCTAssertEqual(snapshot.sequenceRegressions, 1, "sequence regression was not counted")
    }

    func test_converts_latency_through_the_mach_timebase() {
        // 70 ticks at a 2/1 timebase is 140ns; reporting raw ticks would misreport latency
        // on any machine whose timebase is not 1:1.
        XCTAssertEqual(
            snapshot.maximumAuthorizationLatencyNanoseconds, 140,
            "native latency timebase conversion was incorrect"
        )
    }

    func test_deadline_headroom_saturates_at_zero() {
        // An overrun reports zero headroom rather than underflowing to a huge value.
        XCTAssertEqual(
            snapshot.minimumDeadlineRemainingNanoseconds, 0,
            "native deadline headroom did not saturate at zero"
        )
    }

    func test_concurrent_recording_loses_no_events() {
        let metrics = NativeAuthorizationMetrics(testingTimebaseNumerator: 1, denominator: 1)
        DispatchQueue.concurrentPerform(iterations: 1_000) { index in
            metrics.recordEventForTesting(kind: .authOpen, sequence: nil, globalSequence: nil)
            metrics.recordAuthorizationForTesting(
                allow: index.isMultiple(of: 2), observedAtTicks: 10, completedAtTicks: 20,
                deadlineTicks: 100, deadlineGuarded: false, malformed: false,
                responseSucceeded: true
            )
        }
        let concurrent = metrics.snapshot()
        XCTAssertEqual(concurrent.authorizationEvents, 1_000, "concurrent metric events were lost")
        XCTAssertEqual(concurrent.allows, 500, "concurrent metric verdicts were lost")
        XCTAssertEqual(concurrent.denials, 500, "concurrent metric verdicts were lost")
    }
}
