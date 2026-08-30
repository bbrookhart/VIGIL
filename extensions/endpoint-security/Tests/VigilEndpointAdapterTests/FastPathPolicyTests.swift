import Darwin
import Foundation
import XCTest

@testable import VigilEndpointAdapter

/// The fast path: the decision made inside the kernel callback, against installed policy.
final class FastPathPolicyTests: XCTestCase {
    private var fixture: EndpointPolicyFixture!
    private var state: NativeFastPathPolicyState!
    private var policy: NativeSessionEnforcementPolicy!
    private var root: NativeProcessIdentity!
    private var now: Int64 { fixture.verificationTime }

    override func setUpWithError() throws {
        try super.setUpWithError()
        fixture = try EndpointPolicyFixture.load()
        policy = try fixture.sessionPolicy()
        (_, state) = try fixture.installedControl()
        root = identity(1)
        try state.bindRootForTesting(
            auditToken: root.auditToken, sessionID: policy.sessionID, nowUnixMilliseconds: now
        )
    }

    private func decide(_ event: NativeEndpointEvent, at time: Int64? = nil)
        -> NativeAuthorizationDecision
    {
        state.decideForTesting(event, nowUnixMilliseconds: time ?? now)
    }

    private func open(_ path: String, actor: NativeProcessIdentity? = nil, flags: Int32 = FREAD)
        -> NativeEndpointEvent
    {
        NativeEndpointEvent(
            kind: .authOpen, actor: actor ?? root, path: path, requestedOpenFlags: UInt32(flags)
        )
    }

    // MARK: - Paths

    func test_workspace_open_is_permitted() {
        let decision = decide(open("/Users/test/workspace/README.md", flags: FREAD | FWRITE))
        XCTAssertTrue(decision.allow, "managed workspace open was denied")
        XCTAssertEqual(decision.reason, .permitWorkspacePath)
    }

    func test_similar_prefix_sibling_is_not_inside_the_workspace() {
        // `/Users/test/workspace-escape` shares a string prefix with the workspace but is a
        // different directory. Prefix matching without a boundary check grants it.
        let decision = decide(open("/Users/test/workspace-escape/file"))
        XCTAssertFalse(decision.allow, "similar-prefix workspace escape was allowed")
        XCTAssertEqual(decision.reason, .denyOutsideWorkspace)
    }

    func test_protected_path_is_refused() {
        let decision = decide(open("/Users/test/.ssh/id_ed25519"))
        XCTAssertFalse(decision.allow, "protected path was allowed")
        XCTAssertEqual(decision.reason, .denyProtectedPath)
    }

    func test_parent_traversal_is_refused_rather_than_normalized() {
        // Normalizing here would decide against a path the kernel never resolves.
        let decision = decide(NativeEndpointEvent(
            kind: .authCreate, actor: root, path: "/Users/test/workspace/../escape"
        ))
        XCTAssertFalse(decision.allow, "parent traversal create was allowed")
        XCTAssertEqual(decision.reason, .denyMalformedPath)
    }

    func test_rename_destination_must_also_be_inside_the_workspace() {
        let decision = decide(NativeEndpointEvent(
            kind: .authRename, actor: root,
            path: "/Users/test/workspace/source", destinationPath: "/tmp/destination"
        ))
        XCTAssertFalse(decision.allow, "rename out of the workspace was allowed")
        XCTAssertEqual(decision.reason, .denyOutsideWorkspace)
    }

    func test_truncated_path_is_refused() {
        // A truncated path cannot be compared against anything safely, so it is never allowed.
        let decision = decide(NativeEndpointEvent(
            kind: .authUnlink, actor: root, path: "/Users/test/workspace/partial", pathTruncated: true
        ))
        XCTAssertFalse(decision.allow, "truncated unlink path was allowed")
        XCTAssertEqual(decision.reason, .denyTruncatedPath)
    }

    // MARK: - Execution and attribution

    func test_denied_exec_does_not_move_attribution() {
        let decision = decide(NativeEndpointEvent(
            kind: .authExec, actor: root, targetProcess: identity(2, executable: "/bin/sh")
        ))
        XCTAssertFalse(decision.allow, "non-allowlisted executable was allowed")
        XCTAssertEqual(
            state.attributedSession(auditToken: root.auditToken), policy.sessionID,
            "denied exec changed process attribution"
        )
    }

    func test_permitted_exec_moves_attribution_to_the_new_token() {
        // exec replaces the image behind the same pid, so the audit token changes. Attribution
        // has to follow it, or the post-exec process becomes unmanaged.
        let target = identity(3)
        let decision = decide(NativeEndpointEvent(
            kind: .authExec, actor: root, targetProcess: target
        ))
        XCTAssertTrue(decision.allow, "allowlisted executable was denied")
        XCTAssertEqual(decision.reason, .permitExactExecutable)
        XCTAssertNil(
            state.attributedSession(auditToken: root.auditToken),
            "successful exec retained the old audit-token attribution"
        )
        XCTAssertEqual(
            state.attributedSession(auditToken: target.auditToken), policy.sessionID,
            "successful exec did not move attribution to the new audit token"
        )
    }

    func test_fork_inherits_and_exit_releases_attribution() {
        let child = identity(4)
        _ = decide(NativeEndpointEvent(kind: .notifyFork, actor: root, targetProcess: child))
        XCTAssertEqual(
            state.attributedSession(auditToken: child.auditToken), policy.sessionID,
            "fork did not inherit process attribution"
        )

        _ = decide(NativeEndpointEvent(kind: .notifyExit, actor: child))
        XCTAssertNil(
            state.attributedSession(auditToken: child.auditToken),
            "exit did not remove process attribution"
        )
    }

    // MARK: - Blast radius

    func test_unmanaged_process_is_untouched() {
        // VIGIL confines the agent, not the host. A bug that denied here would take the
        // machine down with it.
        let decision = decide(open("/outside/unmanaged", actor: identity(5)))
        XCTAssertTrue(decision.allow, "unmanaged process caused a host-wide denial")
        XCTAssertEqual(decision.reason, .unmanagedProcess)
    }

    func test_expired_policy_denies_managed_but_not_unmanaged_processes() {
        let managed = decide(open("/Users/test/workspace/README.md"), at: now + 60_000)
        XCTAssertFalse(managed.allow, "expired managed policy failed open")
        XCTAssertEqual(managed.reason, .denyExpiredPolicy)

        let unmanaged = decide(open("/outside/unmanaged", actor: identity(5)), at: now + 60_000)
        XCTAssertTrue(unmanaged.allow, "expired policy denied an unmanaged host process")
        XCTAssertEqual(unmanaged.reason, .unmanagedProcess)
    }

    func test_clock_failure_denies_a_managed_process() {
        // Without a trustworthy clock, expiry cannot be evaluated — so authority lapses.
        let decision = state.decideWithClockFailureForTesting(
            open("/Users/test/workspace/README.md")
        )
        XCTAssertFalse(decision.allow, "managed clock failure failed open")
        XCTAssertEqual(decision.reason, .denyPolicyClockFailure)
    }

    // MARK: - Snapshot replacement

    func test_stale_snapshot_is_refused() throws {
        XCTAssertThrowsError(try state.install(fixture.verifiedSnapshot())) { error in
            guard case NativeFastPathPolicyError.staleSnapshot = error else {
                return XCTFail("expected staleSnapshot, got \(error)")
            }
        }
    }

    func test_replacing_the_snapshot_drops_removed_sessions_attributions() throws {
        let target = identity(3)
        _ = decide(NativeEndpointEvent(kind: .authExec, actor: root, targetProcess: target))
        XCTAssertEqual(state.attributedSession(auditToken: target.auditToken), policy.sessionID)

        try state.installForTesting(NativeFastPathSnapshot(
            version: 43, expiresAtUnixMilliseconds: now + 120_000,
            sessions: [], protectedPrefixes: []
        ))

        XCTAssertEqual(state.snapshotVersion(), 43, "policy snapshot version did not advance")
        // A session removed by a new snapshot must not leave a process still attributed to it.
        XCTAssertNil(
            state.attributedSession(auditToken: target.auditToken),
            "removed session retained a stale process attribution"
        )
    }

    // MARK: - Binding guards
    //
    // `NativeEndpointControlService` refuses a bind under expired policy before the fast path
    // is reached, so these exercise the fast path's own guards directly. Without them the
    // checks below are defense in depth that nothing proves is still wired up — removing the
    // expiry guard leaves the whole suite green.

    func test_bind_is_refused_once_policy_has_expired() {
        XCTAssertThrowsError(try state.bindRootForTesting(
            auditToken: identity(9).auditToken, sessionID: policy.sessionID,
            nowUnixMilliseconds: now + 60_000
        )) { error in
            guard case NativeFastPathPolicyError.policyExpired = error else {
                return XCTFail("expected policyExpired, got \(error)")
            }
        }
    }

    func test_bind_is_refused_for_a_negative_clock_reading() {
        // A negative wall clock is not merely early — it is evidence the clock cannot be
        // trusted to evaluate expiry at all.
        XCTAssertThrowsError(try state.bindRootForTesting(
            auditToken: identity(10).auditToken, sessionID: policy.sessionID,
            nowUnixMilliseconds: -1
        )) { error in
            guard case NativeFastPathPolicyError.policyExpired = error else {
                return XCTFail("expected policyExpired, got \(error)")
            }
        }
    }

    func test_bind_is_refused_for_an_unknown_session() {
        XCTAssertThrowsError(try state.bindRootForTesting(
            auditToken: identity(11).auditToken, sessionID: "session-that-does-not-exist",
            nowUnixMilliseconds: now
        )) { error in
            guard case NativeFastPathPolicyError.missingSession = error else {
                return XCTFail("expected missingSession, got \(error)")
            }
        }
    }

    func test_bind_is_refused_for_a_malformed_audit_token() {
        XCTAssertThrowsError(try state.bindRootForTesting(
            auditToken: [1, 2, 3], sessionID: policy.sessionID, nowUnixMilliseconds: now
        )) { error in
            guard case NativeFastPathPolicyError.invalidAuditToken = error else {
                return XCTFail("expected invalidAuditToken, got \(error)")
            }
        }
    }

    func test_a_bound_audit_token_cannot_be_reassigned() throws {
        let second = try NativeSessionEnforcementPolicy(
            sessionID: "session-fixture-2",
            workspaceRoots: ["/Users/test/second-workspace"],
            allowedExecutables: []
        )
        let conflicting = try NativeFastPathPolicyState(
            testingSnapshot: NativeFastPathSnapshot(
                version: 1, expiresAtUnixMilliseconds: now + 120_000,
                sessions: [policy, second], protectedPrefixes: []
            )
        )
        let token = identity(7)
        try conflicting.bindRootForTesting(
            auditToken: token.auditToken, sessionID: policy.sessionID, nowUnixMilliseconds: now
        )

        // A full audit-token identity is immutable once bound — otherwise a second bind could
        // move a running process into a more permissive session.
        XCTAssertThrowsError(try conflicting.bindRootForTesting(
            auditToken: token.auditToken, sessionID: second.sessionID, nowUnixMilliseconds: now
        )) { error in
            guard case NativeFastPathPolicyError.attributionConflict = error else {
                return XCTFail("expected attributionConflict, got \(error)")
            }
        }
        XCTAssertEqual(conflicting.attributionCount(), 1, "conflicting root bind changed state")
        XCTAssertEqual(
            conflicting.attributedSession(auditToken: token.auditToken), policy.sessionID,
            "conflicting root bind replaced the original session"
        )
    }
}
