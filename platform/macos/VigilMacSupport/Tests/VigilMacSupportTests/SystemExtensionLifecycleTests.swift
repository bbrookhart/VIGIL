import Foundation
import Testing
@testable import VigilMacSupport

@Suite("System Extension activation lifecycle")
struct SystemExtensionLifecycleTests {
    private let identifier = "com.vigil.security.network"

    @Test("a newer short version replaces the installed extension")
    func newerVersionReplaces() {
        #expect(decision(existing: ("1.4.9", "19"), candidate: ("1.5.0", "1")) == .replace)
    }

    @Test("a newer build of the same release replaces the installed extension")
    func newerBuildReplaces() {
        #expect(decision(existing: ("1.5.0", "19"), candidate: ("1.5.0", "20")) == .replace)
    }

    @Test("developer-mode replacement of an identical version is allowed")
    func equalVersionReplaces() {
        #expect(decision(existing: ("1.5.0", "20"), candidate: ("1.5.0", "20")) == .replace)
    }

    @Test("a release downgrade is refused")
    func releaseDowngradeIsRefused() {
        #expect(decision(existing: ("2.0.0", "1"), candidate: ("1.9.9", "99")) == .cancelDowngrade)
    }

    @Test("a build downgrade within one release is refused")
    func buildDowngradeIsRefused() {
        #expect(decision(existing: ("1.5.0", "20"), candidate: ("1.5.0", "19")) == .cancelDowngrade)
    }

    @Test("numeric comparison does not order version 10 before version 2")
    func versionsCompareNumerically() {
        #expect(decision(existing: ("1.2.0", "9"), candidate: ("1.10.0", "10")) == .replace)
    }

    @Test("identity mismatch is refused even when the version increases")
    func identityMismatchIsRefused() {
        let existing = version("1.0.0", "1")
        let candidate = SystemExtensionVersion(
            bundleIdentifier: "com.attacker.network",
            shortVersion: "2.0.0",
            buildVersion: "2"
        )
        #expect(SystemExtensionLifecycle.replacementDecision(
            expectedIdentifier: identifier,
            existing: existing,
            candidate: candidate
        ) == .cancelIdentityMismatch)
    }

    @Test("ambiguous or nonnumeric version syntax fails closed", arguments: [
        "", "1..2", "1.2-beta", "١.٢.٣", "1.2.3.4.5", String(repeating: "1", count: 65),
    ])
    func malformedVersionsAreRefused(candidateVersion: String) {
        #expect(decision(existing: ("1.0.0", "1"), candidate: (candidateVersion, "2")) == .cancelInvalidVersion)
    }

    @Test("known OS failures become stable non-sensitive reasons", arguments: [
        (2, SystemExtensionFailureReason.missingEntitlement),
        (8, .invalidCodeSignature),
        (10, .forbiddenBySystemPolicy),
        (11, .requestCancelled),
        (13, .authorizationRequired),
    ])
    func knownFailuresAreClassified(code: Int, reason: SystemExtensionFailureReason) {
        let error = NSError(
            domain: "OSSystemExtensionErrorDomain",
            code: code,
            userInfo: [NSLocalizedDescriptionKey: "sensitive operating-system detail"]
        )
        #expect(SystemExtensionLifecycle.failure(for: error) == SystemExtensionFailure(
            reason: reason,
            systemCode: code
        ))
    }

    @Test("foreign error domains disclose neither description nor code")
    func foreignErrorsAreOpaque() {
        let error = NSError(domain: "attacker.example", code: 999, userInfo: [
            NSLocalizedDescriptionKey: "secret path /Users/example/private",
        ])
        #expect(SystemExtensionLifecycle.failure(for: error) == SystemExtensionFailure(reason: .unknown))
    }

    @Test("only request-pending states block another request")
    func requestInFlightIsExact() {
        #expect(SystemExtensionActivationState.submitting(.activate).requestInFlight)
        #expect(SystemExtensionActivationState.awaitingUserApproval.requestInFlight)
        #expect(!SystemExtensionActivationState.active(version: "1.0 (1)").requestInFlight)
        #expect(!SystemExtensionActivationState.rebootRequired(.deactivate).requestInFlight)
        #expect(!SystemExtensionActivationState.failed(.init(reason: .unknown)).requestInFlight)
    }

    private func decision(
        existing: (String, String),
        candidate: (String, String)
    ) -> SystemExtensionReplacementDecision {
        SystemExtensionLifecycle.replacementDecision(
            expectedIdentifier: identifier,
            existing: version(existing.0, existing.1),
            candidate: version(candidate.0, candidate.1)
        )
    }

    private func version(_ shortVersion: String, _ buildVersion: String) -> SystemExtensionVersion {
        SystemExtensionVersion(
            bundleIdentifier: identifier,
            shortVersion: shortVersion,
            buildVersion: buildVersion
        )
    }
}
