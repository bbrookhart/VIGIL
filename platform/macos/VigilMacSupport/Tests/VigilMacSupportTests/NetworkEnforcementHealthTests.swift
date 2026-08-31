import CryptoKit
import Testing
import VigilNetworkAdapter
@testable import VigilMacSupport

@Suite("Network enforcement health")
struct NetworkEnforcementHealthTests {
    private let now: UInt64 = 1_000_000

    @Test("all four current evidence planes are required for fully enforced")
    func allEvidenceProducesFullyEnforced() {
        #expect(evaluate() == NetworkEnforcementHealth(
            posture: .fullyEnforced,
            reason: .healthy,
            verifiedPolicyGeneration: 42
        ))
    }

    @Test("only verified signed provider health crosses into ready evidence")
    func verifiedProviderHealthMintsReadyEvidence() throws {
        let key = Curve25519.Signing.PrivateKey()
        let reading = try NativeNetworkProviderHealthReading(
            targetInstanceID: "network-instance-1",
            providerBundleIdentifier: "com.vigil.security.network",
            policyGeneration: 42,
            policyExpiresAtUnixMilliseconds: Int64(now + 60_000),
            observedAtUnixMilliseconds: Int64(now - 1_000),
            allowedFlows: 7,
            droppedFlows: 3,
            pausedFlows: 2
        )
        let envelope = try NativeNetworkProviderHealthSigner(
            keyID: "provider-health-k1",
            privateKey: key.rawRepresentation
        ).sign(reading)
        let verified = try NativeSignedNetworkProviderHealthVerifier(
            expectedInstanceID: "network-instance-1",
            expectedProviderBundleIdentifier: "com.vigil.security.network",
            trustedKeys: ["provider-health-k1": key.publicKey.rawRepresentation]
        ).verify(envelopeData: envelope, nowUnixMilliseconds: Int64(now))

        #expect(evaluate(provider: NetworkProviderHealthEvidence(verified)).posture == .fullyEnforced)
    }

    @Test("an inactive extension reports observe only")
    func inactiveExtensionIsObserveOnly() {
        #expect(evaluate(activation: .inactive).reason == .extensionInactive)
        #expect(evaluate(activation: .inactive).posture == .observeOnly)
    }

    @Test("an unknown extension status cannot inherit downstream evidence")
    func unknownExtensionIsObserveOnly() {
        #expect(evaluate(activation: .unknown).reason == .extensionStatusUnknown)
    }

    @Test("transitional extension states do not claim enforcement", arguments: [
        SystemExtensionActivationState.submitting(.activate),
        .awaitingUserApproval,
        .uninstalling,
        .rebootRequired(.activate),
    ])
    func transitionIsObserveOnly(state: SystemExtensionActivationState) {
        #expect(evaluate(activation: state).posture == .observeOnly)
        #expect(evaluate(activation: state).reason == .extensionTransitionInProgress)
    }

    @Test("an activation failure is broken rather than silently downgraded")
    func activationFailureIsBroken() {
        let state = SystemExtensionActivationState.failed(.init(reason: .missingEntitlement))
        #expect(evaluate(activation: state).posture == .broken)
        #expect(evaluate(activation: state).reason == .extensionRequestFailed)
    }

    @Test("missing preference evidence is degraded")
    func missingPreferenceEvidenceIsDegraded() {
        #expect(evaluate(preferences: .unavailable) == NetworkEnforcementHealth(
            posture: .degraded,
            reason: .preferenceEvidenceUnavailable
        ))
    }

    @Test("absent and disabled preferences remain distinct", arguments: [
        (NetworkFilterPreferenceEvidence.absent, NetworkEnforcementHealthReason.preferencesAbsent),
        (.disabled, .preferencesDisabled),
    ])
    func inactivePreferencesAreDegraded(
        evidence: NetworkFilterPreferenceEvidence,
        reason: NetworkEnforcementHealthReason
    ) {
        #expect(evaluate(preferences: evidence).posture == .degraded)
        #expect(evaluate(preferences: evidence).reason == reason)
    }

    @Test("enabled configuration drift is broken")
    func preferenceDriftIsBroken() {
        #expect(evaluate(preferences: .configurationDrifted(enabled: true)).reason == .preferencesDrifted)
        #expect(evaluate(preferences: .configurationDrifted(enabled: true)).posture == .broken)
    }

    @Test("missing provider evidence is degraded")
    func missingProviderEvidenceIsDegraded() {
        #expect(evaluate(provider: .unavailable).reason == .providerEvidenceUnavailable)
    }

    @Test("explicit provider unready evidence is broken")
    func unreadyProviderIsBroken() {
        #expect(evaluate(provider: .unready(.callbackFailure)).posture == .broken)
        #expect(evaluate(provider: .unready(.callbackFailure)).reason == .providerUnready)
    }

    @Test("provider evidence from the future is rejected")
    func futureProviderEvidenceIsBroken() {
        #expect(evaluate(provider: provider(observedAt: now + 1)).reason == .providerEvidenceFromFuture)
    }

    @Test("stale provider evidence is rejected")
    func staleProviderEvidenceIsBroken() {
        #expect(evaluate(provider: provider(observedAt: now - 30_001)).reason == .providerEvidenceStale)
    }

    @Test("policy expiry is exclusive")
    func expiredPolicyIsBroken() {
        #expect(evaluate(provider: provider(expiresAt: now)).reason == .providerPolicyExpired)
    }

    @Test("missing flow proof is degraded")
    func missingFlowEvidenceIsDegraded() {
        #expect(evaluate(flow: .unavailable).posture == .degraded)
        #expect(evaluate(flow: .unavailable).reason == .flowEvidenceUnavailable)
    }

    @Test("a failed privileged probe is broken")
    func failedFlowProbeIsBroken() {
        #expect(evaluate(flow: .probeFailed).reason == .flowProbeFailed)
    }

    @Test("flow evidence from the future is rejected")
    func futureFlowEvidenceIsBroken() {
        #expect(evaluate(flow: flow(observedAt: now + 1)).reason == .flowEvidenceFromFuture)
    }

    @Test("stale flow evidence is rejected")
    func staleFlowEvidenceIsBroken() {
        #expect(evaluate(flow: flow(observedAt: now - 30_001)).reason == .flowEvidenceStale)
    }

    @Test("flow proof must name the provider policy generation")
    func generationMismatchIsBroken() {
        #expect(evaluate(flow: flow(generation: 41)).reason == .flowGenerationMismatch)
    }

    @Test("both the allow and deny probes must prove their expected outcome")
    func bothProbeOutcomesAreRequired() {
        #expect(evaluate(flow: flow(allowed: false)).reason == .allowedDestinationUnreachable)
        #expect(evaluate(flow: flow(denied: false)).reason == .deniedDestinationReachable)
    }

    private func evaluate(
        activation: SystemExtensionActivationState = .active(version: "1.0.0 (1)"),
        preferences: NetworkFilterPreferenceEvidence = .enabled,
        provider: NetworkProviderHealthEvidence? = nil,
        flow: NetworkFlowEnforcementEvidence? = nil
    ) -> NetworkEnforcementHealth {
        NetworkEnforcementHealthEvaluator.evaluate(
            activation: activation,
            preferences: preferences,
            provider: provider ?? self.provider(),
            flow: flow ?? self.flow(),
            nowMilliseconds: now
        )
    }

    private func provider(
        generation: UInt64 = 42,
        expiresAt: UInt64? = nil,
        observedAt: UInt64? = nil
    ) -> NetworkProviderHealthEvidence {
        .ready(
            policyGeneration: generation,
            policyExpiresAtMilliseconds: expiresAt ?? now + 60_000,
            observedAtMilliseconds: observedAt ?? now - 1_000
        )
    }

    private func flow(
        generation: UInt64 = 42,
        allowed: Bool = true,
        denied: Bool = true,
        observedAt: UInt64? = nil
    ) -> NetworkFlowEnforcementEvidence {
        .observed(
            policyGeneration: generation,
            allowedDestinationReached: allowed,
            deniedDestinationBlocked: denied,
            observedAtMilliseconds: observedAt ?? now - 1_000
        )
    }
}
