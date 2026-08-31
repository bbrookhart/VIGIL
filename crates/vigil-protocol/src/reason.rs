//! Machine-readable reason codes.
//!
//! # Why
//!
//! "The model thought this looked risky" is not an auditable reason. Every VIGIL decision
//! returns codes an operator can filter on, a policy can key off, an alert can route by, and
//! a regression test can assert against. Natural-language explanations are for humans reading
//! the console; the codes are the contract.
//!
//! # Assumptions
//!
//! Codes are append-only. A code's meaning never changes, because historical audit records
//! reference it. Unknown codes parse into [`ReasonCode::Other`] so an older reader can still
//! process a newer decision without discarding information.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

macro_rules! reason_codes {
    ($( $(#[$doc:meta])* $variant:ident => $code:literal ),* $(,)?) => {
        /// Why a decision came out the way it did.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum ReasonCode {
            $( $(#[$doc])* $variant, )*
            /// A code emitted by a newer version of VIGIL than this reader.
            Other(String),
        }

        impl ReasonCode {
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $code, )*
                    Self::Other(s) => s.as_str(),
                }
            }

            /// Every code this build knows, used by the CLI to document them and by tests
            /// to assert that codes referenced in policy bundles actually exist.
            pub fn all() -> &'static [ReasonCode] {
                &[ $( ReasonCode::$variant, )* ]
            }
        }

        impl FromStr for ReasonCode {
            type Err = std::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $( $code => Self::$variant, )*
                    other => Self::Other(other.to_string()),
                })
            }
        }
    };
}

reason_codes! {
    // ---- request integrity ----
    /// The request did not match the action schema.
    SchemaInvalid => "SCHEMA_INVALID",
    /// The request could not be canonicalized, so it cannot be bound to an approval.
    CanonicalizationFailed => "CANONICALIZATION_FAILED",
    /// The request body exceeded configured limits.
    RequestTooLarge => "REQUEST_TOO_LARGE",

    // ---- identity ----
    /// No verified workload identity accompanied the request in a mode that requires one.
    WorkloadIdentityUnverified => "WORKLOAD_IDENTITY_UNVERIFIED",
    /// The presented identity does not match the registered agent.
    AgentIdentityMismatch => "AGENT_IDENTITY_MISMATCH",
    /// The request's tenant does not match the authenticated principal's tenant.
    CrossTenantRequest => "CROSS_TENANT_REQUEST",
    /// The principal is not authenticated to the standard this action requires.
    InsufficientAuthentication => "INSUFFICIENT_AUTHENTICATION",

    // ---- capability ----
    /// The capability signature did not verify.
    CapabilitySignatureInvalid => "CAPABILITY_SIGNATURE_INVALID",
    /// The capability is past its expiry.
    CapabilityExpired => "CAPABILITY_EXPIRED",
    /// The capability's nonce was already consumed.
    CapabilityReplay => "CAPABILITY_REPLAY",
    /// The presented action does not match the action the capability was minted for.
    CapabilityActionMismatch => "CAPABILITY_ACTION_MISMATCH",
    /// The capability was issued for a different tenant, agent, session or tool.
    CapabilityBindingMismatch => "CAPABILITY_BINDING_MISMATCH",
    /// The action reached the gateway with no capability at all.
    CapabilityMissing => "CAPABILITY_MISSING",

    // ---- policy ----
    /// An explicit deterministic policy rule denied this action.
    PolicyDeny => "POLICY_DENY",
    /// No rule permitted the action and the bundle is default-deny.
    PolicyDefaultDeny => "POLICY_DEFAULT_DENY",
    /// A policy rule requires human approval for this action.
    PolicyRequiresApproval => "POLICY_REQUIRES_APPROVAL",
    /// The policy engine failed; the action's failure policy was applied.
    PolicyEngineUnavailable => "POLICY_ENGINE_UNAVAILABLE",

    // ---- remit ----
    /// The tool is not in the agent's remit.
    OutOfRemitTool => "OUT_OF_REMIT_TOOL",
    /// The operation is not permitted on a tool that is otherwise in remit.
    OutOfRemitOperation => "OUT_OF_REMIT_OPERATION",
    /// The targeted resource or data class is outside the remit.
    OutOfRemitResource => "OUT_OF_REMIT_RESOURCE",
    /// The action pursues a goal the remit explicitly forbids.
    ForbiddenGoal => "FORBIDDEN_GOAL",
    /// The agent's observed objective has drifted from its declared purpose.
    RemitDrift => "REMIT_DRIFT",
    /// The agent has no registered remit, and unregistered agents are not permitted.
    RemitMissing => "REMIT_MISSING",

    // ---- provenance and taint ----
    /// Untrusted content causally influenced this action.
    UntrustedInstructionFlow => "UNTRUSTED_INSTRUCTION_FLOW",
    /// Untrusted content attempted to assert authority over the agent.
    UntrustedAuthorityClaim => "UNTRUSTED_AUTHORITY_CLAIM",
    /// A secret would leave the trust boundary through this action.
    SecretEgress => "SECRET_EGRESS",
    /// Personal data would leave the trust boundary through this action.
    PiiEgress => "PII_EGRESS",
    /// Financial data would leave the trust boundary through this action.
    FinancialDataEgress => "FINANCIAL_DATA_EGRESS",
    /// Tainted data is flowing to a destination not approved for it.
    TaintedDestination => "TAINTED_DESTINATION",
    /// Content read from memory carries an untrusted provenance label.
    UntrustedMemoryRead => "UNTRUSTED_MEMORY_READ",
    /// An attempt to persist untrusted instructions into memory.
    MemoryPoisoningAttempt => "MEMORY_POISONING_ATTEMPT",

    // ---- detection ----
    /// Content matched prompt-injection indicators.
    PromptInjectionSuspected => "PROMPT_INJECTION_SUSPECTED",
    /// Content contained instructions to disable or evade security controls.
    GuardrailEvasionAttempt => "GUARDRAIL_EVASION_ATTEMPT",
    /// Content used encoding or homoglyphs to obscure instructions.
    ObfuscatedContent => "OBFUSCATED_CONTENT",
    /// Content impersonated a system or tool message.
    RoleSpoofing => "ROLE_SPOOFING",
    /// A detector timed out or errored; risk was raised rather than ignored.
    DetectorDegraded => "DETECTOR_DEGRADED",

    // ---- tool-specific constraint violations ----
    /// A shell command matched a prohibited pattern.
    DangerousShellCommand => "DANGEROUS_SHELL_COMMAND",
    /// An argument contained shell metacharacters where none are permitted.
    CommandInjectionSuspected => "COMMAND_INJECTION_SUSPECTED",
    /// A filesystem path escaped its permitted root.
    PathTraversal => "PATH_TRAVERSAL",
    /// A filesystem path is outside the paths the remit permits.
    PathOutsideAllowlist => "PATH_OUTSIDE_ALLOWLIST",
    /// A SQL statement performs an operation the remit does not permit.
    SqlOperationForbidden => "SQL_OPERATION_FORBIDDEN",
    /// A SQL statement showed injection indicators.
    SqlInjectionSuspected => "SQL_INJECTION_SUSPECTED",
    /// A network destination is not on the permitted egress list.
    EgressDestinationForbidden => "EGRESS_DESTINATION_FORBIDDEN",
    /// A network request targets a private, loopback or link-local address.
    SsrfPrivateAddress => "SSRF_PRIVATE_ADDRESS",
    /// A network request targets a cloud instance metadata endpoint.
    SsrfMetadataEndpoint => "SSRF_METADATA_ENDPOINT",
    /// A request used a protocol scheme that is not permitted.
    ProtocolSchemeForbidden => "PROTOCOL_SCHEME_FORBIDDEN",
    /// A redirect chain left the permitted destination set.
    RedirectOutsidePolicy => "REDIRECT_OUTSIDE_POLICY",
    /// Arguments did not conform to the tool manifest's declared schema.
    ToolArgumentSchemaViolation => "TOOL_ARGUMENT_SCHEMA_VIOLATION",
    /// The tool is not registered, and unregistered tools are treated conservatively.
    ToolUnregistered => "TOOL_UNREGISTERED",

    // ---- MCP ----
    /// An MCP tool definition changed from its recorded fingerprint.
    McpToolDefinitionChanged => "MCP_TOOL_DEFINITION_CHANGED",
    /// An MCP tool description contained instruction-like content aimed at the agent.
    McpToolDescriptionPoisoned => "MCP_TOOL_DESCRIPTION_POISONED",
    /// An MCP server requested scopes beyond what was registered.
    McpExcessiveScope => "MCP_EXCESSIVE_SCOPE",
    /// A token was passed through to an MCP server that should not receive it.
    McpTokenPassthrough => "MCP_TOKEN_PASSTHROUGH",
    /// The MCP server identity did not match the registered server.
    McpServerSubstitution => "MCP_SERVER_SUBSTITUTION",

    // ---- multi-agent ----
    /// A delegation would grant more authority than the delegator holds.
    DelegationPrivilegeExpansion => "DELEGATION_PRIVILEGE_EXPANSION",
    /// The delegation graph contains a cycle.
    DelegationCycle => "DELEGATION_CYCLE",
    /// Delegation exceeded the permitted depth.
    DelegationDepthExceeded => "DELEGATION_DEPTH_EXCEEDED",
    /// A message from another agent carried untrusted instructions.
    PoisonedAgentMessage => "POISONED_AGENT_MESSAGE",

    // ---- approval ----
    /// This action requires an approval that has not been granted.
    ApprovalRequired => "APPROVAL_REQUIRED",
    /// The approval has expired.
    ApprovalExpired => "APPROVAL_EXPIRED",
    /// The approval was already consumed.
    ApprovalReplay => "APPROVAL_REPLAY",
    /// The action changed after approval was granted.
    ApprovalActionMutated => "APPROVAL_ACTION_MUTATED",
    /// The approver is the same principal as the requester.
    SelfApprovalRejected => "SELF_APPROVAL_REJECTED",
    /// The approval signature did not verify.
    ApprovalSignatureInvalid => "APPROVAL_SIGNATURE_INVALID",

    // ---- budgets ----
    /// The session exceeded its tool-call budget.
    ToolCallBudgetExceeded => "TOOL_CALL_BUDGET_EXCEEDED",
    /// The session exceeded its model-call budget.
    ModelCallBudgetExceeded => "MODEL_CALL_BUDGET_EXCEEDED",
    /// The session exceeded its wall-clock budget.
    WallClockBudgetExceeded => "WALL_CLOCK_BUDGET_EXCEEDED",
    /// The session exceeded its estimated cost budget.
    CostBudgetExceeded => "COST_BUDGET_EXCEEDED",
    /// The agent is repeating a semantically equivalent action.
    LoopDetected => "LOOP_DETECTED",
    /// The rate limit for this tool was exceeded.
    RateLimitExceeded => "RATE_LIMIT_EXCEEDED",

    // ---- behavioural ----
    /// The agent retried variants of a denied action.
    DeniedActionRetryPattern => "DENIED_ACTION_RETRY_PATTERN",
    /// The agent attempted to acquire privileges it did not start with.
    PrivilegeSeeking => "PRIVILEGE_SEEKING",
    /// The agent attempted to modify VIGIL policy or configuration.
    SelfModificationAttempt => "SELF_MODIFICATION_ATTEMPT",
    /// The agent attempted to establish persistence.
    PersistenceAttempt => "PERSISTENCE_ATTEMPT",
    /// Session behaviour deviates from the established envelope.
    BehavioralAnomaly => "BEHAVIORAL_ANOMALY",

    // ---- allow-side ----
    /// The action matched an explicit allow rule.
    PolicyAllow => "POLICY_ALLOW",
    /// The action is within remit.
    WithinRemit => "WITHIN_REMIT",
    /// A previously granted, still-valid approval covers this action.
    ApprovalSatisfied => "APPROVAL_SATISFIED",
    /// The action is read-only and low impact.
    LowImpactRead => "LOW_IMPACT_READ",
    /// A scoped, unexpired exception applied.
    ExceptionApplied => "EXCEPTION_APPLIED",

    // ---- failure handling ----
    /// A dependency failed and the action's fail-closed policy applied.
    FailClosed => "FAIL_CLOSED",
    /// A dependency failed and the action's degraded-mode policy permitted it.
    DegradedModeAllow => "DEGRADED_MODE_ALLOW",
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ReasonCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ReasonCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::from_str(&s).unwrap_or(ReasonCode::Other(s)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_through_their_string_form() {
        for code in ReasonCode::all() {
            let s = code.as_str();
            assert_eq!(&ReasonCode::from_str(s).unwrap(), code);
        }
    }

    #[test]
    fn codes_are_screaming_snake_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in ReasonCode::all() {
            let s = code.as_str();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()),
                "{s} is not SCREAMING_SNAKE_CASE"
            );
            assert!(seen.insert(s), "duplicate reason code {s}");
        }
    }

    #[test]
    fn unknown_codes_from_a_newer_build_survive_a_round_trip() {
        let json = "\"SOME_FUTURE_CODE\"";
        let parsed: ReasonCode = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, ReasonCode::Other("SOME_FUTURE_CODE".to_string()));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    }
}
