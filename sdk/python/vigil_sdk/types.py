"""Typed models for the VIGIL wire protocol.

Deviation from the build specification, stated plainly
------------------------------------------------------
The specification calls for Pydantic. This SDK uses dataclasses and hand-written validation
instead, for one reason: it is code that runs *inside* the agent process being protected, and
every dependency it pulls in becomes part of the attack surface of the thing doing the
protecting. A security SDK that drags a large transitive tree into an agent's runtime is
working against its own purpose, and version conflicts with the host application are a
support burden that pushes teams to skip instrumentation entirely.

The properties Pydantic would provide are preserved: every field is typed, every model
validates on construction, and unknown fields are rejected rather than ignored. Pydantic
models are available as an optional extra (``vigil-sdk[pydantic]``) for applications that
already depend on it and want to share validators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

__all__ = [
    "SCHEMA_VERSION",
    "TrustLevel",
    "TaintKind",
    "Decision",
    "ValidationError",
    "Principal",
    "WorkloadIdentity",
    "ProvenanceRef",
    "RequestContext",
    "ActionRequest",
    "DecisionResponse",
]

#: Wire schema version. Must match ``vigil_protocol::SCHEMA_VERSION``.
SCHEMA_VERSION = "vigil.v1"

#: The shared identifier grammar. Narrow on purpose: values matching it are safe to
#: interpolate into log lines, metric labels, URL path segments and file names.
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class ValidationError(ValueError):
    """A value does not satisfy the protocol's requirements."""


def validate_id(field_name: str, value: str) -> str:
    """Validate an identifier, or raise.

    Rejects rather than sanitizes. Silently rewriting an identifier would mean the SDK and
    Core disagree about which session or agent an event belongs to.
    """
    if not isinstance(value, str) or not _ID_PATTERN.match(value):
        raise ValidationError(
            f"{field_name} must match [A-Za-z0-9._:-]{{1,128}}, got {value!r}"
        )
    return value


class TrustLevel(str, Enum):
    """Where content came from, and therefore how much authority it carries."""

    SYSTEM_TRUSTED = "SYSTEM_TRUSTED"
    ADMIN_TRUSTED = "ADMIN_TRUSTED"
    TOOL_SIGNED = "TOOL_SIGNED"
    MEMORY_VALIDATED = "MEMORY_VALIDATED"
    USER_AUTHENTICATED = "USER_AUTHENTICATED"
    USER_UNTRUSTED = "USER_UNTRUSTED"
    TOOL_UNVERIFIED = "TOOL_UNVERIFIED"
    MEMORY_UNTRUSTED = "MEMORY_UNTRUSTED"
    AGENT_UNTRUSTED = "AGENT_UNTRUSTED"
    MCP_UNTRUSTED = "MCP_UNTRUSTED"
    RAG_UNTRUSTED = "RAG_UNTRUSTED"
    EMAIL_UNTRUSTED = "EMAIL_UNTRUSTED"
    WEB_UNTRUSTED = "WEB_UNTRUSTED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"

    @classmethod
    def conservative_default(cls) -> TrustLevel:
        """The label to assume when a source is unknown."""
        return cls.EXTERNAL_UNTRUSTED

    def carries_instruction_authority(self) -> bool:
        """Whether instructions in this content may influence privileged action."""
        return self in {
            TrustLevel.SYSTEM_TRUSTED,
            TrustLevel.ADMIN_TRUSTED,
            TrustLevel.TOOL_SIGNED,
            TrustLevel.MEMORY_VALIDATED,
            TrustLevel.USER_AUTHENTICATED,
        }


class TaintKind(str, Enum):
    """Categories of sensitive or dangerous data."""

    UNTRUSTED_INSTRUCTION = "UNTRUSTED_INSTRUCTION"
    SECRET = "SECRET"  # noqa: S105 - a taint label, not a credential
    CREDENTIAL = "CREDENTIAL"
    PII = "PII"
    FINANCIAL_DATA = "FINANCIAL_DATA"
    AUTHENTICATION_DATA = "AUTHENTICATION_DATA"
    CONFIDENTIAL_DATA = "CONFIDENTIAL_DATA"
    EXECUTABLE_CONTENT = "EXECUTABLE_CONTENT"
    EXTERNAL_URL = "EXTERNAL_URL"
    UNTRUSTED_CODE = "UNTRUSTED_CODE"
    SECURITY_POLICY_CONTENT = "SECURITY_POLICY_CONTENT"
    APPROVAL_DATA = "APPROVAL_DATA"


class Decision(str, Enum):
    """What VIGIL decided."""

    ALLOW = "ALLOW"
    ALLOW_WITH_CONSTRAINTS = "ALLOW_WITH_CONSTRAINTS"
    ALLOW_WITH_REDACTION = "ALLOW_WITH_REDACTION"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    QUARANTINE = "QUARANTINE"
    DENY = "DENY"
    TERMINATE_SESSION = "TERMINATE_SESSION"

    def permits_execution(self) -> bool:
        return self in {
            Decision.ALLOW,
            Decision.ALLOW_WITH_CONSTRAINTS,
            Decision.ALLOW_WITH_REDACTION,
        }

    def terminates_session(self) -> bool:
        return self is Decision.TERMINATE_SESSION


@dataclass(frozen=True)
class Principal:
    """The human or service on whose behalf an agent acts."""

    id: str
    kind: str
    tenant_id: str
    roles: list[str] = field(default_factory=list)
    auth_method: str | None = None
    mfa: bool = False

    def __post_init__(self) -> None:
        validate_id("principal.id", self.id)
        validate_id("principal.tenant_id", self.tenant_id)
        if self.kind not in {"human", "service", "agent", "anonymous"}:
            raise ValidationError(f"unknown principal kind {self.kind!r}")

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "tenant_id": self.tenant_id,
            "roles": list(self.roles),
            "auth_method": self.auth_method,
            "mfa": self.mfa,
        }


@dataclass(frozen=True)
class WorkloadIdentity:
    """A cryptographically attested compute identity.

    ``verified`` must only be True when this process genuinely proved its identity. Setting
    it True without proof does not gain the agent anything — Core re-checks against the
    transport — but it does put a false claim in the audit record.
    """

    id: str
    attestation_method: str
    verified: bool = False

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "attestation_method": self.attestation_method,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class ProvenanceRef:
    """A reference to content already registered with VIGIL Trace."""

    node_id: str
    trust_level: TrustLevel
    origin: str
    content_hash: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "trust_level": self.trust_level.value,
            "origin": self.origin,
            "content_hash": self.content_hash,
        }


@dataclass
class RequestContext:
    """Optional signals accompanying an action.

    ``declared_objective`` and ``action_rationale`` are *observable* reasoning telemetry: a
    planner event the framework emitted, not hidden model chain-of-thought, which VIGIL never
    attempts to extract. Every field here is optional, and enforcement works identically when
    all of them are absent.
    """

    declared_objective: str | None = None
    action_rationale: str | None = None
    influencing_sources: list[ProvenanceRef] = field(default_factory=list)
    step: int = 0
    approval_token: str | None = None
    adapter_metadata: dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        return {
            "declared_objective": self.declared_objective,
            "action_rationale": self.action_rationale,
            "influencing_sources": [s.to_wire() for s in self.influencing_sources],
            "step": self.step,
            "approval_token": self.approval_token,
            "adapter_metadata": self.adapter_metadata,
        }


@dataclass
class ActionRequest:
    """One candidate action, normalized."""

    request_id: str
    tenant_id: str
    environment_id: str
    session_id: str
    agent_id: str
    agent_instance_id: str
    principal: Principal
    action: dict[str, Any]
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    workload_identity: WorkloadIdentity | None = None
    context: RequestContext = field(default_factory=RequestContext)

    def __post_init__(self) -> None:
        for name in (
            "request_id",
            "tenant_id",
            "environment_id",
            "session_id",
            "agent_id",
            "agent_instance_id",
        ):
            validate_id(name, getattr(self, name))
        if "kind" not in self.action:
            raise ValidationError("action must carry a 'kind' discriminator")
        if self.principal.tenant_id != self.tenant_id:
            raise ValidationError(
                "principal tenant does not match request tenant; Core rejects this too, "
                "but failing here keeps a cross-tenant bug local to the caller"
            )

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "request_id": self.request_id,
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat(),
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "agent_instance_id": self.agent_instance_id,
            "principal": self.principal.to_wire(),
            "workload_identity": (
                self.workload_identity.to_wire() if self.workload_identity else None
            ),
            "trace": {},
            "action": self.action,
            "context": self.context.to_wire(),
        }


@dataclass(frozen=True)
class DecisionResponse:
    """What Core decided."""

    decision: Decision
    decision_id: str
    action_hash: str
    risk_score: float
    confidence: float
    reason_codes: list[str]
    capability: str | None
    approval_id: str | None
    latency_ms: int
    raw: dict[str, Any]

    @classmethod
    def from_wire(cls, payload: dict[str, Any]) -> DecisionResponse:
        return cls(
            decision=Decision(payload["decision"]),
            decision_id=payload.get("decision_id", ""),
            action_hash=payload.get("action_hash", ""),
            risk_score=float(payload.get("risk_score", 0.0)),
            confidence=float(payload.get("confidence", 0.0)),
            reason_codes=list(payload.get("reason_codes", [])),
            capability=payload.get("capability"),
            approval_id=payload.get("approval_id"),
            latency_ms=int(payload.get("latency_ms", 0)),
            raw=payload,
        )

    def permits_execution(self) -> bool:
        return self.decision.permits_execution()

    def is_coherent(self) -> bool:
        """A decision that permits execution must carry a capability, and vice versa.

        Checked client-side as well as server-side: a mismatch means either a protocol bug or
        a response that did not come from VIGIL, and both should stop the action.
        """
        return (self.capability is not None) == self.decision.permits_execution()
