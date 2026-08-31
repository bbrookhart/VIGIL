"""The instrumentation surface: hooks an agent framework calls.

Why
---
This is where VIGIL meets the agent. The hooks mirror the lifecycle points every agent
framework already has, so integrating is a matter of wiring existing callbacks rather than
restructuring an application.

The critical design choice is what happens on the *unhappy* path. Every hook that guards a
side effect raises :class:`ActionBlocked` rather than returning a status, because a returned
status can be ignored by a caller who forgot to check it — and "forgot to check the return
value" is not an acceptable failure mode for the thing standing between an agent and a
production system.

What
----
The hooks required by the build specification:

``before_model`` / ``after_model``
``before_tool`` / ``after_tool``
``before_memory_write`` / ``after_memory_read``
``before_agent_message`` / ``after_agent_message``
``before_external_action``

Assumptions
-----------
In Protected Mode the SDK is *not* the enforcement point — the Gateway is. An agent that
skips these hooks gains nothing, because it holds no credentials for the protected tool. The
hooks provide provenance, ergonomics and early failure; they are not the control. In
Observability Mode they are all VIGIL has, and the deployment is labelled accordingly.

Failure mode
------------
If Core is unreachable, :meth:`VigilGuard.before_tool` fails closed for anything that is not
a declared read, and the failure is raised, never swallowed. ``fail_open_reads`` exists so a
degraded VIGIL does not take down an entire read-only assistant, and it cannot be widened to
cover writes.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .client import VigilClient, VigilUnavailable
from .types import (
    ActionRequest,
    Decision,
    DecisionResponse,
    Principal,
    ProvenanceRef,
    RequestContext,
    TaintKind,
    TrustLevel,
    WorkloadIdentity,
)

__all__ = ["ActionBlocked", "ApprovalRequired", "SessionTerminated", "VigilGuard"]


class ActionBlocked(Exception):
    """VIGIL refused an action.

    Carries the machine-readable reason codes so callers can branch on *why* without parsing
    prose, and the decision id so an operator can find the record.
    """

    def __init__(self, response: DecisionResponse) -> None:
        self.response = response
        self.decision = response.decision
        self.reason_codes = response.reason_codes
        self.decision_id = response.decision_id
        super().__init__(
            f"VIGIL returned {response.decision.value} "
            f"({', '.join(response.reason_codes) or 'no reason recorded'}); "
            f"decision {response.decision_id}"
        )


class ApprovalRequired(ActionBlocked):
    """A human must approve this exact action before it can proceed."""

    def __init__(self, response: DecisionResponse) -> None:
        super().__init__(response)
        self.approval_id = response.approval_id


class SessionTerminated(ActionBlocked):
    """The session was ended by VIGIL. Continuing is itself the risk."""


@dataclass
class SessionIdentity:
    """Everything that scopes a session."""

    tenant_id: str
    environment_id: str
    session_id: str
    agent_id: str
    agent_instance_id: str
    principal: Principal
    workload_identity: WorkloadIdentity | None = None


class VigilGuard:
    """The agent-facing instrumentation surface."""

    def __init__(
        self,
        client: VigilClient,
        identity: SessionIdentity,
        *,
        fail_open_reads: bool = False,
    ) -> None:
        """
        ``fail_open_reads`` permits *declared read-only* actions to proceed when Core is
        unreachable. It never applies to writes, external actions, memory writes or
        delegation, and it cannot be configured to. Invariant 7 draws that line, and drawing
        it here rather than in configuration means it cannot be widened by a YAML edit.
        """
        self._client = client
        self._identity = identity
        self._fail_open_reads = fail_open_reads
        self._terminated = False
        self._last_capability: str | None = None

    # ---------------------------------------------------------------- provenance

    def ingest(
        self,
        origin: str,
        trust: TrustLevel,
        content: str | None = None,
        *,
        taints: Iterable[TaintKind] = (),
        derived_from: Iterable[str] = (),
        tracked_values: Iterable[str] = (),
    ) -> ProvenanceRef:
        """Register content entering the session.

        Call this for *everything* the agent reads: user turns, tool results, fetched pages,
        retrieved documents, memory reads. Content that is never ingested has no provenance,
        and VIGIL treats actions with no provenance as maximally influenced — so
        under-reporting makes the system stricter, never blind.

        ``tracked_values`` marks specific sensitive values (a secret just read from a vault)
        to be watched as they move. That is what catches a secret being exfiltrated in a
        later step, even base64-wrapped.
        """
        node_id = self._client.ingest_content(
            tenant_id=self._identity.tenant_id,
            session_id=self._identity.session_id,
            agent_id=self._identity.agent_id,
            agent_instance_id=self._identity.agent_instance_id,
            principal_id=self._identity.principal.id,
            origin=origin,
            trust=trust,
            content=content,
            taints=list(taints),
            derived_from=list(derived_from),
            tracked_values=list(tracked_values),
        )
        return ProvenanceRef(node_id=node_id, trust_level=trust, origin=origin)

    # ---------------------------------------------------------------- model hooks

    def before_model(
        self,
        provider: str,
        model: str,
        *,
        purpose: str | None = None,
        context_provenance: Iterable[ProvenanceRef] = (),
        estimated_cost_usd: float | None = None,
    ) -> DecisionResponse:
        """Called before a model invocation.

        Guards the model-call budget (denial-of-wallet) and records which provenance was in
        context — which is what later lets VIGIL say an untrusted page was in scope when the
        agent chose a tool.
        """
        action = {
            "kind": "model_call",
            "provider": provider,
            "model": model,
            "purpose": purpose,
            "context_provenance": [p.to_wire() for p in context_provenance],
            "estimated_cost_usd": estimated_cost_usd,
        }
        return self._decide(action, influencing=context_provenance)

    def after_model(
        self,
        output: str,
        *,
        derived_from: Iterable[ProvenanceRef] = (),
    ) -> ProvenanceRef:
        """Called with a model's output.

        The output is ingested as content *derived from* everything in context. That is what
        makes trust propagation work: a completion produced from an untrusted page inherits
        the page's trust level and cannot be laundered into an authoritative instruction.
        """
        return self.ingest(
            origin="model:output",
            trust=TrustLevel.SYSTEM_TRUSTED,
            content=output,
            derived_from=[p.node_id for p in derived_from],
        )

    # ---------------------------------------------------------------- tool hooks

    def before_tool(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        operation: str | None = None,
        influencing: Iterable[ProvenanceRef] = (),
        rationale: str | None = None,
        approval_token: str | None = None,
        read_only: bool = False,
    ) -> DecisionResponse:
        """Called before a tool executes. Raises unless VIGIL permits it.

        The returned response carries the capability the Gateway will require. In Protected
        Mode the caller passes it to :meth:`execute`; there is no path from here to the real
        tool that does not carry it.
        """
        action = {
            "kind": "tool_call",
            "protocol": "native",
            "tool_id": tool,
            "name": tool,
            "operation": operation or "invoke",
            "arguments": arguments,
        }
        response = self._decide(
            action,
            influencing=influencing,
            rationale=rationale,
            approval_token=approval_token,
            read_only=read_only,
        )
        self._last_capability = response.capability
        return response

    def after_tool(
        self,
        tool: str,
        result: Any,
        *,
        trust: TrustLevel | None = None,
        taints: Iterable[TaintKind] = (),
        tracked_values: Iterable[str] = (),
    ) -> ProvenanceRef:
        """Called with a tool's result.

        ``trust`` defaults to the conservative label rather than something optimistic: a tool
        result is data from outside the model's own reasoning, and an MCP server or an API can
        return attacker-controlled content. Callers that know better pass a higher label
        explicitly, which is a deliberate, visible act.
        """
        return self.ingest(
            origin=f"tool:{tool}",
            trust=trust or TrustLevel.conservative_default(),
            content=result if isinstance(result, str) else repr(result),
            taints=taints,
            tracked_values=tracked_values,
        )

    # ---------------------------------------------------------------- memory hooks

    def before_memory_write(
        self,
        namespace: str,
        key: str,
        content: str,
        *,
        scope: str = "session",
        influencing: Iterable[ProvenanceRef] = (),
    ) -> DecisionResponse:
        """Called before writing to memory.

        Memory is where a one-off injection becomes a persistent one: content written now is
        replayed into a future session's context with its provenance laundered. This hook is
        what lets policy refuse that.
        """
        action = {
            "kind": "memory_write",
            "namespace": namespace,
            "key": key,
            "content": content,
            "scope": scope,
        }
        return self._decide(action, influencing=influencing)

    def after_memory_read(
        self,
        namespace: str,
        key: str,
        content: str,
        *,
        validated: bool = False,
    ) -> ProvenanceRef:
        """Called with content read from memory.

        Defaults to ``MEMORY_UNTRUSTED``. ``validated=True`` asserts the entry carries a
        validation record from when it was written — it is not a way to mark your own
        agent's past output trustworthy, which would defeat the whole mechanism.
        """
        return self.ingest(
            origin=f"memory:{namespace}/{key}",
            trust=TrustLevel.MEMORY_VALIDATED if validated else TrustLevel.MEMORY_UNTRUSTED,
            content=content,
        )

    # ---------------------------------------------------------------- agent hooks

    def before_agent_message(
        self,
        to_agent: str,
        content: str,
        *,
        influencing: Iterable[ProvenanceRef] = (),
    ) -> DecisionResponse:
        """Called before sending a message to another agent."""
        action = {"kind": "agent_message", "to_agent": to_agent, "content": content}
        return self._decide(action, influencing=influencing)

    def after_agent_message(self, from_agent: str, content: str) -> ProvenanceRef:
        """Called with a message received from another agent.

        Labelled ``AGENT_UNTRUSTED``. Agent A trusting agent B does not mean B's output is
        authoritative: B may itself have been steered by content it read.
        """
        return self.ingest(
            origin=f"agent:{from_agent}",
            trust=TrustLevel.AGENT_UNTRUSTED,
            content=content,
        )

    # ---------------------------------------------------------------- external actions

    def before_external_action(
        self,
        method: str,
        url: str,
        *,
        body: Any = None,
        resolved_addresses: Iterable[str] = (),
        influencing: Iterable[ProvenanceRef] = (),
    ) -> DecisionResponse:
        """Called before any request that leaves the trust boundary.

        ``resolved_addresses`` should carry what the hostname actually resolved to. Without
        it, a hostname allowlist cannot see DNS rebinding — the name is allowed and the
        address is not.
        """
        action = {
            "kind": "network",
            "method": method.upper(),
            "url": url,
            "body": body,
            "resolved_addresses": list(resolved_addresses),
            "header_names": [],
            "redirect_chain": [],
        }
        return self._decide(action, influencing=influencing)

    # ---------------------------------------------------------------- execution

    def execute(
        self,
        response: DecisionResponse,
        request_action: dict[str, Any],
        **kwargs: Any,
    ) -> Any:
        """Execute an authorized action through the Gateway.

        The action body sent here is hashed by the Gateway and compared against the
        capability. Passing anything other than the exact action that was authorized is
        refused — which is the point.
        """
        if not response.permits_execution() or response.capability is None:
            raise ActionBlocked(response)
        return self._client.execute(
            self._build_request(request_action, **kwargs).to_wire(),
            capability=response.capability,
        )

    # ---------------------------------------------------------------- internals

    def _build_request(
        self,
        action: dict[str, Any],
        *,
        influencing: Iterable[ProvenanceRef] = (),
        rationale: str | None = None,
        approval_token: str | None = None,
    ) -> ActionRequest:
        return ActionRequest(
            request_id=f"req-{uuid.uuid4().hex}",
            tenant_id=self._identity.tenant_id,
            environment_id=self._identity.environment_id,
            session_id=self._identity.session_id,
            agent_id=self._identity.agent_id,
            agent_instance_id=self._identity.agent_instance_id,
            principal=self._identity.principal,
            workload_identity=self._identity.workload_identity,
            action=action,
            context=RequestContext(
                action_rationale=rationale,
                influencing_sources=list(influencing),
                approval_token=approval_token,
            ),
        )

    def _decide(
        self,
        action: dict[str, Any],
        *,
        influencing: Iterable[ProvenanceRef] = (),
        rationale: str | None = None,
        approval_token: str | None = None,
        read_only: bool = False,
    ) -> DecisionResponse:
        if self._terminated:
            raise SessionTerminated(
                DecisionResponse(
                    decision=Decision.TERMINATE_SESSION,
                    decision_id="",
                    action_hash="",
                    risk_score=1.0,
                    confidence=1.0,
                    reason_codes=["SESSION_ALREADY_TERMINATED"],
                    capability=None,
                    approval_id=None,
                    latency_ms=0,
                    raw={},
                )
            )

        request = self._build_request(
            action,
            influencing=influencing,
            rationale=rationale,
            approval_token=approval_token,
        )

        try:
            response = self._client.decide(request.to_wire())
        except VigilUnavailable:
            # Invariant 7. A read may proceed under an explicit opt-in; anything that can
            # change the world may not, and no configuration can change that.
            if read_only and self._fail_open_reads:
                return DecisionResponse(
                    decision=Decision.ALLOW_WITH_CONSTRAINTS,
                    decision_id="",
                    action_hash="",
                    risk_score=0.5,
                    confidence=0.0,
                    reason_codes=["DEGRADED_MODE_ALLOW", "POLICY_ENGINE_UNAVAILABLE"],
                    capability=None,
                    approval_id=None,
                    latency_ms=0,
                    raw={},
                )
            raise

        if not response.is_coherent():
            # A response that permits execution without a capability, or the reverse, is
            # either a protocol bug or a response that did not come from VIGIL.
            raise ActionBlocked(response)

        if response.decision.terminates_session():
            self._terminated = True
            raise SessionTerminated(response)
        if response.decision is Decision.REQUIRE_APPROVAL:
            raise ApprovalRequired(response)
        if not response.permits_execution():
            raise ActionBlocked(response)
        return response
