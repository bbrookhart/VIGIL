"""VIGIL Python SDK — instrumentation for agents running under VIGIL.

Quickstart::

    from vigil_sdk import Principal, SessionIdentity, TrustLevel, VigilClient, VigilGuard

    guard = VigilGuard(
        client=VigilClient(core_url="http://localhost:8080",
                           gateway_url="http://localhost:8081"),
        identity=SessionIdentity(
            tenant_id="acme",
            environment_id="prod",
            session_id="sess-1",
            agent_id="customer-support-assistant",
            agent_instance_id="inst-1",
            principal=Principal(id="user-1", kind="human", tenant_id="acme"),
        ),
    )

    # Everything the agent reads gets provenance.
    page = guard.ingest("web:https://vendor.example/docs",
                        TrustLevel.WEB_UNTRUSTED, content=html)

    # Every side effect gets a decision first, and raises if refused.
    decision = guard.before_tool("send_email", {"to": "customer@acme.example"},
                                 operation="send", influencing=[page])
    guard.execute(decision, action)

A note on what this SDK is and is not: in Protected Mode it is *not* the enforcement point.
The Gateway is, because it holds the credentials the agent does not. These hooks supply
provenance and fail fast; skipping them does not get an agent past the Gateway.
"""

from .canonical import CANONICAL_PROFILE, CanonicalizationError, canonicalize, content_hash
from .client import VigilClient, VigilError, VigilRefused, VigilUnavailable
from .guard import (
    ActionBlocked,
    ApprovalRequired,
    SessionIdentity,
    SessionTerminated,
    VigilGuard,
)
from .types import (
    SCHEMA_VERSION,
    ActionRequest,
    Decision,
    DecisionResponse,
    Principal,
    ProvenanceRef,
    RequestContext,
    TaintKind,
    TrustLevel,
    ValidationError,
    WorkloadIdentity,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "CANONICAL_PROFILE",
    "canonicalize",
    "content_hash",
    "CanonicalizationError",
    "VigilClient",
    "VigilError",
    "VigilUnavailable",
    "VigilRefused",
    "VigilGuard",
    "SessionIdentity",
    "ActionBlocked",
    "ApprovalRequired",
    "SessionTerminated",
    "ActionRequest",
    "Decision",
    "DecisionResponse",
    "Principal",
    "ProvenanceRef",
    "RequestContext",
    "TaintKind",
    "TrustLevel",
    "ValidationError",
    "WorkloadIdentity",
]
