#!/usr/bin/env python3
"""Regenerate the SDK wire fixture the Rust contract test consumes.

Run via ``make contract-fixtures``. The fixture is committed so the Rust suite can run
without a Python toolchain, and regenerating it is how an intentional protocol change is
proposed: the diff shows exactly what moved on the wire.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from vigil_sdk.types import (  # noqa: E402
    ActionRequest,
    Principal,
    ProvenanceRef,
    RequestContext,
    TrustLevel,
    WorkloadIdentity,
)

request = ActionRequest(
    request_id="req-abc123",
    tenant_id="acme",
    environment_id="prod",
    session_id="sess-1",
    agent_id="customer-support-assistant",
    agent_instance_id="inst-1",
    principal=Principal(
        id="user-1", kind="human", tenant_id="acme", roles=["support-agent"], mfa=True
    ),
    workload_identity=WorkloadIdentity(
        id="spiffe://vigil.test/ns/agents/sa/support",
        attestation_method="mtls",
        verified=True,
    ),
    action={
        "kind": "tool_call",
        "protocol": "native",
        "tool_id": "send_email",
        "name": "send_email",
        "operation": "send",
        "arguments": {"to": "cfo@acme.example", "body": "Quarterly report"},
    },
    context=RequestContext(
        declared_objective="answer the customer's billing question",
        action_rationale="the customer asked for a summary by email",
        influencing_sources=[
            ProvenanceRef(
                node_id="prov-1",
                trust_level=TrustLevel.WEB_UNTRUSTED,
                origin="web:https://vendor.example/docs",
            )
        ],
        step=3,
    ),
)

target = ROOT / "tests" / "contract" / "sdk_wire_request.json"
target.write_text(
    json.dumps(request.to_wire(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
print(f"wrote {target.relative_to(ROOT)}")
