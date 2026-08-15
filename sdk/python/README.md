# vigil-sdk

Python instrumentation for agents running under [VIGIL](https://github.com/bbrookhart/VIGIL)
runtime security.

```bash
pip install vigil-sdk
```

No runtime dependencies. This package runs inside the agent process it is protecting, so
every dependency it adds becomes part of that process's attack surface.

## Usage

```python
from vigil_sdk import Principal, SessionIdentity, TrustLevel, VigilClient, VigilGuard

guard = VigilGuard(
    client=VigilClient(
        core_url="http://localhost:8080",
        gateway_url="http://localhost:8081",
    ),
    identity=SessionIdentity(
        tenant_id="acme",
        environment_id="prod",
        session_id="sess-1",
        agent_id="customer-support-assistant",
        agent_instance_id="inst-1",
        principal=Principal(id="user-1", kind="human", tenant_id="acme"),
    ),
)
```

### Give everything the agent reads a provenance label

```python
user_turn = guard.ingest("user:request", TrustLevel.USER_AUTHENTICATED, content=message)

page = guard.ingest(
    "web:https://vendor.example/docs",
    TrustLevel.WEB_UNTRUSTED,     # a fetched page never carries instruction authority
    content=html,
)

# A secret read from a vault is tracked as it moves, so VIGIL can spot it later even if
# the agent base64-wraps it before sending.
record = guard.ingest(
    "tool:read_customer_record",
    TrustLevel.USER_AUTHENTICATED,
    content=row,
    tracked_values=[row["api_key"]],
)
```

Content you never ingest has no provenance, and VIGIL treats actions with unknown provenance
as influenced by the session's least-trusted content. Under-reporting makes the system
stricter, not blind.

### Guard every side effect

```python
from vigil_sdk import ActionBlocked, ApprovalRequired

try:
    decision = guard.before_tool(
        "send_email",
        {"to": "customer@acme.example", "body": summary},
        operation="send",
        influencing=[user_turn, page, record],
    )
    guard.execute(decision, action)

except ApprovalRequired as exc:
    # A human must approve this exact action. exc.approval_id identifies the request.
    ...
except ActionBlocked as exc:
    # exc.reason_codes are machine-readable: SECRET_EGRESS, OUT_OF_REMIT_TOOL, ...
    ...
```

Refusals **raise**. They are not a status code you can forget to check.

## Available hooks

| Hook | When |
|---|---|
| `before_model` / `after_model` | around a model invocation |
| `before_tool` / `after_tool` | around a tool call |
| `before_memory_write` / `after_memory_read` | around memory access |
| `before_agent_message` / `after_agent_message` | around agent-to-agent messages |
| `before_external_action` | before anything leaving the trust boundary |
| `ingest` | any content entering the session |

## What this SDK is not

In Protected Mode it is **not** the enforcement point. The VIGIL Gateway is, because it holds
the credentials the agent does not. These hooks provide provenance, ergonomics and early
failure. An agent that skips them gains nothing — it still has no way to reach the protected
tool.

## Degraded operation

If VIGIL is unreachable, `VigilUnavailable` is raised. `VigilGuard(fail_open_reads=True)`
permits *declared read-only* actions to proceed in that case. It never applies to writes,
external actions, memory writes or delegation, and it cannot be configured to — that line is
drawn in code, not configuration.

## License

Apache-2.0
