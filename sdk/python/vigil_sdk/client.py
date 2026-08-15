"""HTTP transport to VIGIL Core and VIGIL Gateway.

Uses only the standard library. A security SDK that runs inside the protected agent should
add as little to that process's dependency surface as it can; ``urllib`` is unglamorous and
already there.

Timeouts are mandatory and bounded. A decision call that hangs is indistinguishable to the
caller from one that is slow, and an agent blocked forever on VIGIL is an availability
incident that operators resolve by removing VIGIL.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .canonical import canonical_bytes
from .types import DecisionResponse, TaintKind, TrustLevel

__all__ = ["VigilClient", "VigilError", "VigilUnavailable", "VigilRefused"]


class VigilError(Exception):
    """Base class for SDK transport failures."""


class VigilUnavailable(VigilError):
    """VIGIL could not be reached or did not answer in time.

    Distinct from a refusal on purpose: "VIGIL said no" and "VIGIL did not answer" call for
    different handling, and collapsing them leads to treating an outage as an allow.
    """


class VigilRefused(VigilError):
    """The Gateway refused to execute an action."""

    def __init__(self, reason: str | None, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"gateway refused the action: {reason or 'unspecified'} — {detail}")


class VigilClient:
    """Client for the Core decision API and the Gateway execution API."""

    def __init__(
        self,
        core_url: str,
        gateway_url: str | None = None,
        *,
        timeout_seconds: float = 5.0,
        auth_token: str | None = None,
    ) -> None:
        self._core_url = core_url.rstrip("/")
        self._gateway_url = (gateway_url or core_url).rstrip("/")
        self._timeout = timeout_seconds
        self._auth_token = auth_token

    # ---------------------------------------------------------------- decisions

    def decide(self, request: dict[str, Any]) -> DecisionResponse:
        """Ask Core for a decision."""
        payload = self._post(f"{self._core_url}/v1/decisions", request)
        return DecisionResponse.from_wire(payload)

    def ingest_content(
        self,
        *,
        tenant_id: str,
        session_id: str,
        agent_id: str,
        agent_instance_id: str,
        principal_id: str,
        origin: str,
        trust: TrustLevel,
        content: str | None,
        taints: list[TaintKind],
        derived_from: list[str],
        tracked_values: list[str],
    ) -> str:
        """Register content entering a session; returns the provenance node id."""
        payload = self._post(
            f"{self._core_url}/v1/content",
            {
                "tenant_id": tenant_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "agent_instance_id": agent_instance_id,
                "principal_id": principal_id,
                "origin": origin,
                "trust": trust.value,
                "content": content,
                "taints": [t.value for t in taints],
                "derived_from": derived_from,
                "tracked_values": tracked_values,
            },
        )
        return payload["node_id"]

    def end_session(
        self,
        *,
        tenant_id: str,
        session_id: str,
        agent_id: str,
        agent_instance_id: str,
        principal_id: str,
    ) -> bool:
        """End a session, releasing its provenance graph and tracked values."""
        payload = self._post(
            f"{self._core_url}/v1/sessions/{session_id}/end",
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "agent_instance_id": agent_instance_id,
                "principal_id": principal_id,
            },
        )
        return bool(payload.get("ended", False))

    # ---------------------------------------------------------------- execution

    def execute(self, request: dict[str, Any], *, capability: str) -> Any:
        """Execute an authorized action through the Gateway.

        The capability travels in a header, not the body, so it cannot become part of the
        action being hashed. The Gateway recomputes the hash from this body and compares.
        """
        try:
            payload = self._post(
                f"{self._gateway_url}/v1/execute",
                request,
                extra_headers={"x-vigil-capability": capability},
            )
        except VigilRefused:
            raise
        return payload.get("output")

    # ---------------------------------------------------------------- transport

    def _post(
        self,
        url: str,
        body: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        # Canonical bytes on the wire too: it costs nothing and means the body a proxy logs
        # is the same body that was hashed.
        data = canonical_bytes(body)
        headers = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self._auth_token:
            headers["authorization"] = f"Bearer {self._auth_token}"
        if extra_headers:
            headers.update(extra_headers)

        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"detail": raw[:200]}

            if error.code == 403:
                raise VigilRefused(
                    parsed.get("refusal_reason") or parsed.get("error"),
                    parsed.get("detail", ""),
                ) from error
            if error.code in (502, 503, 504):
                raise VigilUnavailable(f"VIGIL returned {error.code}") from error
            raise VigilError(
                f"VIGIL returned {error.code}: {parsed.get('error', 'unknown')}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            # Reachability failures are their own class so callers cannot accidentally treat
            # an outage as a permissive answer.
            raise VigilUnavailable(str(error)) from error
