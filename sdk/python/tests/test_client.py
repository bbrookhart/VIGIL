"""Transport-boundary tests that run without making a network request."""

from __future__ import annotations

import pytest

from vigil_sdk.client import VigilClient


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.test",
        "https://user:secret@example.test",
        "https://example.test/path?redirect=https://attacker.test",
        "https://example.test/path#fragment",
        "//example.test/no-scheme",
    ],
)
def test_client_rejects_unsafe_or_ambiguous_base_urls(url: str) -> None:
    with pytest.raises(ValueError):
        VigilClient(url)


@pytest.mark.parametrize("timeout", [0, -1, 31])
def test_client_rejects_unbounded_timeouts(timeout: float) -> None:
    with pytest.raises(ValueError):
        VigilClient("https://vigil.example/api", timeout_seconds=timeout)
