"""VIGIL Canonical JSON (VCJ/1) — the Python half of a two-language contract.

Why
---
An approval issued by VIGIL Core binds to the hash of an action's canonical bytes. The
Python SDK computes that same hash locally to detect drift and to build idempotency keys.
If the two implementations disagree on a single byte for a single input, a signature that
should verify does not — or, far worse, an action the SDK considers "the same" hashes
differently in Core and slips past an approval binding.

So this is not "a JSON serializer". It is the second implementation of a security-critical
specification, and it is pinned to the first by a shared vector suite in
``tests/contract/canonical_vectors.json`` that both languages execute.

What
----
A profile of RFC 8785 (JCS), identical to ``crates/vigil-common/src/canonical.rs``:

* object keys sorted ascending by UTF-16 code unit
* no insignificant whitespace
* only ``"``, ``\\`` and C0 controls escaped, using the short forms JSON defines
* integers printed positionally
* non-integer finite numbers printed as the shortest round-trip decimal, positional only

Assumptions
-----------
Numbers that the two languages cannot be *proven* to render identically are rejected rather
than approximated: non-finite values, and magnitudes at or beyond 1e16 where shortest
round-trip formatters begin to disagree on exponent style. Callers needing those must
transport them as strings. A canonicalizer that silently disagrees across languages is a
signature-forgery primitive, so narrowing the accepted domain is the safe trade.

Failure mode
------------
Raises :class:`CanonicalizationError`. There is no fallback encoding: a value that cannot be
canonicalized produces an error the caller must handle, never non-canonical bytes.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

__all__ = [
    "CANONICAL_PROFILE",
    "CanonicalizationError",
    "canonicalize",
    "canonical_bytes",
    "content_hash",
]

#: Identifier for this canonicalization profile, recorded alongside hashes.
CANONICAL_PROFILE = "VCJ/1"

#: Largest magnitude VCJ/1 will render for a non-integer number.
_MAX_CANONICAL_MAGNITUDE = 1e16

#: Beyond this, a float is no longer exactly representable as an integer.
_MAX_EXACT_INTEGER_FLOAT = 9007199254740992.0


class CanonicalizationError(ValueError):
    """A value cannot be represented in VIGIL Canonical JSON."""


def _utf16_sort_key(key: str) -> tuple[int, ...]:
    """Sort key ordering by UTF-16 code unit, as RFC 8785 requires.

    Python's native string ordering is by code point, which differs from UTF-16 order for
    supplementary-plane characters: U+10000 encodes to the surrogate 0xD800, below U+FF3A,
    while its code point is above. Sorting natively would silently disagree with the Rust
    implementation for exactly those keys.
    """
    encoded = key.encode("utf-16-be")
    return tuple(
        int.from_bytes(encoded[i : i + 2], "big") for i in range(0, len(encoded), 2)
    )


def _write_string(value: str, out: list[str]) -> None:
    out.append('"')
    for ch in value:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')


def _write_number(value: int | float, out: list[str]) -> None:
    # bool is a subclass of int in Python; callers must not reach here with one.
    if isinstance(value, int):
        out.append(str(value))
        return

    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError(
            "non-finite numbers cannot be canonicalized; transport as a string"
        )
    if abs(value) >= _MAX_CANONICAL_MAGNITUDE:
        raise CanonicalizationError(
            f"number magnitude >= {_MAX_CANONICAL_MAGNITUDE:e} cannot be canonicalized "
            "identically across SDKs; transport as a string"
        )
    if value == int(value) and abs(value) < _MAX_EXACT_INTEGER_FLOAT:
        # Integral floats render without a fractional part, matching JCS and the Rust SDK.
        out.append(str(int(value)))
        return

    # `repr` is the shortest decimal that round-trips, as is ryu on the Rust side, so the
    # digits agree. The *formatting* does not: Python writes `1e-07` where ryu writes `1e-7`.
    # A value needing an exponent therefore cannot be canonicalized identically across SDKs,
    # so it is rejected rather than rendered — matching `write_number` in
    # `crates/vigil-common/src/canonical.rs`, which rejects the same domain.
    rendered = repr(value)
    if "e" in rendered or "E" in rendered:
        raise CanonicalizationError(
            f"number requires exponent notation ({rendered}), which VCJ/1 cannot render "
            "identically across SDKs; transport as a string"
        )
    out.append(rendered)


def _write_value(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        _write_string(value, out)
    elif isinstance(value, (int, float)):
        _write_number(value, out)
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write_value(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
        out.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_sort_key)):
            if i:
                out.append(",")
            _write_string(key, out)
            out.append(":")
            _write_value(value[key], out)
        out.append("}")
    else:
        raise CanonicalizationError(
            f"{type(value).__name__} has no canonical JSON representation"
        )


def canonicalize(value: Any) -> str:
    """Serialize ``value`` into VIGIL Canonical JSON."""
    out: list[str] = []
    _write_value(value, out)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """The canonical bytes — the input to every VIGIL hash and signature."""
    return canonicalize(value).encode("utf-8")


def content_hash(value: Any) -> str:
    """The algorithm-tagged hash of a value, matching ``vigil_common::ContentHash``."""
    digest = hashlib.sha256(canonical_bytes(value)).hexdigest()
    return f"sha256:{digest}"
