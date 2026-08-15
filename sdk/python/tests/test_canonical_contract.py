"""The Python half of the cross-language canonicalization contract.

Executes ``tests/contract/canonical_vectors.json`` — the same file
``crates/vigil-common/tests/canonical_contract.rs`` executes. A divergence between the two
implementations fails one of these suites, which is the only automated protection against a
class of bug that would otherwise surface as "the approval signature does not verify in
production" or, worse, not surface at all.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from vigil_sdk.canonical import (
    CANONICAL_PROFILE,
    CanonicalizationError,
    canonicalize,
    content_hash,
)

VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "tests" / "contract" / "canonical_vectors.json"
)


def load_vectors() -> dict:
    assert VECTORS_PATH.exists(), f"contract vectors missing at {VECTORS_PATH}"
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


VECTORS = load_vectors()


def test_the_vector_file_targets_this_canonicalization_profile() -> None:
    assert VECTORS["profile"] == CANONICAL_PROFILE


@pytest.mark.parametrize(
    "case", VECTORS["accepted"], ids=[c["name"] for c in VECTORS["accepted"]]
)
def test_accepted_vectors_canonicalize_to_the_specified_bytes(case: dict) -> None:
    assert canonicalize(case["input"]) == case["canonical"]


@pytest.mark.parametrize(
    "case", VECTORS["accepted"], ids=[c["name"] for c in VECTORS["accepted"]]
)
def test_canonicalization_is_idempotent(case: dict) -> None:
    once = canonicalize(case["input"])
    assert canonicalize(json.loads(once)) == once


def test_rejected_vectors_are_refused_rather_than_approximated() -> None:
    by_name = {c["name"]: c for c in VECTORS["rejected"]}

    assert "magnitude_at_or_above_1e16" in by_name
    with pytest.raises(CanonicalizationError):
        canonicalize(1e17)

    assert "infinity" in by_name
    with pytest.raises(CanonicalizationError):
        canonicalize(math.inf)

    assert "nan" in by_name
    with pytest.raises(CanonicalizationError):
        canonicalize(math.nan)


def test_hashes_are_stable_across_key_orderings() -> None:
    accepted = {c["name"]: c for c in VECTORS["accepted"]}
    a = accepted["key_order_is_normalized"]["input"]
    b = accepted["key_order_is_normalized_reversed_input"]["input"]
    assert content_hash(a) == content_hash(b)


def test_a_changed_value_changes_the_hash() -> None:
    base = {"to": "cfo@acme.example", "amount": 100}
    mutated = {"to": "attacker@evil.example", "amount": 100}
    assert content_hash(base) != content_hash(mutated)


def test_booleans_are_not_serialized_as_integers() -> None:
    # `isinstance(True, int)` is True in Python. A canonicalizer that checks int before bool
    # renders True as 1, which would disagree with Rust on every boolean field.
    assert canonicalize({"flag": True}) == '{"flag":true}'
    assert canonicalize([True, False, 1, 0]) == "[true,false,1,0]"


def test_non_string_object_keys_are_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "a"})


def test_unsupported_types_are_rejected_rather_than_stringified() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"when": object()})
