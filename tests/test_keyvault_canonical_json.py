"""Byte-level pinning tests for :mod:`mordred_hermes.keyvault._canonical_json`.

The bytes this module produces are hashed, MAC'd, signed, and used as AEAD
associated data by the vault manifest (``MVMF``), the ``MVLT`` file-container
header, the device-bound anchor, the audit log, ``meta.json``, the extension
wallet config, and the backup manifest. A change of even one byte would
invalidate artifacts already on disk, so the exact output is pinned here for
both ``ensure_ascii`` settings against a nested object containing non-ASCII
text, mixed-case keys, and non-string scalars.
"""

from __future__ import annotations

import json

from mordred_hermes.keyvault._canonical_json import canonical_json_bytes, canonical_json_text

# Deliberately hostile ordering: the keys are NOT in sorted order, one key and
# several values are non-ASCII, and the nested mapping mixes upper- and
# lower-case keys (``"A"`` sorts before ``"b"`` by code point).
_SAMPLE: dict[str, object] = {
    "z": 1,
    "a": {"nested": ["élève", "日本語"], "b": True, "A": None},
    "m": 1.5,
    "ü": "✓",
}

_EXPECTED_ESCAPED = (
    '{"a":{"A":null,"b":true,"nested":["\\u00e9l\\u00e8ve","\\u65e5\\u672c\\u8a9e"]},"m":1.5,"z":1,"\\u00fc":"\\u2713"}'
)
_EXPECTED_RAW = '{"a":{"A":null,"b":true,"nested":["élève","日本語"]},"m":1.5,"z":1,"ü":"✓"}'


def test_bytes_default_escapes_non_ascii() -> None:
    assert canonical_json_bytes(_SAMPLE) == _EXPECTED_ESCAPED.encode("utf-8")


def test_bytes_ensure_ascii_false_emits_utf8() -> None:
    assert canonical_json_bytes(_SAMPLE, ensure_ascii=False) == _EXPECTED_RAW.encode("utf-8")


def test_text_matches_the_byte_form() -> None:
    assert canonical_json_text(_SAMPLE) == _EXPECTED_ESCAPED
    assert canonical_json_text(_SAMPLE, ensure_ascii=False) == _EXPECTED_RAW


def test_matches_the_historical_json_dumps_call() -> None:
    """The exact ``json.dumps`` spelling every call site used before the extraction."""
    assert canonical_json_bytes(_SAMPLE) == json.dumps(_SAMPLE, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert canonical_json_bytes(_SAMPLE, ensure_ascii=False) == json.dumps(
        _SAMPLE, separators=(",", ":"), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")


def test_key_insertion_order_does_not_change_the_bytes() -> None:
    """Determinism is the whole point: two equal dicts built in different
    insertion orders must serialize to identical bytes."""
    reversed_order = {
        "ü": "✓",
        "m": 1.5,
        "a": {"A": None, "b": True, "nested": ["élève", "日本語"]},
        "z": 1,
    }
    assert canonical_json_bytes(reversed_order) == canonical_json_bytes(_SAMPLE)


def test_output_has_no_whitespace_padding() -> None:
    encoded = canonical_json_bytes({"a": 1, "b": [1, 2]})
    assert encoded == b'{"a":1,"b":[1,2]}'
