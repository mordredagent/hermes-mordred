"""Tests for ``mordred_hermes._provider_identity``.

The normalizer resolves Hermes provider *aliases* to canonical slugs so that
strict-mode enforcement and the transport flagger key off the same identifier
Hermes actually runs under, regardless of which alias the user configured.

Covers:

- Known aliases resolve to their canonical slug (anchored on the providers
  Mordred currently recognises: anthropic / gemini / bedrock).
- Input is stripped + lowercased before lookup.
- Unknown ids, canonical slugs, and the empty string pass through unchanged.
- ``canonicalize_provider`` mirrors ``PROVIDER_ALIASES.get(key, key)`` for
  every entry (faithful-replica invariant; mirrors Hermes ``models.py:1830``).
"""

from __future__ import annotations

import pytest

from mordred_hermes._provider_identity import PROVIDER_ALIASES, canonicalize_provider


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("claude", "anthropic"),
        ("claude-code", "anthropic"),
        ("google", "gemini"),
        ("google-ai-studio", "gemini"),
        ("aws", "bedrock"),
        ("amazon-bedrock", "bedrock"),
        ("glm", "zai"),
        ("deep-seek", "deepseek"),
        ("qwen", "alibaba"),
    ],
)
def test_known_alias_resolves_to_canonical(alias: str, canonical: str) -> None:
    assert canonicalize_provider(alias) == canonical


@pytest.mark.parametrize("raw", ["  Claude  ", "CLAUDE", "Claude-Code", "\tclaude\n"])
def test_strips_and_lowercases_before_lookup(raw: str) -> None:
    assert canonicalize_provider(raw) == "anthropic"


@pytest.mark.parametrize("canonical", ["anthropic", "openai", "gemini", "bedrock"])
def test_canonical_slug_passes_through_unchanged(canonical: str) -> None:
    assert canonicalize_provider(canonical) == canonical


def test_unknown_provider_passes_through() -> None:
    assert canonicalize_provider("frobnicator") == "frobnicator"


def test_empty_string_passes_through() -> None:
    assert canonicalize_provider("") == ""
    assert canonicalize_provider("   ") == ""


def test_canonicalize_mirrors_alias_table() -> None:
    """Every alias entry must resolve exactly as the table declares."""
    for alias, canonical in PROVIDER_ALIASES.items():
        assert canonicalize_provider(alias) == canonical


def test_alias_table_has_expected_anchors() -> None:
    """Guard the replica against accidental truncation/emptying."""
    assert PROVIDER_ALIASES["claude"] == "anthropic"
    assert PROVIDER_ALIASES["google"] == "gemini"
    assert PROVIDER_ALIASES["aws"] == "bedrock"
    assert len(PROVIDER_ALIASES) >= 50


def test_non_string_input_degrades_without_raising() -> None:
    """Non-str input (a contract violation) must degrade to ``""`` — which maps
    to "unknown provider" downstream — rather than raise out of the flagger's
    session-start / audit hook path (review finding L2)."""
    assert canonicalize_provider(None) == ""  # type: ignore[arg-type]
    assert canonicalize_provider(123) == ""  # type: ignore[arg-type]


def test_replica_matches_hermes_source() -> None:
    """The replica must stay byte-for-byte faithful to the installed Hermes
    ``_PROVIDER_ALIASES``. Replicating (vs importing at runtime) only stays safe
    if drift is caught here (review finding M1; the planned Phase-3 guard).

    Skips — rather than fails — when the private upstream symbol can't be
    located, so a future Hermes restructure surfaces as an actionable skip
    instead of red CI on an unrelated change.
    """
    try:
        from hermes_cli.models import _PROVIDER_ALIASES as upstream
    except (ImportError, AttributeError):  # pragma: no cover - upstream moved/renamed
        pytest.skip("hermes_cli.models._PROVIDER_ALIASES not importable; cannot check drift")

    assert dict(PROVIDER_ALIASES) == dict(upstream)
