"""Tests for ``mordred_hermes.llm_guard.local_adapter``.

Codex review B1 (Phase 2 PR1): ``providers.get_provider_profile()`` lazy-loads
plugins from ``<repo>/plugins/model-providers/*`` and ``$HERMES_HOME/plugins/...``
only. A Mordred entry-point plugin that lives under ``mordred_hermes.llm_guard``
will NOT be discovered by that scanner — so registration must happen
*explicitly* inside ``register(ctx)`` (this module's ``register_mordred_local``
helper), not as an arbitrary module-import side effect.

The :class:`MordredLocalProfile` itself is a thin :class:`ProviderProfile`
subclass: name ``mordred-local``, OpenAI ``chat_completions`` wire format,
base URL pulled from ``policy.json`` when present, fallback default
``http://localhost:1234/v1``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


# Test helper: fresh provider registry snapshot so leaks don't cross tests.
@pytest.fixture(autouse=True)
def _clear_mordred_local_from_registry() -> Any:
    """Pop ``mordred-local`` from the provider registry around each test.

    The upstream ``providers`` module is a process singleton; we only
    touch the slot this plugin owns.
    """
    import providers

    providers._REGISTRY.pop("mordred-local", None)
    providers._ALIASES.pop("mordred-local", None)
    yield
    providers._REGISTRY.pop("mordred-local", None)
    providers._ALIASES.pop("mordred-local", None)


def _write_policy_json(
    tmp_path: Path,
    *,
    endpoint: str | None = None,
    model_id: str | None = None,
) -> Path:
    """Write a minimal ``policy.json`` with Phase 2 fields."""
    body: dict[str, Any] = {"policy": "strict"}
    if endpoint is not None:
        body["local_llm_endpoint"] = endpoint
    if model_id is not None:
        body["local_llm_model_id"] = model_id
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


class TestProfileConstruction:
    def test_default_endpoint_when_policy_absent(self, tmp_path: Path) -> None:
        from mordred_hermes.llm_guard.local_adapter import build_mordred_local_profile

        missing = tmp_path / "nonexistent.json"
        profile = build_mordred_local_profile(policy_json_path=missing)
        assert profile.name == "mordred-local"
        assert profile.base_url == "http://localhost:1234/v1"
        assert profile.api_mode == "chat_completions"

    def test_reads_endpoint_from_policy(self, tmp_path: Path) -> None:
        from mordred_hermes.llm_guard.local_adapter import build_mordred_local_profile

        path = _write_policy_json(tmp_path, endpoint="http://127.0.0.1:11434/v1")
        profile = build_mordred_local_profile(policy_json_path=path)
        assert profile.base_url == "http://127.0.0.1:11434/v1"

    def test_handles_malformed_policy_json(self, tmp_path: Path) -> None:
        """A corrupt policy.json must not prevent provider registration —
        Mordred must remain usable so the wizard can recover.
        """
        from mordred_hermes.llm_guard.local_adapter import build_mordred_local_profile

        path = tmp_path / "policy.json"
        path.write_text("{not json", encoding="utf-8")
        profile = build_mordred_local_profile(policy_json_path=path)
        assert profile.base_url == "http://localhost:1234/v1"

    def test_no_env_vars(self) -> None:
        """Local endpoint has no API key requirement — env_vars must be empty."""
        from mordred_hermes.llm_guard.local_adapter import build_mordred_local_profile

        profile = build_mordred_local_profile(policy_json_path=Path("/dev/null"))
        assert profile.env_vars == ()


class TestRegistration:
    """B1: registration MUST be explicit (no module-import side effect)."""

    def test_module_import_does_not_register(self) -> None:
        """Codex B1: importing ``local_adapter`` must NOT touch the registry.

        Side-effect registration was rejected because (a) the lazy
        ``providers._discover_providers()`` scanner doesn't see entry-point
        plugins, and (b) reliance on import side effects is fragile across
        test runs.
        """
        # Force a clean import. The fixture cleared the slot; verify it
        # stays clear even after the adapter module is imported.
        import importlib

        import providers

        import mordred_hermes.llm_guard.local_adapter as la

        importlib.reload(la)
        assert providers._REGISTRY.get("mordred-local") is None, (
            "module import must not self-register; require explicit register_mordred_local()"
        )

    def test_explicit_register_places_profile_in_registry(self, tmp_path: Path) -> None:
        from mordred_hermes.llm_guard.local_adapter import register_mordred_local

        path = _write_policy_json(tmp_path, endpoint="http://x/v1")
        register_mordred_local(policy_json_path=path)

        import providers

        profile = providers._REGISTRY.get("mordred-local")
        assert profile is not None
        assert profile.name == "mordred-local"
        assert profile.base_url == "http://x/v1"

    def test_double_register_is_idempotent(self, tmp_path: Path) -> None:
        """Plugin loader may invoke ``register(ctx)`` defensively."""
        from mordred_hermes.llm_guard.local_adapter import register_mordred_local

        path = _write_policy_json(tmp_path, endpoint="http://x/v1")
        register_mordred_local(policy_json_path=path)
        register_mordred_local(policy_json_path=path)

        import providers

        # Single entry, last-writer-wins semantics (matches the upstream
        # ``register_provider`` docstring: "later registrations ... replace
        # earlier ones").
        assert providers._REGISTRY.get("mordred-local") is not None

    def test_register_returns_profile(self, tmp_path: Path) -> None:
        """Callers (PR2 enforce.py) may want to inspect the profile they registered."""
        from mordred_hermes.llm_guard.local_adapter import register_mordred_local

        path = _write_policy_json(tmp_path, endpoint="http://x/v1")
        result = register_mordred_local(policy_json_path=path)
        assert result is not None
        assert result.name == "mordred-local"
        assert result.base_url == "http://x/v1"
