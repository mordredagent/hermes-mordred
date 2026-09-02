"""Live integration tests for the ``mordred-local`` provider + enforce path.

Gated by ``MORDRED_LIVE_LLM_TEST=1``. Skipped by default so CI runs and
``pytest -q`` on developer machines remain hermetic. Run manually with a
local LM Studio / Ollama / vLLM endpoint listening on
``MORDRED_LIVE_LLM_ENDPOINT`` (default ``http://localhost:1234/v1``):

.. code-block:: bash

   MORDRED_LIVE_LLM_TEST=1 pytest tests/integration/test_llm_local.py -v

Failure-mode coverage (no live server required) also lives here so a
single integration entry point owns both halves of the acceptance gate
row 4 contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.llm_guard import enforce, health
from mordred_hermes.llm_guard._exceptions import (
    MordredLocalUnreachable,
    MordredSessionRefused,
)
from tests._helpers import FakeAuditWriter as _FakeAuditWriter

_LIVE_GATE_ENV = "MORDRED_LIVE_LLM_TEST"
_LIVE_ENDPOINT_ENV = "MORDRED_LIVE_LLM_ENDPOINT"
_DEFAULT_LIVE_ENDPOINT = "http://localhost:1234/v1"


def _live_gated() -> str:
    """Return the endpoint to probe, or skip the test if the gate is off."""
    if os.environ.get(_LIVE_GATE_ENV) != "1":
        pytest.skip(f"set {_LIVE_GATE_ENV}=1 to run live LM Studio / Ollama integration tests")
    return os.environ.get(_LIVE_ENDPOINT_ENV, _DEFAULT_LIVE_ENDPOINT)


def _write_policy_json(tmp_path: Path, endpoint: str) -> Path:
    body = {
        "policy": "strict",
        "allow_cloud_llm": False,
        "cloud_provider_allowlist": [],
        "local_llm_endpoint": endpoint,
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def _reset_enforce_state() -> Any:
    enforce._reset_state()
    yield
    enforce._reset_state()


# --------------------------------------------------------------------------- #
# Failure mode — local endpoint not listening (no live server needed)         #
# --------------------------------------------------------------------------- #


class TestFailureMode:
    """Phase 2 acceptance gate row 4: strict + no local endpoint reachable
    → fails fast with :class:`MordredLocalUnreachable`.

    Port 1 is reserved and unallocated; the TCP connect refuses quickly
    so this runs hermetically without a real local server.
    """

    def test_unreachable_endpoint_raises_via_health_probe(self) -> None:
        with pytest.raises(MordredLocalUnreachable):
            health.probe(endpoint="http://127.0.0.1:1/v1", timeout=1.0)

    def test_enforce_refuses_session_when_local_unreachable(self, tmp_path: Path) -> None:
        """Codex P2 round 2: strict-mode local probe failure must abort the
        session (raise ``MordredSessionRefused``), with the underlying
        :class:`MordredLocalUnreachable` preserved as ``__cause__``. Raising
        :class:`MordredLocalUnreachable` alone would be swallowed by Hermes'
        hook dispatch (``invoke_hook`` catches :class:`Exception` + logs).
        """
        cfg = _write_policy_json(tmp_path, endpoint="http://127.0.0.1:1/v1")
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused) as excinfo:
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="mordred-local",
                audit=audit,
                health_probe=None,  # use default :func:`health.probe`
            )
        assert isinstance(excinfo.value.__cause__, MordredLocalUnreachable)

        # Audit must NOT show an allow — the probe ran before the audit append.
        assert not any(e.get("decision") == "allow" for e in audit.entries)


# --------------------------------------------------------------------------- #
# Live roundtrip — requires a real local LLM endpoint                          #
# --------------------------------------------------------------------------- #


class TestLiveRoundtrip:
    """Gated by ``MORDRED_LIVE_LLM_TEST=1``.

    These verify that the v1 ``ProviderProfile`` declaration + health probe
    + enforce path actually agree with a real OpenAI-compatible local
    endpoint. They are NOT a replacement for the unit tests; they catch
    integration drift between the declared profile and the upstream
    Hermes provider registry on real systems.
    """

    def test_health_probe_succeeds_against_live_endpoint(self) -> None:
        endpoint = _live_gated()
        health.probe(endpoint=endpoint, timeout=5.0)

    def test_enforce_strict_local_allows_against_live_endpoint(self, tmp_path: Path) -> None:
        endpoint = _live_gated()
        cfg = _write_policy_json(tmp_path, endpoint=endpoint)
        audit = _FakeAuditWriter()

        enforce.check_session_provider(
            policy_mode="strict",
            policy_json_path=cfg,
            active_provider="mordred-local",
            audit=audit,
            health_probe=None,  # real probe
        )

        assert audit.entries
        entry = audit.entries[-1]
        assert entry["decision"] == "allow"
        assert entry["reason"] == "policy.strict.cloud_allowlisted"
        assert entry["provider_id"] == "mordred-local"

    def test_enforce_refuses_cloud_under_strict(self, tmp_path: Path) -> None:
        """Cloud provider rejection does not require the live endpoint;
        keep it under the live gate so the full strict-mode path executes
        against the same fixture set as the allow tests.
        """
        _live_gated()  # gate enforcement so this still skips when env unset
        cfg = _write_policy_json(tmp_path, endpoint=_DEFAULT_LIVE_ENDPOINT)
        audit = _FakeAuditWriter()

        with pytest.raises(MordredSessionRefused):
            enforce.check_session_provider(
                policy_mode="strict",
                policy_json_path=cfg,
                active_provider="anthropic",
                audit=audit,
                health_probe=None,
            )
