"""Network runtime API integration and production-module guardrails."""

from __future__ import annotations

from typing import Any

import pytest

from mordred_hermes.network.paths import tor as tor_mod
from tests._network_runtime_fakes import _make_runtime


class TestApiIntegration:
    def test_runtime_implements_api_protocol(self) -> None:
        from mordred_hermes.network import api

        rt = _make_runtime()
        api.set_runtime(rt)
        try:
            rt.use("tor")
            s = api.status()
            assert s.active_path == "tor"
            assert s.ready is True
            assert api.health() in (True, False)
        finally:
            rt.stop()
            api.reset_runtime_for_tests()


# --------------------------------------------------------------------------- #
# Production module guardrail                                                 #
# --------------------------------------------------------------------------- #


def test_production_tor_module_not_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must inject path-module fakes, never fall back to subprocess."""

    def explode(*_: Any, **__: Any) -> Any:
        raise AssertionError("production tor.start_process called from unit test")

    monkeypatch.setattr(tor_mod, "start_process", explode)
    rt = _make_runtime()
    rt.use("tor")
    rt.stop()
