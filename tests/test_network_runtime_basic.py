"""Basic state and clearnet behavior for the network runtime."""

from __future__ import annotations

import pytest

from mordred_hermes.network._exceptions import UnknownPath
from tests._network_runtime_fakes import _make_runtime


class TestInitialState:
    def test_idle_status_reports_clearnet_not_ready(self) -> None:
        rt = _make_runtime()
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is False

    def test_health_returns_true_when_idle(self) -> None:
        rt = _make_runtime()
        assert rt.health() is True


class TestUseValidation:
    def test_unknown_path_raises(self) -> None:
        rt = _make_runtime()
        with pytest.raises(UnknownPath):
            rt.use("i2p")

    def test_unknown_path_does_not_change_state(self) -> None:
        rt = _make_runtime()
        with pytest.raises(UnknownPath):
            rt.use("i2p")
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is False


class TestClearnetUse:
    def test_use_clearnet_sets_ready(self) -> None:
        rt = _make_runtime()
        rt.use("clearnet")
        s = rt.status()
        assert s.active_path == "clearnet"
        assert s.ready is True
        rt.stop()

    def test_use_clearnet_does_not_mutate_proxy_env(self) -> None:
        env: dict[str, str] = {"UNRELATED": "value"}
        rt = _make_runtime(env=env)
        rt.use("clearnet")
        assert "HTTPS_PROXY" not in env
        assert "HTTP_PROXY" not in env
        assert "ALL_PROXY" not in env
        assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"
        assert env["UNRELATED"] == "value"
        rt.stop()
