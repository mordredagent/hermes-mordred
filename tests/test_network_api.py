"""Tests for ``mordred_hermes.network.api``.

PR1 defines the public surface (``use`` / ``status`` / ``health`` /
``blackout_assert``) and a :class:`~typing.Protocol` for the runtime.
PR2 will land the concrete :mod:`mordred_hermes.network.runtime`
singleton; until then, tests inject fakes.

Tests cover:

- ``use(path)`` rejects unknown path with :class:`UnknownPath`.
- ``use(path)`` rejects ``None``-runtime with a clear error so callers
  notice they never wired Mordred.
- ``use(path)`` delegates to the injected runtime.
- ``status()`` returns the dataclass shape PR2 / wizard CLI consume.
- ``health()`` defers to the injected runtime.
- ``blackout_assert`` raises :class:`BlackoutNotAsserted` when probe
  reports reachability; passes silently when probe reports unreachable.
- ``BlackoutNotAsserted`` is a :class:`MordredNetworkError` subclass.
"""

from __future__ import annotations

import pytest


class _FakeRuntime:
    def __init__(self) -> None:
        self.active_path: str = "clearnet"
        self._healthy: bool = True
        self.use_calls: list[str] = []

    def use(self, path: str) -> None:
        self.use_calls.append(path)
        self.active_path = path

    def status(self) -> object:
        from mordred_hermes.network.api import NetworkStatus

        return NetworkStatus(active_path=self.active_path, ready=True, last_health=True)

    def health(self) -> bool:
        return self._healthy


class TestUse:
    def test_clearnet_dispatches(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        api.use("clearnet", runtime=rt)
        assert rt.use_calls == ["clearnet"]

    def test_tor_dispatches(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        api.use("tor", runtime=rt)
        assert rt.use_calls == ["tor"]

    def test_vpn_dispatches(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        api.use("vpn", runtime=rt)
        assert rt.use_calls == ["vpn"]

    def test_unknown_path_raises(self) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.network._exceptions import UnknownPath

        rt = _FakeRuntime()
        with pytest.raises(UnknownPath):
            api.use("i2p", runtime=rt)  # type: ignore[arg-type]

    def test_missing_runtime_raises(self) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.network._exceptions import MordredNetworkError

        api.reset_runtime_for_tests()
        with pytest.raises(MordredNetworkError):
            api.use("tor")


class TestStatus:
    def test_returns_active_path(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        rt.active_path = "tor"
        result = api.status(runtime=rt)
        assert result.active_path == "tor"

    def test_status_has_ready_field(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        result = api.status(runtime=rt)
        assert result.ready is True


class TestHealth:
    def test_health_truthy(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        assert api.health(runtime=rt) is True

    def test_health_falsy(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        rt._healthy = False
        assert api.health(runtime=rt) is False


class TestBlackoutAssert:
    def test_reachable_raises(self) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.network._exceptions import BlackoutNotAsserted

        def probe() -> bool:
            return True

        with pytest.raises(BlackoutNotAsserted):
            api.blackout_assert(probe=probe)

    def test_unreachable_returns_silently(self) -> None:
        from mordred_hermes.network import api

        def probe() -> bool:
            return False

        api.blackout_assert(probe=probe)

    def test_blackout_not_asserted_is_network_error(self) -> None:
        from mordred_hermes.network._exceptions import (
            BlackoutNotAsserted,
            MordredNetworkError,
        )

        assert issubclass(BlackoutNotAsserted, MordredNetworkError)


class TestDefaultProbe:
    """``_default_probe`` must detect reachability over BOTH IPv4 and IPv6.

    Security review H3: the probe gates the keyvault Seed-Phrase blackout.
    An IPv4-only probe reports "isolated" on a dual-stack host whose IPv4
    is down but whose IPv6 still routes — leaking the all-clear while the
    host can egress over IPv6.
    """

    @staticmethod
    def _family_aware_socket(monkeypatch: pytest.MonkeyPatch, *, v4_ok: bool, v6_ok: bool) -> None:
        import socket as _socket

        class _FakeSock:
            def __init__(self, family: int) -> None:
                self._family = family

            def settimeout(self, _t: float) -> None:
                return None

            def connect(self, _addr: object) -> None:
                ok = v4_ok if self._family == _socket.AF_INET else v6_ok
                if not ok:
                    raise OSError("simulated: no route for this family")

            def close(self) -> None:
                return None

        def _fake_socket(family: int, _type: int) -> _FakeSock:
            return _FakeSock(family)

        monkeypatch.setattr(_socket, "socket", _fake_socket)

    def test_reports_reachable_when_only_ipv6_routes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.network import api

        self._family_aware_socket(monkeypatch, v4_ok=False, v6_ok=True)
        assert api._default_probe() is True, "IPv6 egress must count as reachable"

    def test_reports_reachable_when_only_ipv4_routes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.network import api

        self._family_aware_socket(monkeypatch, v4_ok=True, v6_ok=False)
        assert api._default_probe() is True

    def test_reports_isolated_only_when_neither_family_routes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.network import api

        self._family_aware_socket(monkeypatch, v4_ok=False, v6_ok=False)
        assert api._default_probe() is False


class TestRuntimeRegistration:
    def test_set_runtime_used_by_use(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        api.set_runtime(rt)
        try:
            api.use("tor")
            assert rt.use_calls == ["tor"]
        finally:
            api.reset_runtime_for_tests()

    def test_reset_clears_runtime(self) -> None:
        from mordred_hermes.network import api
        from mordred_hermes.network._exceptions import MordredNetworkError

        rt = _FakeRuntime()
        api.set_runtime(rt)
        api.reset_runtime_for_tests()
        with pytest.raises(MordredNetworkError):
            api.use("tor")


def test_network_status_shape() -> None:
    from mordred_hermes.network.api import NetworkStatus

    s = NetworkStatus(active_path="clearnet", ready=True, last_health=True)
    assert s.active_path == "clearnet"
    assert s.ready is True
    assert s.last_health is True


class TestSetIsolationToken:
    """Process-token setup delegates to the runtime; absent runtime is a no-op."""

    def test_delegates_to_runtime(self) -> None:
        from mordred_hermes.network import api

        class _Rec:
            def __init__(self) -> None:
                self.token: str | None = "UNSET"

            def set_isolation_token(self, token: str | None) -> None:
                self.token = token

        rec = _Rec()
        api.set_isolation_token("process-1", runtime=rec)  # type: ignore[arg-type]
        assert rec.token == "process-1"

    def test_noop_when_unregistered(self) -> None:
        from mordred_hermes.network import api

        api.reset_runtime_for_tests()
        # Must not raise when no runtime is registered.
        api.set_isolation_token("process-1")
