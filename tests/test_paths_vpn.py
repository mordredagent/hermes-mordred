"""Tests for ``mordred_hermes.network.paths.vpn``.

Mullvad CLI is fully mocked — no real client install touched. Tests cover:

- ``detect_cli`` resolves ``mullvad`` from PATH
- ``detect_cli`` falls back to the macOS app bundle path
- ``detect_cli`` raises ``BringupFailed`` when neither is present
- ``bring_up`` issues lockdown / relay / connect in the documented order
- ``wait_connected`` polls until ``status`` reports ``Connected``
- ``wait_connected`` raises ``BringupFailed`` on timeout
- ``disconnect`` calls ``mullvad disconnect`` and preserves lockdown by default
- ``disconnect(preserve_lockdown=False)`` also clears lockdown
- ``health`` parses ``wg show`` latest-handshake-age and accepts fresh handshakes
- ``health`` rejects stale handshakes (> 180s default ceiling)

See TODO §3.1 L305-313 for the operational contract this module implements.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

import pytest

# --------------------------------------------------------------------------- #
# Subprocess runner fakes                                                     #
# --------------------------------------------------------------------------- #


class _FakeRunner:
    """Captures every ``subprocess.run``-shaped call for assertion."""

    def __init__(self, responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del check, capture_output, text, timeout
        key = tuple(argv)
        self.calls.append(key)
        try:
            return self._responses[key]
        except KeyError:
            return subprocess.CompletedProcess(args=list(key), returncode=0, stdout="", stderr="")


def _result(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class _FakeClock:
    def __init__(self, *, start: float, step: float) -> None:
        self._t = start
        self._step = step

    def __call__(self) -> float:
        cur = self._t
        self._t += self._step
        return cur


# --------------------------------------------------------------------------- #
# CLI detection                                                               #
# --------------------------------------------------------------------------- #


class TestDetectCli:
    def test_which_returns_path(self) -> None:
        from mordred_hermes.network.paths import vpn

        def which(name: str) -> str | None:
            assert name == "mullvad"
            return "/opt/homebrew/bin/mullvad"

        assert vpn.detect_cli(which=which) == "/opt/homebrew/bin/mullvad"

    def test_macos_app_bundle_fallback(self, monkeypatch: Any) -> None:
        from mordred_hermes.network.paths import vpn

        bundle = "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"

        def exists(self: object) -> bool:
            return str(self) == bundle

        monkeypatch.setattr("pathlib.Path.exists", exists)
        result = vpn.detect_cli(which=lambda _: None)
        assert result == bundle

    def test_not_found_raises_bringup_failed(self, monkeypatch: Any) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        monkeypatch.setattr("pathlib.Path.exists", lambda _self: False)
        with pytest.raises(BringupFailed):
            vpn.detect_cli(which=lambda _: None)


# --------------------------------------------------------------------------- #
# Bring-up sequence                                                           #
# --------------------------------------------------------------------------- #


class TestBringUp:
    def test_strict_enforces_lockdown_and_always_require(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="strict",
            runner=runner,
        )
        assert ("/bin/mullvad", "lockdown-mode", "set", "on") in runner.calls
        assert ("/bin/mullvad", "always-require-vpn", "set", "on") in runner.calls

    def test_lenient_does_not_enforce_lockdown(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="lenient",
            runner=runner,
        )
        assert ("/bin/mullvad", "lockdown-mode", "set", "on") not in runner.calls

    def test_relay_set_with_region(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="jp",
            policy_mode="off",
            runner=runner,
        )
        assert ("/bin/mullvad", "relay", "set", "location", "jp") in runner.calls

    def test_connect_invoked(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="off",
            runner=runner,
        )
        assert ("/bin/mullvad", "connect") in runner.calls


# --------------------------------------------------------------------------- #
# wait_connected                                                              #
# --------------------------------------------------------------------------- #


class TestWaitConnected:
    def test_succeeds_when_status_reports_connected(self) -> None:
        from mordred_hermes.network.paths import vpn

        status_cmd = ("/bin/mullvad", "status")
        runner = _FakeRunner({status_cmd: _result(stdout="Tunnel status: Connected to wg-jp-1\n")})
        vpn.wait_connected(
            cli_path="/bin/mullvad",
            runner=runner,
            timeout=2.0,
            clock=_FakeClock(start=0.0, step=0.01),
        )

    def test_timeout_raises_bringup_failed(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        status_cmd = ("/bin/mullvad", "status")
        runner = _FakeRunner({status_cmd: _result(stdout="Tunnel status: Disconnected\n")})
        with pytest.raises(BringupFailed):
            vpn.wait_connected(
                cli_path="/bin/mullvad",
                runner=runner,
                timeout=0.05,
                clock=_FakeClock(start=0.0, step=0.1),
            )


# --------------------------------------------------------------------------- #
# Disconnect                                                                  #
# --------------------------------------------------------------------------- #


class TestDisconnect:
    def test_calls_mullvad_disconnect(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        vpn.disconnect(handle, runner=runner)
        assert ("/bin/mullvad", "disconnect") in runner.calls

    def test_preserve_lockdown_default(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        vpn.disconnect(handle, runner=runner)
        assert ("/bin/mullvad", "lockdown-mode", "set", "off") not in runner.calls

    def test_preserve_lockdown_false_clears_it(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        vpn.disconnect(handle, runner=runner, preserve_lockdown=False)
        assert ("/bin/mullvad", "lockdown-mode", "set", "off") in runner.calls


# --------------------------------------------------------------------------- #
# Health (wg show handshake age)                                              #
# --------------------------------------------------------------------------- #


class TestHealth:
    _FRESH_WG = "latest handshake: 30 seconds ago\n"
    _STALE_WG = "latest handshake: 9 minutes, 12 seconds ago\n"
    _NEVER_WG = "latest handshake: (none)\n"

    def test_fresh_handshake_is_healthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("wg", "show"): _result(stdout=self._FRESH_WG)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is True

    def test_stale_handshake_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("wg", "show"): _result(stdout=self._STALE_WG)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False

    def test_no_handshake_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("wg", "show"): _result(stdout=self._NEVER_WG)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False

    def test_wg_command_failure_is_unhealthy(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("wg", "show"): _result(stdout="", returncode=1)})
        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=runner) is False

    def test_wg_binary_missing_is_unhealthy(self) -> None:
        """Codex P2 / HIGH-3 (2026-05-13): on hosts where ``wg`` is not on
        PATH (some macOS Mullvad installs ship only the GUI),
        ``subprocess.run`` raises :class:`FileNotFoundError` rather than
        returning a non-zero ``CompletedProcess``. ``health`` must catch
        the exception and return ``False`` so the PR2 liveness worker
        records the path as unhealthy instead of crashing the thread.
        """
        from mordred_hermes.network.paths import vpn

        def missing_wg(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("[Errno 2] No such file or directory: 'wg'")

        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=missing_wg) is False

    def test_wg_command_timeout_is_unhealthy(self) -> None:
        """Defensive: if the liveness worker passes a ``timeout=`` to the
        runner (future PR2 wiring), ``subprocess.TimeoutExpired`` must
        also be coerced into ``unhealthy`` rather than propagating."""
        from mordred_hermes.network.paths import vpn

        def slow_wg(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=["wg", "show"], timeout=1.0)

        handle = vpn.MullvadHandle(cli_path="/bin/mullvad", region="auto", lockdown_enforced=True)
        assert vpn.health(handle, runner=slow_wg) is False


# --------------------------------------------------------------------------- #
# Module constants                                                            #
# --------------------------------------------------------------------------- #


def test_path_name_constant() -> None:
    from mordred_hermes.network.paths import vpn

    assert vpn.PATH_NAME == "vpn"


def test_default_runner_is_callable() -> None:
    """Production default must be a runnable subprocess wrapper."""
    from mordred_hermes.network.paths import vpn

    assert callable(vpn.DEFAULT_RUNNER)


def test_default_handshake_ceiling() -> None:
    from mordred_hermes.network.paths import vpn

    assert vpn.DEFAULT_MAX_HANDSHAKE_AGE_SECONDS == 180.0


def _detect_cli_signature_sanity() -> None:
    """Type-checker sanity: detect_cli is a Callable returning str."""
    from mordred_hermes.network.paths import vpn

    cli: Callable[..., str] = vpn.detect_cli
    del cli
