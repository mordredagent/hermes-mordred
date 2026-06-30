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
        with pytest.raises(BringupFailed) as excinfo:
            vpn.detect_cli(which=lambda _: None)
        msg = str(excinfo.value)
        assert "Install the official Mullvad VPN app/CLI" in msg
        assert "mullvad account login" in msg
        assert "PATH" in msg


# --------------------------------------------------------------------------- #
# Bring-up sequence                                                           #
# --------------------------------------------------------------------------- #


class TestBringUp:
    def test_strict_enforces_lockdown(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="strict",
            runner=runner,
        )
        assert ("/bin/mullvad", "lockdown-mode", "set", "on") in runner.calls

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


class TestBringUpReturnCodes:
    """Codex round 4 P1 (2026-05-14): ``bring_up`` must reject non-zero
    returncodes from any Mullvad CLI subprocess. Previously the helper
    used ``check=False`` and ignored ``returncode``, so a failed
    ``lockdown-mode set on`` / ``connect`` could still produce a handle
    — strict mode would mark the path READY without actually being on
    the tunnel.
    """

    def test_failed_lockdown_command_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "lockdown-mode", "set", "on"): _result(returncode=1)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

    def test_failed_relay_set_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "relay", "set", "location", "jp"): _result(returncode=1)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="jp", policy_mode="off", runner=runner)

    def test_failed_connect_raises(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "connect"): _result(returncode=3)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)

    def test_zero_returncode_does_not_raise(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})  # all responses default to returncode=0
        handle = vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)
        assert handle.cli_path == "mullvad"


class TestPreservePreExistingLockdown:
    """Codex round 8 P1-A (2026-05-14): the rollback path must not turn
    off Mullvad settings the user had enabled before Mordred ran.
    A transient bring-up failure should leave the user's pre-existing
    security posture intact (or stronger), never weaker.
    """

    def test_lockdown_already_on_is_not_disabled_on_failure(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        # Pre-existing user state: lockdown ON.
        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: on\n"),
                ("mullvad", "connect"): _result(returncode=1),  # force failure
            }
        )
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)

        # lockdown was already on → we never touched it, so it stays on.
        assert ("mullvad", "lockdown-mode", "set", "off") not in runner.calls, (
            "user's pre-existing lockdown was disabled on bring-up failure"
        )

    def test_lockdown_already_on_is_not_set_again(self) -> None:
        """Skip the redundant ``set on`` when state already matches."""
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: on\n"),
            }
        )
        vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # No redundant set-on was issued, because lockdown was already on.
        assert ("mullvad", "lockdown-mode", "set", "on") not in runner.calls

    def test_handle_records_what_we_applied(self) -> None:
        """The returned handle reflects whether *we* enabled lockdown
        (so runtime tear-down can decide whether to undo it).
        """
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: off\n"),
            }
        )
        handle = vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # We changed lockdown from off → on, so we should clean up on disconnect.
        assert handle.lockdown_applied_by_us is True

    def test_handle_records_what_already_was(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner(
            {
                ("mullvad", "lockdown-mode", "get"): _result(stdout="Network lockdown when disconnected: on\n"),
            }
        )
        handle = vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # User already had lockdown on; we did NOT apply it.
        assert handle.lockdown_applied_by_us is False


class TestStrictPartialFailureRollback:
    """Codex round 7 P2-A (2026-05-14): if strict bring-up applies
    ``lockdown-mode set on`` and then a later command fails, the
    Mullvad client state must be rolled back so the user is not left
    with a persistent kill-switch that blocks all traffic after the
    session aborts."""

    def test_rolls_back_lockdown_when_connect_fails(self) -> None:
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "connect"): _result(returncode=2)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        # The strict setting we applied must have been undone.
        assert ("mullvad", "lockdown-mode", "set", "off") in runner.calls

    def test_lenient_failure_does_not_alter_user_settings(self) -> None:
        """Lenient mode never sets lockdown, so no rollback fires."""
        from mordred_hermes.network._exceptions import BringupFailed
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({("mullvad", "connect"): _result(returncode=2)})
        with pytest.raises(BringupFailed):
            vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)
        # Must NOT touch lockdown at all in lenient/off.
        for call in runner.calls:
            assert call[:2] != ("mullvad", "lockdown-mode")


class TestMullvadCli2026Drift:
    """Mullvad CLI 2026.2 dropped the ``always-require-vpn`` subcommand;
    its kill-switch semantics are now subsumed by ``lockdown-mode``. The
    bring-up sequence must not invoke ``always-require-vpn`` on any
    code path or strict-mode sessions raise ``BringupFailed`` against
    every modern Mullvad install.
    """

    def test_strict_mode_does_not_invoke_removed_subcommand(self) -> None:
        from mordred_hermes.network.paths import vpn

        def runner_2026_2(
            argv: list[str] | tuple[str, ...],
            **_kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            argv_t = tuple(argv)
            if "always-require-vpn" in argv_t:
                return subprocess.CompletedProcess(
                    args=list(argv_t),
                    returncode=2,
                    stdout="",
                    stderr="error: unrecognized subcommand 'always-require-vpn'\n",
                )
            return subprocess.CompletedProcess(args=list(argv_t), returncode=0, stdout="", stderr="")

        handle = vpn.bring_up(
            cli_path="/bin/mullvad",
            region="auto",
            policy_mode="strict",
            runner=runner_2026_2,
        )
        assert handle.cli_path == "/bin/mullvad"
        assert handle.lockdown_enforced is True

    def test_strict_mode_never_emits_always_require_argv(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="strict", runner=runner)
        for call in runner.calls:
            assert "always-require-vpn" not in call, (
                f"bring_up must not invoke the removed Mullvad CLI subcommand; saw {call!r}"
            )


class TestRegionTranslation:
    """Codex round 6 P1 (2026-05-14): the Mullvad CLI uses ``any`` (not
    ``auto``) for automatic relay selection. Our config / wizard
    surface keeps ``auto`` for user-friendliness, but :func:`bring_up`
    must translate it before invoking the CLI; otherwise the new
    returncode check from r4-P1 turns every default-region bring-up
    into a :class:`BringupFailed`."""

    def test_auto_region_translates_to_any(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(cli_path="mullvad", region="auto", policy_mode="off", runner=runner)
        # Confirm the CLI was asked for "any", not "auto".
        relay_call = next(call for call in runner.calls if call[:3] == ("mullvad", "relay", "set"))
        assert relay_call == ("mullvad", "relay", "set", "location", "any"), (
            f"Expected 'any' translation; got {relay_call!r}"
        )

    def test_explicit_country_code_passes_through(self) -> None:
        from mordred_hermes.network.paths import vpn

        runner = _FakeRunner({})
        vpn.bring_up(cli_path="mullvad", region="jp", policy_mode="off", runner=runner)
        relay_call = next(call for call in runner.calls if call[:3] == ("mullvad", "relay", "set"))
        assert relay_call == ("mullvad", "relay", "set", "location", "jp")


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
