"""VPN rollback and subprocess-error recovery behavior."""

from __future__ import annotations

from typing import Any

import pytest

from mordred_hermes.network._exceptions import BringupFailed
from tests._network_runtime_fakes import _make_runtime, _VpnFakes


class TestVpnWaitFailureRollback:
    """Codex round 9 P1-A (2026-05-14): if ``bring_up()`` succeeded
    (lockdown applied) but ``wait_connected()`` times out, runtime
    cleanup must roll back the setting it applied. Otherwise lockdown
    stays on after the session aborts and blocks the user's traffic.

    Mullvad CLI 2026.2 drift (2026-05-20): the standalone
    ``always-require-vpn`` rollback path was removed upstream;
    ``lockdown-mode`` is now the single kill-switch surface, so only
    its applied-by-us state needs to drive the cleanup.
    """

    def test_wait_failure_clears_lockdown_when_applied_by_us(self) -> None:
        from mordred_hermes.network.paths import vpn as vpn_real

        vpn = _VpnFakes()

        # We turn lockdown on, then wait_connected times out.
        def applying_bring_up(**kwargs: Any) -> Any:
            return vpn_real.MullvadHandle(
                cli_path=kwargs["cli_path"],
                region=kwargs["region"],
                lockdown_enforced=(kwargs["policy_mode"] == "strict"),
                lockdown_applied_by_us=True,
            )

        vpn.bring_up = applying_bring_up  # type: ignore[method-assign]

        def slow_wait(**_: Any) -> None:
            from mordred_hermes.network._exceptions import BringupFailed

            raise BringupFailed("status timeout")

        vpn.wait_connected = slow_wait  # type: ignore[method-assign]

        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")

        # Runtime cleanup must have called disconnect with the flag
        # that clears the applied setting.
        assert len(vpn.disconnect_calls) == 1
        call = vpn.disconnect_calls[0]
        # Lockdown WAS applied by us → clear it on cleanup.
        assert call.get("preserve_lockdown") is False
        rt.stop()

    def test_wait_failure_preserves_user_lockdown_when_not_applied(self) -> None:
        from mordred_hermes.network.paths import vpn as vpn_real

        vpn = _VpnFakes()

        # User already had lockdown on, so we did NOT apply it.
        def neutral_bring_up(**kwargs: Any) -> Any:
            return vpn_real.MullvadHandle(
                cli_path=kwargs["cli_path"],
                region=kwargs["region"],
                lockdown_enforced=(kwargs["policy_mode"] == "strict"),
                lockdown_applied_by_us=False,
            )

        vpn.bring_up = neutral_bring_up  # type: ignore[method-assign]

        def slow_wait(**_: Any) -> None:
            from mordred_hermes.network._exceptions import BringupFailed

            raise BringupFailed("status timeout")

        vpn.wait_connected = slow_wait  # type: ignore[method-assign]

        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")

        # Runtime cleanup must NOT touch a setting we did not apply.
        call = vpn.disconnect_calls[0]
        assert call.get("preserve_lockdown") is True
        rt.stop()

    def test_stop_preserves_user_lockdown_in_lenient_when_not_applied(self) -> None:
        # Regression (audit HIGH #1): NORMAL teardown must honour
        # ``lockdown_applied_by_us`` exactly like the bring-up-failure
        # cleanup above. In lenient, bring_up leaves a user's pre-existing
        # kill-switch untouched (applied_by_us=False) — so ``stop()`` must
        # NOT disable it. Before the fix, teardown keyed only on
        # ``policy_mode`` and cleared the user's own lockdown.
        vpn = _VpnFakes()  # default bring_up → lockdown_applied_by_us=False
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="lenient")
        rt.use("vpn")
        rt.stop()
        assert len(vpn.disconnect_calls) == 1
        assert vpn.disconnect_calls[0].get("preserve_lockdown") is True

    def test_stop_clears_our_lockdown_in_lenient_when_applied(self) -> None:
        # Symmetric: a lockdown WE applied is rolled back on teardown even
        # in lenient (preserve_lockdown=False) — we only refuse to touch
        # what the user set themselves.
        from mordred_hermes.network.paths import vpn as vpn_real

        vpn = _VpnFakes()

        def applying_bring_up(**kwargs: Any) -> Any:
            return vpn_real.MullvadHandle(
                cli_path=kwargs["cli_path"],
                region=kwargs["region"],
                lockdown_enforced=(kwargs["policy_mode"] == "strict"),
                lockdown_applied_by_us=True,
            )

        vpn.bring_up = applying_bring_up  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="lenient")
        rt.use("vpn")
        rt.stop()
        assert len(vpn.disconnect_calls) == 1
        assert vpn.disconnect_calls[0].get("preserve_lockdown") is False


class TestVpnBringupOSErrorWrapping:
    """Codex round 4 P1 (2026-05-14): VPN path symmetric to Tor r3-P1.
    Mullvad CLI invocations can raise ``OSError`` from
    :func:`paths.vpn.detect_cli` / ``bring_up`` / ``wait_connected``
    if the binary is missing or unprivileged. The strict escalation
    path catches only :class:`BringupFailed` — bare ``OSError`` would
    be swallowed by Hermes' ``invoke_hook`` and fail open.
    """

    def test_vpn_detect_cli_filenotfound_becomes_bringup_failed(self) -> None:
        vpn = _VpnFakes()

        def missing_cli(**_: Any) -> Any:
            raise FileNotFoundError("[Errno 2] No such file or directory: 'mullvad'")

        vpn.detect_cli = missing_cli  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        rt.stop()

    def test_vpn_bring_up_oserror_becomes_bringup_failed(self) -> None:
        vpn = _VpnFakes()

        def oserror_bring_up(**_: Any) -> Any:
            raise PermissionError("mullvad daemon socket not accessible")

        vpn.bring_up = oserror_bring_up  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        rt.stop()

    def test_vpn_wait_connected_oserror_becomes_bringup_failed(self) -> None:
        vpn = _VpnFakes()

        def oserror_wait(**_: Any) -> None:
            raise OSError("socket disappeared mid-poll")

        vpn.wait_connected = oserror_wait  # type: ignore[method-assign]
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        rt.stop()
