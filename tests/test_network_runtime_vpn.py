"""VPN activation and strict kill-switch policy tests."""

from __future__ import annotations

import pytest

from mordred_hermes.network._exceptions import BringupFailed
from tests._network_runtime_fakes import _make_runtime, _VpnFakes


class TestVpnUse:
    def test_use_vpn_calls_bring_up_with_policy_mode(self) -> None:
        vpn = _VpnFakes()
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict", mullvad_region="jp")
        rt.use("vpn")
        assert len(vpn.bring_up_calls) == 1
        call = vpn.bring_up_calls[0]
        assert call["policy_mode"] == "strict"
        assert call["region"] == "jp"
        assert call["cli_path"] == "/fake/mullvad"
        rt.stop()

    def test_use_vpn_waits_for_connected(self) -> None:
        vpn = _VpnFakes()
        rt = _make_runtime(vpn_fakes=vpn)
        rt.use("vpn")
        assert len(vpn.wait_calls) == 1
        rt.stop()

    def test_vpn_no_proxy_env_set(self) -> None:
        """VPN routes packets at the kernel level - no HTTPS_PROXY needed."""
        env: dict[str, str] = {}
        rt = _make_runtime(env=env, policy_mode="lenient")
        rt.use("vpn")
        assert "HTTPS_PROXY" not in env
        assert env["NO_PROXY"] == "localhost,127.0.0.1,::1"
        rt.stop()

    def test_policy_off_vpn_preserves_ambient_proxy(self) -> None:
        env = {
            "HTTPS_PROXY": "http://corp-proxy.example:3128",
            "NO_PROXY": "internal.example",
        }
        rt = _make_runtime(vpn_fakes=_VpnFakes(), policy_mode="off", env=env)

        rt.use("vpn")

        assert env["HTTPS_PROXY"] == "http://corp-proxy.example:3128"
        assert env["NO_PROXY"] == "internal.example"
        rt.stop()


class TestStrictKillswitchGate:
    """Fail-closed strict mode (approved design §6): a provider that
    cannot guarantee a verifiable kill-switch is refused under ``strict``
    policy rather than running without leak protection. ``lenient`` / ``off``
    allow it — a third-party VPN is fine for normal use, just not for the
    strict-privacy guarantee that only Mullvad-grade providers satisfy.
    """

    def test_strict_refuses_provider_without_killswitch(self) -> None:
        vpn = _VpnFakes(killswitch=False)
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        with pytest.raises(BringupFailed):
            rt.use("vpn")
        # The tunnel must never have been brought up — we refuse first.
        assert vpn.bring_up_calls == []
        rt.stop()

    def test_strict_allows_provider_with_killswitch(self) -> None:
        vpn = _VpnFakes(killswitch=True)
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="strict")
        rt.use("vpn")
        assert len(vpn.bring_up_calls) == 1
        rt.stop()

    def test_lenient_allows_provider_without_killswitch(self) -> None:
        vpn = _VpnFakes(killswitch=False)
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="lenient")
        rt.use("vpn")
        assert len(vpn.bring_up_calls) == 1
        s = rt.status()
        assert s.active_path == "vpn"
        rt.stop()

    def test_off_allows_provider_without_killswitch(self) -> None:
        vpn = _VpnFakes(killswitch=False)
        rt = _make_runtime(vpn_fakes=vpn, policy_mode="off")
        rt.use("vpn")
        assert len(vpn.bring_up_calls) == 1
        rt.stop()
