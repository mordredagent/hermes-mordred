"""Path switching, audit, and environment restoration behavior."""

from __future__ import annotations

from dataclasses import replace

import pytest

from mordred_hermes.network._exceptions import (
    AlreadySwitching,
    BringupFailed,
    PathSwitchRequiresRestart,
)
from tests._network_runtime_fakes import (
    _FakeAudit,
    _make_runtime,
    _TorFakes,
    _VpnFakes,
)


class TestPathSwitch:
    def test_switch_tor_to_vpn_tears_down_tor(self) -> None:
        tor = _TorFakes()
        vpn = _VpnFakes()
        rt = _make_runtime(tor_fakes=tor, vpn_fakes=vpn)
        rt.use("tor")
        rt.use("vpn")
        assert len(tor.stop_calls) == 1
        s = rt.status()
        assert s.active_path == "vpn"
        rt.stop()

    def test_switch_vpn_to_tor_disconnects_vpn_preserving_lockdown(self) -> None:
        tor = _TorFakes()
        vpn = _VpnFakes()
        rt = _make_runtime(tor_fakes=tor, vpn_fakes=vpn, policy_mode="strict")
        rt.use("vpn")
        rt.use("tor")
        assert len(vpn.disconnect_calls) == 1
        assert vpn.disconnect_calls[0].get("preserve_lockdown") is True
        rt.stop()

    def test_switch_clears_proxy_env_when_leaving_tor(self) -> None:
        env: dict[str, str] = {}
        rt = _make_runtime(env=env)
        rt.use("tor")
        assert "HTTPS_PROXY" in env
        rt.use("vpn")
        assert "HTTPS_PROXY" not in env
        rt.stop()

    def test_frozen_process_route_rejects_live_change_but_allows_same_path(self) -> None:
        tor = _TorFakes()
        vpn = _VpnFakes()
        rt = _make_runtime(tor_fakes=tor, vpn_fakes=vpn)
        rt.use("tor")
        rt.freeze_process_route()

        rt.use("tor")
        assert len(tor.start_calls) == 1
        assert tor.stop_calls == []

        with pytest.raises(PathSwitchRequiresRestart, match=r"[Rr]estart Hermes"):
            rt.use("vpn")

        assert rt.status().active_path == "tor"
        assert vpn.bring_up_calls == []
        assert tor.stop_calls == []

        rt._dropped = True  # type: ignore[attr-defined]
        with pytest.raises(PathSwitchRequiresRestart, match=r"[Rr]estart Hermes"):
            rt.use("tor")
        assert len(tor.start_calls) == 1
        rt._dropped = False  # type: ignore[attr-defined]

        rt.stop()
        assert rt.process_route_frozen is True

        for target in ("tor", "vpn"):
            with pytest.raises(PathSwitchRequiresRestart, match=r"[Rr]estart Hermes"):
                rt.use(target)
        with pytest.raises(PathSwitchRequiresRestart, match="process-scoped"):
            rt.set_isolation_token("replacement-token")

        assert len(tor.start_calls) == 1
        assert vpn.bring_up_calls == []

    def test_frozen_lenient_fallback_reuses_original_request_without_retry(self) -> None:
        tor = _TorFakes(wait_raises=BringupFailed("bootstrap timeout"))
        rt = _make_runtime(tor_fakes=tor, policy_mode="lenient")
        rt.use("tor")
        assert rt.status().active_path == "clearnet"
        assert rt.frozen_requested_path is None
        rt.freeze_process_route()
        assert rt.frozen_requested_path == "tor"

        rt.use("tor")
        assert len(tor.start_calls) == 1

        with pytest.raises(PathSwitchRequiresRestart, match=r"[Rr]estart Hermes"):
            rt.use("clearnet")

        rt.stop()

    @pytest.mark.parametrize(
        ("field_name", "replacement"),
        [
            ("tor_binary", "/opt/other/tor"),
            ("tor_socks_port", 19050),
            ("disable_ipv6", False),
            ("policy_mode", "strict"),
        ],
    )
    def test_frozen_route_rejects_any_activation_config_change(
        self,
        field_name: str,
        replacement: object,
    ) -> None:
        rt = _make_runtime(policy_mode="lenient")
        rt.activate_and_freeze("tor")
        changed = replace(rt._config, **{field_name: replacement})  # type: ignore[arg-type,attr-defined]

        with pytest.raises(PathSwitchRequiresRestart, match="configuration changed"):
            rt.assert_route_config(changed)

        rt.assert_route_config(rt._config)  # type: ignore[attr-defined]
        rt.stop()


# --------------------------------------------------------------------------- #
# AlreadySwitching                                                            #
# --------------------------------------------------------------------------- #


class TestConcurrency:
    def test_already_switching_raises_when_state_is_bringing_up(self) -> None:
        from mordred_hermes.network.runtime import Runtime, State

        rt = _make_runtime()
        rt._state = State.BRINGING_UP  # type: ignore[attr-defined]
        with pytest.raises(AlreadySwitching):
            rt.use("tor")
        rt._state = State.IDLE  # type: ignore[attr-defined]
        assert isinstance(rt, Runtime)


# --------------------------------------------------------------------------- #
# Audit                                                                       #
# --------------------------------------------------------------------------- #


class TestAuditEmission:
    def test_successful_use_emits_network_use_with_subprocess_count(self) -> None:
        audit = _FakeAudit()
        rt = _make_runtime(audit=audit, subprocess_count=3)
        rt.use("tor")
        success_entries = [e for e in audit.entries if e.get("reason") == "network.use"]
        assert len(success_entries) == 1
        entry = success_entries[0]
        assert entry["decision"] == "override"
        assert entry["prev_path"] == "clearnet"
        assert entry["new_path"] == "tor"
        assert entry["live_subprocess_count"] == 3
        rt.stop()

    def test_failed_use_strict_emits_network_use_failed(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(wait_raises=BringupFailed("timeout"))
        rt = _make_runtime(tor_fakes=tor, policy_mode="strict", audit=audit)
        with pytest.raises(BringupFailed):
            rt.use("tor")
        failed = [e for e in audit.entries if e.get("reason") == "network.use_failed"]
        assert len(failed) == 1
        assert failed[0]["decision"] == "raise"
        rt.stop()

    def test_lenient_bringup_failure_emits_bringup_failed(self) -> None:
        audit = _FakeAudit()
        tor = _TorFakes(wait_raises=BringupFailed("timeout"))
        rt = _make_runtime(tor_fakes=tor, policy_mode="lenient", audit=audit)
        rt.use("tor")
        fallback = [e for e in audit.entries if e.get("reason") == "network.bringup_failed"]
        assert len(fallback) == 1
        assert fallback[0]["attempted_path"] == "tor"
        assert fallback[0]["fallback_path"] == "clearnet"
        rt.stop()

    def test_no_audit_writer_does_not_crash(self) -> None:
        rt = _make_runtime(audit=None)
        rt.use("tor")
        rt.stop()


# --------------------------------------------------------------------------- #
# Env snapshot / restore                                                      #
# --------------------------------------------------------------------------- #


class TestEnvSnapshot:
    def test_stop_restores_pre_existing_proxy_env(self) -> None:
        env: dict[str, str] = {
            "HTTPS_PROXY": "http://corp-proxy:3128",
            "NO_PROXY": "internal.example.com",
        }
        rt = _make_runtime(env=env)
        rt.use("tor")
        assert env["HTTPS_PROXY"].startswith("socks5h://")
        rt.stop()
        assert env["HTTPS_PROXY"] == "http://corp-proxy:3128"
        assert env["NO_PROXY"] == "internal.example.com"

    def test_stop_clears_managed_keys_added_by_runtime(self) -> None:
        env: dict[str, str] = {}
        rt = _make_runtime(env=env)
        rt.use("tor")
        assert "HTTPS_PROXY" in env
        rt.stop()
        assert "HTTPS_PROXY" not in env
        assert "NO_PROXY" not in env
