"""Configuration loading and API-helper tests for network-hook registration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    MordredPathBringupFailed,
)
from tests._network_hooks_helpers import (
    _FakeAudit,
    _FakeCtx,
    _FakeRuntime,
    _reset_api,
    _skip_process_route_activation,
    _write_config,
    _write_policy,
)

pytestmark = pytest.mark.usefixtures(_reset_api.__name__)

# --------------------------------------------------------------------------- #
# Policy and network configuration loading                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures(_skip_process_route_activation.__name__)
class TestRegisterLoadsPolicyFromDisk:
    """Codex P1 fix (2026-05-14): the registered Runtime must inherit
    ``policy_mode`` (+ ``default_path`` / ``mullvad_region``) from
    ``policy.json`` and ``config.yaml``. Constructing the runtime with
    the always-``off`` default lets a strict-mode bring-up failure take
    the lenient fallback inside the runtime — the hook then never sees
    :class:`BringupFailed` and never escalates to
    :class:`MordredPathBringupFailed`. Similarly the VPN bring-up
    would skip Mullvad lockdown.
    """

    def test_register_with_strict_policy_propagates_to_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        # Point register() at the synthetic config files.
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        # Prevent NDJSONWriter from writing to ~/.hermes by pointing at tmp.
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        # Clear the lru_cache so the new audit path is honored.
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME  # introspect private singleton
        assert runtime is not None
        # The runtime's RuntimeConfig.policy_mode must reflect disk state.
        assert runtime._config.policy_mode == "strict", (  # type: ignore[attr-defined]
            f"Runtime policy_mode is {runtime._config.policy_mode!r}, expected 'strict'"  # type: ignore[attr-defined]
        )

    def test_register_with_lenient_policy_propagates_to_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "vpn")
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.policy_mode == "lenient"  # type: ignore[attr-defined]

    def test_register_tor_data_dir_under_hermes_base(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Codex P2 round 2 (2026-05-14): the Tor data directory must
        live under the active Hermes profile (``HERMES_BASE``), not
        hard-coded ``~/.hermes``. Sessions using ``HERMES_HOME`` or an
        active_profile must keep their Tor cookies + data isolated.
        """
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        fake_profile = tmp_path / "fake-profile"
        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "clearnet")
        monkeypatch.setattr(net_pkg, "HERMES_BASE", fake_profile)
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        expected = fake_profile / "mordred" / "tor-data"
        assert runtime._config.tor_data_dir == expected, (  # type: ignore[attr-defined]
            f"tor_data_dir = {runtime._config.tor_data_dir!r}, "  # type: ignore[attr-defined]
            f"expected {expected!r} under HERMES_BASE"
        )

    def test_register_unhashable_policy_value_fails_closed_to_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Damaged existing policy must not disable pre-client activation."""
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        # Write a syntactically valid JSON with a non-string `policy` value.
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps({"policy": []}))
        config = _write_config(tmp_path, "clearnet")
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.policy_mode == "strict"  # type: ignore[attr-defined]

    def test_register_missing_policy_defaults_to_off(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Defensive default: no policy.json -> policy_mode='off' (safe)."""
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        # policy.json absent
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", tmp_path / "absent.json")
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", tmp_path / "absent.yaml")
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.policy_mode == "off"  # type: ignore[attr-defined]


@pytest.mark.usefixtures(_skip_process_route_activation.__name__)
class TestRegisterLoadsWizardNetworkSettings:
    """Codex review (2026-05-14, P2): the wizard persists
    ``tor_binary_path`` / ``tor_socks_port`` / ``mullvad_relay_country``
    under ``plugins.mordred_network`` in ``config.yaml`` but
    ``_load_runtime_config`` only reads ``default_path``. The other
    three are silently discarded so the operator's choices never reach
    Tor or Mullvad at runtime.
    """

    def _seed(self, tmp_path: Path) -> tuple[Path, Path]:
        policy = _write_policy(tmp_path, "strict")
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: tor\n"
            "    tor_binary_path: /opt/tor/bin/tor\n"
            "    tor_socks_port: 9150\n"
            "    mullvad_account_id_env: MORDRED_MULLVAD_ACCOUNT\n"
            "    mullvad_relay_country: jp\n"
            "    mullvad_killswitch: true\n",
            encoding="utf-8",
        )
        return policy, config_path

    def test_register_reads_tor_binary_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy, config = self._seed(tmp_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.tor_binary == "/opt/tor/bin/tor", (  # type: ignore[attr-defined]
            "P2: tor_binary_path from config.yaml must reach RuntimeConfig.tor_binary"
        )

    def test_register_reads_tor_socks_port(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy, config = self._seed(tmp_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.tor_socks_port == 9150, (  # type: ignore[attr-defined]
            "P2: tor_socks_port from config.yaml must reach RuntimeConfig"
        )

    def test_register_reads_mullvad_relay_country(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy, config = self._seed(tmp_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.mullvad_region == "jp", (  # type: ignore[attr-defined]
            "P2: mullvad_relay_country from config.yaml must reach RuntimeConfig.mullvad_region"
        )

    def test_register_missing_network_keys_falls_back_to_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When config.yaml only has default_path (older wizards / hand-
        written configs), the new readers must NOT crash. They should
        fall back to RuntimeConfig's built-in defaults.
        """
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy = _write_policy(tmp_path, "lenient")
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "plugins:\n  mordred_network:\n    default_path: clearnet\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)

        runtime = api._RUNTIME
        assert runtime is not None
        # defaults from RuntimeConfig
        assert runtime._config.tor_binary == "tor"  # type: ignore[attr-defined]
        assert runtime._config.tor_socks_port == 0  # 0 = let runtime pick  # type: ignore[attr-defined]
        assert runtime._config.mullvad_region == "auto"  # type: ignore[attr-defined]


@pytest.mark.usefixtures(_skip_process_route_activation.__name__)
class TestRegisterLoadsVpnProvider:
    """The pluggable-VPN config keys (vpn_provider + provider-specific
    settings) persisted under ``plugins.mordred_network`` must reach
    RuntimeConfig, or selecting a non-Mullvad VPN in config.yaml would be
    silently ignored at runtime.
    """

    def _register(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config_body: str) -> Any:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        policy = _write_policy(tmp_path, "off")
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_body, encoding="utf-8")
        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()
        net_pkg.register(_FakeCtx())
        runtime = api._RUNTIME
        assert runtime is not None
        return runtime

    def test_reads_wireguard_provider_and_config_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runtime = self._register(
            tmp_path,
            monkeypatch,
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: vpn\n"
            "    vpn_provider: wireguard\n"
            "    wireguard_config_path: /etc/wireguard/wg0.conf\n",
        )
        assert runtime._config.vpn_provider == "wireguard"  # type: ignore[attr-defined]
        assert runtime._config.wireguard_config_path == "/etc/wireguard/wg0.conf"  # type: ignore[attr-defined]

    def test_reads_custom_provider_and_commands(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runtime = self._register(
            tmp_path,
            monkeypatch,
            "plugins:\n"
            "  mordred_network:\n"
            "    default_path: vpn\n"
            "    vpn_provider: custom\n"
            "    custom_up_cmd: [expressvpn, connect]\n"
            "    custom_down_cmd: [expressvpn, disconnect]\n"
            "    custom_health_cmd: [expressvpn, status]\n",
        )
        assert runtime._config.vpn_provider == "custom"  # type: ignore[attr-defined]
        assert runtime._config.custom_up_cmd == ("expressvpn", "connect")  # type: ignore[attr-defined]
        assert runtime._config.custom_down_cmd == ("expressvpn", "disconnect")  # type: ignore[attr-defined]
        assert runtime._config.custom_health_cmd == ("expressvpn", "status")  # type: ignore[attr-defined]

    def test_missing_vpn_provider_defaults_to_mullvad(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runtime = self._register(
            tmp_path,
            monkeypatch,
            "plugins:\n  mordred_network:\n    default_path: vpn\n",
        )
        assert runtime._config.vpn_provider == "mullvad"  # type: ignore[attr-defined]

    def test_invalid_vpn_provider_falls_back_to_mullvad(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # An unknown provider name must NOT crash register() via
        # build_provider -> UnknownVpnProvider; it falls back to mullvad.
        runtime = self._register(
            tmp_path,
            monkeypatch,
            "plugins:\n  mordred_network:\n    vpn_provider: nope-vpn\n",
        )
        assert runtime._config.vpn_provider == "mullvad"  # type: ignore[attr-defined]


@pytest.mark.usefixtures(_skip_process_route_activation.__name__)
class TestRegisterLoadsDisableIPv6FromDisk:
    """Phase 3 PR3a Task #2: ``disable_ipv6`` schema in ``policy.json``.

    ``RuntimeConfig.disable_ipv6`` is an advisory Tor-client preference in
    v1 (``ClientUseIPv6 0``; full host enforcement is v2-N2). It does not
    suppress provider IPv6 flags. When ``policy.json`` doesn't pin the value,
    the reader infers it from ``policy_mode``. When the user pins it, their
    choice wins.
    """

    def _register_with_policy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        policy_path: Path,
        config_path: Path,
    ) -> Any:
        from mordred_hermes import network as net_pkg
        from mordred_hermes.network import api

        monkeypatch.setattr(net_pkg, "DEFAULT_POLICY_JSON_PATH", policy_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_CONFIG_PATH", config_path)
        monkeypatch.setattr(net_pkg, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        net_pkg._build_audit_writer.cache_clear()

        ctx = _FakeCtx()
        net_pkg.register(ctx)
        return api._RUNTIME

    def test_strict_policy_no_explicit_field_defaults_to_true(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = _write_policy(tmp_path, "strict")  # no disable_ipv6 in JSON
        config = _write_config(tmp_path, "clearnet")
        runtime = self._register_with_policy(tmp_path, monkeypatch, policy, config)
        assert runtime is not None
        assert runtime._config.disable_ipv6 is True, (  # type: ignore[attr-defined]
            "strict without explicit pin must default to True (safe)"
        )

    def test_lenient_policy_no_explicit_field_defaults_to_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "clearnet")
        runtime = self._register_with_policy(tmp_path, monkeypatch, policy, config)
        assert runtime is not None
        assert runtime._config.disable_ipv6 is False, (  # type: ignore[attr-defined]
            "lenient without explicit pin must default to False (user-friendly)"
        )

    def test_off_policy_no_explicit_field_defaults_to_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "clearnet")
        runtime = self._register_with_policy(tmp_path, monkeypatch, policy, config)
        assert runtime is not None
        assert runtime._config.disable_ipv6 is False  # type: ignore[attr-defined]

    def test_strict_policy_user_pin_false_is_honoured(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """User explicitly opting out of IPv6-disable in strict is allowed.
        Documented caveat in POLICY.md - lets IPv6-only providers work but
        the flagger emits a strict-mode warning."""
        policy = _write_policy(tmp_path, "strict", disable_ipv6=False)
        config = _write_config(tmp_path, "clearnet")
        runtime = self._register_with_policy(tmp_path, monkeypatch, policy, config)
        assert runtime is not None
        assert runtime._config.disable_ipv6 is False  # type: ignore[attr-defined]

    def test_lenient_policy_user_pin_true_is_honoured(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy = _write_policy(tmp_path, "lenient", disable_ipv6=True)
        config = _write_config(tmp_path, "clearnet")
        runtime = self._register_with_policy(tmp_path, monkeypatch, policy, config)
        assert runtime is not None
        assert runtime._config.disable_ipv6 is True  # type: ignore[attr-defined]

    def test_non_bool_value_falls_back_to_mode_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A corrupted ``disable_ipv6`` (string, list, dict) falls back to the
        policy-mode default. Mirrors :class:`_read_policy_mode`'s unhashable
        fallback (Codex round 3 P2)."""
        p = tmp_path / "policy.json"
        p.write_text(json.dumps({"policy": "strict", "disable_ipv6": "yes-please"}))
        config = _write_config(tmp_path, "clearnet")
        runtime = self._register_with_policy(tmp_path, monkeypatch, p, config)
        assert runtime is not None
        # strict default = True
        assert runtime._config.disable_ipv6 is True  # type: ignore[attr-defined]

    def test_missing_policy_json_disable_ipv6_defaults_to_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No policy.json → off mode → disable_ipv6 stays False."""
        runtime = self._register_with_policy(tmp_path, monkeypatch, tmp_path / "absent.json", tmp_path / "absent.yaml")
        assert runtime is not None
        assert runtime._config.disable_ipv6 is False  # type: ignore[attr-defined]


class TestSessionStartRefreshesRuntimePolicy:
    """Codex round 9 P1-B (2026-05-14): runtime config is built once
    at ``register()``. Hooks re-read policy/default_path on every
    session start. If ``policy.json`` is bumped lenient → strict
    after registration (a long-lived process), ``on_session_start``
    must propagate the new policy to the runtime before calling
    ``api.use()``. Otherwise a Tor bring-up failure falls back to
    clearnet inside the runtime (which still thinks it's lenient)
    instead of raising :class:`MordredPathBringupFailed`.
    """

    def test_session_start_refuses_changed_activation_config_before_mutating_policy(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks
        from mordred_hermes.network.runtime import Runtime, RuntimeConfig

        cfg = RuntimeConfig(policy_mode="lenient", default_path="clearnet")
        rt = Runtime(
            config=cfg,
            audit=_FakeAudit(),
            env={},
        )
        rt.activate_and_freeze("clearnet")
        api.set_runtime(rt)

        # Disk policy and route changed after provider-client construction.
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        with pytest.raises(MordredPathBringupFailed, match="restart Hermes"):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

        # Do not partially mutate policy on a route whose activation snapshot
        # was rejected; the process must restart as one unit.
        assert rt._config.policy_mode == "lenient"  # type: ignore[attr-defined]
        rt.stop()


# --------------------------------------------------------------------------- #
# api.is_dropped / api.stop helpers                                           #
# --------------------------------------------------------------------------- #


class TestApiHelpers:
    def test_api_is_dropped_delegates_to_runtime(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)
        assert api.is_dropped() is True

    def test_api_stop_delegates_to_runtime(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        api.set_runtime(rt)
        api.stop()
        assert rt.stop_called

    def test_api_is_dropped_no_runtime_returns_false(self) -> None:
        from mordred_hermes.network import api

        assert api.is_dropped() is False

    def test_api_stop_no_runtime_is_noop(self) -> None:
        from mordred_hermes.network import api

        api.stop()
