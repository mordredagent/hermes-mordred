"""Tests for ``mordred_hermes.network.hooks`` (Phase 3 PR2-B).

The hooks layer bridges Hermes's plugin lifecycle and the PR2-A
:class:`Runtime`. Three handlers map directly to TODO.md §3.1 L344-351:

- ``on_session_start`` - read policy + network config from disk and
  bring the configured default path up via :func:`api.use`. Strict +
  bring-up failure raises :class:`MordredPathBringupFailed`
  (``BaseException``-derived; HOOK_PAYLOADS.md §1).
- ``on_session_end`` - :func:`api.stop`.
- ``pre_tool_call`` - strict + :func:`api.is_dropped` raises
  :class:`MordredPathDropped`. Lenient/off return ``None`` because the
  M9 liveness worker already audited the drop with ``decision=warn``.

A tiny ``_FakeCtx`` records ``register_hook`` calls so we can assert
:func:`register` wires the three handlers. Disk I/O is faked via the
``tmp_path`` fixture - synthetic JSON / YAML, no real ``~/.hermes``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    BringupFailed,
    MordredPathBringupFailed,
    MordredPathDropped,
)

# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: dict[str, Any]) -> None:
        self.entries.append(dict(entry))


class _FakeRuntime:
    """Fake satisfying the runtime surface the hooks layer touches."""

    def __init__(self) -> None:
        self.use_calls: list[str] = []
        self.use_raises: BaseException | None = None
        self.stop_called: bool = False
        self.dropped: bool = False
        self._active_path: str = "clearnet"
        self._ready: bool = False
        self.isolation_token: str | None = None

    def use(self, path: str) -> None:
        self.use_calls.append(path)
        if self.use_raises is not None:
            raise self.use_raises
        self._active_path = path
        self._ready = True

    def status(self) -> Any:
        from mordred_hermes.network.api import NetworkStatus

        return NetworkStatus(
            active_path=self._active_path,
            ready=self._ready,
            last_health=True,
        )

    def health(self) -> bool:
        return True

    def stop(self) -> None:
        self.stop_called = True
        self._ready = False

    def is_dropped(self) -> bool:
        return self.dropped

    def update_policy_mode(self, policy_mode: str) -> None:
        # Codex r9-P1-B (2026-05-14): hooks.on_session_start now pushes
        # disk policy into the runtime before api.use. The fake records
        # the value so tests can assert propagation.
        self.policy_mode = policy_mode

    def set_isolation_token(self, token: str | None) -> None:
        # v2-N1 wiring: on_session_start pushes the session_id as the
        # per-session circuit-isolation token before bring-up.
        self.isolation_token = token


class _FakeCtx:
    """Hermes PluginContext stand-in. Records register_hook calls."""

    def __init__(self) -> None:
        self.hooks: list[tuple[str, Callable[..., Any]]] = []

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
        self.hooks.append((hook_name, callback))


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _write_policy(
    tmp_path: Path,
    policy_mode: str = "off",
    *,
    disable_ipv6: bool | None = None,
) -> Path:
    p = tmp_path / "policy.json"
    payload: dict[str, Any] = {"policy": policy_mode}
    if disable_ipv6 is not None:
        payload["disable_ipv6"] = disable_ipv6
    p.write_text(json.dumps(payload))
    return p


def _write_config(tmp_path: Path, default_path: str = "clearnet") -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(f"plugins:\n  mordred_network:\n    default_path: {default_path}\n")
    return p


@pytest.fixture(autouse=True)
def _reset_api() -> Any:
    """Make sure the global api runtime is empty before each test."""
    from mordred_hermes.network import api

    api.reset_runtime_for_tests()
    yield
    api.reset_runtime_for_tests()


# --------------------------------------------------------------------------- #
# on_session_start                                                            #
# --------------------------------------------------------------------------- #


class TestOnSessionStart:
    def test_off_does_not_bring_up_when_default_clearnet(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "clearnet")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.use_calls == []

    def test_sets_isolation_token_from_session_id(self, tmp_path: Path) -> None:
        """v2-N1 wiring: the session_id becomes the per-session circuit token,
        pushed to the runtime before bring-up."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
            session_id="abc-123",
        )
        assert rt.isolation_token == "abc-123"
        assert rt.use_calls == ["tor"]

    def test_without_session_id_leaves_token_unset(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.isolation_token is None

    def test_without_session_id_clears_stale_token(self, tmp_path: Path) -> None:
        """A reused Runtime must not leak a prior session's circuit token into a
        session that supplies no session_id — clear it rather than inherit."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.isolation_token = "stale-from-prev-session"
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.isolation_token is None

    def test_sets_isolation_token_even_when_clearnet_off(self, tmp_path: Path) -> None:
        """Session identity is established regardless of the initial path, so a
        later manual ``network use tor`` rides the session's circuit."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "clearnet")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
            session_id="xyz-789",
        )
        assert rt.isolation_token == "xyz-789"
        assert rt.use_calls == []

    def test_strict_default_tor_brings_up_tor(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.use_calls == ["tor"]

    def test_lenient_default_vpn_brings_up_vpn(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "vpn")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.use_calls == ["vpn"]

    def test_strict_bringup_failure_raises_MordredPathBringupFailed(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use_raises = BringupFailed("tor timeout")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

    def test_lenient_bringup_failure_does_not_raise(self, tmp_path: Path) -> None:
        """Lenient bring-up failure is handled inside the runtime
        (fallback + audit). The hook stays silent."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "tor")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )

    def test_missing_config_defaults_to_clearnet_in_strict(self, tmp_path: Path) -> None:
        """A missing config.yaml behaves like clearnet (safe default)."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = tmp_path / "missing.yaml"

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.use_calls == ["clearnet"]

    def test_strict_bringup_failure_audits_bringup_failed(self, tmp_path: Path) -> None:
        """Strict-path escalation emits ``network.bringup_failed`` audit
        before raising :class:`MordredPathBringupFailed`."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use_raises = BringupFailed("tor timeout")
        api.set_runtime(rt)
        audit = _FakeAudit()
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=audit,
            )
        reasons = [e.get("reason") for e in audit.entries]
        assert "network.bringup_failed" in reasons


# --------------------------------------------------------------------------- #
# on_session_end                                                              #
# --------------------------------------------------------------------------- #


class TestOnSessionEnd:
    def test_stops_runtime(self) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        hooks.on_session_end()
        assert rt.stop_called

    def test_idempotent_when_no_runtime_registered(self) -> None:
        from mordred_hermes.network import hooks

        hooks.on_session_end()  # no exception expected


# --------------------------------------------------------------------------- #
# pre_tool_call                                                               #
# --------------------------------------------------------------------------- #


class TestPreToolCall:
    def test_strict_dropped_raises_MordredPathDropped(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")

        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                audit=_FakeAudit(),
            )

    def test_strict_not_dropped_returns_none(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.dropped = False
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_lenient_dropped_does_not_raise(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "lenient")

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_off_dropped_does_not_raise(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "off")

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_no_runtime_registered_returns_none(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        policy = _write_policy(tmp_path, "strict")
        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            audit=_FakeAudit(),
        )
        assert result is None


# --------------------------------------------------------------------------- #
# Bootstrap polling helper                                                    #
# --------------------------------------------------------------------------- #


class TestWaitUntilReady:
    def test_returns_true_when_ready(self) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        assert hooks.wait_until_ready(timeout=0.1) is True

    def test_returns_false_on_timeout(self) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        assert hooks.wait_until_ready(timeout=0.05) is False


# --------------------------------------------------------------------------- #
# register(ctx) wiring                                                        #
# --------------------------------------------------------------------------- #


class TestRegister:
    def test_register_wires_three_hooks(self) -> None:
        from mordred_hermes.network import register

        ctx = _FakeCtx()
        register(ctx)
        names = [name for name, _ in ctx.hooks]
        assert "on_session_start" in names
        assert "on_session_end" in names
        assert "pre_tool_call" in names

    def test_register_sets_runtime_singleton(self) -> None:
        from mordred_hermes.network import api, register

        ctx = _FakeCtx()
        register(ctx)
        s = api.status()
        assert s.active_path == "clearnet"
        assert s.ready is False

    def test_register_is_idempotent(self) -> None:
        from mordred_hermes.network import register

        ctx = _FakeCtx()
        register(ctx)
        first_count = len(ctx.hooks)
        register(ctx)
        assert len(ctx.hooks) >= first_count


# --------------------------------------------------------------------------- #
# api.is_dropped / api.stop helpers                                           #
# --------------------------------------------------------------------------- #


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

    def test_register_unhashable_policy_value_falls_back_to_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Codex round 3 P2 (2026-05-14): a corrupted ``policy.json``
        with ``policy: []`` or ``policy: {}`` must collapse to the safe
        ``off`` default. The pre-fix code used ``mode in _VALID_MODES``
        against a frozenset which raises ``TypeError`` on unhashable
        values — that would crash plugin registration before the
        runtime and hooks were ever installed.
        """
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
        net_pkg.register(ctx)  # must not raise TypeError

        runtime = api._RUNTIME
        assert runtime is not None
        assert runtime._config.policy_mode == "off"  # type: ignore[attr-defined]

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


class TestRegisterLoadsDisableIPv6FromDisk:
    """Phase 3 PR3a Task #2: ``disable_ipv6`` schema in ``policy.json``.

    ``RuntimeConfig.disable_ipv6`` is the v1 flag for IPv6-leak defence in
    advisory form (flagger warning + IPv4-only resolver hint; full kernel
    enforcement is v2-N2). When ``policy.json`` doesn't pin the value, the
    reader infers it from ``policy_mode`` so a strict-by-disk policy gets
    safe-by-default IPv6 disabling without an explicit toggle. When the
    user pins it, their choice wins.
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

    def test_session_start_pushes_fresh_policy_to_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mordred_hermes.network import api, hooks
        from mordred_hermes.network.runtime import Runtime, RuntimeConfig

        # Build a real Runtime with stale lenient policy.
        cfg = RuntimeConfig(policy_mode="lenient", default_path="clearnet")

        # Tor bring-up always fails for this test.
        def fail_wait(*_: Any, **__: Any) -> None:
            raise BringupFailed("synthetic tor bootstrap failure")

        rt = Runtime(
            config=cfg,
            audit=_FakeAudit(),
            env={},
            tor_wait_for_bootstrap=fail_wait,
        )
        api.set_runtime(rt)

        # Disk policy has since been bumped to strict.
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        # on_session_start must refresh the runtime's policy_mode and
        # then escalate the strict bring-up failure.
        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

        # And the runtime should now reflect the fresh policy.
        assert rt._config.policy_mode == "strict"  # type: ignore[attr-defined]
        rt.stop()


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
