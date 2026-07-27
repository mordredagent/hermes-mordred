"""Tests for ``mordred_hermes.network.hooks`` (Phase 3 PR2-B).

The hooks layer bridges Hermes's plugin lifecycle and the PR2-A
:class:`Runtime`. Four handlers map directly to the Hermes lifecycle:

- ``on_session_start`` - read policy + network config from disk and
  validate/reuse the process-frozen path via :func:`api.use`. A live path
  change or strict bring-up failure raises :class:`MordredPathBringupFailed`
  (``BaseException``-derived; HOOK_PAYLOADS.md §1).
- ``on_session_end`` - retain the active path between conversation turns.
- ``pre_api_request`` - strict protected routes must remain active, ready, and
  not dropped; Tor additionally revalidates the request-resolved provider.
- ``pre_tool_call`` - strict protected routes must still match the frozen
  activation config and remain active/ready/not-dropped. Route validation
  failures escape as a ``BaseException`` refusal; lenient/off retain the
  previous policy result.

A tiny ``_FakeCtx`` records ``register_hook`` calls so we can assert
:func:`register` wires the four handlers. Disk I/O is faked via the
``tmp_path`` fixture - synthetic JSON / YAML, no real ``~/.hermes``.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    BringupFailed,
    MordredNetworkError,
    MordredPathBringupFailed,
    MordredPathDropped,
    PathSwitchRequiresRestart,
)

# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class _FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, entry: Mapping[str, Any]) -> None:
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
        self.isolation_token_calls: list[str | None] = []
        self.process_route_frozen = False
        self.frozen_requested_path: str | None = None
        self.frozen_route_config: Any = None
        self.activation_config_fingerprint: Any = None

    def use(self, path: str) -> None:
        if self._ready and self._active_path == path:
            return
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
        self.isolation_token_calls.append(token)
        self.isolation_token = token

    def freeze_process_route(self, *, expected_path: str | None = None) -> None:
        self.process_route_frozen = True
        self.frozen_requested_path = expected_path or self._active_path
        self.frozen_route_config = self.activation_config_fingerprint

    def activate_and_freeze(self, path: str) -> None:
        self.use(path)
        self.freeze_process_route(expected_path=path)

    def assert_route_config(self, config: Any) -> None:
        if self.frozen_route_config is None:
            return
        from mordred_hermes.network.runtime import route_config_fingerprint

        if route_config_fingerprint(config) != self.frozen_route_config:
            raise PathSwitchRequiresRestart("activation configuration changed; restart Hermes")


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
    provider_overrides: Any | None = None,
) -> Path:
    p = tmp_path / "policy.json"
    payload: dict[str, Any] = {"policy": policy_mode}
    if disable_ipv6 is not None:
        payload["disable_ipv6"] = disable_ipv6
    if provider_overrides is not None:
        payload["provider_overrides"] = provider_overrides
    p.write_text(json.dumps(payload))
    return p


def _write_config(tmp_path: Path, default_path: str = "clearnet") -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(f"plugins:\n  mordred_network:\n    default_path: {default_path}\n")
    return p


def _write_config_with_network_fields(
    tmp_path: Path,
    default_path: str,
    **fields: Any,
) -> Path:
    p = tmp_path / "config.yaml"
    lines = [
        "plugins:",
        "  mordred_network:",
        f"    default_path: {default_path}",
        *(f"    {key}: {json.dumps(value)}" for key, value in fields.items()),
    ]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _write_config_with_provider(tmp_path: Path, default_path: str, provider: str) -> Path:
    """config.yaml carrying both the network default_path and a
    ``model.provider`` (the transport gate resolves the provider from there)."""
    p = tmp_path / "config.yaml"
    p.write_text(f"plugins:\n  mordred_network:\n    default_path: {default_path}\nmodel:\n  provider: {provider}\n")
    return p


@pytest.fixture(autouse=True)
def _reset_api() -> Any:
    """Make sure the global api runtime is empty before each test."""
    from mordred_hermes.network import api

    api.reset_runtime_for_tests()
    yield
    api.stop()
    api.reset_runtime_for_tests()


@pytest.fixture
def _skip_process_route_activation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Config-reader tests should not start real Tor/VPN subprocesses."""
    monkeypatch.setattr(
        "mordred_hermes.network._activate_process_route",
        lambda **_kwargs: None,
    )


# --------------------------------------------------------------------------- #
# on_session_start                                                            #
# --------------------------------------------------------------------------- #


class TestOnSessionStart:
    def test_off_reuses_ready_default_clearnet(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        rt.use_calls.clear()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "clearnet")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert rt.use_calls == []

    @pytest.mark.parametrize("policy_mode", ["strict", "lenient", "off"])
    def test_live_route_change_requires_restart_in_every_policy_mode(
        self,
        tmp_path: Path,
        policy_mode: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use_raises = PathSwitchRequiresRestart("provider clients captured the first route")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, policy_mode)
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed, match="restart Hermes"):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=audit,
            )

        assert rt.stop_called is False
        assert any(
            entry.get("reason") == "network.bringup_failed" and entry.get("decision") == "block"
            for entry in audit.entries
        )

    @pytest.mark.parametrize(
        ("configured_path", "effective_path"),
        [("tor", "clearnet"), ("vpn", "vpn")],
    )
    def test_lenient_protected_route_policy_upgrade_requires_restart_before_reuse(
        self,
        tmp_path: Path,
        configured_path: str,
        effective_path: str,
    ) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api, hooks

        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, configured_path)
        initial_config = network._load_runtime_config(
            policy_json_path=policy,
            config_path=config,
        )
        rt = _FakeRuntime()
        rt._active_path = effective_path
        rt._ready = True
        rt.process_route_frozen = True
        rt.frozen_requested_path = configured_path
        rt.frozen_route_config = network.route_config_fingerprint(initial_config)
        api.set_runtime(rt)
        _write_policy(tmp_path, "strict")

        with pytest.raises(MordredPathBringupFailed, match="restart Hermes"):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

        assert rt.use_calls == []
        assert not hasattr(rt, "policy_mode")

    def test_session_id_does_not_overwrite_process_isolation_token(self, tmp_path: Path) -> None:
        """Gateway session ids must not mutate process-global proxy credentials."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.isolation_token = "process-token"
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
            session_id="abc-123",
        )
        assert rt.isolation_token == "process-token"
        assert rt.isolation_token_calls == []
        assert rt.use_calls == ["tor"]

    def test_strict_default_tor_brings_up_tor(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")

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
# on_session_start — provider-vs-transport compatibility gate (FIX 1)         #
# --------------------------------------------------------------------------- #


class TestTransportCompatibilityGate:
    """FIX 1 (2026-07-13): ``on_session_start`` now runs
    ``provider_transport_flagger.evaluate`` against the resolved provider and
    the active path. A strict Tor session talking to a SOCKS5h-ignoring
    provider (``bedrock``) is refused with :class:`MordredPathBringupFailed`;
    a compatible provider is not; lenient downgrades the abort to an audited
    warning; ``off`` emits nothing. These tests fail if the gate is reverted.
    """

    _TRANSPORT_REASON = "network.transport_incompatible"

    def _transport_entries(self, audit: _FakeAudit) -> list[dict[str, Any]]:
        return [e for e in audit.entries if e.get("reason") == self._TRANSPORT_REASON]

    def test_strict_tor_socks5h_ignoring_provider_aborts(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "bedrock")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        # The path DID come up — the refusal is the transport gate, not bring-up.
        assert rt.use_calls == ["tor"]
        # The route is process-global and may already serve another gateway
        # session, so this session-scoped provider refusal must not stop it.
        assert rt.stop_called is False
        assert rt.status().active_path == "tor"
        blocks = [e for e in self._transport_entries(audit) if e.get("decision") == "block"]
        assert blocks, "expected a block-decision transport audit entry"
        assert blocks[0]["provider"] == "bedrock"
        assert blocks[0]["severity"] == "abort"

    def test_strict_tor_compatible_provider_does_not_abort(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        audit = _FakeAudit()

        # anthropic honours socks5h + ipv6 proxy → no flags, no refusal.
        hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        assert self._transport_entries(audit) == []

    def test_strict_tor_unknown_provider_aborts_without_stopping_route(self, tmp_path: Path) -> None:
        """No compatibility evidence is not safe enough for strict Tor."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "my-internal-llm")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries, "unknown provider should be audited as a block"
        assert all(e.get("decision") == "block" for e in entries)
        assert all(e.get("severity") == "abort" for e in entries)

    def test_strict_tor_unverified_provider_aborts_without_stopping_route(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict", disable_ipv6=True)
        config = _write_config_with_provider(tmp_path, "tor", "openrouter")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert any("not packet-capture verified" in str(e.get("detail")) for e in entries)
        assert all(e.get("decision") == "block" for e in entries)

    def test_lenient_tor_socks5h_ignoring_provider_audits_warning_no_abort(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "lenient")
        config = _write_config_with_provider(tmp_path, "tor", "bedrock")
        audit = _FakeAudit()

        # lenient downgrades every abort to a warning → audited, session continues.
        hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        entries = self._transport_entries(audit)
        assert entries, "expected transport-incompatibility warning audit entries"
        assert all(e.get("decision") == "warn" for e in entries)
        assert all(e.get("severity") == "warning" for e in entries)

    def test_off_emits_no_transport_flags(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "off")
        # off + a non-clearnet default still exercises evaluate(); off returns [].
        config = _write_config_with_provider(tmp_path, "tor", "bedrock")
        audit = _FakeAudit()

        hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        assert self._transport_entries(audit) == []

    def test_provider_resolved_from_auth_json_when_config_absent(self, tmp_path: Path) -> None:
        """When config.yaml has no ``model.provider`` the gate falls back to
        ``auth.json active_provider`` (canonicalised: ``aws`` → ``bedrock``)."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")  # no model.provider
        auth = tmp_path / "auth.json"
        auth.write_text(json.dumps({"active_provider": "aws"}))
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                auth_json_path=auth,
                audit=audit,
            )
        blocks = [e for e in self._transport_entries(audit) if e.get("decision") == "block"]
        assert blocks and blocks[0]["provider"] == "bedrock"

    def test_strict_tor_no_provider_configured_aborts_without_stopping_route(self, tmp_path: Path) -> None:
        """Missing provider evidence is an unknown transport under strict Tor."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries
        assert entries[0]["provider"] == "<unresolved>"
        assert entries[0]["decision"] == "block"

    def test_strict_tor_auto_provider_with_malformed_auth_aborts_as_unresolved(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "auto")
        auth = tmp_path / "auth.json"
        auth.write_text("{not-json")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                auth_json_path=auth,
                audit=audit,
            )

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries and entries[0]["provider"] == "<unresolved>"
        assert entries[0]["decision"] == "block"

    def test_lenient_tor_unresolved_provider_warns_and_continues(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries and entries[0]["provider"] == "<unresolved>"
        assert entries[0]["decision"] == "warn"
        assert entries[0]["severity"] == "warning"

    @pytest.mark.parametrize("stage", ["status", "provider_config", "auth", "evaluate"])
    def test_strict_tor_internal_gate_exception_audits_without_stopping_and_refuses(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        stage: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        auth = tmp_path / "auth.json"
        auth.write_text(json.dumps({"active_provider": "anthropic"}))
        audit = _FakeAudit()

        def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError(f"synthetic {stage} failure")

        if stage == "status":
            monkeypatch.setattr(api, "status", _boom)
        elif stage == "provider_config":
            monkeypatch.setattr(hooks, "_read_config_model_provider", _boom)
        elif stage == "auth":
            config = _write_config_with_provider(tmp_path, "tor", "auto")
            monkeypatch.setattr(hooks, "_read_auth_active_provider", _boom)
        else:
            monkeypatch.setattr(hooks, "evaluate", _boom)

        with pytest.raises(MordredPathBringupFailed) as excinfo:
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                auth_json_path=auth,
                audit=audit,
            )

        assert isinstance(excinfo.value.__cause__, RuntimeError)
        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["decision"] == "block"
        assert entries[0]["severity"] == "abort"
        expected_stage = "provider_resolution" if stage in {"provider_config", "auth"} else stage
        assert entries[0]["stage"] == expected_stage

    @pytest.mark.parametrize("stage", ["status", "provider_config", "auth", "evaluate"])
    @pytest.mark.parametrize("policy_mode", ["lenient", "off"])
    def test_non_strict_internal_gate_exception_warns_and_continues(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        policy_mode: str,
        stage: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, policy_mode)
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        auth = tmp_path / "auth.json"
        auth.write_text(json.dumps({"active_provider": "anthropic"}))
        audit = _FakeAudit()

        def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError(f"synthetic {stage} failure")

        if stage == "status":
            monkeypatch.setattr(api, "status", _boom)
        elif stage == "provider_config":
            monkeypatch.setattr(hooks, "_read_config_model_provider", _boom)
        elif stage == "auth":
            config = _write_config_with_provider(tmp_path, "tor", "auto")
            monkeypatch.setattr(hooks, "_read_auth_active_provider", _boom)
        else:
            monkeypatch.setattr(hooks, "evaluate", _boom)
        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            auth_json_path=auth,
            audit=audit,
        )

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["decision"] == "warn"
        assert entries[0]["severity"] == "warning"
        expected_stage = "provider_resolution" if stage in {"provider_config", "auth"} else stage
        assert entries[0]["stage"] == expected_stage
        assert "continuing" in caplog.text

    def test_strict_tor_gate_refusal_survives_audit_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mordred_hermes.network import api, hooks

        class _ExplodingAudit:
            def append(self, _entry: Mapping[str, Any]) -> None:
                raise OSError("synthetic audit failure")

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        monkeypatch.setattr(hooks, "evaluate", lambda **_kwargs: 1 / 0)

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=_ExplodingAudit(),
            )
        assert rt.stop_called is False

    def test_strict_tor_gate_refusal_never_calls_process_stop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        audit = _FakeAudit()

        def _gate_boom(**_kwargs: Any) -> Any:
            raise RuntimeError("synthetic evaluate failure")

        def _stop_boom() -> None:
            raise AssertionError("session-scoped refusal must not stop the process route")

        monkeypatch.setattr(hooks, "evaluate", _gate_boom)
        monkeypatch.setattr(api, "stop", _stop_boom)

        with pytest.raises(MordredPathBringupFailed) as excinfo:
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        assert isinstance(excinfo.value.__cause__, RuntimeError)
        entries = self._transport_entries(audit)
        assert entries and entries[0]["decision"] == "block"

    def test_strict_tor_additive_provider_override_is_applied(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        override = {
            "my-internal": {
                "transport": "httpx",
                "respects_proxy": True,
                "respects_socks5h": True,
                "respects_ipv6_proxy": True,
                "unverified_baseline": False,
            }
        }
        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict", provider_overrides=override)
        config = _write_config_with_provider(tmp_path, "tor", "my-internal")
        audit = _FakeAudit()

        hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        assert rt.stop_called is False
        assert self._transport_entries(audit) == []

    def test_strict_tor_override_cannot_replace_baseline(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        override = {
            "anthropic": {
                "transport": "httpx",
                "respects_proxy": True,
                "respects_socks5h": True,
                "respects_ipv6_proxy": True,
                "unverified_baseline": False,
            }
        }
        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict", provider_overrides=override)
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed) as excinfo:
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        assert isinstance(excinfo.value.__cause__, ValueError)
        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries and entries[0]["stage"] == "evaluate"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize(
        "malformed",
        [
            [],
            {"my-internal": []},
            {"my-internal": {"respects_socks5h": "yes"}},
            {"my-internal": {"respects_sock5h": True}},
        ],
    )
    def test_strict_tor_malformed_provider_override_fails_closed(
        self,
        tmp_path: Path,
        malformed: Any,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict", provider_overrides=malformed)
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries and entries[0]["stage"] == "provider_overrides"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize("policy_mode", ["lenient", "off"])
    def test_non_strict_tor_malformed_provider_override_warns_and_continues(
        self,
        tmp_path: Path,
        policy_mode: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, policy_mode, provider_overrides=["bad"])
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        audit = _FakeAudit()

        hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert entries and entries[0]["stage"] == "provider_overrides"
        assert entries[0]["decision"] == "warn"


# --------------------------------------------------------------------------- #
# on_session_end                                                              #
# --------------------------------------------------------------------------- #


class TestOnSessionEnd:
    def test_keeps_runtime_active_for_continuation_turn(self) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        api.set_runtime(rt)
        hooks.on_session_end()
        assert rt.stop_called is False
        assert rt.status().active_path == "tor"

    def test_idempotent_when_no_runtime_registered(self) -> None:
        from mordred_hermes.network import hooks

        hooks.on_session_end()  # no exception expected


# --------------------------------------------------------------------------- #
# pre_api_request                                                             #
# --------------------------------------------------------------------------- #


class TestPreApiRequestTransportGate:
    """The request-resolved provider is authoritative immediately pre-egress."""

    _TRANSPORT_REASON = "network.transport_incompatible"

    def _transport_entries(self, audit: _FakeAudit) -> list[dict[str, Any]]:
        return [e for e in audit.entries if e.get("reason") == self._TRANSPORT_REASON]

    def test_runtime_provider_override_is_blocked_on_strict_tor(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        for _attempt in range(2):
            with pytest.raises(MordredPathBringupFailed, match="outbound API request"):
                hooks.pre_api_request(
                    policy_json_path=policy,
                    config_path=config,
                    provider="bedrock",
                    audit=audit,
                )

        # Request refusal must not call Runtime.stop(): stop resets the active
        # path to clearnet and would let a long-lived gateway's next request
        # skip this strict-Tor gate. Both attempts above must remain blocked.
        assert rt.stop_called is False
        assert rt.status().active_path == "tor"
        entries = self._transport_entries(audit)
        assert entries
        assert all(entry["event"] == "pre_api_request" for entry in entries)
        assert all(entry["provider"] == "bedrock" for entry in entries)
        assert all(entry["decision"] == "block" for entry in entries)

    def test_verified_runtime_provider_is_allowed_on_strict_tor(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        hooks.pre_api_request(
            policy_json_path=policy,
            config_path=config,
            provider="anthropic",
            audit=audit,
        )

        assert rt.stop_called is False
        assert self._transport_entries(audit) == []

    @pytest.mark.parametrize("provider", [None, "", "  "])
    def test_missing_runtime_provider_fails_closed_on_strict_tor(
        self,
        tmp_path: Path,
        provider: Any,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider=provider,
                audit=audit,
            )

        assert rt.stop_called is False
        assert rt.status().active_path == "tor"
        entries = self._transport_entries(audit)
        assert entries and entries[0]["provider"] == "<unresolved>"
        assert entries[0]["event"] == "pre_api_request"

    def test_runtime_provider_gate_is_inactive_off_tor(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "clearnet")
        audit = _FakeAudit()

        hooks.pre_api_request(
            policy_json_path=policy,
            config_path=config,
            provider="bedrock",
            audit=audit,
        )

        assert rt.stop_called is False
        assert self._transport_entries(audit) == []

    def test_configured_tor_missing_at_request_time_fails_closed(
        self,
        tmp_path: Path,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed, match="configured protected path 'tor' is not active"):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["event"] == "pre_api_request"
        assert entries[0]["stage"] == "required_path"
        assert entries[0]["active_path"] == "clearnet"
        assert entries[0]["decision"] == "block"

    def test_configured_vpn_missing_at_request_time_fails_closed(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "vpn")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed, match="configured protected path 'vpn' is not active"):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "required_path"
        assert entries[0]["active_path"] == "clearnet"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize("protected_path", ["tor", "vpn"])
    def test_active_protected_path_not_ready_fails_closed(
        self,
        tmp_path: Path,
        protected_path: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt._active_path = protected_path
        rt._ready = False
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, protected_path)
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed, match="is not ready"):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "path_readiness"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize("protected_path", ["tor", "vpn"])
    def test_active_protected_path_dropped_fails_closed_before_provider_request(
        self,
        tmp_path: Path,
        protected_path: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt._active_path = protected_path
        rt._ready = True
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, protected_path)
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed, match="was dropped"):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        assert rt.stop_called is False
        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "path_readiness"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize("config_change", ["disable_ipv6", "vpn_provider"])
    def test_same_path_activation_config_change_fails_closed_on_continuation(
        self,
        tmp_path: Path,
        config_change: str,
    ) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api, hooks

        policy = _write_policy(tmp_path, "strict", disable_ipv6=True)
        protected_path = "tor" if config_change == "disable_ipv6" else "vpn"
        config = _write_config(tmp_path, protected_path)
        initial_config = network._load_runtime_config(
            policy_json_path=policy,
            config_path=config,
        )
        rt = _FakeRuntime()
        rt._active_path = protected_path
        rt._ready = True
        rt.process_route_frozen = True
        rt.frozen_requested_path = protected_path
        rt.frozen_route_config = network.route_config_fingerprint(initial_config)
        api.set_runtime(rt)

        if config_change == "disable_ipv6":
            _write_policy(tmp_path, "strict", disable_ipv6=False)
        else:
            _write_config_with_network_fields(
                tmp_path,
                "vpn",
                vpn_provider="custom",
                custom_up_cmd=["custom-vpn", "connect"],
                custom_down_cmd=["custom-vpn", "disconnect"],
            )
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed, match="activation configuration changed"):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "activation_config"
        assert rt.stop_called is False

    def test_lenient_vpn_to_strict_fails_closed_on_continuation_request(
        self,
        tmp_path: Path,
    ) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api, hooks

        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "vpn")
        initial_config = network._load_runtime_config(
            policy_json_path=policy,
            config_path=config,
        )
        rt = _FakeRuntime()
        rt._active_path = "vpn"
        rt._ready = True
        rt.process_route_frozen = True
        rt.frozen_requested_path = "vpn"
        rt.frozen_route_config = network.route_config_fingerprint(initial_config)
        api.set_runtime(rt)
        _write_policy(tmp_path, "strict")

        with pytest.raises(MordredPathBringupFailed, match="activation configuration changed"):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=_FakeAudit(),
            )

        assert rt.stop_called is False

    def test_config_reader_internal_error_fails_closed_before_request(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        def _boom(_config_path: Path) -> str:
            raise RuntimeError("synthetic config resolution failure")

        monkeypatch.setattr(hooks, "_read_default_network_path_strict", _boom)
        with pytest.raises(MordredPathBringupFailed):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "configured_path"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize(
        "content",
        [
            "- top-level-list\n",
            "plugins: [not, a, mapping]\n",
            "plugins:\n  mordred_network: not-a-mapping\n",
            "plugins:\n  mordred_network:\n    default_path: onion\n",
            "plugins:\n  mordred_network:\n    default_path: 7\n",
            "plugins: [unterminated\n",
        ],
    )
    def test_damaged_existing_config_fails_closed_before_request(
        self,
        tmp_path: Path,
        content: str,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = tmp_path / "config.yaml"
        config.write_text(content, encoding="utf-8")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "configured_path"
        assert entries[0]["decision"] == "block"

    @pytest.mark.parametrize(
        "content",
        [
            None,
            "",
            "{}\n",
            "model:\n  provider: anthropic\n",
            "plugins: {}\n",
            "plugins:\n  mordred_network: {}\n",
        ],
    )
    def test_legitimately_absent_network_path_defaults_to_clearnet(
        self,
        tmp_path: Path,
        content: str | None,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = tmp_path / "config.yaml"
        if content is not None:
            config.write_text(content, encoding="utf-8")
        audit = _FakeAudit()

        hooks.pre_api_request(
            policy_json_path=policy,
            config_path=config,
            provider="anthropic",
            audit=audit,
        )

        assert self._transport_entries(audit) == []

    def test_unreadable_existing_config_fails_closed_before_request(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("clearnet")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()
        real_open = Path.open

        def _open(path: Path, *args: Any, **kwargs: Any) -> Any:
            if path == config:
                raise PermissionError("synthetic unreadable config")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", _open)
        with pytest.raises(MordredPathBringupFailed):
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["stage"] == "configured_path"
        assert entries[0]["decision"] == "block"

    def test_internal_request_gate_error_fails_closed_on_strict_tor(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        audit = _FakeAudit()

        def _boom(**_kwargs: Any) -> Any:
            raise RuntimeError("synthetic request gate failure")

        monkeypatch.setattr(hooks, "evaluate", _boom)
        with pytest.raises(MordredPathBringupFailed) as excinfo:
            hooks.pre_api_request(
                policy_json_path=policy,
                config_path=config,
                provider="anthropic",
                audit=audit,
            )

        assert isinstance(excinfo.value.__cause__, RuntimeError)
        assert rt.stop_called is False
        assert rt.status().active_path == "tor"
        entries = self._transport_entries(audit)
        assert len(entries) == 1
        assert entries[0]["event"] == "pre_api_request"
        assert entries[0]["stage"] == "evaluate"
        assert entries[0]["decision"] == "block"


# --------------------------------------------------------------------------- #
# Hermes multi-turn lifecycle                                                 #
# --------------------------------------------------------------------------- #


class TestMultiTurnLifecycle:
    def test_strict_tor_survives_turns_without_session_rekey(
        self,
        tmp_path: Path,
    ) -> None:
        """Model per-turn end followed by a reset/new session start."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")
        audit = _FakeAudit()

        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=audit,
            session_id="session-1",
        )
        hooks.pre_api_request(
            policy_json_path=policy,
            config_path=config,
            provider="anthropic",
            audit=audit,
        )

        # Hermes invokes on_session_end after turn one, then continues the same
        # session without another on_session_start.
        hooks.on_session_end(session_id="session-1", turn_id="turn-1")
        hooks.pre_api_request(
            policy_json_path=policy,
            config_path=config,
            provider="anthropic",
            audit=audit,
        )

        assert rt.use_calls == ["tor"]
        assert rt.stop_called is False
        assert rt.status().active_path == "tor"

        # A reset/new session reuses the same process-global path. The fake
        # mirrors Runtime.use's same-ready-path no-op, and the hook must not
        # rewrite process-global SOCKS credentials from a session id.
        hooks.on_session_start(
            policy_json_path=policy,
            config_path=config,
            audit=audit,
            session_id="session-2",
        )
        assert rt.use_calls == ["tor"]
        assert rt.isolation_token_calls == []
        assert rt.stop_called is False


# --------------------------------------------------------------------------- #
# pre_tool_call                                                               #
# --------------------------------------------------------------------------- #


class TestPreToolCall:
    @pytest.mark.parametrize("protected_path", ["tor", "vpn"])
    def test_strict_ready_protected_route_preserves_allow_result(
        self,
        tmp_path: Path,
        protected_path: str,
    ) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api, hooks

        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, protected_path)
        current_config = network._load_runtime_config(
            policy_json_path=policy,
            config_path=config,
        )
        rt = _FakeRuntime()
        rt.activation_config_fingerprint = network.route_config_fingerprint(current_config)
        rt.activate_and_freeze(protected_path)
        api.set_runtime(rt)

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )

        assert result is None
        assert rt.stop_called is False

    def test_frozen_tor_stopped_before_tool_call_fails_closed(self, tmp_path: Path) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api, hooks

        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        current_config = network._load_runtime_config(
            policy_json_path=policy,
            config_path=config,
        )

        class _StoppingRuntime(_FakeRuntime):
            def stop(self) -> None:
                super().stop()
                # Match concrete Runtime.stop(): teardown restores clearnet.
                self._active_path = "clearnet"

        rt = _StoppingRuntime()
        rt.activation_config_fingerprint = network.route_config_fingerprint(current_config)
        rt.activate_and_freeze("tor")
        api.set_runtime(rt)
        api.stop()

        with pytest.raises(MordredPathBringupFailed, match="is not active") as exc_info:
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

        assert isinstance(exc_info.value, BaseException)

    def test_lenient_vpn_to_strict_tool_call_requires_restart(self, tmp_path: Path) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api, hooks

        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "vpn")
        initial_config = network._load_runtime_config(
            policy_json_path=policy,
            config_path=config,
        )
        rt = _FakeRuntime()
        rt.activation_config_fingerprint = network.route_config_fingerprint(initial_config)
        rt.activate_and_freeze("vpn")
        api.set_runtime(rt)
        _write_policy(tmp_path, "strict")

        with pytest.raises(MordredPathBringupFailed, match="activation configuration changed"):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

        assert rt.stop_called is False

    def test_strict_dropped_raises_MordredPathDropped(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

    def test_strict_not_dropped_returns_none(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use("tor")
        rt.dropped = False
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_lenient_dropped_does_not_raise(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "lenient")
        config = _write_config(tmp_path, "tor")

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_off_dropped_does_not_raise(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "tor")

        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_strict_protected_path_without_runtime_fails_closed(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        policy = _write_policy(tmp_path, "strict")
        config = _write_config(tmp_path, "tor")
        with pytest.raises(MordredPathBringupFailed):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )


class TestPolicyReadFailClosed:
    """M1 (security review 2026-06-11): a policy.json that EXISTS but cannot
    be read or parsed must fail CLOSED (read as strict), not fall open to
    "off" — corrupting the policy file must not disable strict enforcement.
    A genuinely absent file still reads as "off" (fresh install).
    """

    def _dropped_runtime(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        rt.use("tor")
        rt.dropped = True
        api.set_runtime(rt)

    def test_corrupt_json_dropped_refuses(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.write_text("{not json", encoding="utf-8")
        config = _write_config(tmp_path, "tor")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

    def test_unreadable_policy_path_dropped_refuses(self, tmp_path: Path) -> None:
        """A directory at the policy path raises OSError on open()."""
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.mkdir()
        config = _write_config(tmp_path, "tor")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

    def test_non_dict_root_dropped_refuses(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.write_text('["strict"]', encoding="utf-8")
        config = _write_config(tmp_path, "tor")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

    def test_invalid_mode_value_dropped_refuses(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.write_text('{"policy": "bogus"}', encoding="utf-8")
        config = _write_config(tmp_path, "tor")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(
                tool_name="web_fetch",
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )

    def test_missing_file_still_defaults_off(self, tmp_path: Path) -> None:
        """Fresh install: no policy.json at all keeps the historical "off"."""
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        config = _write_config(tmp_path, "tor")
        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=tmp_path / "nope.json",
            config_path=config,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_dangling_symlink_reads_as_absent(self, tmp_path: Path) -> None:
        """A dangling symlink raises FileNotFoundError on open — equivalent
        to deletion, so it keeps the fresh-install "off" (an attacker who can
        plant the link could delete the file outright; nothing extra leaks)."""
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.symlink_to(tmp_path / "gone.json")
        config = _write_config(tmp_path, "tor")
        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
            config_path=config,
            audit=_FakeAudit(),
        )
        assert result is None

    def test_corrupt_policy_session_start_uses_strict_bringup(self, tmp_path: Path) -> None:
        """on_session_start reads the same file — corrupt must mean strict
        bring-up semantics (failure refuses the session, no lenient fallback)."""
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        rt.use_raises = BringupFailed("tor timeout")
        api.set_runtime(rt)
        policy = tmp_path / "policy.json"
        policy.write_text("{not json", encoding="utf-8")
        config = _write_config(tmp_path, "tor")

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(
                policy_json_path=policy,
                config_path=config,
                audit=_FakeAudit(),
            )


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
    @pytest.fixture(autouse=True)
    def _isolated_clearnet_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import mordred_hermes.network as network

        policy = _write_policy(tmp_path, "off")
        config = _write_config(tmp_path, "clearnet")
        monkeypatch.setattr(network, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(network, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(network, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        network._build_audit_writer.cache_clear()

    def test_register_wires_integrity_and_network_hooks(self) -> None:
        from mordred_hermes.network import register
        from mordred_hermes.privacy_check.hooks import check_plugin_integrity

        ctx = _FakeCtx()
        register(ctx)
        names = [name for name, _ in ctx.hooks]
        assert names == [
            "on_session_start",
            "on_session_start",
            "on_session_end",
            "pre_api_request",
            "pre_tool_call",
        ]
        assert ctx.hooks[0][1] is check_plugin_integrity

    def test_register_sets_runtime_singleton(self) -> None:
        from mordred_hermes.network import api, register

        ctx = _FakeCtx()
        register(ctx)
        s = api.status()
        assert s.active_path == "clearnet"
        assert s.ready is True

    def test_registered_pre_tool_call_passes_default_config_path(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        ctx = _FakeCtx()
        network.register(ctx)
        received: dict[str, Any] = {}

        def _pre_tool_call_spy(**kwargs: Any) -> dict[str, Any]:
            received.update(kwargs)
            return {"action": "block", "message": "sentinel"}

        monkeypatch.setattr(network.hooks, "pre_tool_call", _pre_tool_call_spy)
        result = ctx.hooks[-1][1](tool_name="web_fetch")

        assert result == {"action": "block", "message": "sentinel"}
        assert received["config_path"] == network.DEFAULT_CONFIG_PATH
        assert received["policy_json_path"] == network.DEFAULT_POLICY_JSON_PATH

    def test_register_is_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api

        class _ReusableRuntime(_FakeRuntime):
            def __init__(self) -> None:
                super().__init__()
                self.process_route_frozen = False
                self.use_attempts: list[str] = []
                self.freeze_calls = 0

            def use(self, path: str) -> None:
                self.use_attempts.append(path)
                super().use(path)

            def freeze_process_route(self, *, expected_path: str | None = None) -> None:
                self.freeze_calls += 1
                super().freeze_process_route(expected_path=expected_path)

        runtime = _ReusableRuntime()
        construction_calls = 0

        def _build_runtime(**_kwargs: Any) -> _ReusableRuntime:
            nonlocal construction_calls
            construction_calls += 1
            runtime.activation_config_fingerprint = network.route_config_fingerprint(_kwargs["config"])
            return runtime

        monkeypatch.setattr(network, "Runtime", _build_runtime)
        first_ctx = _FakeCtx()
        second_ctx = _FakeCtx()
        network.register(first_ctx)
        network.register(second_ctx)

        assert construction_calls == 1
        assert runtime.use_attempts == ["clearnet"]
        assert runtime.freeze_calls == 1
        assert api._RUNTIME is runtime
        assert len(first_ctx.hooks) == len(second_ctx.hooks) == 5

    def test_registers_process_shutdown_cleanup_once(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        callbacks: list[Callable[[], None]] = []
        monkeypatch.setattr(network.atexit, "register", callbacks.append)
        monkeypatch.setattr(network, "_PROCESS_SHUTDOWN_REGISTERED", False)

        network.register(_FakeCtx())
        network.register(_FakeCtx())

        assert callbacks == [network._stop_runtime_at_process_exit]

    def test_process_shutdown_cleanup_stops_current_runtime(self) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        rt.use("tor")
        api.set_runtime(rt)

        network._stop_runtime_at_process_exit()

        assert rt.stop_called is True


class TestRegisterProcessRouteActivation:
    def _seed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        path: str = "tor",
        policy_mode: str = "strict",
    ) -> None:
        import mordred_hermes.network as network

        policy = _write_policy(tmp_path, policy_mode)
        config = _write_config(tmp_path, path)
        monkeypatch.setattr(network, "DEFAULT_POLICY_JSON_PATH", policy)
        monkeypatch.setattr(network, "DEFAULT_CONFIG_PATH", config)
        monkeypatch.setattr(network, "DEFAULT_AUDIT_PATH", tmp_path / "audit.log")
        network._build_audit_writer.cache_clear()

    def test_register_activates_and_freezes_route_before_provider_construction(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import httpx

        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        events: list[str] = []
        for proxy_var in (
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
        ):
            monkeypatch.delenv(proxy_var, raising=False)

        class _RegisterRuntime(_FakeRuntime):
            def __init__(self) -> None:
                super().__init__()
                self.frozen = False

            def use(self, path: str) -> None:
                events.append(f"use:{path}")
                super().use(path)
                # Model Runtime._apply_env: a provider client built after
                # register() returns must see the protected transport.
                monkeypatch.setenv("HTTPS_PROXY", "socks5h://127.0.0.1:9050")

            def freeze_process_route(self, *, expected_path: str | None = None) -> None:
                assert self.status().ready is True
                super().freeze_process_route(expected_path=expected_path)
                self.frozen = True
                events.append("freeze")

        runtime = _RegisterRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)

        class _OrderingCtx(_FakeCtx):
            def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
                events.append(f"hook:{hook_name}")
                super().register_hook(hook_name, callback)

        network.register(_OrderingCtx())
        provider_client_proxy = os.environ.get("HTTPS_PROXY")
        with httpx.Client() as provider_client:
            provider_proxy_pools = {
                type(transport._pool).__name__  # type: ignore[attr-defined]
                for transport in provider_client._mounts.values()  # type: ignore[attr-defined]
                if transport is not None
            }

        assert events[:2] == ["use:tor", "freeze"]
        assert events[2].startswith("hook:")
        assert provider_client_proxy == "socks5h://127.0.0.1:9050"
        assert "SOCKSProxy" in provider_proxy_pools
        assert runtime.frozen is True

    def test_strict_registration_bringup_failure_refuses_before_hooks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        runtime = _FakeRuntime()
        runtime.use_raises = BringupFailed("tor bootstrap failed")
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="before provider client construction"):
            network.register(ctx)

        assert ctx.hooks == []
        assert runtime.use_calls == ["tor"]
        assert runtime.stop_called is True
        assert network.api._RUNTIME is None

    @pytest.mark.parametrize("failure_stage", ["use", "freeze"])
    def test_unexpected_activation_exception_fails_closed_and_discards_runtime(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failure_stage: str,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)

        class _UnexpectedFailureRuntime(_FakeRuntime):
            def use(self, path: str) -> None:
                if failure_stage == "use":
                    raise RuntimeError("synthetic use failure")
                super().use(path)

            def freeze_process_route(self, *, expected_path: str | None = None) -> None:
                if failure_stage == "freeze":
                    raise RuntimeError("synthetic freeze failure")
                super().freeze_process_route(expected_path=expected_path)

        runtime = _UnexpectedFailureRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="before provider client construction"):
            network.register(ctx)

        assert ctx.hooks == []
        assert runtime.stop_called is True
        assert network.api._RUNTIME is None

    def test_runtime_constructor_exception_fails_closed_before_hooks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)

        def _constructor_boom(**_kwargs: Any) -> None:
            raise RuntimeError("synthetic constructor failure")

        monkeypatch.setattr(network, "Runtime", _constructor_boom)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="before provider client construction"):
            network.register(ctx)

        assert ctx.hooks == []
        assert network.api._RUNTIME is None

    def test_activation_refusal_survives_cleanup_failure_and_clears_singleton(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)

        class _CleanupFailureRuntime(_FakeRuntime):
            def use(self, path: str) -> None:
                super().use(path)
                raise RuntimeError("synthetic post-bring-up failure")

            def stop(self) -> None:
                self.stop_called = True
                raise OSError("synthetic cleanup failure")

        runtime = _CleanupFailureRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="synthetic post-bring-up failure"):
            network.register(ctx)

        assert ctx.hooks == []
        assert runtime.stop_called is True
        assert network.api._RUNTIME is None

    def test_audit_writer_initialization_exception_fails_closed_before_hooks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)

        def _audit_boom(_path: Path) -> None:
            raise RuntimeError("synthetic audit factory failure")

        monkeypatch.setattr(network, "_build_audit_writer", _audit_boom)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="before audit initialization"):
            network.register(ctx)

        assert ctx.hooks == []
        assert network.api._RUNTIME is None

    def test_atexit_registration_exception_fails_closed_and_discards_unpublished_runtime(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        runtime = _FakeRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)
        monkeypatch.setattr(network, "_PROCESS_SHUTDOWN_REGISTERED", False)
        monkeypatch.setattr(
            network.atexit,
            "register",
            lambda _callback: (_ for _ in ()).throw(RuntimeError("synthetic atexit failure")),
        )
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="process-shutdown cleanup"):
            network.register(ctx)

        assert ctx.hooks == []
        assert runtime.stop_called is True
        assert runtime.use_calls == []
        assert network.api._RUNTIME is None

    def test_integrity_hook_import_exception_fails_closed_and_discards_new_route(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        runtime = _FakeRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)

        def _import_boom() -> None:
            raise RuntimeError("synthetic integrity-hook import failure")

        monkeypatch.setattr(network, "_load_integrity_hook", _import_boom)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="mandatory network hooks"):
            network.register(ctx)

        assert ctx.hooks == []
        assert runtime.stop_called is True
        assert network.api._RUNTIME is None

    @pytest.mark.parametrize("failure_position", range(5))
    def test_each_hook_registration_exception_fails_closed_and_discards_new_route(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failure_position: int,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        runtime = _FakeRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)

        class _FailingCtx(_FakeCtx):
            def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
                if len(self.hooks) == failure_position:
                    raise RuntimeError(f"synthetic hook failure at {failure_position}")
                super().register_hook(hook_name, callback)

        ctx = _FailingCtx()
        with pytest.raises(MordredPathBringupFailed, match="mandatory network hooks"):
            network.register(ctx)

        assert len(ctx.hooks) == failure_position
        assert runtime.stop_called is True
        assert network.api._RUNTIME is None

    def test_reregistration_hook_failure_preserves_existing_process_route(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        current_config = network._load_runtime_config(
            policy_json_path=network.DEFAULT_POLICY_JSON_PATH,
            config_path=network.DEFAULT_CONFIG_PATH,
        )
        runtime = _FakeRuntime()
        runtime._active_path = "tor"
        runtime._ready = True
        runtime.process_route_frozen = True
        runtime.frozen_requested_path = "tor"
        runtime.frozen_route_config = network.route_config_fingerprint(current_config)
        network.api.set_runtime(runtime)

        class _FailingCtx(_FakeCtx):
            def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
                raise RuntimeError(f"cannot register {hook_name}")

        with pytest.raises(MordredPathBringupFailed, match="mandatory network hooks"):
            network.register(_FailingCtx())

        assert runtime.stop_called is False
        assert network.api._RUNTIME is runtime

    def test_runtime_is_not_published_until_atomic_activation_and_freeze_complete(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        activation_started = threading.Event()
        allow_activation = threading.Event()
        failures: list[BaseException] = []

        class _BlockingRuntime(_FakeRuntime):
            def activate_and_freeze(self, path: str) -> None:
                activation_started.set()
                assert allow_activation.wait(timeout=2.0)
                super().activate_and_freeze(path)

        runtime = _BlockingRuntime()
        monkeypatch.setattr(network, "Runtime", lambda **_kwargs: runtime)

        def _register() -> None:
            try:
                network.register(_FakeCtx())
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=_register)
        worker.start()
        assert activation_started.wait(timeout=2.0)
        assert network.api._RUNTIME is None
        with pytest.raises(MordredNetworkError):
            network.api.use("vpn")

        allow_activation.set()
        worker.join(timeout=2.0)

        assert not worker.is_alive()
        assert failures == []
        assert network.api._RUNTIME is runtime
        assert runtime.process_route_frozen is True
        assert runtime.frozen_requested_path == "tor"

    @pytest.mark.parametrize(
        "invalid_state",
        ["not_ready", "invalid_path", "mismatched_path", "dropped", "not_frozen", "status_error"],
    )
    def test_reregistration_rejects_invalid_existing_runtime_without_replacing_it(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        invalid_state: str,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch)
        runtime = _FakeRuntime()
        runtime._active_path = "tor"
        runtime._ready = True
        runtime.process_route_frozen = True
        current_config = network._load_runtime_config(
            policy_json_path=network.DEFAULT_POLICY_JSON_PATH,
            config_path=network.DEFAULT_CONFIG_PATH,
        )
        runtime.frozen_route_config = network.route_config_fingerprint(current_config)
        if invalid_state == "not_ready":
            runtime._ready = False
        elif invalid_state == "invalid_path":
            runtime._active_path = "invalid"
        elif invalid_state == "mismatched_path":
            runtime._active_path = "clearnet"
        elif invalid_state == "dropped":
            runtime.dropped = True
        elif invalid_state == "not_frozen":
            runtime.process_route_frozen = False
        elif invalid_state == "status_error":

            def _status_boom() -> Any:
                raise RuntimeError("synthetic status failure")

            monkeypatch.setattr(runtime, "status", _status_boom)
        network.api.set_runtime(runtime)

        def _must_not_construct(**_kwargs: Any) -> None:
            raise AssertionError("re-registration must not construct a replacement runtime")

        monkeypatch.setattr(network, "Runtime", _must_not_construct)
        ctx = _FakeCtx()

        with pytest.raises(MordredPathBringupFailed, match="during plugin re-registration"):
            network.register(ctx)

        assert ctx.hooks == []
        assert runtime.stop_called is False
        assert network.api._RUNTIME is runtime

    @pytest.mark.parametrize(
        ("path", "config_change"),
        [
            ("tor", "tor_binary"),
            ("tor", "tor_port"),
            ("tor", "disable_ipv6"),
            ("vpn", "vpn_provider"),
        ],
    )
    def test_reregistration_rejects_same_path_activation_config_change(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
        config_change: str,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch, path=path)
        initial_config = network._load_runtime_config(
            policy_json_path=network.DEFAULT_POLICY_JSON_PATH,
            config_path=network.DEFAULT_CONFIG_PATH,
        )
        runtime = _FakeRuntime()
        runtime._active_path = path
        runtime._ready = True
        runtime.process_route_frozen = True
        runtime.frozen_requested_path = path
        runtime.frozen_route_config = network.route_config_fingerprint(initial_config)
        network.api.set_runtime(runtime)

        if config_change == "tor_binary":
            _write_config_with_network_fields(tmp_path, "tor", tor_binary_path="/opt/other/tor")
        elif config_change == "tor_port":
            _write_config_with_network_fields(tmp_path, "tor", tor_socks_port=19050)
        elif config_change == "disable_ipv6":
            _write_policy(tmp_path, "strict", disable_ipv6=False)
        else:
            _write_config_with_network_fields(
                tmp_path,
                "vpn",
                vpn_provider="custom",
                custom_up_cmd=["custom-vpn", "connect"],
                custom_down_cmd=["custom-vpn", "disconnect"],
            )

        with pytest.raises(MordredPathBringupFailed, match="different activation configuration"):
            network.register(_FakeCtx())

        assert runtime.stop_called is False
        assert network.api._RUNTIME is runtime

    def test_reregistration_reuses_healthy_lenient_fallback_for_same_configured_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import mordred_hermes.network as network

        self._seed(tmp_path, monkeypatch, policy_mode="lenient")
        runtime = _FakeRuntime()
        runtime._active_path = "clearnet"
        runtime._ready = True
        runtime.process_route_frozen = True
        runtime.frozen_requested_path = "tor"
        current_config = network._load_runtime_config(
            policy_json_path=network.DEFAULT_POLICY_JSON_PATH,
            config_path=network.DEFAULT_CONFIG_PATH,
        )
        runtime.frozen_route_config = network.route_config_fingerprint(current_config)
        network.api.set_runtime(runtime)

        def _must_not_construct(**_kwargs: Any) -> None:
            raise AssertionError("healthy fallback must reuse its existing runtime")

        monkeypatch.setattr(network, "Runtime", _must_not_construct)
        ctx = _FakeCtx()

        network.register(ctx)

        assert len(ctx.hooks) == 5
        assert runtime.use_calls == []
        assert network.api._RUNTIME is runtime


# --------------------------------------------------------------------------- #
# api.is_dropped / api.stop helpers                                           #
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("_skip_process_route_activation")
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


@pytest.mark.usefixtures("_skip_process_route_activation")
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


@pytest.mark.usefixtures("_skip_process_route_activation")
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


@pytest.mark.usefixtures("_skip_process_route_activation")
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
