"""Tests for ``mordred_hermes.network.hooks`` (Phase 3 PR2-B).

The hooks layer bridges Hermes's plugin lifecycle and the PR2-A
:class:`Runtime`. Four handlers map directly to the Hermes lifecycle:

- ``on_session_start`` - read policy + network config from disk and
  bring the configured default path up via :func:`api.use`. Strict +
  bring-up failure raises :class:`MordredPathBringupFailed`
  (``BaseException``-derived; HOOK_PAYLOADS.md §1).
- ``on_session_end`` - :func:`api.stop`.
- ``pre_api_request`` - strict + Tor revalidates the provider resolved for
  the actual outbound request, including runtime-only overrides.
- ``pre_tool_call`` - strict + :func:`api.is_dropped` raises
  :class:`MordredPathDropped`. Lenient/off return ``None`` because the
  M9 liveness worker already audited the drop with ``decision=warn``.

A tiny ``_FakeCtx`` records ``register_hook`` calls so we can assert
:func:`register` wires the four handlers. Disk I/O is faked via the
``tmp_path`` fixture - synthetic JSON / YAML, no real ``~/.hermes``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
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
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")

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
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")

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
        config = _write_config_with_provider(tmp_path, "tor", "anthropic")

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
        # ...and it was torn down before the refusal escaped, so the Tor daemon /
        # SOCKS proxy env / liveness thread aren't orphaned if the host never
        # calls on_session_end after on_session_start raises.
        assert rt.stop_called is True
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

    def test_strict_tor_unknown_provider_aborts_and_tears_down(self, tmp_path: Path) -> None:
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
        assert rt.stop_called is True
        entries = self._transport_entries(audit)
        assert entries, "unknown provider should be audited as a block"
        assert all(e.get("decision") == "block" for e in entries)
        assert all(e.get("severity") == "abort" for e in entries)

    def test_strict_tor_unverified_provider_aborts_and_tears_down(self, tmp_path: Path) -> None:
        from mordred_hermes.network import api, hooks

        rt = _FakeRuntime()
        api.set_runtime(rt)
        policy = _write_policy(tmp_path, "strict", disable_ipv6=True)
        config = _write_config_with_provider(tmp_path, "tor", "openrouter")
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.on_session_start(policy_json_path=policy, config_path=config, audit=audit)
        assert rt.use_calls == ["tor"]
        assert rt.stop_called is True
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

    def test_strict_tor_no_provider_configured_aborts_and_tears_down(self, tmp_path: Path) -> None:
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
        assert rt.stop_called is True
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

        assert rt.stop_called is True
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
    def test_strict_tor_internal_gate_exception_audits_stops_and_refuses(
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
        assert rt.stop_called is True
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
        assert rt.stop_called is True

    def test_strict_tor_gate_refusal_survives_stop_failure(
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
            raise OSError("synthetic stop failure")

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
        assert rt.stop_called is True
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

        assert rt.stop_called is True
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
        audit = _FakeAudit()

        for _attempt in range(2):
            with pytest.raises(MordredPathBringupFailed, match="outbound API request"):
                hooks.pre_api_request(
                    policy_json_path=policy,
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
        audit = _FakeAudit()

        hooks.pre_api_request(
            policy_json_path=policy,
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
        audit = _FakeAudit()

        with pytest.raises(MordredPathBringupFailed):
            hooks.pre_api_request(
                policy_json_path=policy,
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
        audit = _FakeAudit()

        hooks.pre_api_request(
            policy_json_path=policy,
            provider="bedrock",
            audit=audit,
        )

        assert rt.stop_called is False
        assert self._transport_entries(audit) == []

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
        audit = _FakeAudit()

        def _boom(**_kwargs: Any) -> Any:
            raise RuntimeError("synthetic request gate failure")

        monkeypatch.setattr(hooks, "evaluate", _boom)
        with pytest.raises(MordredPathBringupFailed) as excinfo:
            hooks.pre_api_request(
                policy_json_path=policy,
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


class TestPolicyReadFailClosed:
    """M1 (security review 2026-06-11): a policy.json that EXISTS but cannot
    be read or parsed must fail CLOSED (read as strict), not fall open to
    "off" — corrupting the policy file must not disable strict enforcement.
    A genuinely absent file still reads as "off" (fresh install).
    """

    def _dropped_runtime(self) -> None:
        from mordred_hermes.network import api

        rt = _FakeRuntime()
        rt.dropped = True
        api.set_runtime(rt)

    def test_corrupt_json_dropped_refuses(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.write_text("{not json", encoding="utf-8")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(tool_name="web_fetch", policy_json_path=policy, audit=_FakeAudit())

    def test_unreadable_policy_path_dropped_refuses(self, tmp_path: Path) -> None:
        """A directory at the policy path raises OSError on open()."""
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.mkdir()
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(tool_name="web_fetch", policy_json_path=policy, audit=_FakeAudit())

    def test_non_dict_root_dropped_refuses(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.write_text('["strict"]', encoding="utf-8")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(tool_name="web_fetch", policy_json_path=policy, audit=_FakeAudit())

    def test_invalid_mode_value_dropped_refuses(self, tmp_path: Path) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        policy.write_text('{"policy": "bogus"}', encoding="utf-8")
        with pytest.raises(MordredPathDropped):
            hooks.pre_tool_call(tool_name="web_fetch", policy_json_path=policy, audit=_FakeAudit())

    def test_missing_file_still_defaults_off(self, tmp_path: Path) -> None:
        """Fresh install: no policy.json at all keeps the historical "off"."""
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=tmp_path / "nope.json",
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
        result = hooks.pre_tool_call(
            tool_name="web_fetch",
            policy_json_path=policy,
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
