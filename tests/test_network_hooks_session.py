"""Session lifecycle and provider-transport tests for network hooks."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    BringupFailed,
    MordredPathBringupFailed,
    PathSwitchRequiresRestart,
)
from tests._network_hooks_helpers import (
    _FakeAudit,
    _FakeRuntime,
    _reset_api,
    _write_config,
    _write_config_with_provider,
    _write_policy,
)

pytestmark = pytest.mark.usefixtures(_reset_api.__name__)

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
