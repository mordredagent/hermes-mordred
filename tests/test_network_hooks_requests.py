"""API-request and tool-call enforcement tests for network hooks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    BringupFailed,
    MordredPathBringupFailed,
    MordredPathDropped,
)
from tests._network_hooks_helpers import (
    _FakeAudit,
    _FakeRuntime,
    _reset_api,
    _write_config,
    _write_config_with_network_fields,
    _write_config_with_provider,
    _write_policy,
)

pytestmark = pytest.mark.usefixtures(_reset_api.__name__)

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

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("{not json", id="corrupt_json"),
            # A directory at the policy path raises OSError on open().
            pytest.param(None, id="unreadable_policy_path"),
            pytest.param('["strict"]', id="non_dict_root"),
            pytest.param('{"policy": "bogus"}', id="invalid_mode_value"),
        ],
    )
    def test_policy_read_failure_dropped_refuses(self, tmp_path: Path, content: str | None) -> None:
        from mordred_hermes.network import hooks

        self._dropped_runtime()
        policy = tmp_path / "policy.json"
        if content is None:
            policy.mkdir()
        else:
            policy.write_text(content, encoding="utf-8")
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
