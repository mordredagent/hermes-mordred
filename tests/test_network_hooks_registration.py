"""Registration and process-route activation tests for network hooks."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.network._exceptions import (
    BringupFailed,
    MordredNetworkError,
    MordredPathBringupFailed,
)
from tests._network_hooks_helpers import (
    _FakeCtx,
    _FakeRuntime,
    _reset_api,
    _write_config,
    _write_config_with_network_fields,
    _write_policy,
)

pytestmark = pytest.mark.usefixtures(_reset_api.__name__)

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

    def test_register_allows_all_managed_proxy_vars_through_execute_code(self) -> None:
        from tools.env_passthrough import is_env_passthrough

        from mordred_hermes.network import proxy_env, register

        register(_FakeCtx())

        assert proxy_env.managed_var_names() == {
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "https_proxy",
            "http_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        }
        assert all(is_env_passthrough(name) for name in proxy_env.managed_var_names())

    def test_session_start_restores_proxy_passthrough_after_hermes_reset(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from tools.env_passthrough import clear_env_passthrough, is_env_passthrough

        import mordred_hermes.network as network
        from mordred_hermes.network import proxy_env, register

        ctx = _FakeCtx()
        register(ctx)
        clear_env_passthrough()
        assert not any(is_env_passthrough(name) for name in proxy_env.managed_var_names())
        monkeypatch.setattr(network.hooks, "on_session_start", lambda **_kwargs: None)

        ctx.hooks[1][1]()

        assert all(is_env_passthrough(name) for name in proxy_env.managed_var_names())

    def test_strict_refuses_when_proxy_passthrough_verification_fails(
        self,
        tmp_path: Path,
    ) -> None:
        import mordred_hermes.network as network
        from mordred_hermes.network.runtime import RuntimeConfig
        from mordred_hermes.privacy_check.audit import NDJSONWriter

        audit = NDJSONWriter(tmp_path / "audit.log")
        config = RuntimeConfig(policy_mode="strict", default_path="tor")

        with pytest.raises(MordredPathBringupFailed, match="execute_code child routing"):
            network._register_proxy_env_passthrough(
                config=config,
                audit=audit,
                registrar=lambda _names: None,
                checker=lambda _name: False,
            )

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
