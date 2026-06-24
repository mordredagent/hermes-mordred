"""Tests for ``mordred_hermes.llm_guard.register``.

PR1 plugin wiring:

- ``providers.register_provider(MordredLocalProfile(...))`` happens
  explicitly inside :func:`register` (Codex B1 — no module-import side
  effect).
- ``on_session_start`` hook is registered. The handler runs the harness
  detection at session start; in PR1 it does NOT run enforce (that lands
  in PR2).

Hook *order* matters even within a single ``on_session_start`` slot
(HOOK_PAYLOADS.md §1: callbacks fire in registration order). PR2 will
register the enforce handler AFTER harness — verified by a dedicated
test on the recorded order.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest


class _FakeCtx:
    """Records ``register_hook`` calls so tests can assert wiring."""

    def __init__(self) -> None:
        self.hooks: list[tuple[str, Callable[..., Any]]] = []

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
        self.hooks.append((hook_name, callback))


@pytest.fixture(autouse=True)
def _isolate_provider_registry() -> Any:
    """Don't leak ``mordred-local`` between tests."""
    import providers

    providers._REGISTRY.pop("mordred-local", None)
    providers._ALIASES.pop("mordred-local", None)
    yield
    providers._REGISTRY.pop("mordred-local", None)
    providers._ALIASES.pop("mordred-local", None)


class TestRegisterEntryPoint:
    def test_register_is_callable(self) -> None:
        from mordred_hermes.llm_guard import register

        assert callable(register)

    def test_register_places_mordred_local_in_provider_registry(self) -> None:
        from mordred_hermes.llm_guard import register

        ctx = _FakeCtx()
        register(ctx)

        import providers

        profile = providers._REGISTRY.get("mordred-local")
        assert profile is not None
        assert profile.name == "mordred-local"

    def test_register_wires_on_session_start_hook(self) -> None:
        from mordred_hermes.llm_guard import register

        ctx = _FakeCtx()
        register(ctx)

        names = [name for name, _ in ctx.hooks]
        assert "on_session_start" in names

    def test_register_wires_both_session_start_callbacks_in_order(self) -> None:
        """PR2: ``harness_detect`` is registered FIRST, then ``enforce``.

        HOOK_PAYLOADS.md §1: callbacks fire in registration order. The
        harness refusal must short-circuit before enforce so a harness
        primary aborts the session even when the active provider would
        otherwise pass enforce's allowlist check.
        """
        from mordred_hermes.llm_guard import (
            _on_session_start_enforce,
            _on_session_start_harness,
            register,
        )

        ctx = _FakeCtx()
        register(ctx)

        session_start_callbacks = [cb for name, cb in ctx.hooks if name == "on_session_start"]
        assert len(session_start_callbacks) == 2, "PR2 wires two on_session_start callbacks"
        assert session_start_callbacks[0] is _on_session_start_harness
        assert session_start_callbacks[1] is _on_session_start_enforce

    def test_register_does_not_wire_pre_llm_call(self) -> None:
        """PR1 does NOT touch ``pre_llm_call``.

        HOOK_PAYLOADS.md §5 confirms ``pre_llm_call`` is context-injection
        only in v0.11.0; provider override is structurally impossible.
        PR2 will add ``on_session_start`` enforce; this test guards against
        accidentally re-introducing the stale per-turn override design.
        """
        from mordred_hermes.llm_guard import register

        ctx = _FakeCtx()
        register(ctx)

        names = [name for name, _ in ctx.hooks]
        assert "pre_llm_call" not in names

    def test_register_wires_pre_api_request_enforce(self) -> None:
        """Codex review P1 round 3: ``on_session_start`` only has access to
        disk-based provider state, so runtime overrides
        (``hermes --provider …``, ``HERMES_INFERENCE_PROVIDER``, oneshot /
        gateway model switches) would bypass strict-mode enforcement
        otherwise.

        ``pre_api_request`` is the only hook whose payload includes the
        actually-resolved runtime ``provider`` kwarg (verified at
        ``run_agent.py:11327``). Registering an enforce callback there
        makes strict-mode policy authoritative against the live request,
        not just the persisted files.
        """
        from mordred_hermes.llm_guard import _on_pre_api_request_enforce, register

        ctx = _FakeCtx()
        register(ctx)

        pre_api_callbacks = [cb for name, cb in ctx.hooks if name == "pre_api_request"]
        assert len(pre_api_callbacks) == 1
        assert pre_api_callbacks[0] is _on_pre_api_request_enforce

    def test_register_does_not_wire_pre_tool_call(self) -> None:
        """``pre_tool_call`` is privacy_check's responsibility, not llm_guard's."""
        from mordred_hermes.llm_guard import register

        ctx = _FakeCtx()
        register(ctx)

        names = [name for name, _ in ctx.hooks]
        assert "pre_tool_call" not in names


class TestSessionStartEnforceIsAuditOnly:
    """Codex review P2 round 4: ``on_session_start`` only sees disk-based
    provider state, so a session that would refuse based on disk could be
    valid under a runtime override (``hermes --provider …``,
    ``HERMES_INFERENCE_PROVIDER``, oneshot / gateway switches).

    To avoid false-positive refusals before the runtime is known,
    ``_on_session_start_enforce`` swallows the strict-mode refusal
    exceptions (``MordredSessionRefused`` /
    ``MordredLocalUnreachable``). Audit entries are still written by
    :func:`enforce.check_session_provider` before the raise, so observers
    see the disk-based pre-check signal. Authoritative refusal happens
    later at ``pre_api_request`` where the actual runtime provider is
    known.
    """

    def test_swallows_session_refused_from_disk_state(self, tmp_path: object, monkeypatch: object) -> None:
        import json
        from pathlib import Path

        import mordred_hermes.llm_guard as guard
        from mordred_hermes.llm_guard import _on_session_start_enforce

        tmp = Path(str(tmp_path))
        policy = tmp / "policy.json"
        # Strict mode + disk says cloud provider that's NOT in allowlist.
        policy.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": True,
                    "cloud_provider_allowlist": ["anthropic"],
                }
            ),
            encoding="utf-8",
        )
        config_yaml = tmp / "config.yaml"
        config_yaml.write_text("model:\n  provider: openai\n", encoding="utf-8")
        auth_json = tmp / "auth.json"
        audit_log = tmp / "audit.log"

        from typing import Any, cast

        mp = cast(Any, monkeypatch)
        mp.setattr(guard, "DEFAULT_POLICY_JSON_PATH", policy)
        mp.setattr(guard, "DEFAULT_CONFIG_PATH", config_yaml)
        mp.setattr(guard, "DEFAULT_AUTH_JSON_PATH", auth_json)
        mp.setattr(guard, "DEFAULT_AUDIT_PATH", audit_log)
        # Bypass the lru_cache so the test's audit path is honored.
        guard._build_audit_writer.cache_clear()

        # MUST NOT raise — disk says cloud-refused, but runtime override
        # may be coming via pre_api_request.
        _on_session_start_enforce()

        # Audit was still emitted so observers can correlate the signal.
        assert audit_log.exists()
        lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
        assert any("policy.strict.session_refused" in ln for ln in lines)

    def test_swallows_local_unreachable_from_disk_state(self, tmp_path: object, monkeypatch: object) -> None:
        import json
        from pathlib import Path

        import mordred_hermes.llm_guard as guard
        from mordred_hermes.llm_guard import _on_session_start_enforce

        tmp = Path(str(tmp_path))
        policy = tmp / "policy.json"
        # Disk says mordred-local with unreachable endpoint.
        policy.write_text(
            json.dumps(
                {
                    "policy": "strict",
                    "allow_cloud_llm": False,
                    "cloud_provider_allowlist": [],
                    "local_llm_endpoint": "http://127.0.0.1:1/v1",
                }
            ),
            encoding="utf-8",
        )
        config_yaml = tmp / "config.yaml"
        config_yaml.write_text("model:\n  provider: mordred-local\n", encoding="utf-8")
        auth_json = tmp / "auth.json"
        audit_log = tmp / "audit.log"

        from typing import Any, cast

        mp = cast(Any, monkeypatch)
        mp.setattr(guard, "DEFAULT_POLICY_JSON_PATH", policy)
        mp.setattr(guard, "DEFAULT_CONFIG_PATH", config_yaml)
        mp.setattr(guard, "DEFAULT_AUTH_JSON_PATH", auth_json)
        mp.setattr(guard, "DEFAULT_AUDIT_PATH", audit_log)
        guard._build_audit_writer.cache_clear()

        # MUST NOT raise — local probe failure at session_start is
        # advisory now; pre_api_request will re-probe if runtime is local.
        _on_session_start_enforce()


class TestResolveActiveProvider:
    """``_resolve_active_provider`` must mirror Hermes' runtime resolution
    (``hermes_cli/runtime_provider.py::resolve_requested_provider``):

    1. ``config.yaml model.provider`` (when non-empty and not ``"auto"``)
    2. ``auth.json active_provider`` (fallback for ``"auto"`` / missing)
    3. ``None`` when neither yields a usable identifier.

    Codex review P1: the previous order checked auth.json FIRST, which can
    drive enforce against a stale auth value while Hermes actually runs a
    different ``model.provider`` from config.yaml.
    """

    def _write_auth(self, path: object, active: str | None) -> None:
        import json
        from pathlib import Path

        p = Path(str(path))
        body = {"active_provider": active} if active is not None else {}
        p.write_text(json.dumps(body), encoding="utf-8")

    def _write_config(self, path: object, provider: str | None) -> None:
        from pathlib import Path

        p = Path(str(path))
        if provider is None:
            p.write_text("model: {}\n", encoding="utf-8")
        else:
            p.write_text(f"model:\n  provider: {provider}\n", encoding="utf-8")

    def test_config_yaml_wins_over_auth_json(self, tmp_path: object) -> None:
        """Stale auth.json must NOT override a concrete model.provider."""
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"
        cfg = Path(str(tmp_path)) / "config.yaml"
        self._write_auth(auth, "mordred-local")  # stale
        self._write_config(cfg, "openai")  # what Hermes actually runs

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) == "openai"

    def test_config_auto_falls_back_to_auth_json(self, tmp_path: object) -> None:
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"
        cfg = Path(str(tmp_path)) / "config.yaml"
        self._write_auth(auth, "anthropic")
        self._write_config(cfg, "auto")

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) == "anthropic"

    def test_config_missing_falls_back_to_auth_json(self, tmp_path: object) -> None:
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"
        cfg = Path(str(tmp_path)) / "config.yaml"  # never created
        self._write_auth(auth, "anthropic")

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) == "anthropic"

    def test_both_missing_returns_none(self, tmp_path: object) -> None:
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"  # absent
        cfg = Path(str(tmp_path)) / "config.yaml"  # absent

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) is None

    def test_empty_string_in_config_falls_through(self, tmp_path: object) -> None:
        """``model.provider: ""`` is unusable — fall back to auth.json."""
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"
        cfg = Path(str(tmp_path)) / "config.yaml"
        self._write_auth(auth, "anthropic")
        cfg.write_text('model:\n  provider: ""\n', encoding="utf-8")

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) == "anthropic"

    def test_config_alias_resolves_to_canonical(self, tmp_path: object) -> None:
        """``model.provider: claude`` must resolve to canonical ``anthropic`` so
        the strict gate / flagger key off the registry slug, not the alias."""
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"
        cfg = Path(str(tmp_path)) / "config.yaml"
        self._write_config(cfg, "claude")

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) == "anthropic"

    def test_auth_alias_resolves_to_canonical(self, tmp_path: object) -> None:
        """An aliased ``auth.json active_provider`` (``google``) resolves to ``gemini``."""
        from pathlib import Path

        from mordred_hermes.llm_guard import _resolve_active_provider

        auth = Path(str(tmp_path)) / "auth.json"
        cfg = Path(str(tmp_path)) / "config.yaml"
        self._write_auth(auth, "google")
        self._write_config(cfg, "auto")  # force the auth.json fallback path

        assert _resolve_active_provider(auth_json_path=auth, config_path=cfg) == "gemini"


class TestRegisterIsIdempotent:
    def test_double_call_safe(self) -> None:
        """Defensive registration: plugin loader may call register() twice
        across reloads. Each call appends hooks; the provider registry
        slot is overwritten (last-writer-wins). No exception.

        PR2: each ``register()`` call wires 2 callbacks
        (harness_detect + enforce) on ``on_session_start``.
        """
        from mordred_hermes.llm_guard import register

        ctx1 = _FakeCtx()
        ctx2 = _FakeCtx()
        register(ctx1)
        register(ctx2)

        import providers

        assert providers._REGISTRY.get("mordred-local") is not None
        # 2 on_session_start (harness + enforce) + 1 pre_api_request = 3
        assert len(ctx1.hooks) == 3
        assert len(ctx2.hooks) == 3
