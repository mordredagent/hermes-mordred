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

    def test_register_does_not_wire_pre_tool_call(self) -> None:
        """``pre_tool_call`` is privacy_check's responsibility, not llm_guard's."""
        from mordred_hermes.llm_guard import register

        ctx = _FakeCtx()
        register(ctx)

        names = [name for name, _ in ctx.hooks]
        assert "pre_tool_call" not in names


class TestRegisterIsIdempotent:
    def test_double_call_safe(self) -> None:
        """Defensive registration: plugin loader may call register() twice
        across reloads. Each call appends a hook; the provider registry
        slot is overwritten (last-writer-wins). No exception.
        """
        from mordred_hermes.llm_guard import register

        ctx1 = _FakeCtx()
        ctx2 = _FakeCtx()
        register(ctx1)
        register(ctx2)

        import providers

        assert providers._REGISTRY.get("mordred-local") is not None
        assert len(ctx1.hooks) == 1
        assert len(ctx2.hooks) == 1
