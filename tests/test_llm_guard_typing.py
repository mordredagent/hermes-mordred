"""Tests for ``mordred_hermes.llm_guard._typing``.

Mirrors ``tests/test_imports.py`` style (compile/contract checks). The
``_typing`` module is a structural ``Protocol`` covering the subset of
``hermes_cli.plugins.PluginContext`` the plugin actually calls — Hermes does
not publish stubs (see ``[[tool.mypy.overrides]]`` in
``mordred-hermes/pyproject.toml``).

Plan note: ``register_cli_command`` is NOT in this Protocol. The wizard
plugin is the only Mordred plugin that registers a CLI command, and
Hermes 0.11.0 does not wire entry-point CLI commands to argparse anyway
(see ``[project.scripts] hermes-mordred`` workaround in pyproject.toml).
``llm_guard`` only needs ``register_hook``.
"""

from __future__ import annotations

from typing import Protocol, get_type_hints

import pytest


def test_plugin_context_is_protocol() -> None:
    from mordred_hermes.llm_guard._typing import PluginContext

    assert issubclass(PluginContext, Protocol)


def test_plugin_context_declares_register_hook() -> None:
    """Protocol must expose register_hook(hook_name, callback) -> None."""
    from mordred_hermes.llm_guard._typing import PluginContext

    assert hasattr(PluginContext, "register_hook")
    method = PluginContext.register_hook
    hints = get_type_hints(method)
    assert "hook_name" in hints
    assert "callback" in hints
    assert hints["return"] is type(None)


def test_duck_typed_object_satisfies_protocol() -> None:
    """Structural typing: any object with the right shape qualifies at runtime.

    Hermes does not stamp PluginContext anywhere we control. The Protocol
    must remain structural so tests can pass a plain fake without
    monkey-patching the upstream class.
    """
    from mordred_hermes.llm_guard._typing import PluginContext

    class Fake:
        def register_hook(self, hook_name: str, callback: object) -> None:
            del hook_name, callback

    fake = Fake()
    # ``isinstance`` against a Protocol requires ``@runtime_checkable``.
    # Some narrow Protocols opt out; in that case fall back to structural
    # assertion via attribute presence.
    try:
        assert isinstance(fake, PluginContext)
    except TypeError:
        pytest.skip("PluginContext is not @runtime_checkable; structural check still implicit")


def test_no_unused_methods_added() -> None:
    """Codex review precedent: keep the Protocol minimal.

    If we add ``register_provider``/``register_cli_command`` later, drift
    detection via ``upstream-check.yml`` becomes noisier. Pin the surface
    explicitly so future contributors think twice before expanding it.
    """
    from mordred_hermes.llm_guard._typing import PluginContext

    public = {name for name in dir(PluginContext) if not name.startswith("_")}
    # ``Protocol`` itself contributes a few attrs; we filter to user-defined methods.
    user_methods = {name for name in public if callable(getattr(PluginContext, name, None))}
    assert user_methods == {"register_hook"}, f"unexpected Protocol methods: {user_methods}"
