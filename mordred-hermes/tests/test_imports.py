"""Phase 0 acceptance test: all 5 plugins import and expose register().

Hermes loads entry-point plugins by importing the module and calling
getattr(module, 'register'). Entry points point at the module (not module:attr).
See hermes_cli/plugins.py:_load_entrypoint_module + _load_plugin.
"""

import importlib
from types import ModuleType

import pytest

PLUGINS = [
    "mordred_hermes.privacy_check",
    "mordred_hermes.wizard",
    "mordred_hermes.llm_guard",
    "mordred_hermes.network",
    "mordred_hermes.keyvault",
]


class _FakeContext:
    """Captures register_hook calls so plugins-with-hooks (Phase 1+) can be tested
    alongside Phase 0 stubs without spinning up a real Hermes session."""

    def __init__(self) -> None:
        self.hooks: list[tuple[str, object]] = []

    def register_hook(self, hook_name: str, callback: object) -> None:
        self.hooks.append((hook_name, callback))

    def register_cli_command(self, *args: object, **kwargs: object) -> None:
        return None

    def register_provider(self, *args: object, **kwargs: object) -> None:
        return None


@pytest.mark.parametrize("module_path", PLUGINS)
def test_plugin_imports(module_path: str) -> None:
    module = importlib.import_module(module_path)
    register = getattr(module, "register", None)
    assert callable(register), f"{module_path}.register must be callable"
    # Phase 0 stubs ignore ctx; Phase 1+ call ctx.register_hook(...).
    assert register(_FakeContext()) is None


def test_entry_points_resolve() -> None:
    """Each entry point in pyproject.toml resolves to a module with register()."""
    from importlib.metadata import entry_points

    eps = entry_points(group="hermes_agent.plugins")
    mordred_eps = {ep.name: ep for ep in eps if ep.name.startswith("mordred_")}
    expected = {
        "mordred_network",
        "mordred_privacy_check",
        "mordred_llm_guard",
        "mordred_keyvault",
        "mordred_wizard",
    }
    assert set(mordred_eps.keys()) == expected, f"missing entry points: {expected - set(mordred_eps.keys())}"
    for name, ep in mordred_eps.items():
        loaded = ep.load()
        assert isinstance(loaded, ModuleType), f"entry point {name} must load to a module (got {type(loaded).__name__})"
        register = getattr(loaded, "register", None)
        assert callable(register), f"entry point {name} module must expose callable register()"


def test_hermes_plugin_manager_discovery() -> None:
    """End-to-end: Hermes PluginManager discovers all 5 mordred plugins via entry points.

    Guards against drift between (a) our entry-point declarations in pyproject.toml
    and (b) Hermes loader expectations (`getattr(module, 'register')` on the loaded module).
    """
    pytest = __import__("pytest")
    try:
        from hermes_cli.plugins import PluginManager
    except ImportError:
        pytest.skip("hermes_cli not importable in this environment")

    mgr = PluginManager()
    mgr.discover_and_load(force=True)
    mordred = {k: p for k, p in mgr._plugins.items() if p.manifest.source == "entrypoint" and k.startswith("mordred_")}
    expected = {
        "mordred_network",
        "mordred_privacy_check",
        "mordred_llm_guard",
        "mordred_keyvault",
        "mordred_wizard",
    }
    assert set(mordred.keys()) == expected, f"missing: {expected - set(mordred.keys())}"
    for k, p in mordred.items():
        if p.error and "not enabled in config" not in p.error:
            raise AssertionError(f"{k} failed to load: {p.error}")
