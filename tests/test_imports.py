"""Phase 0 acceptance test: all 5 plugins import and expose register().

Hermes loads entry-point plugins by importing the module and calling
getattr(module, 'register'). Entry points point at the module (not module:attr).
See hermes_cli/plugins.py:_load_entrypoint_module + _load_plugin.
"""

import importlib
from pathlib import Path
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
def test_plugin_imports(module_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate HERMES_HOME before calling the real register() below. On any machine
    # that has actually run `hermes-mordred keyvault init` (including this repo's
    # own maintainer's), mordred_hermes.keyvault.register() -> install_vault_env_decrypt()
    # -> inject_vault_env(root=default_vault_root()) would otherwise open the
    # operator's REAL ~/.hermes/mordred/vault and block on a Secure Enclave (Touch
    # ID) authorization — which a headless pytest run cancels, raising
    # WrapAuthCancelled: auth_failed instead of exercising the plugin contract.
    # An empty tmp_path has no Keychain anchor for its (path-derived) vault id and
    # no manifest.*.mvmf artifacts on disk, so register() takes its documented
    # no-op path (see _runtime_env.py / _identity.py). This is a no-op for the
    # other 4 plugins: their default paths are derived from
    # mordred_hermes._home.HERMES_BASE, a module-level constant frozen at first
    # import, so this env var can no longer influence them (see _home.py).
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
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


def test_hermes_plugin_manager_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: Hermes PluginManager discovers all 5 mordred plugins via entry points.

    Guards against drift between (a) our entry-point declarations in pyproject.toml
    and (b) Hermes loader expectations (`getattr(module, 'register')` on the loaded module).
    """
    pytest = __import__("pytest")
    try:
        from hermes_cli.plugins import PluginManager
    except ImportError:
        pytest.skip("hermes_cli not importable in this environment")

    # Same HERMES_HOME isolation as test_plugin_imports above, and for the same
    # reason: discover_and_load() below calls the real register() for every
    # discovered entry point, including mordred_hermes.keyvault's, which would
    # otherwise reach for the operator's real ~/.hermes vault and hang on a Touch
    # ID prompt on any machine with a live vault enrolled.
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

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
