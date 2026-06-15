"""``hermes mordred plugins list`` -- Mordred plugin discovery surface.

Hermes 0.11 silently drops ``ctx.register_cli_command`` from its argparse
build (only ``plugins.memory.discover_plugin_cli_commands`` is consulted);
that leaves users with no built-in way to confirm which Mordred plugins
loaded. This module is the workaround -- a direct ``PluginManager`` query
restricted to keys starting with ``mordred_``.

A YAML fallback reads ``~/.hermes/config.yaml`` ``plugins.enabled`` when
the ``hermes_cli.plugins`` module is unavailable (older / vendored Hermes
or test environments).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Protocol, cast

from ..__about__ import __version__ as _PACKAGE_VERSION
from .._home import HERMES_BASE

DEFAULT_CONFIG_PATH = HERMES_BASE / "config.yaml"

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "cli_handler",
    "run",
]


class _ManagerLike(Protocol):
    """Minimal surface we depend on -- keeps tests free of hermes_cli."""

    def discover_and_load(self, force: bool = False) -> None: ...
    def list_plugins(self) -> list[dict[str, Any]]: ...


def _get_manager() -> _ManagerLike:
    """Return the Hermes PluginManager singleton.

    Raises :class:`ImportError` (re-raised by callers as the fallback
    trigger) when ``hermes_cli.plugins`` is not installed.
    """
    from hermes_cli.plugins import get_plugin_manager

    return cast(_ManagerLike, get_plugin_manager())


def _print_from_manager(mgr: _ManagerLike) -> int:
    mgr.discover_and_load()
    plugins = [p for p in mgr.list_plugins() if str(p.get("key", "")).startswith("mordred_")]
    if not plugins:
        print("No Mordred plugins discovered.")
        return 0
    for p in plugins:
        enabled = "enabled" if p.get("enabled") else "disabled"
        # Hermes' entry-point discovery leaves `version` empty (it never reads
        # the plugin.yaml for pip/entry-point plugins), so backfill with the
        # mordred-hermes package version — every Mordred plugin ships from it.
        version = p.get("version") or _PACKAGE_VERSION
        print(f"{p['key']:30s}  {version:10s}  {enabled}")
    return 0


def _print_from_yaml_fallback(config_path: Path) -> int:
    """Read ``plugins.enabled`` from config.yaml when PluginManager is absent."""
    print(f"(fallback: hermes_cli.plugins unavailable; reading {config_path})")
    if not config_path.exists():
        print("No Mordred plugins discovered (no config.yaml).")
        return 0
    try:
        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except Exception as e:
        print(f"Failed to read {config_path}: {e}", file=sys.stderr)
        return 0
    if not isinstance(data, dict):
        print("No Mordred plugins discovered.")
        return 0
    plugins_section = data.get("plugins")
    if not isinstance(plugins_section, dict):
        print("No Mordred plugins discovered.")
        return 0
    enabled = plugins_section.get("enabled")
    if not isinstance(enabled, list):
        print("No Mordred plugins discovered.")
        return 0
    mordred = [name for name in enabled if isinstance(name, str) and name.startswith("mordred_")]
    if not mordred:
        print("No Mordred plugins discovered.")
        return 0
    for name in mordred:
        print(f"{name:30s}  {_PACKAGE_VERSION:10s}  enabled")
    return 0


def run(*, config_path: Path = DEFAULT_CONFIG_PATH) -> int:
    """Print discovered Mordred plugins to stdout. Returns CLI exit code."""
    try:
        mgr = _get_manager()
    except ImportError:
        return _print_from_yaml_fallback(config_path)
    return _print_from_manager(mgr)


def cli_handler(args: argparse.Namespace) -> int:
    return run()
