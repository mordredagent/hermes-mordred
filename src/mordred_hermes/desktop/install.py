"""``hermes-mordred desktop install|uninstall`` — place the Hermes Desktop half.

Hermes loads a desktop page and its local API only from a plugin *folder*
(``<home>/plugins/<id>/{desktop,dashboard}``), not from a pip entry point.
This writes a thin folder whose API module imports :mod:`.api` from the
installed package, and enables ``mordred`` in ``plugins.enabled``. The folder
has no ``plugin.yaml``, so Hermes' agent-plugin scanner skips it and the
entry-point plugins are not duplicated.
"""

from __future__ import annotations

import argparse
import io
import shutil
from importlib import resources
from pathlib import Path

from ..wizard import _term

PLUGIN_ID = "mordred"
_FILES = ("desktop/plugin.js", "dashboard/manifest.json", "dashboard/plugin_api.py")


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def plugin_dir(home: Path | None = None) -> Path:
    return (home or _home()) / "plugins" / PLUGIN_ID


def _set_enabled(config: Path, enabled: bool) -> None:
    """Add/remove ``mordred`` in ``plugins.enabled`` only (round-trip, locked)."""
    from ..wizard.policy_writer import _atomic_write_text, _policy_write_lock, _read_regular_text, _round_trip_yaml

    with _policy_write_lock(config.parent):
        yaml = _round_trip_yaml()
        text = _read_regular_text(config)
        root = yaml.load(text) if text else None
        if root is None:
            root = {}
        plugins = root.setdefault("plugins", {})
        names = plugins.get("enabled")
        if not isinstance(names, list):
            names = []
            plugins["enabled"] = names
        if enabled and PLUGIN_ID not in names:
            names.append(PLUGIN_ID)
        if not enabled and PLUGIN_ID in names:
            names.remove(PLUGIN_ID)
        buffer = io.StringIO()
        yaml.dump(root, buffer)
        _atomic_write_text(config, buffer.getvalue())


def install(home: Path | None = None) -> int:
    base = home or _home()
    target = plugin_dir(base)
    assets = resources.files("mordred_hermes.desktop").joinpath("assets")
    for rel in _FILES:
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(assets.joinpath(rel).read_bytes())
    _set_enabled(base / "config.yaml", True)
    print(f"Installed the Mordred desktop page at {target}.")
    print("Next: restart Hermes Desktop, turn Mordred on in Capabilities → Plugins (Desktop),")
    print("then open “Mordred” in the sidebar (or ⌘K → “Mordred: Set up private Telegram”).")
    return 0


def uninstall(home: Path | None = None) -> int:
    base = home or _home()
    target = plugin_dir(base)
    if target.is_dir() and not target.is_symlink():
        shutil.rmtree(target)
    _set_enabled(base / "config.yaml", False)
    print("Removed the Mordred desktop page. Restart Hermes Desktop.")
    return 0


def status(home: Path | None = None) -> int:
    target = plugin_dir(home)
    missing = [rel for rel in _FILES if not (target / rel).is_file()]
    if missing:
        _term.emit_warn(f"Mordred desktop page not installed (missing: {', '.join(missing)}).")
        return 1
    print(f"Mordred desktop page installed at {target}.")
    return 0


def cli_desktop(args: argparse.Namespace) -> int:
    command = getattr(args, "desktop_command", None)
    if command == "install":
        return install()
    if command == "uninstall":
        return uninstall()
    return status()
