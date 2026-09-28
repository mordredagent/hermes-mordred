"""``hermes-mordred desktop install|uninstall`` — place the Hermes Desktop half.

Hermes loads a desktop page and its local API only from a plugin *folder*
(``<home>/plugins/<id>/{desktop,dashboard}``), not from a pip entry point.
This writes a thin folder whose API module imports :mod:`.api` from the
installed package, and enables ``mordred`` in ``plugins.enabled``.

``mordred`` is also the name of Mordred's single entry-point plugin
(:mod:`mordred_hermes.plugin`), so one ``plugins.enabled`` entry turns on both
halves and Hermes Desktop shows them as one plugin row (its hub matches the
dashboard manifest's ``name`` to the agent plugin). The folder has no
``plugin.yaml``, so Hermes' agent-plugin scanner finds no directory plugin
there that could shadow the entry point. For the same reason ``uninstall``
removes only the folder and leaves ``plugins.enabled`` alone: dropping
``mordred`` there would turn every Mordred protection off.
"""

from __future__ import annotations

import argparse
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


def _enable(home: Path) -> None:
    """Add ``mordred`` to ``plugins.enabled`` (round-trip, locked), migrating legacy names."""
    from ..wizard.policy_writer import PolicyWriter

    writer = PolicyWriter(config_path=home / "config.yaml", policy_json_path=home / "mordred" / "policy.json")
    for note in writer.migrate_plugin_identity(create_missing=True).notes():
        _term.emit_warn(note)


def install(home: Path | None = None) -> int:
    base = home or _home()
    target = plugin_dir(base)
    assets = resources.files("mordred_hermes.desktop").joinpath("assets")
    for rel in _FILES:
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(assets.joinpath(rel).read_bytes())
    _enable(base)
    print(f"Installed the Mordred desktop page at {target}.")
    print("Next: restart Hermes Desktop, then open “Mordred” in the sidebar")
    print("(or ⌘K → “Mordred: Set up private Telegram”).")
    return 0


def remove_page(home: Path | None = None) -> bool:
    """Remove the page folder; return whether one was removed.

    A symlink at the folder path is left alone (this command never writes one).
    Shared by :func:`uninstall` and ``hermes-mordred uninstall``.
    """
    target = plugin_dir(home or _home())
    if target.is_dir() and not target.is_symlink():
        shutil.rmtree(target)
        return True
    return False


def uninstall(home: Path | None = None) -> int:
    remove_page(home)
    print("Removed the Mordred desktop page. Restart Hermes Desktop.")
    print("The Mordred plugin itself stays enabled; turn it off with `hermes plugins disable mordred`.")
    print("To remove Mordred completely, run `hermes-mordred uninstall`.")
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
