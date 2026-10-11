"""``hermes-mordred desktop install|uninstall`` — place the Hermes Desktop half.

Hermes loads a desktop page and its local API only from folders, not from a
pip entry point:

- the page: ``<home>/desktop-plugins/mordred/plugin.js``. Hermes Desktop's
  "disk door" for user plugins, which it loads enabled. (A page shipped as
  ``<home>/plugins/<id>/desktop/`` is copied there by the app but starts
  switched off until the user finds it under Skills & Tools → Plugins, so
  it is not used.)
- the local API: ``<home>/plugins/mordred/dashboard/``, a thin module that
  imports :mod:`.api` from the installed package.

``install`` writes both and enables ``mordred`` in ``plugins.enabled``;
:func:`ensure_page` rewrites only changed files and is called by the plugin at
every start, so any install method (installer, agent, pip) gets the page.

``mordred`` is also the name of Mordred's single entry-point plugin
(:mod:`mordred_hermes.plugin`), so one ``plugins.enabled`` entry turns on both
halves and Hermes Desktop shows them as one plugin row (its hub matches the
dashboard manifest's ``name`` to the agent plugin). The folder has no
``plugin.yaml``, so Hermes' agent-plugin scanner finds no directory plugin
there that could shadow the entry point. For the same reason ``uninstall``
removes only the folder and leaves ``plugins.enabled`` alone: dropping
``mordred`` there would turn every Mordred protection off.

On Windows the same two folders are written through the checked filesystem
primitives (:mod:`._windows_assets`): Hermes-owned parents are admitted as
trusted parents, Mordred's folders are checked private directories, nothing is
repaired, and removal deletes only the enumerated files (no recursive removal),
reporting every exact path.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

from ..wizard import _term

if TYPE_CHECKING:
    from ._windows_assets import Removal

_log = logging.getLogger(__name__)
PLUGIN_ID = "mordred"
#: Shown whenever a Windows placement refuses unsafe state; Mordred never repairs it.
WINDOWS_REMEDY = (
    "Unsafe state is never repaired: fix the ownership or ACL of that path by hand, or remove the Mordred "
    "folder there (pre-C11 Windows builds created `desktop-plugins\\mordred` and `plugins\\mordred` with "
    "inherited ACLs), then re-run `hermes-mordred desktop install`."
)
_PAGE_FILE = "desktop/plugin.js"
_API_FILES = ("dashboard/manifest.json", "dashboard/plugin_api.py")
_FILES = (_PAGE_FILE, *_API_FILES)


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _platform() -> str:
    """The platform the placement routes on (a seam; never patch ``sys.platform``)."""
    return sys.platform


def _windows() -> bool:
    return _platform() == "win32"


def _assets() -> dict[str, bytes]:
    root = resources.files("mordred_hermes.desktop").joinpath("assets")
    return {rel: root.joinpath(rel).read_bytes() for rel in _FILES}


def _quoted(path: Path) -> str:
    return f'"{path}"'


def plugin_dir(home: Path | None = None) -> Path:
    return (home or _home()) / "plugins" / PLUGIN_ID


def page_dir(home: Path | None = None) -> Path:
    return (home or _home()) / "desktop-plugins" / PLUGIN_ID


def _targets(base: Path) -> dict[str, Path]:
    targets = {rel: plugin_dir(base) / rel for rel in _API_FILES}
    targets[_PAGE_FILE] = page_dir(base) / "plugin.js"
    return targets


def ensure_page(home: Path | None = None) -> bool:
    """Write the page and API files that are missing or outdated; return whether any changed.

    Never follows a symlinked folder, and never touches ``config.yaml``. On
    Windows the checked placement refuses unsafe state instead (raising
    :class:`._windows_assets.PlacementRefused`).
    """
    base = home or _home()
    if _windows():
        from . import _windows_assets

        try:
            return _windows_assets.place(base, _assets()).changed
        except _windows_assets.PlacementRefused as exc:
            # The plugin's start hook logs only the exception type; name the exact path and remedy here.
            _log.warning("Mordred desktop page not placed: %s. %s", exc, WINDOWS_REMEDY)
            raise
    assets = resources.files("mordred_hermes.desktop").joinpath("assets")
    changed = False
    for rel, destination in _targets(base).items():
        if any(p.is_symlink() for p in (destination.parent, destination.parent.parent)):
            continue
        data = assets.joinpath(rel).read_bytes()
        try:
            if destination.read_bytes() == data:
                continue
        except OSError:
            pass
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_name(f".{destination.name}.tmp")
        tmp.write_bytes(data)
        tmp.replace(destination)
        changed = True
    # Earlier builds put the page under plugins/mordred/desktop/, which the app
    # copies out as a second, switched-off "mordred" row. Drop it.
    legacy = plugin_dir(base) / "desktop"
    if legacy.is_dir() and not legacy.is_symlink():
        shutil.rmtree(legacy)
        changed = True
    return changed


def ensure_member(home: Path | None = None, *, force: bool = False) -> bool:
    """Keep ``<home>/plugins/mordred/`` a pm workspace member (see :mod:`.member`).

    Only on pm-managed Hermes installs (Hermes Desktop, source installs), where
    each update builds a fresh environment from its recorded inputs; a plain
    ``pip install hermes-agent`` never rebuilds and needs no member. ``force``
    skips that check (``hermes-mordred desktop install --pm-member``).
    """
    from . import member

    if not force and not member.pm_managed():
        return False
    return member.ensure_member(plugin_dir(home or _home()))


def _enable(home: Path) -> None:
    """Add ``mordred`` to ``plugins.enabled`` (round-trip, locked), migrating legacy names."""
    from ..wizard.policy_writer import PolicyWriter

    writer = PolicyWriter(
        config_path=home / "config.yaml",
        policy_json_path=home / "mordred" / "policy.json",
        mordred_dir=home / "mordred",
    )
    for note in writer.migrate_plugin_identity(create_missing=True).notes():
        _term.emit_warn(note)


def _install_windows(base: Path) -> int:
    from . import _windows_assets

    try:
        placement = _windows_assets.place(base, _assets())
    except _windows_assets.PlacementRefused as exc:
        _term.emit_error(f"Mordred desktop page not installed: {exc}. {WINDOWS_REMEDY}")
        return 1
    for path in placement.written:
        print(f"Wrote {_quoted(path)}.")
    for path in placement.unchanged:
        print(f"Unchanged {_quoted(path)}.")
    for path in placement.legacy_removed:
        print(f"Removed the legacy page {_quoted(path)}.")
    for refusal in placement.legacy_refused:
        _term.emit_warn(f"legacy page folder kept: {refusal}")
    _enable(base)
    print(f"Installed the Mordred desktop page at {_quoted(page_dir(base))}.")
    print("Next: restart Hermes Desktop, then open “Mordred” in the sidebar")
    print("(or Ctrl+K → “Mordred: Set up private Telegram”).")
    return 0


def install(home: Path | None = None) -> int:
    base = home or _home()
    if _windows():
        return _install_windows(base)
    ensure_page(base)
    _enable(base)
    print(f"Installed the Mordred desktop page at {page_dir(base)}.")
    try:
        if ensure_member(base):
            print("Registered Mordred with Hermes's package manager: Hermes updates now rebuild it in.")
    except Exception as exc:  # the page works without it; say why survival is off
        _term.emit_warn(f"Could not register Mordred with Hermes's package manager ({type(exc).__name__}: {exc}).")
    print("Next: restart Hermes Desktop, then open “Mordred” in the sidebar")
    print("(or ⌘K → “Mordred: Set up private Telegram”).")
    return 0


def remove_page(home: Path | None = None) -> bool:
    """Remove the page folder; return whether one was removed.

    A symlink at the folder path is left alone (this command never writes one).
    Shared by :func:`uninstall` and ``hermes-mordred uninstall``. On Windows
    only the enumerated files are deleted and every path is reported; a
    refused folder is reported, never raised, so a caller's later steps run.
    """
    base = home or _home()
    if _windows():
        return bool(_remove_windows(base).removed)
    removed = False
    for target in (page_dir(base), plugin_dir(base)):
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
            removed = True
    return removed


def _remove_windows(base: Path) -> Removal:
    from . import _windows_assets

    removal = _windows_assets.remove(base)
    for path in removal.removed:
        print(f"Removed {_quoted(path)}.")
    for path in removal.kept:
        print(f"Kept {_quoted(path)} (no recursive removal on Windows).")
    for refusal in removal.refused:
        _term.emit_warn(f"kept, could not be checked: {refusal}; nothing there was repaired or removed.")
    return removal


def uninstall(home: Path | None = None) -> int:
    if _windows():
        removal = _remove_windows(home or _home())
        if removal.removed:
            print("Deleted the Mordred desktop page files listed above. Restart Hermes Desktop.")
        else:
            print("No Mordred desktop page file was found to delete.")
        print("The Mordred plugin itself stays enabled; turn it off with `hermes plugins disable mordred`.")
        print("To remove Mordred completely, run `hermes-mordred uninstall`.")
        return 1 if removal.refused else 0
    remove_page(home)
    print("Removed the Mordred desktop page. Restart Hermes Desktop.")
    print("The Mordred plugin itself stays enabled; turn it off with `hermes plugins disable mordred`.")
    print("To remove Mordred completely, run `hermes-mordred uninstall`.")
    return 0


def _status_windows(base: Path) -> int:
    from . import _windows_assets

    missing, refused = _windows_assets.missing(base)
    for refusal in refused:
        _term.emit_warn(f"Mordred desktop page could not be checked: {refusal}.")
    if missing or refused:
        if missing:
            _term.emit_warn(
                f"Mordred desktop page not installed (missing: {', '.join(_quoted(path) for path in missing)})."
            )
        return 1
    print(f"Mordred desktop page installed at {_quoted(page_dir(base))}.")
    return 0


def status(home: Path | None = None) -> int:
    base = home or _home()
    if _windows():
        return _status_windows(base)
    missing = [str(path) for path in _targets(base).values() if not path.is_file()]
    if missing:
        _term.emit_warn(f"Mordred desktop page not installed (missing: {', '.join(missing)}).")
        return 1
    print(f"Mordred desktop page installed at {page_dir(base)}.")
    from . import member

    recorded = member.member_status(plugin_dir(base))
    if recorded.get("present") and recorded.get("valid"):
        print(
            f"Hermes package-manager member: hermes-mordred {recorded.get('version')} "
            f"({recorded.get('source')}, extras: {', '.join(recorded.get('extras') or []) or 'none'})."
        )
    elif member.pm_managed():
        _term.emit_warn(
            "Mordred is not registered with Hermes's package manager; a Hermes update will drop it. "
            "Run `hermes-mordred desktop install`."
        )
    return 0


def cli_desktop(args: argparse.Namespace) -> int:
    command = getattr(args, "desktop_command", None)
    if command == "install":
        return install()
    if command == "uninstall":
        return uninstall()
    return status()
