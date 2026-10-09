"""Hermes Desktop page placement and removal on Windows (C11), portable.

The Windows branch of ``desktop.install`` runs on any host: ``install._platform``
says ``win32`` and the real descriptor-relative ``_private_fs`` backend stands
beneath the same calls. Only the two Windows-only openers are host stand-ins:
the optional private opener (absence only for a missing final directory below an
existing parent) and the Hermes-owned shared-parent admission (created only when
missing). A frame-filtered spy proves that no ``mordred_hermes.desktop`` frame
performs raw profile I/O (no ``mkdir``/``write``/``replace``/``unlink``/``rmtree``).
Paths contain spaces and non-ASCII characters.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import os
import shutil
import stat
import sys
from collections.abc import Iterator
from importlib import resources
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mordred_hermes._private_fs import PrivateDirectory, open_private_directory
from mordred_hermes.desktop import install

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX stand-in for the private DACL; see tests/test_desktop_windows_native.py"
)

ASSETS = resources.files("mordred_hermes.desktop").joinpath("assets")


def asset(rel: str) -> bytes:
    return ASSETS.joinpath(rel).read_bytes()


def windows_assets():
    from mordred_hermes.desktop import _windows_assets

    return _windows_assets


@contextlib.contextmanager
def host_optional_private(path: str | Path) -> Iterator[PrivateDirectory | None]:
    raw = os.fspath(path)
    if not os.path.lexists(raw) and os.path.isdir(os.path.dirname(raw)):
        yield None
        return
    with open_private_directory(raw) as directory:
        yield directory


def host_admit_shared(path: Path) -> None:
    if not os.path.lexists(path):
        os.mkdir(path, 0o700)


class RawIOSpy:
    """Record raw filesystem calls made directly by a ``mordred_hermes.desktop`` frame under ``home``."""

    _PATH_METHODS = ("mkdir", "write_bytes", "write_text", "replace", "rename", "unlink", "rmdir", "touch", "open")
    _PATH_READS = ("read_bytes", "read_text", "is_file", "is_dir", "exists", "is_symlink", "iterdir", "stat")
    _OS = ("mkdir", "makedirs", "replace", "rename", "remove", "unlink", "rmdir", "open")

    def __init__(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        self.home = os.fspath(home)
        self.calls: list[tuple[str, str]] = []
        for name in self._PATH_METHODS + self._PATH_READS:
            monkeypatch.setattr(Path, name, self._wrap(f"Path.{name}", getattr(Path, name)))
        for name in self._OS:
            monkeypatch.setattr(os, name, self._wrap(f"os.{name}", getattr(os, name)))
        monkeypatch.setattr(shutil, "rmtree", self._wrap("shutil.rmtree", shutil.rmtree))
        monkeypatch.setattr(builtins, "open", self._wrap("open", builtins.open))
        monkeypatch.setattr(io, "open", self._wrap("io.open", io.open))

    def _wrap(self, label: str, original: Any) -> Any:
        spy = self

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            module = sys._getframe(1).f_globals.get("__name__", "")
            target = os.fspath(args[0]) if args and isinstance(args[0], (str, os.PathLike)) else ""
            if module.startswith("mordred_hermes.desktop") and target.startswith(spy.home):
                spy.calls.append((label, module))
            return original(*args, **kwargs)

        return wrapper


@pytest.fixture
def windows_install(monkeypatch, tmp_path):
    home = tmp_path / "Hermes Hömé dir"
    home.mkdir()
    monkeypatch.setattr(install, "_platform", lambda: "win32", raising=False)
    monkeypatch.setattr(install, "_home", lambda: home)
    try:
        module = windows_assets()
    except ImportError:
        module = None
    if module is not None:
        monkeypatch.setattr(module, "_optional_private", host_optional_private)
        monkeypatch.setattr(module, "_admit_shared", host_admit_shared)
    return SimpleNamespace(home=home, spy=RawIOSpy(monkeypatch, home))


def page(home: Path) -> Path:
    return home / "desktop-plugins" / "mordred" / "plugin.js"


def dashboard(home: Path) -> Path:
    return home / "plugins" / "mordred" / "dashboard"


def put(directory: Path, name: str, data: bytes) -> None:
    with open_private_directory(directory, create=True) as checked, checked.transaction() as tx:
        tx.create_bytes(name, data)


def test_windows_install_places_assets_through_checked_primitives(windows_install, capsys):
    home = windows_install.home
    assert install.install(home) == 0
    out = capsys.readouterr().out

    assert page(home).read_bytes() == asset("desktop/plugin.js")
    assert (dashboard(home) / "manifest.json").read_bytes() == asset("dashboard/manifest.json")
    assert (dashboard(home) / "plugin_api.py").read_bytes() == asset("dashboard/plugin_api.py")
    assert not (home / "plugins" / "mordred" / "plugin.yaml").exists()
    for written in (page(home), dashboard(home) / "manifest.json", dashboard(home) / "plugin_api.py"):
        assert f'"{written}"' in out, "every written path is reported exactly, quoted"
    for directory in (page(home).parent, home / "plugins" / "mordred", dashboard(home)):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700, "Mordred folders are checked private directories"
    assert "- mordred\n" in (home / "config.yaml").read_text()
    assert windows_install.spy.calls == []

    assert install.ensure_page(home) is False, "nothing changed, nothing rewritten"
    assert install.status(home) == 0
    assert windows_install.spy.calls == []


def test_windows_ensure_page_rewrites_only_a_changed_file(windows_install):
    home = windows_install.home
    assert install.ensure_page(home) is True
    manifest = dashboard(home) / "manifest.json"
    identity = manifest.stat().st_ino
    with open_private_directory(page(home).parent) as checked, checked.transaction() as tx:
        tx.replace_bytes("plugin.js", b"// stale page")
    assert install.ensure_page(home) is True
    assert page(home).read_bytes() == asset("desktop/plugin.js")
    assert manifest.stat().st_ino == identity, "an unchanged file is not republished"
    assert windows_install.spy.calls == []


def test_windows_removal_deletes_only_the_enumerated_files(windows_install, capsys):
    home = windows_install.home
    assert install.install(home) == 0
    put(page(home).parent, "notes.txt", b"user file")
    capsys.readouterr()

    assert install.uninstall(home) == 0
    out = capsys.readouterr().out

    removed = [page(home), dashboard(home) / "manifest.json", dashboard(home) / "plugin_api.py"]
    for path in removed:
        assert not path.exists()
        assert f'Removed "{path}"' in out
    assert (page(home).parent / "notes.txt").read_bytes() == b"user file", "unknown files are kept"
    assert f'Kept "{page(home).parent / "notes.txt"}"' in out
    for directory in (page(home).parent, dashboard(home), home / "plugins" / "mordred"):
        assert directory.is_dir(), "no directory is removed (no recursive removal)"
        assert f'Kept "{directory}"' in out
    assert "- mordred\n" in (home / "config.yaml").read_text(), "the plugin stays enabled"
    assert windows_install.spy.calls == []

    assert install.uninstall(home) == 0, "a second removal finds nothing and changes nothing"
    assert "Removed" not in capsys.readouterr().out
    assert install.status(home) == 1


def test_windows_install_refuses_unsafe_state_without_repair(windows_install, capsys):
    home = windows_install.home
    unsafe = page(home).parent
    unsafe.mkdir(parents=True)
    os.chmod(unsafe, 0o755)  # broad: the POSIX stand-in for an inherited/broadened Windows DACL

    assert install.install(home) == 1
    err = capsys.readouterr().err
    assert f'"{unsafe}"' in err and "(unsafe)" in err and "never repaired" in err
    assert stat.S_IMODE(unsafe.stat().st_mode) == 0o755, "no permission repair"
    assert not page(home).exists()
    assert not (home / "config.yaml").exists(), "a refused placement does not enable the plugin"
    assert windows_install.spy.calls == []


def test_windows_removal_reports_a_refused_directory_and_keeps_going(windows_install, capsys):
    home = windows_install.home
    assert install.install(home) == 0
    os.chmod(page(home).parent, 0o755)
    capsys.readouterr()

    assert install.uninstall(home) == 1
    captured = capsys.readouterr()
    assert f'"{page(home).parent}"' in captured.err and "(unsafe)" in captured.err
    assert page(home).exists(), "a refused directory keeps its files"
    assert not (dashboard(home) / "manifest.json").exists(), "other directories are still cleaned"
    assert windows_install.spy.calls == []


def test_windows_legacy_page_drops_only_the_known_file(windows_install):
    home = windows_install.home
    legacy = home / "plugins" / "mordred" / "desktop"
    for directory in (home / "plugins", home / "plugins" / "mordred"):
        with open_private_directory(directory, create=True):
            pass
    put(legacy, "plugin.js", b"old page")
    put(legacy, "README.txt", b"keep me")

    assert install.ensure_page(home) is True
    assert not (legacy / "plugin.js").exists()
    assert (legacy / "README.txt").read_bytes() == b"keep me" and legacy.is_dir()
    assert windows_install.spy.calls == []


def test_wizard_uninstall_step_never_raises_on_a_refused_page(windows_install, capsys):
    home = windows_install.home
    assert install.install(home) == 0
    os.chmod(dashboard(home), 0o755)
    assert install.remove_page(home) is True, "the page file in the safe directory was removed"
    assert "(unsafe)" in capsys.readouterr().err


def test_posix_branch_is_unchanged(tmp_path):
    assert install.install(tmp_path) == 0
    assert (tmp_path / "desktop-plugins" / "mordred" / "plugin.js").is_file()
    assert install.uninstall(tmp_path) == 0
    assert not (tmp_path / "plugins" / "mordred").exists(), "POSIX keeps its folder removal"


def test_windows_status_and_removal_on_a_home_without_desktop_folders(windows_install, capsys):
    home = windows_install.home
    assert install.status(home) == 1
    err = capsys.readouterr().err
    assert "not installed" in err and "could not be checked" not in err
    assert install.uninstall(home) == 0, "nothing to remove is not a refusal"
    captured = capsys.readouterr()
    assert "could not be checked" not in captured.err and "Removed" not in captured.out
    assert not (home / "desktop-plugins").exists() and not (home / "plugins").exists(), "reads create nothing"
    assert windows_install.spy.calls == []


def test_windows_refused_placement_logs_the_exact_path(windows_install, caplog):
    import logging

    home = windows_install.home
    unsafe = page(home).parent
    unsafe.mkdir(parents=True)
    os.chmod(unsafe, 0o755)
    with caplog.at_level(logging.WARNING, logger="mordred_hermes.desktop.install"), pytest.raises(OSError):
        install.ensure_page(home)
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert f'"{unsafe}"' in logged and "(unsafe)" in logged
    assert "desktop install" in logged, "the log names the manual remedy"
