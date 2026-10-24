"""Lexical refusal precedes bootstrap or any native database open."""

from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest


def implementation() -> ModuleType:
    from mordred_hermes import dbcrypt

    assert importlib.util.find_spec(f"{dbcrypt.__name__}._windows_vfs") is not None, "checked VFS admission is missing"
    return importlib.import_module(f"{dbcrypt.__name__}._windows_vfs")


@pytest.mark.parametrize(
    ("path", "uri"),
    [
        (r"\\server\share\state.db", False),
        (r"\\?\C:\private\state.db", False),
        (r"\\.\C:\private\state.db", False),
        (r"C:\private\state.db:stream", False),
        (r"C:state.db", False),
        (r"\private\state.db", False),
        (r"C:\private\state.db.", False),
        (r"C:\private\state.db ", False),
        (r"C:\private\..\state.db", False),
        (r"C:\private\CON.db", False),
        (r"C:\private\LPT¹.db", False),
        (r"C:\private\state?.db", False),
        ("C:\\private\\state.db\x00ignored", False),
        (r"C:\private-other\state.db", False),
        (r"D:\private\state.db", False),
        (r"C:\private", False),
        (r"C:\private\\state.db", False),
        ("file:///C:/private/state.db%3fstream", True),
        ("file:///C:/private/state.db?vfs=win32", True),
        ("file:///C:/private/state.db?vfs=mordred_checked_v1", True),
        ("file:C:/private/state.db", True),
        ("file:///C:/private/state.db", True),
        (":memory:", False),
        ("", False),
        ("C:\\private\\" + "x" * 218 + ".db", False),
    ],
)
def test_unsupported_path_never_calls_xopen(path: str, uri: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    module = implementation()
    unchecked_opens: list[str] = []

    def unexpected(*args: object, **kwargs: object) -> None:
        unchecked_opens.append(str(args))
        pytest.fail("classification must not touch the native boundary")

    monkeypatch.setattr(module, "_load_native", unexpected)
    with pytest.raises(ValueError):
        module.classify_windows_database(path, uri=uri, root=Path(r"C:\private"))
    assert unchecked_opens == []


@pytest.mark.parametrize("path", [r"C:\private\state.db", r"c:\PRIVATE\nested\state.db", "C:/private/日本語.db"])
def test_supported_drive_path_is_classified_without_resolving_on_host(path: str) -> None:
    result = implementation().classify_windows_database(path, uri=False, root=Path(r"C:\private"))
    assert str(result).replace("\\", "/").casefold() == path.replace("\\", "/").casefold()


@pytest.mark.parametrize("root", ["C:\\", r"C:private", r"\\server\private", r"C:\private.", r"C:\private\.."])
def test_invalid_root_is_refused(root: str) -> None:
    with pytest.raises(ValueError):
        implementation().classify_windows_database(r"C:\private\state.db", uri=False, root=Path(root))


def test_unqualified_registration_cannot_enable_runtime_support() -> None:
    # Building or loading an adapter cannot qualify production by accident.
    assert implementation().NATIVE_QUALIFIED is False


def test_other_platform_registration_does_not_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    module = implementation()
    monkeypatch.setattr(module.sys, "platform", "darwin")
    driver = ModuleType("no_driver_calls")
    with pytest.raises(RuntimeError, match="Windows"):
        module.register_checked_vfs(driver, root=Path(r"C:\private"))


def test_non_cipher_driver_refuses_before_loading_native(monkeypatch: pytest.MonkeyPatch) -> None:
    module = implementation()
    monkeypatch.setattr(module.sys, "platform", "win32")

    def unexpected() -> None:
        pytest.fail("must not pin a non-SQLCipher driver's API table")

    monkeypatch.setattr(module, "_load_native", unexpected)
    with pytest.raises(RuntimeError, match="SQLCipher"):
        module.register_checked_vfs(sqlite3, root=Path(r"C:\private"))
