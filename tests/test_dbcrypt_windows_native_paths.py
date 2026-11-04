"""Real Windows database admission for local names and remote namespaces.

``test_dbcrypt_windows_paths.py`` simulates ``os.name``; this module does not. NTFS,
ACL admission, leases, custody records and SQLCipher are real, and only the CNG
hardware boundary is a software double (no TPM or production home is involved).

``:memory:`` and refusals need no checked VFS: ``_connection._open`` gates the
edition and VFS on a file path only, and ``_shim._native_path`` refuses before it.
File opens need the native-qualified prerequisite and skip naming it when absent.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from mordred_hermes._core._database_contracts import DatabaseRefused

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="real Windows database admission")


def _extended_spelling(path: Path) -> str:
    return "\\\\?\\" + str(path)


def _unc_spelling(path: Path) -> str:
    return f"\\\\127.0.0.1\\{path.drive[:1]}$" + str(path)[2:]


def _missing_checked_vfs_prerequisites() -> list[str]:
    from mordred_hermes.dbcrypt import _windows_vfs as vfs

    checks = (
        (vfs.NATIVE_QUALIFIED, "a native-qualified build"),
        (vfs.windows_edition_admitted(), "a Windows Server edition"),
        (vfs.driver_distribution_qualified(), "the qualified sqlcipher3-wheels 0.5.7 driver"),
        (vfs.packaged_library_path() is not None, "the packaged mordred_dbcrypt_vfs.dll"),
    )
    return [name for present, name in checks if not present]


@pytest.fixture
def checked_vfs() -> None:
    missing = _missing_checked_vfs_prerequisites()
    if missing:
        pytest.skip("Windows file databases need the checked VFS prerequisite; missing " + ", ".join(missing))


@pytest.fixture
def admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Any]]:
    """A private home, a real ``Authority`` and the shim module it admits through."""
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._marker import write_marker
    from mordred_hermes.dbcrypt._shim import build_module
    from mordred_hermes.keyvault import _windows_custody as custody
    from mordred_hermes.keyvault._database_authority import enroll_database_source
    from mordred_hermes.keyvault._database_mutation import database_key_mutation
    from tests._keyvault_fakes import FakeBackend

    home = tmp_path / "home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    with open_private_directory(home, create=True):
        pass
    backend = FakeBackend()
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    with (
        database_key_mutation(root=home, generation=None) as mutation,
        custody.windows_custody_session(home, create=True, backend=backend) as session,
    ):
        session.enroll_memory(database_lease=mutation)
    with acquire_exclusive(home) as lease:
        write_marker(home, enroll_database_source(root=home, lease=lease), lease=lease)
    authority = Authority.acquire(home)
    try:
        yield home, build_module(authority=authority)
    finally:
        authority.close()


def _round_trip_through_reopen(module: Any, database: str, **options: Any) -> None:
    first = module.connect(database, **options)
    try:
        first.execute("CREATE TABLE records(value TEXT)")
        first.execute("INSERT INTO records VALUES ('synthetic')")
        first.commit()
    finally:
        first.close()
    reopened = module.connect(database, **options)
    try:
        assert reopened.execute("SELECT value FROM records").fetchall() == [("synthetic",)]
    finally:
        reopened.close()


def _assert_refused_before_target_io(module: Any, spelling: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusal order only: in-process nothing can observe an SMB session directly."""
    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt import _connection

    touched: list[str] = []

    def watch(owner: Any, name: str, guard: pytest.MonkeyPatch) -> None:
        original = getattr(owner, name)

        def checked(*args: Any, **kwargs: Any) -> Any:
            target = args[0] if args else None
            if isinstance(target, str | os.PathLike) and spelling.casefold() in os.fspath(target).casefold():
                touched.append(name)
                raise AssertionError(f"{name} reached a refused namespace")
            return original(*args, **kwargs)

        guard.setattr(owner, name, checked)

    with monkeypatch.context() as guard:
        # The authority's own checks of the local home stay real.
        for method in ("absolute", "resolve", "exists", "stat", "lstat"):
            watch(Path, method, guard)
        for function in ("stat", "lstat", "open"):
            watch(os, function, guard)
        for function in ("realpath", "exists", "isfile"):
            watch(os.path, function, guard)
        watch(sc, "connect", guard)
        watch(_connection, "_PathBinding", guard)
        watch(_connection, "_open", guard)
        with pytest.raises(DatabaseRefused) as refused:
            module.connect(spelling)
    assert touched == []
    assert spelling not in str(refused.value)


def test_memory_database_opens_without_the_checked_vfs(admission: tuple[Path, Any]) -> None:
    _, module = admission
    connection = module.connect(":memory:")
    try:
        assert connection.execute("SELECT 1").fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize("spelling", [_extended_spelling, _unc_spelling], ids=["extended", "unc"])
def test_remote_and_device_spellings_are_refused_before_target_io(
    admission: tuple[Path, Any], monkeypatch: pytest.MonkeyPatch, spelling: Any
) -> None:
    home, module = admission
    local = home / "state.db"
    _assert_refused_before_target_io(module, spelling(local), monkeypatch)
    assert not local.exists()


def test_local_path_round_trips_and_its_other_spellings_stay_refused(
    checked_vfs: None, admission: tuple[Path, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, module = admission
    local = home / "state.db"
    _round_trip_through_reopen(module, str(local))
    before = local.read_bytes()
    _assert_refused_before_target_io(module, _extended_spelling(local), monkeypatch)
    _assert_refused_before_target_io(module, _unc_spelling(local), monkeypatch)
    assert local.read_bytes() == before


def test_local_file_uri_round_trips_through_reopen(checked_vfs: None, admission: tuple[Path, Any]) -> None:
    home, module = admission
    uri = f"file:{quote((home / 'state.db').as_posix(), safe='/:')}?mode=rwc"
    _round_trip_through_reopen(module, uri, uri=True)
