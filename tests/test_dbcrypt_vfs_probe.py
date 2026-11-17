"""A working encrypted SELECT alone cannot qualify a Windows VFS boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests._dbcrypt_support import acceptance_tool


@pytest.mark.parametrize("missing", ["extension_loaded", "persistent", "same_library", "shm_boundary_viable"])
def test_missing_native_boundary_rejects_probe(missing: str) -> None:
    module = acceptance_tool("dbcrypt_vfs_probe")
    flags = dict.fromkeys(("extension_loaded", "persistent", "same_library", "shm_boundary_viable"), True)
    flags[missing] = False
    result = module.ProbeResult(
        wheel_version="0.5.7",
        sqlite_version="3.51.0",
        sqlcipher_version="4.12.0",
        selected_vfs="mordred_probe_v1",
        callbacks=("xOpen", "xDelete", "xShmMap", "xShmUnmap"),
        **flags,
    )
    assert result.passed is False


def test_missing_shm_boundary_returns_failure_from_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = acceptance_tool("dbcrypt_vfs_probe")
    result = module.ProbeResult(
        "0.5.7",
        "3.51.0",
        "4.12.0",
        True,
        True,
        "mordred_probe_v1",
        ("xOpen", "xDelete", "xShmMap", "xShmUnmap"),
        True,
        False,
    )
    monkeypatch.setattr(module, "probe", lambda **_kwargs: result)
    assert module.main(["--output", str(tmp_path / "report.json")]) == 1


def test_missing_callbacks_are_not_a_pass() -> None:
    module = acceptance_tool("dbcrypt_vfs_probe")
    result = module.ProbeResult("0.5.7", "3.51.0", "4.12.0", True, True, "mordred_probe_v1", ("xOpen",), True, True)
    assert result.passed is False


def test_absent_extension_fails_without_creating_database(tmp_path: Path) -> None:
    module = acceptance_tool("dbcrypt_vfs_probe")
    report = tmp_path / "report.json"
    assert module.main(["--output", str(report), "--extension", str(tmp_path / "absent.dll")]) == 1
    payload = json.loads(report.read_text())
    assert payload["passed"] is False and payload["error"] == "extension_unavailable"
    assert not list(tmp_path.glob("*.db"))


def test_optional_module_inventory_does_not_require_memory_maps(monkeypatch: pytest.MonkeyPatch) -> None:
    import psutil

    module = acceptance_tool("dbcrypt_vfs_probe")
    monkeypatch.setattr(psutil, "Process", lambda: object())
    assert hasattr(module, "loaded_modules"), "optional module inventory must handle unsupported hosts"
    assert module.loaded_modules() is None


def test_failed_connection_setup_closes_handle(tmp_path: Path) -> None:
    driver = pytest.importorskip("sqlcipher3.dbapi2")
    from mordred_hermes.dbcrypt._key import derive

    module = acceptance_tool("dbcrypt_vfs_probe")
    connection = driver.connect(":memory:")
    connection.set_authorizer(
        lambda action, first, *_rest: (
            driver.SQLITE_DENY if action == driver.SQLITE_PRAGMA and first == "temp_store" else driver.SQLITE_OK
        )
    )

    class Driver:
        @staticmethod
        def connect(*_args, **_kwargs):
            return connection

    assert hasattr(module, "keyed_connection"), "connection setup must close handles on refusal"
    with (
        pytest.raises(driver.DatabaseError),
        module.keyed_connection(Driver, tmp_path / "synthetic.db", derive(bytes(32))),
    ):
        pytest.fail("refused setup entered the connection scope")
    with pytest.raises(driver.ProgrammingError):
        connection.execute("SELECT 1")
