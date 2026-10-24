"""Fresh-child admission must refuse bad bootstrap inputs before native imports."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

_MODULE = Path(__file__).parent / "integration/test_dbcrypt_windows_vfs.py"
_CHILDREN = (
    "test_same_process_and_multiprocess_writer_exclusion",
    "test_crash_releases_locks_and_recovers_checked_files",
    "test_distinct_sqlite_library_cannot_replace_checked_api",
    "test_wal_reader_in_another_process_blocks_restart_until_release",
    "test_wal_multiregion_commit_survives_process_crash",
)


def _child_program(name: str) -> str:
    """Read the actual subprocess artifact without importing the native test module."""
    module = ast.parse(_MODULE.read_text())
    constants = {
        target.id: node.value.value
        for node in module.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    def value(node: ast.expr) -> str:
        if isinstance(node, ast.Constant):
            assert isinstance(node.value, str)
            return node.value
        if isinstance(node, ast.Name):
            return constants[node.id]
        assert isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        return value(node.left) + value(node.right)

    function = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name)
    assignment = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "child" for target in node.targets)
    )
    return value(assignment.value)


@pytest.mark.parametrize("name", _CHILDREN)
@pytest.mark.parametrize(
    ("mode", "override", "reason"),
    [
        ("invalid", None, "invalid checked VFS child mode"),
        ("packaged", "", "packaged checked VFS child forbids DLL override"),
        ("packaged", "conflicting.dll", "packaged checked VFS child forbids DLL override"),
        ("source", None, "source checked VFS child requires its explicit DLL"),
        ("source", "different.dll", "source checked VFS child DLL differs from parent"),
    ],
)
def test_vfs_child_refuses_bad_bootstrap_before_native_imports(
    name: str, mode: str, override: str | None, reason: str, tmp_path: Path
) -> None:
    child = _child_program(name)
    # Block the native boundary rather than replacing the driver, VFS or loader.
    # A missing/misordered guard reaches this audit trap and fails this test.
    harness = r"""
import sys

def native_boundary(event, args):
    if event == 'import' and (args[0] in ('sqlite3', '_sqlite3') or args[0].startswith('sqlcipher3')):
        raise RuntimeError('NATIVE_IMPORT_BEFORE_ADMISSION')
    if event == 'import' and args[0].startswith('mordred_hermes'):
        raise RuntimeError('PRODUCT_IMPORT_BEFORE_ADMISSION')
    if event == 'ctypes.dlopen':
        raise RuntimeError('NATIVE_LOAD_BEFORE_ADMISSION')

sys.addaudithook(native_boundary)
exec(compile(sys.argv.pop(1), '<actual-vfs-child>', 'exec'))
"""
    environment = {key: value for key, value in os.environ.items() if key != "MORDRED_DBCRYPT_CHECKED_LIBRARY"}
    environment["HERMES_HOME"] = str(tmp_path / "synthetic-home")
    (tmp_path / "bridge.dll").touch()
    if override == "different.dll":
        other = tmp_path / "different.dll"
        other.touch()
        override = str(other)
    if override is not None:
        environment["MORDRED_DBCRYPT_CHECKED_LIBRARY"] = override
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", harness, child, str(tmp_path), mode, str(tmp_path / "bridge.dll")],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode != 0
    assert reason in result.stderr, result.stderr
    assert "NATIVE_IMPORT_BEFORE_ADMISSION" not in result.stderr
    assert "NATIVE_LOAD_BEFORE_ADMISSION" not in result.stderr
    assert "PRODUCT_IMPORT_BEFORE_ADMISSION" not in result.stderr
