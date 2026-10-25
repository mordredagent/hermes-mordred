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
    "test_checkedtest_initialization_failure_rolls_back_in_fresh_process",
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
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            harness,
            child,
            str(tmp_path),
            mode,
            str(tmp_path / "bridge.dll"),
            *(["20"] if "initialization_failure" in name else []),
        ],
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


def _bootstrap_program():
    module = ast.parse(_MODULE.read_text())
    return next(
        node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_CHECKED_VFS_CHILD_BOOTSTRAP" for target in node.targets)
    )


def test_activated_packaged_child_never_assigns_eligibility(tmp_path, monkeypatch):
    import base64
    import hashlib
    import importlib.metadata
    from types import ModuleType, SimpleNamespace

    dll = tmp_path / "owned.dll"
    dll.write_bytes(b"inert packaged DLL, not loaded")
    loader = tmp_path / "_windows_vfs.py"
    loader.write_text("NATIVE_QUALIFIED: bool = True\n")

    class OwnedEntry(str):
        hash = SimpleNamespace(
            mode="sha256",
            value=base64.urlsafe_b64encode(hashlib.sha256(dll.read_bytes()).digest()).rstrip(b"=").decode(),
        )

        def locate(self):
            return dll

    class ActivatedModule(ModuleType):
        def __setattr__(self, name, value):
            if name == "NATIVE_QUALIFIED":
                raise AssertionError("production child assigned qualification")
            super().__setattr__(name, value)

    vfs = ActivatedModule("mordred_hermes.dbcrypt._windows_vfs")
    vfs.__dict__.update(
        NATIVE_QUALIFIED=True,
        __file__=str(loader),
        driver_distribution_qualified=lambda: True,
        packaged_library_path=lambda: dll,
        register_checked_vfs=object(),
    )
    package = ModuleType("mordred_hermes.dbcrypt")
    package._windows_vfs = vfs
    monkeypatch.setitem(sys.modules, "mordred_hermes.dbcrypt", package)
    monkeypatch.setattr(
        importlib.metadata,
        "distribution",
        lambda name: SimpleNamespace(files=[OwnedEntry("mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll")]),
    )
    monkeypatch.setattr(sys, "argv", ["child", str(tmp_path), "packaged", str(dll)])
    monkeypatch.delenv("MORDRED_DBCRYPT_CHECKED_LIBRARY", raising=False)
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "production")
    namespace = {}
    exec(_bootstrap_program(), namespace)
    assert namespace["register_checked_vfs"] is vfs.register_checked_vfs


def test_production_child_cannot_select_diagnostic_eligibility(tmp_path, monkeypatch):
    dll = tmp_path / "CheckedTest.dll"
    dll.write_bytes(b"inert")
    monkeypatch.setattr(sys, "argv", ["child", str(tmp_path), "source", str(dll)])
    monkeypatch.setenv("MORDRED_DBCRYPT_CHECKED_LIBRARY", str(dll))
    monkeypatch.setenv("MORDRED_DBCRYPT_WINDOWS_VFS_TEST", "1")
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "production")
    with pytest.raises(RuntimeError, match="diagnostic child forbids Native storage eligibility"):
        exec(_bootstrap_program(), {})


def _diagnostic_context():
    """Execute only the real fixture's metadata/eligibility boundary, no native test."""
    from collections.abc import Iterator

    tree = ast.parse(_MODULE.read_text())
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "diagnostic_eligibility"
    )
    function.decorator_list = []
    namespace = {"os": os, "Path": Path, "Iterator": Iterator}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(_MODULE), "exec"), namespace)
    return namespace["diagnostic_eligibility"]()


def test_production_parent_requires_observed_eligibility_without_assigning(monkeypatch):
    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.delenv("MORDRED_DBCRYPT_CHECKED_LIBRARY", raising=False)
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "production")
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", False)
    with pytest.raises(AssertionError, match="production VFS requires activated eligibility"):
        next(_diagnostic_context())
    assert _windows_vfs.NATIVE_QUALIFIED is False


def test_full_diagnostic_context_is_separate_and_restores_source_gate(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt import _windows_vfs

    dll = tmp_path / "CheckedTest.dll"
    dll.write_bytes(b"inert test artifact")
    monkeypatch.setenv("MORDRED_DBCRYPT_CHECKED_LIBRARY", str(dll))
    monkeypatch.setenv("MORDRED_DBCRYPT_WINDOWS_VFS_TEST", "1")
    monkeypatch.delenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", raising=False)
    monkeypatch.delenv("MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY", raising=False)
    previous = _windows_vfs.NATIVE_QUALIFIED
    context = _diagnostic_context()
    next(context)
    assert _windows_vfs.NATIVE_QUALIFIED is False
    context.close()
    assert _windows_vfs.NATIVE_QUALIFIED is previous
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_KIND", "production")
    with pytest.raises(AssertionError, match="diagnostic gate forbids Native storage eligibility"):
        next(_diagnostic_context())
    assert _windows_vfs.NATIVE_QUALIFIED is previous
