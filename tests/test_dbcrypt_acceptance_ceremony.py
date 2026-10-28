"""Acceptance ceremonies use real startup/leases, never a runtime exemption."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests._dbcrypt_support import acceptance_tool
from tests.test_dbcrypt_authority import native_root as native_root


def bootstrap_observation(argv: list[str], root: Path) -> dict:
    # A fresh interpreter owns its real lifetime lease until exit. No cleanup or
    # installer replacement can hide a mistaken runtime launch.
    code = """
import json, sys
from pathlib import Path
from types import SimpleNamespace
from mordred_hermes import dbcrypt, _runtime_bootstrap, _pth_bootstrap
from mordred_hermes._database_lifecycle import acquire_exclusive
argv, root = json.loads(sys.argv[1]), Path(sys.argv[2])
sys.argv = argv
dbcrypt.sys = SimpleNamespace(platform='linux')
engaged = _pth_bootstrap._looks_like_hermes(argv, {}, orig_argv=[])
if engaged:
    _runtime_bootstrap._install_database_encryption()
exists = root.exists()
busy = False
if exists:
    try:
        with acquire_exclusive(root): pass
    except RuntimeError:
        busy = True
print(json.dumps({'exists': exists, 'busy': busy, 'engaged': engaged}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, json.dumps(argv), str(root)],
        env={**os.environ, "HERMES_HOME": str(root)},
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    return json.loads(result.stdout)


@pytest.mark.skipif(os.name != "posix", reason="real POSIX lease fixture; Windows runtime proof is separate")
@pytest.mark.parametrize("operation", ["preflight", "provision"])
def test_passive_and_ceremony_collector_launch_does_not_initialize_fresh_root(tmp_path, monkeypatch, operation):
    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text("{}")
    directory = tmp_path / "evidence"
    directory.mkdir()
    root = tmp_path / "mordred-dbcrypt-fresh"
    context = {
        "bundle": bundle,
        "manifest": {"checkout": str(tmp_path), "files": {"tests/_dbcrypt_acceptance_native.py": "a" * 64}},
        "kind": "production",
        "mode": "source",
        "helper_sha256": "b" * 64,
    }
    monkeypatch.setattr(tool, "validate_bundle", lambda *_: None)
    monkeypatch.setattr(tool, "require_native_source_checkout", lambda *_: None)
    monkeypatch.setattr(tool, "probe_interpreter", lambda *_args, **_kwargs: {"product_file": str(tmp_path)})
    monkeypatch.setattr(tool, "validate_import_provenance", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tool, "_native_environment", lambda *_: {})

    def process(_context, argv, _environment, **_kwargs):
        observed = bootstrap_observation(argv[1:], root)
        assert observed == {"exists": False, "busy": False, "engaged": False}
        # Stop before any native collector code; the regression is the actual
        # public startup side effect of the producer's selected invocation.
        raise StopIteration

    monkeypatch.setattr(tool, "_native_process", process)
    with pytest.raises(StopIteration):
        tool._collector_child(context, root, operation, directory)


@pytest.mark.skipif(os.name != "posix", reason="real POSIX lease fixture; Windows runtime proof is separate")
@pytest.mark.parametrize("args", [["preflight"], ["provision"], ["seed"], ["read"], ["mordred", "databases", "bogus"]])
def test_ordinary_or_malformed_hermes_keeps_plain_runtime_exclusion(tmp_path, args):
    assert bootstrap_observation(["hermes", *args], tmp_path / "home") == {
        "exists": True,
        "busy": True,
        "engaged": True,
    }


@pytest.mark.skipif(os.name != "posix", reason="real POSIX lease fixture; Windows runtime proof is separate")
@pytest.mark.parametrize("args", [["encryption", "enable", "memory"], ["databases", "encrypt"]])
def test_actual_maintenance_grammar_leaves_fresh_root_for_ceremony(tmp_path, args):
    assert bootstrap_observation(["hermes-mordred", *args], tmp_path / "home") == {
        "exists": False,
        "busy": False,
        "engaged": True,
    }


@pytest.mark.parametrize(
    "damage", [None, "secret", "extra", "wrong_operation", "bool_schema", "oversized", "nonzero_other"]
)
def test_child_refusal_preserves_only_existing_finite_safe_json(damage):
    tool = acceptance_tool("dbcrypt_acceptance")
    value = {
        "schema_version": 2,
        "operation": "provision",
        "status": "refused",
        "reason": "native_provision_requires_new_root_no_repair",
    }
    code = 2
    if damage == "secret":
        value["reason"] = "secret-canary"
    elif damage == "extra":
        value["stdout"] = "secret-canary"
    elif damage == "wrong_operation":
        value["operation"] = "read"
    elif damage == "bool_schema":
        value["schema_version"] = True
    elif damage == "nonzero_other":
        code = 1
    text = json.dumps(value) + (" " * 4096 if damage == "oversized" else "")
    observed = tool.native_refusal_payload(text, "provision", code)
    assert observed == (value if damage is None else None)


@pytest.mark.skipif(os.name != "posix", reason="real POSIX authority fixture; Windows native proof is separate")
def test_installed_database_ceremony_owns_ex_then_real_automatic_runtime(native_root, monkeypatch):
    """Run the installed console code; only hardware is fake, not EX/Authority/SQL."""
    import contextlib
    import io
    import runpy
    from types import SimpleNamespace

    from mordred_hermes import _runtime_bootstrap, dbcrypt
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _capability, _shim

    root, backend, _, _ = native_root
    helper = runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))
    monkeypatch.setattr(dbcrypt, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(_capability, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    monkeypatch.setitem(sys.modules, "sqlite3", __import__("sqlite3"))
    monkeypatch.setitem(sys.modules, "sqlite3.dbapi2", sys.modules.get("sqlite3.dbapi2"))
    before = (root / "mordred/db-key-source.json").read_bytes()
    entrypoint = Path(sys.prefix) / "bin/hermes-mordred"
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "source_probe": {
                    "maintenance_entrypoint": {"path": str(entrypoint), "sha256": helper["_digest"](entrypoint)}
                }
            }
        )
    )
    monkeypatch.setenv("DBCRYPT_BUNDLE", str(root))
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_MODE", "source")

    def launch(argv, **kwargs):
        # Run the genuine installed entrypoint with its exact selected command.
        # Same process is solely so the hardware-bound fake survives; no lease
        # cleanup or replacement installer is used to get past exclusion.
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["env"]["HERMES_HOME"] == str(root)
        with monkeypatch.context() as child:
            child.setattr(sys, "argv", argv)
            _runtime_bootstrap._install_database_encryption()
            with acquire_exclusive(root):
                pass
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
                pytest.raises(SystemExit) as result,
            ):
                runpy.run_path(argv[0], run_name="__main__")
        return subprocess.CompletedProcess(argv, result.value.code)

    monkeypatch.setattr(subprocess, "run", launch)
    record = helper["_maintenance"](root, ["databases", "encrypt"])
    assert record["returncode"] == 0
    assert record["argv"][1:] == ["databases", "encrypt"]
    assert (root / "mordred/db-key-source.json").read_bytes() == before
    assert any(name == "ecdh" for name, _ in backend.calls)
    with acquire_exclusive(root):
        pass
    monkeypatch.setattr(sys, "argv", ["hermes", "read"])
    try:
        _runtime_bootstrap._install_database_encryption()
        assert _shim.is_installed()
        assert dbcrypt._PROVIDER.authority.root == root
        with pytest.raises(RuntimeError), acquire_exclusive(root):
            pass
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()


def test_changed_installed_ceremony_entrypoint_refuses_before_execution(tmp_path, monkeypatch):
    import runpy

    helper = runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"source_probe": {"maintenance_entrypoint": {"path": "wrong", "sha256": "0" * 64}}}))
    monkeypatch.setenv("DBCRYPT_BUNDLE", str(tmp_path))
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_MODE", "source")

    def forbidden(*_args, **_kwargs):
        pytest.fail("changed entrypoint was executed before checking its frozen probe")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(RuntimeError, match="owned_checked_distribution_required"):
        helper["_maintenance"](tmp_path, ["databases", "encrypt"])


@pytest.mark.skipif(os.name != "posix", reason="real POSIX custody fixture; Windows native proof is separate")
def test_installed_memory_ceremony_enrolls_fresh_home_without_runtime_lease(tmp_path, monkeypatch):
    import contextlib
    import io
    import runpy
    from types import SimpleNamespace

    from mordred_hermes import _database_locking_posix, _runtime_bootstrap, dbcrypt
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.keyvault import _database_authority, _memory_key, _runtime_probe
    from mordred_hermes.wizard import encryption_cli, memory_cli
    from tests._keyvault_fakes import FakeBackend

    root = tmp_path / "fresh"
    root.mkdir(mode=0o700)
    backend = FakeBackend()
    monkeypatch.setenv("HERMES_HOME", str(root))
    for module in (dbcrypt, _database_locking_posix, _database_authority, encryption_cli, memory_cli):
        monkeypatch.setattr(module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(encryption_cli._windows_gates, "host_platform", lambda: "linux")
    monkeypatch.setattr(_memory_key, "linux_memory_backend", lambda home: backend)
    # These probes cross into a separate hardware process in production. Keep
    # their native key read real here, using only the in-memory hardware backend.
    monkeypatch.setattr(_runtime_probe, "discover_running_gateway_runtimes", lambda **_kw: [])
    monkeypatch.setattr(_runtime_probe, "runtime_memory_encryption_available", lambda **_kw: (True, "unit runtime"))
    monkeypatch.setattr(
        _runtime_probe,
        "runtime_memory_key_available",
        lambda **_kw: (bool(_memory_key.load_linux_memory_key(home=root)), "unit hardware boundary"),
    )
    helper = runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))
    entrypoint = Path(sys.prefix) / "bin/hermes-mordred"
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "source_probe": {
                    "maintenance_entrypoint": {"path": str(entrypoint), "sha256": helper["_digest"](entrypoint)}
                }
            }
        )
    )
    monkeypatch.setenv("DBCRYPT_BUNDLE", str(tmp_path))
    monkeypatch.setenv("MORDRED_DBCRYPT_ACCEPTANCE_MODE", "source")

    def launch(argv, **kwargs):
        assert argv == [str(entrypoint), "encryption", "enable", "memory"]
        with monkeypatch.context() as child:
            child.setattr(sys, "argv", argv)
            _runtime_bootstrap._install_database_encryption()
            with acquire_exclusive(root):
                pass
            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(output),
                pytest.raises(SystemExit) as result,
            ):
                runpy.run_path(argv[0], run_name="__main__")
        assert result.value.code == 0, output.getvalue()
        return subprocess.CompletedProcess(argv, result.value.code)

    monkeypatch.setattr(subprocess, "run", launch)
    assert helper["_maintenance"](root, ["encryption", "enable", "memory"])["returncode"] == 0
    _database_authority.require_database_memory_enabled(root=root)
    assert (root / "mordred/memory-vault.marker").is_file()
    assert any(name == "generate" for name, _ in backend.calls)
    with acquire_exclusive(root):
        pass


def test_existing_provision_root_stays_untouched_before_any_ceremony(tmp_path, monkeypatch):
    import runpy

    helper = runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))
    root = tmp_path / "mordred-dbcrypt-partial"
    root.mkdir(mode=0o700)
    (root / "retain").write_bytes(b"prior partial evidence")
    before = (root / "retain").read_bytes()

    def forbidden(*_args, **_kwargs):
        pytest.fail("partial root retried a ceremony")

    monkeypatch.setitem(helper["provision"].__globals__, "_maintenance", forbidden)
    with pytest.raises(RuntimeError, match="native_provision_requires_new_root_no_repair"):
        helper["provision"](root)
    assert list(root.iterdir()) == [root / "retain"]
    assert (root / "retain").read_bytes() == before


@pytest.mark.parametrize("operation", ["preflight", "provision", "seed", "read"])
@pytest.mark.parametrize("with_failure", [False, True])
def test_failed_collector_retains_only_safe_refusal_in_execution_record(tmp_path, monkeypatch, operation, with_failure):
    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text("{}")
    directory = tmp_path / "evidence"
    directory.mkdir()
    context = {"bundle": bundle, "manifest": {"checkout": str(tmp_path)}, "kind": "production", "mode": "source"}
    monkeypatch.setattr(tool, "validate_bundle", lambda *_: None)
    monkeypatch.setattr(tool, "require_native_source_checkout", lambda *_: None)
    monkeypatch.setattr(tool, "probe_interpreter", lambda *_args, **_kwargs: {"product_file": str(tmp_path)})
    monkeypatch.setattr(tool, "validate_import_provenance", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tool, "_native_environment", lambda *_: {})
    payload = {"schema_version": 2, "operation": operation, "status": "refused", "reason": "native_operation_failed"}
    if with_failure:
        payload["failure"] = {
            "stage": "memory_read",
            "home": "work",
            "child_returncode": 9,
            "exception_category": "assertion",
        }
    record = {}
    monkeypatch.setattr(
        tool,
        "_native_process",
        lambda *_args, **_kwargs: (
            subprocess.CompletedProcess([], 2, json.dumps(payload), "never-export-this-stderr"),
            record,
        ),
    )
    with pytest.raises(tool.AcceptanceRefused, match="native_child_refused_or_failed"):
        tool._collector_child(context, tmp_path / "mordred-dbcrypt-fresh", operation, directory)
    assert record["refusal"] == payload
    assert "never-export" not in json.dumps(record)
