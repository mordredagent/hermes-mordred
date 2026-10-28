"""Wizard authority boundaries: metadata observation and guarded key lifecycle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from mordred_hermes.wizard import databases_cli, mail_cli, memory_cli
from tests.test_dbcrypt_authority import native_root as native_root


def snapshot(root: Path):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode) for p in root.rglob("*") if p.is_file()}


def test_cli_status_no_native_auth(native_root, monkeypatch, capsys):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _migrate

    root, backend, _, _ = native_root
    before = snapshot(root)
    monkeypatch.setattr(_migrate, "discover", lambda *a, **k: pytest.fail("status opened SQL"))
    monkeypatch.setattr(dbcrypt, "diagnose_database", lambda *a: pytest.fail("status authenticated"))
    assert databases_cli.databases_status(root) == 0
    out = capsys.readouterr().out
    assert "configured: yes" in out and "authenticated: not checked" in out
    assert backend.calls == [] and snapshot(root) == before


def test_diagnose_auth_failure_is_not_ready(tmp_path, monkeypatch, capsys):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt._capability import DatabaseStatus

    monkeypatch.setattr(
        dbcrypt,
        "diagnose_database",
        lambda home: DatabaseStatus(True, 1, "unavailable", False, "authentication refused"),
    )
    monkeypatch.setattr(databases_cli, "_home", lambda: tmp_path)
    assert databases_cli.cli_databases(argparse.Namespace(databases_command="diagnose")) == 1
    out = capsys.readouterr().out
    assert "authenticated: no" in out and "ready" not in out.lower()


@pytest.mark.parametrize(
    "dependency",
    ["state.db", "mordred/db-encryption.pending", "mordred/db-encryption.journal.json", "backups/state.db.bak"],
)
@pytest.mark.parametrize("operation", ["disable", "purge", "reset", "uninstall"])
def test_disable_purge_reset_uninstall_dependencies_refuse(native_root, dependency, monkeypatch, operation):
    root, backend, _, _ = native_root
    path = root / dependency
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"retained dependency")
    before = snapshot(root)
    if operation == "disable":
        monkeypatch.setattr(memory_cli, "_disable", lambda **k: pytest.fail("entered memory custody before DB guard"))
        code = memory_cli.disable(home=root, root=root / "mordred/vault")
    elif operation == "purge":
        code = memory_cli.purge(home=root, root=root / "mordred/vault")
    elif operation == "reset":
        from mordred_hermes.wizard.keyvault_cli import reset_keyvault

        code = reset_keyvault(home=root, backend=backend, assume_yes=True)
    else:
        from mordred_hermes.wizard import uninstall_cli
        from tests.test_uninstall_cli import FakeRunner, _hermes_env

        _hermes_env(root)
        runner = FakeRunner()
        ctx = uninstall_cli.UninstallContext(
            home=root,
            vault_root=root / "mordred/vault",
            user_home=root / "user",
            platform="linux",
            backend=backend,
            runner=runner,
            which=lambda name: None,
            gateways=lambda home: [],
        )
        code = uninstall_cli.run_uninstall(ctx, uninstall_cli.UninstallOptions(yes=True))
        assert runner.uninstalls == []
    assert code == 1
    # Restoration can complete before the final teardown guard refuses. Native
    # source/key material must remain exact even after that partial success.
    for name in ("mordred/memory-key.wrapped", "mordred/db-key-source.json"):
        assert snapshot(root)[name] == before[name]
    assert not any(op == "delete" for op, _ in backend.calls)
    if operation != "uninstall":
        assert snapshot(root) == before and backend.calls == []


def test_child_memory_disable_does_not_disable_root_database(native_root, monkeypatch):
    root, backend, _, _ = native_root
    (root / "state.db").write_bytes(b"root database")
    before = snapshot(root)
    child = root / "profiles/work"
    monkeypatch.setattr(memory_cli, "_warn_gateways", lambda *a, **k: None)
    assert memory_cli.disable(home=child, root=child / "mordred/vault") == 0
    after = snapshot(root)
    assert all(after[name] == value for name, value in before.items())
    assert (child / "mordred/memory-vault.optout").exists()
    assert not (root / "mordred/memory-vault.optout").exists()
    assert backend.calls == []


def test_mail_status_does_not_open_store(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(mail_cli, "_home", lambda: tmp_path)
    monkeypatch.setattr(mail_cli, "_open_store", lambda *a: pytest.fail("status opens SQL"))
    assert mail_cli.cmd_status(argparse.Namespace(json=True)) == 0
    assert "null" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes-mordred", "encryption", "status"],
        ["hermes-mordred", "mail", "status", "--json"],
        ["hermes-mordred", "status"],
        ["hermes", "--profile", "work", "mordred", "encryption", "status"],
    ],
)
def test_status_startup_classification(argv, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    monkeypatch.setattr("sys.argv", argv)
    assert maintenance_process()


def test_activity_restore_is_offline_maintenance_with_strict_grammar(monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    for argv, expected in (
        (["hermes-mordred", "activity", "restore", "--input", "/tmp/b", "--yes"], True),
        (["hermes-mordred", "activity", "restore", "--input", "/tmp/b"], True),
        (["hermes", "mordred", "activity", "restore", "--input", "/tmp/b", "--yes"], True),
        (["hermes-mordred", "activity", "restore", "--bogus"], False),
        (["hermes-mordred", "activity", "restore"], False),
        (["hermes-mordred", "activity", "backup", "--output", "/tmp/b"], False),
    ):
        monkeypatch.setattr("sys.argv", argv)
        assert maintenance_process() is expected, argv


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes", "--oneshot", "mordred encryption status"],
        ["hermes", "--model", "mordred", "encryption", "status"],
        ["hermes-mordred", "mail", "fetch"],
    ],
)
def test_status_words_in_values_are_not_passive(argv, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    monkeypatch.setattr("sys.argv", argv)
    assert not maintenance_process()


def test_explicit_encrypt_requires_enabled_root_even_when_bound(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.dbcrypt._capability import DatabaseStatus

    root, backend, _, _ = native_root
    marker = root / "mordred/memory-vault.marker"
    marker.unlink(missing_ok=True)
    before = snapshot(root)
    monkeypatch.setattr(dbcrypt, "database_status", lambda home: DatabaseStatus(True, 1, "unknown", False, None))
    monkeypatch.setattr(_migrate, "migrate", lambda *a, **k: pytest.fail("disabled root entered conversion"))
    assert databases_cli.databases_encrypt(home=root) == 1
    assert snapshot(root) == before and backend.calls == []


def test_fresh_source_requires_enabled_root_before_auth(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes._database_contracts import DatabaseRefused
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.keyvault import _database_authority as custody
    from mordred_hermes.keyvault import _memory_key as memory
    from tests._keyvault_fakes import FakeBackend

    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="linux"))
    from mordred_hermes import _database_locking_posix as locking

    monkeypatch.setattr(locking, "sys", SimpleNamespace(platform="linux"))
    backend = FakeBackend()
    memory.ensure_linux_memory_key(home=tmp_path, backend=backend)
    monkeypatch.setattr(memory, "linux_memory_backend", lambda home: backend)
    backend.calls.clear()
    with acquire_exclusive(tmp_path) as lease:
        before = snapshot(tmp_path)
        with pytest.raises(DatabaseRefused, match="enabled"):
            custody.enroll_database_source(root=tmp_path, lease=lease)
        assert snapshot(tmp_path) == before and backend.calls == []


def test_bound_disabled_source_observation_does_not_repair(native_root):
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.keyvault import _database_authority as custody

    root, backend, _, expected = native_root
    (root / "mordred/memory-vault.marker").unlink()
    with acquire_exclusive(root) as lease:
        before = snapshot(root)
        assert custody.enroll_database_source(root=root, lease=lease) == expected
        assert snapshot(root) == before
    assert sum(op == "ecdh" for op, _ in backend.calls) == 1


@pytest.mark.parametrize("operation", ["purge", "rotate"])
def test_explicit_source_mutations_refuse_before_vault_open(native_root, monkeypatch, operation):
    from mordred_hermes.wizard import vault_memory_key

    root, backend, _, _ = native_root
    (root / "state.db").write_bytes(b"retained")
    before = snapshot(root)
    monkeypatch.setattr(
        vault_memory_key,
        "_open_hot_path_or_report",
        lambda *a, **k: pytest.fail("opened native vault before preceding broker"),
    )
    if operation == "rotate":
        assert vault_memory_key.set_memory_key(root=root / "mordred/vault", rotate=True) == 1
    else:
        assert memory_cli.purge(home=root, root=root / "mordred/vault") == 1
    assert snapshot(root) == before and backend.calls == []


@pytest.mark.parametrize("command", [["databases", "status"], ["encryption", "status"], ["mail", "status", "--json"]])
def test_real_dispatch_and_database_bootstrap_are_passive(tmp_path, command):
    import json
    import os
    import subprocess
    import sys

    root = tmp_path / "home"
    (root / "mordred").mkdir(parents=True, mode=0o700)
    (root / "mordred/db-encryption.marker").write_bytes(b"retained unknown marker\n")
    (root / "state.db").write_bytes(b"retained opaque database")
    before = snapshot(root)
    script = r"""
import json, os, sys, types
from pathlib import Path
sys.dont_write_bytecode = True
sys.argv = ['hermes-mordred', *json.loads(sys.argv[1])]
audit = types.ModuleType('mordred_hermes._audit_support')
audit.safe_audit_append = lambda *args, **kwargs: None
sys.modules[audit.__name__] = audit
from mordred_hermes.dbcrypt import _key
_key.KeyProvider = lambda *a, **k: (_ for _ in ()).throw(AssertionError('startup constructed provider'))
root = str(Path(os.environ['HERMES_HOME']))
def observe(event, args):
    if event == 'sqlite3.connect':
        raise AssertionError('status opened SQL')
    if event == 'open' and str(args[0]).startswith(root):
        if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            raise AssertionError('status wrote a file')
    mutation = event in {'os.mkdir', 'os.remove', 'os.rename', 'os.chmod', 'os.rmdir'}
    if mutation and any(str(a).startswith(root) for a in args):
        raise AssertionError('status changed filesystem')
sys.addaudithook(observe)
from mordred_hermes.keyvault import _config_bootstrap, _runtime_env
_config_bootstrap.materialize_config = lambda **k: (_ for _ in ()).throw(AssertionError('startup materialized config'))
_runtime_env.inject_vault_env = lambda **k: (_ for _ in ()).throw(AssertionError('startup unwrapped env vault'))
from mordred_hermes import _pth_bootstrap, _runtime_bootstrap
assert _pth_bootstrap.run() is True
assert _runtime_env.install_vault_env_decrypt() == 0
_runtime_bootstrap._install_database_encryption()
from mordred_hermes.wizard.cli import main
assert main(sys.argv[1:]) == 0
"""
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(command)],
        env={**os.environ, "HERMES_HOME": str(root), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert snapshot(root) == before


def test_dependency_appearing_after_windows_proof_refuses_final_guard(native_root, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _memory_storage
    from mordred_hermes.wizard import _windows_memory

    root, backend, _, _ = native_root
    # Only the independent source exists before proof; remove database marker
    # so the first complete mutation scan can admit the load-only proof phase.
    (root / "mordred/db-encryption.marker").unlink()
    report = SimpleNamespace(managed=True, sealed=("MEMORY.md",), broken=(), pending=(), opted_out=False, armed=True)
    monkeypatch.setattr(_windows_memory, "observe", lambda *a, **k: SimpleNamespace(report=report))
    monkeypatch.setattr(_windows_memory, "_preflight", lambda *a: None)
    monkeypatch.setattr(_windows_memory, "_helper_refusal", lambda *a: None)
    monkeypatch.setattr(_windows_memory, "_gate", lambda *a, **k: 0)

    def prove(*a, **k):
        from mordred_hermes._database_lifecycle import acquire_runtime

        # A real SH lease proves the parent has released its early EX guard.
        with acquire_runtime(root, timeout=0):
            (root / "state.db").write_bytes(b"appeared during proof")
        return object()

    monkeypatch.setattr(_windows_memory, "_prove", prove)
    monkeypatch.setattr(
        _memory_storage, "disable_memory_encryption", lambda *a, **k: pytest.fail("final scan admitted new dependency")
    )
    assert _windows_memory.disable(home=root) == 1
    assert backend.calls == [] and (root / "mordred/memory-key.wrapped").exists()


def test_native_offline_conversion_none_key_authenticates_once_per_ex_operation(native_root):
    import sqlite3

    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.dbcrypt._marker import Marker, read_marker

    root, backend, _, snapshot = native_root
    path = root / "state.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
        conn.execute("INSERT INTO sample VALUES ('preserved')")
    report = _migrate.migrate(root, None, arm=dbcrypt.arm, holders_of=lambda paths: [])
    assert report.converted == ["state.db"] and read_marker(root) == Marker(snapshot)
    assert sum(op == "ecdh" for op, _ in backend.calls) == 1
    backend.calls.clear()
    report = _migrate.decrypt_all(root, None, holders_of=lambda paths: [])
    assert report.converted == ["state.db"]
    assert sum(op == "ecdh" for op, _ in backend.calls) == 1
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT value FROM sample").fetchall() == [("preserved",)]
    assert (root / "mordred/db-key-source.json").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["encryption", "disable", "memory"],
        ["encryption", "enable", "--non-interactive", "all"],
        ["encryption", "purge", "memory", "--yes"],
        ["vault", "set-memory-key", "--root", "/isolated/vault", "--rotate"],
        ["vault", "init"],
        ["vault", "recover", "--root=/isolated/vault"],
        ["keyvault", "init", "--paper-only"],
        ["keyvault", "reset", "-y"],
        ["keyvault", "recover", "--blob", "/isolated/backup"],
        ["keyvault", "native", "init", "--role", "memory"],
    ],
)
def test_source_ceremonies_do_not_install_ambient_runtime(args, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    monkeypatch.setattr("sys.argv", ["hermes-mordred", *args])
    assert maintenance_process()


@pytest.mark.parametrize(
    "args",
    [
        ["encryption", "enable"],
        ["encryption", "disable", "memory", "--bogus"],
        ["vault", "recover", "--root"],
        ["keyvault", "recover"],
        ["keyvault", "native", "init", "--role", "mail"],
        ["mail", "status", "--password", "prompt"],
        ["databases", "unknown"],
        ["encryption", "status", "unexpected"],
        ["uninstall", "--unknown"],
    ],
)
def test_malformed_commands_do_not_disable_runtime_protection(args, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    monkeypatch.setattr("sys.argv", ["hermes-mordred", *args])
    assert not maintenance_process()


@pytest.mark.parametrize(
    "args",
    [
        ["encryption", "status"],
        ["mail", "status"],
        ["databases", "diagnose"],
        ["vault", "set-memory-key", "--rotate"],
        ["keyvault", "reset", "--yes"],
    ],
)
def test_startup_vault_installers_do_not_unwrap_or_cache_ceremonies(tmp_path, monkeypatch, args):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _config_bootstrap, _runtime_env

    monkeypatch.setattr("sys.argv", ["hermes-mordred", *args])
    monkeypatch.setattr(_config_bootstrap, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(_runtime_env, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(_config_bootstrap, "materialize_config", lambda **k: pytest.fail("startup materialized config"))
    monkeypatch.setattr(_runtime_env, "inject_vault_env", lambda **k: pytest.fail("startup unwrapped env vault"))
    monkeypatch.setattr(_runtime_env, "_INJECTED_INTO_OS_ENVIRON", False)
    assert _config_bootstrap.install_config_decrypt(home=tmp_path) == 0
    assert _runtime_env.install_vault_env_decrypt() == 0
    assert _runtime_env._INJECTED_INTO_OS_ENVIRON is False


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes", "mordred", "encryption", "--profile", "work", "disable", "memory"],
        ["hermes", "--model", "mordred encryption disable memory", "mordred", "databases", "status"],
        ["hermes-mordred", "encryption", "status", "--help"],
    ],
)
def test_profiles_and_option_values_are_parsed_before_maintenance_admission(argv, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    monkeypatch.setattr("sys.argv", argv)
    assert maintenance_process()


@pytest.mark.parametrize(
    "argv",
    [
        ["python", "mordred", "encryption", "disable", "memory"],
        ["hermes", "--model", "mordred", "encryption", "disable", "memory"],
        ["hermes", "mordred", "vault", "set-memory-key", "--root", "encryption", "disable", "memory"],
    ],
)
def test_only_actual_command_boundaries_admit_maintenance(argv, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    # An earlier test may have imported the Hermes bootstrap; this process is
    # not a Hermes command boundary.
    monkeypatch.delitem(sys.modules, "hermes_bootstrap", raising=False)
    monkeypatch.setattr("sys.argv", argv)
    assert not maintenance_process()


@pytest.mark.parametrize(
    "command",
    [
        ["encryption", "disable", "memory"],
        ["vault", "set-memory-key", "--rotate"],
        ["keyvault", "reset", "--yes"],
    ],
)
def test_real_source_ceremony_startup_has_no_implicit_custody(tmp_path, command):
    import json
    import os
    import subprocess
    import sys

    root = tmp_path / "home"
    root.mkdir(mode=0o700)
    script = r"""
import json, os, sys, types
sys.dont_write_bytecode = True
sys.argv = ['hermes-mordred', *json.loads(sys.argv[1])]
audit = types.ModuleType('mordred_hermes._audit_support')
audit.safe_audit_append = lambda *a, **k: None
sys.modules[audit.__name__] = audit
from mordred_hermes.dbcrypt import _key
_key.KeyProvider = lambda *a, **k: (_ for _ in ()).throw(AssertionError('implicit runtime custody'))
from mordred_hermes.keyvault import _config_bootstrap, _runtime_env
_config_bootstrap.materialize_config = lambda **k: (_ for _ in ()).throw(AssertionError('implicit config custody'))
_runtime_env.inject_vault_env = lambda **k: (_ for _ in ()).throw(AssertionError('implicit env custody'))
from mordred_hermes import _runtime_bootstrap, _pth_bootstrap
_runtime_bootstrap._install_database_encryption()
assert _pth_bootstrap.run() is True
assert _runtime_env.install_vault_env_decrypt() == 0
# Exercise the actual public parser while leaving the explicit ceremony to its
# separately tested owning engine. Startup must neither authorize nor execute it.
import argparse
from mordred_hermes.wizard._cli_parsers import _setup_subparser
parser = argparse.ArgumentParser()
_setup_subparser(parser)
assert parser.parse_args(sys.argv[1:]).func is not None
"""
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(command)],
        env={**os.environ, "HERMES_HOME": str(root), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert list(root.iterdir()) == []


@pytest.mark.parametrize(
    "argv",
    [
        ["hermes", "--profile", "--oneshot", "mordred", "encryption", "status"],
        ["hermes", "--profile=", "mordred", "encryption", "status"],
        ["hermes", "--model", "--oneshot", "mordred", "encryption", "status"],
    ],
)
def test_malformed_root_option_values_do_not_grant_maintenance(argv, monkeypatch):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    monkeypatch.setattr("sys.argv", argv)
    assert not maintenance_process()
