"""Windows refuses retained macOS database state without opening databases."""

from __future__ import annotations

import sys

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.dbcrypt import _migrate
from mordred_hermes.wizard import databases_cli, memory_cli, uninstall_cli
from mordred_hermes.wizard._uninstall_config import ConfigCleanup
from mordred_hermes.wizard.uninstall_cli import UninstallOptions, run_uninstall
from tests.test_windows_custody import fs as fs
from tests.test_windows_memory_proof import installed_runtime as installed_runtime
from tests.test_windows_memory_proof import proof_env as proof_env
from tests.test_wizard_windows_memory import win as win
from tests.test_wizard_windows_uninstall import Runner, context
from tests.test_wizard_windows_uninstall import hermes_files as hermes_files

STATES = (
    "db-encryption.marker",
    "db-encryption.pending",
    "db-decryption.pending",
    "db-encryption.journal.json",
)


def put_state(home, name):
    with open_private_directory(home / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(name, b"retained state\n")


@pytest.mark.parametrize("name", STATES)
@pytest.mark.parametrize("profile", [False, True])
def test_uninstall_refuses_retained_database_state_before_any_cleanup(
    win, monkeypatch, hermes_files, capsys, name, profile
):
    env = win
    env.runner = Runner()
    put_state(env.home, name)
    home = env.home
    if profile:
        with open_private_directory(home / "profiles", create=True):
            pass
        home = home / "profiles" / "work"
        with open_private_directory(home, create=True):
            pass
    database = home / "state.db"
    database.write_bytes(b"retained encrypted database content")
    monkeypatch.setattr(
        uninstall_cli, "plan_config_cleanup", lambda path: ConfigCleanup(path, removed=["plugins.enabled: mordred"])
    )
    monkeypatch.setattr(uninstall_cli, "uninstall_packages", lambda *args, **kwargs: pytest.fail("package removed"))
    monkeypatch.setattr(memory_cli, "disable", lambda **kwargs: pytest.fail("memory modified before database refusal"))
    calls = list(env.backend.calls)
    assert run_uninstall(context(env, home=home), UninstallOptions(yes=True)) == 1
    err = capsys.readouterr().err
    assert "database" in err and "macOS" in err
    assert database.read_bytes() == b"retained encrypted database content"
    assert (env.home / "mordred" / name).read_bytes() == b"retained state\n"
    assert hermes_files == [] and env.runner.calls == [] and env.backend.calls == calls


def test_uninstall_rechecks_database_state_after_confirmation(win, monkeypatch, hermes_files, capsys):
    env = win
    env.runner = Runner()
    with open_private_directory(env.home / "mordred", create=True):
        pass
    monkeypatch.setattr(
        uninstall_cli, "plan_config_cleanup", lambda path: ConfigCleanup(path, removed=["plugins.enabled: mordred"])
    )

    def confirm(_ctx, _opts, plan):
        assert not any(item.target == "databases" for item in plan.restores)
        put_state(env.home, "db-encryption.marker")
        return True

    monkeypatch.setattr(uninstall_cli, "_confirm", confirm)
    monkeypatch.setattr(uninstall_cli, "uninstall_packages", lambda *args, **kwargs: pytest.fail("package removed"))
    monkeypatch.setattr(memory_cli, "purge", lambda **kwargs: pytest.fail("custody purged"))
    calls = list(env.backend.calls)
    assert run_uninstall(context(env), UninstallOptions(yes=True, purge_data=True)) == 1
    assert "database" in capsys.readouterr().err
    assert hermes_files == [] and env.runner.calls == [] and env.backend.calls == calls


@pytest.mark.parametrize("name", [None, *STATES])
def test_windows_database_status_does_not_discover_or_promise_conversion(fs, monkeypatch, capsys, name):
    _, _, home, backend = fs
    if name:
        put_state(home, name)
    database = home / "state.db"
    database.write_bytes(b"do not inspect this database")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_migrate, "discover", lambda *args: pytest.fail("unsupported database discovery"))
    assert databases_cli.databases_status(home=home) == (1 if name else 0)
    captured = capsys.readouterr()
    assert "unsupported" in captured.out.lower()
    assert "runs the next time Hermes starts" not in captured.out
    assert "Database encryption: on" not in captured.out
    if name:
        assert "macOS" in captured.err
    assert database.read_bytes() == b"do not inspect this database" and backend.calls == []


def test_windows_database_status_refuses_unknown_checked_home(fs, monkeypatch, capsys):
    from mordred_hermes import _config_io

    _, _, home, backend = fs
    monkeypatch.setattr(sys, "platform", "win32")

    def unsafe(_home):
        raise PrivateFSError("unsafe", "test-DO-NOT-ECHO")

    monkeypatch.setattr(_config_io, "open_optional_confidential_directory", unsafe)
    monkeypatch.setattr(_migrate, "discover", lambda *args: pytest.fail("unsupported database discovery"))
    assert databases_cli.databases_status(home=home) == 1
    err = capsys.readouterr().err
    assert "unsafe" in err and "DO-NOT-ECHO" not in err
    assert backend.calls == []
