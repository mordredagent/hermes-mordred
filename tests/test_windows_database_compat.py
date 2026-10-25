"""Windows retained-state refusal and passive capability never open databases."""

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
    assert "database" in err and "Nothing was removed" in err
    assert database.read_bytes() == b"retained encrypted database content"
    assert (env.home / "mordred" / name).read_bytes() == b"retained state\n"
    # Native Windows planning may inspect the installed interpreter read-only.
    # Teardown and custody mutation must still never run.
    assert hermes_files == [] and env.backend.calls == calls
    assert not any("uninstall" in argv for argv in env.runner.calls)


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
    assert hermes_files == [] and env.backend.calls == calls
    assert not any("uninstall" in argv for argv in env.runner.calls)


@pytest.mark.parametrize("name", [None, *STATES])
def test_windows_database_status_does_not_discover_or_promise_conversion(fs, monkeypatch, capsys, name):
    _, _, home, backend = fs
    if name:
        put_state(home, name)
    database = home / "state.db"
    database.write_bytes(b"do not inspect this database")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_migrate, "discover", lambda *args: pytest.fail("unsupported database discovery"))
    assert databases_cli.databases_status(home=home) == 0
    captured = capsys.readouterr()
    assert "authenticated: not checked" in captured.out
    assert "capability: unavailable" in captured.out
    assert "configured: " + ("yes" if name else "no") in captured.out
    assert "runs the next time Hermes starts" not in captured.out
    assert "Database encryption: on" not in captured.out
    assert captured.err == ""
    assert database.read_bytes() == b"do not inspect this database" and backend.calls == []


@pytest.mark.parametrize("failure", ["unsafe_lexical", "checked_inventory"])
def test_windows_database_status_refuses_unknown_checked_home(fs, monkeypatch, capsys, failure):
    _, _, home, backend = fs
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(_migrate, "discover", lambda *args: pytest.fail("unsafe database discovery"))
    # Exercise the current status boundary, retaining the original checked-IO
    # refusal/no-private-error-disclosure intent as well as unsafe lexical paths.
    selected = home
    if failure == "checked_inventory":
        from mordred_hermes import _database_inventory

        def unsafe(_home):
            raise PrivateFSError("unsafe", "test-DO-NOT-ECHO")

        monkeypatch.setattr(_database_inventory, "scan_dependencies", unsafe)
    else:
        selected = home / ".." / home.name
    before = {path.relative_to(home): path.read_bytes() for path in home.rglob("*") if path.is_file()}
    assert databases_cli.databases_status(home=selected) == 0
    captured = capsys.readouterr()
    assert "capability: unknown" in captured.out
    assert "dependencies: unknown" in captured.out
    assert (
        "inventory is incomplete" if failure == "checked_inventory" else "requires checked diagnosis"
    ) in captured.out
    assert "authenticated: not checked" in captured.out
    assert "DO-NOT-ECHO" not in captured.out + captured.err
    assert before == {path.relative_to(home): path.read_bytes() for path in home.rglob("*") if path.is_file()}
    assert captured.err == "" and backend.calls == []
