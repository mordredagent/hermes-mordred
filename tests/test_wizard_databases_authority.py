"""Legacy offline callers cannot consume runtime-native authority keys."""

from __future__ import annotations

import os

import pytest

from mordred_hermes._core._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._key import KeyProvider
from tests.test_dbcrypt_authority import native_root as native_root


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_native_offline_commands_use_ex_without_runtime_provider(native_root, monkeypatch, capsys, command, dry_run):
    from mordred_hermes import dbcrypt
    from mordred_hermes._core._database_lifecycle import current_thread_exclusive_leases
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.dbcrypt._capability import DatabaseStatus
    from mordred_hermes.wizard import databases_cli

    root, backend, _, _ = native_root
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    monkeypatch.setattr(dbcrypt, "database_status", lambda home: DatabaseStatus(True, 1, "unknown", False, None))
    monkeypatch.setattr(
        dbcrypt._runtime, "database_status", lambda home: DatabaseStatus(True, 1, "unknown", False, None)
    )
    monkeypatch.setattr(KeyProvider, "__call__", lambda self: pytest.fail("offline command consumed runtime SH key"))
    calls = []

    def convert(home, key, **kwargs):
        assert home == root and key is None
        leases = current_thread_exclusive_leases()
        assert len(leases) == 1
        leases[0].assert_held(root)
        calls.append(command)
        return _migrate.Report()

    monkeypatch.setattr(_migrate, "migrate" if command == "encrypt" else "decrypt_all", convert)
    assert getattr(databases_cli, "databases_" + command)(home=root, dry_run=dry_run) == 0
    assert calls == ([] if dry_run else [command])
    assert backend.calls == []
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("directory_mode", [0o700, 0o755])
def test_legacy_arm_cannot_downgrade_native_marker(native_root, directory_mode):
    from mordred_hermes import dbcrypt

    root, backend, _, _ = native_root
    (root / "mordred").chmod(directory_mode)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    with pytest.raises(DatabaseRefused):
        dbcrypt.arm(root)
    assert backend.calls == []
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX legacy directory modes")
def test_legacy_arm_is_idempotent_in_owned_0755_directory(tmp_path):
    from mordred_hermes import dbcrypt

    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    dbcrypt.arm(tmp_path)
    marker = dbcrypt.marker_path(tmp_path)
    before_bytes = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    before_modes = {path: path.stat().st_mode for path in tmp_path.rglob("*")}
    before_identity = (marker.stat().st_dev, marker.stat().st_ino)
    dbcrypt.arm(tmp_path)
    assert marker.read_bytes() == b"1\n"
    assert directory.stat().st_mode & 0o777 == 0o755
    assert marker.stat().st_mode & 0o777 == 0o600
    assert (marker.stat().st_dev, marker.stat().st_ino) == before_identity
    assert {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before_bytes
    assert {path: path.stat().st_mode for path in tmp_path.rglob("*")} == before_modes


@pytest.mark.skipif(os.name != "posix", reason="POSIX legacy directory/file admission")
@pytest.mark.parametrize("damage", ["unknown", "mode", "symlink", "hardlink", "directory", "fifo"])
def test_legacy_arm_in_0755_directory_refuses_unsafe_or_unknown_entries(tmp_path, damage):
    from mordred_hermes import dbcrypt

    directory = tmp_path / "mordred"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    dbcrypt.arm(tmp_path)
    marker = dbcrypt.marker_path(tmp_path)
    if damage == "unknown":
        marker.write_bytes(b"x\n")
    elif damage == "mode":
        marker.chmod(0o644)
    elif damage == "symlink":
        target = tmp_path / "target"
        marker.rename(target)
        marker.symlink_to(target)
    elif damage == "hardlink":
        (tmp_path / "alias").hardlink_to(marker)
    else:
        marker.unlink()
        if damage == "directory":
            marker.mkdir(mode=0o700)
        else:
            os.mkfifo(marker, mode=0o600)
    before_bytes = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    before_metadata = {path: (path.lstat().st_mode, path.lstat().st_ino) for path in tmp_path.rglob("*")}
    with pytest.raises(DatabaseRefused):
        dbcrypt.arm(tmp_path)
    assert {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before_bytes
    assert {path: (path.lstat().st_mode, path.lstat().st_ino) for path in tmp_path.rglob("*")} == before_metadata


def _recover_args(*flags):
    import argparse

    from mordred_hermes.wizard import _cli_parsers

    parser = argparse.ArgumentParser()
    _cli_parsers._setup_subparser(parser)
    return parser.parse_args(["databases", "backup", "recover", *flags])


def test_backup_recover_cli_outcomes(native_root, monkeypatch, capsys):
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    journal = root / "mordred/db-backups.journal.json"
    monkeypatch.setattr(databases_cli, "_home", lambda: root)

    assert databases_cli.cli_databases(_recover_args()) == 0
    assert "nothing to recover" in capsys.readouterr().out
    assert databases_cli.cli_databases(_recover_args("--abandon", "--yes")) == 0
    assert "nothing to abandon" in capsys.readouterr().out

    destination = _crashed_backup(native_root, monkeypatch, "published")
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args("--yes")) == 1
    assert "--yes applies only to --abandon" in capsys.readouterr().err
    assert journal.exists()

    assert databases_cli.cli_databases(_recover_args("--abandon")) == 1
    out = capsys.readouterr().out
    assert str(destination) in out and ".mordred-backup-" in out
    assert "unmanaged encrypted copy" in out and "Preview only" in out
    assert journal.exists()

    assert databases_cli.cli_databases(_recover_args()) == 0
    assert f"finished and registered: {destination}" in capsys.readouterr().out
    assert not journal.exists()


def test_backup_recover_abandon_yes_removes_only_the_journal(native_root, monkeypatch, capsys):
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    destination = _crashed_backup(native_root, monkeypatch, "published")
    before = destination.read_bytes()
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args("--abandon", "--yes", "--accept-unmanaged-copy")) == 0
    assert "Abandoned" in capsys.readouterr().out
    assert not (root / "mordred/db-backups.journal.json").exists()
    assert destination.read_bytes() == before


def test_backup_recover_failure_points_at_abandon(native_root, monkeypatch, capsys):
    import shutil

    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    gone = root.parent / (root.name + "-gone")
    gone.mkdir(mode=0o700)
    _crashed_backup(native_root, monkeypatch, "verified", destination=gone / "x.backup")
    shutil.rmtree(gone)
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args()) == 1
    err = capsys.readouterr().err
    assert "the journal may remain" in err and "--abandon" in err
    assert (root / "mordred/db-backups.journal.json").exists()


def test_backup_recover_escapes_control_characters_in_journal_paths(native_root, monkeypatch, capsys):
    import json

    from mordred_hermes.dbcrypt._backup import BackupRecovery
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    _crashed_backup(native_root, monkeypatch, "verified")
    journal = root / "mordred/db-backups.journal.json"
    data = json.loads(journal.read_bytes())
    data["destination"] = str(root.parent / "evil\nfake line\x1b[31m.backup")
    data["prepared"] = str(root.parent / "evil\nfake line\x1b[31m.backup.mordred-backup-ab")
    journal.write_text(json.dumps(data))
    capsys.readouterr()

    assert databases_cli.cli_databases(_recover_args("--abandon")) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\nfake line" not in out
    assert "evil\\nfake line\\x1b[31m.backup" in out

    bad = root.parent / "evil\nfake\x1b[31m.backup"
    for outcome in ("published", "deleted"):
        assert databases_cli._report_recovery(BackupRecovery(outcome, bad)) == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\nfake" not in out and "evil\\nfake\\x1b[31m.backup" in out


def test_status_prints_backup_recovery_line_without_changing_capability(native_root, capsys):
    from mordred_hermes.dbcrypt import database_status
    from mordred_hermes.wizard import databases_cli

    root = native_root[0]
    fields = lambda status: (status.configured, status.capability, status.authenticated, status.reason)  # noqa: E731
    before = fields(database_status(root))
    assert databases_cli.databases_status(home=root) == 0
    assert "backup recovery" not in capsys.readouterr().out

    (root / "mordred/db-backups.journal.json").write_bytes(b"{}")
    assert fields(database_status(root)) == before
    assert databases_cli.databases_status(home=root) == 0
    assert "backup recovery: required unless a backup is running" in capsys.readouterr().out
    assert databases_cli.databases_status(home=root / "profiles/work") == 0  # lexical root
    assert "backup recovery: required" in capsys.readouterr().out


def test_backup_recovery_state_is_unknown_when_metadata_is_unreadable(tmp_path, monkeypatch):
    from pathlib import Path

    from mordred_hermes.dbcrypt._capability import backup_recovery_required

    assert backup_recovery_required(tmp_path) is False

    def denied(self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "lstat", denied)
    assert backup_recovery_required(tmp_path) is None


@pytest.mark.parametrize(
    ("flags", "accepted"),
    [
        ([], True),
        (["--abandon"], True),
        (["--abandon", "--yes"], True),
        (["--abandon", "--yes", "--accept-unmanaged-copy"], True),
        (["--yes"], True),  # parses; the handler rejects it
        (["--bogus"], False),
        (["extra"], False),
    ],
)
def test_backup_recover_grammar_matches_the_startup_exemption(flags, accepted):
    from mordred_hermes.dbcrypt._cli import maintenance_process

    argv = ["hermes-mordred", "databases", "backup", "recover", *flags]
    assert maintenance_process(argv) is accepted
    if accepted:
        assert _recover_args(*flags).backup_command == "recover"
    else:
        with pytest.raises(SystemExit):
            _recover_args(*flags)


def test_backup_recover_yes_alone_keeps_journal_when_a_copy_may_remain(native_root, monkeypatch, capsys):
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    destination = _crashed_backup(native_root, monkeypatch, "published")
    journal = root / "mordred/db-backups.journal.json"
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args("--abandon", "--yes")) == 1
    out = capsys.readouterr().out
    assert "Not abandoned" in out and "--accept-unmanaged-copy" in out and "Preview only" not in out
    assert journal.exists()

    assert databases_cli.cli_databases(_recover_args("--accept-unmanaged-copy")) == 1
    assert "applies only to --abandon --yes" in capsys.readouterr().err
    assert journal.exists() and destination.exists()


def test_backup_abandon_output_after_removal_never_offers_recover(native_root, monkeypatch, capsys):
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    _crashed_backup(native_root, monkeypatch, "verified")
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args("--abandon", "--yes", "--accept-unmanaged-copy")) == 0
    out = capsys.readouterr().out
    assert "now an unmanaged encrypted copy" in out and "can no longer finish it" in out
    assert "publishes and registers" not in out and "would become" not in out


def test_backup_abandon_output_says_a_registered_destination_stays_protected(native_root, monkeypatch, capsys):
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    _crashed_backup(native_root, monkeypatch, "registered")
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args("--abandon")) == 1
    out = capsys.readouterr().out
    assert "already registered" in out and "stays protected" in out
    assert "unmanaged" not in out and "--accept-unmanaged-copy" not in out


def test_backup_abandon_output_for_a_preparing_journal_says_rebuilds(native_root, monkeypatch, capsys):
    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    _crashed_backup(native_root, monkeypatch, "staged")
    capsys.readouterr()
    assert databases_cli.cli_databases(_recover_args("--abandon")) == 1
    out = capsys.readouterr().out
    assert "rebuilds the staged copy" in out and "publishes and registers" not in out


def test_backup_recover_reports_non_os_failures_without_a_traceback(native_root, monkeypatch, capsys):
    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.wizard import databases_cli

    class SqliteLikeError(Exception):
        pass

    def fail(*_args, **_kwargs):
        raise SqliteLikeError("disk I/O error")

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    monkeypatch.setattr(_backup, "recover_backups", fail)
    assert databases_cli.cli_databases(_recover_args()) == 1
    err = capsys.readouterr().err
    assert "disk I/O error" in err and "the journal may remain" in err


def test_backup_recover_output_survives_a_legacy_stream_encoding(native_root, monkeypatch, capsys):
    import io
    import sys

    from mordred_hermes.wizard import databases_cli
    from tests.test_dbcrypt_backup import _crashed_backup

    root = native_root[0]
    monkeypatch.setattr(databases_cli, "_home", lambda: root)
    destination = root.parent / (root.name + "-日本語.backup")
    _crashed_backup(native_root, monkeypatch, "verified", destination=destination)
    capsys.readouterr()
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    assert databases_cli.cli_databases(_recover_args()) == 0
    stream.flush()
    assert b"finished and registered" in stream.buffer.getvalue()
    assert b"\\u65e5" in stream.buffer.getvalue()
    assert destination.exists() and not (root / "mordred/db-backups.journal.json").exists()
