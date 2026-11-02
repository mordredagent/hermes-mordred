"""Uninstall proof checks real databases; only native hardware is substituted."""

from __future__ import annotations

import contextlib
import sqlite3
import threading
import zipfile

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _migrate
from tests.test_dbcrypt_adoption import cipher
from tests.test_dbcrypt_authority import native_root as native_root


def plain(path):
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE messages(body TEXT)")
        connection.execute("INSERT INTO messages VALUES ('hello')")
    connection.close()
    path.chmod(0o600)


def test_plaintext_permit_requires_real_verification_and_live_lease(tmp_path):
    from mordred_hermes._database_uninstall import check_authorization
    from mordred_hermes.dbcrypt._uninstall import preflight, verified

    plain(tmp_path / "state.db")
    with acquire_exclusive(tmp_path) as lease:
        report = preflight(tmp_path, lease=lease, purge=False)
        with verified(report, lease=lease) as permit:
            check_authorization(permit, root=tmp_path, lease=lease, purpose="restore")
            with pytest.raises(DatabaseRefused):
                check_authorization(permit, root=tmp_path, lease=lease, purpose="delete")
    with acquire_exclusive(tmp_path) as next_lease, pytest.raises(DatabaseRefused):
        check_authorization(permit, root=tmp_path, lease=next_lease, purpose="restore")


@pytest.mark.parametrize("change", ["new", "replace", "modify", "forge", "thread"])
def test_permit_rejects_changed_inventory_and_foreign_owner(tmp_path, change):
    from mordred_hermes._database_uninstall import UninstallAuthorization, check_authorization
    from mordred_hermes.dbcrypt._uninstall import preflight, verified

    path = tmp_path / "state.db"
    plain(path)
    with acquire_exclusive(tmp_path) as lease:
        report = preflight(tmp_path, lease=lease, purge=True)
        with verified(report, lease=lease) as permit:
            if change == "new":
                plain(tmp_path / "new.db")
            elif change == "replace":
                path.unlink()
                plain(path)
            elif change == "modify":
                with sqlite3.connect(path) as connection:
                    connection.execute("INSERT INTO messages VALUES ('changed')")
            elif change == "forge":
                permit = object.__new__(UninstallAuthorization)
            if change == "thread":
                errors = []

                def other():
                    try:
                        check_authorization(permit, root=tmp_path, lease=lease, purpose="delete")
                    except DatabaseRefused as exc:
                        errors.append(exc)

                thread = threading.Thread(target=other)
                thread.start()
                thread.join()
                assert errors
            else:
                with pytest.raises(DatabaseRefused):
                    check_authorization(permit, root=tmp_path, lease=lease, purpose="delete")


@pytest.mark.parametrize(
    "name", ["state.db", "state.db.bak", "mordred/db-backups.journal.json", "state.db.mordred-enc"]
)
def test_corrupt_or_pending_state_refuses_before_changes(tmp_path, name):
    from mordred_hermes.dbcrypt._uninstall import preflight

    path = tmp_path / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"not a database or valid record")
    with acquire_exclusive(tmp_path) as lease, pytest.raises(DatabaseRefused):
        preflight(tmp_path, lease=lease, purge=False)
    assert path.read_bytes() == b"not a database or valid record"


def test_restore_proves_every_profile_against_preflight(native_root, monkeypatch):
    from mordred_hermes._database_uninstall import check_authorization
    from mordred_hermes.dbcrypt._uninstall import preflight, verified

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    plain(root / "profiles/work/state.db")
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        report = preflight(root, lease=lease, purge=True)
        _migrate.decrypt_all(root, None)
        with verified(report, lease=lease) as permit:
            check_authorization(permit, root=root, lease=lease, purpose="delete")
        with sqlite3.connect(root / "state.db") as connection:
            assert connection.execute("SELECT body FROM messages").fetchone() == ("private 日本語",)


@pytest.mark.parametrize("checked_policy", [False, True])
def test_registered_backup_retained_and_exportable_after_decrypt(native_root, monkeypatch, checked_policy):
    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._uninstall import preflight, verified

    root, _, key, _ = native_root
    cipher(root / "state.db", key)
    backup = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(root / "state.db", backup, authority=authority)
    finally:
        authority.close()
    before = backup.read_bytes()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        with pytest.raises(DatabaseRefused, match="backup"):
            preflight(root, lease=lease, purge=True)
        report = preflight(root, lease=lease, purge=False)
        _migrate.decrypt_all(root, None)
        with verified(report, lease=lease):
            pass
    # Fresh lease and native authentication, as after uninstall/reinstall.
    from mordred_hermes._private_fs import open_private_directory

    output_dir = root.parent / (root.name + "-export's directory")
    with open_private_directory(output_dir, create=True):
        pass
    output = output_dir / "plain.db"
    if checked_policy:
        offline = _migrate._offline_connection

        @contextlib.contextmanager
        def checked_offline(path, **kwargs):
            with offline(path, **kwargs) as connection:
                connection._install_export_policy(kwargs.get("target"), kwargs.get("alias"))
                yield connection

        monkeypatch.setattr(_migrate, "_offline_connection", checked_offline)
    with acquire_exclusive(root) as lease:
        _backup.export_database(root, backup, output, lease=lease)
        with pytest.raises(DatabaseRefused):
            _backup.export_database(root, backup, output, lease=lease)
    assert backup.read_bytes() == before
    with sqlite3.connect(output) as connection:
        assert connection.execute("SELECT body FROM messages").fetchone() == ("private 日本語",)


def test_zip_backup_export_preserves_archive(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.dbcrypt._uninstall import preflight, verified

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    (root / "backups").mkdir(mode=0o700)
    archive = root / "backups/history.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.write(source, "history/state.db")
    archive.chmod(0o600)
    before = archive.read_bytes()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        report = preflight(root, lease=lease, purge=False)
        _migrate.decrypt_all(root, None)
        with verified(report, lease=lease):
            pass
        output = root.parent / (root.name + "-export.db")
        _backup.export_database(root, archive, output, member="history/state.db", lease=lease)
    assert archive.read_bytes() == before
    with sqlite3.connect(output) as connection:
        assert connection.execute("SELECT count(*) FROM messages").fetchone() == (1,)


def test_new_dependency_during_permit_issuance_refuses(tmp_path, monkeypatch):
    from mordred_hermes import _database_uninstall as permissions
    from mordred_hermes.dbcrypt._uninstall import preflight, verified

    plain(tmp_path / "state.db")
    with acquire_exclusive(tmp_path) as lease:
        report = preflight(tmp_path, lease=lease, purge=True)
        original = permissions.fingerprint

        def replaced(root):
            if not (root / "new.db").exists():
                plain(root / "new.db")
            return original(root)

        monkeypatch.setattr(permissions, "fingerprint", replaced)
        with pytest.raises(DatabaseRefused), verified(report, lease=lease):
            pytest.fail("unverified new dependency was authorized")


def test_backup_export_cli_requires_paths_and_routes(tmp_path, monkeypatch):
    import argparse

    from mordred_hermes.wizard import _cli_parsers, databases_cli

    parser = argparse.ArgumentParser()
    _cli_parsers._setup_subparser(parser)
    args = parser.parse_args(
        ["databases", "backup", "export", "--source", "backup.zip", "--member", "state.db", "--output", "new.db"]
    )
    assert args.member == "state.db"
    monkeypatch.setattr(databases_cli, "_home", lambda: tmp_path)
    # Invalid source fails clearly without creating an output, not status success.
    assert databases_cli.cli_databases(args) == 1
    assert not (tmp_path / "new.db").exists()


def test_export_rejects_replaced_verified_staging(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.dbcrypt._authority import Authority

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    backup = root.parent / (root.name + "-backup.db")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, backup, authority=authority)
    finally:
        authority.close()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    schema = _migrate._schema

    def replace_after_verifying(path, *args, **kwargs):
        result = schema(path, *args, **kwargs)
        if path.name.endswith("-plain.db"):
            path.unlink()
            plain(path)  # An unrelated valid DB after the original was checked.
        return result

    monkeypatch.setattr(_migrate, "_schema", replace_after_verifying)
    output = root.parent / (root.name + "-result.db")
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        _backup.export_database(root, backup, output, lease=lease)
    assert not output.exists()
    assert backup.exists()


def test_final_preflight_cannot_authorize_new_encrypted_database(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _uninstall

    root, _, key, _ = native_root
    plain(root / "state.db")
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    with acquire_exclusive(root) as lease:
        report = _uninstall.preflight(root, lease=lease, purge=True)
        (root / "mordred/db-encryption.marker").unlink()
        original = _uninstall.preflight

        def changed(*args, **kwargs):
            cipher(root / "new.db", key)
            return original(*args, **kwargs)

        monkeypatch.setattr(_uninstall, "preflight", changed)
        with pytest.raises(DatabaseRefused), _uninstall.verified(report, lease=lease):
            pytest.fail("new encrypted file received deletion authority")


def test_unregistered_encrypted_backup_refuses_without_conversion(native_root, monkeypatch):
    from mordred_hermes.dbcrypt._uninstall import preflight

    root, _, key, _ = native_root
    backup = root / "state.db.pre-update.bak"
    cipher(backup, key)
    before = backup.read_bytes()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    for purge in (False, True):
        with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused, match="backup"):
            preflight(root, lease=lease, purge=purge)
    assert backup.read_bytes() == before


def test_export_copy_does_not_follow_replaced_staging(native_root, monkeypatch):
    from pathlib import Path

    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.dbcrypt._authority import Authority

    root, _, key, _ = native_root
    source = root / "state.db"
    cipher(source, key)
    backup = root.parent / (root.name + "-copy-backup.db")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(source, backup, authority=authority)
    finally:
        authority.close()
    victim = root.parent / (root.name + "-unrelated.txt")
    victim.write_bytes(b"preserve unrelated data")
    original_open = Path.open

    def substituted(path, *args, **kwargs):
        if path == backup and args and args[0] == "rb":
            for staged in root.parent.glob(".mordred-export-*.db"):
                staged.unlink()
                staged.symlink_to(victim)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", substituted)
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    output = root.parent / (root.name + "-copy-result.db")
    with acquire_exclusive(root) as lease, pytest.raises((DatabaseRefused, OSError)):
        _backup.export_database(root, backup, output, lease=lease)
    assert victim.read_bytes() == b"preserve unrelated data"
    assert not output.exists()
