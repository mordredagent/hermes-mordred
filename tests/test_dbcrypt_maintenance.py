"""EX-only component SQL: fake custody, real same-driver SQLCipher, no native acceptance."""

from __future__ import annotations

import os

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._connection import open_protected
from tests.test_dbcrypt_authority import native_root as native_root


def seed(root):
    authority = Authority.acquire(root)
    try:
        conn = open_protected(root / "component.db", authority=authority)
        conn.execute("CREATE TABLE records(value TEXT)")
        conn.execute("INSERT INTO records VALUES ('original 日本語')")
        conn.commit()
        conn.close()
    finally:
        authority.close()
    return root / "component.db"


def test_scope_materializes_rows_and_one_auth_for_all_statements(native_root):
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root, backend, _, _ = native_root
    path = seed(root)
    with acquire_exclusive(root) as lease, maintenance_scope(root, lease=lease) as scope:
        calls = list(backend.calls)
        with scope.connection(path) as conn:
            rows = conn.execute("SELECT value FROM records")
            assert rows.fetchall() == (("original 日本語",),)
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany("INSERT INTO records VALUES (?)", [("one",), ("two",)])
            conn.commit()
            assert conn.execute("SELECT count(*) FROM records").fetchone() == (3,)
            assert conn.execute("PRAGMA temp_store").fetchone() == (2,)
            assert conn.execute("PRAGMA mmap_size").fetchone() == (0,)
        assert rows.fetchall() == (("original 日本語",),)
        assert backend.calls == calls
        with scope.connection(path, readonly=True) as reader:
            assert reader.execute("SELECT count(*) FROM records").fetchone() == (3,)
    with pytest.raises(DatabaseRefused), scope.connection(path):
        pass


def test_fake_or_released_ex_never_authenticates(native_root):
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root, backend, _, _ = native_root

    class Fake:
        def assert_held(self, home):
            raise AssertionError("duck-typed lease was used")

    calls = list(backend.calls)
    for invalid in (None, Fake()):
        with pytest.raises(DatabaseRefused), maintenance_scope(root, lease=invalid):
            pass
    with acquire_exclusive(root) as old:
        pass
    with pytest.raises(DatabaseRefused), maintenance_scope(root, lease=old):
        pass
    assert backend.calls == calls


@pytest.mark.parametrize("mutation", ["marker", "source", "path", "profile"])
def test_scope_revocation_rolls_back_without_reauthentication(native_root, mutation):
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root, backend, _, _ = native_root
    home = root / "profiles/work" if mutation == "profile" else root
    path = seed(home)
    with acquire_exclusive(root) as lease:
        with (
            pytest.raises(DatabaseRefused),
            maintenance_scope(home, lease=lease) as scope,
            scope.connection(path) as conn,
        ):
            calls = list(backend.calls)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO records VALUES ('must roll back')")
            if mutation == "marker":
                (root / "mordred/db-encryption.marker").unlink()
            elif mutation == "source":
                (root / "mordred/db-key-source.json").write_bytes(b"changed")
            elif mutation == "profile":
                home.rename(root / "profiles/previous")
                home.mkdir(mode=0o700)
            else:
                path.rename(home / "previous.db")
                path.write_bytes(b"changed")
            conn.commit()
        assert backend.calls == calls
    # Verify rollback through the same owning library after the scope is gone,
    # using the original fixture key rather than any reauthentication.
    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._shim import apply_key

    original = (
        (root / "profiles/previous/component.db")
        if mutation == "profile"
        else (root / "previous.db" if mutation == "path" else path)
    )
    raw = sc.connect(str(original))
    try:
        apply_key(raw, derive(native_root[2]))
        assert raw.execute("SELECT value FROM records").fetchall() == [("original 日本語",)]
    finally:
        raw.close()


@pytest.mark.parametrize(
    "sql",
    [
        "ATTACH DATABASE ':memory:' AS leak",
        "PRAGMA key='leak'",
        "PRAGMA rekey='leak'",
        "PRAGMA temp_store=FILE",
        "PRAGMA mmap_size=4096",
        "SELECT load_extension('leak')",
        "SELECT sqlcipher_export('leak')",
        "VACUUM INTO ':memory:'",
        "PRAGMA cipher_plaintext_header_size=0",
        "INSERT INTO records VALUES ('x') RETURNING value",
    ],
)
def test_scope_denies_escape_and_terminally_refuses(native_root, sql):
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root = native_root[0]
    path = seed(root)
    with (
        acquire_exclusive(root) as lease,
        pytest.raises(DatabaseRefused),
        maintenance_scope(root, lease=lease) as scope,
    ):
        with pytest.raises(DatabaseRefused), scope.connection(path) as conn:
            conn.execute(sql)
        with pytest.raises(DatabaseRefused), scope.connection(path):
            pass


def test_registered_backup_readonly_and_unregistered_foreign_refused(native_root):
    from mordred_hermes.dbcrypt._backup import backup_database
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root = native_root[0]
    path = seed(root)
    backup = root.parent / (root.name + "-component.backup")
    authority = Authority.acquire(root)
    try:
        backup_database(path, backup, authority=authority)
    finally:
        authority.close()
    with acquire_exclusive(root) as lease, maintenance_scope(root, lease=lease) as scope:
        with scope.connection(backup, readonly=True) as conn:
            assert conn.execute("SELECT value FROM records").fetchall() == (("original 日本語",),)
        with pytest.raises(DatabaseRefused), scope.connection(backup):
            pass
    foreign = root.parent / (root.name + "-unregistered.db")
    os.link(backup, foreign)
    with (
        acquire_exclusive(root) as lease,
        maintenance_scope(root, lease=lease) as scope,
        pytest.raises(DatabaseRefused),
        scope.connection(foreign, readonly=True),
    ):
        pass


@pytest.mark.filterwarnings("ignore:This process.*multi-threaded:DeprecationWarning")
def test_scope_fork_refuses_before_inherited_sql_or_lease_locks(native_root):
    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork ownership")
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root = native_root[0]
    path = seed(root)
    with (
        acquire_exclusive(root) as lease,
        maintenance_scope(root, lease=lease) as scope,
        scope.connection(path) as conn,
    ):
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO records VALUES ('parent pending')")
        child = os.fork()
        if child == 0:
            try:
                conn.execute("INSERT INTO records VALUES ('child escape')")
            except DatabaseRefused:
                os._exit(0)
            os._exit(9)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert conn.execute("SELECT count(*) FROM records").fetchone() == (2,)
        conn.rollback()


def test_scope_thread_refusal_terminally_closes_without_sql(native_root):
    import threading

    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root = native_root[0]
    path = seed(root)
    errors = []
    with (
        acquire_exclusive(root) as lease,
        pytest.raises(DatabaseRefused),
        maintenance_scope(root, lease=lease) as scope,
        scope.connection(path) as conn,
    ):

        def attempt():
            try:
                conn.execute("INSERT INTO records VALUES ('thread escape')")
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=attempt)
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert len(errors) == 1 and isinstance(errors[0], DatabaseRefused)


def test_pending_state_refuses_scope_before_any_sql(native_root):
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root = native_root[0]
    path = seed(root)
    (root / "mordred/db-encryption.pending").write_text("pending")
    with (
        acquire_exclusive(root) as lease,
        pytest.raises(DatabaseRefused),
        maintenance_scope(root, lease=lease) as scope,
        scope.connection(path),
    ):
        pytest.fail("pending state admitted SQL")


def test_releasing_actual_lease_revokes_open_scope_before_sql(native_root):
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope

    root, backend, _, _ = native_root
    path = seed(root)
    lease_context = acquire_exclusive(root)
    lease = lease_context.__enter__()
    try:
        with (
            pytest.raises(DatabaseRefused),
            maintenance_scope(root, lease=lease) as scope,
            scope.connection(path) as conn,
        ):
            calls = list(backend.calls)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO records VALUES ('pending')")
            lease_context.__exit__(None, None, None)
            conn.commit()
        assert backend.calls == calls
    finally:
        lease_context.__exit__(None, None, None)


@pytest.mark.parametrize("changed_values", [False, True])
def test_registered_identity_survives_registry_to_sql_handoff(native_root, monkeypatch, changed_values):
    import shutil

    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.dbcrypt import _backup
    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._maintenance import maintenance_scope
    from mordred_hermes.dbcrypt._shim import apply_key

    root, _, material, _ = native_root
    path = seed(root)
    backup = root.parent / (root.name + "-registered.backup")
    replacement = root.parent / (root.name + "-replacement.backup")
    authority = Authority.acquire(root)
    try:
        _backup.backup_database(path, backup, authority=authority)
    finally:
        authority.close()
    shutil.copyfile(backup, replacement)
    replacement.chmod(0o600)
    if changed_values:
        raw = sc.connect(str(replacement))
        try:
            apply_key(raw, derive(material))
            raw.execute("UPDATE records SET value='unregistered changed value'")
            raw.commit()
        finally:
            raw.close()
    registered_identity = backup.stat().st_ino
    real_find = _backup._find

    def swapped_after_find(home, source, snapshot):
        entry = real_find(home, source, snapshot)
        assert source == backup
        os.replace(replacement, backup)
        assert backup.stat().st_ino != registered_identity
        return entry

    monkeypatch.setattr(_backup, "_find", swapped_after_find)
    with (
        acquire_exclusive(root) as lease,
        maintenance_scope(root, lease=lease) as scope,
        pytest.raises(DatabaseRefused),
        scope.connection(backup, readonly=True),
    ):
        pytest.fail("a replacement inode was admitted using the original inode's registration")
