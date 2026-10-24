"""Explicit real-custody maintenance gate; never provision native keys here.

The operator supplies an existing synthetic, natively provisioned root named
mordred-dbcrypt-*. Its database source must already be enrolled. Each subprocess
sets HERMES_HOME before importing Mordred and suppresses the audit sink. Missing
native/driver/holder prerequisites FAIL after opt-in; they never become skips.
Windows uses a scoped eligibility patch after real Task5 acceptance; this is
not production activation or directory/power-loss qualification.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("MORDRED_DBCRYPT_NATIVE_TEST") != "1", reason="explicit real-native database maintenance gate"
    ),
]

_SCRIPT = r"""
import os
import sys
from pathlib import Path
root = Path(os.environ['MORDRED_DBCRYPT_TEST_ROOT'])
assert os.environ['HERMES_HOME'] == str(root)
# Isolate audit before importing any operation that may unwrap real custody.
from mordred_hermes.keyvault import kek
kek._noop_audit = lambda entry: None
import sqlcipher3.dbapi2 as sc
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.dbcrypt import _backup, _migrate
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._key import derive
from mordred_hermes.dbcrypt._marker import read_marker, write_marker
from mordred_hermes.dbcrypt._shim import apply_key
from mordred_hermes.keyvault._database_authority import observe_database_source, load_database_source
def run():
    operation, direction, phase = sys.argv[1:]
    path = root / 'task7-native.db'
    backup = root.parent / (root.name + '-task7-native.backup')
    if operation == 'prepare':
        with acquire_exclusive(root) as lease:
            snapshot = observe_database_source(root=root)
            key = derive(load_database_source(root=root, expected=snapshot))
            files = _migrate.database_paths(root)
            assert files in ([], [path]), 'gate root contains unrelated databases'
            assert not _migrate.journal_path(root).exists(), 'recover previous gate first'
            assert not (root / 'mordred/db-backups.journal.json').exists(), 'recover backup gate first'
            if path.exists():
                assert _migrate.holders([path]) == [], 'native holder proof unavailable'
                with open_private_directory(root) as directory, directory.transaction() as tx:
                    tx.delete_file(path.name, expected_identity=tx.stat(path.name).identity)
            _migrate._disarm(root)
            _migrate._reserve(path)
            with _migrate._offline_connection(path) as connection:
                if direction != 'encrypt':
                    apply_key(connection, key)
                connection.execute('CREATE TABLE task7_fixture(value TEXT)')
                connection.execute("INSERT INTO task7_fixture VALUES ('native crash fixture 日本語')")
                connection.commit()
            connection.close()
            if os.name != 'nt':
                path.chmod(0o600)
            if direction == 'adopt':
                _migrate._put_legacy_marker(root)
            elif direction != 'encrypt':
                write_marker(root, snapshot, lease=lease)
            assert _migrate.holders([path]) == [], 'native holder proof unavailable'
    elif operation == 'crash':
        def crash(point):
            if point == phase:
                os._exit(86)
        if direction == 'backup':
            _backup._transition = crash
            authority = Authority.acquire(root)
            try:
                _backup.backup_database(path, backup, authority=authority)
            finally:
                authority.close()
        else:
            _migrate._transition = crash
            with acquire_exclusive(root) as lease:
                snapshot = observe_database_source(root=root)
                key = derive(load_database_source(root=root, expected=snapshot))
                if direction == 'adopt':
                    _migrate.adopt_legacy(root, lease=lease)
                elif direction == 'encrypt':
                    _migrate.migrate(root, key, arm=lambda root: (_ for _ in ()).throw(AssertionError('raw arm')))
                else:
                    _migrate.decrypt_all(root, key)
        raise AssertionError('requested durable transition not reached')
    else:
        if direction == 'backup':
            from mordred_hermes._database_contracts import DatabaseRefused
            from mordred_hermes._database_inventory import assert_mutation_safe
            with acquire_exclusive(root) as lease:
                snapshot = observe_database_source(root=root)
                try:
                    assert_mutation_safe(root, snapshot.generation, lease)
                except DatabaseRefused:
                    pass
                else:
                    raise AssertionError('published backup did not retain its key')
                _backup.recover_backups(root, lease=lease)
            authority = Authority.acquire(root)
            try:
                _backup.delete_backup(backup, authority=authority)
            finally:
                authority.close()
        else:
            _migrate.resume(root)
        with acquire_exclusive(root) as lease:
            snapshot = observe_database_source(root=root)
            key = derive(load_database_source(root=root, expected=snapshot))
            with _migrate._offline_connection(path, readonly=True) as connection:
                if direction != 'decrypt':
                    apply_key(connection, key)
                rows = connection.execute('SELECT value FROM task7_fixture').fetchall()
                assert rows == [('native crash fixture 日本語',)]
            connection.close()
            assert not _migrate.journal_path(root).exists()
            assert (read_marker(root) is None) == (direction == 'decrypt')

from contextlib import ExitStack
from unittest.mock import patch
with ExitStack() as eligibility:
    if sys.platform == 'win32':
        import ctypes
        assert os.environ.get('MORDRED_DBCRYPT_NATIVE_TEST') == '1'
        assert root.is_absolute() and root.is_dir() and root.name.startswith('mordred-dbcrypt-')
        assert not ctypes.windll.shell32.IsUserAnAdmin(), 'ordinary-token evidence is required'
        with open_private_directory(root), open_private_directory(root.parent):
            pass
        # Parent runs this gate only after real Task5 76/41 native acceptance.
        # Fresh-process eligibility override; actual native/driver I/O stays real.
        os.environ['MORDRED_DBCRYPT_WINDOWS_VFS_TEST'] = '1'
        eligibility.enter_context(patch('mordred_hermes.dbcrypt._windows_vfs.NATIVE_QUALIFIED', True))
    run()

"""


@pytest.fixture
def native_root():
    text = os.environ.get("MORDRED_DBCRYPT_TEST_ROOT")
    assert text, "opt-in requires an explicit pre-provisioned synthetic root"
    root = Path(text)
    assert root.is_absolute() and root.is_dir() and root == root.resolve(strict=True)
    assert root.name.startswith("mordred-dbcrypt-")
    assert root != Path.home() / ".hermes"
    assert not root.is_symlink()
    return root


@pytest.mark.parametrize(
    "direction,phase",
    [
        (direction, phase)
        for direction in ("encrypt", "decrypt")
        for phase in ("prepared", "verified", "armed", "swapped", "complete", "removed")
    ]
    + [("adopt", phase) for phase in ("verified", "armed", "complete")]
    + [("backup", "published")]
    + (
        [(direction, phase) for direction in ("encrypt", "decrypt") for phase in ("retained", "published", "retired")]
        if sys.platform == "win32"
        else []
    ),
)
def test_native_crash_subprocess_recovery(native_root, direction, phase):
    env = {**os.environ, "HERMES_HOME": str(native_root), "MORDRED_DBCRYPT_TEST_ROOT": str(native_root)}
    for operation, expected in [("prepare", 0), ("crash", 86), ("recover", 0)]:
        result = subprocess.run(
            [sys.executable, "-c", _SCRIPT, operation, direction, phase],
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
        )
        assert result.returncode == expected, f"{operation}: {result.stdout}\n{result.stderr}"
