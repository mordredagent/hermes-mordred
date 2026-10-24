"""Actual checked export snapshots and policy-only database destinations."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

from mordred_hermes.activity._gate import ActivityRefused
from tests._activity_protection import native_root as native_root


def test_checked_source_yields_snapshot_after_source_identity_validation(tmp_path):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b'{"text":"original"}\n')
    with checked_import_source(source, home=tmp_path) as handle:
        source.write_bytes(b'{"text":"changed"}\n')
        assert handle.read() == b'{"text":"original"}\n'
    assert handle.closed


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "parent_symlink", "database", "sidecar", "writable"])
def test_unsafe_source_refuses_before_content_escapes(tmp_path, kind):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b"private content")
    if kind == "symlink":
        link = tmp_path / "link.jsonl"
        link.symlink_to(source)
        source = link
    elif kind == "hardlink":
        os.link(source, tmp_path / "second.jsonl")
    elif kind == "parent_symlink":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        source = link / source.name
    elif kind == "database":
        source = source.rename(tmp_path / "mordred.db")
    elif kind == "sidecar":
        source = source.rename(tmp_path / "mordred.db-journal")
    elif kind == "writable":
        source.chmod(0o666)
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pytest.fail("unsafe source escaped admission")


@pytest.mark.skipif(os.name != "posix", reason="POSIX isolated worker handoff")
def test_source_swap_during_worker_handoff_is_refused(tmp_path, monkeypatch):
    import subprocess

    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b"original")
    real_popen = subprocess.Popen

    def swap_before_exec(args, *pargs, **kwargs):
        source.rename(tmp_path / "original.jsonl")
        source.write_bytes(b"replacement")
        return real_popen(args, *pargs, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", swap_before_exec)
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pytest.fail("swapped source escaped worker handoff admission")


def test_database_source_is_never_raw_opened(tmp_path, monkeypatch):
    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "plugin-data/mordred/mordred.db"

    def forbidden(*args, **kwargs):
        raise AssertionError("raw database open")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pass


def test_destination_is_policy_only_and_creates_nothing(tmp_path):
    from mordred_hermes.imports._protected_destination import checked_store_destination

    expected = tmp_path / "plugin-data/mordred/mordred.db"
    assert checked_store_destination(expected, home=tmp_path) == expected
    assert not expected.parent.exists()
    with pytest.raises(ActivityRefused):
        checked_store_destination(tmp_path / "other.db", home=tmp_path)


def test_destination_rejects_planted_parent(tmp_path):
    from mordred_hermes.imports._protected_destination import checked_store_destination

    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "plugin-data").symlink_to(target, target_is_directory=True)
    with pytest.raises(ActivityRefused):
        checked_store_destination(tmp_path / "plugin-data/mordred/mordred.db", home=tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX per-process SQLCipher advisory locks")
@pytest.mark.parametrize("consumer", ["export", "peer"])
def test_live_sqlcipher_lock_survives_rejected_database_alias(native_root, monkeypatch, tmp_path, consumer):
    import json
    import subprocess
    import sys
    import threading

    import sqlcipher3.dbapi2 as sc

    from mordred_hermes.activity import peers
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.imports._protected_destination import checked_import_source

    root = native_root[0]
    database = root / "protected.db"
    source = root / ("peer.json" if consumer == "peer" else "export.jsonl")
    source.write_bytes(b'{"original":true}\n')
    source.chmod(0o600)
    authority = Authority.acquire(root)
    conn = open_protected(database, authority=authority)
    conn.execute("CREATE TABLE records(value TEXT)")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    key = authority.key
    real_popen, real_open = subprocess.Popen, os.open
    parent_source_opens, worker_database_opens, errors = [], [], []
    threads = []
    owned_fds = set()

    def pipe():
        pair = os.pipe()
        owned_fds.update(pair)
        return pair

    def close(fd):
        if fd in owned_fds:
            owned_fds.remove(fd)
            os.close(fd)

    def swap_alias():
        source.unlink()
        os.link(database, source)

    def legacy_parent_open(path, flags, *args, **kwargs):
        if Path(path) == source:
            parent_source_opens.append(path)
            swap_alias()
        return real_open(path, flags, *args, **kwargs)

    runner = tmp_path / "source-race-runner.py"
    runner.write_text(
        """import os, runpy, sys
assert sys.flags.isolated and sys.flags.no_site
assert 'HERMES_MEMORY_KEY' not in os.environ and 'HERMES_HOME' not in os.environ
helper, target, expected_inode = sys.argv[1], sys.argv[2], int(sys.argv[3])
ready, proceed = int(sys.argv[4]), int(sys.argv[5])
module = runpy.run_path(helper)
assert not any(name.startswith(('mordred_hermes', 'sqlcipher3')) for name in sys.modules)
real_open = os.open
def intercepted(path, flags, *args, **kwargs):
    if os.fspath(path) == target:
        os.write(ready, b'R')
        assert os.read(proceed, 1) == b'G'
        descriptor = real_open(path, flags, *args, **kwargs)
        if os.fstat(descriptor).st_ino == expected_inode:
            os.write(ready, b'D')
        return descriptor
    return real_open(path, flags, *args, **kwargs)
os.open = intercepted
raise SystemExit(module['main']())
""",
        encoding="utf-8",
    )

    def launch_with_child_handoff(args, *pargs, **kwargs):
        if isinstance(args, (list, tuple)) and Path(args[-1]).name == "_posix_source.py":
            ready_r, ready_w = pipe()
            go_r, go_w = pipe()
            command = [
                *args[:3],
                str(runner),
                str(args[-1]),
                str(source),
                str(database.stat().st_ino),
                str(ready_w),
                str(go_r),
            ]
            process = real_popen(command, *pargs, pass_fds=(ready_w, go_r), **kwargs)
            close(ready_w)
            close(go_r)

            def handoff():
                try:
                    assert os.read(ready_r, 1) == b"R"
                    swap_alias()
                    os.write(go_w, b"G")
                    worker_database_opens.append(os.read(ready_r, 1) == b"D")
                except BaseException as error:
                    errors.append(error)
                    with contextlib.suppress(OSError):
                        os.write(go_w, b"G")

            worker = threading.Thread(target=handoff)
            worker.start()
            threads.append(worker)
            return process
        return real_popen(args, *pargs, **kwargs)

    competitor = """import json, sys
sys.path.insert(0, sys.argv[1])
import sqlcipher3.dbapi2 as sc
key, salt = json.loads(sys.stdin.read())
connection = sc.connect(sys.argv[2], timeout=0)
connection.execute("PRAGMA key = " + chr(34) + "x" + chr(39) + key + chr(39) + chr(34))
connection.execute('PRAGMA cipher_plaintext_header_size=112')
connection.execute("PRAGMA cipher_salt = " + chr(34) + "x" + chr(39) + salt + chr(39) + chr(34))
connection.execute('SELECT count(*) FROM sqlite_master').fetchall()
try:
    connection.execute('BEGIN IMMEDIATE')
except sc.OperationalError as error:
    if 'locked' not in str(error).lower() and 'busy' not in str(error).lower():
        raise
    code = 0
else:
    connection.rollback()
    code = 9
connection.close()
raise SystemExit(code)
"""

    def reserved_lock_is_held():
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", competitor, str(Path(sc.__file__).parents[1]), str(database)],
            input=json.dumps([key.key.hex(), key.salt.hex()]),
            text=True,
            capture_output=True,
            env={"HERMES_HOME": str(root)},
            timeout=10,
        )
        assert result.returncode in (0, 9), result.stderr
        return result.returncode == 0

    try:
        assert reserved_lock_is_held(), "fixture did not establish a real cross-process RESERVED lock"
        monkeypatch.setattr(os, "open", legacy_parent_open)
        monkeypatch.setattr(subprocess, "Popen", launch_with_child_handoff)
        if consumer == "peer":
            with pytest.raises(RuntimeError):
                peers._read(source)
        else:
            with pytest.raises(ActivityRefused), checked_import_source(source, home=root):
                pytest.fail("swapped database alias escaped admission")
        for worker in threads:
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert errors == []
        source.unlink()  # remove the transient alias before guarded DB rechecks
        assert reserved_lock_is_held(), "rejected source close released the live SQLCipher RESERVED lock"
        assert parent_source_opens == []
        assert worker_database_opens == [True], "regression did not reach an actual database-alias open in the child"
    finally:
        for fd in tuple(owned_fds):
            close(fd)
        source.unlink(missing_ok=True)
        conn.rollback()
        conn.close()
        authority.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX isolated worker transport")
def test_posix_snapshot_transport_rejects_truncated_success(tmp_path, monkeypatch):
    import subprocess

    from mordred_hermes.imports._protected_destination import checked_import_source

    source = tmp_path / "export.jsonl"
    source.write_bytes(b"original")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, b"x"))
    with pytest.raises(ActivityRefused), checked_import_source(source, home=tmp_path):
        pytest.fail("a truncated snapshot was accepted as the observed source")
