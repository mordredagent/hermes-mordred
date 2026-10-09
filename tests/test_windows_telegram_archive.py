"""Checked Windows Telegram archive, sync lock and logout/forget (C10b).

Real checked private transactions on the host, real MTG1 archive crypto and
real MRKW custody; only the native P-256 boundary, token SID and platform
admission are injected. ``store._platform`` selects the Windows dispatch.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.extension.telegram import secrets, store
from tests.test_windows_telegram_custody import (  # noqa: F401
    _value,
    code,
    custody_fixture,
    enroll,
    ops,
    posix_only,
    sealed_path,
    stat_mode,
    telegram_fs,
    windows_store,
)

KEY = b"\x42" * 32


def _msg(i, text="hello"):
    return store.StoredMessage(id=i, date=1_700_000_000 + i, sender="Alice", text=f"{text} {i}")


@pytest.fixture
def archive(tg):
    c, home, backend = tg
    with open_private_directory(home / "mordred", create=True):
        pass
    root = home / "mordred" / "telegram"
    return c, home, backend, root


def names(path):
    return sorted(p.name for p in path.iterdir())


@contextmanager
def held_in_thread(root):
    """Hold the sync lock from another thread (a separate lock descriptor)."""
    entered, release, failure = threading.Event(), threading.Event(), []

    def run():
        try:
            with store.ArchiveStore(KEY, root).locked():
                entered.set()
                release.wait(10)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failure.append(exc)
            entered.set()

    thread = threading.Thread(target=run)
    thread.start()
    assert entered.wait(10)
    assert not failure
    try:
        yield
    finally:
        release.set()
        thread.join(10)


# -- read/write through checked primitives ---------------------------------------------


def test_index_and_segments_roundtrip_with_private_layout(archive, monkeypatch):
    _c, _home, _backend, root = archive
    monkeypatch.setattr(store, "SEGMENT_SIZE", 3)
    s = store.ArchiveStore(KEY, root)
    assert s.load_index() == store.ArchiveIndex()
    assert s.load_messages(7) == []
    index = store.ArchiveIndex(account_label="me", account_id=9, last_sync=5)
    index.dialogs[7] = store.DialogInfo(dialog_id=7, kind="user", title="Alice", message_count=7)
    s.save_index(index)
    assert s.append_messages(7, [_msg(i) for i in range(1, 6)]) == 5
    assert s.append_messages(7, [_msg(i) for i in range(4, 8)]) == 2
    assert [m.id for m in s.load_messages(7)] == list(range(1, 8))
    assert s.load_index() == index
    assert names(root) == [".gitignore", ".mordred-fs.lock", "dialogs", "index.enc"]
    segments = [n for n in names(root / "dialogs") if n.endswith(".enc")]
    assert len(segments) == 3 and all(len(n) == 44 for n in segments)
    assert (root / ".gitignore").read_bytes() == store._GITIGNORE
    assert (root / "dialogs" / ".gitignore").read_bytes() == store._GITIGNORE
    for path in [root / "index.enc", *[root / "dialogs" / n for n in segments]]:
        assert b"hello" not in path.read_bytes() and b"Alice" not in path.read_bytes()
        if os.name != "nt":
            assert stat_mode(path) == 0o600
    if os.name != "nt":
        assert stat_mode(root) == stat_mode(root / "dialogs") == 0o700


def test_raw_posix_archive_paths_are_unreachable_on_windows(archive, monkeypatch):
    _c, _home, _backend, root = archive

    def forbidden(*args, **kwargs):
        raise AssertionError("raw POSIX archive I/O reached on Windows")

    from mordred_hermes.keyvault import _storage

    monkeypatch.setattr(_storage, "atomic_write", forbidden)
    monkeypatch.setattr(store, "_nonblocking_flock", forbidden)
    monkeypatch.setattr(os, "chmod", forbidden)
    s = store.ArchiveStore(KEY, root)
    with s.locked():
        s.save_index(store.ArchiveIndex(account_label="x"))
        s.append_messages(1, [_msg(1)])
        assert store.archive_busy(root) is True
    assert s.load_messages(1)[0].id == 1
    assert store.archive_busy(root) is False
    assert store.archive_updated(root) is not None
    store.wipe_archive(root)
    assert s.load_index() == store.ArchiveIndex()


def test_corrupt_or_swapped_archive_files_refuse_never_empty(archive, monkeypatch):
    _c, _home, _backend, root = archive
    monkeypatch.setattr(store, "SEGMENT_SIZE", 2)
    s = store.ArchiveStore(KEY, root)
    s.save_index(store.ArchiveIndex(account_label="me"))
    s.append_messages(1, [_msg(i) for i in range(1, 5)])
    index = root / "index.enc"
    good = index.read_bytes()
    index.write_bytes(good[:-3])
    with pytest.raises(store.StoreError, match="store_undecryptable"):
        s.load_index()
    index.write_bytes(b"")
    with pytest.raises(store.StoreError, match="store_undecryptable"):
        s.load_index()
    index.write_bytes(good)
    first, second = (root / "dialogs" / f"{s.segment_name(1, n)}.enc" for n in (0, 1))
    a, b = first.read_bytes(), second.read_bytes()
    first.write_bytes(b)
    second.write_bytes(a)
    with pytest.raises(store.StoreError, match="store_undecryptable"):
        s.load_messages(1)
    with pytest.raises(store.StoreError, match="store_undecryptable"):
        store.ArchiveStore(b"\x01" * 32, root).load_index()


@posix_only
def test_unsafe_archive_state_refuses_without_acl_repair(archive, tmp_path):
    _c, _home, _backend, root = archive
    s = store.ArchiveStore(KEY, root)
    s.save_index(store.ArchiveIndex(account_label="me"))
    s.append_messages(1, [_msg(1)])
    index = root / "index.enc"
    os.chmod(index, 0o644)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        s.load_index()
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        s.save_index(store.ArchiveIndex())
    # The whole wipe plan is validated first: no segment goes before the refusal.
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        store.wipe_archive(root)
    assert [n for n in names(root / "dialogs") if n.endswith(".enc")]
    assert stat_mode(index) == 0o644
    os.chmod(index, 0o600)
    dialogs = root / "dialogs"
    os.chmod(dialogs, 0o755)
    for call in (lambda: s.load_messages(1), lambda: s.append_messages(1, [_msg(2)]), lambda: store.wipe_archive(root)):
        with pytest.raises(store.StoreError, match="store_path_unsafe"):
            call()
    assert stat_mode(dialogs) == 0o755
    os.chmod(dialogs, 0o700)
    segment = dialogs / f"{s.segment_name(1, 0)}.enc"
    os.link(segment, tmp_path / "alias")
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        s.load_messages(1)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        store.wipe_archive(root)
    (tmp_path / "alias").unlink()
    index.unlink()
    index.symlink_to(segment)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        s.load_index()
    # Nothing was deleted by the refused wipes.
    assert segment.exists()


def test_oversized_archive_file_refuses(archive, monkeypatch):
    _c, _home, _backend, root = archive
    from mordred_hermes.extension.telegram import _windows_archive

    s = store.ArchiveStore(KEY, root)
    s.save_index(store.ArchiveIndex(account_label="me"))
    monkeypatch.setattr(_windows_archive, "MAX_FILE_BYTES", 16)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        s.load_index()
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        s.save_index(store.ArchiveIndex(account_label="a much longer label"))


# -- sync lock and busy semantics ----------------------------------------------------------


def test_sync_lock_is_non_blocking_in_process_and_across_threads(archive):
    _c, _home, _backend, root = archive
    s = store.ArchiveStore(KEY, root)
    assert store.archive_busy(root) is False  # absent archive: nothing is syncing
    with s.locked():
        assert store.archive_busy(root) is True
        with pytest.raises(store.StoreError, match="sync_in_progress"), s.locked():
            pass
        with pytest.raises(store.StoreError, match="sync_in_progress"):
            store.wipe_archive(root)
        # Data I/O and status reads never wait for the long-held sync lock.
        s.save_index(store.ArchiveIndex(account_label="during sync"))
        assert s.load_index().account_label == "during sync"
    assert store.archive_busy(root) is False
    with held_in_thread(root):
        assert store.archive_busy(root) is True
        with pytest.raises(store.StoreError, match="sync_in_progress"), s.locked():
            pass
        with pytest.raises(store.StoreError, match="sync_in_progress"):
            store.wipe_archive(root, forget=True)
    assert store.archive_busy(root) is False
    with s.locked():
        pass
    assert (root / "sync-lock" / ".mordred-fs.lock").exists()


def test_sync_lock_held_by_another_process_refuses_without_waiting(archive):
    _c, _home, _backend, root = archive
    import subprocess
    import sys
    import time

    s = store.ArchiveStore(KEY, root)
    s.save_index(store.ArchiveIndex(account_label="me"))
    with s.locked():
        pass  # create the dedicated sync-lock directory and its permanent lock
    holder = """
import sys
from mordred_hermes._private_fs import open_private_directory
with open_private_directory(sys.argv[1]) as d, d.transaction():
    print("locked", flush=True)
    sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", holder, str(root / "sync-lock")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "locked"
        started = time.monotonic()
        assert store.archive_busy(root) is True
        with pytest.raises(store.StoreError, match="sync_in_progress"), s.locked():
            pass
        with pytest.raises(store.StoreError, match="sync_in_progress"):
            store.wipe_archive(root)
        assert time.monotonic() - started < 5  # refused, never waited
        assert (root / "index.enc").exists()
        # Data reads/writes use other directory locks and still proceed.
        s.save_index(store.ArchiveIndex(account_label="concurrent"))
    finally:
        process.communicate("done\n", timeout=20)
    assert process.returncode == 0
    assert store.archive_busy(root) is False
    store.wipe_archive(root)
    assert not (root / "index.enc").exists()


def test_service_start_sync_holds_the_checked_lock_until_the_task_ends(archive, monkeypatch):
    c, home, backend, root = archive
    import asyncio

    from mordred_hermes.extension.telegram import service

    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value(store_key=KEY))
    gate = asyncio.Event()
    observed = []

    async def fake_sync(client, archive_store, *, options, progress):
        observed.append(store.archive_busy(root))
        await gate.wait()
        return service.SyncProgress()

    class Client:
        async def connect(self):
            return None

        async def is_user_authorized(self):
            return True

        async def disconnect(self):
            return None

    monkeypatch.setattr(service, "sync_archive", fake_sync)
    monkeypatch.setattr(service, "_audit", lambda *args, **kwargs: None)
    svc = service.TelegramService(
        secret_store=windows_store(home, backend),
        archive_root=root,
        client_factory=lambda *a, **k: Client(),
        installed=lambda: True,
        memory_guard=lambda: None,
    )

    async def run():
        await svc.start_sync()
        await asyncio.sleep(0)
        assert store.archive_busy(root) is True
        with pytest.raises(store.StoreError, match="sync_in_progress"):
            store.wipe_archive(root)
        gate.set()
        await svc.wait_for_sync()

    asyncio.run(run())
    assert observed == [True]
    assert store.archive_busy(root) is False
    assert svc._last_error is None


# -- wipe and logout/forget ------------------------------------------------------------------


def seed(home, backend, root, c):
    leases = enroll(c, home, backend, "memory", "audit", "telegram")
    windows_store(home, backend).store(_value(store_key=KEY))
    s = store.ArchiveStore(KEY, root)
    s.save_index(store.ArchiveIndex(account_label="me"))
    s.append_messages(1, [_msg(1)])
    s.append_messages(2, [_msg(2)])
    return leases


def test_wipe_without_forget_deletes_only_enumerated_archive_files(archive):
    c, home, backend, root = archive
    leases = seed(home, backend, root, c)
    with open_private_directory(root / "dialogs") as d, d.transaction() as tx:
        tx.create_bytes("unknown.bin", b"not ours")
    store.wipe_archive(root)
    assert not (root / "index.enc").exists()
    assert names(root / "dialogs") == [".gitignore", ".mordred-fs.lock", "unknown.bin"]
    # Credentials, metadata, the role and permanent locks remain; no rmtree.
    assert sealed_path(home).exists()
    assert (root / "credentials.meta.json").exists()
    assert (root / "sync-lock" / ".mordred-fs.lock").exists()
    assert windows_store(home, backend).load() == _value(store_key=KEY)
    with c.windows_custody_session(home, backend=backend) as session:
        session.validate_lease(leases["telegram"])
    assert ops(backend, "delete") == 0


def test_forget_deletes_archive_credentials_and_only_the_telegram_role(archive):
    c, home, backend, root = archive
    leases = seed(home, backend, root, c)
    with c.windows_custody_session(home, backend=backend) as session:
        memory_key = session.load_memory_key()
    store.wipe_archive(root, forget=True, backend=backend)
    assert not (root / "index.enc").exists()
    assert [n for n in names(root / "dialogs") if n.endswith(".enc")] == []
    assert not sealed_path(home).exists()
    assert not (root / "credentials.meta.json").exists()
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.role_status("telegram") == c.RoleStatus("telegram", None, (), False)
        session.validate_lease(leases["memory"])
        session.validate_lease(leases["audit"])
        assert session.load_memory_key() == memory_key
    assert leases["telegram"].native_key_id not in backend._keys
    assert {leases["memory"].native_key_id, leases["audit"].native_key_id} <= set(backend._keys)
    assert not (home / "mordred" / "windows-telegram.pending.json").exists()
    assert (home / "mordred" / "memory-key.wrapped").exists()
    assert windows_store(home, backend).load() is None
    # Forget is repeatable: nothing left, nothing generated.
    store.wipe_archive(root, forget=True, backend=backend)
    assert ops(backend, "generate") == 3


def test_forget_deletes_retained_generations_without_unsealing(archive, monkeypatch):
    c, home, backend, root = archive
    seed(home, backend, root, c)
    with c.windows_custody_session(home, backend=backend) as session:
        session.enroll_role("telegram", retain_current=True)
    from mordred_hermes.keyvault import wrap

    def tripwire(*args, **kwargs):
        raise AssertionError("forget must not unseal credentials")

    monkeypatch.setattr(wrap, "unwrap_dek", tripwire)
    store.wipe_archive(root, forget=True, backend=backend)
    assert ops(backend, "delete") == 2
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.role_status("telegram") == c.RoleStatus("telegram", None, (), False)


def test_ambiguous_native_deletion_stays_journaled_and_blocks_the_next_forget(archive, monkeypatch):
    c, home, backend, root = archive
    leases = seed(home, backend, root, c)
    real_delete = backend.delete_enclave_key

    def lost(key_id):
        real_delete(key_id)
        raise RuntimeError("native deletion result lost")

    monkeypatch.setattr(backend, "delete_enclave_key", lost)
    with pytest.raises(RuntimeError):
        store.wipe_archive(root, forget=True, backend=backend)
    journal = home / "mordred" / "windows-telegram.pending.json"
    assert journal.exists()
    before = journal.read_bytes()
    monkeypatch.setattr(backend, "delete_enclave_key", real_delete)
    # Recreate archive state: the next forget must refuse before deleting it.
    s = store.ArchiveStore(KEY, root)
    s.save_index(store.ArchiveIndex(account_label="again"))
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        store.wipe_archive(root, forget=True, backend=backend)
    assert code(excinfo) == "custody_uncertain"
    assert (root / "index.enc").exists()
    assert journal.read_bytes() == before
    with c.windows_custody_session(home, backend=backend) as session:
        session.validate_lease(leases["memory"])
        session.validate_lease(leases["audit"])
    assert ops(backend, "generate") == 3


@posix_only
def test_forget_with_copied_home_refuses_before_deleting_anything(archive, tmp_path):
    c, home, backend, root = archive
    seed(home, backend, root, c)
    import shutil

    copy = tmp_path / "copied"
    shutil.copytree(home, copy, symlinks=True)
    copied_root = copy / "mordred" / "telegram"
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        store.wipe_archive(copied_root, forget=True, backend=backend)
    assert code(excinfo) == "custody_broken"
    assert (copied_root / "index.enc").exists()
    assert (copied_root / "credentials.sealed").exists()
    assert ops(backend, "delete") == 0


def test_forget_requires_the_profile_telegram_directory(archive, tmp_path):
    _c, _home, backend, _root = archive
    with pytest.raises(ValueError):
        store.wipe_archive(tmp_path / "elsewhere", forget=True, backend=backend)


def test_forget_without_a_mordred_directory_is_a_noop(tg, tmp_path):
    _c, home, backend = tg
    store.wipe_archive(home / "mordred" / "telegram", forget=True, backend=backend)
    assert backend.calls == []
    assert not (home / "mordred").exists()


@posix_only
def test_posix_forget_flag_is_refused_and_posix_wipe_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "_platform", lambda: "darwin")
    s = store.ArchiveStore(KEY, tmp_path)
    s.save_index(store.ArchiveIndex(account_label="me"))
    with pytest.raises(store.StoreError, match="forget_unsupported"):
        store.wipe_archive(tmp_path, forget=True)
    assert (tmp_path / "index.enc").exists()
    store.wipe_archive(tmp_path)
    assert not (tmp_path / "index.enc").exists()
    assert (tmp_path / ".lock").exists()


def test_hermes_tool_coverage_uses_checked_metadata(archive, monkeypatch):
    _c, _home, _backend, root = archive
    from mordred_hermes.extension.telegram import hermes_tools

    monkeypatch.setattr(store, "telegram_dir", lambda: root)
    assert hermes_tools._coverage()["archive_updated"] is None
    store.ArchiveStore(KEY, root).save_index(store.ArchiveIndex(account_label="me"))
    coverage = hermes_tools._coverage()
    assert coverage["archive_updated"] is not None
    assert coverage["sync_running"] is False
    with store.ArchiveStore(KEY, root).locked():
        assert hermes_tools._coverage()["sync_running"] is True
