"""Native NTFS admission for Windows Telegram credentials and archive (C10b).

Real private/confidential admission, binary SID, physical home identity,
ACLs, hardlinks, junctions and a competing process lock. Only the CNG backend
is injected; host-skipped off Windows and selected by the scoped Windows CI job.
"""

import os
import subprocess
import sys
import time

import pytest

from mordred_hermes.extension.telegram import secrets, store
from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore
from mordred_hermes.keyvault import _windows_custody as custody
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS Telegram custody and archive")

KEY = b"\x42" * 32


def _value():
    return secrets.TelegramSecrets(
        api_id=12345, api_hash="ab" * 16, store_key=KEY, session="SYNTHETIC-SESSION", venice_api_key="SYNTHETIC"
    )


@pytest.fixture
def native_telegram(shared_home):
    home = shared_home
    backend = FakeBackend()
    with custody.windows_custody_session(home, create=True, backend=backend) as session:
        session.enroll_memory()
        session.enroll_role("audit")
        leases = {"telegram": session.enroll_role("telegram")}
    return home, backend, leases


def _store(home, backend):
    return WindowsCustodySecretStore(home, backend=backend, audit_sink=lambda entry: None)


def _archive(home):
    root = home / "mordred" / "telegram"
    archive = store.ArchiveStore(KEY, root)
    archive.save_index(store.ArchiveIndex(account_label="synthetic"))
    archive.append_messages(1, [store.StoredMessage(id=1, date=1, sender="A", text="synthetic")])
    return root, archive


def test_native_inherited_safe_home_roundtrip_and_forget_keep_shared_parent(native_telegram):
    home, backend, leases = native_telegram
    parent = descriptor(home)
    vault = _store(home, backend)
    vault.store(_value())
    assert vault.load() == _value()
    root, archive = _archive(home)
    assert archive.load_messages(1)[0].text == "synthetic"
    alias = home.with_name(home.name.upper())
    assert _store(alias, backend).load() == _value()  # case alias, same physical role
    store.wipe_archive(root, forget=True, backend=backend)
    assert not (root / "credentials.sealed").exists()
    assert not (root / "index.enc").exists()
    assert leases["telegram"].native_key_id not in backend._keys
    with custody.windows_custody_session(home, backend=backend) as session:
        session.lease("memory")
        session.lease("audit")
    assert descriptor(home) == parent


def test_native_inherited_telegram_directory_refuses_unchanged(native_telegram):
    home, backend, _ = native_telegram
    root = home / "mordred" / "telegram"
    os.mkdir(root)  # inherits Mordred's ACEs instead of an exact protected private DACL
    before = descriptor(root)
    with pytest.raises(secrets.TelegramSecretsError, match="custody_unsafe"):
        _store(home, backend).store(_value())
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        store.ArchiveStore(KEY, root).save_index(store.ArchiveIndex())
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        store.archive_busy(root)
    assert descriptor(root) == before
    assert not list(root.iterdir())


def test_native_broadened_sealed_file_acl_refuses_without_repair(native_telegram):
    home, backend, _ = native_telegram
    vault = _store(home, backend)
    vault.store(_value())
    path = home / "mordred" / "telegram" / "credentials.sealed"
    subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    before = (descriptor(path), path.read_bytes())
    for call in (vault.load, lambda: vault.store(_value()), vault.flags):
        with pytest.raises(secrets.TelegramSecretsError, match="custody_unsafe"):
            call()
    assert (descriptor(path), path.read_bytes()) == before


def test_native_hardlinked_archive_file_refuses_and_wipe_deletes_nothing(native_telegram):
    home, _backend, _ = native_telegram
    root, archive = _archive(home)
    os.link(root / "index.enc", home.parent / "index-alias")
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        archive.load_index()
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        store.wipe_archive(root)
    assert (root / "index.enc").exists()
    assert [p for p in (root / "dialogs").iterdir() if p.suffix == ".enc"]


def test_native_dialogs_junction_refuses_without_following(native_telegram, tmp_path):
    home, _backend, _ = native_telegram
    root, archive = _archive(home)
    target = tmp_path / "junction-target"
    from mordred_hermes._private_fs import open_private_directory

    with open_private_directory(target, create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(f"{archive.segment_name(1, 0)}.enc", b"not an archive segment")
    for child in (root / "dialogs").iterdir():
        if child.suffix == ".enc":
            child.unlink()
    os.unlink(root / "dialogs" / ".gitignore")
    os.unlink(root / "dialogs" / ".mordred-fs.lock")
    os.rmdir(root / "dialogs")
    junction = ["cmd.exe", "/c", "mklink", "/J", str(root / "dialogs"), str(target)]
    subprocess.run(junction, check=True, capture_output=True)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        archive.load_messages(1)
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        store.wipe_archive(root)
    assert sorted(p.name for p in target.iterdir() if p.suffix == ".enc") == [f"{archive.segment_name(1, 0)}.enc"]


def test_native_sync_lock_held_by_another_process_refuses_promptly(native_telegram):
    home, backend, _ = native_telegram
    vault = _store(home, backend)
    vault.store(_value())
    root, archive = _archive(home)
    script = """
import sys
from pathlib import Path
from mordred_hermes.extension.telegram import store
with store.ArchiveStore(b"\\x42" * 32, Path(sys.argv[1])).locked():
    print("locked", flush=True)
    sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", script, str(root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        from tests.test_config_io_windows import line

        assert line(process) == "locked"
        started = time.monotonic()
        assert store.archive_busy(root) is True
        with pytest.raises(store.StoreError, match="sync_in_progress"), archive.locked():
            pass
        with pytest.raises(store.StoreError, match="sync_in_progress"):
            store.wipe_archive(root, forget=True, backend=backend)
        assert time.monotonic() - started < 10
        assert (root / "credentials.sealed").exists() and (root / "index.enc").exists()
        assert vault.flags()["logged_in"] is True  # status never waits for a sync
    finally:
        process.communicate("done\n", timeout=20)
    assert process.returncode == 0
    assert store.archive_busy(root) is False
