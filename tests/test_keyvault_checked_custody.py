"""Real checked keyvault producer feeding the native capability boundary."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _native_deletion as deletion
from mordred_hermes.keyvault import _native_key_id as ids
from mordred_hermes.keyvault import _storage
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps


def _owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    selector = ids.scoped_native_key_id(root, "default")
    meta = _storage.load_meta(root)
    meta["keys"][hashlib.sha256(b"default").digest()[:16].hex()] = {
        "key_id": "default",
        ids.NATIVE_KEY_ID_FIELD: selector,
    }
    _storage.save_meta(root, meta)
    _storage.atomic_write(root / "digests" / (hashlib.sha256(b"default").digest()[:16].hex() + ".commit"), b"v" * 32)
    calls = []
    ops = _HelperSecKeyOps("/not/executed")
    monkeypatch.setattr(_HelperSecKeyOps, "_invoke", lambda self, payload: calls.append(payload) or {"ok": True})
    backend = _SecKeyBackend(ops=ops, sw_ops=None)._for_keyvault_root(root)
    return root, selector, backend, calls


def test_real_checked_owner_deletes_and_expires(tmp_path, monkeypatch):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        owner = deletion._issue_native_owner(custody, native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            backend.delete_enclave_key(selector, deletion=permit)
    assert [p["cmd"] for p in calls] == ["delete"]
    with pytest.raises(DatabaseRefused):
        deletion._owned_delete_scope(owner, backend=backend, database_lease=None).__enter__()


@pytest.mark.parametrize(
    "mutation", ["backend", "selector", "metadata", "root", "thread", "fabricated", "lock", "commit"]
)
def test_real_checked_owner_refuses_changed_transaction(tmp_path, monkeypatch, mutation):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        owner = deletion._issue_native_owner(custody, native_key_id=selector, backend=backend)
        if mutation == "backend":
            backend = _SecKeyBackend(ops=backend._ops, sw_ops=None)
        elif mutation == "selector":
            with pytest.raises(DatabaseRefused):
                deletion._issue_native_owner(custody, native_key_id="mordred.memory", backend=backend)
            return
        elif mutation == "lock":
            lock = root / ".lock"
            lock.rename(root / ".old-lock")
            lock.write_bytes(b"")
            lock.chmod(0o600)
        elif mutation == "commit":
            (root / "digests" / (hashlib.sha256(b"default").digest()[:16].hex() + ".commit")).unlink()
        elif mutation == "metadata":
            _storage.save_meta(root, {"version": 1, "keys": {}})
        elif mutation == "root":
            root.rename(root.with_name("old"))
            root.mkdir(mode=0o700)
        elif mutation == "fabricated":
            custody = object.__new__(_storage.KeyvaultCustody)
            with pytest.raises(DatabaseRefused):
                deletion._issue_native_owner(custody, native_key_id=selector, backend=backend)
            return
        elif mutation == "thread":
            refused = []

            def attempt():
                try:
                    deletion._issue_native_owner(custody, native_key_id=selector, backend=backend)
                except DatabaseRefused:
                    refused.append(True)

            thread = threading.Thread(target=attempt)
            thread.start()
            thread.join()
            assert refused == [True]
            return
        with pytest.raises(DatabaseRefused), deletion._owned_delete_scope(owner, backend=backend, database_lease=None):
            pass
    assert calls == []


def test_reset_journal_rechecked_before_native_io(tmp_path, monkeypatch):
    from mordred_hermes.wizard import keyvault_cli

    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    _, encoded = keyvault_cli._encode_reset_journal(root, {"default": selector}, [], False)
    _storage.write_reset_journal(root, encoded)
    with _storage.keyvault_custody(root, backend=backend, reset=True) as custody:
        owner = deletion._issue_native_owner(custody, native_key_id=selector, backend=backend)
        payload = json.loads(encoded)
        payload["targets"][0][ids.NATIVE_KEY_ID_FIELD] = "hostile"
        _storage.write_reset_journal(root, json.dumps(payload).encode())
        with pytest.raises(DatabaseRefused), deletion._owned_delete_scope(owner, backend=backend, database_lease=None):
            pass
    assert calls == []


@pytest.mark.parametrize(
    "relative",
    [
        "state.db",
        "profiles/work/state.db",
        "mordred/db-encryption.pending",
        "backups/old.tgz",
        "mordred/db-key-source.json",
    ],
)
def test_reset_preserves_helper_and_all_database_dependencies(tmp_path, monkeypatch, relative):
    from mordred_hermes.wizard import keyvault_cli

    root, _, backend, calls = _owned(tmp_path, monkeypatch)
    helper_file = root / "tpm" / "synthetic-key"
    helper_file.parent.mkdir(mode=0o700)
    helper_file.write_bytes(b"native custody")
    dependency = tmp_path / relative
    dependency.parent.mkdir(parents=True, exist_ok=True)
    dependency.write_bytes(b"retained source or dependency")
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert helper_file.read_bytes() == b"native custody"
    assert dependency.read_bytes() == b"retained source or dependency"
    assert not _storage.reset_journal_path(root).exists()
    assert calls == []


def test_reset_final_inventory_precedes_journal(tmp_path, monkeypatch):
    from mordred_hermes.wizard import keyvault_cli

    root, _, backend, calls = _owned(tmp_path, monkeypatch)
    original = keyvault_cli._collect_reset_key_ids

    def late_dependency(root):
        result = original(root)
        (tmp_path / "state.db").write_bytes(b"new dependency")
        return result

    monkeypatch.setattr(keyvault_cli, "_collect_reset_key_ids", late_dependency)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert root.exists()
    assert not _storage.reset_journal_path(root).exists()
    assert calls == []


def test_real_reset_deletes_only_checked_targets(tmp_path, monkeypatch):
    from mordred_hermes.keyvault._seckey_errors import _application_tag
    from mordred_hermes.wizard import keyvault_cli

    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert not root.exists()
    assert not _storage.reset_journal_path(root).exists()
    assert calls == [{"cmd": "delete", "tag_hex": _application_tag(selector).hex()}]


def test_empty_checked_layout_reset_never_resolves_native_backend(tmp_path, monkeypatch):
    from mordred_hermes.wizard import keyvault_cli

    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    monkeypatch.setattr(keyvault_cli, "resolve_backend", lambda backend: pytest.fail("empty reset resolved backend"))
    assert keyvault_cli.reset_keyvault(home=tmp_path, assume_yes=True) == 0
    assert not root.exists()


def _audit_backend(backend, monkeypatch):
    from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecDuplicateItem, errSecItemNotFound
    from tests.test_keyvault_native_deletion import _PUBLIC_KEY

    keys = {}
    calls = []

    def invoke(ops, payload):
        calls.append(payload)
        tag = payload["tag_hex"]
        if payload["cmd"] == "generate":
            if tag in keys:
                raise _OpsError(errSecDuplicateItem)
            keys[tag] = _PUBLIC_KEY
            return {"public_key_hex": _PUBLIC_KEY.hex()}
        if payload["cmd"] == "public_key":
            if tag not in keys:
                raise _OpsError(errSecItemNotFound)
            return {"public_key_hex": keys[tag].hex()}
        if payload["cmd"] == "delete":
            keys.pop(tag, None)
            return {"ok": True}
        raise AssertionError(payload)

    monkeypatch.setattr(_HelperSecKeyOps, "_invoke", invoke)
    return keys, calls


def test_real_audit_receipt_rolls_back_failed_ownership_commit(tmp_path, monkeypatch):
    from mordred_hermes.keyvault._seckey_errors import _application_tag
    from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID
    from mordred_hermes.wizard import _keyvault_init as init

    root, _, backend, _ = _owned(tmp_path, monkeypatch)
    keys, calls = _audit_backend(backend, monkeypatch)
    original = _storage.save_meta

    def fail_commit(root, meta):
        if ids.AUDIT_KEY_FIELD in meta:
            raise OSError("ownership commit failed")
        original(root, meta)

    monkeypatch.setattr(_storage, "save_meta", fail_commit)
    with _storage.keyvault_lock(root), pytest.raises(OSError, match="ownership commit failed"):
        init._provision_audit_log_key_locked(root, backend, AUDIT_LOG_KEY_ID)
    assert keys == {}
    assert ids.PENDING_AUDIT_KEY_FIELD not in _storage.load_meta(root)
    assert [call for call in calls if call["cmd"] == "delete"] == [
        {"cmd": "delete", "tag_hex": _application_tag(ids.scoped_native_key_id(root, AUDIT_LOG_KEY_ID)).hex()}
    ]


def test_audit_ownership_is_independent_of_database_dependencies(tmp_path, monkeypatch):
    from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID

    root, _, backend, calls = _owned(tmp_path, monkeypatch)
    meta = _storage.load_meta(root)
    selector = ids.add_pending_audit_key(root, meta, AUDIT_LOG_KEY_ID)
    ids.add_committed_audit_key(root, meta, AUDIT_LOG_KEY_ID, selector)
    meta.pop(ids.PENDING_AUDIT_KEY_FIELD)
    _storage.save_meta(root, meta)
    (tmp_path / "state.db").write_bytes(b"independent database")
    with _storage.keyvault_custody(root, backend=backend) as custody:
        owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            backend.delete_enclave_key(selector, deletion=permit)
    assert [call["cmd"] for call in calls] == ["delete"]
    assert (tmp_path / "state.db").read_bytes() == b"independent database"


def test_ambiguous_or_legacy_reset_journal_retains_state(tmp_path, monkeypatch):
    from mordred_hermes.wizard import keyvault_cli

    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    _, raw = keyvault_cli._encode_reset_journal(root, {"default": selector}, [], False)
    payload = json.loads(raw)
    payload["version"] = 1
    _storage.write_reset_journal(root, json.dumps(payload).encode())
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert root.exists()
    assert _storage.reset_journal_path(root).exists()
    assert calls == []


def test_duplicate_ownership_json_refuses_before_native_io(tmp_path, monkeypatch):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    raw = _storage.safe_read(root / "meta.json")
    _storage.atomic_write(root / "meta.json", raw.replace(b'"version":1', b'"version":1,"version":1'))
    with _storage.keyvault_custody(root, backend=backend) as custody, pytest.raises(DatabaseRefused):
        ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
    assert calls == []


def test_valid_source_only_binding_survives_reset_after_source_is_lost(tmp_path, monkeypatch):
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.keyvault import _database_authority as authority
    from mordred_hermes.keyvault import _memory_key as memory
    from mordred_hermes.wizard import keyvault_cli
    from tests._keyvault_fakes import FakeBackend

    root, _, backend, calls = _owned(tmp_path, monkeypatch)
    memory_backend = FakeBackend()
    monkeypatch.setattr(authority.sys, "platform", "linux")
    monkeypatch.setattr(memory, "linux_memory_backend", lambda home: memory_backend)
    memory.ensure_linux_memory_key(home=tmp_path, backend=memory_backend)
    with acquire_exclusive(tmp_path) as lease:
        authority.enroll_database_source(root=tmp_path, lease=lease)
    source = tmp_path / "mordred/db-key-source.json"
    before = source.read_bytes()
    memory.memory_key_path(tmp_path).unlink()
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert source.read_bytes() == before
    assert root.exists()
    assert not _storage.reset_journal_path(root).exists()
    assert calls == []


def test_pending_audit_duplicate_cleanup_uses_real_checked_owner(tmp_path, monkeypatch):
    from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists
    from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID
    from mordred_hermes.wizard import _keyvault_init as init

    root, _, backend, _ = _owned(tmp_path, monkeypatch)
    keys, calls = _audit_backend(backend, monkeypatch)
    meta = _storage.load_meta(root)
    selector = ids.add_pending_audit_key(root, meta, AUDIT_LOG_KEY_ID)
    _storage.save_meta(root, meta)
    backend.generate_enclave_key(selector)
    with _storage.keyvault_lock(root), pytest.raises(WrapKeyAlreadyExists):
        init._provision_audit_log_key_locked(root, backend, AUDIT_LOG_KEY_ID)
    assert keys == {}
    assert ids.PENDING_AUDIT_KEY_FIELD not in _storage.load_meta(root)
    assert len([call for call in calls if call["cmd"] == "delete"]) == 1


def test_audit_durable_commit_revokes_receipt_inside_live_scope(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID
    from mordred_hermes.wizard import _keyvault_init as init

    root, _, backend, _ = _owned(tmp_path, monkeypatch)
    keys, calls = _audit_backend(backend, monkeypatch)
    commit = wrap.commit_created_key
    revoked = []

    def checked_commit(receipt):
        commit(receipt)
        with pytest.raises(DatabaseRefused):
            wrap.rollback_created_key(receipt)
        revoked.append(True)

    monkeypatch.setattr(wrap, "commit_created_key", checked_commit)
    with _storage.keyvault_lock(root):
        init._provision_audit_log_key_locked(root, backend, AUDIT_LOG_KEY_ID)
    assert revoked == [True]
    assert len(keys) == 1
    assert not any(call["cmd"] == "delete" for call in calls)


def test_changed_helper_store_refuses_before_native_io(tmp_path, monkeypatch):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
        backend._ops._env_override = ("MORDRED_TPMKEY_STORE", str(tmp_path / "foreign"))
        with pytest.raises(DatabaseRefused), deletion._owned_delete_scope(owner, backend=backend, database_lease=None):
            pass
    assert calls == []


@pytest.mark.parametrize(
    "logical",
    [
        "mordred.memory",
        "mordred-hermes.vault.opaque",
        "mordred-hermes.windows.v1.opaque",
        "mordred-hermes.memory.v1.opaque",
    ],
)
def test_managed_role_logical_names_cannot_gain_generic_ownership(tmp_path, monkeypatch, logical):
    root, _, backend, calls = _owned(tmp_path, monkeypatch)
    selector = ids.scoped_native_key_id(root, logical)
    meta = _storage.load_meta(root)
    meta["keys"] = {
        hashlib.sha256(logical.encode()).digest()[:16].hex(): {"key_id": logical, ids.NATIVE_KEY_ID_FIELD: selector}
    }
    _storage.save_meta(root, meta)
    with _storage.keyvault_custody(root, backend=backend) as custody, pytest.raises(DatabaseRefused):
        ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
    assert calls == []


def test_pid_changed_custody_refuses_before_native_io(tmp_path, monkeypatch):
    import os

    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        pid = os.getpid()
        with monkeypatch.context() as patch:
            patch.setattr(os, "getpid", lambda: pid + 1)
            with pytest.raises(DatabaseRefused):
                ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
    assert calls == []


def test_forked_child_cannot_reuse_checked_custody(tmp_path, monkeypatch):
    import os

    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork invalidation")
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    read_fd, write_fd = os.pipe()
    try:
        with _storage.keyvault_custody(root, backend=backend) as custody:
            pid = os.fork()
            if pid == 0:
                try:
                    try:
                        ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
                    except DatabaseRefused:
                        os.write(write_fd, b"refused")
                    else:
                        os.write(write_fd, b"admitted")
                finally:
                    os._exit(0)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            assert os.read(read_fd, 7) == b"refused"
            ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
    finally:
        os.close(read_fd)
        os.close(write_fd)
    assert calls == []


def test_precanonical_scoped_selector_keeps_checked_ownership(tmp_path, monkeypatch):
    import os

    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    root, _, backend, calls = _owned(real, monkeypatch)
    alias_root = _storage.resolve_keyvault_dir(alias)
    selector = ids._native_key_id_for_root_name(os.path.abspath(alias_root), "default")
    meta = _storage.load_meta(root)
    next(iter(meta["keys"].values()))[ids.NATIVE_KEY_ID_FIELD] = selector
    _storage.save_meta(root, meta)
    with _storage.keyvault_custody(alias_root, backend=backend) as custody:
        owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            backend.delete_enclave_key(selector, deletion=permit)
    assert [call["cmd"] for call in calls] == ["delete"]


def test_metadata_is_rechecked_at_native_invocation_after_permit_issue(tmp_path, monkeypatch):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    with _storage.keyvault_custody(root, backend=backend) as custody:
        owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            _storage.save_meta(root, {"version": 1, "keys": {}})
            with pytest.raises(DatabaseRefused):
                backend.delete_enclave_key(selector, deletion=permit)
    assert calls == []


def _replace_lock(path: Path) -> None:
    path.rename(path.with_name(path.name + ".old"))
    path.write_bytes(b"")
    path.chmod(0o600)


@pytest.mark.parametrize("kind", ["keyvault", "lifecycle"])
def test_replaced_lock_before_nested_custody_never_authorizes_native_delete(tmp_path, monkeypatch, kind):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    path = root / ".lock" if kind == "keyvault" else root.parent / ".keyvault.lifecycle.lock"
    with _storage.keyvault_lock(root):
        _replace_lock(path)
        with (
            pytest.raises((DatabaseRefused, _storage.KeyvaultPermissionError)),
            _storage.keyvault_custody(root, backend=backend) as custody,
        ):
            owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
            with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
                backend.delete_enclave_key(selector, deletion=permit)
    assert calls == []


@pytest.mark.parametrize("kind", ["keyvault", "lifecycle"])
def test_replaced_lock_while_initial_flock_waits_never_authorizes_native_delete(tmp_path, monkeypatch, kind):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    path = root / ".lock" if kind == "keyvault" else root.parent / ".keyvault.lifecycle.lock"
    original = _storage.fcntl.flock
    replaced = []

    def flock(fd, operation):
        import os

        # Synchronously inject the same pathname replacement possible while a
        # real flock blocks, without relying on scheduling or native hardware.
        if operation == _storage.fcntl.LOCK_EX and os.fstat(fd).st_ino == path.stat().st_ino:
            _replace_lock(path)
            replaced.append(True)
        original(fd, operation)

    monkeypatch.setattr(_storage.fcntl, "flock", flock)
    with (
        pytest.raises((DatabaseRefused, _storage.KeyvaultPermissionError)),
        _storage.keyvault_custody(root, backend=backend) as custody,
    ):
        owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            backend.delete_enclave_key(selector, deletion=permit)
    assert replaced == [True]
    assert calls == []


@pytest.mark.parametrize("kind", ["keyvault", "lifecycle"])
def test_replaced_actual_held_lock_at_native_use_refuses(tmp_path, monkeypatch, kind):
    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    path = root / ".lock" if kind == "keyvault" else root.parent / ".keyvault.lifecycle.lock"
    with _storage.keyvault_custody(root, backend=backend) as custody:
        owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            _replace_lock(path)
            with pytest.raises((DatabaseRefused, _storage.KeyvaultPermissionError)):
                backend.delete_enclave_key(selector, deletion=permit)
    assert calls == []


@pytest.mark.parametrize("kind", ["keyvault", "lifecycle"])
def test_replacement_during_actual_blocked_flock_refuses(tmp_path, monkeypatch, kind):
    import os
    import subprocess
    import sys

    root, selector, backend, calls = _owned(tmp_path, monkeypatch)
    path = root / ".lock" if kind == "keyvault" else root.parent / ".keyvault.lifecycle.lock"
    script = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX)
print("locked", flush=True)
sys.stdin.readline()
os.close(fd)
"""
    original = _storage.fcntl.flock
    waiting = threading.Event()
    outcomes = []

    def flock(fd, operation):
        if operation == _storage.fcntl.LOCK_EX and os.fstat(fd).st_ino == path.stat().st_ino:
            waiting.set()
        original(fd, operation)

    def transaction():
        try:
            with _storage.keyvault_custody(root, backend=backend) as custody:
                owner = ids.checked_native_owner(custody, native_key_id=selector, backend=backend)
                with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
                    backend.delete_enclave_key(selector, deletion=permit)
        except (DatabaseRefused, _storage.KeyvaultPermissionError):
            outcomes.append("refused")
        else:
            outcomes.append("admitted")

    with subprocess.Popen(
        [sys.executable, "-c", script, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as blocker:
        assert blocker.stdout.readline() == "locked\n"
        monkeypatch.setattr(_storage.fcntl, "flock", flock)
        worker = threading.Thread(target=transaction)
        worker.start()
        try:
            assert waiting.wait(5)
            assert worker.is_alive()
            _replace_lock(path)
        finally:
            blocker.communicate(input="release\n", timeout=5)
            worker.join(timeout=5)
        assert not worker.is_alive()
        assert blocker.returncode == 0
    assert outcomes == ["refused"]
    assert calls == []
