"""POSIX Telegram authentication and local deletion use real native boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import threading
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.extension.telegram import tee
from mordred_hermes.extension.telegram.secrets import TelegramSecrets
from mordred_hermes.keyvault import _native_deletion as deletion
from mordred_hermes.keyvault import _storage, wrap
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecItemNotFound
from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps


class NativeTelegram:
    """Inject only helper I/O; backend, wrap, ECDH and native guards stay real."""

    def __init__(self, home):
        self.home = home
        self.calls = []
        self.keys = {}
        self.fail_delete = False
        self.on_unwrap = None
        name, leaf = ("MORDRED_SEKEY_STORE", "sekey") if sys.platform == "darwin" else ("MORDRED_TPMKEY_STORE", "tpm")
        self.ops = _HelperSecKeyOps(
            "/test-only-never-executed", env_override=(name, str(home / "mordred/keyvault" / leaf))
        )
        self.ops._invoke = self.invoke
        self.backend = _SecKeyBackend(ops=self.ops, sw_ops=None, legacy_ops=None)

    @property
    def ecdh_calls(self):
        return self.calls.count("ecdh")

    def invoke(self, payload):
        command, tag = payload["cmd"], payload["tag_hex"]
        self.calls.append(command)
        if command == "generate":
            self.keys[tag] = ec.generate_private_key(ec.SECP256R1())
        if command == "delete":
            if self.fail_delete:
                raise _OpsError(-1, "helper", "transport response lost")
            self.keys.pop(tag, None)
            return {"ok": True}
        if tag not in self.keys:
            raise _OpsError(errSecItemNotFound)
        key = self.keys[tag]
        if command in {"generate", "public_key"}:
            return {
                "public_key_hex": key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
            }
        if command == "ecdh":
            if self.on_unwrap:
                self.on_unwrap()
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(payload["peer_pub_hex"]))
            return {"shared_hex": key.exchange(ec.ECDH(), peer).hex()}
        raise AssertionError(command)


def native_store(home):
    native = NativeTelegram(home)
    vault = tee.TeeSecretStore(
        home / "mordred/telegram", backend_factory=lambda: native.backend, audit_sink=lambda _e: None
    )
    return vault, native


def value():
    return TelegramSecrets(1, "ab" * 16, b"x" * 32, session="PRIVATE-SESSION")


@pytest.fixture
def owned(tmp_path):
    vault, native = native_store(tmp_path)
    vault.ensure_key()
    vault.store(value())
    return vault, native


def test_one_unwrap_native_first_independent_of_root_databases(owned):
    vault, native = owned
    (native.home / "state.db").write_bytes(b"unrelated root DB")
    snapshot = vault.load_snapshot()
    before = native.ecdh_calls
    vault.forget_from_snapshot(snapshot)
    assert native.ecdh_calls == before == 1
    assert native.calls.count("delete") == 1
    assert not vault.sealed_path.exists()
    assert not (native.home / "mordred/telegram-forget.json").exists()


def test_no_custody_lock_held_during_unwrap(owned):
    vault, native = owned

    def check():
        for name in (".telegram.credentials.lock", ".keyvault.lifecycle.lock"):
            with pytest.raises(OSError):
                _storage.assert_advisory_lock_held(native.home / "mordred" / name)

    native.on_unwrap = check
    assert vault.load() == value()


@pytest.mark.parametrize("kind", ["digest", "fabricated", "none"])
def test_public_snapshot_values_cannot_authorize_forget(owned, kind):
    vault, native = owned
    from mordred_hermes.keyvault._telegram_custody import TelegramAuthentication

    proof = {
        "digest": hashlib.sha256(vault.sealed_path.read_bytes()).digest(),
        "fabricated": object.__new__(TelegramAuthentication),
        "none": None,
    }[kind]
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot((value(), proof))
    assert "delete" not in native.calls
    assert vault.sealed_path.exists()


def test_opaque_authentication_cannot_construct_or_copy(owned):
    from mordred_hermes.keyvault._telegram_custody import TelegramAuthentication

    with pytest.raises(DatabaseRefused):
        TelegramAuthentication()
    with pytest.raises(DatabaseRefused):
        copy.copy(owned[0].load_snapshot()[1])


@pytest.mark.parametrize("change", ["source", "public", "store", "thread", "lock"])
def test_changed_or_foreign_authentication_refuses(owned, change):
    vault, native = owned
    snapshot = vault.load_snapshot()
    if change == "source":
        vault.store(replace(value(), session="new account"))
    elif change == "public":
        for tag in native.keys:
            native.keys[tag] = ec.generate_private_key(ec.SECP256R1())
    elif change == "store":
        native.ops._env_override = (native.ops._env_override[0], str(native.home / "elsewhere"))
    elif change == "lock":
        lock = native.home / "mordred/.telegram.credentials.lock"
        lock.unlink()
        lock.write_bytes(b"")
        lock.chmod(0o600)
    if change == "thread":
        errors = []

        def foreign():
            try:
                vault.forget_from_snapshot(snapshot)
            except DatabaseRefused as error:
                errors.append(error)

        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(2)
        assert not thread.is_alive() and len(errors) == 1
    else:
        with pytest.raises(DatabaseRefused):
            vault.forget_from_snapshot(snapshot)
    assert "delete" not in native.calls
    assert vault.sealed_path.exists()


def test_native_failure_retains_every_local_file_and_intent(owned):
    vault, native = owned
    archive = vault.sealed_path.parent / "index.enc"
    archive.write_bytes(b"encrypted archive")
    archive.chmod(0o600)
    snapshot = vault.load_snapshot()
    before = {p.name: p.read_bytes() for p in (vault.sealed_path, vault.meta_path, archive)}
    native.fail_delete = True
    with pytest.raises(WrapError):
        vault.forget_from_snapshot(snapshot)
    assert before == {p.name: p.read_bytes() for p in (vault.sealed_path, vault.meta_path, archive)}
    journal = native.home / "mordred/telegram-forget.json"
    assert json.loads(journal.read_bytes())["phase"] == "intent"
    calls = list(native.calls)
    with pytest.raises(DatabaseRefused):
        vault.load()
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot(snapshot)
    assert native.calls == calls


def test_sync_lock_blocks_forget_without_source_changes(owned):
    from mordred_hermes.extension.telegram.store import ArchiveStore, StoreError

    vault, native = owned
    snapshot = vault.load_snapshot()
    before = vault.sealed_path.read_bytes()
    archive = ArchiveStore(value().store_key, root=vault.sealed_path.parent)
    with archive.locked():
        with pytest.raises(StoreError, match="sync_in_progress"):
            vault.forget_from_snapshot(snapshot)
        vault.update_from_snapshot(snapshot, lambda old: replace(old, session=None))
    assert native.calls.count("delete") == 0
    assert vault.sealed_path.read_bytes() != before


def test_deleted_journal_resumes_without_unwrap_or_native_delete(owned, monkeypatch):
    vault, native = owned
    snapshot = vault.load_snapshot()
    original = _storage.atomic_write

    def interrupted(path, data):
        original(path, data)
        if path.name == "telegram-forget.json" and json.loads(data)["phase"] == "deleted":
            raise OSError("crash after durable acknowledgement")

    monkeypatch.setattr(_storage, "atomic_write", interrupted)
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot(snapshot)
    monkeypatch.setattr(_storage, "atomic_write", original)
    calls = list(native.calls)
    vault.forget_from_snapshot((None, None))
    assert native.calls == calls
    assert not vault.sealed_path.exists()


def test_bare_delete_and_wrong_root_refuse(owned, tmp_path):
    vault, native = owned
    with pytest.raises(DatabaseRefused):
        vault.delete_key()
    with pytest.raises(DatabaseRefused):
        wrap.delete_wrapping_key(tee.KEY_ID, backend=native.backend)
    other = tee.TeeSecretStore(tmp_path / "arbitrary", backend_factory=lambda: native.backend)
    with pytest.raises(DatabaseRefused):
        other.load_snapshot()


def test_update_none_cannot_remove_ownership(owned):
    vault, _native = owned
    before = vault.sealed_path.read_bytes()
    with pytest.raises(DatabaseRefused):
        vault.update(lambda _old: None)
    assert vault.sealed_path.read_bytes() == before


def test_telegram_receipt_refuses_before_native_calls_and_raw_publication_succeeds(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from mordred_hermes.keyvault import _native_key_id
    from mordred_hermes.keyvault._telegram_custody import telegram_credential_transaction

    vault, native = native_store(tmp_path)
    root = tmp_path / "mordred/keyvault"
    _storage.ensure_layout(root)
    with _storage.keyvault_custody(root, backend=native.backend) as custody:
        meta = _storage.load_meta(root)
        main_selector = _native_key_id.add_pending_native_key(root, meta, "default")
        _storage.save_meta(root, meta)
        before = _storage.safe_read(root / "meta.json")
        # This is genuine live, correctly bound main provisioning custody,
        # rather than a missing argument or a fabricated custody object.
        _storage.KeyvaultCustody._check_native_creation_owner(custody, "default", main_selector, native.backend)
        assert native.calls == []
        for selector in (tee.KEY_ID, main_selector):
            with (
                pytest.raises(DatabaseRefused),
                wrap.create_wrapping_key_scope(
                    tee.KEY_ID, backend=native.backend, custody=custody, native_key_id=selector
                ),
            ):
                pytest.fail("main custody cannot issue a Telegram creation receipt")
            assert native.calls == []  # no public lookup, generation, ECDH, or deletion
            assert _storage.safe_read(root / "meta.json") == before

    # Telegram still uses ordinary raw generation and authenticated source
    # publication. No main/audit receipt or caller-selected role is needed.
    vault.ensure_key()
    vault.store(value())
    current, proof = vault.load_snapshot()
    assert current == value() and proof is not None
    assert native.calls.count("generate") == 1 and native.ecdh_calls == 1
    with telegram_credential_transaction(home=tmp_path, backend=native.backend, authenticated=proof) as custody:
        owner = deletion._issue_native_owner(custody, native_key_id=tee.KEY_ID, backend=native.backend)
        with deletion._owned_delete_scope(owner, backend=native.backend, database_lease=None):
            pass
    assert native.ecdh_calls == 1 and "delete" not in native.calls
    assert vault.sealed_path.exists()


def test_issuer_detects_publication_during_unwrap_without_minting_proof(owned):
    vault, native = owned
    native.on_unwrap = lambda: vault.store(replace(value(), session="new credentials"))
    with pytest.raises(DatabaseRefused, match="changed during authentication"):
        vault.load_snapshot()
    assert native.ecdh_calls == 1 and "delete" not in native.calls


def test_exact_backend_reused_for_authentication_and_delete(owned):
    vault, native = owned
    calls = []
    vault._native_backend = None
    vault._backend_factory = lambda: calls.append("factory") or native.backend
    snapshot = vault.load_snapshot()
    vault.forget_from_snapshot(snapshot)
    assert calls == ["factory"] and native.ecdh_calls == 1


def test_owner_scope_is_exact_live_thread_local_and_selector_bound(owned):
    from mordred_hermes.keyvault._telegram_custody import telegram_credential_transaction

    vault, native = owned
    _current, proof = vault.load_snapshot()
    with telegram_credential_transaction(home=native.home, backend=native.backend, authenticated=proof) as custody:
        with pytest.raises(DatabaseRefused):
            deletion._issue_native_owner(custody, native_key_id="memory-selector", backend=native.backend)
        owner = deletion._issue_native_owner(custody, native_key_id=tee.KEY_ID, backend=native.backend)
    with pytest.raises(DatabaseRefused):
        deletion._issue_native_owner(custody, native_key_id=tee.KEY_ID, backend=native.backend)
    with (
        pytest.raises(DatabaseRefused),
        deletion._owned_delete_scope(owner, backend=native.backend, database_lease=None),
    ):
        pytest.fail("expired custody cannot issue a permit")
    assert native.ecdh_calls == 1 and "delete" not in native.calls


def test_replaced_held_credential_fd_cannot_issue_owner(owned):
    from mordred_hermes.keyvault._telegram_custody import telegram_credential_transaction

    vault, native = owned
    _current, proof = vault.load_snapshot()
    with telegram_credential_transaction(home=native.home, backend=native.backend, authenticated=proof) as custody:
        path = native.home / "mordred/.telegram.credentials.lock"
        path.rename(path.with_suffix(".old"))
        path.write_bytes(b"")
        path.chmod(0o600)
        with pytest.raises((DatabaseRefused, OSError)):
            deletion._issue_native_owner(custody, native_key_id=tee.KEY_ID, backend=native.backend)
    assert "delete" not in native.calls


@pytest.mark.parametrize("change", ["home", "backend", "fallback", "source_inode", "root", "meta_symlink"])
def test_wrong_binding_and_unsafe_source_refuse_before_native_delete(owned, tmp_path, change):
    vault, native = owned
    snapshot = vault.load_snapshot()
    if change == "home":
        vault._root = tmp_path / "other/mordred/telegram"
        vault._root.parent.parent.mkdir()
    elif change == "backend":
        vault._native_backend = _SecKeyBackend(ops=native.ops, sw_ops=None, legacy_ops=None)
    elif change == "fallback":
        native.backend._sw_ops = native.ops
    elif change == "source_inode":
        raw = vault.sealed_path.read_bytes()
        _storage.atomic_write(vault.sealed_path, raw)
    elif change == "root":
        root = vault.sealed_path.parent
        root.rename(root.with_name("retained"))
        root.symlink_to(root.with_name("retained"))
    else:
        path = vault.meta_path
        path.unlink()
        path.symlink_to(vault.sealed_path)
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot(snapshot)
    assert "delete" not in native.calls


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork required")
def test_forked_authentication_cannot_authorize_native_delete(owned):
    vault, native = owned
    snapshot = vault.load_snapshot()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            vault.forget_from_snapshot(snapshot)
        except DatabaseRefused:
            os.write(write_fd, b"refused")
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 32) == b"refused"
        assert os.waitpid(pid, 0)[1] == 0
    finally:
        os.close(read_fd)
    assert vault.sealed_path.exists() and "delete" not in native.calls


@pytest.mark.parametrize(
    "point",
    ["before_intent", "after_intent", "before_deleted", "after_deleted", "meta", "source", "archive", "journal_last"],
)
def test_journal_crash_points_preserve_evidence_and_safe_retry(owned, monkeypatch, point):
    vault, native = owned
    archive = vault.sealed_path.parent / "index.enc"
    archive.write_bytes(b"encrypted archive")
    archive.chmod(0o600)
    snapshot = vault.load_snapshot()
    original_write = _storage.atomic_write
    original_unlink = type(archive).unlink
    journal = native.home / "mordred/telegram-forget.json"

    def write(path, data):
        if path == journal:
            phase = json.loads(data)["phase"]
            if (point == "before_intent" and phase == "intent") or (point == "before_deleted" and phase == "deleted"):
                raise OSError("injected crash before journal publication")
            original_write(path, data)
            if (point == "after_intent" and phase == "intent") or (point == "after_deleted" and phase == "deleted"):
                raise OSError("injected crash after journal publication")
            return
        original_write(path, data)

    def unlink(path, *args, **kwargs):
        target = {
            "meta": vault.meta_path,
            "source": vault.sealed_path,
            "archive": archive,
            "journal_last": journal,
        }.get(point)
        if path == target:
            raise OSError("injected cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(_storage, "atomic_write", write)
    monkeypatch.setattr(type(archive), "unlink", unlink)
    with pytest.raises((DatabaseRefused, OSError)):
        vault.forget_from_snapshot(snapshot)
    monkeypatch.setattr(_storage, "atomic_write", original_write)
    monkeypatch.setattr(type(archive), "unlink", original_unlink)
    if point == "before_intent":
        assert not journal.exists() and native.calls.count("delete") == 0
        assert vault.sealed_path.exists() and vault.meta_path.exists() and archive.exists()
        return
    phase = json.loads(journal.read_bytes())["phase"]
    assert phase == ("intent" if point in {"after_intent", "before_deleted"} else "deleted")
    assert vault.flags()["forget_pending"] is True
    calls = list(native.calls)
    if phase == "intent":
        with pytest.raises(DatabaseRefused):
            vault.forget_from_snapshot((None, None))
        assert vault.sealed_path.exists() and archive.exists()
    else:
        vault.forget_from_snapshot((None, None))
        assert not journal.exists() and not vault.sealed_path.exists() and not archive.exists()
    assert native.calls == calls


def test_acknowledgement_cannot_be_asserted_by_caller(owned):
    from mordred_hermes.keyvault._telegram_custody import telegram_credential_transaction

    vault, native = owned
    _current, proof = vault.load_snapshot()
    with telegram_credential_transaction(home=native.home, backend=native.backend, authenticated=proof) as custody:
        custody.begin_forget()
        with pytest.raises(DatabaseRefused):
            custody.acknowledge_forget()
    assert "delete" not in native.calls


def test_pending_journal_gates_sync_and_every_credential_publisher(owned):
    from mordred_hermes.extension.telegram.store import ArchiveStore

    vault, native = owned
    snapshot = vault.load_snapshot()
    native.fail_delete = True
    with pytest.raises(WrapError):
        vault.forget_from_snapshot(snapshot)
    for call in (
        vault.ensure_key,
        lambda: vault.store(value()),
        lambda: vault._write(value()),
        lambda: vault.update(lambda old: old),
        lambda: vault.update_from_snapshot(snapshot, lambda old: old),
        lambda: vault.save_sync_scope({}),
        lambda: vault._write_meta(value()),
    ):
        with pytest.raises(DatabaseRefused):
            call()
    with pytest.raises(DatabaseRefused), ArchiveStore(value().store_key, root=vault.sealed_path.parent).locked():
        pytest.fail("pending forget cannot admit sync")


def test_custody_issuance_has_no_database_or_sql_imports(tmp_path):
    import subprocess

    script = r"""
import importlib.abc
import sys
from pathlib import Path
class Forbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if (fullname.startswith(("mordred_hermes.dbcrypt", "sqlcipher", "pysqlcipher", "mordred_hermes.imports"))
                or fullname in {"mordred_hermes.extension.telegram.history", "mordred_hermes.extension.telegram.store",
                                "mordred_hermes.extension.telegram.service", "sqlite3"}):
            raise RuntimeError("forbidden import: " + fullname)
sys.meta_path.insert(0, Forbidden())
from tests.test_posix_telegram_custody import NativeTelegram, value
from mordred_hermes.keyvault import _telegram_custody as custody, _storage, wrap, _native_deletion
from mordred_hermes.extension.telegram.secrets import encode
home = Path(sys.argv[1])
home.joinpath("mordred/telegram").mkdir(parents=True, mode=0o700)
native = NativeTelegram(home)
wrap.generate_wrapping_key(custody.KEY_ID, backend=native.backend)
dek = b"x" * 32
blob = wrap.wrap_dek(dek, custody.KEY_ID, backend=native.backend)
_storage.atomic_write(home / "mordred/telegram/credentials.sealed", custody._pack(blob, dek, encode(value())))
current, proof = custody.authenticate_telegram_source(home=home, backend=native.backend, audit_sink=lambda e: None)
assert current == value()
with custody.telegram_credential_transaction(home=home, backend=native.backend, authenticated=proof) as scope:
    owner = _native_deletion._issue_native_owner(scope, native_key_id=custody.KEY_ID, backend=native.backend)
assert native.ecdh_calls == 1
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, timeout=15
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("kind", ["hardlink", "mode"])
def test_source_safety_requires_private_single_link_regular_file(owned, kind):
    vault, native = owned
    if kind == "hardlink":
        os.link(vault.sealed_path, vault.sealed_path.with_name("substituted-link"))
    else:
        vault.sealed_path.chmod(0o400)
    with pytest.raises(DatabaseRefused):
        vault.load_snapshot()
    assert native.ecdh_calls == 0


def test_same_content_replaced_journal_refuses_live_scope_use(owned):
    from mordred_hermes.keyvault._telegram_custody import telegram_credential_transaction

    vault, native = owned
    _current, proof = vault.load_snapshot()
    with telegram_credential_transaction(home=native.home, backend=native.backend, authenticated=proof) as custody:
        custody.begin_forget()
        path = native.home / "mordred/telegram-forget.json"
        _storage.atomic_write(path, path.read_bytes())
        with pytest.raises(DatabaseRefused):
            custody.forget_journal()


def test_ambiguous_native_response_does_not_infer_success_from_missing_key(owned):
    vault, native = owned
    snapshot = vault.load_snapshot()
    original = native.ops._invoke

    def lose_response(payload):
        result = original(payload)
        if payload["cmd"] == "delete":
            raise _OpsError(-1, "helper", "lost acknowledgement")
        return result

    native.ops._invoke = lose_response
    with pytest.raises(WrapError):
        vault.forget_from_snapshot(snapshot)
    assert not native.keys
    assert vault.sealed_path.exists() and vault.meta_path.exists()
    assert json.loads((native.home / "mordred/telegram-forget.json").read_bytes())["phase"] == "intent"
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot((None, None))
    assert native.ecdh_calls == 1 and native.calls.count("delete") == 1


def test_parallel_writers_apply_mutations_to_current_authenticated_source(owned):
    vault, native = owned
    barrier = threading.Barrier(2)
    errors = []

    def writer(field):
        try:
            snapshot = vault.load_snapshot()
            barrier.wait(timeout=5)
            vault.update_from_snapshot(snapshot, lambda old: replace(old, **{field: "preserved"}))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(field,)) for field in ("venice_api_key", "venice_model")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(8)
        assert not thread.is_alive()
    assert errors == []
    result = vault.load()
    assert result.venice_api_key == result.venice_model == "preserved"
    assert native.ecdh_calls == 4  # 2 snapshots + stale writer reauthentication + final load


@pytest.mark.parametrize("malformed", ["version_bool", "duplicate", "home", "selector", "roots", "source"])
def test_malformed_or_misbound_deleted_journal_never_cleans_files(owned, monkeypatch, malformed):
    vault, native = owned
    snapshot = vault.load_snapshot()
    journal_path = native.home / "mordred/telegram-forget.json"
    original = _storage.atomic_write

    def interrupted(path, data):
        original(path, data)
        if path == journal_path and json.loads(data)["phase"] == "deleted":
            raise OSError("interrupted acknowledged cleanup")

    monkeypatch.setattr(_storage, "atomic_write", interrupted)
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot(snapshot)
    monkeypatch.setattr(_storage, "atomic_write", original)
    journal = json.loads(journal_path.read_bytes())
    if malformed == "duplicate":
        data = json.dumps(journal)[:-1] + ', "phase":"deleted"}'
    else:
        if malformed == "version_bool":
            journal["version"] = True
        elif malformed == "source":
            journal["source_digest"] = "0" * 64
        else:
            journal[malformed] = "different binding"
        data = json.dumps(journal)
    original(journal_path, data.encode())
    with pytest.raises(DatabaseRefused):
        vault.forget_from_snapshot((None, None))
    assert vault.sealed_path.exists() and vault.meta_path.exists() and journal_path.exists()


def test_archive_cleanup_requires_live_exact_held_fd(owned):
    from mordred_hermes.extension.telegram.store import (
        PosixArchiveLock,
        StoreError,
        _posix_archive_lock,
        _prepare_archive_wipe,
        _wipe_archive_locked,
    )

    vault, native = owned
    archive = vault.sealed_path.parent / "index.enc"
    archive.write_bytes(b"retained encrypted archive")
    archive.chmod(0o600)
    with pytest.raises(StoreError):
        PosixArchiveLock()
    with pytest.raises(StoreError):
        _wipe_archive_locked(object.__new__(PosixArchiveLock))
    with _posix_archive_lock(vault.sealed_path.parent) as held:
        _prepare_archive_wipe(held)
        path = vault.sealed_path.parent / ".lock"
        path.rename(path.with_suffix(".old"))
        path.write_bytes(b"")
        path.chmod(0o600)
        with pytest.raises(StoreError):
            _wipe_archive_locked(held)
    with pytest.raises(StoreError):
        _wipe_archive_locked(held)
    assert archive.exists() and "delete" not in native.calls


def test_public_cli_native_refusal_returns_integer_but_internal_result_propagates(owned, monkeypatch, capsys):
    from mordred_hermes.wizard import telegram_cli

    vault, native = owned
    monkeypatch.setattr(telegram_cli.telegram_migrate_cli, "forget_import_rows", lambda current: None)
    native.fail_delete = True
    assert telegram_cli.telegram_logout(forget=True, store=vault) == 1
    assert vault.sealed_path.exists() and "PRIVATE-SESSION" not in capsys.readouterr().err
    with pytest.raises(DatabaseRefused):
        telegram_cli._telegram_logout_result(forget=True, store=vault)
    assert native.calls.count("delete") == 1 and native.ecdh_calls == 1


def test_custom_store_without_checked_forget_never_falls_back_to_deletes(monkeypatch):
    from mordred_hermes.wizard import telegram_cli

    class Unchecked:
        def load(self, **kwargs):
            return value()

        def update(self, mutate):
            pytest.fail("unchecked delete fallback")

        def delete_key(self):
            pytest.fail("unchecked key delete fallback")

    monkeypatch.setattr(telegram_cli.telegram_migrate_cli, "forget_import_rows", lambda current: None)
    assert telegram_cli.telegram_logout(forget=True, store=Unchecked()) == 1
    with pytest.raises(DatabaseRefused):
        telegram_cli._telegram_logout_result(forget=True, store=Unchecked())
