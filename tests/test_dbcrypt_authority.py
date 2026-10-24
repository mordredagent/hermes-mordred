"""Root-native runtime authority; checked disk/lease policy, fake hardware only."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mordred_hermes._database_contracts import DatabaseBusy, DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt._key import KeyProvider, derive
from mordred_hermes.keyvault import _database_authority as custody
from mordred_hermes.keyvault import _memory_key as memory
from tests._keyvault_fakes import FakeBackend
from tests.test_dbcrypt_marker import encoded, put


@pytest.fixture
def native_root(tmp_path, monkeypatch):
    # No Secure Enclave, TPM, production home, or ambient audit sink is used.
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="linux"))
    from mordred_hermes import _database_locking_posix as locking

    monkeypatch.setattr(locking, "sys", SimpleNamespace(platform="linux"))
    backend = FakeBackend()
    key = memory.ensure_linux_memory_key(home=tmp_path, backend=backend)
    monkeypatch.setattr(memory, "linux_memory_backend", lambda home: backend)
    child = tmp_path / "profiles/work"
    child.mkdir(parents=True, mode=0o700, exist_ok=True)
    memory.ensure_linux_memory_key(home=child, backend=backend)
    with acquire_exclusive(tmp_path) as lease:
        snapshot = custody.enroll_database_source(root=tmp_path, lease=lease)
    put(tmp_path, encoded(snapshot))
    backend.calls.clear()
    return tmp_path, backend, key, snapshot


class HeldConnection:
    """Task6's protocol boundary, deliberately no raw SQL wrapper."""

    def __init__(self, authority, *, fail=False):
        self.authority = authority
        self.invalidated = False
        self.pending = ["uncommitted"]
        self.committed = []
        self.fail = fail

    def invalidate(self):
        self.invalidated = True
        self.pending.clear()  # rollback before close
        if self.fail:
            raise RuntimeError("callback failed")

    def commit(self):
        self.authority.check()
        assert not self.invalidated
        self.committed.extend(self.pending)
        self.pending.clear()

    def fetchone(self):
        self.authority.check()
        assert not self.invalidated
        return (1,)


def test_child_profile_uses_root_key_not_memory_key(native_root, monkeypatch):
    from mordred_hermes.dbcrypt._authority import Authority

    root, _, root_key, _ = native_root
    child = root / "profiles/work"
    child.mkdir(parents=True, mode=0o700, exist_ok=True)
    child_key = memory.load_linux_memory_key(home=child)
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + child_key.hex())
    with pytest.raises(DatabaseRefused):
        custody.observe_database_source(root=child)
    authority = Authority.acquire(child)
    try:
        assert authority.root == root
        assert authority.key == derive(root_key)
        assert authority.key != derive(child_key)
        assert memory.load_linux_memory_key(home=child) == child_key
    finally:
        authority.close()


def test_hundred_operations_one_unwrap(native_root):
    from mordred_hermes.dbcrypt._authority import Authority

    root, backend, key, snapshot = native_root
    authority = Authority.acquire(root)
    held = HeldConnection(authority)
    authority.register_connection(held)
    try:
        assert authority.snapshot == snapshot
        for _ in range(100):
            assert authority.key == derive(key)
            assert held.fetchone() == (1,)
            held.commit()
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        with pytest.raises(DatabaseBusy), acquire_exclusive(root):
            pass
    finally:
        authority.close()
    assert held.invalidated
    with acquire_exclusive(root):
        pass


@pytest.mark.parametrize(
    "damage",
    [
        "root",
        "generation",
        "owner",
        "wrapped",
        "record-loss",
        "marker-loss",
        "marker-generation",
        "marker-legacy",
        "profile",
    ],
)
def test_replaced_root_invalidates_held_cursor(native_root, damage):
    from mordred_hermes.dbcrypt._authority import Authority

    root, backend, _, _ = native_root
    child = root / "profiles/work"
    child.mkdir(parents=True, mode=0o700, exist_ok=True)
    authority = Authority.acquire(child)
    held = HeldConnection(authority, fail=True)
    cursor = HeldConnection(authority)
    authority.register_connection(held)
    authority.register_connection(cursor)
    before = list(backend.calls)
    binding = root / "mordred/db-key-source.json"
    marker = root / "mordred/db-encryption.marker"
    if damage == "root":
        root.rename(root.with_name(root.name + "-replaced"))
        root.mkdir(mode=0o700)
    elif damage in {"generation", "owner"}:
        value = json.loads(binding.read_bytes())
        if damage == "generation":
            value["generation"] = "f" * 32
        else:
            value["root"]["owner"] = "999"
        binding.write_text(json.dumps(value))
    elif damage == "wrapped":
        wrapped = root / "mordred/memory-key.wrapped"
        blob = bytearray(wrapped.read_bytes())
        blob[-1] ^= 1
        wrapped.write_bytes(blob)
    elif damage == "record-loss":
        binding.unlink()
    elif damage == "marker-loss":
        marker.unlink()
    elif damage == "marker-generation":
        value = json.loads(marker.read_bytes())
        value["generation"] = "f" * 32
        marker.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    elif damage == "marker-legacy":
        marker.write_bytes(b"1\n")
    else:
        child.rename(child.with_name("previous"))
        child.mkdir(mode=0o700)
    with pytest.raises(DatabaseRefused):
        held.commit()
    assert authority.terminal is True
    assert held.invalidated and cursor.invalidated
    assert not held.pending and not held.committed and not cursor.committed
    for operation in (
        lambda: authority.key,
        authority.check,
        cursor.fetchone,
        lambda: authority.register_connection(cursor),
    ):
        with pytest.raises(DatabaseRefused):
            operation()
    assert backend.calls == before
    authority.close()


def test_cached_hardware_loss_differs_from_record_loss(native_root):
    from mordred_hermes.dbcrypt._authority import Authority

    root, backend, key, _ = native_root
    authority = Authority.acquire(root)
    try:
        backend._keys.clear()
        assert authority.key == derive(key)
        authority.check()
        with pytest.raises(DatabaseRefused):
            Authority.acquire(root)
        assert not authority.terminal
        (root / "mordred/memory-key.wrapped").unlink()
        with pytest.raises(DatabaseRefused):
            authority.check()
        assert authority.terminal
    finally:
        authority.close()


def test_acquisition_is_load_only_and_legacy_is_not_native_authority(native_root, monkeypatch):
    from mordred_hermes.dbcrypt._authority import Authority

    root, backend, key, _ = native_root
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + key.hex())
    path = put(root, b"1\n")
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        Authority.acquire(root)
    assert path.read_bytes() == b"1\n"
    assert backend.calls == before
    (root / "mordred/db-key-source.json").unlink()
    with pytest.raises(DatabaseRefused):
        Authority.acquire(root)
    assert not (root / "mordred/db-key-source.json").exists()


def test_provider_retains_scoped_authority_and_checks_every_call(native_root):
    root, backend, key, _ = native_root
    provider = KeyProvider(home=root)
    try:
        for _ in range(100):
            assert provider() == derive(key)
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        (root / "mordred/memory-key.wrapped").unlink()
        with pytest.raises(DatabaseRefused):
            provider()
        with pytest.raises(DatabaseRefused):
            provider()
    finally:
        provider.close()


def test_fork_invalidates_without_releasing_parent_lease(native_root):
    from mordred_hermes.dbcrypt._authority import Authority

    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork lifetime")
    root, _, _, _ = native_root
    authority = Authority.acquire(root)
    held = HeldConnection(authority)
    authority.register_connection(held)
    pid = os.fork()
    if pid == 0:
        try:
            try:
                authority.check()
            except DatabaseRefused:
                if authority.terminal and held.invalidated:
                    os._exit(0)
            os._exit(2)
        except BaseException:
            os._exit(3)
    try:
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        authority.check()
        with pytest.raises(DatabaseBusy), acquire_exclusive(root):
            pass
    finally:
        authority.close()


def test_derivation_and_plaintext_header_golden_compatibility():
    from mordred_hermes.dbcrypt import _shim

    key = derive(bytes(range(32)))
    assert key.key.hex() == "a1b72bf5b252df9d872abe5e919af37b55a1899e75bfb38816fe867f75768b37"
    assert key.salt.hex() == "ac024548a96c11b9e1662b5be04c35cb"
    pytest.importorskip("sqlcipher3")
    from sqlcipher3 import dbapi2

    connection = dbapi2.connect(":memory:")
    try:
        _shim.apply_key(connection, key)
        assert connection.execute("PRAGMA cipher_plaintext_header_size").fetchone() == ("112",)
    finally:
        connection.close()


def test_default_install_refuses_legacy_without_adoption(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    root, backend, key, _ = native_root
    marker = put(root, b"1\n")
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(_shim, "is_installed", lambda: False)
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + key.hex())
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        dbcrypt.install(home=root)
    assert marker.read_bytes() == b"1\n"
    assert backend.calls == before


def test_changed_marker_during_native_load_releases_failed_acquisition(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _authority

    root, _, _, _ = native_root
    load = _authority.load_database_source

    def change_after_load(*, root, expected):
        material = load(root=root, expected=expected)
        (root / "mordred/db-encryption.marker").unlink()
        return material

    monkeypatch.setattr(_authority, "load_database_source", change_after_load)
    with pytest.raises(DatabaseRefused):
        _authority.Authority.acquire(root)
    with acquire_exclusive(root):
        pass


def test_closed_authority_never_reacquires_or_registers(native_root):
    from mordred_hermes.dbcrypt._authority import Authority

    root, backend, _, _ = native_root
    authority = Authority.acquire(root)
    held = HeldConnection(authority)
    authority.register_connection(held)
    authority.close()
    before = list(backend.calls)
    authority.invalidate("do not retain potentially sensitive reason")
    for operation in (lambda: authority.key, authority.check, lambda: authority.register_connection(held)):
        with pytest.raises(DatabaseRefused):
            operation()
    assert held.invalidated and authority.terminal
    assert backend.calls == before
    with acquire_exclusive(root):
        pass


def test_owner_sid_change_invalidates_without_native_load(native_root, monkeypatch):
    from mordred_hermes.dbcrypt import _authority

    root, backend, _, _ = native_root
    authority = _authority.Authority.acquire(root)
    held = HeldConnection(authority)
    authority.register_connection(held)
    domain = custody.resolve_database_domain(root)
    changed_identity = replace(domain.identities[0], platform="win32", owner="010100000000000516000000")
    monkeypatch.setattr(
        _authority,
        "resolve_database_domain",
        lambda home: replace(domain, identities=(changed_identity,)),
    )
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        held.commit()
    assert authority.terminal and held.invalidated and not held.committed
    assert backend.calls == before


def test_default_provider_never_injects_ambient_key(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt import _key

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + "aa" * 32)

    def forbidden():
        raise AssertionError("production provider used environment injection")

    monkeypatch.setattr(_key, "_inject_vault_env", forbidden)
    provider = _key.KeyProvider(home=tmp_path)
    with pytest.raises(DatabaseRefused):
        provider()
    assert not (tmp_path / "mordred/db-key-source.json").exists()
    provider.close()


def test_default_startup_cannot_return_unregistered_live_sql_connection(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim
    from mordred_hermes.dbcrypt._connection import ProtectedConnection

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    installed = []
    monkeypatch.setattr(_shim, "install_module", installed.append)
    try:
        assert dbcrypt.install(home=root)
        held = installed[0].connect(root / "state.db")
        assert isinstance(held, ProtectedConnection)
        cursor = held.execute("SELECT 1")
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        (root / "mordred/db-encryption.marker").unlink()
        with pytest.raises(DatabaseRefused):
            cursor.fetchone()
        with pytest.raises(DatabaseRefused):
            held.commit()
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()
    with acquire_exclusive(root):
        pass


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("damage", ["directory", "mapping"])
def test_default_profile_startup_refuses_before_sql_or_native(native_root, monkeypatch, installed, damage):
    """An installed shim cannot bypass admission or rebind a held profile runtime."""
    import sqlite3

    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim
    from mordred_hermes.dbcrypt._connection import ProtectedConnection

    root, backend, _, _ = native_root
    profile = root / "profiles/work"
    before_modules = (dbcrypt.sys.modules["sqlite3"], dbcrypt.sys.modules["sqlite3.dbapi2"])
    assert before_modules[0] is sqlite3
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(_shim, "is_installed", lambda: installed)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    modules = []
    monkeypatch.setattr(_shim, "install_module", modules.append)
    try:
        assert dbcrypt.install(home=profile)
        assert len(modules) == 1
        held = modules[0].connect(profile / "state.db")
        assert isinstance(held, ProtectedConnection)
        cursor = held.execute("SELECT 1")
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        authority = dbcrypt._PROVIDER.current_authority
        assert authority is not None and authority.home == profile and authority.root == root
        before_calls = list(backend.calls)
        if damage == "directory":
            profile.rename(profile.with_name("retired-work"))
            profile.mkdir(mode=0o700)
        else:
            (profile / "mordred/db-key-source.json").write_bytes(b"foreign root binding")
        with pytest.raises(DatabaseRefused):
            cursor.fetchone()
        assert authority.terminal
        with pytest.raises(DatabaseRefused):
            held.commit()
        with pytest.raises(DatabaseRefused):
            modules[0].connect(profile / "state.db")
        assert backend.calls == before_calls
        if damage == "directory":
            assert not (profile / "state.db").exists()
        else:
            assert (profile / "state.db").exists()
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()
    assert (dbcrypt.sys.modules["sqlite3"], dbcrypt.sys.modules["sqlite3.dbapi2"]) == before_modules
    with acquire_exclusive(root):
        pass


def test_status_never_acquires_runtime_authority(native_root, monkeypatch):
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.wizard.databases_cli import databases_status

    root, backend, _, _ = native_root

    def forbidden(*args, **kwargs):
        raise AssertionError("status tried to load native custody")

    monkeypatch.setattr(Authority, "acquire", forbidden)
    before = list(backend.calls)
    assert databases_status(home=root) == 0
    assert backend.calls == before


@pytest.mark.parametrize("damage", ["broken-symlink", "directory"])
def test_default_install_refuses_unsafe_marker_entry(native_root, monkeypatch, damage):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _shim

    root, backend, _, _ = native_root
    marker = root / "mordred/db-encryption.marker"
    marker.unlink()
    if damage == "broken-symlink":
        marker.symlink_to(root / "missing")
    else:
        marker.mkdir(mode=0o700)
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(_shim, "is_installed", lambda: False)
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        dbcrypt.install(home=root)
    assert backend.calls == before


@pytest.mark.filterwarnings("ignore:This process.*multi-threaded:DeprecationWarning")
@pytest.mark.parametrize("operation", ["register", "provider"])
def test_fork_refuses_before_entering_inherited_thread_lock(native_root, operation):
    import signal
    import threading

    from mordred_hermes.dbcrypt._authority import Authority

    if not hasattr(os, "fork"):
        pytest.skip("POSIX fork lifetime")
    root, _, _, _ = native_root
    provider = KeyProvider(home=root)
    authority = Authority.acquire(root) if operation == "register" else None
    if authority is None:
        provider()
    lock = authority._lock if authority is not None else provider._lock
    locked, release = threading.Event(), threading.Event()

    def hold_lock():
        with lock:
            locked.set()
            release.wait(timeout=10)

    thread = threading.Thread(target=hold_lock)
    thread.start()
    assert locked.wait(timeout=3)
    pid = os.fork()
    if pid == 0:
        signal.alarm(2)
        try:
            if authority is not None:
                authority.register_connection(HeldConnection(authority))
            else:
                provider()
        except DatabaseRefused:
            os._exit(0)
        except BaseException:
            os._exit(3)
        os._exit(2)
    release.set()
    thread.join(timeout=3)
    try:
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        if authority is not None:
            authority.check()
        else:
            assert provider() is not None
    finally:
        if authority is not None:
            authority.close()
        provider.close()


@pytest.mark.parametrize("kind", ["journal", "encrypt-pending", "decrypt-pending"])
def test_default_startup_without_marker_preserves_recovery_state(tmp_path, monkeypatch, kind):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _migrate, _shim

    root = tmp_path
    directory = root / "mordred"
    directory.mkdir(mode=0o700)
    original, prepared = root / "state.db", root / "state.db.prepared"
    original.write_bytes(b"original database bytes")
    prepared.write_bytes(b"prepared database bytes")
    state = {
        "journal": _migrate.journal_path(root),
        "encrypt-pending": _migrate.pending_path(root),
        "decrypt-pending": _migrate.decrypt_pending_path(root),
    }[kind]
    state.write_text(
        json.dumps({"direction": "encrypt", "swaps": [{"path": str(original), "prepared": str(prepared)}]})
    )
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    resumed = []
    resume = _migrate.resume_at_startup

    def observe_resume(*args, **kwargs):
        resumed.append(True)
        return resume(*args, **kwargs)

    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(_shim, "is_installed", lambda: False)
    monkeypatch.setattr(_migrate, "resume_at_startup", observe_resume)
    try:
        with pytest.raises(DatabaseRefused):
            dbcrypt.install(home=root)
        assert not resumed
        assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
        assert not dbcrypt.marker_path(root).exists()
    finally:
        if dbcrypt._PROVIDER is not None:
            dbcrypt._PROVIDER.close()


def test_explicit_native_provider_cannot_enter_legacy_install(native_root, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt import _migrate, _shim

    root, backend, _, _ = native_root
    monkeypatch.setattr(dbcrypt.sys, "platform", "darwin")
    monkeypatch.setattr(dbcrypt.sys, "argv", ["hermes"])
    monkeypatch.setattr(dbcrypt, "_PROVIDER", None)
    installed = []
    monkeypatch.setattr(_shim, "install_module", installed.append)

    def forbidden(*args, **kwargs):
        raise AssertionError("native runtime entered legacy recovery")

    monkeypatch.setattr(_migrate, "resume_at_startup", forbidden)
    provider = KeyProvider(home=root)
    try:
        assert dbcrypt.install(home=root, provider=provider)
        held = installed[0].connect(root / "state.db")
        held.execute("SELECT 1")
        assert sum(op == "ecdh" for op, _ in backend.calls) == 1
        provider.close()
        with pytest.raises(DatabaseRefused):
            held.commit()
    finally:
        provider.close()
