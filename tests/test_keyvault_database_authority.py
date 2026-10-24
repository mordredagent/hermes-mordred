"""Database source policy; only native hardware is replaced by a crypto fake."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive
from mordred_hermes.keyvault import _memory_key as memory
from tests._keyvault_fakes import FakeBackend
from tests.test_windows_custody import fs  # noqa: F401


@pytest.fixture
def source(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _database_authority as authority

    monkeypatch.setattr(authority.sys, "platform", "linux")
    backend = FakeBackend()
    key = memory.ensure_linux_memory_key(home=tmp_path, backend=backend)
    monkeypatch.setattr(memory, "linux_memory_backend", lambda home: backend)
    return authority, tmp_path, backend, key


def enroll(authority, root):
    with acquire_exclusive(root) as lease:
        return authority.enroll_database_source(root=root, lease=lease)


def test_snapshot_does_not_unwrap(source, monkeypatch):
    authority, root, backend, key = source
    expected = enroll(authority, root)
    before = list(backend.calls)

    def no_backend(home):
        raise AssertionError("passive observation constructed a native backend")

    with monkeypatch.context() as patch:
        patch.setattr(memory, "linux_memory_backend", no_backend)
        assert authority.observe_database_source(root=root) == expected
    assert backend.calls == before
    assert authority.load_database_source(root=root, expected=expected) == key
    assert sum(op == "ecdh" for op, _ in backend.calls[len(before) :]) == 1


def test_enrollment_requires_exclusive_source_verification(source):
    authority, root, backend, _ = source
    binding = root / "mordred/db-key-source.json"
    with pytest.raises(DatabaseRefused):
        authority.enroll_database_source(root=root, lease=None)
    assert not binding.exists()
    backend._keys.clear()
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.enroll_database_source(root=root, lease=lease)
    assert not binding.exists()


def test_binding_is_private_exact_and_reused(source):
    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    path = root / "mordred/db-key-source.json"
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    assert path.stat().st_mode & 0o777 == 0o600
    data = json.loads(raw)
    assert set(data) == {"version", "root", "provider", "generation", "record_sha256"}
    assert data["version"] == 1
    assert data["provider"] == "tpm"
    assert len(data["generation"]) == 32
    assert data["root"] == {
        "platform": "linux",
        "volume": root.stat().st_dev,
        "file_id": str(root.stat().st_ino),
        "owner": str(root.stat().st_uid),
    }
    assert enroll(authority, root) == snapshot
    assert path.read_bytes() == raw


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "bad-json",
        "provider",
        "root",
        "root-volume-float",
        "generation",
        "digest",
        "extra",
        "duplicate",
        "mode",
        "symlink",
    ],
)
def test_bad_binding_refuses_without_native_calls(source, damage):
    authority, root, backend, _ = source
    snapshot = enroll(authority, root)
    path = root / "mordred/db-key-source.json"
    data = json.loads(path.read_bytes())
    if damage == "missing":
        path.unlink()
    elif damage == "bad-json":
        path.write_bytes(b"{broken")
    elif damage == "mode":
        path.chmod(0o644)
    elif damage == "symlink":
        target = root / "other"
        path.rename(target)
        path.symlink_to(target)
    elif damage == "duplicate":
        path.write_bytes(b'{"version":1,"version":1}\n')
    else:
        if damage == "provider":
            data["provider"] = "cng"
        elif damage == "root":
            data["root"]["owner"] = "999999"
        elif damage == "root-volume-float":
            data["root"]["volume"] = float(data["root"]["volume"])
        elif damage == "generation":
            data["generation"] = "F" * 32
        elif damage == "digest":
            data["record_sha256"] = "0" * 64
        else:
            data["extra"] = True
        path.write_text(json.dumps(data) + "\n")
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        authority.observe_database_source(root=root)
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)
    assert backend.calls == before


def test_changed_wrapper_requires_reconciliation(source):
    authority, root, backend, _ = source
    expected = enroll(authority, root)
    old_binding = (root / "mordred/db-key-source.json").read_bytes()
    from mordred_hermes.keyvault import wrap

    memory.memory_key_path(root).write_bytes(wrap.wrap_dek(b"z" * 32, memory.memory_key_id(root), backend=backend))
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=expected)
    with pytest.raises(DatabaseRefused):
        enroll(authority, root)
    assert (root / "mordred/db-key-source.json").read_bytes() == old_binding


@pytest.mark.parametrize("blob", [b"", b"x" * 127])
def test_malformed_wrapper_refuses_observation_without_unwrap(source, blob):
    authority, root, backend, _ = source
    enroll(authority, root)
    memory.memory_key_path(root).write_bytes(blob)
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        authority.observe_database_source(root=root)
    assert backend.calls == before


def test_expected_snapshot_and_post_unwrap_change_refuse(source, monkeypatch):
    authority, root, backend, _ = source
    snapshot = enroll(authority, root)
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=replace(snapshot, generation="f" * 32))
    assert backend.calls == before
    original = backend.enclave_ecdh

    def changed(key_id, peer_pub):
        result = original(key_id, peer_pub)
        (root / "mordred/db-key-source.json").unlink()
        return result

    monkeypatch.setattr(backend, "enclave_ecdh", changed)
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)


def test_unrelated_vault_update_preserves_database_source_binding(source):
    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    (root / "mordred/unrelated.env").write_bytes(b"unrelated ciphertext update")
    assert authority.observe_database_source(root=root) == snapshot


def test_explicit_child_home_is_rejected_before_native_access(source):
    authority, root, backend, _ = source
    child = root / "profiles/child"
    child.mkdir(parents=True, mode=0o700)
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        authority.observe_database_source(root=child)
    assert backend.calls == before


@pytest.fixture
def mac_source(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes import _database_locking_posix
    from mordred_hermes.keyvault import _database_authority as authority
    from mordred_hermes.keyvault import _identity, _seckey_backend, vault
    from tests._keyvault_fakes import FakeAnchorStore

    monkeypatch.setattr(authority, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(_database_locking_posix, "sys", SimpleNamespace(platform="darwin"))
    backend = FakeBackend()
    store = FakeAnchorStore()
    (tmp_path / "mordred").mkdir(mode=0o700)
    vault_root = tmp_path / "mordred/vault"
    key_id = _identity.vault_identity(vault_root)
    backend.generate_enclave_key(key_id)
    from mordred_hermes.keyvault._database_mutation import database_key_mutation

    with (
        database_key_mutation(root=tmp_path, generation=None) as lease,
        vault.init_vault(
            vault_root,
            key_id=key_id,
            passphrase="synthetic-passphrase",
            backend=backend,
            store=store,
            anchor_label=key_id,
            database_lease=lease,
        ) as opened,
    ):
        opened.enroll_file(".env", b"HERMES_MEMORY_KEY=hex:" + b"61" * 32 + b"\nAPI_KEY=old\n", database_lease=lease)

    def native_only_backend(**kwargs):
        assert kwargs == {"sw_ops": None}
        return backend

    monkeypatch.setattr(_seckey_backend, "_SecKeyBackend", native_only_backend)
    monkeypatch.setattr(_identity, "resolve_store", lambda value: store)
    return authority, tmp_path, backend, store, key_id


def test_unrelated_macos_vault_update_preserves_database_source_binding(mac_source):
    from mordred_hermes.keyvault import vault

    authority, root, backend, store, key_id = mac_source
    snapshot = enroll(authority, root)
    before = list(backend.calls), list(store.calls)
    assert authority.observe_database_source(root=root) == snapshot
    assert (backend.calls, store.calls) == before
    with vault.open_vault(
        root / "mordred/vault", key_id=key_id, backend=backend, store=store, anchor_label=key_id
    ) as opened:
        opened.enroll_file(".env", b"HERMES_MEMORY_KEY=hex:" + b"61" * 32 + b"\nAPI_KEY=new\n")
        opened.enroll_file("config.yaml", b"unrelated: update\n")
    assert authority.observe_database_source(root=root) == snapshot
    assert authority.load_database_source(root=root, expected=snapshot) == b"a" * 32


def test_macos_source_load_rejects_legacy_malformed_dotenv(mac_source, monkeypatch):
    from mordred_hermes.keyvault import vault

    authority, root, _, _, _ = mac_source
    snapshot = enroll(authority, root)
    original = vault.OpenVault.read_file

    def legacy_payload(opened, name):
        if name == ".env":
            # Simulate a legacy authenticated payload rejected by new writers.
            return b"bad key =ignored\nHERMES_MEMORY_KEY=hex:" + b"61" * 32 + b"\n"
        return original(opened, name)

    monkeypatch.setattr(vault.OpenVault, "read_file", legacy_payload)
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)


def test_macos_uncommitted_wrapping_header_cannot_be_enrolled(mac_source):
    from mordred_hermes.keyvault import manifest, wrap
    from mordred_hermes.keyvault.kek import MasterKey

    authority, root, backend, _, key_id = mac_source
    vault_root = root / "mordred/vault"
    replacement = wrap.wrap_dek(b"b" * 32, key_id, backend=backend)
    with MasterKey(b"b" * 32) as master:
        future = manifest.VaultManifest(key_id=key_id, wmk=replacement, files={".env": "0" * 64}, generation=999)
        blob = manifest.encode(future, master)
    path = vault_root / "manifest.999.mvmf"
    path.write_bytes(blob)
    path.chmod(0o600)
    with pytest.raises(DatabaseRefused):
        enroll(authority, root)
    assert not (root / "mordred/db-key-source.json").exists()


def test_load_refuses_non_256_bit_material(source, monkeypatch):
    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    monkeypatch.setattr(memory, "load_linux_memory_key", lambda **kwargs: b"short")
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)


def test_authority_imports_without_sql(tmp_path):
    import os
    import subprocess
    import sys

    script = """
import importlib.abc
import sys
class NoSQL(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if "dbcrypt" in fullname or fullname.startswith(("sqlcipher", "pysqlcipher")):
            raise AssertionError("SQL imported by custody: " + fullname)
sys.meta_path.insert(0, NoSQL())
from mordred_hermes.keyvault._database_authority import observe_database_source
assert callable(observe_database_source)
"""
    environ = os.environ.copy()
    environ.pop("PYTHONPATH", None)
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=environ, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.fixture
def windows_source(fs, monkeypatch):  # noqa: F811
    from types import SimpleNamespace

    from mordred_hermes import _database_locking_windows as locking
    from mordred_hermes._database_contracts import RootIdentity
    from mordred_hermes.keyvault import _database_authority as authority
    from mordred_hermes.keyvault._database_mutation import database_key_mutation
    from tests.test_windows_custody_profile import SID

    custody, _, root, backend = fs
    with (
        database_key_mutation(root=root, generation=None) as database_lease,
        custody.windows_custody_session(root, create=True, backend=backend) as session,
    ):
        key = session.enroll_memory(database_lease=database_lease)
    monkeypatch.setattr(authority, "sys", SimpleNamespace(platform="win32"))
    identity = RootIdentity("win32", root.stat().st_dev, root.stat().st_ino.to_bytes(16, "little").hex(), SID.hex())
    monkeypatch.setattr(locking, "identify_root", lambda path: identity)
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    return authority, custody, root, backend, key


def test_windows_source_observation_is_native_free_and_generation_is_full(windows_source, monkeypatch):
    authority, custody, root, backend, key = windows_source
    snapshot = enroll(authority, root)
    assert snapshot.provider == "cng"
    assert len(snapshot.generation) == 64
    assert not (root / "mordred/db-key-source.json").exists()
    before = list(backend.calls)

    def no_backend():
        raise AssertionError("passive observation constructed a native backend")

    with monkeypatch.context() as patch:
        patch.setattr(custody, "windows_backend", no_backend)
        assert authority.observe_database_source(root=root) == snapshot
    assert backend.calls == before
    assert authority.load_database_source(root=root, expected=snapshot) == key
    assert sum(op == "ecdh" for op, _ in backend.calls[len(before) :]) == 1


def test_windows_unrelated_role_epochs_do_not_revoke_source(windows_source):
    authority, custody, root, backend, _ = windows_source
    snapshot = enroll(authority, root)
    with custody.windows_custody_session(root, backend=backend) as session:
        session.enroll_role("audit")
        session.enroll_role("telegram")
    assert authority.observe_database_source(root=root) == snapshot


@pytest.mark.parametrize("damage", ["missing", "malformed", "foreign"])
def test_windows_bad_wrapper_refuses_without_native_calls(windows_source, damage):
    from mordred_hermes.keyvault import wrap

    authority, _, root, backend, _ = windows_source
    snapshot = enroll(authority, root)
    path = root / "mordred/memory-key.wrapped"
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"x" * 127)
    else:
        backend.generate_enclave_key("foreign")
        path.write_bytes(wrap.wrap_dek(b"a" * 32, "foreign", backend=backend))
    before = list(backend.calls)
    with pytest.raises(DatabaseRefused):
        authority.observe_database_source(root=root)
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)
    assert backend.calls == before


def test_enrollment_refuses_expired_and_foreign_exclusive_leases(source):
    authority, root, _, _ = source
    with acquire_exclusive(root) as expired:
        pass
    with pytest.raises(DatabaseRefused):
        authority.enroll_database_source(root=root, lease=expired)
    other = root / "other-root"
    other.mkdir(mode=0o700)
    with acquire_exclusive(other) as foreign, pytest.raises(DatabaseRefused):
        authority.enroll_database_source(root=root, lease=foreign)
    assert not (root / "mordred/db-key-source.json").exists()


def test_missing_native_source_never_uses_ambient_key(source, monkeypatch):
    authority, root, backend, key = source
    snapshot = enroll(authority, root)
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + key.hex())
    backend._keys.clear()
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)


def test_macos_missing_native_source_never_uses_ambient_key(mac_source, monkeypatch):
    authority, root, backend, _, _ = mac_source
    snapshot = enroll(authority, root)
    monkeypatch.setenv("HERMES_MEMORY_KEY", "hex:" + "61" * 32)
    backend._keys.clear()
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)


def test_windows_memory_authority_epoch_change_rejects_expected_before_unwrap(windows_source):
    authority, _, root, backend, _ = windows_source
    snapshot = enroll(authority, root)
    path = root / "mordred/windows-custody.json"
    data = json.loads(path.read_bytes())
    data["epoch"] += 1
    data["roles"]["memory"]["current"]["epoch"] = data["epoch"]
    path.write_text(json.dumps(data))
    before = list(backend.calls)
    changed = authority.observe_database_source(root=root)
    assert changed.generation == snapshot.generation
    assert changed.record_sha256 != snapshot.record_sha256
    with pytest.raises(DatabaseRefused):
        authority.load_database_source(root=root, expected=snapshot)
    assert backend.calls == before


def test_hook_arming_does_not_replace_committed_native_source(source):
    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    for name in ("memory-vault.marker", "memory-vault.optout"):
        path = root / "mordred" / name
        path.write_bytes(b"1\n")
        path.chmod(0o600)
    assert authority.observe_database_source(root=root) == snapshot


def test_enrollment_refuses_forged_exclusive_subclass(source):
    from mordred_hermes._database_lifecycle import ExclusiveLease

    authority, root, _, _ = source

    class ForgedLease(ExclusiveLease):
        def __init__(self):
            pass

        def assert_held(self, root):
            pass

    with pytest.raises(DatabaseRefused):
        authority.enroll_database_source(root=root, lease=ForgedLease())
    assert not (root / "mordred/db-key-source.json").exists()


def test_valid_source_only_binding_can_retire_without_unwrap(source):
    authority, root, backend, _ = source
    snapshot = enroll(authority, root)
    before = list(backend.calls)
    with acquire_exclusive(root) as lease:
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert not (root / "mordred/db-key-source.json").exists()
    assert memory.memory_key_path(root).exists()
    assert backend.calls == before
    with pytest.raises(DatabaseRefused):
        authority.observe_database_source(root=root)


@pytest.mark.parametrize(
    "dependency",
    [
        "state.db",
        "mordred/db-encryption.marker",
        "mordred/db-encryption.pending",
        "mordred/db-backups.json",
        "backups/root.tgz",
        "mordred/db-key-source.json.tmp",
        "profiles/work/mordred/db-key-source.json",
    ],
)
def test_retirement_preserves_binding_when_any_dependency_remains(source, dependency):
    authority, root, backend, _ = source
    snapshot = enroll(authority, root)
    binding = root / "mordred/db-key-source.json"
    original = binding.read_bytes()
    path = root / dependency
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_bytes(b"retained dependency")
    before = list(backend.calls)
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert binding.read_bytes() == original
    assert backend.calls == before


def test_retirement_refuses_missing_wrong_or_expired_authority(source):
    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    binding = root / "mordred/db-key-source.json"
    original = binding.read_bytes()
    with acquire_exclusive(root) as expired:
        pass
    with pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=expired)
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=replace(snapshot, generation="f" * 32), lease=lease)
    assert binding.read_bytes() == original
    binding.unlink()
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)


def test_retirement_refuses_binding_replaced_before_unlink(source, monkeypatch):
    from mordred_hermes._private_fs import _posix

    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    binding = root / "mordred/db-key-source.json"
    original = binding.read_bytes()
    real_delete = _posix._Transaction.delete_file

    def replace_before_delete(tx, name, *, expected_identity=None):
        replacement = binding.with_suffix(".replacement")
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        replacement.replace(binding)
        return real_delete(tx, name, expected_identity=expected_identity)

    monkeypatch.setattr(_posix._Transaction, "delete_file", replace_before_delete)
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert binding.read_bytes() == original


def test_retirement_preserves_malformed_binding(source):
    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    binding = root / "mordred/db-key-source.json"
    binding.write_bytes(b"malformed source record\n")
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert binding.read_bytes() == b"malformed source record\n"


def test_retirement_guard_includes_other_known_generations(source, monkeypatch):
    from mordred_hermes import _database_inventory as inventory
    from mordred_hermes._database_contracts import Dependency, Inventory

    authority, root, _, _ = source
    snapshot = enroll(authority, root)
    binding = root / "mordred/db-key-source.json"
    original = binding.read_bytes()
    monkeypatch.setattr(
        inventory,
        "scan_dependencies",
        lambda path: Inventory((Dependency(root / "older.db", "database", "different-generation"),), True),
    )
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert binding.read_bytes() == original


def test_macos_source_retirement_does_not_open_native_or_anchor(mac_source):
    authority, root, backend, store, _ = mac_source
    snapshot = enroll(authority, root)
    before = list(backend.calls), list(store.calls)
    with acquire_exclusive(root) as lease:
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert (backend.calls, store.calls) == before
    assert not (root / "mordred/db-key-source.json").exists()
    assert (root / "mordred/vault").is_dir()


def test_windows_source_retirement_refuses_without_changing_custody(windows_source):
    authority, _, root, backend, _ = windows_source
    snapshot = enroll(authority, root)
    before = list(backend.calls)
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority.retire_database_source(root=root, expected=snapshot, lease=lease)
    assert authority.observe_database_source(root=root) == snapshot
    assert backend.calls == before


def test_historical_macos_source_authenticates_without_publishing(mac_source):
    authority, root, backend, _, _ = mac_source
    binding = root / "mordred/db-key-source.json"
    assert not binding.exists()
    before = list(backend.calls)
    with acquire_exclusive(root) as lease:
        digest, material = authority._load_historical_database_source(root=root, lease=lease)
    assert len(digest) == 64 and material == b"a" * 32
    assert not binding.exists()
    assert sum(op == "ecdh" for op, _ in backend.calls[len(before) :]) == 1


def test_historical_source_rechecks_actual_ex_before_custody(source, monkeypatch):
    authority, root, _backend, _ = source
    calls = []
    monkeypatch.setattr(authority, "_posix_record", lambda *args: calls.append(args))
    with acquire_exclusive(root) as lease:
        pass
    with pytest.raises(DatabaseRefused):
        authority._load_historical_database_source(root=root, lease=lease)
    assert calls == []


def test_historical_source_rejects_record_change_without_binding(source, monkeypatch):
    authority, root, _, _ = source
    original = authority._load_posix

    def replace_record(*args):
        material = original(*args)
        wrapped = root / "mordred/memory-key.wrapped"
        blob = bytearray(wrapped.read_bytes())
        blob[-1] ^= 1
        wrapped.write_bytes(blob)
        return material

    monkeypatch.setattr(authority, "_load_posix", replace_record)
    with acquire_exclusive(root) as lease, pytest.raises(DatabaseRefused):
        authority._load_historical_database_source(root=root, lease=lease)
    assert not (root / "mordred/db-key-source.json").exists()
