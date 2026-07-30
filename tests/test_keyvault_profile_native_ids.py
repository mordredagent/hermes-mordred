"""Profile-scoped native-key identifiers and legacy ownership compatibility."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _native_key_id, _secret_ops, _storage, api, log_encryption, wrap
from mordred_hermes.keyvault._exceptions import WrapError, WrapKeyNotFound
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps
from mordred_hermes.privacy_check.audit import NDJSONWriter, make_audit_writer
from mordred_hermes.wizard import keyvault_cli
from mordred_hermes.wizard._keyvault_init import _provision_audit_log_key
from tests._keyvault_fakes import FakeBackend


def _prepare() -> tuple[api.SeedDisplayHandle, bytes]:
    return api.prepare_generate("profile scoped seed", "passphrase", b"\x42" * 32)


def _init(home: Path, backend: FakeBackend, key_id: str = "default") -> str:
    handle, digest = _prepare()
    api.confirm_generate(
        handle,
        digest,
        key_id=key_id,
        backend=backend,
        audit_sink=lambda _entry: None,
        home=home,
    )
    root = _storage.resolve_keyvault_dir(home)
    return _native_key_id.scoped_native_key_id(root, key_id)


def _legacy_meta(home: Path, backend: FakeBackend, key_id: str = "default") -> Path:
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    backend.generate_enclave_key(key_id)
    key_hash = wrap._key_id_hash(key_id).hex()
    meta = _storage.load_meta(root)
    meta["keys"][key_hash] = {"key_id": key_id, "created_at": "2026-01-01T00:00:00Z"}
    _storage.atomic_write(root / "digests" / f"{key_hash}.commit", b"\x11" * 32)
    _storage.save_meta(root, meta)
    return root


def _scoped_audit_file(tmp_path: Path) -> tuple[FakeBackend, Path, Path, Path]:
    """Create one scoped MRAL file and return backend/path/home/root."""

    backend = FakeBackend()
    home = tmp_path / "profile"
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.generate_enclave_key(physical)
    log_path = tmp_path / "audit.log"
    log_encryption.EncryptedWriter(
        log_path,
        backend=backend,
        native_key_id=physical,
    ).append({"event": "scoped"})
    backend.calls.clear()
    return backend, log_path, home, root


def _replace_main_hash_with_traversal(home: Path) -> tuple[Path, Path]:
    """Move the sole main row under a traversal-shaped metadata object key."""

    root = _storage.resolve_keyvault_dir(home)
    meta = _storage.load_meta(root)
    [(_key_hash, row)] = meta["keys"].items()
    hostile_hash = "../../../victim"
    meta["keys"] = {hostile_hash: row}
    _storage.save_meta(root, meta)
    victim = (root / "digests" / f"{hostile_hash}.commit").resolve()
    victim.write_bytes(b"V" * 32)
    os.chmod(victim, 0o600)
    return root, victim


def _replace_digests_with_external_symlink(root: Path, base: Path, key_id: str = "default") -> Path:
    """Redirect ``root/digests`` to an external 0700 directory."""

    digests = root / "digests"
    digests.rename(root / "original-digests")
    external = base / "external-digests"
    external.mkdir(mode=0o700)
    os.chmod(external, 0o700)
    victim = external / f"{wrap._key_id_hash(key_id).hex()}.commit"
    victim.write_bytes(b"V" * 32)
    os.chmod(victim, 0o600)
    digests.symlink_to(external, target_is_directory=True)
    return victim


def test_scoped_id_is_deterministic_private_and_profile_distinct(tmp_path: Path) -> None:
    root_a = tmp_path / "profile-a" / "mordred" / "keyvault"
    root_b = tmp_path / "profile-b" / "mordred" / "keyvault"
    first = _native_key_id.scoped_native_key_id(root_a, "wallet-secret")

    assert first == _native_key_id.scoped_native_key_id(root_a, "wallet-secret")
    assert first != _native_key_id.scoped_native_key_id(root_b, "wallet-secret")
    assert "wallet-secret" not in first
    assert str(root_a) not in first


def test_scoped_id_supports_a_surrogateescape_profile_path(tmp_path: Path) -> None:
    raw_component = b"profile-\xff"
    component = os.fsdecode(raw_component)
    if os.fsencode(component) != raw_component:
        pytest.skip("filesystem encoding does not use a reversible surrogateescape")
    root = tmp_path / component / "mordred" / "keyvault"

    first = _native_key_id.scoped_native_key_id(root, "default")

    assert first == _native_key_id.scoped_native_key_id(root, "default")
    assert first.startswith("mordred-hermes.native.v1.")


def test_scoped_id_canonicalizes_parent_directory_aliases(tmp_path: Path) -> None:
    real_home_parent = tmp_path / "real"
    real_home_parent.mkdir()
    alias_home_parent = tmp_path / "alias"
    alias_home_parent.symlink_to(real_home_parent, target_is_directory=True)
    real_root = real_home_parent / "profile" / "mordred" / "keyvault"
    alias_root = alias_home_parent / "profile" / "mordred" / "keyvault"

    assert _native_key_id.scoped_native_key_id(alias_root, "default") == _native_key_id.scoped_native_key_id(
        real_root,
        "default",
    )


def test_scoped_id_does_not_follow_a_symlink_at_managed_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-keyvault"
    real_root.mkdir()
    linked_root = tmp_path / "linked-keyvault"
    linked_root.symlink_to(real_root, target_is_directory=True)

    assert _native_key_id.scoped_native_key_id(linked_root, "default") != _native_key_id.scoped_native_key_id(
        real_root,
        "default",
    )


def test_profile_can_be_initialized_and_used_through_equivalent_home_aliases(tmp_path: Path) -> None:
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    alias_home = tmp_path / "alias-home"
    alias_home.symlink_to(real_home, target_is_directory=True)
    backend = FakeBackend()

    _init(alias_home, backend)
    envelope_id = api.encrypt(
        "default",
        b"same-profile",
        "secret",
        backend=backend,
        audit_sink=lambda _entry: None,
        home=real_home,
    )

    assert (
        api.decrypt(
            "default",
            envelope_id,
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=alias_home,
        )
        == b"same-profile"
    )


def test_precanonical_scoped_main_alias_still_provisions_and_uses_audit_key(tmp_path: Path) -> None:
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    alias_home = tmp_path / "alias-home"
    alias_home.symlink_to(real_home, target_is_directory=True)
    root = _storage.resolve_keyvault_dir(alias_home)
    logical_key_id = "default"
    legacy_native_key_id = _native_key_id._native_key_id_for_root_name(
        os.path.abspath(os.fspath(root)),
        logical_key_id,
    )
    assert legacy_native_key_id != _native_key_id.scoped_native_key_id(root, logical_key_id)

    backend = FakeBackend()
    backend.generate_enclave_key(legacy_native_key_id)
    _storage.ensure_layout(root)
    key_id_hash = wrap._key_id_hash(logical_key_id).hex()
    meta = _storage.load_meta(root)
    meta["keys"][key_id_hash] = {
        "key_id": logical_key_id,
        "created_at": "2026-01-01T00:00:00Z",
        _native_key_id.NATIVE_KEY_ID_FIELD: legacy_native_key_id,
    }
    _storage.atomic_write(root / "digests" / f"{key_id_hash}.commit", b"\x11" * 32)
    _storage.save_meta(root, meta)

    _provision_audit_log_key(backend, home=alias_home)

    audit_native_key_id = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    committed = _storage.load_meta(root)
    assert (
        _native_key_id.committed_audit_key_from_meta(root, committed, log_encryption.AUDIT_LOG_KEY_ID)
        == audit_native_key_id
    )
    assert ("generate", audit_native_key_id) in backend.calls
    writer = make_audit_writer(alias_home / "audit.log", keyvault_home=alias_home, backend=backend)
    assert isinstance(writer, log_encryption.EncryptedWriter)


def test_helper_backend_binds_explicit_api_root_not_ambient_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    root = tmp_path / "explicit" / "mordred" / "keyvault"
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delenv("MORDRED_SEKEY_STORE", raising=False)
    backend = _SecKeyBackend(ops=_HelperSecKeyOps("/fake/se-helper"), sw_ops=None)

    bound = _native_key_id.bind_backend_to_root(backend, root)

    assert isinstance(bound, _SecKeyBackend)
    assert isinstance(bound._ops, _HelperSecKeyOps)
    assert bound._ops._env_override == ("MORDRED_SEKEY_STORE", str(root / "sekey"))


def test_helper_backend_preserves_authoritative_store_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    root = tmp_path / "explicit" / "mordred" / "keyvault"
    override = tmp_path / "operator-store"
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("MORDRED_SEKEY_STORE", str(override))
    backend = _SecKeyBackend(ops=_HelperSecKeyOps("/fake/se-helper"), sw_ops=None)

    bound = _native_key_id.bind_backend_to_root(backend, root)

    assert isinstance(bound, _SecKeyBackend)
    assert isinstance(bound._ops, _HelperSecKeyOps)
    assert bound._ops._env_override == ("MORDRED_SEKEY_STORE", str(override))


class _AmbientStoreBackend:
    """Fake helper whose unbound instance uses an ambient historical store."""

    def __init__(
        self,
        *,
        ambient: FakeBackend | None = None,
        root_stores: dict[str, FakeBackend] | None = None,
        selected_root: str | None = None,
    ) -> None:
        self.ambient = ambient if ambient is not None else FakeBackend()
        self.root_stores = root_stores if root_stores is not None else {}
        self.selected_root = selected_root

    @property
    def active(self) -> FakeBackend:
        if self.selected_root is None:
            return self.ambient
        return self.root_stores.setdefault(self.selected_root, FakeBackend())

    def _for_keyvault_root(self, root: Path) -> _AmbientStoreBackend:
        return _AmbientStoreBackend(
            ambient=self.ambient,
            root_stores=self.root_stores,
            selected_root=str(root),
        )

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        return self.active.generate_enclave_key(key_id, unattended=unattended)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        return self.active.get_enclave_public_key(key_id)

    def delete_enclave_key(self, key_id: str) -> None:
        self.active.delete_enclave_key(key_id)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        return self.active.enclave_ecdh(key_id, peer_pub)


def test_legacy_explicit_home_can_read_key_from_historical_ambient_helper_store(tmp_path: Path) -> None:
    home = tmp_path / "explicit-home"
    backend = _AmbientStoreBackend()
    root = _legacy_meta(home, backend)  # pre-scoping helper used ambient HERMES_HOME

    envelope_id = api.encrypt(
        "default",
        b"legacy-secret",
        "secret",
        backend=backend,
        audit_sink=lambda _entry: None,
        home=home,
    )

    assert (
        api.decrypt(
            "default",
            envelope_id,
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=home,
        )
        == b"legacy-secret"
    )
    bound_calls = backend.root_stores[str(root)].calls
    assert ("get_pub", "default") in bound_calls
    assert ("ecdh", "default") in bound_calls
    assert ("get_pub", "default") in backend.ambient.calls
    assert ("ecdh", "default") in backend.ambient.calls


def test_scoped_key_never_falls_back_to_ambient_helper_store(tmp_path: Path) -> None:
    home = tmp_path / "explicit-home"
    backend = _AmbientStoreBackend()
    physical = _init(home, backend)  # current generation is root-bound
    root = _storage.resolve_keyvault_dir(home)
    root_store = backend.root_stores[str(root)]
    root_store.delete_enclave_key(physical)
    backend.ambient.generate_enclave_key(physical)
    backend.ambient.calls.clear()

    with pytest.raises(WrapKeyNotFound):
        api.encrypt(
            "default",
            b"must-not-use-ambient",
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=home,
        )

    assert backend.ambient.calls == []


def test_two_profiles_can_use_same_logical_id_without_native_collision(tmp_path: Path) -> None:
    backend = FakeBackend()
    home_a = tmp_path / "a"
    home_b = tmp_path / "b"
    native_a = _init(home_a, backend)
    native_b = _init(home_b, backend)

    assert native_a != native_b
    envelope_a = api.encrypt(
        "default",
        b"profile-a",
        "secret",
        backend=backend,
        audit_sink=lambda _entry: None,
        home=home_a,
    )
    envelope_b = api.encrypt(
        "default",
        b"profile-b",
        "secret",
        backend=backend,
        audit_sink=lambda _entry: None,
        home=home_b,
    )
    assert (
        api.decrypt(
            "default",
            envelope_a,
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=home_a,
        )
        == b"profile-a"
    )
    assert (
        api.decrypt(
            "default",
            envelope_b,
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=home_b,
        )
        == b"profile-b"
    )

    backend.calls.clear()
    assert keyvault_cli.reset_keyvault(home=home_a, backend=backend, assume_yes=True) == 0
    deleted = {key_id for operation, key_id in backend.calls if operation == "delete"}
    assert native_a in deleted
    assert native_b not in deleted
    assert (
        api.decrypt(
            "default",
            envelope_b,
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=home_b,
        )
        == b"profile-b"
    )


def test_mrkw_wire_hash_remains_logical_while_native_lookup_is_scoped(tmp_path: Path) -> None:
    backend = FakeBackend()
    root = tmp_path / "profile" / "mordred" / "keyvault"
    logical = "portable-logical-id"
    physical = _native_key_id.scoped_native_key_id(root, logical)
    backend.generate_enclave_key(physical)

    blob = wrap.wrap_dek(b"\x23" * 32, logical, backend=backend, native_key_id=physical)

    assert blob[6:22] == wrap._key_id_hash(logical)
    assert (
        wrap.unwrap_dek(
            blob,
            logical,
            backend=backend,
            native_key_id=physical,
            audit_sink=lambda _entry: None,
        )
        == b"\x23" * 32
    )


def test_legacy_row_stays_readable_but_reset_never_deletes_global_id(tmp_path: Path) -> None:
    backend = FakeBackend()
    root = _legacy_meta(tmp_path, backend)
    envelope_id = api.encrypt(
        "default",
        b"legacy",
        "secret",
        backend=backend,
        audit_sink=lambda _entry: None,
        home=tmp_path,
    )
    assert (
        api.decrypt(
            "default",
            envelope_id,
            "secret",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=tmp_path,
        )
        == b"legacy"
    )

    backend.calls.clear()
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    deleted = {key_id for operation, key_id in backend.calls if operation == "delete"}
    assert "default" not in deleted
    assert log_encryption.AUDIT_LOG_KEY_ID not in deleted
    assert _native_key_id.scoped_native_key_id(root, "default") in deleted


@pytest.mark.parametrize("persisted", [None, 7, "", "mordred-hermes.native.v1.foreign"])
def test_present_invalid_native_id_resets_only_deterministic_scoped_target(
    tmp_path: Path,
    persisted: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    backend = FakeBackend()
    root = _legacy_meta(tmp_path, backend)
    meta = _storage.load_meta(root)
    row = next(iter(meta["keys"].values()))
    row[_native_key_id.NATIVE_KEY_ID_FIELD] = persisted
    _storage.save_meta(root, meta)
    backend.calls.clear()

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    deleted = {key_id for operation, key_id in backend.calls if operation == "delete"}
    assert _native_key_id.scoped_native_key_id(root, "default") in deleted
    assert "default" not in deleted
    if isinstance(persisted, str):
        assert persisted not in deleted
    assert not root.exists()
    assert "metadata was incomplete" in capsys.readouterr().out.lower()


def test_surrogate_key_id_metadata_resets_cleanly_without_using_it_as_a_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    meta["keys"]["malformed"] = {
        "key_id": "\ud800",
        "created_at": "2026-01-01T00:00:00Z",
        _native_key_id.NATIVE_KEY_ID_FIELD: "untrusted-selector",
    }
    _storage.save_meta(root, meta)
    backend = FakeBackend()

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0

    selected = {key_id for _operation, key_id in backend.calls}
    assert "untrusted-selector" not in selected
    assert "\ud800" not in selected
    assert "metadata was incomplete" in capsys.readouterr().out.lower()


def test_present_null_native_id_blocks_decrypt_before_backend_io(tmp_path: Path) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    envelope_id = api.encrypt(
        "default",
        b"secret",
        "purpose",
        backend=backend,
        audit_sink=lambda _entry: None,
        home=tmp_path,
    )
    root = _storage.resolve_keyvault_dir(tmp_path)
    meta = _storage.load_meta(root)
    row = next(iter(meta["keys"].values()))
    row[_native_key_id.NATIVE_KEY_ID_FIELD] = None
    _storage.save_meta(root, meta)
    backend.calls.clear()

    with pytest.raises(_storage.KeyvaultCorruptError, match="native_key_id"):
        api.decrypt(
            "default",
            envelope_id,
            "purpose",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=tmp_path,
        )
    assert backend.calls == []


class _GeneratePublishedThenFailed(FakeBackend):
    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        super().generate_enclave_key(key_id, unattended=unattended)
        raise WrapError("helper reported a post-publication durability failure")


def test_generation_error_leaves_owned_pending_journal_for_reset(tmp_path: Path) -> None:
    backend = _GeneratePublishedThenFailed()
    handle, digest = _prepare()
    with pytest.raises(WrapError):
        api.confirm_generate(
            handle,
            digest,
            backend=backend,
            audit_sink=lambda _entry: None,
            home=tmp_path,
        )

    root = _storage.resolve_keyvault_dir(tmp_path)
    meta = _storage.load_meta(root)
    pending = _native_key_id.pending_native_key_from_meta(root, meta)
    assert pending is not None
    _logical, physical = pending

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert ("delete", physical) in backend.calls


class _DeleteFailsOnce(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.fail_delete = True

    def delete_enclave_key(self, key_id: str) -> None:
        if self.fail_delete:
            self.fail_delete = False
            self.calls.append(("delete", key_id))
            raise WrapError("temporary delete failure")
        super().delete_enclave_key(key_id)


def test_failed_rollback_retains_pending_ownership_until_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _DeleteFailsOnce()
    real_atomic_write = _storage.atomic_write

    def fail_commit(path: Path, data: bytes) -> None:
        if path.suffix == ".commit":
            raise OSError("commit failed")
        real_atomic_write(path, data)

    monkeypatch.setattr(_storage, "atomic_write", fail_commit)
    handle, digest = _prepare()
    with pytest.raises(OSError, match="commit failed"):
        api.confirm_generate(
            handle,
            digest,
            key_id="custom",
            backend=backend,
            audit_sink=lambda _entry: None,
            home=tmp_path,
        )

    root = _storage.resolve_keyvault_dir(tmp_path)
    pending = _native_key_id.pending_native_key_from_meta(root, _storage.load_meta(root))
    assert pending is not None
    assert pending[0] == "custom"

    monkeypatch.setattr(_storage, "atomic_write", real_atomic_write)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert ("delete", pending[1]) in backend.calls


def test_audit_key_provision_does_not_recreate_key_after_reset_wins(tmp_path: Path) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)

    # Model reset winning the lifecycle order before the best-effort
    # post-commit auxiliary provisioning step begins.
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    backend.calls.clear()
    _provision_audit_log_key(backend, home=tmp_path)

    assert not root.exists()
    assert not any(operation == "generate" for operation, _key_id in backend.calls)


def test_audit_key_provision_commits_metadata_and_is_idempotent(tmp_path: Path) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)

    _provision_audit_log_key(backend, home=tmp_path)
    _provision_audit_log_key(backend, home=tmp_path)

    meta = _storage.load_meta(root)
    assert _native_key_id.pending_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) is None
    assert _native_key_id.committed_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    assert backend.calls.count(("generate", physical)) == 1
    writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=backend)
    assert isinstance(writer, log_encryption.EncryptedWriter)


def test_scoped_audit_factory_requires_committed_record_even_when_native_key_exists(tmp_path: Path) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.generate_enclave_key(physical)
    backend.calls.clear()

    writer = make_audit_writer(tmp_path / "uncommitted.log", keyvault_home=tmp_path, backend=backend)

    assert isinstance(writer, NDJSONWriter)
    assert backend.calls == []


def test_scoped_audit_factory_rejects_tampered_committed_record_before_backend_io(tmp_path: Path) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    _provision_audit_log_key(backend, home=tmp_path)
    root = _storage.resolve_keyvault_dir(tmp_path)
    meta = _storage.load_meta(root)
    audit_record = meta[_native_key_id.AUDIT_KEY_FIELD]
    assert isinstance(audit_record, dict)
    audit_record[_native_key_id.NATIVE_KEY_ID_FIELD] = _native_key_id.scoped_native_key_id(
        tmp_path / "other-profile" / "mordred" / "keyvault",
        log_encryption.AUDIT_LOG_KEY_ID,
    )
    _storage.save_meta(root, meta)
    backend.calls.clear()

    writer = make_audit_writer(tmp_path / "tampered.log", keyvault_home=tmp_path, backend=backend)

    assert isinstance(writer, NDJSONWriter)
    assert backend.calls == []


def test_scoped_audit_factory_rejects_traversal_hash_before_external_read_or_backend_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    _provision_audit_log_key(backend, home=tmp_path)
    _root, victim = _replace_main_hash_with_traversal(tmp_path)
    victim_before = victim.read_bytes()
    read_paths: list[Path] = []
    real_safe_read = _storage.safe_read

    def tracking_safe_read(path: Path) -> bytes:
        read_paths.append(path.resolve(strict=False))
        return real_safe_read(path)

    monkeypatch.setattr(_storage, "safe_read", tracking_safe_read)
    backend.calls.clear()

    writer = make_audit_writer(tmp_path / "traversal.log", keyvault_home=tmp_path, backend=backend)

    assert isinstance(writer, NDJSONWriter)
    assert backend.calls == []
    assert victim.resolve() not in read_paths
    assert victim.read_bytes() == victim_before


def test_core_and_audit_factory_reject_symlinked_digests_before_external_read_or_backend_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    _provision_audit_log_key(backend, home=tmp_path)
    root = _storage.resolve_keyvault_dir(tmp_path)
    victim = _replace_digests_with_external_symlink(root, tmp_path)
    victim_before = victim.read_bytes()
    read_paths: list[Path] = []
    real_safe_read = _storage.safe_read

    def tracking_safe_read(path: Path) -> bytes:
        read_paths.append(path.resolve(strict=False))
        return real_safe_read(path)

    monkeypatch.setattr(_storage, "safe_read", tracking_safe_read)
    backend.calls.clear()
    key_hash = wrap._key_id_hash("default").hex()

    with pytest.raises(_storage.KeyvaultCorruptError, match="digest directory"):
        _secret_ops._assert_key_committed(root, "default", key_hash)
    writer = make_audit_writer(tmp_path / "symlinked-digests.log", keyvault_home=tmp_path, backend=backend)

    assert isinstance(writer, NDJSONWriter)
    assert backend.calls == []
    assert victim.resolve() not in read_paths
    assert victim.read_bytes() == victim_before


def test_audit_provision_rejects_traversal_hash_before_external_read_or_backend_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    _root, victim = _replace_main_hash_with_traversal(tmp_path)
    victim_before = victim.read_bytes()
    read_paths: list[Path] = []
    real_safe_read = _storage.safe_read

    def tracking_safe_read(path: Path) -> bytes:
        read_paths.append(path.resolve(strict=False))
        return real_safe_read(path)

    monkeypatch.setattr(_storage, "safe_read", tracking_safe_read)
    backend.calls.clear()

    _provision_audit_log_key(backend, home=tmp_path)

    assert backend.calls == []
    assert victim.resolve() not in read_paths
    assert victim.read_bytes() == victim_before


def test_audit_key_provision_adopts_exact_scoped_duplicate_after_durable_pending(tmp_path: Path) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.generate_enclave_key(physical)  # pre-record scoped release / interrupted prior attempt
    backend.calls.clear()

    _provision_audit_log_key(backend, home=tmp_path)

    meta = _storage.load_meta(root)
    assert _native_key_id.PENDING_AUDIT_KEY_FIELD not in meta
    assert _native_key_id.committed_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    assert ("generate", physical) in backend.calls
    assert ("get_pub", physical) in backend.calls
    assert not any(operation == "delete" for operation, _key_id in backend.calls)


class _AuditPublishedThenFailed(FakeBackend):
    fail_key_id: str | None = None

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        public = super().generate_enclave_key(key_id, unattended=unattended)
        if key_id == self.fail_key_id:
            raise WrapError("audit helper reported a post-publication durability failure")
        return public


def test_audit_generation_durability_error_recovers_by_discarding_the_untrusted_key(tmp_path: Path) -> None:
    """A durability failure must degrade, then still be recoverable.

    The refusal to *adopt* a visible-but-unproven native key is deliberate:
    visibility is not durability. Refusing and stopping there, however, left the
    profile permanently plaintext — every retry re-derived the same scoped
    selector, hit the same duplicate and re-refused. The retry therefore
    discards the untrusted key (strictly stronger than adopting it; nothing can
    depend on it because committed ownership was never published) so the next
    attempt provisions cleanly.
    """
    backend = _AuditPublishedThenFailed()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.fail_key_id = physical

    _provision_audit_log_key(backend, home=tmp_path)

    # Phase 1: the durability error leaves pending published and uncommitted,
    # and the audit log correctly stays plaintext.
    meta = _storage.load_meta(root)
    assert _native_key_id.pending_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    assert _native_key_id.AUDIT_KEY_FIELD not in meta
    backend.calls.clear()
    writer = make_audit_writer(tmp_path / "pending.log", keyvault_home=tmp_path, backend=backend)
    assert isinstance(writer, NDJSONWriter)
    assert backend.calls == []

    # Phase 2: the retry still refuses to adopt, but now discards the key of
    # unproven durability instead of stranding the profile.
    backend.fail_key_id = None
    _provision_audit_log_key(backend, home=tmp_path)
    retried_meta = _storage.load_meta(root)
    assert _native_key_id.PENDING_AUDIT_KEY_FIELD not in retried_meta
    assert _native_key_id.AUDIT_KEY_FIELD not in retried_meta
    assert ("delete", physical) in backend.calls
    retried = make_audit_writer(tmp_path / "retried.log", keyvault_home=tmp_path, backend=backend)
    assert isinstance(retried, NDJSONWriter)

    # Phase 3: a clean run now succeeds — the profile self-heals rather than
    # staying plaintext forever.
    _provision_audit_log_key(backend, home=tmp_path)
    healed_meta = _storage.load_meta(root)
    assert _native_key_id.PENDING_AUDIT_KEY_FIELD not in healed_meta
    assert _native_key_id.committed_audit_key_from_meta(root, healed_meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    healed = make_audit_writer(tmp_path / "healed.log", keyvault_home=tmp_path, backend=backend)
    assert not isinstance(healed, NDJSONWriter), "audit-log encryption must be active after recovery"


class _AuditDeleteFails(FakeBackend):
    fail_delete_key_id: str | None = None

    def delete_enclave_key(self, key_id: str) -> None:
        if key_id == self.fail_delete_key_id:
            self.calls.append(("delete", key_id))
            raise WrapError("audit native delete failed")
        super().delete_enclave_key(key_id)


def test_audit_ownership_post_replace_failure_and_delete_failure_stays_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _AuditDeleteFails()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.fail_delete_key_id = physical
    real_save_meta = _storage.save_meta

    def ownership_commit_then_boom(saved_root: Path, meta: dict[str, Any]) -> None:
        real_save_meta(saved_root, meta)
        if _native_key_id.AUDIT_KEY_FIELD in meta and _native_key_id.PENDING_AUDIT_KEY_FIELD in meta:
            raise OSError("audit ownership parent fsync failed")

    monkeypatch.setattr(_storage, "save_meta", ownership_commit_then_boom)
    _provision_audit_log_key(backend, home=tmp_path)

    meta = _storage.load_meta(root)
    assert _native_key_id.pending_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    assert _native_key_id.committed_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    backend.calls.clear()
    writer = make_audit_writer(tmp_path / "uncertain.log", keyvault_home=tmp_path, backend=backend)
    assert isinstance(writer, NDJSONWriter)
    assert backend.calls == []

    # Here row+pending proves generation returned success before the metadata
    # fsync error. Once the transient delete failure clears, retry may adopt
    # that exact duplicate and complete only the pending cleanup.
    monkeypatch.setattr(_storage, "save_meta", real_save_meta)
    backend.fail_delete_key_id = None
    _provision_audit_log_key(backend, home=tmp_path)
    resumed = make_audit_writer(tmp_path / "resumed.log", keyvault_home=tmp_path, backend=backend)
    assert isinstance(resumed, log_encryption.EncryptedWriter)


def test_audit_ownership_commit_failure_rolls_back_new_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    real_save_meta = _storage.save_meta

    def fail_before_ownership_commit(saved_root: Path, meta: dict[str, Any]) -> None:
        if _native_key_id.AUDIT_KEY_FIELD in meta and _native_key_id.PENDING_AUDIT_KEY_FIELD in meta:
            raise OSError("audit ownership write failed")
        real_save_meta(saved_root, meta)

    monkeypatch.setattr(_storage, "save_meta", fail_before_ownership_commit)
    _provision_audit_log_key(backend, home=tmp_path)

    meta = _storage.load_meta(root)
    assert _native_key_id.PENDING_AUDIT_KEY_FIELD not in meta
    assert _native_key_id.AUDIT_KEY_FIELD not in meta
    assert ("delete", physical) in backend.calls
    with pytest.raises(WrapKeyNotFound):
        backend.get_enclave_public_key(physical)


def test_audit_pending_cleanup_post_replace_error_accepts_visible_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    _init(tmp_path, backend)
    root = _storage.resolve_keyvault_dir(tmp_path)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    real_save_meta = _storage.save_meta

    def cleanup_commit_then_boom(saved_root: Path, meta: dict[str, Any]) -> None:
        real_save_meta(saved_root, meta)
        if _native_key_id.AUDIT_KEY_FIELD in meta and _native_key_id.PENDING_AUDIT_KEY_FIELD not in meta:
            raise OSError("audit pending cleanup parent fsync failed")

    monkeypatch.setattr(_storage, "save_meta", cleanup_commit_then_boom)
    _provision_audit_log_key(backend, home=tmp_path)

    meta = _storage.load_meta(root)
    assert _native_key_id.PENDING_AUDIT_KEY_FIELD not in meta
    assert _native_key_id.committed_audit_key_from_meta(root, meta, log_encryption.AUDIT_LOG_KEY_ID) == physical
    writer = make_audit_writer(tmp_path / "committed.log", keyvault_home=tmp_path, backend=backend)
    assert isinstance(writer, log_encryption.EncryptedWriter)


def test_mral_header_selects_scoped_native_id_and_legacy_header_still_reads(tmp_path: Path) -> None:
    backend = FakeBackend()
    home = tmp_path / "profile"
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.generate_enclave_key(physical)
    scoped_path = tmp_path / "scoped.log"
    log_encryption.EncryptedWriter(
        scoped_path,
        backend=backend,
        native_key_id=physical,
    ).append({"event": "scoped"})
    scoped_header = json.loads(scoped_path.read_bytes().splitlines()[0])
    assert scoped_header[_native_key_id.NATIVE_KEY_ID_FIELD] == physical
    audit: list[dict[str, Any]] = []
    assert (
        log_encryption.decrypt_log_file(
            scoped_path,
            backend=backend,
            audit_sink=audit.append,
            keyvault_home=home,
        )[0]["event"]
        == "scoped"
    )
    assert audit[-1]["key_id_hash"] == wrap._audit_key_id_hex(log_encryption.AUDIT_LOG_KEY_ID)

    backend.generate_enclave_key(log_encryption.AUDIT_LOG_KEY_ID)
    legacy_path = tmp_path / "legacy.log"
    log_encryption.EncryptedWriter(legacy_path, backend=backend).append({"event": "legacy"})
    legacy_header = json.loads(legacy_path.read_bytes().splitlines()[0])
    assert _native_key_id.NATIVE_KEY_ID_FIELD not in legacy_header
    assert (
        log_encryption.decrypt_log_file(
            legacy_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )[0]["event"]
        == "legacy"
    )


def test_legacy_mral_explicit_home_falls_back_to_historical_ambient_store(tmp_path: Path) -> None:
    home = tmp_path / "explicit-home"
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    backend = _AmbientStoreBackend()
    backend.generate_enclave_key(log_encryption.AUDIT_LOG_KEY_ID)
    log_path = tmp_path / "legacy-audit.log"
    log_encryption.EncryptedWriter(log_path, backend=backend).append({"event": "legacy-ambient"})

    assert (
        log_encryption.decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )[0]["event"]
        == "legacy-ambient"
    )
    assert ("ecdh", log_encryption.AUDIT_LOG_KEY_ID) in backend.root_stores[str(root)].calls
    assert ("ecdh", log_encryption.AUDIT_LOG_KEY_ID) in backend.ambient.calls


def test_legacy_audit_factory_uses_historical_ambient_store(tmp_path: Path) -> None:
    home = tmp_path / "explicit-home"
    backend = _AmbientStoreBackend()
    root = _legacy_meta(home, backend)
    backend.generate_enclave_key(log_encryption.AUDIT_LOG_KEY_ID)

    writer = make_audit_writer(
        tmp_path / "audit.log",
        keyvault_home=home,
        backend=backend,
    )
    assert isinstance(writer, log_encryption.EncryptedWriter)
    writer.append({"event": "legacy-factory"})

    assert ("get_pub", log_encryption.AUDIT_LOG_KEY_ID) in backend.root_stores[str(root)].calls
    assert ("get_pub", log_encryption.AUDIT_LOG_KEY_ID) in backend.ambient.calls


def test_scoped_mral_never_falls_back_to_ambient_store(tmp_path: Path) -> None:
    home = tmp_path / "explicit-home"
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    backend = _AmbientStoreBackend()
    native_key_id = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    bound = _native_key_id.bind_backend_to_root(backend, root)
    bound.generate_enclave_key(native_key_id)
    log_path = tmp_path / "scoped-audit.log"
    log_encryption.EncryptedWriter(
        log_path,
        backend=bound,
        native_key_id=native_key_id,
    ).append({"event": "scoped"})
    backend.root_stores[str(root)].delete_enclave_key(native_key_id)
    backend.ambient.generate_enclave_key(native_key_id)
    backend.ambient.calls.clear()

    with pytest.raises(WrapKeyNotFound):
        log_encryption.decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )
    assert backend.ambient.calls == []


def test_mral_present_null_native_id_is_rejected_before_backend_io(tmp_path: Path) -> None:
    backend = FakeBackend()
    home = tmp_path / "profile"
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    physical = _native_key_id.scoped_native_key_id(root, log_encryption.AUDIT_LOG_KEY_ID)
    backend.generate_enclave_key(physical)
    log_path = tmp_path / "audit.log"
    writer = log_encryption.EncryptedWriter(log_path, backend=backend, native_key_id=physical)
    writer.append({"event": "scoped"})
    writer.close()

    lines = log_path.read_bytes().splitlines()
    header = json.loads(lines[0])
    header[_native_key_id.NATIVE_KEY_ID_FIELD] = None
    lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    log_path.write_bytes(b"\n".join(lines) + b"\n")
    backend.calls.clear()

    with pytest.raises(log_encryption.AuditLogDecryptError, match="native_key_id"):
        log_encryption.decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )
    assert backend.calls == []


@pytest.mark.parametrize("tamper_kind", ["main-role", "foreign-selector", "extra-field"])
def test_mral_header_role_selector_and_schema_are_rejected_before_backend_io(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    backend, log_path, home, root = _scoped_audit_file(tmp_path)
    lines = log_path.read_bytes().splitlines()
    header = json.loads(lines[0])
    if tamper_kind == "main-role":
        header["key_id"] = "default"
    elif tamper_kind == "foreign-selector":
        header[_native_key_id.NATIVE_KEY_ID_FIELD] = _native_key_id.scoped_native_key_id(root, "default")
    else:
        header["unexpected"] = "field"
    lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises(log_encryption.AuditLogDecryptError):
        log_encryption.decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )

    assert backend.calls == []


def test_mral_duplicate_header_field_is_rejected_before_backend_io(tmp_path: Path) -> None:
    backend, log_path, home, _root = _scoped_audit_file(tmp_path)
    lines = log_path.read_bytes().splitlines()
    lines[0] = lines[0][:-1] + b',"key_id":"mordred.audit-log"}'
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises(log_encryption.AuditLogDecryptError, match="duplicate"):
        log_encryption.decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )

    assert backend.calls == []


def test_mral_noncanonical_base64_is_rejected_before_backend_io(tmp_path: Path) -> None:
    backend, log_path, home, _root = _scoped_audit_file(tmp_path)
    lines = log_path.read_bytes().splitlines()
    header = json.loads(lines[0])
    canonical = header["wdek"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    significant_length = len(canonical.rstrip("="))
    final_index = significant_length - 1
    value = alphabet.index(canonical[final_index])
    # A 127-byte MRKW blob leaves four unused low bits in the last base64
    # sextet. Flip one unused bit: permissive decoders accept the spelling and
    # return identical bytes, while the exact header contract must reject it.
    assert len(base64.b64decode(canonical, validate=True)) % 3 == 1
    assert value % 16 == 0
    noncanonical = canonical[:final_index] + alphabet[value + 1] + canonical[final_index + 1 :]
    assert base64.b64decode(noncanonical, validate=True) == base64.b64decode(canonical, validate=True)
    header["wdek"] = noncanonical
    lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises(log_encryption.AuditLogDecryptError, match="canonical"):
        log_encryption.decrypt_log_file(
            log_path,
            backend=backend,
            audit_sink=lambda _entry: None,
            keyvault_home=home,
        )

    assert backend.calls == []
