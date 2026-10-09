"""Windows Telegram credentials sealed under the independent custody ``telegram`` role (C10b).

Real checked transactions, real MRKW wrap/unwrap and real MTC1 AES-GCM; only the
native P-256 boundary, the token SID and platform admission are injected (the
same seams as the C5a/C5e suites). Nothing here contacts Telegram.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import struct

import pytest

from mordred_hermes import _config_io
from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.extension.telegram import secrets, store, tee
from mordred_hermes.keyvault import wrap
from tests import test_windows_custody
from tests.test_windows_custody_profile import SID

custody_fixture = test_windows_custody.fs

SESSION = "1BVtsOK8Bu-TELETHON-SESSION-SECRET"
#: POSIX mode bits, chmod-broadened state, symlinks and copied trees stand in
#: for Windows ACL/reparse/identity cases, which the native module covers.
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX stand-in for a native Windows case")
VENICE = "VENICE-API-KEY-SECRET"


def _value(**overrides):
    base = {
        "api_id": 12345,
        "api_hash": "ab" * 16,
        "store_key": b"\x07" * 32,
        "session": SESSION,
        "venice_api_key": VENICE,
    }
    base.update(overrides)
    return secrets.TelegramSecrets(**base)


@pytest.fixture(name="tg")
def telegram_fs(custody_fixture, monkeypatch):
    from mordred_hermes.extension.telegram import _windows_archive

    # Same POSIX stand-in for the Windows-only optional opener that C5a uses.
    monkeypatch.setattr(_windows_archive, "open_optional_private_directory", _config_io.open_optional_private_directory)
    monkeypatch.setattr(store, "_platform", lambda: "win32")
    c, _storage, home, backend = custody_fixture
    return c, home, backend


def windows_store(home, backend, audit=None):
    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore

    return WindowsCustodySecretStore(home, backend=backend, audit_sink=(audit.append if audit is not None else None))


def enroll(c, home, backend, *roles):
    leases = {}
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        for role in roles:
            if role == "memory":
                session.enroll_memory()
                leases[role] = session.lease("memory")
            else:
                leases[role] = session.enroll_role(role)
    return leases


def ops(backend, name):
    return [op for op, _ in backend.calls].count(name)


def sealed_path(home):
    return home / "mordred" / "telegram" / "credentials.sealed"


def code(excinfo):
    return excinfo.value.code


# -- roundtrip through the telegram role ----------------------------------------------


def test_roundtrip_seals_mtc1_under_the_telegram_role_lease(tg):
    c, home, backend = tg
    lease = enroll(c, home, backend, "telegram")["telegram"]
    vault = windows_store(home, backend, audit=[])
    assert vault.load() is None
    vault.store(_value())
    raw = sealed_path(home).read_bytes()
    assert raw.startswith(b"MTC1")
    (blob_len,) = struct.unpack(">H", raw[4:6])
    assert blob_len == wrap.HEADER_LEN
    blob = raw[6 : 6 + blob_len]
    # The MRKW header names the existing logical Telegram key id; the native
    # selector is the profile-scoped generation, never the global tag.
    assert blob[:4] == b"MRKW"
    assert blob[6:22] == hashlib.sha256(tee.KEY_ID.encode("utf-8")).digest()[:16]
    for secret in (SESSION.encode(), VENICE.encode(), b"abab", b"\x07" * 32):
        assert secret not in raw
    assert vault.load() == _value()
    natives = {key_id for op, key_id in backend.calls if op in ("ecdh", "get_pub")}
    assert natives == {lease.native_key_id}
    assert ops(backend, "generate") == 1  # only the explicit enrollment
    if os.name != "nt":
        assert stat_mode(sealed_path(home)) == 0o600
        assert stat_mode(home / "mordred" / "telegram") == 0o700


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


def test_update_snapshot_flags_and_scope_keep_the_existing_contract(tg):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    audit = []
    vault = windows_store(home, backend, audit=audit)
    vault.update(lambda old: _value() if old is None else old)
    vault.save_sync_scope({"include_channels": False, "since_days": 30})
    assert vault.sync_scope()["include_channels"] is False
    ecdh = ops(backend, "ecdh")
    flags = vault.flags()
    assert ops(backend, "ecdh") == ecdh  # status never unseals
    assert flags["logged_in"] is True and flags["llm_backend"] == "venice"
    assert flags["sync_scope"]["since_days"] == 30
    assert SESSION not in json.dumps(flags)

    snapshot = vault.load_snapshot()
    assert snapshot[0] == _value()
    assert snapshot[1] == hashlib.sha256(sealed_path(home).read_bytes()).digest()
    ecdh = ops(backend, "ecdh")
    vault.update_from_snapshot(snapshot, lambda old: secrets.with_session(old, None))
    assert ops(backend, "ecdh") == ecdh  # unchanged file: no second unwrap
    assert vault.load().session is None
    assert vault.flags()["logged_in"] is False
    # The sync scope survives credential rewrites (same as the Enclave store).
    assert vault.sync_scope()["include_channels"] is False

    # A changed file since the snapshot falls back to one fresh unwrap.
    stale = vault.load_snapshot()
    vault.update(lambda old: secrets.with_session(old, "OTHER"))
    ecdh = ops(backend, "ecdh")
    vault.update_from_snapshot(stale, lambda old: old)
    assert ops(backend, "ecdh") == ecdh + 1
    assert vault.load().session == "OTHER"

    vault.update(lambda _old: None)
    assert not sealed_path(home).exists()
    assert not (home / "mordred" / "telegram" / "credentials.meta.json").exists()
    assert vault.load() is None and vault.flags() is None
    assert audit and all(entry["event"] == "keyvault.unwrap_dek" for entry in audit)
    assert all(SESSION not in json.dumps(entry) for entry in audit)
    assert ops(backend, "generate") == 1


def test_audit_entries_are_emitted_after_the_custody_scope(tg):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value())
    seen = []

    def sink(entry):
        # A synchronous sink must never run inside the custody/canonical scope.
        seen.append(getattr(_config_io._local, "state", None))

    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore

    WindowsCustodySecretStore(home, backend=backend, audit_sink=sink).load()
    assert seen == [None]


# -- load-only custody: no key creation ----------------------------------------------


def test_absent_role_refuses_without_key_creation(tg):
    _c, home, backend = tg
    with open_private_directory(home / "mordred", create=True):
        pass
    vault = windows_store(home, backend)
    assert vault.load() is None  # nothing sealed: nothing to unwrap
    for call in (
        lambda: vault.store(_value()),
        lambda: vault.update(lambda _old: _value()),
        lambda: vault.ensure_key(require_presence=False),
    ):
        with pytest.raises(secrets.TelegramSecretsError) as excinfo:
            call()
        assert code(excinfo) == "telegram_not_enrolled"
    assert backend.calls == []
    assert not (home / "mordred" / "telegram").exists()
    assert not (home / "mordred" / "windows-telegram.pending.json").exists()


def test_sealed_credentials_without_a_role_refuse_and_never_generate(tg):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value())
    with c.windows_custody_session(home, backend=backend) as session:
        session.reset_role("telegram", erase_authorized=True)
    vault = windows_store(home, backend)
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        vault.load()
    assert code(excinfo) == "telegram_not_enrolled"
    assert ops(backend, "generate") == 1


def test_missing_native_key_refuses_without_regeneration(tg):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    vault = windows_store(home, backend)
    vault.store(_value())
    before = sealed_path(home).read_bytes()
    backend._keys.clear()
    for call in (vault.load, lambda: vault.store(_value()), lambda: vault.ensure_key(require_presence=False)):
        with pytest.raises(secrets.TelegramSecretsError) as excinfo:
            call()
        assert code(excinfo) == "tee_unavailable"
    assert ops(backend, "generate") == 1
    assert sealed_path(home).read_bytes() == before


def test_missing_helper_is_tee_unavailable_before_any_file_change(tg, monkeypatch):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")

    def no_helper():
        raise c.CustodyError("Windows TPM helper unavailable; install the package-bound helper")

    monkeypatch.setattr(c, "windows_backend", no_helper)
    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore

    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        WindowsCustodySecretStore(home).store(_value())
    assert code(excinfo) == "tee_unavailable"
    assert not sealed_path(home).exists()


def test_unresolved_role_journal_refuses_as_uncertain(tg, monkeypatch):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value())
    lease = enroll_retained(c, home, backend)

    def lost(key_id):
        raise RuntimeError("native deletion outcome lost")

    monkeypatch.setattr(backend, "delete_enclave_key", lost)
    with pytest.raises(RuntimeError), c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(lease, erase_authorized=True)
    assert (home / "mordred" / "windows-telegram.pending.json").exists()
    vault = windows_store(home, backend)
    for call in (vault.load, lambda: vault.store(_value()), lambda: vault.ensure_key(require_presence=False)):
        with pytest.raises(secrets.TelegramSecretsError) as excinfo:
            call()
        assert code(excinfo) == "custody_uncertain"
    assert ops(backend, "generate") == 2


def enroll_retained(c, home, backend):
    with c.windows_custody_session(home, backend=backend) as session:
        old = session.lease("telegram")
        session.enroll_role("telegram", retain_current=True)
    return old


# -- presence ------------------------------------------------------------------------------


def test_per_use_presence_refuses_before_any_native_operation(tg):
    c, home, backend = tg
    vault = windows_store(home, backend)
    for call in (vault.ensure_key, lambda: vault.ensure_key(require_presence=True)):
        with pytest.raises(secrets.TelegramSecretsError) as excinfo:
            call()
        assert code(excinfo) == "presence_unsupported"
        from mordred_hermes.keyvault._windows_capability import KeyvaultUnsupportedOnWindows

        cause = excinfo.value.__cause__
        assert isinstance(cause, KeyvaultUnsupportedOnWindows) and cause.capability == "presence"
    assert backend.calls == []
    enroll(c, home, backend, "telegram")
    calls = list(backend.calls)
    with pytest.raises(secrets.TelegramSecretsError, match="presence_unsupported"):
        vault.ensure_key()
    assert backend.calls == calls  # never silently unattended, never generated
    vault.ensure_key(require_presence=False)
    assert ops(backend, "generate") == 1


def test_windows_store_has_no_native_delete_outside_the_forget_ceremony():
    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore

    # The wizard calls ``delete_key`` only when present; Windows role deletion
    # is ``wipe_archive(forget=True)`` -> C5e ``reset_role`` with erasure.
    assert not hasattr(WindowsCustodySecretStore, "delete_key")


# -- profile, role and copy binding ----------------------------------------------------------


@posix_only
def test_copied_home_refuses_as_broken_without_generation(tg, tmp_path):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value())
    copy = tmp_path / "copied"
    shutil.copytree(home, copy, symlinks=True)
    vault = windows_store(copy, backend)
    before = sealed_path(copy).read_bytes()
    for call in (vault.load, lambda: vault.store(_value()), lambda: vault.ensure_key(require_presence=False)):
        with pytest.raises(secrets.TelegramSecretsError) as excinfo:
            call()
        assert code(excinfo) == "custody_broken"
    assert sealed_path(copy).read_bytes() == before
    assert ops(backend, "generate") == 1


def test_other_token_sid_refuses_as_broken(tg, monkeypatch):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value())
    other = bytearray(SID)
    other[-1] ^= 1
    monkeypatch.setattr(c, "current_principal_id", lambda: bytes(other))
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        windows_store(home, backend).load()
    assert code(excinfo) == "custody_broken"


def test_other_profile_and_other_role_wraps_never_unseal(tg, tmp_path):
    c, home, backend = tg
    leases = enroll(c, home, backend, "telegram", "audit")
    vault = windows_store(home, backend)
    vault.store(_value())
    good = sealed_path(home).read_bytes()

    # Another physical profile with its own telegram role cannot open it.
    other = tmp_path / "other"
    with open_private_directory(other, create=True):
        pass
    enroll(c, other, backend, "telegram")
    windows_store(other, backend).store(_value(session="OTHER"))
    sealed_path(other).write_bytes(good)
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        windows_store(other, backend).load()
    assert code(excinfo) == "secrets_corrupt"

    # Same logical id and layout, but wrapped to the audit role's native key.
    dek = b"\x11" * 32
    blob = wrap.wrap_dek(dek, tee.KEY_ID, backend=backend, native_key_id=leases["audit"].native_key_id)
    forged = tee._pack(blob, dek, secrets.encode(_value(session="FORGED")))
    sealed_path(home).write_bytes(forged)
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        vault.load()
    assert code(excinfo) == "secrets_corrupt"
    assert ops(backend, "generate") == 3


def test_non_telegram_lease_is_refused_by_the_role_guard(tg):
    c, home, backend = tg
    from mordred_hermes.extension.telegram import windows_secrets

    leases = enroll(c, home, backend, "telegram", "audit")
    with c.windows_custody_session(home, backend=backend) as session:
        with pytest.raises(c.CustodyError):
            windows_secrets._require_telegram_lease(leases["audit"])
        windows_secrets._require_telegram_lease(session.lease("telegram"))


def test_tampered_or_truncated_seal_is_corrupt(tg):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    vault = windows_store(home, backend)
    vault.store(_value())
    raw = bytearray(sealed_path(home).read_bytes())
    raw[-1] ^= 1
    sealed_path(home).write_bytes(bytes(raw))
    with pytest.raises(secrets.TelegramSecretsError, match="secrets_corrupt"):
        vault.load()
    sealed_path(home).write_bytes(b"MTC1\x00")
    with pytest.raises(secrets.TelegramSecretsError, match="secrets_corrupt"):
        vault.load()


# -- independent roles ---------------------------------------------------------------------


def test_memory_purge_leaves_telegram_credentials_decryptable(tg, monkeypatch):
    c, home, backend = tg
    leases = enroll(c, home, backend, "memory", "audit", "telegram")
    vault = windows_store(home, backend)
    vault.store(_value())
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: None)
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.optout", b"1\n")
    with c.windows_custody_session(home, backend=backend) as session:
        session.reset_role("memory")
        session.validate_lease(leases["audit"])
        session.validate_lease(leases["telegram"])
    assert vault.load() == _value()


def test_telegram_forget_leaves_memory_and_audit_roles(tg):
    c, home, backend = tg
    leases = enroll(c, home, backend, "memory", "audit", "telegram")
    with c.windows_custody_session(home, backend=backend) as session:
        memory_key = session.load_memory_key()
    windows_store(home, backend).store(_value())
    store.wipe_archive(home / "mordred" / "telegram", forget=True, backend=backend)
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.load_memory_key() == memory_key
        session.validate_lease(leases["memory"])
        session.validate_lease(leases["audit"])
        assert session.role_status("telegram") == c.RoleStatus("telegram", None, (), False)
    assert leases["telegram"].native_key_id not in backend._keys
    assert leases["audit"].native_key_id in backend._keys


# -- unsafe filesystem state ---------------------------------------------------------------


@posix_only
def test_unsafe_telegram_directory_refuses_without_repair(tg):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    vault = windows_store(home, backend)
    vault.store(_value())
    directory = home / "mordred" / "telegram"
    os.chmod(directory, 0o755)
    try:
        for call in (vault.load, lambda: vault.store(_value()), vault.flags):
            with pytest.raises(secrets.TelegramSecretsError) as excinfo:
                call()
            assert code(excinfo) == "custody_unsafe"
        assert stat_mode(directory) == 0o755  # never repaired
    finally:
        os.chmod(directory, 0o700)


@posix_only
def test_hardlinked_or_symlinked_seal_refuses_unchanged(tg, tmp_path):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    vault = windows_store(home, backend)
    vault.store(_value())
    path = sealed_path(home)
    before = path.read_bytes()
    alias = tmp_path / "alias"
    os.link(path, alias)
    with pytest.raises(secrets.TelegramSecretsError, match="custody_unsafe"):
        vault.load()
    with pytest.raises(secrets.TelegramSecretsError, match="custody_unsafe"):
        vault.store(_value(session="NEW"))
    assert path.read_bytes() == before
    alias.unlink()
    path.unlink()
    path.symlink_to(alias)
    with pytest.raises(secrets.TelegramSecretsError, match="custody_unsafe"):
        vault.load()


# -- selection seam and POSIX stores ---------------------------------------------------------


def test_factory_selects_the_custody_store_only_on_windows(tg, monkeypatch):
    from mordred_hermes.extension.telegram import hardening, service
    from mordred_hermes.extension.telegram.windows_secrets import WindowsCustodySecretStore

    assert isinstance(tee.default_secret_store(), WindowsCustodySecretStore)
    monkeypatch.setattr(hardening, "harden_process", lambda: None)
    assert isinstance(service.TelegramService()._secrets, WindowsCustodySecretStore)
    monkeypatch.setattr(store, "_platform", lambda: "darwin")
    assert isinstance(tee.default_secret_store(), tee.TeeSecretStore)
    assert isinstance(service.TelegramService()._secrets, tee.TeeSecretStore)


def test_hermes_tool_status_reads_flags_through_the_factory(tg, monkeypatch):
    c, home, backend = tg
    from mordred_hermes.extension.telegram import hermes_tools, windows_secrets

    enroll(c, home, backend, "telegram")
    windows_store(home, backend).store(_value())
    monkeypatch.setattr(windows_secrets.WindowsCustodySecretStore, "_resolved_home", lambda self: home)
    calls = list(backend.calls)
    assert hermes_tools._telegram_logged_in() is True
    assert backend.calls == calls  # status flags never touch the native key


def test_posix_raw_stores_refuse_on_windows_before_any_filesystem_change(tg, tmp_path):
    _c, _home, _backend = tg
    root = tmp_path / "raw-tee"
    raw = tee.TeeSecretStore(root, backend_factory=lambda: pytest.fail("native backend reached"))
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        raw.flags()
    with pytest.raises(store.StoreError, match="store_path_unsafe"):
        raw.store(_value())
    assert not root.exists()
    vault_root = tmp_path / "file-vault"
    vault_root.mkdir()
    (vault_root / "manifest.1.mvmf").write_bytes(b"retained")
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        secrets.VaultSecretStore(vault_root).load()
    assert code(excinfo) == "vault_unavailable"
    from mordred_hermes.keyvault._windows_capability import KeyvaultUnsupportedOnWindows

    assert isinstance(excinfo.value.__cause__, KeyvaultUnsupportedOnWindows)


# -- secret hygiene -----------------------------------------------------------------------------


def test_session_bytes_never_reach_logs_errors_or_metadata(tg, caplog):
    c, home, backend = tg
    enroll(c, home, backend, "telegram")
    vault = windows_store(home, backend)
    caplog.set_level(logging.DEBUG)
    vault.store(_value())
    loaded = vault.load()
    assert SESSION not in repr(loaded)
    raw = sealed_path(home).read_bytes()
    raw = raw[:-1] + bytes([raw[-1] ^ 1])
    sealed_path(home).write_bytes(raw)
    with pytest.raises(secrets.TelegramSecretsError) as excinfo:
        vault.load()
    assert SESSION not in str(excinfo.value) and SESSION not in repr(excinfo.value)
    meta = (home / "mordred" / "telegram" / "credentials.meta.json").read_text("utf-8")
    for text in (caplog.text, meta):
        assert SESSION not in text and VENICE not in text
