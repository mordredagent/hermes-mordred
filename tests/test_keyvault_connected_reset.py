"""Coordinated local reset: real custody, synthetic native hardware only."""

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.wizard import keyvault_cli
from tests._keyvault_fakes import FakeBackend
from tests._keyvault_owned_deletion import install_fake_owned_deletion
from tests._mail_sync_helpers import generic_creds
from tests.test_dbcrypt_authority import native_root as native_root
from tests.test_wizard_keyvault_reset import _build_keyvault


@pytest.fixture(autouse=True)
def owned_deletion(monkeypatch):
    install_fake_owned_deletion(monkeypatch)


def test_reset_preserves_independent_helper_files(tmp_path):
    root = _build_keyvault(tmp_path, ["default"])
    shared = root / "sekey"
    shared.mkdir(mode=0o700)
    memory = shared / "independent-memory.bin"
    memory.write_bytes(b"KEEP MEMORY AND DATABASE KEY")
    unknown = root / "unknown-owner"
    unknown.write_bytes(b"KEEP UNKNOWN")
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 0
    assert memory.read_bytes() == b"KEEP MEMORY AND DATABASE KEY"
    assert unknown.read_bytes() == b"KEEP UNKNOWN"
    assert not (root / "meta.json").exists()


@pytest.mark.parametrize("mail,telegram", [(True, False), (False, True), (True, True)])
def test_reset_removes_credentials_through_authenticated_custody(tmp_path, monkeypatch, mail, telegram):
    from mordred_hermes.extension.telegram import tee
    from mordred_hermes.keyvault import _mail_key
    from tests.test_mail_cross_platform_storage import native_store
    from tests.test_posix_telegram_custody import value

    _build_keyvault(tmp_path, ["default"])
    mail_store, native = native_store(tmp_path)
    telegram_store = tee.TeeSecretStore(
        tmp_path / "mordred/telegram", backend_factory=lambda: native.backend, audit_sink=lambda _e: None
    )
    monkeypatch.setattr(_mail_key, "mail_backend", lambda **kw: native.backend)
    monkeypatch.setattr(tee, "hardware_backend", lambda *a: native.backend)
    if mail:
        mail_store.ensure_key(require_presence=False)
        mail_store.store(generic_creds(), require_presence=False)
    if telegram:
        telegram_store.ensure_key(require_presence=False)
        telegram_store.store(value())
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 0
    assert not (tmp_path / "mordred/mail/credentials.sealed").exists()
    assert not (tmp_path / "mordred/telegram/credentials.sealed").exists()
    assert not native.keys
    assert not _storage.reset_journal_path(tmp_path / "mordred/keyvault").exists()


def test_reset_erases_all_accounts_in_profile_cipher_database(native_root):
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.imports import _schema

    home, _, _, _ = native_root
    root = _build_keyvault(home, ["default"])
    path = home / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(parents=True, mode=0o700)
    authority = Authority.acquire(home)
    try:
        conn = open_protected(path, authority=authority)
        for statement in _schema.STATEMENTS:
            conn.execute(statement)
        conn.executemany(
            "INSERT INTO import_meta VALUES (?, ?)",
            [
                ("schema_version", "2"),
                ("profile_home", str(home)),
                ("store_generation", "keep"),
                ("mail_imap.old.last", "erase"),
                ("telegram.retired_account", "123"),
                ("other.keep", "keep"),
            ],
        )
        for source, account in [("mail", "old"), ("mail", "new"), ("telegram", "123"), ("other", "keep")]:
            conn.execute("INSERT INTO import_accounts VALUES (?, ?, ?)", (source, account, "[]"))
            conn.execute("INSERT INTO import_runs VALUES (?, ?, 0, 1, ?, ?)", (account, source, "committed", "{}"))
            conn.execute(
                "INSERT INTO import_conversations VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, 0, NULL, 1)",
                (account, source, account, account, "private", "title", "[]"),
            )
        for account, token in [
            ("old", "erasemail"),
            ("new", "erasemail"),
            ("123", "erasetelegram"),
            ("keep", "keepother"),
        ]:
            conn.execute(
                "INSERT INTO import_messages (source_uid,conv_uid,message_id,sent_at,imported_at,sender_kind,"
                "sender_id,sender_name,owner_class,owner_evidence,recipients_json,reply_to_uid,media,"
                "provenance_quality,source_revision,record_version,content_digest,run_id) "
                "VALUES (?,?,?,0,0,'user',?,'sender','unknown','unknown','[]',NULL,NULL,'legacy',NULL,1,'digest',?)",
                (account, account, account, account, account),
            )
            conn.execute(
                "INSERT INTO import_parts (part_uid,source_uid,ordinal,part_kind,author_kind,author_name,"
                "author_owner_class,author_evidence,text,provenance_quality) "
                "VALUES (?,?,0,'text','user','sender','unknown','unknown',?,'legacy')",
                (account, account, token),
            )
            conn.execute("INSERT INTO import_mail_refs VALUES (?,?)", (account, "ref-" + account))
        conn.execute("CREATE TABLE activity_kept (body TEXT)")
        conn.execute("INSERT INTO activity_kept VALUES ('KEEP ACTIVITY')")
        conn.commit()
        conn.close()
    finally:
        authority.close()
    source = (home / "mordred/db-key-source.json").read_bytes()
    memory = (home / "mordred/memory-key.wrapped").read_bytes()
    assert keyvault_cli.reset_keyvault(home=home, backend=FakeBackend(), assume_yes=True) == 0
    assert (home / "mordred/db-key-source.json").read_bytes() == source
    assert (home / "mordred/memory-key.wrapped").read_bytes() == memory
    assert not (root / "meta.json").exists()
    authority = Authority.acquire(home)
    try:
        conn = open_protected(path, authority=authority)
        assert conn.execute("SELECT source, account FROM import_accounts").fetchall() == [("other", "keep")]
        assert conn.execute("SELECT source FROM import_runs").fetchall() == [("other",)]
        assert conn.execute("SELECT source_uid FROM import_messages").fetchall() == [("keep",)]
        assert conn.execute("SELECT source_uid FROM import_mail_refs").fetchall() == [("keep",)]
        assert conn.execute("SELECT text FROM import_parts").fetchall() == [("keepother",)]
        for token, count in [("erasemail", 0), ("erasetelegram", 0), ("keepother", 1)]:
            assert conn.execute(
                "SELECT count(*) FROM import_parts_fts WHERE import_parts_fts MATCH ?", (token,)
            ).fetchone() == (count,)
        assert conn.execute("SELECT source FROM import_conversations").fetchall() == [("other",)]
        assert dict(conn.execute("SELECT key, value FROM import_meta")) == {
            "schema_version": "2",
            "profile_home": str(home),
            "store_generation": "keep",
            "other.keep": "keep",
        }
        assert conn.execute("SELECT body FROM activity_kept").fetchall() == [("KEEP ACTIVITY",)]
        conn.close()
    finally:
        authority.close()


def test_pending_reset_blocks_import_writes(native_root):
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.imports.store import ImportStore

    home = native_root[0]
    root = _build_keyvault(home, ["default"])
    path = home / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(parents=True, mode=0o700)
    authority = Authority.acquire(home)
    try:
        store = ImportStore(path, opener=lambda path: open_protected(path, authority=authority))
        store.initialize(home)
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending")
        with pytest.raises(Exception, match="reset"):
            store.set_meta("telegram.retired_account", "99")
        assert store.get_meta("telegram.retired_account") is None
    finally:
        authority.close()


def test_v2_journal_never_authorizes_connected_data_erase(tmp_path):
    from tests.test_wizard_keyvault_reset import _write_current_reset_journal

    root = _build_keyvault(tmp_path, ["default"])
    mail = tmp_path / "mordred/mail"
    mail.mkdir(mode=0o700)
    credentials = mail / "credentials.sealed"
    _storage.atomic_write(credentials, b"keep old sealed credentials")
    _write_current_reset_journal(root)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 1
    assert credentials.read_bytes() == b"keep old sealed credentials"
    assert _storage.reset_journal_path(root).exists()


@pytest.mark.parametrize("stage", ["database", "mail", "telegram", "keys", "files", "complete"])
def test_interrupt_between_stages_can_resume(tmp_path, monkeypatch, stage):
    from mordred_hermes.wizard import _keyvault_reset as reset

    root = _build_keyvault(tmp_path, ["default", "payments"])
    backend = FakeBackend()
    real_save = reset._save
    stopped = False

    def crash_before_save(root, journal):
        nonlocal stopped
        if not stopped and journal.connected["stage"] == stage:
            stopped = True
            raise KeyboardInterrupt("simulated termination")
        real_save(root, journal)

    monkeypatch.setattr(reset, "_save", crash_before_save)
    with pytest.raises(KeyboardInterrupt):
        keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True)
    monkeypatch.setattr(reset, "_save", real_save)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert not (root / "meta.json").exists()
    assert not _storage.reset_journal_path(root).exists()


def test_database_failure_keeps_credentials_and_native_keys(tmp_path, monkeypatch):
    from mordred_hermes.extension.telegram import tee
    from mordred_hermes.imports import _reset as history
    from tests.test_posix_telegram_custody import native_store, value

    root = _build_keyvault(tmp_path, ["default"])
    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(value())
    sealed = store.sealed_path.read_bytes()
    keys = dict(native.keys)
    monkeypatch.setattr(tee, "hardware_backend", lambda *a: native.backend)

    def failure(*args, **kwargs):
        raise OSError("database write failed")

    monkeypatch.setattr(history, "erase_reset_history", failure)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 1
    assert store.sealed_path.read_bytes() == sealed
    assert native.keys == keys
    assert (root / "meta.json").exists()
    assert _storage.reset_journal_path(root).exists()
    with pytest.raises(Exception, match="reset"):
        store.store(value())
    with pytest.raises(Exception, match="reset"):
        _storage.ensure_layout(root)


@pytest.mark.parametrize("component", ["mail", "telegram"])
def test_component_acknowledgement_survives_outer_journal_failure(tmp_path, monkeypatch, component):
    from mordred_hermes.extension.telegram import tee
    from mordred_hermes.keyvault import _mail_key
    from mordred_hermes.wizard import _keyvault_reset as reset
    from tests.test_mail_cross_platform_storage import native_store
    from tests.test_posix_telegram_custody import value

    root = _build_keyvault(tmp_path, ["default"])
    mail_store, native = native_store(tmp_path)
    telegram_store = tee.TeeSecretStore(
        tmp_path / "mordred/telegram", backend_factory=lambda: native.backend, audit_sink=lambda _e: None
    )
    monkeypatch.setattr(_mail_key, "mail_backend", lambda **kw: native.backend)
    monkeypatch.setattr(tee, "hardware_backend", lambda *a: native.backend)
    if component == "mail":
        mail_store.ensure_key(require_presence=False)
        mail_store.store(generic_creds(), require_presence=False)
    else:
        telegram_store.ensure_key(require_presence=False)
        telegram_store.store(value())
    real_save = reset._save
    stopped = False

    def crash_after_retirement(root, journal):
        nonlocal stopped
        if (
            not stopped
            and journal.connected["stage"] == component
            and journal.connected["native"].get(component) == "deleted"
        ):
            stopped = True
            raise KeyboardInterrupt("simulated termination after authenticated deletion")
        real_save(root, journal)

    monkeypatch.setattr(reset, "_save", crash_after_retirement)
    with pytest.raises(KeyboardInterrupt):
        keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True)
    assert _storage.reset_journal_path(root).exists()
    monkeypatch.setattr(reset, "_save", real_save)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 0
    assert not native.keys


def test_cancel_keeps_credentials_without_journaling(tmp_path):
    from tests.test_wizard_keyvault_reset import _ScriptedPrompt

    root = _build_keyvault(tmp_path, ["default"])
    mail = tmp_path / "mordred/mail"
    mail.mkdir(mode=0o700)
    _storage.atomic_write(mail / "credentials.sealed", b"KEEP SEALED")
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), prompt_io=_ScriptedPrompt("no")) == 1
    assert (mail / "credentials.sealed").read_bytes() == b"KEEP SEALED"
    assert not _storage.reset_journal_path(root).exists()


@pytest.mark.parametrize("component", ["mail", "telegram"])
def test_orphan_native_blob_without_source_is_retained(tmp_path, component):
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    root = _build_keyvault(tmp_path, ["default"])
    helper = root / "sekey"
    helper.mkdir(mode=0o700)
    selector = f"mordred-hermes.{component}.credentials.v1"
    blob = helper / (_application_tag(selector).hex() + ".bin")
    _storage.atomic_write(blob, b"ORPHAN NEEDS OWNERSHIP RECONCILIATION")
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 1
    assert blob.read_bytes() == b"ORPHAN NEEDS OWNERSHIP RECONCILIATION"
    assert _storage.reset_journal_path(root).exists()


def test_unknown_empty_layout_directories_survive(tmp_path):
    root = _build_keyvault(tmp_path, ["default"])
    unknown = root / "ciphertexts/unknown-owner"
    unknown.mkdir(mode=0o700)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 0
    assert unknown.is_dir()


def test_native_target_replaced_after_intent_refuses_deletion(tmp_path, monkeypatch):
    from mordred_hermes.imports import _reset as history
    from mordred_hermes.keyvault._native_key_id import scoped_native_key_id
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    root = _build_keyvault(tmp_path, ["default"])
    helper = root / "sekey"
    helper.mkdir(mode=0o700)
    blob = helper / (_application_tag(scoped_native_key_id(root, "default")).hex() + ".bin")
    _storage.atomic_write(blob, b"ORIGINAL NATIVE TARGET")
    backend = FakeBackend()

    def replace_during_database_stage(*args, **kwargs):
        _storage.atomic_write(blob, b"REPLACED NATIVE TARGET")

    monkeypatch.setattr(history, "erase_reset_history", replace_during_database_stage)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert not any(op == "delete" for op, _ in backend.calls)
    assert _storage.reset_journal_path(root).exists()


def test_reset_clears_legacy_staged_credentials(tmp_path):
    root = _build_keyvault(tmp_path, ["default"])
    mail = tmp_path / "mordred/mail"
    mail.mkdir(mode=0o700)
    staged = mail / ".credentials.sealed.interrupted.staged"
    _storage.atomic_write(staged, b"OLD SEALED COPY")
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=FakeBackend(), assume_yes=True) == 0
    assert not staged.exists()
    assert not _storage.reset_journal_path(root).exists()


def test_child_reset_keeps_root_database_and_other_profile(native_root):
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected

    home = native_root[0]
    child = home / "profiles/work"
    root = _build_keyvault(child, ["default"])
    path = home / "other-feature.db"
    authority = Authority.acquire(home)
    try:
        conn = open_protected(path, authority=authority)
        conn.execute("CREATE TABLE keep(value TEXT)")
        conn.execute("INSERT INTO keep VALUES ('KEEP ROOT HISTORY')")
        conn.commit()
        conn.close()
    finally:
        authority.close()
    root_db = path.read_bytes()
    sibling = home / "profiles/other/mordred/mail"
    sibling.mkdir(parents=True, mode=0o700)
    _storage.atomic_write(sibling / "credentials.sealed", b"OTHER PROFILE")
    assert keyvault_cli.reset_keyvault(home=child, backend=FakeBackend(), assume_yes=True) == 0
    assert path.read_bytes() == root_db
    assert (sibling / "credentials.sealed").read_bytes() == b"OTHER PROFILE"
    assert not (root / "meta.json").exists()


def test_reset_authority_cannot_be_forged_retargeted_or_reused(tmp_path):
    from mordred_hermes._core._database_contracts import DatabaseRefused
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.keyvault._reset_authority import (
        ResetAuthorization,
        check_reset_access,
        reset_authorization,
    )
    from mordred_hermes.wizard._keyvault_reset import _prepare

    _build_keyvault(tmp_path, ["default"])
    with acquire_exclusive(tmp_path) as lease:
        _prepare(tmp_path, True, None)
        with pytest.raises(DatabaseRefused):
            check_reset_access(tmp_path, object.__new__(ResetAuthorization))
        with reset_authorization(tmp_path, lease) as authorization:
            check_reset_access(tmp_path, authorization, component="database")
            with pytest.raises(DatabaseRefused):
                check_reset_access(tmp_path, authorization, component="mail")
            with pytest.raises(DatabaseRefused):
                check_reset_access(tmp_path / "profiles/other", authorization)
        with pytest.raises(DatabaseRefused):
            check_reset_access(tmp_path, authorization)


def test_backend_initialization_failure_is_retryable_before_native_deletion(tmp_path, monkeypatch):
    root = _build_keyvault(tmp_path, ["default"])
    backend = FakeBackend()
    real_resolve = keyvault_cli.resolve_backend

    def unavailable(_backend):
        raise RuntimeError("temporarily unavailable")

    monkeypatch.setattr(keyvault_cli, "resolve_backend", unavailable)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert not backend.calls
    monkeypatch.setattr(keyvault_cli, "resolve_backend", real_resolve)
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert not (root / "meta.json").exists()
    assert not _storage.reset_journal_path(root).exists()


def test_v2_resume_recognizes_its_authorized_main_native_blob(tmp_path):
    from mordred_hermes.keyvault._native_key_id import scoped_native_key_id
    from mordred_hermes.keyvault._seckey_errors import _application_tag
    from tests.test_wizard_keyvault_reset import _write_current_reset_journal

    root = _build_keyvault(tmp_path, ["default"])
    helper = root / "sekey"
    helper.mkdir(mode=0o700)
    selector = scoped_native_key_id(root, "default")
    _storage.atomic_write(helper / (_application_tag(selector).hex() + ".bin"), b"AUTHORIZED MAIN KEY")
    _write_current_reset_journal(root)
    backend = FakeBackend()
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert ("delete", selector) in backend.calls
    assert not _storage.reset_journal_path(root).exists()


def test_sql_failure_mid_erase_rolls_back_all_account_rows(native_root):
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.imports import _schema

    home = native_root[0]
    root = _build_keyvault(home, ["default"])
    path = home / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(parents=True, mode=0o700)
    authority = Authority.acquire(home)
    try:
        conn = open_protected(path, authority=authority)
        for statement in _schema.STATEMENTS:
            conn.execute(statement)
        conn.executemany("INSERT INTO import_meta VALUES (?,?)", [("profile_home", str(home)), ("schema_version", "2")])
        conn.executemany(
            "INSERT INTO import_accounts VALUES (?,?,?)", [("mail", "old", "[]"), ("telegram", "123", "[]")]
        )
        conn.execute(
            "CREATE TRIGGER refuse_test_erase BEFORE DELETE ON import_accounts "
            "WHEN OLD.source='telegram' BEGIN SELECT RAISE(ABORT, 'synthetic database failure'); END"
        )
        conn.commit()
        conn.close()
    finally:
        authority.close()
    backend = FakeBackend()
    assert keyvault_cli.reset_keyvault(home=home, backend=backend, assume_yes=True) == 1
    assert not backend.calls
    assert (root / "meta.json").exists()
    assert _storage.reset_journal_path(root).exists()
    authority = Authority.acquire(home)
    try:
        conn = open_protected(path, authority=authority)
        assert conn.execute("SELECT source, account FROM import_accounts ORDER BY source").fetchall() == [
            ("mail", "old"),
            ("telegram", "123"),
        ]
        conn.close()
    finally:
        authority.close()


def test_recover_after_reset_retains_shared_helpers_and_backup(tmp_path, fake_native_creation_receipts):
    from mordred_hermes.keyvault import api
    from tests.test_keyvault_api_backup import _export_backup, _import_backup, _init_device

    backend = FakeBackend()

    def sink(_event):
        pass

    key_id = _init_device(tmp_path, backend, sink)
    api.encrypt(key_id, b"RECOVER THIS SECRET", "reset-test", backend=backend, audit_sink=sink, home=tmp_path)
    blob = _export_backup(key_id, backend, tmp_path, sink)
    backup_path = tmp_path / "retained-backup.mrkv"
    backup_path.write_bytes(blob)
    root = tmp_path / "mordred/keyvault"
    shared = root / "sekey"
    shared.mkdir(mode=0o700)
    retained = shared / "independent-source.bin"
    _storage.atomic_write(retained, b"KEEP SHARED SOURCE")
    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    recovered = _import_backup(blob, backend, tmp_path, sink)
    envelopes = list((root / "ciphertexts").glob("*/*/*.gcm"))
    assert len(envelopes) == 1
    assert (
        api.decrypt(recovered, envelopes[0].stem, "reset-test", backend=backend, audit_sink=sink, home=tmp_path)
        == b"RECOVER THIS SECRET"
    )
    assert retained.read_bytes() == b"KEEP SHARED SOURCE"
    assert backup_path.read_bytes() == blob


def _native_target(root):
    from mordred_hermes.keyvault._native_key_id import scoped_native_key_id
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    helper = root / "sekey"
    helper.mkdir(mode=0o700)
    blob = helper / (_application_tag(scoped_native_key_id(root, "default")).hex() + ".bin")
    _storage.atomic_write(blob, b"ORIGINAL NATIVE TARGET")
    return blob


def _failing_delete_once(monkeypatch, backend, on_failure=None):
    real = backend.delete_enclave_key
    state = {"fail": True}

    def delete(key_id):
        if state["fail"]:
            state["fail"] = False
            if on_failure is not None:
                on_failure(real, key_id)
            raise RuntimeError("temporarily unavailable")
        real(key_id)

    monkeypatch.setattr(backend, "delete_enclave_key", delete)


def test_failed_native_deletion_can_be_retried(tmp_path, monkeypatch):
    root = _build_keyvault(tmp_path, ["default"])
    blob = _native_target(root)
    backend = FakeBackend()
    _failing_delete_once(monkeypatch, backend)

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert _storage.reset_journal_path(root).exists()
    assert blob.exists()

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert not _storage.reset_journal_path(root).exists()
    assert not (root / "meta.json").exists()


def test_native_deletion_that_finished_before_interruption_resumes(tmp_path, monkeypatch):
    root = _build_keyvault(tmp_path, ["default"])
    blob = _native_target(root)
    backend = FakeBackend()

    def delete_then_lose_the_outcome(real, key_id):
        real(key_id)
        blob.unlink()

    _failing_delete_once(monkeypatch, backend, on_failure=delete_then_lose_the_outcome)

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert not blob.exists()

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 0
    assert not _storage.reset_journal_path(root).exists()


def test_native_deletion_retry_refuses_a_replaced_target(tmp_path, monkeypatch):
    root = _build_keyvault(tmp_path, ["default"])
    blob = _native_target(root)
    backend = FakeBackend()
    _failing_delete_once(monkeypatch, backend)

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    _storage.atomic_write(blob, b"REPLACED NATIVE TARGET")
    deletes_before = [call for call in backend.calls if call[0] == "delete"]

    assert keyvault_cli.reset_keyvault(home=tmp_path, backend=backend, assume_yes=True) == 1
    assert [call for call in backend.calls if call[0] == "delete"] == deletes_before
    assert _storage.reset_journal_path(root).exists()
    assert (root / "meta.json").exists()


def _restored_plaintext_store(home, monkeypatch):
    from mordred_hermes.dbcrypt import _migrate
    from mordred_hermes.dbcrypt._authority import Authority
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.imports import _schema

    path = home / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(parents=True, mode=0o700)
    authority = Authority.acquire(home)
    try:
        conn = open_protected(path, authority=authority)
        for statement in _schema.STATEMENTS:
            conn.execute(statement)
        conn.commit()
        conn.close()
    finally:
        authority.close()
    monkeypatch.setattr(_migrate, "holders", lambda paths: [])
    return path


def test_uninstall_reset_retains_the_restored_plaintext_database(native_root, monkeypatch, capsys):
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _migrate, _uninstall

    home, _, _, _ = native_root
    root = _build_keyvault(home, ["default"])
    path = _restored_plaintext_store(home, monkeypatch)
    backend = FakeBackend()

    with acquire_exclusive(home) as lease:
        _migrate.decrypt_all(home, None)
        assert path.read_bytes().startswith(b"SQLite format 3")
        before = path.read_bytes()
        with _uninstall.verified(_uninstall.preflight(home, lease=lease, purge=True), lease=lease) as permit:
            rc = keyvault_cli._reset_with_memory_guard(
                home=home, backend=backend, assume_yes=True, database_lease=lease, uninstall=permit
            )

    assert rc == 0
    assert path.read_bytes() == before
    assert not _storage.reset_journal_path(root).exists()
    assert not (root / "meta.json").exists()
    assert any(call[0] == "delete" for call in backend.calls)
    output = capsys.readouterr().out
    assert "history removed" not in output
    assert "keep their imported history" in output


def test_plaintext_store_still_refuses_reset_without_uninstall_authority(native_root, monkeypatch):
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _migrate

    home, _, _, _ = native_root
    root = _build_keyvault(home, ["default"])
    _restored_plaintext_store(home, monkeypatch)
    backend = FakeBackend()

    with acquire_exclusive(home) as lease:
        _migrate.decrypt_all(home, None)
        rc = keyvault_cli._reset_with_memory_guard(home=home, backend=backend, assume_yes=True, database_lease=lease)

    assert rc == 1
    assert not any(call[0] == "delete" for call in backend.calls)
    assert (root / "meta.json").exists()


def test_expired_uninstall_authority_cannot_skip_history_erasure(native_root, monkeypatch):
    from mordred_hermes._core._database_lifecycle import acquire_exclusive
    from mordred_hermes.dbcrypt import _migrate, _uninstall

    home, _, _, _ = native_root
    root = _build_keyvault(home, ["default"])
    _restored_plaintext_store(home, monkeypatch)
    backend = FakeBackend()

    with acquire_exclusive(home) as lease:
        _migrate.decrypt_all(home, None)
        with _uninstall.verified(_uninstall.preflight(home, lease=lease, purge=True), lease=lease) as permit:
            expired = permit
        rc = keyvault_cli._reset_with_memory_guard(
            home=home, backend=backend, assume_yes=True, database_lease=lease, uninstall=expired
        )

    assert rc == 1
    assert not any(call[0] == "delete" for call in backend.calls)
    assert (root / "meta.json").exists()
