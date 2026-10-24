"""Independent mail custody; real guards with synthetic native operations only."""

import json
from dataclasses import replace

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.imports.mail.secrets import KEY_ID, MailSecretsError, MailSecretStore
from mordred_hermes.keyvault import wrap
from tests._activity_protection import native_root as native_root
from tests._activity_protection import protected_runtime as protected_runtime
from tests._mail_sync_helpers import generic_creds
from tests.test_posix_telegram_custody import NativeTelegram
from tests.test_windows_custody import fs as fs


def native_store(home):
    native = NativeTelegram(home)
    store = MailSecretStore(home / "mordred/mail", backend_factory=lambda: native.backend, audit_sink=lambda _e: None)
    return store, native


@pytest.mark.parametrize("entry", ["prepare", "ensure", "store", "setup"])
def test_linux_presence_admission_precedes_writer_discovery_and_probe(tmp_path, monkeypatch, entry):
    """Synthetic platform policy test; no native helper or account is used."""
    from mordred_hermes.imports.mail import imap_sync
    from mordred_hermes.imports.mail.setup_flow import MailSetupError, MailSetupFlows
    from tests._mail_sync_helpers import PASSWORD, secrets_in_traceback

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported presence reached writer/native/credential probe")

    monkeypatch.setattr(imap_sync, "mail_writer_scope", forbidden)
    store = MailSecretStore(
        tmp_path / "mordred/mail", platform=lambda: "linux", backend_factory=forbidden, audit_sink=forbidden
    )
    error = MailSetupError if entry == "setup" else MailSecretsError
    with pytest.raises(error, match=r"^presence_unsupported$") as caught:
        if entry == "prepare":
            store._prepare_setup(require_presence=True)
        elif entry == "ensure":
            store.ensure_key(require_presence=True)
        elif entry == "store":
            store.store(generic_creds(), require_presence=True)
        else:
            flow = MailSetupFlows(store, home=lambda: tmp_path, lock=forbidden, connect=forbidden)
            flow.start(address="owner@example.com", imap_host="imap.example.com", app_password=PASSWORD, presence=True)
    assert caught.value.code == "presence_unsupported"
    if entry == "setup":
        assert secrets_in_traceback(caught.value, PASSWORD) == []
        assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert list(tmp_path.iterdir()) == []


def test_linux_explicit_no_presence_setup_uses_machine_bound_policy(tmp_path):
    """The synthetic helper ignores unattended, just like the TPM capability; NOT native acceptance."""
    from mordred_hermes.imports.mail.setup_flow import MailSetupFlows
    from tests._mail_sync_helpers import PASSWORD, gmail_server

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    server = gmail_server()
    flow = MailSetupFlows(store, home=lambda: tmp_path, connect=lambda _host, _port: server.session())
    done = flow.start(address="owner@example.com", imap_host="imap.example.com", app_password=PASSWORD, presence=False)
    assert done.presence is False
    assert store.flags()["touch_id"] is False
    assert json.loads(store.key_record_path.read_bytes())["touch_id"] is False
    assert store.load().app_password == PASSWORD
    assert native.calls.count("generate") == 1


@pytest.mark.parametrize("entry", ["prepare", "ensure", "store", "setup"])
def test_linux_presence_refusal_preserves_existing_credential_state(tmp_path, entry):
    from mordred_hermes.imports.mail.secrets import new_setup_generation
    from mordred_hermes.imports.mail.setup_flow import MailSetupError, MailSetupFlows
    from tests._mail_sync_helpers import PASSWORD

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    new_setup_generation(tmp_path)
    paths = [store.sealed_path, store.meta_path, store.key_record_path, tmp_path / "mordred/mail/generation"]
    before = [p.read_bytes() for p in paths]
    calls, keys = list(native.calls), dict(native.keys)
    error = MailSetupError if entry == "setup" else MailSecretsError
    with pytest.raises(error, match=r"^presence_unsupported$"):
        if entry == "prepare":
            store._prepare_setup(require_presence=True)
        elif entry == "ensure":
            store.ensure_key(require_presence=True, replace=True)
        elif entry == "store":
            store.store(replace(generic_creds(), app_password="replacement"), require_presence=True)
        else:
            MailSetupFlows(store, home=lambda: tmp_path).start(
                address="owner@example.com", imap_host="imap.example.com", app_password=PASSWORD, presence=True
            )
    assert [p.read_bytes() for p in paths] == before
    assert native.calls == calls and native.keys == keys


@pytest.mark.parametrize("policy", [True, None, "missing", "unverified"])
def test_linux_legacy_flags_are_unknown_and_block_read_reuse_without_mutation(tmp_path, policy):
    from mordred_hermes.imports.mail.secrets import new_setup_generation

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    new_setup_generation(tmp_path)
    flags = json.loads(store.meta_path.read_bytes())
    if policy == "missing":
        flags.pop("touch_id")
    else:
        flags["touch_id"] = policy
    store.meta_path.write_text(json.dumps(flags))
    paths = [store.sealed_path, store.meta_path, store.key_record_path, tmp_path / "mordred/mail/generation"]
    before, calls, keys = [p.read_bytes() for p in paths], list(native.calls), dict(native.keys)
    assert store.flags()["touch_id"] is None
    assert native.calls == calls  # status is passive
    for operation in (
        store.load,
        lambda: store.ensure_key(require_presence=False),
        lambda: store.store(replace(generic_creds(), app_password="replacement"), require_presence=False),
    ):
        with pytest.raises(MailSecretsError, match=r"^presence_unsupported$"):
            operation()
    assert native.ecdh_calls == 0 and "delete" not in native.calls
    assert [p.read_bytes() for p in paths] == before and native.keys == keys


@pytest.mark.parametrize("policy", [True, None, "missing", "wrong_public", "absent", "invalid_json"])
def test_linux_unknown_key_policy_cannot_become_explicit_false(tmp_path, policy):
    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    record = json.loads(store.key_record_path.read_bytes())
    if policy == "missing":
        record.pop("touch_id")
    elif policy == "wrong_public":
        record["public_sha256"] = "0" * 64
    else:
        record["touch_id"] = policy
    store.key_record_path.write_text(json.dumps(record))
    if policy == "absent":
        store.key_record_path.unlink()
    elif policy == "invalid_json":
        store.key_record_path.write_text("{")
    paths = [p for p in (store.sealed_path, store.meta_path, store.key_record_path) if p.exists()]
    before, keys = [p.read_bytes() for p in paths], dict(native.keys)
    assert store._recorded_policy(wrap.get_wrapping_key_public(KEY_ID, backend=native.backend)) is None
    for operation in (
        store.load,
        lambda: store.ensure_key(require_presence=False),
        lambda: store.ensure_key(require_presence=False, replace=True),
        lambda: store.store(generic_creds(), require_presence=False),
    ):
        with pytest.raises(MailSecretsError, match=r"^presence_unsupported$"):
            operation()
    assert native.ecdh_calls == 0 and "delete" not in native.calls
    assert [p.read_bytes() for p in paths] == before and native.keys == keys


@pytest.mark.parametrize("change", ["flags", "key_policy", "key_rewritten", "after_authentication"])
def test_linux_read_rechecks_policy_after_authentication_without_secret_traceback(tmp_path, monkeypatch, change):
    from tests._mail_sync_helpers import PASSWORD, secrets_in_traceback

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)

    def changed():
        path = store.meta_path if change in {"flags", "after_authentication"} else store.key_record_path
        value = json.loads(path.read_bytes())
        value["touch_id"] = change != "key_rewritten"
        path.write_text(json.dumps(value))

    if change == "after_authentication":
        from mordred_hermes.keyvault import _mail_custody

        original = _mail_custody.authenticate_mail_source

        def changed_after_authentication(**kwargs):
            result = original(**kwargs)
            changed()
            return result

        monkeypatch.setattr(_mail_custody, "authenticate_mail_source", changed_after_authentication)
    else:
        native.on_unwrap = changed
    with pytest.raises(MailSecretsError) as caught:
        store.load()
    assert caught.value.code == ("presence_unsupported" if change == "key_policy" else "tee_unavailable")
    assert secrets_in_traceback(caught.value, PASSWORD) == []
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert native.ecdh_calls == 1 and "delete" not in native.calls


@pytest.mark.parametrize("policy", [True, None, "missing"])
def test_linux_legacy_policy_does_not_authorize_or_strand_native_first_retirement(tmp_path, policy):
    from mordred_hermes.imports.mail.forget import forget

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    flags = json.loads(store.meta_path.read_bytes())
    flags["account"] = "forged"
    if policy == "missing":
        flags.pop("touch_id")
    else:
        flags["touch_id"] = policy
    store.meta_path.write_text(json.dumps(flags))
    record = json.loads(store.key_record_path.read_bytes())
    record["touch_id"] = None
    store.key_record_path.write_text(json.dumps(record))
    events = []

    class Rows:
        def delete_source(self, source, account):
            assert native.calls.count("delete") == 1
            assert not store.sealed_path.exists()
            events.append((source, account))
            return 3

        def meta_items(self, prefix):
            return {}

    done = forget(store, tmp_path, rows=True, open_store=lambda _home: Rows())
    assert done.key_gone and done.deleted_messages == 3
    assert events == [("mail", generic_creds().account)]
    assert native.ecdh_calls == 1
    assert store.ensure_key(require_presence=False) is False
    store.store(generic_creds(), require_presence=False)
    assert store.load() == generic_creds() and store.flags()["touch_id"] is False


def test_linux_legacy_policy_sync_refuses_before_login_with_policy_code(tmp_path):
    from mordred_hermes.imports.mail.imap_sync import FetchOptions, run_fetch
    from tests._mail_sync_helpers import generic_server, make_env, make_store

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    flags = json.loads(store.meta_path.read_bytes())
    flags["touch_id"] = True
    store.meta_path.write_text(json.dumps(flags))
    db = make_store(tmp_path, tmp_path)
    env = make_env(tmp_path, db, generic_server(), store, platform="linux")
    env.connect = lambda *args: pytest.fail("legacy policy reached IMAP connection")
    result = run_fetch(FetchOptions(), env)
    assert result.error == "presence_unsupported"
    assert native.ecdh_calls == 0 and store.sealed_path.exists()


def test_linux_unknown_unsealed_key_policy_setup_refuses_without_replacement_or_probe(tmp_path):
    from mordred_hermes.imports.mail.setup_flow import MailSetupError, MailSetupFlows
    from tests._mail_sync_helpers import PASSWORD, secrets_in_traceback

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    record = json.loads(store.key_record_path.read_bytes())
    record["touch_id"] = None
    store.key_record_path.write_text(json.dumps(record))
    before, keys = store.key_record_path.read_bytes(), dict(native.keys)
    flow = MailSetupFlows(
        store, home=lambda: tmp_path, connect=lambda *args: pytest.fail("unknown key policy reached probe")
    )
    with pytest.raises(MailSetupError, match=r"^presence_unsupported$") as caught:
        flow.start(address="owner@example.com", imap_host="imap.example.com", app_password=PASSWORD, presence=False)
    assert secrets_in_traceback(caught.value, PASSWORD) == []
    assert store.key_record_path.read_bytes() == before and native.keys == keys
    assert native.calls.count("generate") == 1 and "delete" not in native.calls
    assert not store.sealed_path.exists()


def test_linux_orphan_policy_record_is_not_repaired_by_ensure(tmp_path):
    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    before = store.key_record_path.read_bytes()
    native.keys.clear()  # synthetic missing TPM object; preserve the recorded evidence
    with pytest.raises(MailSecretsError, match=r"^presence_unsupported$"):
        store.ensure_key(require_presence=False)
    assert native.keys == {} and native.calls.count("generate") == 1
    assert store.key_record_path.read_bytes() == before


def test_linux_legacy_policy_uncertain_retirement_retains_source_and_rows(tmp_path):
    from mordred_hermes.imports.mail.forget import MailForgetError, forget

    store, native = native_store(tmp_path)
    store._platform = lambda: "linux"
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    flags = json.loads(store.meta_path.read_bytes())
    flags["touch_id"] = True
    store.meta_path.write_text(json.dumps(flags))
    before = store.sealed_path.read_bytes()
    native.fail_delete = True

    class Rows:
        def delete_source(self, source, account):
            pytest.fail("rows deleted before native acknowledgement")

        def meta_items(self, prefix):
            return {}

    with pytest.raises(MailForgetError, match=r"^tee_unavailable$"):
        forget(store, tmp_path, rows=True, open_store=lambda _home: Rows())
    assert store.sealed_path.read_bytes() == before and native.keys
    assert json.loads((tmp_path / "mordred/mail/mail-forget.json").read_bytes())["phase"] == "intent"


def test_native_mail_credential_roundtrip_distinct_roles(tmp_path):
    store, native = native_store(tmp_path)
    other = "mordred-hermes.telegram.credentials.v1"
    wrap.generate_wrapping_key(other, backend=native.backend)
    public = wrap.get_wrapping_key_public(other, backend=native.backend)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    (tmp_path / "state.db").write_bytes(b"unrelated encrypted root database")
    loaded = store.load()
    assert loaded.app_password == generic_creds().app_password
    assert store.forget() is True
    assert not store.residue()
    assert wrap.get_wrapping_key_public(other, backend=native.backend) == public
    assert (tmp_path / "state.db").read_bytes() == b"unrelated encrypted root database"


def test_native_failure_preserves_authenticated_source(tmp_path):
    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    sealed = store.sealed_path.read_bytes()
    native.fail_delete = True
    from mordred_hermes.imports.mail.secrets import MailSecretsError
    from mordred_hermes.keyvault._exceptions import WrapError

    with pytest.raises((WrapError, MailSecretsError)):
        store.forget()
    assert store.sealed_path.read_bytes() == sealed
    assert json.loads((tmp_path / "mordred/mail/mail-forget.json").read_bytes())["phase"] == "intent"


@pytest.mark.parametrize("change", ["source", "generation", "root", "backend"])
def test_forget_stale_setup_preserves_replacement(tmp_path, change):
    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    assert hasattr(store, "load_snapshot"), "mail needs an issued authenticated snapshot"
    snapshot = store.load_snapshot()
    if change == "source":
        store.store(replace(generic_creds(), app_password="replacement"), require_presence=False)
    elif change == "generation":
        from mordred_hermes.imports.mail.secrets import new_setup_generation

        new_setup_generation(tmp_path)
    elif change == "root":
        store._root = tmp_path / "other/mordred/mail"
    else:
        from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend

        store._native_backend = _SecKeyBackend(ops=native.ops, sw_ops=None, legacy_ops=None)
    with pytest.raises(MailSecretsError, match=r"^tee_unavailable$"):
        store.forget_from_snapshot(snapshot)
    assert "delete" not in native.calls
    assert (tmp_path / "mordred/mail/credentials.sealed").exists()


def test_corrupt_authenticated_source_never_retires_key(tmp_path):
    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    sealed = store.sealed_path.read_bytes()
    store.sealed_path.write_bytes(sealed[:-1] + bytes([sealed[-1] ^ 1]))
    from mordred_hermes.imports.mail.secrets import MailSecretsError
    from mordred_hermes.keyvault._exceptions import WrapError

    with pytest.raises((WrapError, MailSecretsError)):
        store.forget()
    assert "delete" not in native.calls
    assert store.sealed_path.exists()


def test_bare_mail_native_delete_is_refused(tmp_path):
    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    with pytest.raises(DatabaseRefused):
        wrap.delete_wrapping_key(KEY_ID, backend=native.backend)


def test_windows_mail_uses_genuine_independent_role(fs):
    from mordred_hermes.keyvault import _mail_custody

    assert hasattr(_mail_custody, "WindowsMailStore"), "genuine mail session mapping is missing"
    c, _, home, backend = fs
    from mordred_hermes.keyvault._database_mutation import database_key_mutation

    with (
        database_key_mutation(root=home, generation=None) as lease,
        c.windows_custody_session(home, create=True, backend=backend) as session,
    ):
        root_key = session.enroll_memory(database_lease=lease)
        telegram = session.enroll_role("telegram")
    (home / "state.db").write_bytes(b"existing encrypted database")
    store = MailSecretStore(
        home / "mordred/mail", backend_factory=lambda: backend, platform=lambda: "win32", audit_sink=lambda _e: None
    )
    assert store.ensure_key(require_presence=False) is False
    store.store(generic_creds(), require_presence=False)
    assert store.load().app_password == generic_creds().app_password
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.lease("mail").native_key_id != telegram.native_key_id
    assert store.forget() is True
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.load_memory_key() == root_key
        session.validate_lease(telegram)
        assert session.role_status("mail").current is None


@pytest.mark.parametrize("change", ["source", "generation", "role"])
def test_windows_mail_stale_authentication_retains_source(fs, change):
    from mordred_hermes.keyvault import _mail_custody

    assert hasattr(_mail_custody, "WindowsMailStore"), "genuine mail session mapping is missing"
    c, _, home, backend = fs
    store = MailSecretStore(
        home / "mordred/mail", backend_factory=lambda: backend, platform=lambda: "win32", audit_sink=lambda _e: None
    )
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    snapshot = store.load_snapshot()
    if change == "source":
        store.store(replace(generic_creds(), app_password="replacement"), require_presence=False)
    elif change == "generation":
        from mordred_hermes.imports.mail.secrets import new_setup_generation

        new_setup_generation(home)
    else:
        with c.windows_custody_session(home, backend=backend) as session:
            session.enroll_role("mail", retain_current=True)
    calls = list(backend.calls)
    with pytest.raises(MailSecretsError, match=r"^tee_unavailable$"):
        store.forget_from_snapshot(snapshot)
    assert [call for call in backend.calls[len(calls) :] if call[0] == "delete"] == []
    assert store.sealed_path.exists()


def test_passive_native_mail_flags_reject_hardlinked_metadata(tmp_path):
    import os

    from mordred_hermes.imports.mail.secrets import MailSecretsError

    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    os.link(store.meta_path, tmp_path / "metadata-alias")
    calls = list(native.calls)
    with pytest.raises((MailSecretsError, OSError, DatabaseRefused)):
        store.flags()
    assert native.calls == calls


def test_setup_generation_never_reads_a_hardlink(tmp_path):
    import os

    from mordred_hermes.imports.mail.secrets import new_setup_generation, setup_generation

    new_setup_generation(tmp_path)
    os.link(tmp_path / "mordred/mail/generation", tmp_path / "generation-alias")
    from mordred_hermes.imports.mail.secrets import MailSecretsError

    with pytest.raises((OSError, DatabaseRefused, MailSecretsError)):
        setup_generation(tmp_path)


def test_native_policy_record_is_checked_not_followed(tmp_path):
    import os

    store, _native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    os.link(store.key_record_path, tmp_path / "policy-alias")
    with pytest.raises(MailSecretsError, match=r"^store_path_unsafe$"):
        store.ensure_key(require_presence=False)


def test_native_setup_cannot_publish_while_another_writer_is_held(tmp_path):
    import threading

    from mordred_hermes.imports.mail.imap_sync import fetch_lock

    store, _native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    before = store.sealed_path.read_bytes()
    failures = []

    def replace_source():
        try:
            store.store(replace(generic_creds(), app_password="concurrent"), require_presence=False)
        except Exception as exc:
            failures.append(exc)

    with fetch_lock(tmp_path):
        thread = threading.Thread(target=replace_source)
        thread.start()
        thread.join(3)
        assert not thread.is_alive()
        assert failures, "native publication bypassed the shared mail writer lock"
        assert store.sealed_path.read_bytes() == before


def test_native_forget_advances_setup_generation_before_retirement(tmp_path):
    from mordred_hermes.imports.mail.secrets import setup_generation

    store, _native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    before = setup_generation(tmp_path)
    store.forget()
    assert setup_generation(tmp_path) != before


def test_foreground_forget_authenticates_label_and_retires_before_rows(tmp_path):
    from mordred_hermes.imports.mail.forget import forget

    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    # Flags cannot redirect deletion to another account.
    flags = json.loads(store.meta_path.read_bytes())
    flags["account"] = "other"
    store.meta_path.write_text(json.dumps(flags))
    events = []

    class Rows:
        def delete_source(self, source, account):
            assert native.calls.count("delete") == 1
            assert not store.sealed_path.exists()
            events.append((source, account))
            return 3

        def meta_items(self, prefix):
            return {}

    done = forget(store, tmp_path, rows=True, open_store=lambda _home: Rows())
    assert events == [("mail", generic_creds().account)]
    assert done.deleted_messages == 3


def test_mail_mbox_imap_dedup_search_restart(protected_runtime, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt._key import KeyProvider
    from mordred_hermes.imports.mail import MboxSource, plan_import
    from mordred_hermes.imports.mail.imap_sync import FetchOptions, run_fetch
    from mordred_hermes.imports.store import open_import_store
    from tests._fake_imap import FakeImapServer, FakeMailbox, FakeMessage, mail
    from tests._mail_sync_helpers import FakeSecrets, make_env

    home, provider, _backend = protected_runtime
    raw = mail(1, body="日本語の会話を保存します", subject="日本語の件名")
    mbox = home / "export.mbox"
    mbox.write_bytes(b"From a Mon Oct  5 10:00:00 2026\n" + raw + b"\n")
    plan = plan_import([MboxSource(mbox)], account="mail", own_addresses=["owner@example.com"])
    store = open_import_store(home)
    run = store.run_begin("mail")
    store.write_batch(
        run,
        [thread.messages for thread in plan.threads],
        conversations=[thread.conversation for thread in plan.threads],
        meta_updates={},
        refs=plan.refs,
    )
    imported_japanese_ids = [hit.source_uid for hit in store.search("日本語")]
    assert imported_japanese_ids == ["mail:mail:msg1@example.net"]
    server = FakeImapServer({"INBOX": FakeMailbox(7, messages={1: FakeMessage(raw)})})
    env = make_env(home, store, server, FakeSecrets(generic_creds()), platform="linux")
    result = run_fetch(FetchOptions(roles=("inbox",)), env)
    assert result.error is None and result.duplicates == 1 and result.inserted == 0
    with store.connection() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    provider.close()
    restarted = KeyProvider(home=home)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", restarted)
    try:
        restarted_store = open_import_store(home)
        restarted_search_ids = [hit.source_uid for hit in restarted_store.search("日本語")]
        assert restarted_search_ids == imported_japanese_ids
    finally:
        restarted.close()


def test_fabricated_writer_record_cannot_authorize_borrow(tmp_path, monkeypatch):
    import os
    import threading

    from mordred_hermes.imports.mail import imap_sync

    root = tmp_path / "mordred/mail"
    root.mkdir(parents=True, mode=0o700)
    path = root / ".lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        info = os.fstat(fd)
        forged = imap_sync._HeldMailWriter(
            tmp_path, (os.getpid(), threading.get_ident()), imap_sync._LockRelease(fd), fd, (info.st_dev, info.st_ino)
        )
        monkeypatch.setattr(imap_sync._mail_writers, "held", forged, raising=False)
        with pytest.raises(imap_sync.FetchStop):
            imap_sync.assert_mail_writer_held(tmp_path)
    finally:
        os.close(fd)


@pytest.mark.parametrize("change", ["closed", "replaced"])
def test_closed_or_replaced_writer_cannot_authorize_borrow(tmp_path, monkeypatch, change):
    from mordred_hermes.imports.mail import imap_sync

    with imap_sync.fetch_lock(tmp_path):
        held = imap_sync._mail_writers.held
        if change == "replaced":
            path = tmp_path / "mordred/mail/.lock"
            path.rename(path.with_name(".old-lock"))
            path.write_bytes(b"")
            path.chmod(0o600)
            with pytest.raises(imap_sync.FetchStop):
                imap_sync.assert_mail_writer_held(tmp_path)
    if change == "closed":
        monkeypatch.setattr(imap_sync._mail_writers, "held", held)
        with pytest.raises(imap_sync.FetchStop):
            imap_sync.assert_mail_writer_held(tmp_path)


def test_first_native_generation_keeps_checked_store_binding(tmp_path):
    store, native = native_store(tmp_path)

    def create_like_native_helper(payload):
        if payload["cmd"] == "generate":
            from pathlib import Path

            Path(native.ops._env_override[1]).mkdir(mode=0o700, parents=True, exist_ok=True)
        return native.invoke(payload)

    native.ops._invoke = create_like_native_helper
    assert store.ensure_key(require_presence=False) is False
    store.store(generic_creds(), require_presence=False)
    assert store.load() == generic_creds()


def test_deleted_posix_journal_resumes_without_unwrap_or_native_delete(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _mail_custody

    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    original = _mail_custody.publish

    def interrupted(tx, name, data):
        original(tx, name, data)
        if name == _mail_custody.JOURNAL and json.loads(data)["phase"] == "deleted":
            raise OSError("injected after acknowledged publication")

    monkeypatch.setattr(_mail_custody, "publish", interrupted)
    with pytest.raises(MailSecretsError, match=r"^store_path_unsafe$"):
        store.forget()
    monkeypatch.setattr(_mail_custody, "publish", original)
    calls = list(native.calls)
    assert store.forget() is True
    assert native.calls == calls
    assert not store.sealed_path.exists()


def test_windows_forget_is_idempotent_after_acknowledged_retirement(fs):
    _c, _, home, backend = fs
    store = MailSecretStore(
        home / "mordred/mail", backend_factory=lambda: backend, platform=lambda: "win32", audit_sink=lambda _e: None
    )
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    assert store.forget() is True
    assert store.forget() is True


def test_windows_native_failure_retains_source_and_journals(fs, monkeypatch):
    _c, _, home, backend = fs
    store = MailSecretStore(
        home / "mordred/mail", backend_factory=lambda: backend, platform=lambda: "win32", audit_sink=lambda _e: None
    )
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    sealed = store.sealed_path.read_bytes()

    def lost(*args, **kwargs):
        raise RuntimeError("injected transport failure")

    monkeypatch.setattr(backend, "delete_enclave_key", lost)
    with pytest.raises(RuntimeError):
        store.forget()
    assert store.sealed_path.read_bytes() == sealed
    assert json.loads((home / "mordred/mail/mail-forget.json").read_bytes())["phase"] == "intent"
    assert (home / "mordred/windows-mail.pending.json").exists()


def test_mail_forget_rows_preserves_live_root_database_authority(protected_runtime):
    from mordred_hermes.imports.mail.forget import forget
    from mordred_hermes.imports.store import open_import_store
    from mordred_hermes.keyvault._database_authority import observe_database_source

    home, provider, _backend = protected_runtime
    store = open_import_store(home)
    authority = provider.authority
    before = observe_database_source(root=home)
    credentials, _native = native_store(home)
    credentials.ensure_key(require_presence=False)
    credentials.store(generic_creds(), require_presence=False)
    done = forget(credentials, home, rows=True)
    assert done.key_gone and done.account == generic_creds().account
    assert observe_database_source(root=home) == before
    assert provider.authority is authority
    assert store.search("日本語") == []


def test_absent_native_key_does_not_hide_orphan_metadata(tmp_path):
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.keyvault._mail_custody import META, publish

    store, _native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    store.forget()
    with open_private_directory(store.meta_path.parent) as directory, directory.transaction() as tx:
        publish(tx, META, b'{"account":"mail"}')
    with pytest.raises(MailSecretsError, match=r"^tee_unavailable$"):
        store.forget()
    assert store.residue()


@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("interruption", ["rows", "cursors", "gap"])
def test_native_forget_lost_account_requires_named_retry(fs, tmp_path, monkeypatch, capsys, platform, interruption):
    from mordred_hermes.imports.mail.forget import MailForgetError, forget
    from mordred_hermes.wizard.mail_sync_cli import _report_forget

    if platform == "windows":
        _c, _, home, backend = fs
        credentials = MailSecretStore(
            home / "mordred/mail", backend_factory=lambda: backend, platform=lambda: "win32", audit_sink=lambda _e: None
        )
    else:
        home = tmp_path / "posix"
        home.mkdir(mode=0o700)
        credentials, _native = native_store(home)
    credentials.ensure_key(require_presence=False)
    credentials.store(generic_creds(), require_presence=False)

    class Rows:
        def __init__(self):
            self.messages = {"mail": 3, "other": 7}
            self.cursors = {"mail_imap.mail.inbox": "cursor"}
            self.broken = True

        def delete_source(self, source, account):
            assert not credentials.residue(), "SQL preceded credential retirement"
            if self.broken and interruption == "rows":
                raise OSError("injected SQL failure")
            return self.messages.pop(account, 0)

        def meta_items(self, prefix):
            return {key: value for key, value in self.cursors.items() if key.startswith(prefix)}

        def delete_meta(self, key):
            if self.broken and interruption == "cursors":
                raise OSError("injected cursor failure")
            self.cursors.pop(key)

    rows = Rows()
    if interruption == "gap":
        credentials.forget()  # Process stopped after acknowledged native cleanup, before SQL.
    else:
        with pytest.raises(MailForgetError):
            forget(credentials, home, rows=True, open_store=lambda _home: rows)
    rows.broken = False
    for _ in range(2):
        done = forget(credentials, home, rows=True, open_store=lambda _home: rows)
        assert done.warnings == ("account_unknown",)
        assert _report_forget(done, True) == 1
        assert "--yes --account LABEL" in capsys.readouterr().err
        assert rows.cursors and rows.messages["other"] == 7
    done = forget(credentials, home, rows=True, account="mail", open_store=lambda _home: rows)
    assert done.warnings == () and done.account == "mail"
    assert rows.messages == {"other": 7} and rows.cursors == {}


def test_public_forget_resumes_acknowledged_cleanup(tmp_path, monkeypatch):
    from mordred_hermes.imports.mail.forget import forget
    from mordred_hermes.keyvault import _mail_custody

    store, native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    original = _mail_custody.publish

    def interrupted(tx, name, data):
        original(tx, name, data)
        if name == _mail_custody.JOURNAL and json.loads(data)["phase"] == "deleted":
            raise OSError("injected after acknowledgement")

    monkeypatch.setattr(_mail_custody, "publish", interrupted)
    with pytest.raises(MailSecretsError, match=r"^store_path_unsafe$"):
        store.forget()
    monkeypatch.setattr(_mail_custody, "publish", original)
    calls = list(native.calls)

    def unavailable(_home):
        raise RuntimeError("no database required for credential cleanup")

    done = forget(store, tmp_path, open_store=unavailable)
    assert done.key_gone and not store.residue()
    assert native.calls == calls


@pytest.mark.parametrize("failure", ["native", "custody", "flags", "generation"])
def test_native_setup_refusal_scrubs_password_bearing_inner_frames(tmp_path, monkeypatch, failure):
    from mordred_hermes.imports.mail.setup_flow import MailSetupError, MailSetupFlows
    from mordred_hermes.keyvault._exceptions import WrapNativeUnavailable
    from tests._mail_sync_helpers import PASSWORD, secrets_in_traceback

    store, _native = native_store(tmp_path)
    error = WrapNativeUnavailable if failure == "native" else DatabaseRefused

    def refused(*args, **kwargs):
        raise error("synthetic native refusal")

    if failure in {"flags", "generation"}:
        from mordred_hermes.keyvault import _mail_custody

        original = _mail_custody.read

        def changed(directory, name):
            if name == (_mail_custody.JOURNAL if failure == "flags" else _mail_custody.GENERATION):
                raise DatabaseRefused("synthetic changed metadata")
            return original(directory, name)

        monkeypatch.setattr(_mail_custody, "read", changed)
    else:
        monkeypatch.setattr(wrap, "generate_wrapping_key", refused)
    flow = MailSetupFlows(store, home=lambda: tmp_path)
    with pytest.raises(MailSetupError) as caught:
        flow.start(address="owner@example.com", imap_host="imap.example.com", app_password=PASSWORD, presence=False)
    assert caught.value.code == ("store_path_unsafe" if failure == "generation" else "tee_unavailable")
    assert secrets_in_traceback(caught.value, PASSWORD) == []
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    frames = []
    trace = caught.value.__traceback__
    while trace is not None:
        frames.append(trace.tb_frame.f_code.co_name)
        trace = trace.tb_next
    assert "_start" not in frames and "_fresh_key" not in frames


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("WrapAuthCancelled", "tee_auth_cancelled"),
        ("WrapNativeUnavailable", "tee_unavailable"),
        ("WrapParseError", "secrets_corrupt"),
        ("WrapIntegrityError", "secrets_corrupt"),
    ],
)
def test_native_load_and_sync_preserve_refusal_taxonomy(tmp_path, monkeypatch, failure, expected):
    from mordred_hermes.imports.mail.imap_sync import FetchOptions, run_fetch
    from mordred_hermes.imports.mail.secrets import MailSecretsError
    from mordred_hermes.keyvault import _exceptions
    from tests._mail_sync_helpers import generic_server, make_env, make_store

    store, _native = native_store(tmp_path)
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    sealed = store.sealed_path.read_bytes()

    def refused(*args, **kwargs):
        raise getattr(_exceptions, failure)("synthetic private native detail")

    monkeypatch.setattr(wrap, "unwrap_dek", refused)
    with pytest.raises(MailSecretsError) as caught:
        store.load()
    assert caught.value.code == expected and str(caught.value) == expected
    db = make_store(tmp_path, tmp_path)
    result = run_fetch(FetchOptions(), make_env(tmp_path, db, generic_server(), store))
    assert result.error == expected
    from mordred_hermes.imports.mail.forget import MailForgetError, forget

    with pytest.raises(MailForgetError) as forgotten:
        forget(store, tmp_path, open_store=lambda _home: db)
    assert forgotten.value.code == expected
    assert store.sealed_path.read_bytes() == sealed


def test_windows_store_custody_failure_reaches_sanitized_setup_error(fs, monkeypatch):
    from mordred_hermes.imports.mail.setup_flow import MailSetupError, MailSetupFlows
    from mordred_hermes.keyvault._mail_custody import WindowsMailStore
    from mordred_hermes.keyvault._windows_profile import CustodyError
    from tests._mail_sync_helpers import PASSWORD, gmail_server, secrets_in_traceback

    _c, _, home, backend = fs
    store = MailSecretStore(
        home / "mordred/mail", backend_factory=lambda: backend, platform=lambda: "win32", audit_sink=lambda _e: None
    )
    store.ensure_key(require_presence=False)

    def refused(*args, **kwargs):
        raise CustodyError("synthetic custody refusal")

    monkeypatch.setattr(WindowsMailStore, "store", refused)
    server = gmail_server()
    flow = MailSetupFlows(store, home=lambda: home, connect=lambda _host, _port: server.session())
    with pytest.raises(MailSetupError) as caught:
        flow.start(address="owner@example.com", imap_host="imap.example.com", app_password=PASSWORD, presence=False)
    assert caught.value.code == "tee_unavailable"
    assert secrets_in_traceback(caught.value, PASSWORD) == []
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize("entry", ["public", "internal"])
def test_windows_store_presence_refuses_before_files_or_native_discovery(tmp_path, entry):
    from mordred_hermes.keyvault._mail_custody import WindowsMailStore

    if entry == "public":
        store = MailSecretStore(
            tmp_path / "mordred/mail",
            platform=lambda: "win32",
            backend_factory=lambda: pytest.fail("native discovery preceded presence refusal"),
        )
    else:
        store = WindowsMailStore(tmp_path, backend=None, audit_sink=lambda _e: None)
    with pytest.raises(MailSecretsError, match=r"^presence_unsupported$"):
        store.store(generic_creds(), require_presence=True)
    assert not (tmp_path / "mordred").exists()


@pytest.mark.parametrize("entry", ["public", "internal"])
def test_windows_store_presence_refusal_preserves_source_and_native_calls(fs, entry):
    _c, _, home, backend = fs
    store = MailSecretStore(
        home / "mordred/mail", platform=lambda: "win32", backend_factory=lambda: backend, audit_sink=lambda _e: None
    )
    store.ensure_key(require_presence=False)
    store.store(generic_creds(), require_presence=False)
    before = {path.name: path.read_bytes() for path in (store.sealed_path, store.meta_path)}
    calls = list(backend.calls)
    target = store if entry == "public" else store._windows()
    with pytest.raises(MailSecretsError, match=r"^presence_unsupported$"):
        target.store(replace(generic_creds(), app_password="replacement"), require_presence=True)
    assert backend.calls == calls
    assert {path.name: path.read_bytes() for path in (store.sealed_path, store.meta_path)} == before
    replacement = replace(generic_creds(), app_password="explicit-machine-bound-replacement")
    store.store(replacement, require_presence=False)
    assert store.load() == replacement
