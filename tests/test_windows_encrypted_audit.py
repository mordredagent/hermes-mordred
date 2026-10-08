"""Real checked filesystem/MRKW/MRAL with only native custody boundaries injected."""

import base64
import gzip
import json
from contextlib import suppress
from dataclasses import replace

import pytest

from mordred_hermes._audit_session import AuditSession, audit_session
from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import log_encryption as log
from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
from tests import test_windows_custody

custody_fixture = test_windows_custody.fs


@pytest.fixture(name="fs")
def audit_fs(custody_fixture):
    return custody_fixture


def assert_no_cached_dek(writer):
    absent = writer._dek is None
    assert absent, "cached audit DEK was not dropped"


def assert_wiped(buffer):
    wiped = buffer is not None and not any(buffer)
    assert wiped, "cached audit DEK was not wiped"


def adapter():
    from mordred_hermes.keyvault import windows_audit

    return windows_audit


@pytest.fixture(autouse=True)
def checked_audit_boundary(fs, monkeypatch):
    from mordred_hermes import _audit_session, _config_io

    a = adapter()
    monkeypatch.setattr(a, "open_optional_private_directory", _config_io.open_optional_private_directory)
    monkeypatch.setattr(
        _audit_session.fs, "open_optional_private_directory", _config_io.open_optional_private_directory
    )


def enrolled(fs):
    custody, _, home, backend = fs
    with custody.windows_custody_session(home, create=True, backend=backend) as session:
        lease = session.enroll_role("audit")
    return adapter(), custody, home, backend, lease


def provider(a, home, backend):
    return a.WindowsAuditProvider(home, backend=backend)


def test_audit_provider_is_load_only_without_filevault_or_memory(fs):
    a = adapter()
    c, _, home, backend = fs
    with pytest.raises(c.CustodyError):
        provider(a, home, backend).writer(home / "mordred" / "audit.log")
    assert not backend.calls
    assert not (home / "mordred").exists()


def test_exact_owned_native_lookup_current_retained_and_wrong_role(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        old = session.enroll_role("audit")
        current = session.enroll_role("audit", retain_current=True)
        assert session.lease_for_native("audit", old.native_key_id) == old
        assert session.lease_for_native("audit", current.native_key_id) == current
        with pytest.raises(c.CustodyError):
            session.lease_for_native("memory", old.native_key_id)
        with pytest.raises(c.CustodyError):
            session.lease_for_native("audit", "arbitrary.native.tag")


def test_writer_mral_roundtrip_independent_of_filevault(fs):
    a, _, home, backend, lease = enrolled(fs)
    path = home / "mordred" / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "first", "ts": "fixed"})
    header = json.loads(path.read_bytes().splitlines()[0])
    assert header["key_id"] == log.AUDIT_LOG_KEY_ID
    assert header["native_key_id"] == lease.native_key_id
    assert len(base64.b64decode(header["wdek"])) == 127
    assert a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None) == [
        {"event": "first", "ts": "fixed"}
    ]
    assert not (home / "mordred" / "keyvault").exists()
    assert not (home / "mordred" / "memory-key.wrapped").exists()
    w.close()
    assert_no_cached_dek(w)


def test_retained_audit_history_and_stale_writer_refusal(fs):
    a, c, home, backend, old = enrolled(fs)
    path = home / "mordred" / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "old"})
    cached = w._dek
    with c.windows_custody_session(home, backend=backend) as session:
        session.enroll_role("audit", retain_current=True)
    before = path.read_bytes()
    with pytest.raises(c.CustodyError):
        w.append({"event": "stale"})
    assert_no_cached_dek(w)
    assert_wiped(cached)
    assert path.read_bytes() == before
    assert (
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)[0]["event"] == "old"
    )
    fresh = provider(a, home, backend).writer(path)
    fresh.append({"event": "new"})
    historical = next(path.parent.glob("audit.log.*.gz"))
    assert (
        a.decrypt_windows_log_file(historical, home=home, backend=backend, audit_sink=lambda event: None)[0]["event"]
        == "old"
    )
    assert old.native_key_id in backend._keys


def test_missing_native_lookup_never_regenerates(fs):
    a, _, home, backend, _lease = enrolled(fs)
    backend._keys.clear()
    with pytest.raises(WrapKeyNotFound):
        provider(a, home, backend).writer(home / "mordred" / "audit.log")
    assert [op for op, _ in backend.calls].count("generate") == 1


def test_header_swap_wipes_cached_dek_and_refuses_foreign_selector(fs):
    a, c, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "first"})
    cached = w._dek
    lines = path.read_bytes().splitlines()
    header = json.loads(lines[0])
    header["native_key_id"] = "arbitrary.native.tag"
    path.write_bytes(json.dumps(header).encode() + b"\n" + b"\n".join(lines[1:]) + b"\n")
    before = path.read_bytes()
    with pytest.raises(c.CustodyError):
        w.append({"event": "refuse"})
    assert_wiped(cached)
    assert_no_cached_dek(w)
    assert path.read_bytes() == before
    assert not list(path.parent.glob("audit.log.*.gz"))


def test_two_writers_checked_rotation_preserves_all_events(fs):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    p = provider(a, home, backend)
    first, second = p.writer(path), p.writer(path)
    for n in range(6):
        (first if n % 2 == 0 else second).append({"n": n})
    values = []
    for candidate in [path, *path.parent.glob("audit.log.*.gz")]:
        values += a.decrypt_windows_log_file(candidate, home=home, backend=backend, audit_sink=lambda event: None)
    assert sorted(event["n"] for event in values) == list(range(6))


def test_decrypt_callback_explicit_custody_reuses_loan_after_audit_unlock(fs):
    a, c, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "before"})
    with (
        c.windows_custody_session(home, backend=backend) as session,
        session.canonical.borrow_mordred_transaction() as loan,
    ):

        def sink(event):
            # Snapshot is immutable; explicit borrowing avoids another home.
            w.append_in_custody(event, custody=session, transaction=loan)

        result = a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=sink, custody=session)
    assert [event["event"] for event in result] == ["before"]
    assert len(a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)) == 2


def test_custom_path_caught_uncertain_mutation_poisons_outer_and_writer(fs, monkeypatch):
    a, c, home, backend, _ = enrolled(fs)
    custom = home.parent / "custom"
    with open_private_directory(custom, create=True):
        pass
    w = provider(a, home, backend).writer(custom / "audit.log")
    w.append({"event": "before"})
    original = AuditSession.append

    def interrupted(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise PrivateFSError("io", "injected_after_append", commit_state="uncertain")

    monkeypatch.setattr(AuditSession, "append", interrupted)
    with (
        pytest.raises(PrivateFSError) as failure,
        c.windows_custody_session(home, backend=backend) as session,
        suppress(PrivateFSError),
    ):
        w.append_in_custody({"event": "published"}, custody=session)
    assert failure.value.commit_state == "uncertain"
    assert_no_cached_dek(w)
    with pytest.raises(c.CustodyError, match="poison"):
        w.append({"event": "never retry"})


@pytest.mark.parametrize("payload", [b"", b"not json\n", b'{"fmt":"MRAL","ver":1}\n', b"{}\n"])
def test_bounded_malformed_read_never_calls_native(fs, payload):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    path.write_bytes(payload)
    path.chmod(0o600)
    before = len(backend.calls)
    with pytest.raises(log.AuditLogDecryptError):
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)
    assert len(backend.calls) == before


def test_gzip_and_snapshot_limits(fs):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    path.write_bytes(gzip.compress(b"A" * 2048))
    path.chmod(0o600)
    with pytest.raises(PrivateFSError, match="audit_decode_limit"):
        a.decrypt_windows_log_file(
            path, home=home, backend=backend, audit_sink=lambda event: None, max_output_bytes=1024
        )
    with pytest.raises(PrivateFSError, match="audit_read_limit"):
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None, max_file_bytes=1)


def test_wrong_home_and_copied_header_refuse(fs):
    a, c, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    provider(a, home, backend).writer(path).append({"event": "owned"})
    other = home.parent / "other"
    with open_private_directory(other, create=True):
        pass
    with c.windows_custody_session(other, create=True, backend=backend) as session:
        session.enroll_role("audit")
        with pytest.raises(c.CustodyError):
            a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None, custody=session)
    with pytest.raises(c.CustodyError):
        a.decrypt_windows_log_file(path, home=other, backend=backend, audit_sink=lambda event: None)


def test_default_loan_lifetime_and_wrong_transaction_refusal(fs):
    a, c, home, backend, _ = enrolled(fs)
    w = provider(a, home, backend).writer(home / "mordred" / "audit.log")
    with c.windows_custody_session(home, backend=backend) as session:
        with session.canonical.borrow_mordred_transaction() as loan:
            w.append_in_custody({"event": "borrowed"}, custody=session, transaction=loan)
        with pytest.raises(RuntimeError):
            w.append_in_custody({"event": "expired"}, custody=session, transaction=loan)
    with pytest.raises(RuntimeError):
        w.append_in_custody({"event": "closed"}, custody=session)


def test_writer_lease_forgery_is_not_authority(fs):
    _a, c, home, backend, lease = enrolled(fs)
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.validate_lease(replace(lease, epoch=lease.epoch + 1))


def test_missing_active_identity_never_autorecreates(fs):
    a, c, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "before"})
    cached = w._dek
    path.unlink()
    with pytest.raises(PrivateFSError, match="audit_active_missing"):
        w.append({"event": "lost"})
    assert_wiped(cached)
    assert not path.exists()
    with pytest.raises(c.CustodyError, match="poison"):
        w.append({"event": "retry"})
    assert not path.exists()


def test_malformed_wrapped_dek_refuses_before_any_native_lookup(fs):
    a, _, home, backend, lease = enrolled(fs)
    path = home / "mordred" / "audit.log"
    path.write_bytes(log._make_log_header(b"invalid wrapper", log.AUDIT_LOG_KEY_ID, lease.native_key_id) + b"\n")
    path.chmod(0o600)
    count = len(backend.calls)
    with pytest.raises(log.AuditLogDecryptError):
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)
    assert len(backend.calls) == count


def test_malformed_gzip_has_decrypt_error_contract(fs):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    path.write_bytes(b"\x1f\x8bmalformed")
    path.chmod(0o600)
    with pytest.raises(log.AuditLogDecryptError):
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)


def test_audit_retained_history_survives_memory_purge_and_reenroll(fs, monkeypatch):
    a, c, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    provider(a, home, backend).writer(path).append({"event": "retained"})
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda home: None)
    with c.windows_custody_session(home, backend=backend) as session:
        session.enroll_memory()
        memory = session.lease("memory")
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.optout", b"1\n")
    with c.windows_custody_session(home, backend=backend) as session:
        session.delete_role(memory)
        session.enroll_memory()
    assert (
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)[0]["event"]
        == "retained"
    )


def test_custom_snapshot_releases_directory_lock_before_unwrap_callback(fs):
    a, c, home, backend, _ = enrolled(fs)
    custom = home.parent / "custom"
    with open_private_directory(custom, create=True):
        pass
    path = custom / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "before"})
    with c.windows_custody_session(home, backend=backend) as session:

        def sink(event):
            # Different directory than the retained lifecycle loan: a live
            # C7a session would refuse implicit cross-directory reentrancy.
            with audit_session(home / "mordred" / "unused", transaction=loan):
                pass
            w.append_in_custody(event, custody=session)

        with session.canonical.borrow_mordred_transaction() as loan:
            entries = a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=sink, custody=session)
    assert len(entries) == 1
    assert len(a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)) == 2


@pytest.mark.parametrize("mutation", ["create", "rename", "delete"])
def test_custom_each_uncertain_mutation_and_catch_is_monotonic(fs, monkeypatch, mutation):
    a, c, home, backend, _ = enrolled(fs)
    custom = home.parent / "custom"
    with open_private_directory(custom, create=True):
        pass
    path = custom / "audit.log"
    w = provider(a, home, backend).writer(path, rotate_bytes=1)
    if mutation != "create":
        w.append({"event": "old"})
    original = getattr(AuditSession, mutation)

    def interrupted(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise PrivateFSError("io", "injected_after_" + mutation, commit_state="uncertain")

    monkeypatch.setattr(AuditSession, mutation, interrupted)
    with (
        pytest.raises(PrivateFSError) as failure,
        c.windows_custody_session(home, backend=backend) as session,
        suppress(PrivateFSError),
    ):
        w.append_in_custody({"event": "new"}, custody=session)
    assert failure.value.commit_state == "uncertain"
    assert_no_cached_dek(w)
    with pytest.raises(c.CustodyError, match="poison"):
        w.append({"event": "retry"})


def test_corrupt_ciphertext_authentication_refuses(fs):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    provider(a, home, backend).writer(path).append({"event": "auth"})
    header, encoded = path.read_bytes().splitlines()
    blob = bytearray(base64.b64decode(encoded))
    blob[-1] ^= 1
    path.write_bytes(header + b"\n" + base64.b64encode(blob) + b"\n")
    with pytest.raises(log.AuditLogDecryptError, match="authentication"):
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)


def test_custom_missing_directory_and_home_path_refuse_without_creation(fs):
    a, _, home, backend, _ = enrolled(fs)
    missing = home.parent / "absent" / "audit.log"
    with pytest.raises(PrivateFSError, match="audit_directory"):
        provider(a, home, backend).writer(missing).append({"event": "refuse"})
    assert not missing.parent.exists()
    with pytest.raises(PrivateFSError, match="audit_home_lock_order"):
        provider(a, home, backend).writer(home / "audit.log").append({"event": "refuse"})
    assert not (home / "audit.log").exists()


def test_custom_child_exit_failure_is_sticky_after_caught_error(fs, monkeypatch):
    from contextlib import contextmanager

    a, c, home, backend, _ = enrolled(fs)
    custom = home.parent / "custom"
    with open_private_directory(custom, create=True):
        pass
    w = provider(a, home, backend).writer(custom / "audit.log")
    original = a.audit_session

    @contextmanager
    def failing_child(*args, **kwargs):
        with original(*args, **kwargs) as session:
            yield session
        raise PrivateFSError("io", "injected_child_exit", commit_state="uncertain")

    monkeypatch.setattr(a, "audit_session", failing_child)
    with (
        pytest.raises(PrivateFSError) as failure,
        c.windows_custody_session(home, backend=backend) as session,
        suppress(PrivateFSError),
    ):
        w.append_in_custody({"event": "published"}, custody=session)
    assert failure.value.operation == "injected_child_exit"
    assert failure.value.commit_state == "uncertain"
    assert_no_cached_dek(w)
    assert (custom / "audit.log").exists()


def test_checked_owned_identity_swap_rotates_and_wipes_old_buffer(fs):
    a, _, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    first = provider(a, home, backend).writer(path)
    second = provider(a, home, backend).writer(path)
    first.append({"event": "first"})
    cached = first._dek
    second.append({"event": "second"})
    first.append({"event": "third"})
    assert_wiped(cached)
    assert (
        a.decrypt_windows_log_file(path, home=home, backend=backend, audit_sink=lambda event: None)[0]["event"]
        == "third"
    )


def test_stale_profile_manifest_absence_wipes_before_any_mutation(fs):
    a, c, home, backend, _ = enrolled(fs)
    path = home / "mordred" / "audit.log"
    w = provider(a, home, backend).writer(path)
    w.append({"event": "old"})
    before = path.read_bytes()
    (home / "mordred" / c.MANIFEST).unlink()
    with pytest.raises(c.CustodyError):
        w.append({"event": "refuse"})
    assert_no_cached_dek(w)
    assert path.read_bytes() == before
    assert [op for op, _ in backend.calls].count("generate") == 1


def test_generic_failure_after_custom_header_publication_poisoned_and_classified(fs, monkeypatch):
    a, c, home, backend, _ = enrolled(fs)
    custom = home.parent / "custom"
    with open_private_directory(custom, create=True):
        pass
    w = provider(a, home, backend).writer(custom / "audit.log")

    def fail_encrypt(*args, **kwargs):
        __tracebackhide__ = True  # Never render the injected DEK arguments.
        raise ValueError("injected crypto failure")

    monkeypatch.setattr(a, "encrypt", fail_encrypt)
    with pytest.raises(PrivateFSError) as error:
        w.append({"event": "refuse"})
    assert error.value.commit_state == "uncertain"
    assert (custom / "audit.log").exists()
    assert_no_cached_dek(w)
    with pytest.raises(c.CustodyError, match="poison"):
        w.append({"event": "retry"})
