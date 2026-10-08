"""Flat, role-specific Windows custody reset over existing deletion journals (C5e)."""

import json
from dataclasses import replace

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from tests.test_windows_custody import fs, opt_out  # noqa: F401


def deletes(backend):
    return [op for op, _ in backend.calls].count("delete")


def enrolled(c, home, backend, *roles):
    leases = {}
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        for role in roles:
            if role == "memory":
                session.enroll_memory()
                leases[role] = session.lease("memory")
            else:
                leases[role] = session.enroll_role(role)
    return leases


@pytest.fixture
def stopped(fs, monkeypatch):  # noqa: F811
    c, storage, home, backend = fs
    gates = []
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda path: gates.append(path))
    return c, storage, home, backend, gates


def forbid_unwrap(monkeypatch):
    from mordred_hermes.keyvault import wrap

    def tripwire(*args, **kwargs):
        raise AssertionError("reset must not unwrap or decrypt memory")

    monkeypatch.setattr(wrap, "unwrap_dek", tripwire)


def write_memory(home, name, data):
    with open_private_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(name, data)


def test_memory_reset_preserves_audit_telegram_and_memory_files(stopped, monkeypatch):
    c, _, home, backend, gates = stopped
    leases = enrolled(c, home, backend, "memory", "audit", "telegram")
    write_memory(home, "MEMORY.md", b"plaintext memory")
    opt_out(home)
    forbid_unwrap(monkeypatch)
    with c.windows_custody_session(home, backend=backend) as session:
        result = session.reset_role("memory")
        assert result == c.RoleReset("memory", (leases["memory"].generation,))
        session.validate_lease(leases["audit"])
        session.validate_lease(leases["telegram"])
        assert session.role_status("memory") == c.RoleStatus("memory", None, (), False)
        assert session.memory_state().lease is None
    assert gates == [home]
    assert leases["memory"].native_key_id not in backend._keys
    assert leases["audit"].native_key_id in backend._keys
    assert leases["telegram"].native_key_id in backend._keys
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"plaintext memory"
    assert not (home / "mordred" / "memory-key.wrapped").exists()
    assert not (home / "mordred" / "windows-memory.pending.json").exists()
    # Flat reset: the permanent directory and its lock stay.
    assert (home / "mordred").is_dir()
    assert (home / "mordred" / ".mordred-fs.lock").exists()


def test_audit_reset_requires_erasure_and_deletes_retained_before_current(stopped):
    c, _, home, backend, _ = stopped
    leases = enrolled(c, home, backend, "memory", "telegram")
    with c.windows_custody_session(home, backend=backend) as session:
        old = session.enroll_role("audit")
        new = session.enroll_role("audit", retain_current=True)
        with pytest.raises(c.CustodyError):
            session.reset_role("audit")
        assert deletes(backend) == 0
        assert not (home / "mordred" / "windows-audit.pending.json").exists()
        status = session.role_status("audit")
        assert status.current == new and status.retained == (old,) and not status.pending
        result = session.reset_role("audit", erase_authorized=True)
        assert result == c.RoleReset("audit", (old.generation, new.generation))
        session.validate_lease(leases["memory"])
        session.validate_lease(leases["telegram"])
        assert session.role_status("audit") == c.RoleStatus("audit", None, (), False)
    assert [key for op, key in backend.calls if op == "delete"] == [old.native_key_id, new.native_key_id]
    assert (home / "mordred" / "memory-key.wrapped").exists()


def test_telegram_reset_without_erasure_refuses_before_journal(stopped):
    c, _, home, backend, _ = stopped
    lease = enrolled(c, home, backend, "telegram")["telegram"]
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reset_role("telegram")
    assert deletes(backend) == 0
    assert lease.native_key_id in backend._keys
    assert not (home / "mordred" / "windows-telegram.pending.json").exists()


def test_reset_refuses_absent_or_empty_ownership(stopped):
    c, _, home, backend, _ = stopped
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        with pytest.raises(c.CustodyError):
            session.reset_role("memory", erase_authorized=True)
        session.enroll_role("audit")
        with pytest.raises(c.CustodyError):
            session.reset_role("telegram", erase_authorized=True)
        with pytest.raises(c.CustodyError):
            session.reset_role("unknown", erase_authorized=True)
    assert deletes(backend) == 0


def test_reset_refuses_pending_role_journal_without_native_action(stopped, monkeypatch):
    c, _, home, backend, _ = stopped
    enrolled(c, home, backend, "audit")

    def denied(*args, **kwargs):
        raise c.CustodyError("native unavailable")

    monkeypatch.setattr(backend, "generate_enclave_key", denied)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home, backend=backend) as session:
        session.enroll_role("audit", retain_current=True)
    journal = home / "mordred" / "windows-audit.pending.json"
    before = journal.read_bytes()
    calls = list(backend.calls)
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.role_status("audit").pending
        with pytest.raises(c.CustodyError):
            session.reset_role("audit", erase_authorized=True)
    assert journal.read_bytes() == before
    assert backend.calls == calls


def test_reset_validates_every_role_journal_before_mutation(stopped):
    c, _, home, backend, _ = stopped
    lease = enrolled(c, home, backend, "memory")["memory"]
    opt_out(home)
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("windows-audit.pending.json", b"{not json")
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reset_role("memory")
    assert deletes(backend) == 0
    assert lease.native_key_id in backend._keys
    assert (home / "mordred" / "memory-key.wrapped").exists()


@pytest.mark.parametrize("erase_authorized", [False, True])
def test_memory_reset_refuses_marker_and_sealed_inventory_without_touching_files(
    stopped, monkeypatch, erase_authorized
):
    c, _, home, backend, gates = stopped
    from mordred_hermes.keyvault.memory_crypto import seal

    lease = enrolled(c, home, backend, "memory")["memory"]
    sealed = seal(b"sealed memory", key=b"K" * 32, name="MEMORY.md")
    write_memory(home, "MEMORY.md", sealed)
    forbid_unwrap(monkeypatch)
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.marker", b"1\n")
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reset_role("memory", erase_authorized=erase_authorized)
    assert gates == []  # a marker refuses before even the gateway inventory gate
    # An opt-out does not authorize crypto-shredding retained seals either.
    (home / "mordred" / "memory-vault.marker").unlink()
    opt_out(home)
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reset_role("memory", erase_authorized=erase_authorized)
    assert deletes(backend) == 0
    assert lease.native_key_id in backend._keys
    assert (home / "memories" / "MEMORY.md").read_bytes() == sealed
    assert not (home / "mordred" / "windows-memory.pending.json").exists()


def test_memory_reset_requires_explicit_opt_out(stopped):
    c, _, home, backend, _ = stopped
    enrolled(c, home, backend, "memory")
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reset_role("memory", erase_authorized=True)
    assert deletes(backend) == 0


@pytest.fixture
def retained_memory(stopped):
    c, _, home, backend, _ = stopped
    from mordred_hermes.keyvault import _windows_profile as profile
    from tests.test_windows_custody_profile import SID

    enrolled(c, home, backend, "memory")
    opt_out(home)
    with open_private_directory(home) as directory:
        identity = directory.directory_identity()
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        manifest = profile.parse_manifest(tx.read_bytes("windows-custody.json", max_bytes=profile.LIMIT), identity, SID)
        record = profile.new_record(manifest, "memory")
        record = replace(record, epoch=manifest.epoch, public_sha256="ab" * 32)
        state = manifest.role("memory")
        changed = manifest.with_role("memory", replace(state, retained=(record,)), epoch=manifest.epoch)
        tx.replace_bytes("windows-custody.json", profile.encode_manifest(changed))
    return c, home, backend


def test_memory_reset_refuses_retained_memory_generations(retained_memory):
    c, home, backend = retained_memory
    before = (home / "mordred" / "windows-custody.json").read_bytes()
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.reset_role("memory", erase_authorized=True)
    assert deletes(backend) == 0
    assert (home / "mordred" / "windows-custody.json").read_bytes() == before
    assert (home / "mordred" / "memory-key.wrapped").exists()


def test_ambiguous_native_deletion_stays_unresolved_and_refuses_next_reset(stopped, monkeypatch):
    c, _, home, backend, _ = stopped
    leases = enrolled(c, home, backend, "memory")
    with c.windows_custody_session(home, backend=backend) as session:
        first = session.enroll_role("audit")
        second = session.enroll_role("audit", retain_current=True)
        current = session.enroll_role("audit", retain_current=True)
    delete = backend.delete_enclave_key

    def ambiguous(key_id):
        delete(key_id)
        if key_id == second.native_key_id:
            raise c.CustodyError("native response lost")

    monkeypatch.setattr(backend, "delete_enclave_key", ambiguous)
    with pytest.raises(c.CustodyError) as failed, c.windows_custody_session(home, backend=backend) as session:
        session.reset_role("audit", erase_authorized=True)
    assert any("1 confirmed deletion" in note for note in getattr(failed.value, "__notes__", ()))
    journal = home / "mordred" / "windows-audit.pending.json"
    before = journal.read_bytes()
    assert json.loads(before)["phase"] == "intent"
    with c.windows_custody_session(home, backend=backend) as session:
        status = session.role_status("audit")
        assert status.pending
        assert status.current == current and status.retained == (second,)
        with pytest.raises(c.CustodyError):
            session.reset_role("audit", erase_authorized=True)
        with pytest.raises(c.CustodyError):
            session.reconcile_pending("audit", erase_authorized=True)
        session.validate_lease(leases["memory"])
    assert journal.read_bytes() == before
    assert [key for op, key in backend.calls if op == "delete"] == [first.native_key_id, second.native_key_id]
    assert current.native_key_id in backend._keys


def test_crash_between_native_delete_and_journal_commit_is_unresolved_on_reload(stopped, monkeypatch):
    c, _, home, backend, _ = stopped
    lease = enrolled(c, home, backend, "telegram")["telegram"]
    journal = c.WindowsCustodySession._journal

    def crash(session, pending, **kwargs):
        if pending.phase == "deleted":
            raise PrivateFSError("io", "deleted_ledger")
        journal(session, pending, **kwargs)

    monkeypatch.setattr(c.WindowsCustodySession, "_journal", crash)
    with pytest.raises(PrivateFSError) as failed, c.windows_custody_session(home, backend=backend) as session:
        session.reset_role("telegram", erase_authorized=True)
    assert failed.value.commit_state == "uncertain"
    monkeypatch.setattr(c.WindowsCustodySession, "_journal", journal)
    with c.windows_custody_session(home, backend=backend) as session:
        assert session.role_status("telegram").pending
        with pytest.raises(c.CustodyError):
            session.reset_role("telegram", erase_authorized=True)
        with pytest.raises(c.CustodyError):
            session.lease("telegram")
    assert deletes(backend) == 1
    assert lease.native_key_id not in backend._keys
    assert (home / "mordred" / "windows-telegram.pending.json").exists()


def test_role_status_is_read_only_and_needs_no_native_backend(stopped, monkeypatch):
    c, _, home, backend, _ = stopped
    leases = enrolled(c, home, backend, "memory", "audit")
    calls = list(backend.calls)

    def tripwire():
        raise AssertionError("role status constructed a native backend")

    monkeypatch.setattr(c, "windows_backend", tripwire)
    with c.windows_custody_session(home) as session:
        assert session.role_status("memory") == c.RoleStatus("memory", leases["memory"], (), False)
        assert session.role_status("audit") == c.RoleStatus("audit", leases["audit"], (), False)
        assert session.role_status("telegram") == c.RoleStatus("telegram", None, (), False)
    assert backend.calls == calls
