"""Explicit schema migration preserves existing ownership and never calls native."""

import json
from contextlib import ExitStack

import pytest

from mordred_hermes.keyvault._database_mutation import database_key_mutation
from tests.test_windows_custody import fs as fs


def _populated(fs):
    c, _, home, backend = fs
    with (
        database_key_mutation(root=home, generation=None) as lease,
        c.windows_custody_session(home, create=True, backend=backend) as session,
    ):
        session.enroll_memory(database_lease=lease)
        session.enroll_role("audit")
        session.enroll_role("telegram")
        before = session._manifest()
    return before


def test_v1_three_roles_upgrade_without_rekey(fs):
    c, _, home, backend = fs
    before = _populated(fs)
    raw = (home / "mordred" / c.MANIFEST).read_bytes()
    assert json.loads(raw)["version"] == 1
    calls = list(backend.calls)
    assert hasattr(c, "upgrade_manifest_v2"), "explicit schema upgrade is missing"
    c.upgrade_manifest_v2(home=home)
    with c.windows_custody_session(home) as session:
        after = session._manifest()
        for role in ("memory", "audit", "telegram"):
            assert after.role(role) == before.role(role)
            assert (
                json.loads(raw)["roles"][role]
                == json.loads((home / "mordred" / c.MANIFEST).read_bytes())["roles"][role]
            )
        assert after.role("mail").current is None
        assert after.epoch == before.epoch
        assert after.profile_nonce == before.profile_nonce
    assert backend.calls == calls
    assert json.loads((home / "mordred" / c.MANIFEST).read_bytes())["version"] == 2
    published = (home / "mordred" / c.MANIFEST).read_bytes()
    c.upgrade_manifest_v2(home=home)
    assert (home / "mordred" / c.MANIFEST).read_bytes() == published


@pytest.mark.parametrize("boundary", ["intent", "manifest", "published", "remove"])
def test_schema_upgrade_crash_recovers_exactly_once(fs, monkeypatch, boundary):
    c, _, home, backend = fs
    before = _populated(fs)
    assert hasattr(c, "upgrade_manifest_v2"), "explicit schema upgrade is missing"
    original = c.WindowsCustodySession._publish
    remove = c.WindowsCustodySession._remove
    interrupted = False

    def publish(self, name, data, **kwargs):
        nonlocal interrupted
        original(self, name, data, **kwargs)
        phase = json.loads(data).get("phase")
        hit = (boundary == "manifest" and name == c.MANIFEST) or phase == boundary
        if hit and not interrupted:
            interrupted = True
            raise RuntimeError("simulated crash")

    def deleting(self, name):
        if boundary == "remove":
            raise RuntimeError("simulated crash")
        remove(self, name)

    with monkeypatch.context() as patch:
        patch.setattr(c.WindowsCustodySession, "_publish", publish)
        patch.setattr(c.WindowsCustodySession, "_remove", deleting)
        with pytest.raises(RuntimeError, match="simulated crash"):
            c.upgrade_manifest_v2(home=home)
    calls = list(backend.calls)
    with c.windows_custody_session(home) as session, pytest.raises(c.CustodyError):
        session.lease("memory")
    c.upgrade_manifest_v2(home=home)
    c.upgrade_manifest_v2(home=home)
    with c.windows_custody_session(home) as session:
        for role in ("memory", "audit", "telegram"):
            assert session._manifest().role(role) == before.role(role)
        assert session._manifest().role("mail").current is None
    assert backend.calls == calls
    assert not (home / "mordred" / c.SCHEMA_PENDING).exists()


def test_upgrade_refuses_unknown_schema_and_pending_role_without_native(fs):
    c, _, home, backend = fs
    _populated(fs)
    assert hasattr(c, "upgrade_manifest_v2"), "explicit schema upgrade is missing"
    path = home / "mordred" / c.MANIFEST
    original = path.read_bytes()
    value = json.loads(original)
    value["version"] = 3
    path.write_text(json.dumps(value))
    with pytest.raises(c.CustodyError):
        c.upgrade_manifest_v2(home=home)
    path.write_bytes(original)
    pending = home / "mordred/windows-audit.pending.json"
    pending.write_bytes(b"uncertain")
    pending.chmod(0o600)
    calls = list(backend.calls)
    with pytest.raises(c.CustodyError):
        c.upgrade_manifest_v2(home=home)
    assert path.read_bytes() == original
    assert backend.calls == calls


def test_mail_upgrade_preserves_database_authority_snapshot(fs, monkeypatch):
    from mordred_hermes._database_lifecycle import acquire_runtime
    from mordred_hermes.dbcrypt import _authority as runtime
    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._marker import Marker
    from mordred_hermes.keyvault import _database_authority as source

    c, _, home, backend = fs
    _populated(fs)
    domain = source.resolve_database_domain(home)

    def observe(*, root):
        with c.windows_custody_session(root) as session:
            return source._observe_windows(session, domain.identities[0])

    before = observe(root=home)
    monkeypatch.setattr(runtime, "observe_database_source", observe)
    monkeypatch.setattr(runtime, "read_marker", lambda root: Marker(before))
    assert hasattr(c, "upgrade_manifest_v2"), "explicit schema upgrade is missing"
    with ExitStack() as resources:
        lease = resources.enter_context(acquire_runtime(home))
        authority = runtime.Authority(domain, before, derive(b"K" * 32), lease, resources)
        authority.check()
        calls = list(backend.calls)
        c.upgrade_manifest_v2(home=home)
        assert observe(root=home) == before
        authority.check()
        assert authority.snapshot == before
        assert not authority.terminal
        assert backend.calls == calls


def test_mail_enrollment_requires_explicit_upgrade(fs):
    c, _, home, backend = fs
    _populated(fs)
    with c.windows_custody_session(home, backend=backend) as session, pytest.raises(c.CustodyError):
        session.enroll_role("mail")
    c.upgrade_manifest_v2(home=home)
    with c.windows_custody_session(home, backend=backend) as session:
        mail = session.enroll_role("mail")
        assert mail.role == "mail"
        session.delete_role(mail, erase_authorized=True)
        assert session.role_status("mail").current is None


def test_mail_creation_and_owned_deletion_preserve_held_database_authority(fs, monkeypatch):
    from mordred_hermes._database_lifecycle import acquire_runtime
    from mordred_hermes.dbcrypt import _authority as runtime
    from mordred_hermes.dbcrypt._key import derive
    from mordred_hermes.dbcrypt._marker import Marker
    from mordred_hermes.keyvault import _database_authority as source

    c, _, home, backend = fs
    before = _populated(fs)
    domain = source.resolve_database_domain(home)

    def observe(*, root):
        with c.windows_custody_session(root) as session:
            return source._observe_windows(session, domain.identities[0])

    snapshot = observe(root=home)
    marker = home / "mordred/db-encryption.marker"
    marker.write_bytes(b"1\n")
    marker.chmod(0o600)
    monkeypatch.setattr(runtime, "observe_database_source", observe)
    monkeypatch.setattr(runtime, "read_marker", lambda root: Marker(snapshot))
    c.upgrade_manifest_v2(home=home)
    with ExitStack() as resources:
        lease = resources.enter_context(acquire_runtime(home))
        authority = runtime.Authority(domain, snapshot, derive(b"K" * 32), lease, resources)
        with c.windows_custody_session(home, backend=backend) as session:
            mail = session.enroll_role("mail")
            session.delete_role(mail, erase_authorized=True)
            assert session._manifest().role("memory") == before.role("memory")
        authority.check()
        assert authority.snapshot == snapshot
    assert marker.read_bytes() == b"1\n"
    deletes = [selector for op, selector in backend.calls if op == "delete"]
    assert deletes == [mail.native_key_id]


@pytest.mark.parametrize("damage", ["unknown-version", "duplicate", "phase", "before", "after", "published-old"])
def test_schema_journal_refuses_conflicts_without_repair(fs, monkeypatch, damage):
    import json

    c, _, home, backend = fs
    _populated(fs)
    original = c.WindowsCustodySession._publish

    def interrupted(self, name, data, **kwargs):
        original(self, name, data, **kwargs)
        if name == c.SCHEMA_PENDING:
            raise RuntimeError("simulated crash")

    with monkeypatch.context() as patch:
        patch.setattr(c.WindowsCustodySession, "_publish", interrupted)
        with pytest.raises(RuntimeError):
            c.upgrade_manifest_v2(home=home)
    journal = home / "mordred" / c.SCHEMA_PENDING
    obj = json.loads(journal.read_bytes())
    if damage == "unknown-version":
        obj["version"] = 2
    elif damage == "phase":
        obj["phase"] = []
    elif damage == "before":
        obj["before_sha256"] = "00" * 32
    elif damage == "after":
        obj["after_sha256"] = "00" * 32
    elif damage == "published-old":
        obj["phase"] = "published"
    raw = json.dumps(obj).encode()
    if damage == "duplicate":
        raw = raw.replace(b'"version": 1', b'"version": 1, "version": 1')
    journal.write_bytes(raw)
    manifest = (home / "mordred" / c.MANIFEST).read_bytes()
    calls = list(backend.calls)
    with pytest.raises(c.CustodyError):
        c.upgrade_manifest_v2(home=home)
    assert journal.read_bytes() == raw
    assert (home / "mordred" / c.MANIFEST).read_bytes() == manifest
    assert backend.calls == calls


def test_fresh_mail_only_profile_uses_explicit_public_upgrade(fs):
    c, _, home, backend = fs
    c.upgrade_manifest_v2(home=home)
    assert backend.calls == []
    with c.windows_custody_session(home, backend=backend) as session:
        manifest = session._manifest()
        assert manifest.version == 2
        assert all(manifest.role(role).current is None for role in ("memory", "audit", "telegram", "mail"))
        mail = session.enroll_role("mail")
        assert session.role_status("memory").current is None
        session.delete_role(mail, erase_authorized=True)


@pytest.mark.parametrize(
    "artifact",
    [
        "windows-schema.pending.json",
        "windows-mail.pending.json",
        "windows-custody.json.bak",
        "memory-key.wrapped",
        "memory-vault.marker",
        "memory-vault.optout",
        "db-key-source.json",
        "db-encryption.marker",
        "unknown-custody.json",
        "mail",
        "keyvault",
    ],
)
def test_missing_manifest_with_retained_state_never_becomes_fresh(fs, artifact):
    from mordred_hermes._private_fs import open_private_directory

    c, _, home, backend = fs
    with open_private_directory(home / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(artifact, b"retain-for-reconciliation")
    before = (home / "mordred" / artifact).read_bytes()
    with pytest.raises(c.CustodyError):
        c.upgrade_manifest_v2(home=home)
    assert (home / "mordred" / artifact).read_bytes() == before
    assert not (home / "mordred" / c.MANIFEST).exists()
    assert backend.calls == []


def test_fresh_schema_refuses_lost_ownership_with_sealed_memory(fs):
    from mordred_hermes._private_fs import open_private_directory
    from mordred_hermes.keyvault.memory_crypto import seal

    c, _, home, backend = fs
    with open_private_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("MEMORY.md", seal(b"retained", key=b"K" * 32, name="MEMORY.md"))
    with pytest.raises(c.CustodyError):
        c.upgrade_manifest_v2(home=home)
    assert not (home / "mordred" / c.MANIFEST).exists()
    assert backend.calls == []
