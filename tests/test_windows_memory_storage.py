"""Windows memory contracts through real checked storage and real MRKW crypto."""

from dataclasses import replace

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import _memory_storage as storage
from mordred_hermes.keyvault.memory_crypto import is_sealed, seal, unseal
from tests.test_windows_custody import fs as fs


@pytest.fixture
def memory(fs, monkeypatch):
    c, _, home, backend = fs
    monkeypatch.setattr(storage, "open_confidential_directory", open_private_directory, raising=False)
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda: True, raising=False)
    monkeypatch.setattr(c, "windows_backend", lambda: backend)
    return c, home, backend


def put(home, name, data):
    with open_private_directory(home / "memories", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(name, data)


def enroll(memory):
    c, home, backend = memory
    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        key = owner.enroll_memory()
        lease = owner.lease("memory")
    return key, lease


def mark(home, name="memory-vault.marker"):
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes(name, b"1\n")


def test_unmanaged_checked_io_does_not_enroll(memory):
    _, home, backend = memory
    with storage.windows_memory_session(home, create=True) as session:
        assert session.read_text("MEMORY.md") is None
        session.write_entries("MEMORY.md", [" alpha ", "beta"], delimiter="\n§\n")
        assert session.read_plaintext("MEMORY.md") == " alpha \n§\nbeta"
    assert backend.calls == []
    assert not (home / "mordred" / "memory-key.wrapped").exists()


def test_managed_sticky_write_and_bounded_state(memory):
    c, home, _ = memory
    key, lease = enroll(memory)
    mark(home)
    with storage.windows_memory_session(home, create=True, lease=lease) as session:
        session.write_entries("MEMORY.md", ["alpha"], delimiter="\n§\n")
        assert session.read_plaintext("MEMORY.md") == "alpha"
    mark(home, "memory-vault.optout")
    with storage.windows_memory_session(home, safe_mode=True) as session:
        session.write_entries("MEMORY.md", ["beta"], delimiter="\n§\n")
    data = (home / "memories" / "MEMORY.md").read_bytes()
    assert is_sealed(data)
    opened = unseal(data, key=key, name="MEMORY.md") == b"beta"
    assert opened, "safe-mode write did not stay sealed"
    with c.windows_custody_session(home) as owner:
        state = owner.memory_state()
        assert state.lease == lease
        assert state.marker == b"1\n"
        assert state.optout == b"1\n"
        assert len(state.wrapped_sha256) == 64


@pytest.mark.parametrize("payload", [b"HERMES-MEMORY-ENC-v1\nbroken", b"invalid\xff"], ids=["seal", "utf8"])
def test_invalid_file_never_rewritten(memory, payload):
    _, home, _ = memory
    enroll(memory)
    put(home, "MEMORY.md", payload)
    with pytest.raises((ValueError, RuntimeError, UnicodeError)), storage.windows_memory_session(home) as session:
        session.write_entries("MEMORY.md", ["replacement"], delimiter="\n§\n")
    assert (home / "memories" / "MEMORY.md").read_bytes() == payload


def test_wrong_key_seal_refuses_even_disarmed(memory):
    _, home, _ = memory
    enroll(memory)
    payload = seal(b"preserve", key=b"x" * 32, name="MEMORY.md")
    put(home, "MEMORY.md", payload)
    with pytest.raises(RuntimeError), storage.windows_memory_session(home) as session:
        session.write_entries("MEMORY.md", ["replacement"], delimiter="\n§\n")
    assert (home / "memories" / "MEMORY.md").read_bytes() == payload


def test_backup_is_sealed_before_publication_and_collision_preserves(memory):
    _, home, _ = memory
    key, _ = enroll(memory)
    with storage.windows_memory_session(home, create=True) as session:
        name = "MEMORY.md.bak.42"
        session.create_backup(name, " keep me ")
        with pytest.raises(PrivateFSError) as collision:
            session.create_backup(name, "overwrite")
        assert collision.value.reason == "exists"
        inventory = session.inventory()
        assert [row.name for row in inventory] == [name]
        opened = unseal(inventory[0].data, key=key, name=name) == b" keep me "
        assert opened, "backup collision replaced the original seal"


def test_stale_lease_refuses_without_publication(memory):
    _, home, _ = memory
    _, lease = enroll(memory)
    with (
        pytest.raises(RuntimeError),
        storage.windows_memory_session(home, create=True, lease=replace(lease, generation="0" * 32)),
    ):
        pass
    assert not (home / "memories").exists()


def test_target_other_profile_refuses(memory, tmp_path):
    _, home, _ = memory
    other = tmp_path / "other"
    with open_private_directory(other, create=True):
        pass
    with open_private_directory(other / "memories", create=True):
        pass
    with (
        pytest.raises((RuntimeError, PrivateFSError)),
        storage.windows_memory_session(home, path=other / "memories" / "MEMORY.md", create=True),
    ):
        pass
    assert not (other / "memories" / "MEMORY.md").exists()


@pytest.mark.parametrize("name", ["../MEMORY.md", "USER.md:stream", ".mordred-fs.lock", "other.txt"])
def test_invalid_leaf_refuses(memory, name):
    _, home, _ = memory
    with storage.windows_memory_session(home, create=True) as session, pytest.raises((PrivateFSError, ValueError)):
        session.write_entries(name, ["no"], delimiter="\n§\n")


def test_session_expiry_and_generation_drift_refuse(memory):
    c, home, _ = memory
    enroll(memory)
    with pytest.raises(RuntimeError), storage.windows_memory_session(home, create=True) as session:
        session.write_entries("MEMORY.md", ["original"], delimiter="\n§\n")
        with session.custody.canonical.borrow_mordred_transaction() as tx:
            tx.create_bytes("memory-vault.marker", b"1\n")
        with pytest.raises(RuntimeError):
            session.write_entries("MEMORY.md", ["stale"], delimiter="\n§\n")
    with pytest.raises(RuntimeError):
        session.read_text("MEMORY.md")
    assert (home / "memories" / "MEMORY.md").read_text() == "original"
    with c.windows_custody_session(home) as owner:
        state = owner.memory_state()
        assert state.marker == b"1\n"


def test_unsupported_runtime_allows_only_unmanaged(memory, monkeypatch):
    _, home, _ = memory
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda: False)
    with storage.windows_memory_session(home, create=True) as session:
        session.write_entries("MEMORY.md", ["plain"], delimiter="\n§\n")
    enroll(memory)
    with pytest.raises(RuntimeError), storage.windows_memory_session(home):
        pass


def test_structural_admission_pythonw_and_renamed(tmp_path):
    root = tmp_path / "env"
    scripts = root / "Scripts"
    scripts.mkdir(parents=True)
    (root / "pyvenv.cfg").write_text("home = ignored\n")
    for name in ["python.exe", "pythonw.exe", "renamed.exe"]:
        (scripts / name).touch()
    assert storage.windows_memory_runtime_admitted(scripts / "python.exe")
    assert storage.windows_memory_runtime_admitted(scripts / "pythonw.exe")
    assert not storage.windows_memory_runtime_admitted(scripts / "renamed.exe")
    (scripts / "python.exe").unlink()
    assert not storage.windows_memory_runtime_admitted(scripts / "pythonw.exe")


def test_caught_postpublication_read_failure_poison_owner(memory, monkeypatch):
    c, home, _ = memory
    put(home, "MEMORY.md", b"old")
    injected = PrivateFSError("io", "verify_read")
    with (
        pytest.raises(PrivateFSError) as outer,
        c.windows_custody_session(home, create=True) as owner,
        storage.windows_memory_session(home, custody=owner) as session,
    ):
        transaction = session._tx
        write = transaction.replace_bytes
        read = transaction.read_bytes
        published = False

        def publish(name, data):
            nonlocal published
            write(name, data)
            published = True

        def fail_after_publish(name, **kwargs):
            if published:
                raise injected
            return read(name, **kwargs)

        monkeypatch.setattr(transaction, "replace_bytes", publish)
        monkeypatch.setattr(transaction, "read_bytes", fail_after_publish)
        with pytest.raises(PrivateFSError) as inner:
            session.write_entries("MEMORY.md", ["new"], delimiter="\n§\n")
        assert inner.value is injected
        assert injected.commit_state == "uncertain"
    assert outer.value is injected
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"new"


def test_native_key_missing_cannot_overwrite_ciphertext(memory):
    _, home, backend = memory
    key, _ = enroll(memory)
    data = seal(b"retained", key=key, name="MEMORY.md")
    put(home, "MEMORY.md", data)
    backend._keys.clear()
    with pytest.raises(RuntimeError), storage.windows_memory_session(home, create=True):
        pass
    assert (home / "memories" / "MEMORY.md").read_bytes() == data


@pytest.mark.parametrize("bound", ["file", "total", "entry"])
def test_bounded_inventory_and_publication_refuse(memory, monkeypatch, bound):
    _, home, _ = memory
    put(home, "MEMORY.md", b"1234")
    put(home, "USER.md", b"1234")
    limit = {"file": "MEMORY_FILE_LIMIT", "total": "MEMORY_TOTAL_LIMIT", "entry": "MEMORY_ENTRY_LIMIT"}[bound]
    monkeypatch.setattr(storage, limit, 3 if bound != "entry" else 1)
    with pytest.raises(PrivateFSError), storage.windows_memory_session(home, create=True):
        pass
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"1234"


def test_cross_thread_session_refuses(memory):
    from concurrent.futures import ThreadPoolExecutor

    _, home, _ = memory
    with (
        storage.windows_memory_session(home, create=True) as session,
        ThreadPoolExecutor(1) as executor,
        pytest.raises(RuntimeError),
    ):
        executor.submit(session.read_text, "MEMORY.md").result()


def test_marker_limit_refuses_as_uncertain_state_not_absence(memory):
    c, home, _ = memory
    enroll(memory)
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.create_bytes("memory-vault.marker", b"x" * 4097)
    with pytest.raises(PrivateFSError), c.windows_custody_session(home) as owner:
        owner.memory_state()


def test_copied_profile_refuses_before_memory_publication(memory, tmp_path):
    import shutil

    _, home, _ = memory
    enroll(memory)
    copy = tmp_path / "copy"
    shutil.copytree(home, copy)
    with pytest.raises((RuntimeError, PrivateFSError)), storage.windows_memory_session(copy, create=True):
        pass
    assert not (copy / "memories").exists()


def test_child_cleanup_failure_caught_still_poison_owner(memory, monkeypatch):
    from contextlib import contextmanager

    c, home, _ = memory
    put(home, "MEMORY.md", b"old")
    injected = PrivateFSError("io", "child_cleanup")
    optional = storage.open_optional_confidential_directory

    class CleanupDirectory:
        def __init__(self, directory):
            self.directory = directory

        def directory_identity(self):
            return self.directory.directory_identity()

        @contextmanager
        def transaction(self):
            with self.directory.transaction() as tx:
                yield tx
            raise injected

    visits = 0

    @contextmanager
    def cleanup_directory(path):
        nonlocal visits
        with optional(path) as directory:
            if path.name == "memories":
                visits += 1
            yield CleanupDirectory(directory) if path.name == "memories" and visits == 2 else directory

    with pytest.raises(PrivateFSError) as outer, c.windows_custody_session(home, create=True) as owner:
        monkeypatch.setattr(storage, "open_optional_confidential_directory", cleanup_directory)
        with pytest.raises(PrivateFSError), storage.windows_memory_session(home, custody=owner) as session:
            session.write_entries("MEMORY.md", ["new"], delimiter="\n§\n")
    assert outer.value is injected
    assert injected.commit_state == "uncertain"
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"new"


def test_new_name_cannot_overflow_entry_bound(memory, monkeypatch):
    _, home, _ = memory
    put(home, "MEMORY.md", b"old")
    monkeypatch.setattr(storage, "MEMORY_ENTRY_LIMIT", 1)
    with storage.windows_memory_session(home) as session, pytest.raises(PrivateFSError):
        session.write_entries("USER.md", ["new"], delimiter="\n§\n")
    assert not (home / "memories" / "USER.md").exists()


def test_checked_absent_home_reads_absent_without_creation(memory, monkeypatch):
    from contextlib import contextmanager

    _, home, _ = memory
    optional = storage.open_optional_confidential_directory

    @contextmanager
    def strict_optional(path):
        if not path.parent.exists():
            raise PrivateFSError("unsafe", "missing_intermediate")
        with optional(path) as directory:
            yield directory

    monkeypatch.setattr(storage, "open_optional_confidential_directory", strict_optional)
    missing = home / "new-profile"
    with storage.windows_memory_session(missing) as session:
        assert session.read_plaintext("MEMORY.md") is None
    assert not missing.exists()


def test_empty_file_at_exact_aggregate_bound_is_valid(memory, monkeypatch):
    _, home, _ = memory
    put(home, "MEMORY.md", b"1234")
    put(home, "USER.md", b"")
    monkeypatch.setattr(storage, "MEMORY_TOTAL_LIMIT", 4)
    with storage.windows_memory_session(home) as session:
        assert len(session.inventory()) == 2
        assert session.read_plaintext("USER.md") == ""


def test_name_lookup_skips_non_memory_entries(memory):
    _, home, _ = memory
    put(home, "MEMORY.md", b"plain")
    (home / "memories" / ".archive").mkdir()
    with storage.windows_memory_session(home) as session:
        assert session.read_plaintext("MEMORY.md") == "plain"
        session.write_entries("MEMORY.md", ["next"], delimiter="\n§\n")
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"next"


class Abort(BaseException):
    pass


def test_postpublication_base_exception_stays_unchanged_and_uncertain(memory, monkeypatch):
    c, home, _ = memory
    put(home, "MEMORY.md", b"old")
    injected = Abort()
    caught = []
    with pytest.raises(PrivateFSError) as outer, c.windows_custody_session(home, create=True) as owner:
        try:
            with storage.windows_memory_session(home, custody=owner) as session:
                transaction = session._tx
                write = transaction.replace_bytes
                read = transaction.read_bytes
                published = False

                def publish(name, data):
                    nonlocal published
                    write(name, data)
                    published = True

                def interrupt_after_publish(name, **kwargs):
                    if published:
                        raise injected
                    return read(name, **kwargs)

                monkeypatch.setattr(transaction, "replace_bytes", publish)
                monkeypatch.setattr(transaction, "read_bytes", interrupt_after_publish)
                session.write_entries("MEMORY.md", ["new"], delimiter="\n§\n")
        except Abort as exc:
            caught.append(exc)
    assert caught == [injected]
    assert outer.value.commit_state == "uncertain"
    assert (home / "memories" / "MEMORY.md").read_bytes() == b"new"


@pytest.mark.parametrize(
    "leaf",
    ["memory-vault.marker", "memory-vault.optout", "memory-key.wrapped", "windows-memory.pending.json"],
    ids=["marker", "optout", "wrapper", "pending"],
)
def test_memory_state_rejects_evidence_without_ownership(memory, leaf):
    c, home, _ = memory
    with open_private_directory(home / "mordred", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes(leaf, b"1\n")
    with pytest.raises(c.CustodyError), c.windows_custody_session(home) as owner:
        owner.memory_state()


def test_memory_state_rejects_ownership_without_wrapper(memory):
    c, home, _ = memory
    enroll(memory)
    with open_private_directory(home / "mordred") as directory, directory.transaction() as tx:
        tx.delete_file("memory-key.wrapped", expected_identity=tx.stat("memory-key.wrapped").identity)
    with pytest.raises(c.CustodyError), c.windows_custody_session(home) as owner:
        owner.memory_state()


def test_case_alias_keeps_stored_basename_aad(memory):
    _, home, _ = memory
    key, _ = enroll(memory)
    put(home, "MEMORY.md", seal(b"alpha", key=key, name="MEMORY.md"))
    if not (home / "memories" / "memory.MD").exists():
        pytest.skip("case-sensitive host filesystem")
    with storage.windows_memory_session(home) as session:
        assert session.read_plaintext("memory.MD") == "alpha"
        session.write_entries("memory.md", ["beta"], delimiter="\n§\n")
        assert [row.name for row in session.inventory()] == ["MEMORY.md"]
    opened = unseal((home / "memories" / "MEMORY.md").read_bytes(), key=key, name="MEMORY.md") == b"beta"
    assert opened, "case alias did not keep the stored basename as AAD"
