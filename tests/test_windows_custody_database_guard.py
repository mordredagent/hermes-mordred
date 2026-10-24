"""Windows memory mutations require database-before-custody proof."""

import os

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from tests.test_windows_custody import fs as fs


def test_already_held_enrollment_refuses_without_preceding_database_proof(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as session:
        before = tuple((home / "mordred").iterdir())
        with pytest.raises(DatabaseRefused):
            session.enroll_memory()
        assert tuple((home / "mordred").iterdir()) == before
        assert not backend.calls


DEPENDENCIES = [
    "state.db",
    "state.db.mordred-enc",
    "state.db-wal",
    "state.db.bak",
    "mordred/db-encryption.marker",
    "mordred/db-encryption.pending",
    "mordred/db-backups.json",
    "mordred/db-unknown",
]


def snapshot(home):
    return {p.relative_to(home): p.read_bytes() for p in home.rglob("*") if p.is_file()}


@pytest.mark.parametrize("dependency", DEPENDENCIES)
@pytest.mark.parametrize("operation", ["enroll", "delete", "reset", "create-pending", "deleted-pending"])
def test_every_memory_mutation_preserves_dependencies_and_custody(fs, monkeypatch, dependency, operation):
    c, _, home, backend = fs

    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda home: None)
    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        if operation != "enroll":
            owner.enroll_memory(database_lease=backend.database_lease)
            memory = owner.lease("memory")
            owner._publish(c.OPTOUT, b"1\n", create=True)
        if operation == "create-pending":
            manifest = owner._manifest()
            record = manifest.role("memory").current
            # This is a validated interrupted ownership commit, not a fabricated owner.
            owner._journal(c.Pending(manifest.profile_nonce, "memory", "create", "verified", record), create=True)
        if operation == "deleted-pending":
            manifest = owner._manifest()
            record = manifest.role("memory").current
            owner._journal(c.Pending(manifest.profile_nonce, "memory", "delete", "deleted", record), create=True)
        path = home / dependency
        path.write_bytes(b"retained database evidence")
        before = snapshot(home)
        calls = list(backend.calls)
        with pytest.raises(DatabaseRefused):
            if operation == "enroll":
                owner.enroll_memory(database_lease=backend.database_lease)
            elif operation == "delete":
                owner.delete_role(memory, erase_authorized=True, database_lease=backend.database_lease)
            elif operation == "reset":
                owner.reset_role("memory", erase_authorized=True, database_lease=backend.database_lease)
            else:
                owner.reconcile_pending("memory", erase_authorized=True, database_lease=backend.database_lease)
        assert snapshot(home) == before
        assert backend.calls == calls


def test_lost_memory_source_cannot_be_recreated_over_database(fs):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        owner.enroll_memory(database_lease=backend.database_lease)
    # Simulate lost custody metadata; an existing database still owns the key's lifecycle.
    for name in (c.MANIFEST, c.WRAPPED):
        (home / "mordred" / name).unlink()
    (home / "state.db").write_bytes(b"retained")
    before = snapshot(home)
    calls = list(backend.calls)
    with c.windows_custody_session(home, backend=backend) as owner, pytest.raises(DatabaseRefused):
        owner.enroll_memory(database_lease=backend.database_lease)
    assert snapshot(home) == before
    assert backend.calls == calls


@pytest.mark.parametrize("role", ["audit", "telegram"])
def test_independent_current_retained_roles_delete_with_memory_dependencies(fs, role):
    c, _, home, backend = fs
    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        owner.enroll_memory(database_lease=backend.database_lease)
        memory = owner.lease("memory")
        first = owner.enroll_role(role)
        second = owner.enroll_role(role, retain_current=True)
        (home / "state.db").write_bytes(b"retained")
        independent = _issue_native_owner(owner, native_key_id=first.native_key_id, backend=backend)
        with _owned_delete_scope(independent, backend=backend, database_lease=None) as permit:
            calls = list(backend.calls)
            with pytest.raises(DatabaseRefused):
                backend.delete_enclave_key(memory.native_key_id, deletion=permit)
            assert backend.calls == calls
        result = owner.reset_role(role, erase_authorized=True)
        assert result.deleted == (first.generation, second.generation)
        assert memory.native_key_id in backend._keys


def test_owner_facts_preserve_full_memory_generation_and_raw_delete_refuses(fs):
    c, _, home, backend = fs
    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        owner.enroll_memory(database_lease=backend.database_lease)
        lease = owner.lease("memory")
        facts = owner._check_native_delete_owner(lease.native_key_id, backend)
        assert facts.database_home == facts.home == home
        assert facts.generation == lease.generation and len(facts.generation) == 64
        calls = list(backend.calls)
        with pytest.raises(DatabaseRefused):
            backend.delete_enclave_key(lease.native_key_id)
        assert backend.calls == calls
        native = _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
        with _owned_delete_scope(native, backend=backend, database_lease=backend.database_lease) as expired:
            pass
        with pytest.raises(DatabaseRefused):
            backend.delete_enclave_key(lease.native_key_id, deletion=expired)
        assert backend.calls == calls


@pytest.mark.parametrize("changed", ["selector", "backend", "ops", "ownership", "closed", "thread", "unregistered"])
def test_checked_native_owner_refuses_stale_or_borrowed_session_before_native_io(fs, changed):
    c, _, home, backend = fs
    from concurrent.futures import ThreadPoolExecutor

    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope
    from tests._windows_custody_fakes import windows_test_backend

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        lease = owner.enroll_role("audit")
        native = _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
        with _owned_delete_scope(native, backend=backend, database_lease=None) as permit:
            calls = list(backend.calls)
            if changed == "selector":
                with pytest.raises(DatabaseRefused):
                    backend.delete_enclave_key("other-selector", deletion=permit)
            elif changed == "backend":
                with pytest.raises(DatabaseRefused):
                    windows_test_backend().delete_enclave_key(lease.native_key_id, deletion=permit)
            elif changed == "ops":
                original = backend._ops
                backend._ops = windows_test_backend()._ops
                try:
                    with pytest.raises(DatabaseRefused):
                        backend.delete_enclave_key(lease.native_key_id, deletion=permit)
                finally:
                    backend._ops = original
            elif changed == "ownership":
                manifest = owner._manifest()
                owner._save(manifest.with_role("audit", c.RoleState(), epoch=manifest.epoch + 1))
                with pytest.raises(DatabaseRefused):
                    backend.delete_enclave_key(lease.native_key_id, deletion=permit)
            elif changed == "closed":
                owner._live = False
                try:
                    with pytest.raises(RuntimeError):
                        backend.delete_enclave_key(lease.native_key_id, deletion=permit)
                finally:
                    owner._live = True
            elif changed == "thread":
                with ThreadPoolExecutor(1) as executor, pytest.raises(DatabaseRefused):
                    executor.submit(backend.delete_enclave_key, lease.native_key_id, deletion=permit).result()
            else:
                borrowed = c.WindowsCustodySession(
                    home, owner.canonical, owner._tx, owner._identity, owner._sid, backend
                )
                with pytest.raises(RuntimeError):
                    _issue_native_owner(borrowed, native_key_id=lease.native_key_id, backend=backend)
            assert backend.calls == calls


def test_generic_borrowed_canonical_refuses_late_database_proof(fs, monkeypatch):
    c, _, home, backend = fs
    from mordred_hermes._config_io import CanonicalPaths, canonical_session
    from mordred_hermes._database_lifecycle import acquire_exclusive
    from mordred_hermes.keyvault import _database_mutation as mutation

    # Use a separate root with no fixture lease, to prove that canonical intent
    # predates the late database transaction even when custody joins it.
    other = home.parent / "other"
    other.mkdir(mode=0o700)
    with canonical_session(CanonicalPaths(other), scope="policy", create=True) as canonical:
        monkeypatch.setattr(mutation, "acquire_exclusive", lambda *a, **k: pytest.fail("reverse acquisition"))
        with pytest.raises(DatabaseRefused), mutation.database_key_mutation(root=other, generation=None):
            pass
        with (
            acquire_exclusive(other) as late,
            c.windows_custody_session(other, canonical=canonical, backend=backend) as owner,
        ):
            before = snapshot(other)
            with pytest.raises(DatabaseRefused):
                owner.enroll_memory(database_lease=late)
            assert snapshot(other) == before


@pytest.mark.parametrize("operation", ["enroll", "delete", "reset", "reconcile"])
def test_child_memory_mutation_guards_actual_root_all_generations(fs, monkeypatch, operation):
    c, _, home, backend = fs
    child = home / "profiles/work"
    child.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(c, "require_stopped_windows_gateways", lambda home: None)
    with c.windows_custody_session(child, create=True, backend=backend) as owner:
        if operation != "enroll":
            owner.enroll_memory(database_lease=backend.database_lease)
            memory = owner.lease("memory")
            owner._publish(c.OPTOUT, b"1\n", create=True)
        if operation == "reconcile":
            manifest = owner._manifest()
            owner._journal(
                c.Pending(manifest.profile_nonce, "memory", "delete", "deleted", manifest.role("memory").current),
                create=True,
            )
        (home / "older-generation.db").write_bytes(b"legacy root or child ciphertext")
        before = snapshot(home)
        calls = list(backend.calls)
        with pytest.raises(DatabaseRefused):
            if operation == "enroll":
                owner.enroll_memory(database_lease=backend.database_lease)
            elif operation == "delete":
                owner.delete_role(memory, erase_authorized=True, database_lease=backend.database_lease)
            elif operation == "reset":
                owner.reset_role("memory", erase_authorized=True, database_lease=backend.database_lease)
            else:
                owner.reconcile_pending("memory", erase_authorized=True, database_lease=backend.database_lease)
        assert snapshot(home) == before
        assert backend.calls == calls


def test_retained_memory_generation_has_exact_checked_facts_and_database_guard(fs):
    c, _, home, backend = fs
    from dataclasses import replace

    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        owner.enroll_memory(database_lease=backend.database_lease)
        manifest = owner._manifest()
        record = c.new_record(manifest, "memory")
        public = backend.generate_enclave_key(record.native_key_id, unattended=True)
        retained = replace(record, epoch=manifest.epoch, public_sha256=c._fingerprint(public))
        owner._save(
            manifest.with_role("memory", replace(manifest.role("memory"), retained=(retained,)), epoch=manifest.epoch)
        )
        lease = owner.lease_for_native("memory", retained.native_key_id)
        native = _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
        facts = owner._check_native_delete_owner(lease.native_key_id, backend)
        assert facts.generation == retained.generation and len(facts.generation) == 64
        (home / "old.db").write_bytes(b"retained")
        calls = list(backend.calls)
        with (
            pytest.raises(DatabaseRefused),
            _owned_delete_scope(native, backend=backend, database_lease=backend.database_lease),
        ):
            pytest.fail("retained memory earned independent-role permission")
        assert backend.calls == calls


def test_owner_scope_exit_expires_outstanding_permission(fs):
    c, _, home, backend = fs
    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        lease = owner.enroll_role("audit")
        native = _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
        scope = _owned_delete_scope(native, backend=backend, database_lease=None)
        permit = scope.__enter__()
    calls = list(backend.calls)
    try:
        with pytest.raises(RuntimeError):
            backend.delete_enclave_key(lease.native_key_id, deletion=permit)
        assert backend.calls == calls
    finally:
        scope.__exit__(None, None, None)


@pytest.mark.parametrize("dependency", DEPENDENCIES)
@pytest.mark.parametrize("sink", ["backend", "wrap", "raw-ops"])
def test_windows_native_sink_rechecks_each_database_dependency_before_io(fs, dependency, sink):
    c, _, home, backend = fs
    from mordred_hermes.keyvault import wrap
    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope
    from mordred_hermes.keyvault._seckey_errors import _application_tag

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        owner.enroll_memory(database_lease=backend.database_lease)
        lease = owner.lease("memory")
        native = _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
        with _owned_delete_scope(native, backend=backend, database_lease=backend.database_lease) as permit:
            # A late observed dependency must be checked at the real sink too.
            (home / dependency).write_bytes(b"retained")
            before = snapshot(home)
            calls = list(backend.calls)
            with pytest.raises(DatabaseRefused):
                if sink == "backend":
                    backend.delete_enclave_key(lease.native_key_id, deletion=permit)
                elif sink == "wrap":
                    wrap.delete_wrapping_key(lease.native_key_id, backend=backend, deletion=permit)
                else:
                    backend._ops.delete_key(_application_tag(lease.native_key_id))
            assert snapshot(home) == before
            assert backend.calls == calls


def test_swapped_store_refuses_before_native_ownership_lookup(fs):
    c, _, home, backend = fs
    from tests._windows_custody_fakes import windows_test_backend

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        audit = owner.enroll_role("audit")
        public = backend.get_enclave_public_key(audit.native_key_id)
        original = backend._ops
        replacement = windows_test_backend()._ops
        io = []

        def lookup(tag):
            io.append(tag)
            return public

        replacement.copy_public_key = lookup
        backend._ops = replacement
        try:
            with pytest.raises(DatabaseRefused):
                owner.delete_role(audit, erase_authorized=True)
            assert io == []
        finally:
            backend._ops = original


def test_enrollment_rechecks_dependencies_after_fresh_memory_inspection(fs, monkeypatch):
    c, _, home, backend = fs
    fresh = c.WindowsCustodySession._fresh_memory

    def changed(owner, key):
        fresh(owner, key)
        (home / "late.db").write_bytes(b"retained")

    monkeypatch.setattr(c.WindowsCustodySession, "_fresh_memory", changed)
    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        with pytest.raises(DatabaseRefused):
            owner.enroll_memory(database_lease=backend.database_lease)
        assert not (home / "mordred" / c.MANIFEST).exists()
        assert not (home / "mordred" / "windows-memory.pending.json").exists()
        assert backend.calls == []


def test_deleted_reconciliation_rechecks_dependencies_after_gateway_observation(fs, monkeypatch):
    c, _, home, backend = fs
    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        owner.enroll_memory(database_lease=backend.database_lease)
        manifest = owner._manifest()
        owner._journal(
            c.Pending(manifest.profile_nonce, "memory", "delete", "deleted", manifest.role("memory").current),
            create=True,
        )
        before = snapshot(home)

        def changed(home):
            (home / "late.db").write_bytes(b"retained")

        monkeypatch.setattr(c, "require_stopped_windows_gateways", changed)
        with pytest.raises(DatabaseRefused):
            owner.reconcile_pending("memory", database_lease=backend.database_lease)
        assert all((home / name).read_bytes() == data for name, data in before.items())


@pytest.mark.parametrize("proof", ["fabricated", "expired", "wrong-root"])
def test_memory_enrollment_rejects_nonpreceding_database_proof_before_io(fs, proof):
    c, _, home, backend = fs
    from contextlib import ExitStack

    from mordred_hermes._database_lifecycle import ExclusiveLease, acquire_exclusive

    other = home.parent / "other"
    other.mkdir(mode=0o700)
    with ExitStack() as leases:
        lease = leases.enter_context(acquire_exclusive(other))
        if proof == "expired":
            leases.close()
        candidate = object.__new__(ExclusiveLease) if proof == "fabricated" else lease
        with c.windows_custody_session(home, create=True, backend=backend) as owner:
            before = snapshot(home)
            with pytest.raises(DatabaseRefused):
                owner.enroll_memory(database_lease=candidate)
            assert snapshot(home) == before
            assert backend.calls == []


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX process-bound custody registry")
def test_forked_session_cannot_issue_or_use_native_authority(fs):
    c, _, home, backend = fs
    from mordred_hermes.keyvault._native_deletion import _issue_native_owner, _owned_delete_scope

    with c.windows_custody_session(home, create=True, backend=backend) as owner:
        lease = owner.enroll_role("audit")
        native = _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
        with _owned_delete_scope(native, backend=backend, database_lease=None) as permit:
            read_fd, write_fd = os.pipe()
            try:
                pid = os.fork()
                if pid == 0:
                    try:
                        calls = list(backend.calls)
                        with pytest.raises(DatabaseRefused):
                            _issue_native_owner(owner, native_key_id=lease.native_key_id, backend=backend)
                        with pytest.raises(DatabaseRefused):
                            backend.delete_enclave_key(lease.native_key_id, deletion=permit)
                        assert backend.calls == calls
                        os.write(write_fd, b"refused")
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                _, status = os.waitpid(pid, 0)
                assert os.waitstatus_to_exitcode(status) == 0
                assert os.read(read_fd, 7) == b"refused"
            finally:
                os.close(read_fd)
                os.close(write_fd)
