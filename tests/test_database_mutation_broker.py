"""Database mutation must precede every custody intent, including callbacks."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys

import pytest

from mordred_hermes._database_contracts import DatabaseRefused, Dependency, Inventory
from mordred_hermes._database_lifecycle import ExclusiveLease, acquire_exclusive


def broker():
    from mordred_hermes.keyvault import _database_mutation

    return _database_mutation


def test_empty_home_yields_genuine_live_lease(tmp_path):
    with broker().database_key_mutation(root=tmp_path, generation=None) as lease:
        assert type(lease) is ExclusiveLease
        lease.assert_held(tmp_path)
        broker().assert_database_helper_removal_safe(tmp_path, lease)
    with pytest.raises(DatabaseRefused):
        broker().assert_database_helper_removal_safe(tmp_path, lease)


@pytest.mark.parametrize("kind", ["database", "pending", "journal", "backup", "unknown"])
def test_all_generations_are_guarded(tmp_path, monkeypatch, kind):
    from mordred_hermes import _database_inventory as inventory

    monkeypatch.setattr(
        inventory,
        "scan_dependencies",
        lambda root: Inventory((Dependency(root / "retained", kind, "other"),), kind != "unknown"),
    )
    with pytest.raises(DatabaseRefused), broker().database_key_mutation(root=tmp_path, generation="requested"):
        pytest.fail("dependency admitted")


@pytest.mark.parametrize("lock_kind", ["memory", "lifecycle", "keyvault"])
def test_custody_callback_refuses_before_database_acquisition(tmp_path, monkeypatch, lock_kind):
    from mordred_hermes.keyvault import _memory_key, _storage

    module = broker()

    def forbidden(*args, **kwargs):
        pytest.fail("database acquisition attempted below custody")

    monkeypatch.setattr(module, "acquire_exclusive", forbidden)
    root = tmp_path / "mordred/keyvault"
    _storage.ensure_layout(root)
    locks = {
        "memory": lambda: _memory_key.memory_key_lock(tmp_path),
        "lifecycle": lambda: _storage.keyvault_lifecycle_lock(root),
        "keyvault": lambda: _storage.keyvault_lock(root),
    }
    with (
        locks[lock_kind](),
        pytest.raises(DatabaseRefused),
        module.database_key_mutation(root=tmp_path, generation=None),
    ):
        pytest.fail("reverse lock admitted")


def test_nested_custody_borrows_preceding_lease_without_acquisition(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _memory_key

    module = broker()
    with module.database_key_mutation(root=tmp_path, generation=None) as outer:
        monkeypatch.setattr(module, "acquire_exclusive", lambda *a, **kw: pytest.fail("nested OS acquisition"))
        with (
            _memory_key.memory_key_lock(tmp_path),
            module.database_key_mutation(root=tmp_path, generation=None) as inner,
        ):
            assert inner is outer
            with _memory_key.memory_key_lock(tmp_path):
                module._assert_memory_database_mutation_safe(home=tmp_path, database_lease=inner)


def test_lease_acquired_after_custody_is_insufficient(tmp_path):
    from mordred_hermes.keyvault import _memory_key

    with _memory_key.memory_key_lock(tmp_path), acquire_exclusive(tmp_path) as late:
        with pytest.raises(DatabaseRefused):
            broker()._assert_memory_database_mutation_safe(home=tmp_path, database_lease=late)
        with pytest.raises(DatabaseRefused), broker().database_key_mutation(root=tmp_path, generation=None):
            pytest.fail("late lease borrowed")


def test_fabricated_missing_wrong_root_and_expired_proofs_refuse(tmp_path):
    module = broker()
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    fake = object.__new__(ExclusiveLease)
    for lease in (None, fake):
        with pytest.raises(DatabaseRefused):
            module._assert_memory_database_mutation_safe(home=tmp_path, database_lease=lease)
    with acquire_exclusive(other) as wrong, pytest.raises(DatabaseRefused):
        module._assert_memory_database_mutation_safe(home=tmp_path, database_lease=wrong)
    with acquire_exclusive(tmp_path) as expired:
        pass
    with pytest.raises(DatabaseRefused):
        module._assert_memory_database_mutation_safe(home=tmp_path, database_lease=expired)


def test_child_uses_actual_root_and_guard_is_fresh(tmp_path):
    module = broker()
    child = tmp_path / "profiles/work"
    child.mkdir(parents=True, mode=0o700)
    with module.database_key_mutation(root=child, generation="child") as lease:
        lease.assert_held(tmp_path)
        module._assert_memory_database_mutation_safe(home=child, database_lease=lease)
        (tmp_path / "root.db").write_bytes(b"retained")
        with pytest.raises(DatabaseRefused):
            module._assert_memory_database_mutation_safe(home=child, database_lease=lease)


@pytest.mark.parametrize("alias", ["home", "profiles", "root"])
def test_child_aliases_refuse(tmp_path, alias):
    root = tmp_path / "root"
    child = root / "profiles/work"
    child.mkdir(parents=True, mode=0o700)
    link = tmp_path / "alias"
    link.symlink_to({"home": child, "profiles": child.parent, "root": root}[alias], target_is_directory=True)
    path = {"home": link, "profiles": link / "work", "root": link / "profiles/work"}[alias]
    with pytest.raises(DatabaseRefused), broker().database_key_mutation(root=path, generation=None):
        pytest.fail("alias admitted")


def test_child_source_binding_cannot_claim_root(tmp_path):
    child = tmp_path / "profiles/work"
    (child / "mordred").mkdir(parents=True, mode=0o700)
    (child / "mordred/db-key-source.json").write_bytes(b"untrusted root authority")
    with pytest.raises(DatabaseRefused), broker().database_key_mutation(root=child, generation=None):
        pytest.fail("child binding admitted")


def test_missing_root_is_not_created(tmp_path):
    root = tmp_path / "absent"
    with pytest.raises(DatabaseRefused), broker().database_key_mutation(root=root, generation=None):
        pytest.fail("missing root admitted")
    assert not root.exists()


def test_broker_imports_without_sql(tmp_path):
    script = """
import importlib.abc
import sys
class NoSQL(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if "dbcrypt" in fullname or fullname.startswith(("sqlcipher", "pysqlcipher")):
            raise AssertionError(fullname)
sys.meta_path.insert(0, NoSQL())
from mordred_hermes.keyvault._database_mutation import database_key_mutation
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_final_guard_rechecks_all_generations_after_preflight(tmp_path, monkeypatch):
    from mordred_hermes import _database_inventory as inventory

    with broker().database_key_mutation(root=tmp_path, generation="first") as lease:
        monkeypatch.setattr(
            inventory,
            "scan_dependencies",
            lambda root: Inventory((Dependency(root / "older.db", "database", "other"),), True),
        )
        with pytest.raises(DatabaseRefused):
            broker()._assert_memory_database_mutation_safe(home=tmp_path, database_lease=lease)


def test_custody_intent_precedes_mutex_wait(tmp_path, monkeypatch):
    from mordred_hermes.keyvault import _storage

    module = broker()
    observed = []

    class Mutex:
        def __enter__(self):
            with pytest.raises(DatabaseRefused), module.database_key_mutation(root=tmp_path, generation=None):
                pytest.fail("reverse acquisition in mutex callback")
            observed.append("refused")

        def __exit__(self, *args):
            pass

    (tmp_path / "mordred").mkdir(mode=0o700)
    monkeypatch.setattr(_storage, "_LIFECYCLE_THREAD_LOCK", Mutex())
    monkeypatch.setattr(module, "acquire_exclusive", lambda *a, **kw: pytest.fail("lock acquisition during wait"))
    with _storage.keyvault_lifecycle_lock(tmp_path / "mordred/keyvault"):
        pass
    assert observed == ["refused"]


def test_tracking_is_thread_local_and_cleans_up_on_error(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from mordred_hermes._custody_order import active_custody_scopes, custody_scope

    with pytest.raises(ValueError), custody_scope():
        assert active_custody_scopes()
        with ThreadPoolExecutor(1) as executor:
            assert executor.submit(active_custody_scopes).result() is False
        raise ValueError("exit")
    assert not active_custody_scopes()
    with broker().database_key_mutation(root=tmp_path, generation=None):
        pass


def test_registry_snapshot_does_not_check_native_or_filesystem(tmp_path, monkeypatch):
    from mordred_hermes._custody_order import assert_preceding_database_lease, custody_scope
    from mordred_hermes._database_lifecycle import current_thread_exclusive_leases

    with acquire_exclusive(tmp_path) as lease:

        def forbidden():
            pytest.fail("native check during custody observation")

        with monkeypatch.context() as patch:
            patch.setattr(lease._native, "check", forbidden)
            with custody_scope():
                assert current_thread_exclusive_leases() == (lease,)
                assert_preceding_database_lease(lease)


@pytest.mark.parametrize("unsafe", ["root", "profiles", "child"])
def test_unsafe_relationship_components_refuse(tmp_path, unsafe):
    root = tmp_path / "root"
    child = root / "profiles/work"
    child.mkdir(parents=True, mode=0o700)
    path = {"root": root, "profiles": child.parent, "child": child}[unsafe]
    path.chmod(0o777)
    with pytest.raises(DatabaseRefused), broker().database_key_mutation(root=child, generation=None):
        pytest.fail("unsafe owner relationship admitted")


def test_parent_replacement_during_acquisition_refuses(tmp_path, monkeypatch):
    child = tmp_path / "profiles/work"
    child.mkdir(parents=True, mode=0o700)
    module = broker()
    original = module.acquire_exclusive

    @contextlib.contextmanager
    def replaced(root):
        with original(root) as lease:
            child.parent.rename(tmp_path / "retained-profiles")
            child.mkdir(parents=True, mode=0o700)
            yield lease

    monkeypatch.setattr(module, "acquire_exclusive", replaced)
    with pytest.raises(DatabaseRefused), module.database_key_mutation(root=child, generation=None):
        pytest.fail("replaced profiles admitted")


def test_cross_thread_proof_refuses_without_native_check(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    with acquire_exclusive(tmp_path) as lease, ThreadPoolExecutor(1) as executor, pytest.raises(DatabaseRefused):
        executor.submit(broker()._assert_memory_database_mutation_safe, home=tmp_path, database_lease=lease).result()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork registry cleanup")
def test_fork_discards_inherited_custody_and_database_proof(tmp_path):
    from mordred_hermes._custody_order import active_custody_scopes, custody_scope
    from mordred_hermes._database_lifecycle import current_thread_exclusive_leases

    read_fd, write_fd = os.pipe()
    try:
        with acquire_exclusive(tmp_path) as lease, custody_scope():
            pid = os.fork()
            if pid == 0:
                try:
                    assert not active_custody_scopes()
                    assert not current_thread_exclusive_leases()
                    with pytest.raises(DatabaseRefused):
                        broker()._assert_memory_database_mutation_safe(home=tmp_path, database_lease=lease)
                    os.write(write_fd, b"clean")
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            assert os.read(read_fd, 5) == b"clean"
            assert active_custody_scopes()
            lease.assert_held(tmp_path)
    finally:
        os.close(read_fd)
        os.close(write_fd)
