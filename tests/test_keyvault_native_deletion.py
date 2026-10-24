"""Native deletion rejects unsupported callers before crossing native I/O."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import wrap
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps
from mordred_hermes.keyvault._seckey_ops import _PyobjcSecKeyOps, _SoftwareFallbackOps

_PUBLIC_KEY = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


def test_bare_backend_delete_never_reaches_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    ops = _HelperSecKeyOps("/not/executed")
    monkeypatch.setattr(ops, "_invoke", lambda payload: calls.append(payload) or {"ok": True})
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key("opaque-memory-selector")
    assert calls == []


@pytest.mark.parametrize("kind", ["helper", "pyobjc", "software"])
def test_bare_raw_ops_delete_never_reaches_native(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    if kind == "helper":
        ops = _HelperSecKeyOps("/not/executed")
        monkeypatch.setattr(ops, "_invoke", lambda payload: calls.append(payload) or {"ok": True})
    else:
        ops = _PyobjcSecKeyOps() if kind == "pyobjc" else _SoftwareFallbackOps()
        monkeypatch.setattr(ops, "_security", lambda: calls.append("security"))
    with pytest.raises(DatabaseRefused):
        ops.delete_key(b"opaque-tag")
    assert calls == []


def test_bare_wrap_rejects_even_custom_backend() -> None:
    class Backend:
        def __init__(self):
            self.calls = []

        def delete_enclave_key(self, key_id: str, **kwargs: object) -> None:
            self.calls.append(key_id)

    backend = Backend()
    with pytest.raises(DatabaseRefused):
        wrap.delete_wrapping_key("opaque-selector", backend=backend)
    assert backend.calls == []


def test_fabricated_owner_and_permit_refuse() -> None:
    from mordred_hermes.keyvault import _native_deletion as deletion

    backend = _SecKeyBackend(ops=_HelperSecKeyOps("/not/executed"), sw_ops=None)

    class FakeOwner:
        def _check_native_delete_owner(self, selector: str) -> object:
            return object()

    with pytest.raises(DatabaseRefused):
        deletion._issue_native_owner(FakeOwner(), native_key_id="key", backend=backend)
    for cls in (deletion.NativeDeletePermit, deletion.NativeCreateReceipt, deletion.ValidatedNativeOwner):
        with pytest.raises(DatabaseRefused):
            cls()
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key("key", deletion=object.__new__(deletion.NativeDeletePermit))


def test_create_receipt_rolls_back_only_winning_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.keyvault import _native_deletion as deletion
    from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecItemNotFound, errSecMissingEntitlement

    calls = []
    primary = _HelperSecKeyOps("/primary")
    software = _HelperSecKeyOps("/software")

    def invoke_primary(payload: dict) -> dict:
        if payload["cmd"] == "generate":
            raise _OpsError(errSecMissingEntitlement)
        raise AssertionError(payload)

    def invoke_sw(payload: dict) -> dict:
        calls.append(payload)
        if payload["cmd"] == "generate":
            return {"public_key_hex": _PUBLIC_KEY.hex()}
        if payload["cmd"] == "public_key":
            if not any(p["cmd"] == "generate" for p in calls):
                raise _OpsError(errSecItemNotFound)
            return {"public_key_hex": _PUBLIC_KEY.hex()}
        return {"ok": True}

    monkeypatch.setattr(primary, "_invoke", invoke_primary)
    monkeypatch.setattr(software, "_invoke", invoke_sw)
    backend = _SecKeyBackend(ops=primary, sw_ops=software)
    with wrap.create_wrapping_key_scope("key", backend=backend) as receipt:
        assert receipt.public_key == _PUBLIC_KEY
        deletion.rollback_created_key(receipt)
        with pytest.raises(DatabaseRefused):
            deletion.rollback_created_key(receipt)
    assert [p["cmd"] for p in calls] == ["public_key", "generate", "public_key", "delete"]


def test_owner_permit_consumes_once_and_closure_refuses(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from mordred_hermes.keyvault import _native_deletion as deletion

    calls = []
    ops = _HelperSecKeyOps("/fake")
    monkeypatch.setattr(ops, "_invoke", lambda payload: calls.append(payload) or {"ok": True})
    backend = _SecKeyBackend(ops=ops, sw_ops=None)
    # Fixed trusted producer seam is mocked; arbitrary duck-typed issuance is
    # separately rejected above. No native provider executes in these tests.
    facts = deletion._NativeOwnerFacts(home=tmp_path, role="audit")
    monkeypatch.setattr(deletion, "_checked_owner_facts", lambda scope, selector, backend: facts)
    owner = deletion._issue_native_owner(object(), native_key_id="audit", backend=backend)
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        backend.delete_enclave_key("audit", deletion=permit)
        with pytest.raises(DatabaseRefused):
            backend.delete_enclave_key("audit", deletion=permit)
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key("audit", deletion=permit)
    assert len(calls) == 1


# A fixed trusted producer seam for backend/transport unit tests. Genuine
# platform custody integration is exercised in its own containing modules.


@contextmanager
def checked_audit_permit(backend, selector):
    from mordred_hermes.keyvault import _native_deletion as deletion

    facts = deletion._NativeOwnerFacts(home=Path("/isolated-unit-owner"), role="audit")
    with patch.object(deletion, "_checked_owner_facts", lambda scope, key, supplied_backend: facts):
        owner = deletion._issue_native_owner(object(), native_key_id=selector, backend=backend)
        with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
            yield permit


def test_legacy_read_adapter_keeps_delete_on_checked_primary(monkeypatch, tmp_path):
    from mordred_hermes.keyvault import _native_deletion as deletion
    from mordred_hermes.keyvault._native_key_id import _LegacyReadFallbackBackend

    calls = []
    primary_ops = _HelperSecKeyOps("/isolated-primary")
    fallback_ops = _HelperSecKeyOps("/isolated-fallback")
    monkeypatch.setattr(primary_ops, "_invoke", lambda payload: calls.append("primary") or {"ok": True})
    monkeypatch.setattr(fallback_ops, "_invoke", lambda payload: calls.append("fallback") or {"ok": True})
    primary = _SecKeyBackend(ops=primary_ops, sw_ops=None)
    fallback = _SecKeyBackend(ops=fallback_ops, sw_ops=None)
    adapter = _LegacyReadFallbackBackend(primary, fallback)
    with pytest.raises(DatabaseRefused):
        adapter.delete_enclave_key("audit", deletion=None)
    assert calls == []
    facts = deletion._NativeOwnerFacts(home=tmp_path, role="audit")
    monkeypatch.setattr(deletion, "_checked_owner_facts", lambda scope, selector, backend: facts)
    owner = deletion._issue_native_owner(object(), native_key_id="audit", backend=primary)
    with deletion._owned_delete_scope(owner, backend=primary, database_lease=None) as permit:
        adapter.delete_enclave_key("audit", deletion=permit)
    assert calls == ["primary"]


@pytest.fixture
def owned_native(monkeypatch: pytest.MonkeyPatch, tmp_path):
    from mordred_hermes.keyvault import _native_deletion as deletion
    from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecItemNotFound

    calls = []
    keys = {}
    active = [True]
    facts = [deletion._NativeOwnerFacts(home=tmp_path, role="audit")]
    ops = _HelperSecKeyOps("/isolated-fake")

    def invoke(payload):
        calls.append(payload["cmd"])
        if payload["cmd"] == "generate":
            keys[payload["tag_hex"]] = _PUBLIC_KEY
            return {"public_key_hex": keys[payload["tag_hex"]].hex()}
        if payload["cmd"] == "public_key":
            if payload["tag_hex"] not in keys:
                raise _OpsError(errSecItemNotFound)
            return {"public_key_hex": keys[payload["tag_hex"]].hex()}
        keys.pop(payload["tag_hex"], None)
        return {"ok": True}

    monkeypatch.setattr(ops, "_invoke", invoke)
    backend = _SecKeyBackend(ops=ops, sw_ops=None)

    def checked(scope, selector, supplied_backend):
        if not active[0]:
            raise DatabaseRefused("custody closed")
        return facts[0]

    monkeypatch.setattr(deletion, "_checked_owner_facts", checked)
    owner = deletion._issue_native_owner(object(), native_key_id="audit", backend=backend)
    return deletion, backend, owner, calls, keys, active, facts


@pytest.mark.parametrize("mismatch", ["selector", "backend", "store", "owner", "generation", "thread", "pid"])
def test_owner_mismatch_refuses_before_io_and_consumes(owned_native, monkeypatch, mismatch):
    import threading
    from dataclasses import replace

    deletion, backend, owner, calls, _keys, active, facts = owned_native
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        selector = "audit"
        target = backend
        if mismatch == "selector":
            selector = "memory"
        elif mismatch == "backend":
            target = _SecKeyBackend(ops=backend._ops, sw_ops=None)
        elif mismatch == "store":
            monkeypatch.setenv("MORDRED_TPMKEY_STORE", "/different-store")
        elif mismatch == "owner":
            active[0] = False
        elif mismatch == "generation":
            facts[0] = replace(facts[0], generation="f" * 64)
        elif mismatch == "pid":
            monkeypatch.setattr(deletion.os, "getpid", lambda: -1)
        if mismatch == "thread":
            errors = []

            def attempt():
                try:
                    target.delete_enclave_key(selector, deletion=permit)
                except DatabaseRefused:
                    errors.append("refused")

            thread = threading.Thread(target=attempt)
            thread.start()
            thread.join()
            assert errors == ["refused"]
        else:
            with pytest.raises(DatabaseRefused):
                target.delete_enclave_key(selector, deletion=permit)
        with pytest.raises(DatabaseRefused):
            backend.delete_enclave_key("audit", deletion=permit)
    assert calls == []


def test_native_error_consumes_permit(owned_native, monkeypatch):
    from mordred_hermes.keyvault._exceptions import WrapError
    from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecAuthFailed

    deletion, backend, owner, calls, *_ = owned_native

    def fail(payload):
        calls.append(payload["cmd"])
        raise _OpsError(errSecAuthFailed)

    monkeypatch.setattr(backend._ops, "_invoke", fail)
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        with pytest.raises(WrapError):
            backend.delete_enclave_key("audit", deletion=permit)
        with pytest.raises(DatabaseRefused):
            backend.delete_enclave_key("audit", deletion=permit)
    assert calls == ["delete"]


@pytest.mark.parametrize("method", ["copy", "deepcopy", "pickle", "fabricate", "subclass"])
def test_permit_cannot_be_reconstituted(owned_native, method):
    import copy
    import pickle

    deletion, backend, owner, calls, *_ = owned_native
    with (
        deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit,
        pytest.raises(DatabaseRefused),
    ):
        if method == "copy":
            copy.copy(permit)
        elif method == "deepcopy":
            copy.deepcopy(permit)
        elif method == "pickle":
            pickle.dumps(permit)
        else:
            cls = deletion.NativeDeletePermit
            if method == "subclass":

                class SubPermit(cls):
                    pass

                cls = SubPermit
            backend.delete_enclave_key("audit", deletion=object.__new__(cls))
    assert calls == []


@pytest.mark.parametrize("end", ["commit", "expiry", "fingerprint", "store", "backend"])
def test_receipt_expiry_or_substitution_never_deletes(owned_native, monkeypatch, end):
    deletion, backend, _owner, calls, keys, *_ = owned_native
    with deletion.create_wrapping_key_scope("fresh", backend=backend) as receipt:
        if end == "commit":
            deletion.commit_created_key(receipt)
        elif end == "fingerprint":
            tag = next(iter(keys))
            keys[tag] = b"substituted"
        elif end == "store":
            monkeypatch.setenv("MORDRED_TPMKEY_STORE", "/other")
        elif end == "backend":
            backend._ops = _HelperSecKeyOps("/other")
        if end != "expiry":
            with pytest.raises(DatabaseRefused):
                deletion.rollback_created_key(receipt)
    with pytest.raises(DatabaseRefused):
        deletion.rollback_created_key(receipt)
    assert "delete" not in calls
    assert keys


@pytest.mark.parametrize("error", ["duplicate", "lost-response"])
def test_create_failure_has_no_receipt_or_cleanup(owned_native, monkeypatch, error):
    from mordred_hermes.keyvault._exceptions import WrapError
    from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecDuplicateItem

    deletion, backend, _owner, calls, *_ = owned_native

    def fail(payload):
        calls.append(payload["cmd"])
        raise _OpsError(errSecDuplicateItem if error == "duplicate" else -1)

    monkeypatch.setattr(backend._ops, "_invoke", fail)
    entered = False
    with pytest.raises(WrapError), deletion.create_wrapping_key_scope("key", backend=backend):
        entered = True
    assert not entered
    assert calls == ["generate"]


def test_owner_requires_final_database_guard_before_delete(owned_native, monkeypatch):
    import sys
    from dataclasses import replace
    from types import SimpleNamespace

    deletion, backend, _owner, calls, _keys, _active, facts = owned_native
    facts[0] = replace(facts[0], role="memory", database_home=facts[0].home)
    owner = deletion._issue_native_owner(object(), native_key_id="audit", backend=backend)
    with pytest.raises(DatabaseRefused), deletion._owned_delete_scope(owner, backend=backend, database_lease=None):
        pytest.fail("missing lease entered")
    guarded = []

    def guard(*, home, database_lease):
        guarded.append(home)
        if len(guarded) == 2:
            raise DatabaseRefused("dependency appeared")

    monkeypatch.setitem(
        sys.modules, "mordred_hermes._database_mutation", SimpleNamespace(_assert_memory_database_mutation_safe=guard)
    )
    with (
        deletion._owned_delete_scope(owner, backend=backend, database_lease=object()) as permit,
        pytest.raises(DatabaseRefused),
    ):
        backend.delete_enclave_key("audit", deletion=permit)
    assert guarded == [facts[0].home, facts[0].home]
    assert calls == []


def test_checked_ownership_handoff_revokes_creation_rollback(owned_native):
    deletion, backend, _owner, calls, keys, *_ = owned_native
    with deletion.create_wrapping_key_scope("fresh", backend=backend) as receipt:
        deletion._issue_native_owner(object(), native_key_id="fresh", backend=backend)
        with pytest.raises(DatabaseRefused):
            deletion.rollback_created_key(receipt)
    assert "delete" not in calls
    assert keys


def test_store_change_during_create_retains_key_without_receipt(owned_native, monkeypatch):
    deletion, backend, _owner, calls, keys, *_ = owned_native
    original = backend._ops._invoke

    def changed(payload):
        result = original(payload)
        if payload["cmd"] == "generate":
            monkeypatch.setenv("MORDRED_TPMKEY_STORE", "/changed-during-create")
        return result

    monkeypatch.setattr(backend._ops, "_invoke", changed)
    with pytest.raises(DatabaseRefused), deletion.create_wrapping_key_scope("fresh", backend=backend):
        pytest.fail("changed store issued a receipt")
    assert calls == ["generate"]
    assert keys


def test_replaced_checked_home_refuses_before_native_io(owned_native, tmp_path):
    deletion, backend, owner, calls, _keys, _active, _facts = owned_native
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        moved = tmp_path.with_name(tmp_path.name + "-old")
        tmp_path.rename(moved)
        tmp_path.mkdir()
        with pytest.raises(DatabaseRefused):
            backend.delete_enclave_key("audit", deletion=permit)
    assert calls == []


@pytest.mark.parametrize("kind", ["pyobjc", "software"])
def test_python_probe_cleanup_is_fresh_exact_namespace_only(kind, monkeypatch):
    from types import SimpleNamespace

    from mordred_hermes.keyvault import _seckey_ops

    cls = _PyobjcSecKeyOps if kind == "pyobjc" else _SoftwareFallbackOps
    keys = {b"existing-managed-key": b"existing-public"}
    deleted = []

    def create(self, tag, label, *, unattended):
        assert tag not in keys
        keys[tag] = _PUBLIC_KEY
        return keys[tag]

    def remove(query):
        tag = query["tag"]
        deleted.append(tag)
        del keys[tag]
        return 0

    monkeypatch.setattr(cls, "create_keypair", create)
    monkeypatch.setattr(cls, "copy_public_key", lambda self, tag: keys[tag])
    monkeypatch.setattr(cls, "_security", lambda self: SimpleNamespace(SecItemDelete=remove))
    query = "_keychain_query" if kind == "pyobjc" else "_sw_keychain_query"
    monkeypatch.setattr(_seckey_ops, query, lambda sec, tag: {"tag": tag})
    cls().probe()
    assert len(deleted) == 1
    assert deleted[0] != b"existing-managed-key"
    assert keys == {b"existing-managed-key": b"existing-public"}


def test_probe_creation_failure_cannot_delete_existing_key(monkeypatch):
    from mordred_hermes.keyvault._seckey_errors import _OpsError, errSecDuplicateItem

    calls = []

    def duplicate(self, tag, label, *, unattended):
        raise _OpsError(errSecDuplicateItem)

    monkeypatch.setattr(_PyobjcSecKeyOps, "create_keypair", duplicate)
    monkeypatch.setattr(_PyobjcSecKeyOps, "_security", lambda self: calls.append("native"))
    with pytest.raises(_OpsError):
        _PyobjcSecKeyOps().probe()
    assert calls == []


def test_unused_permission_expires_at_delete_scope_exit(owned_native):
    deletion, backend, owner, calls, *_ = owned_native
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        pass
    with pytest.raises(DatabaseRefused):
        backend.delete_enclave_key("audit", deletion=permit)
    assert calls == []


def test_refused_wrapper_invocation_consumes_permit(owned_native):
    deletion, backend, owner, calls, *_ = owned_native
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        with pytest.raises(DatabaseRefused):
            wrap.delete_wrapping_key("memory", backend=backend, deletion=permit)
        with pytest.raises(DatabaseRefused):
            wrap.delete_wrapping_key("audit", backend=backend, deletion=permit)
    assert calls == []


def test_forked_permission_refuses_without_native_io(owned_native):
    import os

    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    deletion, backend, owner, calls, *_ = owned_native
    with deletion._owned_delete_scope(owner, backend=backend, database_lease=None) as permit:
        child = os.fork()
        if child == 0:
            try:
                backend.delete_enclave_key("audit", deletion=permit)
            except DatabaseRefused:
                os._exit(0 if calls == [] else 2)
            except BaseException:
                os._exit(3)
            os._exit(4)
        waited, status = os.waitpid(child, 0)
        assert waited == child
        assert os.waitstatus_to_exitcode(status) == 0
    assert calls == []


def test_malformed_create_public_key_never_issues_receipt(owned_native, monkeypatch):
    from mordred_hermes.keyvault._exceptions import WrapError

    deletion, backend, _owner, calls, keys, *_ = owned_native
    original = backend._ops._invoke

    def malformed(payload):
        result = original(payload)
        if payload["cmd"] == "generate":
            return {"public_key_hex": ""}
        return result

    monkeypatch.setattr(backend._ops, "_invoke", malformed)
    with pytest.raises(WrapError), deletion.create_wrapping_key_scope("fresh", backend=backend):
        pytest.fail("malformed create result issued a receipt")
    assert "delete" not in calls
    assert keys


def test_capability_import_has_no_sql_or_native_initialization():
    import subprocess
    import sys

    script = """
import importlib.abc
import sys
class RejectSql(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blocked = ('dbcrypt', 'sqlcipher', 'sqlite', '_seckey_backend', '_seckey_helper', '_seckey_ops')
        if any(part in fullname for part in blocked):
            raise RuntimeError('forbidden import: ' + fullname)
sys.meta_path.insert(0, RejectSql())
import mordred_hermes.keyvault._native_deletion
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
