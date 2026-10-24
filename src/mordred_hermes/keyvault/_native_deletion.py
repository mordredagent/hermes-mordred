"""Issuer-backed native deletion authority, without SQL or native imports.

This is an API misuse boundary, not a sandbox against replacing module internals.
Object fields alone never convey authority: only live registered identities do.
"""

from __future__ import annotations

import importlib
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Never, cast
from weakref import WeakKeyDictionary

from mordred_hermes._database_contracts import DatabaseRefused

if TYPE_CHECKING:
    from mordred_hermes._database_lifecycle import ExclusiveLease

    from ._seckey_ops import _SecKeyOps
    from .wrap import NativeBackend


class _OpaqueAuthority:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> _OpaqueAuthority:
        raise DatabaseRefused("native deletion authority cannot be constructed")

    def __copy__(self) -> None:
        raise DatabaseRefused("native deletion authority cannot be copied")

    def __deepcopy__(self, memo: object) -> None:
        raise DatabaseRefused("native deletion authority cannot be copied")

    def __reduce__(self) -> Never:
        raise DatabaseRefused("native deletion authority cannot be serialized")


class NativeDeletePermit(_OpaqueAuthority):
    """Opaque single-invocation authority issued under checked custody."""

    __slots__ = ()


class ValidatedNativeOwner(_OpaqueAuthority):
    """Opaque ownership from a fixed in-tree custody implementation."""

    __slots__ = ()


class NativeCreateReceipt(_OpaqueAuthority):
    """A positive create-only result, valid only in its creating scope."""

    __slots__ = ()

    @property
    def public_key(self) -> bytes:
        return _receipt_record(self).public_key


@dataclass(frozen=True)
class _NativeOwnerFacts:
    home: Path
    role: Literal["memory", "vault", "main", "audit", "telegram"]
    generation: str | None = None
    database_home: Path | None = None


@dataclass
class _OwnerRecord:
    scope: object
    selector: str
    backend: NativeBackend
    facts: _NativeOwnerFacts
    home_identity: tuple[object, ...]
    binding: tuple[object, ...]
    process: tuple[int, int]


@dataclass
class _PermitRecord:
    owner: ValidatedNativeOwner
    lease: ExclusiveLease | None
    active: bool = True
    consumed: bool = False


@dataclass
class _ReceiptRecord:
    backend: NativeBackend | None
    binding: tuple[object, ...]
    ops: _SecKeyOps
    tag: bytes
    public_key: bytes
    process: tuple[int, int]
    active: bool = True
    consumed: bool = False


@dataclass
class _Invocation:
    pairs: list[tuple[object, bytes, tuple[object, ...]]]
    process: tuple[int, int]


_owners: WeakKeyDictionary[ValidatedNativeOwner, _OwnerRecord] = WeakKeyDictionary()
_permits: WeakKeyDictionary[NativeDeletePermit, _PermitRecord] = WeakKeyDictionary()
_receipts: WeakKeyDictionary[NativeCreateReceipt, _ReceiptRecord] = WeakKeyDictionary()
_invocations = threading.local()


def _process() -> tuple[int, int]:
    return os.getpid(), threading.get_ident()


def _path_identity(value: str) -> tuple[object, ...]:
    path = Path(value).absolute()
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return (os.fspath(path), None)
    except OSError as exc:
        raise DatabaseRefused("native owner/store identity cannot be checked") from exc
    try:
        target = path.stat()
    except FileNotFoundError:
        target_identity = None
    except OSError as exc:
        raise DatabaseRefused("native owner/store target cannot be checked") from exc
    else:
        target_identity = (target.st_dev, target.st_ino, target.st_mode, target.st_uid)
    return (os.fspath(path), stat.st_dev, stat.st_ino, stat.st_mode, stat.st_uid, target_identity)


def _ops_configuration(ops: object) -> tuple[object, ...]:
    from ._seckey_helper import _HelperSecKeyOps

    if isinstance(ops, _HelperSecKeyOps):
        override = ops._env_override
        stores = tuple(
            (
                name,
                os.fspath(
                    Path(override[1] if override and override[0] == name else os.environ.get(name, "")).absolute()
                ),
            )
            for name in ("MORDRED_SEKEY_STORE", "MORDRED_TPMKEY_STORE")
        )
        return (
            id(ops),
            _path_identity(ops._binary),
            override,
            os.environ.get("HERMES_HOME"),
            os.fspath(Path.home()),
            stores,
        )
    return (id(ops),)


def _ops_binding(ops: object) -> tuple[object, ...]:
    configuration = _ops_configuration(ops)
    from ._seckey_helper import _HelperSecKeyOps

    if isinstance(ops, _HelperSecKeyOps):
        override = ops._env_override
        stores = tuple(
            (name, _path_identity(override[1] if override and override[0] == name else os.environ.get(name, "")))
            for name in ("MORDRED_SEKEY_STORE", "MORDRED_TPMKEY_STORE")
        )
        return (configuration, stores)
    return (configuration,)


def _backend_pairs(backend: NativeBackend, selector: str) -> tuple[tuple[_SecKeyOps, bytes], ...]:
    from ._seckey_backend import _SecKeyBackend
    from ._seckey_errors import _application_tag, _sw_application_tag

    if type(backend) is not _SecKeyBackend:
        raise DatabaseRefused("native deletion requires the trusted production backend")
    pairs = [(backend._ops, _application_tag(selector))]
    if backend._legacy_ops is not None and backend._legacy_ops is not backend._ops:
        pairs.append((backend._legacy_ops, _application_tag(selector)))
    if backend._sw_ops is not None:
        pairs.append((backend._sw_ops, _sw_application_tag(selector)))
    return tuple(pairs)


def _backend_binding(backend: NativeBackend, selector: str) -> tuple[object, ...]:
    return (id(backend), tuple((_ops_binding(ops), tag) for ops, tag in _backend_pairs(backend, selector)))


def _checked_owner_facts(scope: object, selector: str, backend: NativeBackend) -> _NativeOwnerFacts:
    # Fixed concrete classes only. Never invoke an arbitrary instance override.
    adapters = (
        ("._memory_key", "MemoryKeyCustody"),
        ("._storage", "KeyvaultCustody"),
        ("._windows_custody", "WindowsCustodySession"),
        (".vault", "OpenVault"),
    )
    for module_name, name in adapters:
        module = importlib.import_module(module_name, __package__)
        cls = getattr(module, name, None)
        if cls is not None and type(scope) is cls:
            method = getattr(cls, "_check_native_delete_owner", None)
            if method is None:
                break
            facts = method(scope, selector, backend)
            if type(facts) is _NativeOwnerFacts:
                return facts
            break
    raise DatabaseRefused("native owner is not a live supported custody scope")


def _issue_native_owner(scope: object, *, native_key_id: str, backend: NativeBackend) -> ValidatedNativeOwner:
    facts = _checked_owner_facts(scope, native_key_id, backend)
    owner = object.__new__(ValidatedNativeOwner)
    _owners[owner] = _OwnerRecord(
        scope,
        native_key_id,
        backend,
        facts,
        _path_identity(os.fspath(facts.home)),
        _backend_binding(backend, native_key_id),
        _process(),
    )
    # Successful checked ownership handoff ends unpublished-key rollback rights.
    pairs = _backend_pairs(backend, native_key_id)
    for receipt in list(_receipts.values()):
        if receipt.active and any(receipt.ops is ops and receipt.tag == tag for ops, tag in pairs):
            receipt.consumed = True
    return owner


def _owner_record(owner: ValidatedNativeOwner, backend: NativeBackend) -> _OwnerRecord:
    record = _owners.get(owner) if type(owner) is ValidatedNativeOwner else None
    if record is None or record.process != _process() or record.backend is not backend:
        raise DatabaseRefused("native owner is invalid for this process or backend")
    if record.home_identity != _path_identity(os.fspath(record.facts.home)):
        raise DatabaseRefused("native owner home changed")
    if record.binding != _backend_binding(backend, record.selector):
        raise DatabaseRefused("native backend or store changed")
    if _checked_owner_facts(record.scope, record.selector, backend) != record.facts:
        raise DatabaseRefused("native custody ownership changed")
    return record


def _check_database(record: _OwnerRecord, lease: ExclusiveLease | None) -> None:
    if record.facts.role == "memory" and record.facts.database_home != record.facts.home:
        raise DatabaseRefused("native memory owner lacks its checked database home")
    if record.facts.database_home is not None:
        if lease is None:
            raise DatabaseRefused("native memory deletion requires a preceding database lease")
        from ._database_mutation import _assert_memory_database_mutation_safe

        _assert_memory_database_mutation_safe(home=record.facts.database_home, database_lease=lease)


@contextmanager
def _owned_delete_scope(
    owner: ValidatedNativeOwner, *, backend: NativeBackend, database_lease: ExclusiveLease | None
) -> Iterator[NativeDeletePermit]:
    record = _owner_record(owner, backend)
    _check_database(record, database_lease)
    permit = object.__new__(NativeDeletePermit)
    issued = _PermitRecord(owner, database_lease)
    _permits[permit] = issued
    try:
        yield permit
    finally:
        issued.active = False


def _require_delete_permit(deletion: NativeDeletePermit | None) -> _PermitRecord:
    record = _permits.get(deletion) if type(deletion) is NativeDeletePermit else None
    if record is None or not record.active or record.consumed:
        raise DatabaseRefused("native deletion requires live checked ownership")
    return record


def _check_delete_request(*, backend: NativeBackend, native_key_id: str, deletion: NativeDeletePermit | None) -> None:
    permit = _require_delete_permit(deletion)
    try:
        owner = _owner_record(permit.owner, backend)
        if native_key_id != owner.selector:
            raise DatabaseRefused("native deletion selector does not match custody")
        _check_database(owner, permit.lease)
    except BaseException:
        permit.consumed = True
        raise


@contextmanager
def _tag_invocation(pairs: tuple[tuple[_SecKeyOps, bytes], ...]) -> Iterator[None]:
    invocation = _Invocation([(ops, tag, _ops_binding(ops)) for ops, tag in pairs], _process())
    stack = getattr(_invocations, "stack", None)
    if stack is None:
        stack = []
        _invocations.stack = stack
    stack.append(invocation)
    try:
        yield
    finally:
        stack.pop()


@contextmanager
def _validate_delete_invocation(
    *, backend: NativeBackend, native_key_id: str, deletion: NativeDeletePermit | None
) -> Iterator[None]:
    permit = _require_delete_permit(deletion)
    # Every attempted invocation consumes authority, including failed validation.
    permit.consumed = True
    owner = _owner_record(permit.owner, backend)
    if native_key_id != owner.selector:
        raise DatabaseRefused("native deletion selector does not match custody")
    _check_database(owner, permit.lease)
    with _tag_invocation(_backend_pairs(backend, native_key_id)):
        yield


def _assert_native_tag_delete(*, ops: object, tag: bytes) -> None:
    stack = getattr(_invocations, "stack", [])
    if stack:
        invocation = stack[-1]
        if invocation.process == _process():
            for index, (allowed, allowed_tag, binding) in enumerate(invocation.pairs):
                if allowed is ops and allowed_tag == tag and binding == _ops_binding(ops):
                    invocation.pairs.pop(index)
                    return
    raise DatabaseRefused("raw native deletion requires an active exact-tag invocation")


def _receipt_record(receipt: NativeCreateReceipt) -> _ReceiptRecord:
    record = _receipts.get(receipt) if type(receipt) is NativeCreateReceipt else None
    if record is None or not record.active or record.consumed or record.process != _process():
        raise DatabaseRefused("native creation receipt is expired or consumed")
    return record


@contextmanager
def create_wrapping_key_scope(
    key_id: str, *, backend: NativeBackend, unattended: bool | None = None, native_key_id: str | None = None
) -> Iterator[NativeCreateReceipt]:
    from ._seckey_backend import _SecKeyBackend
    from .wrap import _decode_sec1_uncompressed_p256

    selector = key_id if native_key_id is None else native_key_id
    pairs = _backend_pairs(backend, selector)
    configuration = tuple((_ops_configuration(ops), tag) for ops, tag in pairs)
    if type(backend) is not _SecKeyBackend:
        raise DatabaseRefused("creation receipts require the trusted create-only backend")
    public_key, ops, tag = _SecKeyBackend._create_tracked_key(backend, selector, unattended=unattended)
    if configuration != tuple((_ops_configuration(ops), tag) for ops, tag in _backend_pairs(backend, selector)):
        raise DatabaseRefused("native backend or store changed during create")
    _decode_sec1_uncompressed_p256(public_key)
    backend_binding = _backend_binding(backend, selector)
    receipt = object.__new__(NativeCreateReceipt)
    record = _ReceiptRecord(backend, (_ops_binding(ops), selector, backend_binding), ops, tag, public_key, _process())
    _receipts[receipt] = record
    try:
        yield receipt
    finally:
        record.active = False


def _probe_native_ops(ops: _SecKeyOps) -> None:
    # Only these concrete create-only implementations can issue probe receipts.
    from ._seckey_errors import _PROBE_TAG_PREFIX, _SW_TAG_PREFIX, _OpsError
    from ._seckey_ops import _PyobjcSecKeyOps, _SoftwareFallbackOps
    from .wrap import _decode_sec1_uncompressed_p256

    if type(ops) not in (_PyobjcSecKeyOps, _SoftwareFallbackOps):
        raise DatabaseRefused("unsupported native probe implementation")
    prefix = _SW_TAG_PREFIX if type(ops) is _SoftwareFallbackOps else _PROBE_TAG_PREFIX
    tag = prefix + b"__probe__." + os.urandom(16)
    public_key = ops.create_keypair(tag, "Mordred capability probe", unattended=True)
    _decode_sec1_uncompressed_p256(public_key)
    receipt = object.__new__(NativeCreateReceipt)
    record = _ReceiptRecord(None, (_ops_binding(ops),), ops, tag, public_key, _process())
    _receipts[receipt] = record
    try:
        # A successful probe retains its historical cleanup-failure policy.
        with suppress(_OpsError):
            rollback_created_key(receipt)
    finally:
        record.active = False


def rollback_created_key(receipt: NativeCreateReceipt) -> None:
    record = _receipt_record(receipt)
    record.consumed = True
    if record.binding[0] != _ops_binding(record.ops):
        raise DatabaseRefused("created native key store changed")
    if record.backend is not None and record.binding[2] != _backend_binding(
        record.backend, cast(str, record.binding[1])
    ):
        raise DatabaseRefused("created native backend changed")
    if record.ops.copy_public_key(record.tag) != record.public_key:
        raise DatabaseRefused("created native public key changed")
    with _tag_invocation(((record.ops, record.tag),)):
        record.ops.delete_key(record.tag)


def commit_created_key(receipt: NativeCreateReceipt) -> None:
    _receipt_record(receipt).consumed = True


def _after_fork() -> None:
    _owners.clear()
    _permits.clear()
    _receipts.clear()
    _invocations.__dict__.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
