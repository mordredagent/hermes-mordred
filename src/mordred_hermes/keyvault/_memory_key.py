"""Linux memory-key custody. TPM only; no file vault, ambient fallback or cache."""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import os
import secrets
import stat
import tempfile
import threading
import time
import weakref
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from .._custody_order import custody_scope
from .._database_contracts import DatabaseBusy, DatabaseRefused
from .._database_lifecycle import ExclusiveLease
from . import _storage, wrap
from ._exceptions import WrapError, WrapKeyNotFound
from ._native_deletion import _issue_native_owner, _NativeOwnerFacts, _owned_delete_scope
from .memory_crypto import MemoryCryptoError, decode_key, looks_like_magic_line, unseal
from .wrap import NativeBackend

MEMORY_KEY_PROVIDER_VERSION = 1


class MemoryKeyError(DatabaseRefused):
    """Custody failed; callers must preserve ciphertext and refuse access."""


@contextlib.contextmanager
def _memory_failure() -> Iterator[None]:
    try:
        yield
    except MemoryKeyError:
        raise
    except (DatabaseRefused, OSError) as exc:
        raise MemoryKeyError("TPM memory custody refused; existing data was preserved") from exc


@dataclass(frozen=True)
class _MemoryOwnerRecord:
    home: Path
    backend: NativeBackend
    pid: int
    thread: int
    wrapper: bytes
    identity: tuple[int, int]


_memory_owners: weakref.WeakKeyDictionary[MemoryKeyCustody, _MemoryOwnerRecord] = weakref.WeakKeyDictionary()


class MemoryKeyCustody:
    """Opaque live checked ownership, created only inside the real memory lock."""

    def __new__(cls) -> MemoryKeyCustody:
        raise TypeError("memory custody is issued only by a checked transaction")

    def _check_native_delete_owner(self, native_key_id: str, backend: NativeBackend) -> _NativeOwnerFacts:
        record = _memory_owners.get(self)
        if (
            record is None
            or record.pid != os.getpid()
            or record.thread != threading.get_ident()
            or record.backend is not backend
            or native_key_id != memory_key_id(record.home)
        ):
            raise DatabaseRefused("memory native ownership is no longer held")
        try:
            _storage.assert_advisory_lock_held(record.home / "mordred" / "memory-key.lock")
        except OSError as exc:
            raise DatabaseRefused("memory native ownership requires its live custody lock") from exc
        path = memory_key_path(record.home)
        observed = path.lstat()
        if (observed.st_dev, observed.st_ino) != record.identity or _storage.safe_read(path) != record.wrapper:
            raise DatabaseRefused("memory wrapping record changed")
        wrap._parse_header(record.wrapper, native_key_id)
        return _NativeOwnerFacts(home=record.home, role="memory", database_home=record.home)


@contextlib.contextmanager
def _native_memory_custody(home: Path, backend: NativeBackend) -> Iterator[MemoryKeyCustody]:
    from ._database_authority import resolve_database_domain
    from ._seckey_backend import _SecKeyBackend
    from ._seckey_helper import _HelperSecKeyOps

    home = resolve_database_domain(home).home
    if type(backend) is not _SecKeyBackend or backend._sw_ops is not None or backend._legacy_ops is not None:
        raise DatabaseRefused("Linux memory requires its native-only backend")
    if isinstance(backend._ops, _HelperSecKeyOps) and backend._ops._env_override != (
        "MORDRED_TPMKEY_STORE",
        os.fspath(home / "mordred" / "keyvault" / "tpm"),
    ):
        raise DatabaseRefused("memory native backend belongs to another store")
    _private_parent(home)
    path = memory_key_path(home)
    blob = _storage.safe_read(path)
    observed = path.lstat()
    scope = object.__new__(MemoryKeyCustody)
    _memory_owners[scope] = _MemoryOwnerRecord(
        home, backend, os.getpid(), threading.get_ident(), blob, (observed.st_dev, observed.st_ino)
    )
    try:
        MemoryKeyCustody._check_native_delete_owner(scope, memory_key_id(home), backend)
        yield scope
    finally:
        _memory_owners.pop(scope, None)


def memory_key_path(home: Path) -> Path:
    return home / "mordred" / "memory-key.wrapped"


def memory_key_id(home: Path) -> str:
    return "mordred-hermes.memory.v1." + hashlib.sha256(str(home.resolve()).encode()).hexdigest()[:16]


def linux_memory_backend(home: Path) -> NativeBackend:
    from . import _seckey_helper
    from ._seckey_backend import _SecKeyBackend

    ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_tpmkey_helper)
    if ops is None:
        raise MemoryKeyError("TPM helper unavailable; run `hermes-mordred keyvault enable-tpm`")
    # Explicit binding overrides ambient store selection: this key belongs to home.
    ops = ops.with_store_override("MORDRED_TPMKEY_STORE", home / "mordred" / "keyvault" / "tpm")
    return _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)


def _private_parent(home: Path, *, create: bool = False) -> Path:
    parent = memory_key_path(home).parent
    if create:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        # Provisioning holds memory_key_lock, which has validated this directory.
        if stat.S_IMODE(parent.lstat().st_mode) != 0o700:
            parent.chmod(0o700)
    _storage._check_dir_mode(parent)
    return parent


@contextlib.contextmanager
def memory_key_lock(home: Path) -> Iterator[None]:
    """Serialize provisioning and lifecycle operations within a profile."""
    with custody_scope(), _memory_key_lock(home):
        yield


@contextlib.contextmanager
def _memory_key_lock(home: Path) -> Iterator[None]:
    try:
        parent = memory_key_path(home).parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        mode = parent.lstat().st_mode
        # A lock contains no secret. Ordinary plaintext profiles may have a
        # 0755 parent; custody itself still requires exactly 0700.
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o022:
            raise MemoryKeyError("unsafe memory lock directory")
        path = parent / "memory-key.lock"
        _storage.ensure_lock_file(path)
        with _storage._advisory_file_lock(path, label="memory key"):
            yield
    except (OSError, ValueError, WrapError) as exc:
        raise MemoryKeyError("TPM memory key unavailable or invalid; existing data was not replaced") from exc


def _load(home: Path, backend: NativeBackend) -> bytes:
    _private_parent(home)
    blob = _storage.safe_read(memory_key_path(home))
    return wrap.unwrap_dek(blob, memory_key_id(home), backend=backend, audit_sink=lambda entry: None)


def load_linux_memory_key(*, home: Path, backend: NativeBackend | None = None) -> bytes:
    try:
        return _load(home, backend if backend is not None else linux_memory_backend(home))
    except (OSError, ValueError, WrapError) as exc:
        raise MemoryKeyError("TPM memory key unavailable or invalid; restore access to the original TPM") from exc


def linux_memory_managed(home: Path) -> bool:
    parent = memory_key_path(home).parent
    return any(
        path.exists() or path.is_symlink()
        for path in (memory_key_path(home), parent / "memory-vault.marker", parent / "memory-vault.optout")
    )


def linux_memory_files(home: Path) -> list[Path]:
    """Enumerate completely or refuse; glob suppresses permission/I/O failures."""
    memories = home / "memories"
    try:
        mode = memories.lstat().st_mode
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(mode):
        raise MemoryKeyError("refusing a non-directory or symlinked memory directory")
    paths = []
    for path in memories.iterdir():
        if not (fnmatch.fnmatchcase(path.name, "*.md") or fnmatch.fnmatchcase(path.name, "*.md.bak.*")):
            continue
        if not stat.S_ISREG(path.lstat().st_mode):
            raise MemoryKeyError("refusing a non-regular memory file")
        paths.append(path)
    return sorted(paths)


def _validate_adoption(home: Path, key: bytes | None) -> None:
    """Authenticate all existing seals before accepting an explicitly supplied key."""
    if key is not None and len(key) != 32:
        raise MemoryKeyError("memory key must be 32 bytes")
    for path in linux_memory_files(home):
        data = path.read_bytes()
        if looks_like_magic_line(data.decode("utf-8", "surrogateescape")):
            if key is None:
                raise MemoryKeyError("sealed memory exists; explicit authenticated key adoption is required")
            try:
                unseal(data, key=key, name=path.name)
            except MemoryCryptoError as exc:
                raise MemoryKeyError("existing memory does not authenticate with the supplied key") from exc


def _publish(path: Path, blob: bytes) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".memory-key-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        # link is atomic and refuses to replace an existing file, even on a race.
        os.link(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.unlink(temporary)


def ensure_linux_memory_key(
    *,
    home: Path,
    adopted_key: bytes | None = None,
    backend: NativeBackend | None = None,
    database_lease: ExclusiveLease | None = None,
) -> bytes:
    from ._database_mutation import _assert_memory_database_mutation_safe, database_key_mutation

    with _memory_failure(), contextlib.ExitStack() as stack:
        path = memory_key_path(home)
        if not (path.exists() or path.is_symlink()):
            # Explicit provisioning may initialize a fresh home before exclusion;
            # an identified missing source is never reconstructed over DB state.
            home.mkdir(mode=0o700, parents=True, exist_ok=True)
            if database_lease is None:
                # A competing first enrollment can publish while we are waiting.
                # Retry only exclusion admission, outside every custody lock.
                deadline = time.monotonic() + 1.0
                while True:
                    try:
                        database_lease = stack.enter_context(database_key_mutation(root=home, generation=None))
                        break
                    except DatabaseBusy:
                        if path.exists() or path.is_symlink():
                            break
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.01)
            else:
                _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
        return _ensure_linux_memory_key(
            home=home, adopted_key=adopted_key, backend=backend, database_lease=database_lease
        )


def _ensure_linux_memory_key(
    *, home: Path, adopted_key: bytes | None, backend: NativeBackend | None, database_lease: ExclusiveLease | None
) -> bytes:
    from ._database_mutation import _assert_memory_database_mutation_safe

    with memory_key_lock(home):
        path = memory_key_path(home)
        if not (path.exists() or path.is_symlink()):
            _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
        _private_parent(home, create=True)
        selected = backend if backend is not None else linux_memory_backend(home)
        path = memory_key_path(home)
        if path.exists() or path.is_symlink():
            existing = _load(home, selected)
            _validate_adoption(home, existing)
            return existing
        if (path.parent / "memory-vault.marker").exists():
            raise MemoryKeyError("armed profile has lost its wrapped key; refusing regeneration")
        _validate_adoption(home, adopted_key)
        _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
        key_id = memory_key_id(home)
        try:
            selected.get_enclave_public_key(key_id)
        except WrapKeyNotFound:
            _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
            selected.generate_enclave_key(key_id, unattended=True)
        key = adopted_key if adopted_key is not None else secrets.token_bytes(32)
        blob = wrap.wrap_dek(key, key_id, backend=selected)
        # Verify actual TPM access before publishing: a public-key lookup is insufficient.
        if wrap.unwrap_dek(blob, key_id, backend=selected, audit_sink=lambda entry: None) != key:
            raise MemoryKeyError("TPM memory key verification failed")
        _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
        _publish(path, blob)
        return key


def delete_linux_memory_key(
    *, home: Path, backend: NativeBackend | None = None, database_lease: ExclusiveLease | None = None
) -> None:
    from ._database_authority import observe_database_source, retire_database_source
    from ._database_mutation import _assert_memory_database_mutation_safe, database_key_mutation

    with _memory_failure(), contextlib.ExitStack() as stack:
        if database_lease is None:
            database_lease = stack.enter_context(database_key_mutation(root=home, generation=None))
        _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
        stack.enter_context(memory_key_lock(home))
        _assert_memory_database_mutation_safe(home=home, database_lease=database_lease)
        selected = backend if backend is not None else linux_memory_backend(home)
        path = memory_key_path(home)
        if not (path.exists() or path.is_symlink()):
            return  # No checked owner: retain any orphan native key for explicit repair.
        with _native_memory_custody(home, selected) as custody:
            owner = _issue_native_owner(custody, native_key_id=memory_key_id(home), backend=selected)
            binding = home / "mordred" / "db-key-source.json"
            if binding.exists() or binding.is_symlink():
                expected = observe_database_source(root=home)
                retire_database_source(root=home, expected=expected, lease=database_lease)
            with _owned_delete_scope(owner, backend=selected, database_lease=database_lease) as permit:
                selected.delete_enclave_key(memory_key_id(home), deletion=permit)
            path.unlink()


def resolve_memory_key(*, home: Path, platform: str, environ: Mapping[str, str]) -> bytes | None:
    if platform == "win32":
        from ._windows_custody import CustodyError, resolve_windows_memory_key

        try:
            return resolve_windows_memory_key(home=home)
        except (CustodyError, OSError, ValueError, WrapError, wrap.NativeBackendError) as exc:
            raise MemoryKeyError("Windows memory custody unavailable; existing data was not replaced") from exc
    if platform == "linux" and linux_memory_managed(home):
        return load_linux_memory_key(home=home)
    value = environ.get("HERMES_MEMORY_KEY")
    if not value:
        return None
    try:
        return decode_key(value)
    except MemoryCryptoError:
        return None
