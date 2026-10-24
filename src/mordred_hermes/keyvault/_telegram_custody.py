"""Authenticated POSIX Telegram ownership. No archive, database or SQL imports.

Authentication releases all locks before attended ECDH and retains only public
source observations. Existing sources lazily initialize the stable lock files;
empty read/status never initializes custody. An ambiguous forget is retained for
explicit repair, never interpreted as successful deletion from key absence.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import stat
import struct
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never
from weakref import WeakKeyDictionary

from .._database_contracts import DatabaseRefused
from ..extension.telegram.secrets import TelegramSecrets, TelegramSecretsError, decode
from . import _storage, wrap
from ._exceptions import WrapAuthCancelled, WrapError
from ._native_deletion import (
    _backend_binding,
    _issue_native_owner,
    _native_creation_handoff,
    _NativeOwnerFacts,
    _owned_delete_scope,
)
from .wrap import NativeBackend

KEY_ID = "mordred-hermes.telegram.credentials.v1"
_SEALED_NAME = "credentials.sealed"
_META_NAME = "credentials.meta.json"
_JOURNAL = "telegram-forget.json"
_MAGIC = b"MTC1"
_NONCE_LEN = 12
_AAD = b"mordred-telegram-credentials-v1"
_MAX_SOURCE = 4 * 1024 * 1024
AuditSink = Callable[[dict[str, Any]], None]


def _pack(blob: bytes, dek: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(_NONCE_LEN)
    return _MAGIC + struct.pack(">H", len(blob)) + blob + nonce + AESGCM(dek).encrypt(nonce, plaintext, _AAD)


def _unpack(sealed: bytes) -> tuple[bytes, bytes, bytes]:
    header = len(_MAGIC) + 2
    if len(sealed) < header or not sealed.startswith(_MAGIC):
        raise TelegramSecretsError("secrets_corrupt")
    (size,) = struct.unpack(">H", sealed[len(_MAGIC) : header])
    blob, nonce, body = (
        sealed[header : header + size],
        sealed[header + size : header + size + _NONCE_LEN],
        sealed[header + size + _NONCE_LEN :],
    )
    if len(blob) != size or len(nonce) != _NONCE_LEN or len(body) < 16:
        raise TelegramSecretsError("secrets_corrupt")
    return blob, nonce, body


def _decrypt(dek: bytes, nonce: bytes, body: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        return AESGCM(dek).decrypt(nonce, body, _AAD)
    except InvalidTag as exc:
        raise TelegramSecretsError("secrets_corrupt") from exc


def _process() -> tuple[int, int]:
    return os.getpid(), threading.get_ident()


def _identity(path: Path, *, directory: bool = True) -> tuple[int, int, int, int]:
    observed = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(observed.st_mode)
        or observed.st_uid != os.getuid()
        or (stat.S_IMODE(observed.st_mode) & 0o022 if directory else stat.S_IMODE(observed.st_mode) != 0o600)
        or (not directory and observed.st_nlink != 1)
    ):
        raise DatabaseRefused("unsafe Telegram custody path")
    return observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid


def checked_telegram_home(home: Path, *, create: bool = False) -> Path:
    if sys.platform not in {"darwin", "linux"} or not home.is_absolute() or home != home.resolve():
        raise DatabaseRefused("Telegram requires a canonical POSIX home")
    _identity(home)
    for path in (home / "mordred", home / "mordred/telegram"):
        try:
            _identity(path)
        except FileNotFoundError:
            if create:
                path.mkdir(mode=0o700)
                _identity(path)
        else:
            if path.name == "telegram" and stat.S_IMODE(path.lstat().st_mode) != 0o700:
                raise DatabaseRefused("Telegram credential directory must be private")
    return home


def _roots(home: Path) -> tuple[tuple[int, int, int, int], ...]:
    return tuple(_identity(path) for path in (home, home / "mordred", home / "mordred/telegram"))


def _backend(home: Path, backend: NativeBackend) -> tuple[object, ...]:
    from ._seckey_backend import _SecKeyBackend
    from ._seckey_helper import _HelperSecKeyOps

    name, leaf = ("MORDRED_SEKEY_STORE", "sekey") if sys.platform == "darwin" else ("MORDRED_TPMKEY_STORE", "tpm")
    if (
        type(backend) is not _SecKeyBackend
        or backend._sw_ops is not None
        or backend._legacy_ops is not None
        or type(backend._ops) is not _HelperSecKeyOps
        or backend._ops._env_override != (name, os.fspath(home / "mordred/keyvault" / leaf))
    ):
        raise DatabaseRefused("Telegram requires its profile-bound native helper backend")
    for path in (home / "mordred/keyvault", home / "mordred/keyvault" / leaf):
        try:
            _identity(path)
        except FileNotFoundError:
            continue
        if stat.S_IMODE(path.lstat().st_mode) != 0o700:
            raise DatabaseRefused("Telegram helper store is not private")
    return _backend_binding(backend, KEY_ID)


def _read(path: Path, *, maximum: int = _MAX_SOURCE) -> tuple[bytes, tuple[int, int, int, int]] | None:
    try:
        before = _identity(path, directory=False)
    except FileNotFoundError:
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if before != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid) or opened.st_size > maximum:
            raise DatabaseRefused("Telegram source identity or size is unsafe")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > maximum or _identity(path, directory=False) != before:
            raise DatabaseRefused("Telegram source changed during read")
        return bytes(data), before
    finally:
        os.close(fd)


def pending_telegram_forget(home: Path) -> bool:
    """Public state observation only; any journal, including unsafe state, retains ownership."""
    path = home / "mordred" / _JOURNAL
    return path.exists() or path.is_symlink()


def assert_no_pending_forget(home: Path) -> None:
    if pending_telegram_forget(home):
        raise DatabaseRefused("Telegram forget is pending; retained evidence requires checked recovery")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate journal member")
        result[key] = value
    return result


class _Opaque:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> _Opaque:
        raise DatabaseRefused("Telegram authority cannot be constructed")

    def __copy__(self) -> Never:
        raise DatabaseRefused("Telegram authority cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        raise DatabaseRefused("Telegram authority cannot be copied")

    def __reduce__(self) -> Never:
        raise DatabaseRefused("Telegram authority cannot be serialized")


class TelegramSnapshotChanged(DatabaseRefused):
    """An ordinary writer may authenticate fresh after releasing all locks."""


class TelegramAuthentication(_Opaque):
    """Nonsecret issued authentication; contains no plaintext or private key material."""

    __slots__ = ()


@dataclass(frozen=True)
class _Observation:
    home: Path
    roots: tuple[tuple[int, int, int, int], ...]
    source_identity: tuple[int, int, int, int]
    digest: str
    public_fingerprint: str
    binding: tuple[object, ...]
    locks: tuple[tuple[Path, tuple[int, int, int]], ...]


@dataclass(frozen=True)
class _AuthenticationRecord:
    observed: _Observation
    backend: NativeBackend
    process: tuple[int, int]


@dataclass
class _CustodyRecord:
    home: Path
    backend: NativeBackend
    roots: tuple[tuple[int, int, int, int], ...]
    process: tuple[int, int]
    locks: tuple[tuple[Path, tuple[int, int, int]], ...]
    authenticated: TelegramAuthentication | None
    binding: tuple[object, ...]
    journal: bytes | None = None
    journal_identity: tuple[int, int, int, int] | None = None
    native_deleted: bool = False


_authentications: WeakKeyDictionary[TelegramAuthentication, _AuthenticationRecord] = WeakKeyDictionary()
_custodies: WeakKeyDictionary[PosixTelegramCustody, _CustodyRecord] = WeakKeyDictionary()


def _record(scope: PosixTelegramCustody) -> _CustodyRecord:
    record = _custodies.get(scope) if type(scope) is PosixTelegramCustody else None
    if record is None or record.process != _process():
        raise DatabaseRefused("Telegram custody is closed or foreign")
    if _roots(record.home) != record.roots:
        raise DatabaseRefused("Telegram custody root changed")
    for path, identity in record.locks:
        _identity(path, directory=False)
        if _storage._checked_advisory_lock(path).identity != identity:
            raise DatabaseRefused("Telegram custody lock changed")
    if _backend(record.home, record.backend) != record.binding:
        raise DatabaseRefused("Telegram custody backend/store changed")
    journal = _read(record.home / "mordred" / _JOURNAL, maximum=8192)
    if (journal[0] if journal else None) != record.journal or (
        journal[1] if journal else None
    ) != record.journal_identity:
        raise DatabaseRefused("Telegram forget journal is pending or changed")
    return record


def _observe(scope: PosixTelegramCustody) -> tuple[_Observation | None, bytes | None]:
    record = _record(scope)
    source = _read(record.home / "mordred/telegram" / _SEALED_NAME)
    if source is None:
        return None, None
    sealed, identity = source
    fingerprint = hashlib.sha256(wrap.get_wrapping_key_public(KEY_ID, backend=record.backend)).hexdigest()
    return _Observation(
        record.home,
        record.roots,
        identity,
        hashlib.sha256(sealed).hexdigest(),
        fingerprint,
        _backend(record.home, record.backend),
        record.locks,
    ), sealed


def _validate_authentication(
    scope: PosixTelegramCustody, authentication: TelegramAuthentication | None
) -> _Observation:
    record = _record(scope)
    issued = _authentications.get(authentication) if type(authentication) is TelegramAuthentication else None
    if issued is None or issued.process != _process() or issued.backend is not record.backend:
        raise DatabaseRefused("Telegram source has no live issued authentication")
    observed, _sealed = _observe(scope)
    if observed != issued.observed:
        raise TelegramSnapshotChanged("Telegram authenticated source changed")
    return observed


class PosixTelegramCustody(_Opaque):
    """Exact adapter admitted by the closed native-owner dispatcher."""

    __slots__ = ()

    def _check_native_delete_owner(self, native_key_id: str, backend: NativeBackend) -> _NativeOwnerFacts:
        record = _record(self)
        if native_key_id != KEY_ID or backend is not record.backend:
            raise DatabaseRefused("Telegram native selector/backend mismatch")
        _validate_authentication(self, record.authenticated)
        return _NativeOwnerFacts(home=record.home, role="telegram", database_home=None)

    def delete_native_key(self) -> None:
        record = _record(self)
        self.begin_forget()
        owner = _issue_native_owner(self, native_key_id=KEY_ID, backend=record.backend)
        with _owned_delete_scope(owner, backend=record.backend, database_lease=None) as permit:
            wrap.delete_wrapping_key(KEY_ID, backend=record.backend, deletion=permit)
        record.native_deleted = True
        self.acknowledge_forget()

    def check_absence(self) -> None:
        if _observe(self)[0] is not None:
            raise TelegramSnapshotChanged("Telegram source appeared before publication")

    def validate(self, authentication: TelegramAuthentication | None) -> None:
        _validate_authentication(self, authentication)

    def write_source(self, sealed: bytes, meta: bytes) -> None:
        record = _record(self)
        with _native_creation_handoff(KEY_ID):
            _record(self)
            _storage.atomic_write(record.home / "mordred/telegram" / _SEALED_NAME, sealed)
            _record(self)
            _storage.atomic_write(record.home / "mordred/telegram" / _META_NAME, meta)

    def write_metadata(self, data: bytes) -> None:
        record = _record(self)
        _storage.atomic_write(record.home / "mordred/telegram" / _META_NAME, data)

    def forget_journal(self) -> dict[str, Any] | None:
        record = _record(self)
        if record.journal is None:
            return None
        try:
            journal = json.loads(record.journal, object_pairs_hook=_unique_json_object)
            required = {
                "version",
                "home",
                "roots",
                "selector",
                "public_fingerprint",
                "source_digest",
                "source_identity",
                "phase",
            }
            if (
                not isinstance(journal, dict)
                or set(journal) != required
                or type(journal["version"]) is not int
                or journal["version"] != 1
                or journal["home"] != str(record.home)
                or journal["roots"] != [list(item) for item in record.roots]
                or journal["selector"] != KEY_ID
                or journal["phase"] not in {"intent", "deleted"}
                or any(
                    not isinstance(journal[key], str)
                    or len(journal[key]) != 64
                    or any(c not in "0123456789abcdef" for c in journal[key])
                    for key in ("public_fingerprint", "source_digest")
                )
                or not isinstance(journal["source_identity"], list)
                or len(journal["source_identity"]) != 4
                or any(type(item) is not int for item in journal["source_identity"])
            ):
                raise ValueError("invalid binding")
            source = _read(record.home / "mordred/telegram" / _SEALED_NAME)
            if source is not None and (
                hashlib.sha256(source[0]).hexdigest() != journal["source_digest"]
                or list(source[1]) != journal["source_identity"]
            ):
                raise ValueError("changed source")
            return journal
        except (ValueError, TypeError, KeyError) as exc:
            raise DatabaseRefused("Telegram forget journal is invalid; retained for repair") from exc

    def begin_forget(self) -> None:
        record = _record(self)
        if record.journal is not None:
            raise DatabaseRefused("Telegram forget already pending")
        observed = _validate_authentication(self, record.authenticated)
        _read(record.home / "mordred/telegram" / _META_NAME)
        journal = {
            "version": 1,
            "home": str(record.home),
            "roots": [list(item) for item in record.roots],
            "selector": KEY_ID,
            "public_fingerprint": observed.public_fingerprint,
            "source_digest": observed.digest,
            "source_identity": list(observed.source_identity),
            "phase": "intent",
        }
        self._publish_journal(journal)

    def _publish_journal(self, journal: dict[str, Any]) -> None:
        record = _record(self)
        data = json.dumps(journal, sort_keys=True, separators=(",", ":")).encode()
        path = record.home / "mordred" / _JOURNAL
        _storage.atomic_write(path, data)
        published = _read(path, maximum=8192)
        if published is None or published[0] != data:
            raise DatabaseRefused("Telegram forget journal changed during publication")
        record.journal, record.journal_identity = published

    def acknowledge_forget(self) -> None:
        if not _record(self).native_deleted:
            raise DatabaseRefused("Telegram native deletion has not acknowledged completion")
        journal = self.forget_journal()
        if journal is None or journal["phase"] != "intent":
            raise DatabaseRefused("Telegram forget has no matching intent")
        self._publish_journal({**journal, "phase": "deleted"})

    def clean_source(self) -> None:
        record = _record(self)
        journal = self.forget_journal()
        if journal is None or journal["phase"] != "deleted":
            raise DatabaseRefused("Telegram forget lacks acknowledged native deletion")
        for name in (_META_NAME, _SEALED_NAME):
            path = record.home / "mordred/telegram" / name
            if _read(path) is not None:
                _record(self)
                path.unlink()
        _sync_directory(record.home / "mordred/telegram")

    def finish_forget(self) -> None:
        record = _record(self)
        journal = self.forget_journal()
        if journal is None or journal["phase"] != "deleted":
            raise DatabaseRefused("Telegram forget lacks acknowledged native deletion")
        if any(_read(record.home / "mordred/telegram" / name) is not None for name in (_SEALED_NAME, _META_NAME)):
            raise DatabaseRefused("Telegram source cleanup is incomplete")
        (record.home / "mordred" / _JOURNAL).unlink()
        _sync_directory(record.home / "mordred")
        record.journal = None
        record.journal_identity = None


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _storage._fsync_durable(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def telegram_credential_transaction(
    *,
    home: Path,
    backend: NativeBackend,
    authenticated: TelegramAuthentication | None = None,
    create: bool = False,
    _resume: bool = False,
) -> Iterator[PosixTelegramCustody]:
    """Lifecycle → credential lock, with live descriptor checks on every use."""
    try:
        checked_telegram_home(home, create=create)
        _backend(home, backend)
        roots = _roots(home)
        # Lazy lock initialization for an existing source is intentional. Unlike
        # key material these two stable locks survive every forget operation.
        with _storage.keyvault_lifecycle_lock(home / "mordred/keyvault"):
            credential_lock = home / "mordred/.telegram.credentials.lock"
            _storage.ensure_lock_file(credential_lock)
            with _storage._advisory_file_lock(credential_lock, label="Telegram credentials"):
                if _roots(home) != roots:
                    raise DatabaseRefused("Telegram root changed while waiting for custody")
                journal = _read(home / "mordred" / _JOURNAL, maximum=8192)
                if journal is not None and not _resume:
                    raise DatabaseRefused("Telegram forget is pending; evidence retained")
                paths = (home / "mordred/.keyvault.lifecycle.lock", credential_lock)
                scope = object.__new__(PosixTelegramCustody)
                _custodies[scope] = _CustodyRecord(
                    home,
                    backend,
                    roots,
                    _process(),
                    tuple((path, _storage._checked_advisory_lock(path).identity) for path in paths),
                    authenticated,
                    _backend(home, backend),
                    journal[0] if journal else None,
                    journal[1] if journal else None,
                )
                try:
                    _record(scope)
                    if authenticated is not None and journal is None:
                        _validate_authentication(scope, authenticated)
                    yield scope
                finally:
                    _custodies.pop(scope, None)
    except (OSError, ValueError) as exc:
        raise DatabaseRefused("Telegram custody path or lock is unsafe; evidence retained") from exc


def authenticate_telegram_source(
    *, home: Path, backend: NativeBackend, audit_sink: AuditSink
) -> tuple[TelegramSecrets | None, TelegramAuthentication | None]:
    checked_telegram_home(home)
    assert_no_pending_forget(home)
    if _read(home / "mordred/telegram" / _SEALED_NAME) is None:
        return None, None
    with telegram_credential_transaction(home=home, backend=backend) as custody:
        observed, sealed = _observe(custody)
    if sealed is None:
        return None, None
    blob, nonce, body = _unpack(sealed)
    try:
        dek = wrap.unwrap_dek(blob, KEY_ID, backend=backend, audit_sink=audit_sink)
    except WrapAuthCancelled as exc:
        raise TelegramSecretsError("tee_auth_cancelled") from exc
    except WrapError as exc:
        raise TelegramSecretsError("tee_unavailable") from exc
    current = decode(_decrypt(dek, nonce, body))
    del dek
    with telegram_credential_transaction(home=home, backend=backend) as custody:
        if _observe(custody)[0] != observed:
            raise DatabaseRefused("Telegram source changed during authentication")
        with _native_creation_handoff(KEY_ID):
            authentication = object.__new__(TelegramAuthentication)
            assert observed is not None
            _authentications[authentication] = _AuthenticationRecord(observed, backend, _process())
        return current, authentication
