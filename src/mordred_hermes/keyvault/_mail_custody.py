"""Concrete authenticated mail ownership, independent of database-key custody.

POSIX authentication releases lifecycle/credential locks before attended ECDH.
Only issued proofs bind a source to a native deletion. Checked private filesystem
transactions preserve intent/deleted journals and never repair unsafe paths.
An orphan key (no sealed source) is retained until the explicit
``mail forget --yes --force-orphan`` repair, whose distinct in-transaction proof
binds the key to its recorded public digest; a sealed source whose native key is
definitively absent is removed by the same repair without any native deletion.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Never
from weakref import WeakKeyDictionary

from .._database_contracts import DatabaseRefused
from .._private_fs import FileMetadata, PrivateDirectory, PrivateFSError, PrivateTransaction, open_private_directory
from ._mail_key import KEY_ID

if TYPE_CHECKING:
    from ..imports.mail.secrets import MailCredentials
from . import _storage, wrap
from ._exceptions import WrapKeyNotFound
from ._native_deletion import _backend_binding, _issue_native_owner, _NativeOwnerFacts, _owned_delete_scope
from .wrap import NativeBackend

SEALED = "credentials.sealed"
META = "credentials.meta.json"
GENERATION = "generation"
JOURNAL = "mail-forget.json"
KEY_RECORD = "enclave-key.json"
LIMIT = 65536


class MailOrphanKey(DatabaseRefused):
    """A native mail key without a sealed source; retained for the explicit orphan repair."""


def read(directory: PrivateDirectory | PrivateTransaction, name: str) -> tuple[bytes, FileMetadata] | None:
    try:
        before = directory.stat(name)
        data = directory.read_bytes(name, max_bytes=LIMIT)
        if directory.stat(name) != before:
            raise DatabaseRefused("mail source changed during checked read")
        return data, before
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return None
        raise


def pending_mail_retirement(home: Path) -> bool:
    """Checked public recovery state; this never grants deletion authority."""
    try:
        with open_private_directory(home / "mordred/mail") as directory:
            return read(directory, JOURNAL) is not None
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return False
        raise


def publish(tx: PrivateTransaction, name: str, data: bytes) -> None:
    if read(tx, name) is None:
        tx.create_bytes(name, data)
    else:
        tx.replace_bytes(name, data)


def remove(tx: PrivateTransaction, name: str) -> None:
    item = read(tx, name)
    if item is not None:
        tx.delete_file(name, expected_identity=item[1].identity)


def decrypt(
    sealed: bytes, backend: NativeBackend, entries: list[dict[str, Any]], *, native_key_id: str | None = None
) -> MailCredentials:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from ..imports.mail.secrets import _AAD, MailSecretsError, _unpack, decode

    blob, nonce, body = _unpack(sealed)
    dek = wrap.unwrap_dek(blob, KEY_ID, backend=backend, native_key_id=native_key_id, audit_sink=entries.append)
    try:
        return decode(AESGCM(dek).decrypt(nonce, body, _AAD))
    except InvalidTag as exc:
        raise MailSecretsError("secrets_corrupt") from exc
    finally:
        del dek


def checked_home(root: Path) -> Path:
    if root.name != "mail" or root.parent.name != "mordred" or not root.is_absolute() or root != root.resolve():
        raise DatabaseRefused("mail requires its canonical profile directory")
    return root.parent.parent


def _roots(home: Path) -> tuple[tuple[int, int], ...]:
    result = []
    for path in (home, home / "mordred", home / "mordred/mail"):
        with open_private_directory(path) as directory:
            identity = directory.directory_identity()
            result.append((identity.volume, int.from_bytes(identity.file_id)))
    return tuple(result)


def _backend(home: Path, backend: NativeBackend) -> tuple[object, ...]:
    import sys

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
        raise DatabaseRefused("mail requires its profile-bound native helper backend")
    for path in (home / "mordred/keyvault", home / "mordred/keyvault" / leaf):
        try:
            with open_private_directory(path):
                pass
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
    return _backend_binding(backend, KEY_ID)


def _process() -> tuple[int, int]:
    return os.getpid(), threading.get_ident()


class _Opaque:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> _Opaque:
        raise DatabaseRefused("mail authentication cannot be constructed")

    def __copy__(self) -> Never:
        raise DatabaseRefused("mail authentication cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        raise DatabaseRefused("mail authentication cannot be copied")

    def __reduce__(self) -> Never:
        raise DatabaseRefused("mail authentication cannot be serialized")


class MailAuthentication(_Opaque):
    __slots__ = ()


class OrphanKeyAuthentication(_Opaque):
    """Issued only inside :meth:`PosixMailCustody.retire_orphan`; never a source authentication."""

    __slots__ = ()


@dataclass(frozen=True)
class Observation:
    home: Path
    roots: tuple[tuple[int, int], ...]
    files: tuple[tuple[str, str, FileMetadata] | None, ...]
    public: str
    binding: tuple[object, ...]
    locks: tuple[tuple[Path, tuple[int, int, int]], ...]


@dataclass(frozen=True)
class _OrphanFacts:
    """What an orphan proof binds: one live transaction, the selector, and the recorded key."""

    tx: PrivateTransaction
    backend: NativeBackend
    selector: str
    public: str
    record: tuple[object, ...]
    journal: str
    observation: Observation
    process: tuple[int, int]


@dataclass
class _Record:
    home: Path
    backend: NativeBackend
    tx: PrivateTransaction
    roots: tuple[tuple[int, int], ...]
    binding: tuple[object, ...]
    locks: tuple[tuple[Path, tuple[int, int, int]], ...]
    process: tuple[int, int]
    authentication: MailAuthentication | None
    orphan: OrphanKeyAuthentication | None = None


_custodies: WeakKeyDictionary[PosixMailCustody, _Record] = WeakKeyDictionary()
_proofs: WeakKeyDictionary[MailAuthentication, tuple[Observation, NativeBackend, tuple[int, int]]] = WeakKeyDictionary()
_orphan_proofs: WeakKeyDictionary[OrphanKeyAuthentication, _OrphanFacts] = WeakKeyDictionary()


def _record(scope: PosixMailCustody) -> _Record:
    record = _custodies.get(scope) if type(scope) is PosixMailCustody else None
    if record is None or record.process != _process():
        raise DatabaseRefused("mail custody is closed or foreign")
    if _roots(record.home) != record.roots or _backend(record.home, record.backend) != record.binding:
        raise DatabaseRefused("mail custody root/backend changed")
    for path, identity in record.locks:
        if _storage._checked_advisory_lock(path).identity != identity:
            raise DatabaseRefused("mail credential lock changed")
    record.tx.assert_private_admission()
    return record


def _observe(scope: PosixMailCustody) -> Observation:
    r = _record(scope)
    files = []
    for name in (SEALED, META, GENERATION):
        item = read(r.tx, name)
        files.append(None if item is None else (name, hashlib.sha256(item[0]).hexdigest(), item[1]))
    public = hashlib.sha256(wrap.get_wrapping_key_public(KEY_ID, backend=r.backend)).hexdigest()
    return Observation(r.home, r.roots, tuple(files), public, r.binding, r.locks)


def _validate(scope: PosixMailCustody, proof: MailAuthentication | None) -> Observation:
    r = _record(scope)
    issued = _proofs.get(proof) if type(proof) is MailAuthentication else None
    if issued is None or issued[1] is not r.backend or issued[2] != _process() or issued[0] != _observe(scope):
        raise DatabaseRefused("mail authenticated source/generation changed")
    return issued[0]


def _validate_orphan(scope: PosixMailCustody, proof: OrphanKeyAuthentication | None) -> Observation:
    """Recheck every orphan fact live; the proof exists only while ``retire_orphan`` runs."""
    r = _record(scope)
    facts = _orphan_proofs.get(proof) if type(proof) is OrphanKeyAuthentication else None
    if (
        facts is None
        or r.orphan is not proof
        or r.authentication is not None
        or facts.tx is not r.tx
        or facts.backend is not r.backend
        or facts.process != _process()
        or facts.selector != KEY_ID
    ):
        raise DatabaseRefused("mail orphan repair proof is foreign or stale")
    observed = _observe(scope)
    record = read(r.tx, KEY_RECORD)
    journal = read(r.tx, JOURNAL)
    if (
        observed != facts.observation
        or observed.files[0] is not None
        or observed.files[1] is not None
        or observed.public != facts.public
        or record is None
        or tuple(_file_document(record)) != facts.record
        or journal is None
        or hashlib.sha256(journal[0]).hexdigest() != facts.journal
    ):
        raise DatabaseRefused("mail orphan key/source changed")
    return observed


def _recorded_public(item: tuple[bytes, FileMetadata] | None) -> str | None:
    try:
        value = None if item is None else json.loads(item[0])
    except ValueError:
        return None
    digest = value.get("public_sha256") if isinstance(value, dict) else None
    return digest if isinstance(digest, str) else None


def _key_absent(backend: NativeBackend) -> bool:
    """True only for definitive absence; any other native failure propagates unchanged."""
    try:
        wrap.get_wrapping_key_public(KEY_ID, backend=backend)
    except WrapKeyNotFound as exc:
        if type(exc) is not WrapKeyNotFound:  # e.g. WrapKeyAlreadyExists: not an absence
            raise
        return True
    return False


class PosixMailCustody(_Opaque):
    __slots__ = ()

    def _check_native_delete_owner(self, selector: str, backend: NativeBackend) -> _NativeOwnerFacts:
        r = _record(self)
        if selector != KEY_ID or backend is not r.backend:
            raise DatabaseRefused("mail native selector/backend mismatch")
        if r.orphan is not None:
            _validate_orphan(self, r.orphan)
        else:
            _validate(self, r.authentication)
        return _NativeOwnerFacts(home=r.home, role="mail")

    @property
    def transaction(self) -> PrivateTransaction:
        return _record(self).tx

    def retire(self) -> None:
        r = _record(self)
        observed = _validate(self, r.authentication)
        if read(r.tx, JOURNAL) is not None:
            raise DatabaseRefused("mail retirement is pending")
        import secrets

        from ..imports.mail.imap_sync import assert_mail_writer_held

        assert_mail_writer_held(r.home)
        publish(r.tx, GENERATION, secrets.token_hex(16).encode())
        refreshed = _observe(self)
        if (
            refreshed.files[:2] != observed.files[:2]
            or refreshed.public != observed.public
            or refreshed.binding != observed.binding
            or refreshed.roots != observed.roots
        ):
            raise DatabaseRefused("mail source changed during setup invalidation")
        assert r.authentication is not None
        _proofs[r.authentication] = refreshed, r.backend, _process()
        observed = refreshed
        journal = _journal_document(observed)
        publish(r.tx, JOURNAL, json.dumps(journal, sort_keys=True).encode())
        owner = _issue_native_owner(self, native_key_id=KEY_ID, backend=r.backend)
        with _owned_delete_scope(owner, backend=r.backend, database_lease=None) as permit:
            wrap.delete_wrapping_key(KEY_ID, backend=r.backend, deletion=permit)
        publish(r.tx, JOURNAL, json.dumps({**journal, "phase": "deleted"}, sort_keys=True).encode())
        self.cleanup()

    def retire_orphan(self, *, linux: bool) -> None:
        """The explicit ``mail forget --yes --force-orphan`` repair; never a source authentication.

        Orphan key: no sealed source, metadata or journal, and a key record whose
        ``public_sha256`` names the live public key (Linux: also its checked
        no-presence policy). An in-transaction orphan proof then drives the usual
        intent journal, owned native deletion, acknowledgement and cleanup.
        Keyless source: the native key is definitively absent (``WrapKeyNotFound``
        exactly), so nothing is deleted natively; the undecryptable source, its
        metadata and the key record are removed, the sealed file last so an
        interruption stays repairable. Every other state refuses and retains evidence.
        """
        r = _record(self)
        if r.authentication is not None or r.orphan is not None:
            raise DatabaseRefused("mail orphan repair never reuses another proof")
        if read(r.tx, JOURNAL) is not None:
            raise DatabaseRefused("mail retirement is pending")
        from ..imports.mail.imap_sync import assert_mail_writer_held

        assert_mail_writer_held(r.home)
        if _key_absent(r.backend):
            self._remove_keyless_source()
            return
        if read(r.tx, SEALED) is not None:
            raise DatabaseRefused("mail source has its native key; retire it with an authenticated forget")
        if read(r.tx, META) is not None:
            raise DatabaseRefused("mail metadata without a source requires reconciliation")
        public = hashlib.sha256(wrap.get_wrapping_key_public(KEY_ID, backend=r.backend)).hexdigest()
        record = read(r.tx, KEY_RECORD)
        if record is None or _recorded_public(record) != public:
            raise DatabaseRefused("mail native key is not the recorded orphan; retained")
        if linux:
            record = require_linux_no_presence_policy(r.tx, public)
        self._retire_orphan_key(public, record)

    def _retire_orphan_key(self, public: str, record: tuple[bytes, FileMetadata]) -> None:
        import secrets

        r = _record(self)
        publish(r.tx, GENERATION, secrets.token_hex(16).encode())  # pending setup flows go stale
        observed = _observe(self)
        current = read(r.tx, KEY_RECORD)
        if (
            observed.files[0] is not None
            or observed.files[1] is not None
            or observed.public != public
            or current is None
            or _file_document(current) != _file_document(record)
        ):
            raise DatabaseRefused("mail source changed during orphan repair")
        document = _journal_document(observed)
        intent = json.dumps(document, sort_keys=True).encode()
        publish(r.tx, JOURNAL, intent)
        proof = object.__new__(OrphanKeyAuthentication)
        _orphan_proofs[proof] = _OrphanFacts(
            r.tx,
            r.backend,
            KEY_ID,
            public,
            tuple(_file_document(current)),
            hashlib.sha256(intent).hexdigest(),
            observed,
            _process(),
        )
        r.orphan = proof
        try:
            owner = _issue_native_owner(self, native_key_id=KEY_ID, backend=r.backend)
            with _owned_delete_scope(owner, backend=r.backend, database_lease=None) as permit:
                wrap.delete_wrapping_key(KEY_ID, backend=r.backend, deletion=permit)
        finally:
            r.orphan = None
            _orphan_proofs.pop(proof, None)
        publish(r.tx, JOURNAL, json.dumps({**document, "phase": "deleted"}, sort_keys=True).encode())
        self.cleanup()

    def _remove_keyless_source(self) -> None:
        import secrets

        r = _record(self)
        present = {name: read(r.tx, name) for name in (META, KEY_RECORD, SEALED)}
        if all(item is None for item in present.values()):
            return  # nothing native and nothing local: the plain forget outcome
        publish(r.tx, GENERATION, secrets.token_hex(16).encode())  # pending setup flows go stale
        if not _key_absent(r.backend):
            raise DatabaseRefused("mail native key appeared during orphan repair")
        for name in (META, KEY_RECORD, SEALED):  # the sealed source last: an interruption stays repairable
            item = present[name]
            if item is None:
                continue
            current = read(r.tx, name)
            if current is None or _file_document(current) != _file_document(item):
                raise DatabaseRefused("mail source changed during orphan repair")
            r.tx.delete_file(name, expected_identity=item[1].identity)

    def cleanup(self) -> None:
        r = _record(self)
        item = read(r.tx, JOURNAL)
        if item is None:
            raise DatabaseRefused("mail retirement has no acknowledgement")
        try:
            journal = json.loads(item[0])
            if (
                journal["phase"] != "deleted"
                or journal["home"] != str(r.home)
                or journal["roots"] != [list(x) for x in r.roots]
            ):
                raise ValueError
            if (
                set(journal) != {"version", "home", "roots", "files", "public", "phase", "selector"}
                or journal["version"] != 1
                or journal["selector"] != KEY_ID
            ):
                raise ValueError
            for name in (SEALED, META, GENERATION):
                current = read(r.tx, name)
                expected = journal["files"][name]
                if current is not None and _file_document(current) != expected:
                    raise ValueError
                if name == GENERATION and current is None and expected is not None:
                    raise ValueError
        except (ValueError, TypeError, KeyError) as exc:
            raise DatabaseRefused("mail retirement journal/source changed; evidence retained") from exc
        for name in (SEALED, META, KEY_RECORD):
            remove(r.tx, name)
        remove(r.tx, JOURNAL)


def _file_document(item: tuple[bytes, FileMetadata]) -> list[object]:
    data, meta = item
    return [
        hashlib.sha256(data).hexdigest(),
        meta.identity.volume,
        meta.identity.file_id.hex(),
        meta.size,
        meta.mtime_ns,
    ]


def _journal_document(observed: Observation) -> dict[str, Any]:
    files: dict[str, list[object] | None] = {}
    for name, item in zip((SEALED, META, GENERATION), observed.files, strict=True):
        if item is None:
            files[name] = None
        else:
            _, digest, meta = item
            files[name] = [digest, meta.identity.volume, meta.identity.file_id.hex(), meta.size, meta.mtime_ns]
    return dict(
        version=1,
        home=str(observed.home),
        roots=observed.roots,
        files=files,
        public=observed.public,
        selector=KEY_ID,
        phase="intent",
    )


@contextlib.contextmanager
def mail_credential_transaction(
    *,
    home: Path,
    backend: NativeBackend,
    authenticated: MailAuthentication | None = None,
    create: bool = False,
    resume: bool = False,
) -> Iterator[PosixMailCustody]:
    root = home / "mordred/mail"
    if authenticated is not None:
        issued = _proofs.get(authenticated) if type(authenticated) is MailAuthentication else None
        if issued is None or issued[0].home != home:
            raise DatabaseRefused("mail authentication belongs to another root")
    checked_home(root)
    with open_private_directory(home / "mordred", create=create):
        pass
    with open_private_directory(root, create=create):
        pass
    roots = _roots(home)
    _backend(home, backend)
    with _storage.keyvault_lifecycle_lock(home / "mordred/keyvault"):
        if create:
            import sys

            leaf = "sekey" if sys.platform == "darwin" else "tpm"
            # Stable checked helper directory identity precedes first native
            # generation, whose helper would otherwise create this directory.
            for path in (home / "mordred/keyvault", home / "mordred/keyvault" / leaf):
                with open_private_directory(path, create=True):
                    pass
        lock = home / "mordred/.mail.credentials.lock"
        _storage.ensure_lock_file(lock)
        with (
            _storage._advisory_file_lock(lock, label="mail credentials"),
            open_private_directory(root) as directory,
            directory.transaction() as tx,
        ):
            if _roots(home) != roots:
                raise DatabaseRefused("mail root changed waiting for custody")
            if read(tx, JOURNAL) is not None and not resume:
                raise DatabaseRefused("mail retirement pending; evidence retained")
            locks = tuple(
                (p, _storage._checked_advisory_lock(p).identity)
                for p in (home / "mordred/.keyvault.lifecycle.lock", lock)
            )
            scope = object.__new__(PosixMailCustody)
            _custodies[scope] = _Record(
                home, backend, tx, roots, _backend(home, backend), locks, _process(), authenticated
            )
            try:
                if authenticated is not None:
                    _validate(scope, authenticated)
                yield scope
            finally:
                _custodies.pop(scope, None)


def authenticate_mail_source(
    *, home: Path, backend: NativeBackend, entries: list[dict[str, Any]]
) -> tuple[MailCredentials | None, MailAuthentication | None]:
    """Authenticate MMC1 ownership for retirement; this is not a presence-policy proof."""
    with mail_credential_transaction(home=home, backend=backend) as custody:
        item = read(custody.transaction, SEALED)
        if item is None:
            return None, None
        observed = _observe(custody)
    value = decrypt(item[0], backend, entries)
    with mail_credential_transaction(home=home, backend=backend) as custody:
        if _observe(custody) != observed:
            raise DatabaseRefused("mail source changed during authentication")
        proof = object.__new__(MailAuthentication)
        _proofs[proof] = observed, backend, _process()
    return value, proof


def require_linux_no_presence_policy(tx: PrivateTransaction, public: str) -> tuple[bytes, FileMetadata]:
    """Read existing policy without relabeling an unsupported or unknown TPM claim."""
    from ..imports.mail.secrets import _KEY_RECORD_NAME, MailSecretsError

    record = read(tx, _KEY_RECORD_NAME)
    meta = read(tx, META)
    try:
        key_policy = None if record is None else json.loads(record[0])
        flags = None if meta is None else json.loads(meta[0])
    except ValueError:
        raise MailSecretsError("presence_unsupported") from None
    if (
        record is None
        or not isinstance(key_policy, dict)
        or key_policy.get("public_sha256") != public
        or key_policy.get("touch_id") is not False
    ):
        raise MailSecretsError("presence_unsupported")
    if (meta is not None or read(tx, SEALED) is not None) and (
        not isinstance(flags, dict) or flags.get("touch_id") is not False
    ):
        raise MailSecretsError("presence_unsupported")
    return record


def load_linux_mail_credentials(
    *, home: Path, backend: NativeBackend, entries: list[dict[str, Any]]
) -> MailCredentials | None:
    """Refuse legacy policy before unwrap and recheck against the issued source afterward."""
    with mail_credential_transaction(home=home, backend=backend) as custody:
        if read(custody.transaction, SEALED) is None:
            return None
        observed = _observe(custody)
        policy = require_linux_no_presence_policy(custody.transaction, observed.public)
    value, proof = authenticate_mail_source(home=home, backend=backend, entries=entries)
    try:
        with mail_credential_transaction(home=home, backend=backend, authenticated=proof) as custody:
            if _validate(custody, proof) != observed:
                raise DatabaseRefused("mail source changed during credential read")
            current = require_linux_no_presence_policy(custody.transaction, observed.public)
            if current != policy:
                raise DatabaseRefused("mail key policy changed during credential read")
    except BaseException:
        del value
        raise
    return value


class _WindowsAuthentication(_Opaque):
    __slots__ = ()


@dataclass(frozen=True)
class _WindowsObservation:
    home: Path
    directory: object
    profile: object
    lease: object
    binding: tuple[object, ...]
    files: dict[str, list[object] | None]
    process: tuple[int, int]


_windows_proofs: WeakKeyDictionary[_WindowsAuthentication, _WindowsObservation] = WeakKeyDictionary()


def _files(tx: PrivateTransaction) -> dict[str, list[object] | None]:
    result = {}
    for name in (SEALED, META, GENERATION):
        item = read(tx, name)
        result[name] = None if item is None else _file_document(item)
    return result


class WindowsMailStore:
    """MMC1 mail source coupled to genuine current Windows mail custody.

    No reset of retained generations: each authenticated source owns exactly
    its current generation. Native deletion is acknowledged before local source
    removal; an ambiguous intent is retained and never retried automatically.
    """

    def __init__(self, home: Path, *, backend: NativeBackend | None, audit_sink: Any) -> None:
        self.home = home
        self.backend = backend
        self.audit_sink = audit_sink

    @contextlib.contextmanager
    def _session(self, *, create: bool = False) -> Iterator[Any]:
        from ._windows_custody import windows_custody_session

        with windows_custody_session(self.home, create=create, backend=self.backend) as session:
            yield session

    @contextlib.contextmanager
    def _transaction(self, *, create: bool = False) -> Iterator[PrivateTransaction]:
        with (
            open_private_directory(self.home / "mordred/mail", create=create) as directory,
            directory.transaction() as tx,
        ):
            yield tx

    def _role(self, session: Any) -> tuple[Any, NativeBackend]:
        lease = session.lease("mail")
        if lease.role != "mail" or lease.key_id != KEY_ID:
            raise DatabaseRefused("mail requires its own current generation")
        backend: NativeBackend = session.backend_for(lease)
        self.backend = backend  # nonsecret backend identity only, never credentials or DEK
        return lease, backend

    def prepare_setup(self) -> None:
        with self._session(create=True) as session:
            session.upgrade_manifest_v2()

    def ensure_key(self, *, require_presence: bool, replace: bool) -> bool:
        from ..imports.mail.secrets import MailSecretsError

        del replace  # Existing policy is fixed machine-bound; never silently retire it.
        if require_presence:
            raise MailSecretsError("presence_unsupported")
        with self._session(create=True) as session:
            # Explicit setup only: this invokes the v2/fresh-empty guard, never
            # the unrelated memory-role database inventory mutation guard.
            session.upgrade_manifest_v2()
            status = session.role_status("mail")
            if status.pending:
                raise DatabaseRefused("mail enrollment is pending")
            if status.current is None:
                try:
                    with self._transaction() as tx:
                        if any(read(tx, name) is not None for name in (SEALED, META, JOURNAL)):
                            raise DatabaseRefused("mail source without a role must be retained")
                except PrivateFSError as exc:
                    if exc.reason != "missing":
                        raise
                if status.retained:
                    raise DatabaseRefused("retained mail generations require reconciliation")
                session.enroll_role("mail")
            self._role(session)
        return False

    def _observation(self, session: Any, tx: PrivateTransaction) -> _WindowsObservation:
        lease, backend = self._role(session)
        return _WindowsObservation(
            self.home,
            tx.directory_identity(),
            session.profile_binding(),
            lease,
            _backend_binding(backend, lease.native_key_id),
            _files(tx),
            _process(),
        )

    def load_snapshot(self) -> tuple[MailCredentials | None, _WindowsAuthentication | None]:
        entries: list[dict[str, Any]] = []
        try:
            with self._session() as session:
                try:
                    with self._transaction() as tx:
                        if read(tx, JOURNAL) is not None:
                            raise DatabaseRefused("mail retirement pending")
                        item = read(tx, SEALED)
                        if item is None:
                            return None, None
                        observed = self._observation(session, tx)
                        lease, backend = self._role(session)
                        value = decrypt(item[0], backend, entries, native_key_id=lease.native_key_id)
                        if self._observation(session, tx) != observed:
                            raise DatabaseRefused("mail source changed during authentication")
                        proof = object.__new__(_WindowsAuthentication)
                        _windows_proofs[proof] = observed
                        return value, proof
                except PrivateFSError as exc:
                    if exc.reason == "missing":
                        return None, None
                    raise
        finally:
            for entry in entries:
                self.audit_sink(entry)

    def store(self, value: MailCredentials, *, require_presence: bool) -> None:
        import secrets

        from ..imports.mail.secrets import MailSecretsError, _pack, encode

        if require_presence:
            raise MailSecretsError("presence_unsupported")
        with self._session() as session:
            lease, backend = self._role(session)
            with session.canonical.publication_receipt() as receipt, self._transaction(create=True) as tx:
                if read(tx, JOURNAL) is not None:
                    raise DatabaseRefused("mail retirement pending")
                dek = secrets.token_bytes(32)
                blob = wrap.wrap_dek(dek, KEY_ID, backend=backend, native_key_id=lease.native_key_id)
                sealed = _pack(blob, dek, encode(value))
                del dek
                flags = dict(
                    version=1,
                    account=value.account,
                    gmail=value.gmail,
                    roles=list(value.roles),
                    touch_id=False,
                    setup_id=secrets.token_hex(16),
                    sealed_sha256=hashlib.sha256(sealed).hexdigest(),
                )
                receipt.mark_published()
                publish(tx, SEALED, sealed)
                publish(tx, META, json.dumps(flags, sort_keys=True).encode())

    def _cleanup(self, session: Any, tx: PrivateTransaction) -> None:
        raw = read(tx, JOURNAL)
        if raw is None:
            raise DatabaseRefused("mail retirement has no acknowledgement")
        try:
            journal = json.loads(raw[0])
            identity = tx.directory_identity()
            expected = {"version", "home", "directory", "files", "generation", "phase"}
            if (
                set(journal) != expected
                or journal["version"] != 1
                or journal["phase"] != "deleted"
                or journal["home"] != str(self.home)
                or journal["directory"] != [identity.volume, identity.file_id.hex()]
            ):
                raise ValueError
            status = session.role_status("mail")
            if (
                status.pending
                or status.current is not None
                or any(x.generation == journal["generation"] for x in status.retained)
            ):
                raise ValueError
            current = _files(tx)
            if any(value is not None and value != journal["files"][name] for name, value in current.items()):
                raise ValueError
            if current[GENERATION] != journal["files"][GENERATION]:
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise DatabaseRefused("mail retirement/source changed; evidence retained") from exc
        for name in (SEALED, META, "enclave-key.json"):
            remove(tx, name)
        remove(tx, JOURNAL)

    def forget_from_snapshot(self, snapshot: tuple[MailCredentials | None, Any]) -> bool:
        with self._session() as session, session.canonical.publication_receipt() as receipt, self._transaction() as tx:
            if read(tx, JOURNAL) is not None:
                receipt.mark_published()
                self._cleanup(session, tx)
                return True
            if read(tx, SEALED) is None:
                status = session.role_status("mail")
                if status.pending or read(tx, META) is not None or (status.current is not None and status.retained):
                    raise DatabaseRefused("mail role/source requires checked reconciliation")
                if status.current is not None:
                    raise MailOrphanKey("mail role has no authenticated source; retained for the orphan repair")
                return True
            proof = snapshot[1]
            observed = _windows_proofs.get(proof) if type(proof) is _WindowsAuthentication else None
            if observed is None or observed != self._observation(session, tx):
                raise DatabaseRefused("mail authentication/source/generation changed")
            import secrets

            from ..imports.mail.imap_sync import assert_mail_writer_held

            assert_mail_writer_held(self.home)
            publish(tx, GENERATION, secrets.token_hex(16).encode())
            refreshed = self._observation(session, tx)
            from dataclasses import replace

            if replace(refreshed, files=observed.files) != observed or any(
                refreshed.files[name] != observed.files[name] for name in (SEALED, META)
            ):
                raise DatabaseRefused("mail source changed during setup invalidation")
            observed = refreshed
            lease, _backend_value = self._role(session)
            identity = tx.directory_identity()
            journal = dict(
                version=1,
                home=str(self.home),
                directory=[identity.volume, identity.file_id.hex()],
                files=_files(tx),
                generation=lease.generation,
                phase="intent",
            )
            # Last complete source and generation check is inside the actual
            # live session, immediately before its concrete delete_role call.
            if self._observation(session, tx) != observed:
                raise DatabaseRefused("mail authentication changed before retirement")
            receipt.mark_published()
            publish(tx, JOURNAL, json.dumps(journal, sort_keys=True).encode())
            session.delete_role(lease, erase_authorized=True)
            publish(tx, JOURNAL, json.dumps({**journal, "phase": "deleted"}, sort_keys=True).encode())
            self._cleanup(session, tx)
        return True

    def forget(self, *, force_orphan: bool = False) -> bool:
        try:
            with self._transaction() as tx:
                pending = read(tx, JOURNAL) is not None
        except PrivateFSError as exc:
            if exc.reason != "missing":
                raise
            if not force_orphan:
                return True
            pending = False
        if pending:
            return self.forget_from_snapshot((None, None))
        if force_orphan:
            return self.retire_orphan()
        return self.forget_from_snapshot(self.load_snapshot())

    def retire_orphan(self) -> bool:
        """Explicit ``--force-orphan`` repair: retire a current mail role that has no mail source.

        The role is deleted only through the session's own journaled
        ``delete_role``; any credential file, mail journal, pending or retained
        generation refuses, and an absent role is the plain forget outcome.
        """
        from ..imports.mail.imap_sync import assert_mail_writer_held

        assert_mail_writer_held(self.home)
        with self._session() as session, contextlib.ExitStack() as stack:
            status = session.role_status("mail")
            if status.pending or status.retained:
                raise DatabaseRefused("mail role requires checked reconciliation")
            if status.current is None:
                return True
            try:
                tx = stack.enter_context(self._transaction())
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
            else:
                if any(read(tx, name) is not None for name in (SEALED, META, JOURNAL)):
                    raise DatabaseRefused("mail source exists; retire it with an authenticated forget")
            lease, _backend_value = self._role(session)
            session.delete_role(lease, erase_authorized=True)
        return True


def check_snapshot_home(proof: object, home: Path) -> None:
    if proof is None:
        return
    if type(proof) is MailAuthentication:
        record = _proofs.get(proof)
        if record is not None and record[0].home == home and record[2] == _process():
            return
    elif type(proof) is _WindowsAuthentication:
        observed = _windows_proofs.get(proof)
        if observed is not None and observed.home == home and observed.process == _process():
            return
    raise DatabaseRefused("mail authentication is foreign or unissued")
