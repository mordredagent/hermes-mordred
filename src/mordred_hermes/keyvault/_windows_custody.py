"""Windows CNG custody with checked ownership and durable role journals.

Enrollment is explicit and inert: this module never arms memory hooks. Runtime
lookups never generate, import ambient keys, infer native absence, or repair ACLs.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from .._config_io import CanonicalPaths, CanonicalSession, canonical_session
from .._custody_order import custody_scope
from .._database_contracts import DatabaseRefused
from .._private_fs import (
    FileIdentity,
    PrivateFSError,
    PrivateTransaction,
    current_principal_id,
    open_optional_confidential_directory,
)
from . import wrap
from ._exceptions import WrapParseError
from ._memory_storage import inventory_memory_files
from ._native_deletion import (
    _backend_binding,
    _issue_native_owner,
    _native_creation_handoff,
    _NativeOwnerFacts,
    _owned_delete_scope,
)
from ._runtime_probe import require_stopped_windows_gateways
from ._windows_profile import (
    LIMIT,
    MAX_EPOCH,
    ROLES,
    Manifest,
    Pending,
    Role,
    RoleRecord,
    RoleState,
    SchemaUpgrade,
    encode_manifest,
    encode_pending,
    encode_schema_upgrade,
    new_manifest,
    new_record,
    parse_manifest,
    parse_pending,
    parse_schema_upgrade,
)
from ._windows_profile import (
    CustodyError as CustodyError,
)
from .memory_crypto import MemoryCryptoError, looks_like_magic_line, unseal
from .wrap import NativeBackend

if TYPE_CHECKING:
    from .._database_lifecycle import ExclusiveLease


@dataclass
class _LiveSession:
    home: Path
    canonical: CanonicalSession
    tx: PrivateTransaction | None
    identity: FileIdentity | None
    sid: bytes
    process: tuple[int, int]
    backend: NativeBackend | None
    binding: tuple[object, ...] | None = None


_sessions: WeakKeyDictionary[WindowsCustodySession, _LiveSession] = WeakKeyDictionary()


MANIFEST = "windows-custody.json"
SCHEMA_PENDING = "windows-schema.pending.json"
WRAPPED = "memory-key.wrapped"
MARKER = "memory-vault.marker"
OPTOUT = "memory-vault.optout"


@dataclass(frozen=True)
class GenerationLease:
    profile_nonce: str
    role: Role
    generation: str
    epoch: int
    key_id: str
    native_key_id: str
    public_sha256: str


@dataclass(frozen=True)
class RoleStatus:
    """Checked read-only observation of one role; leases still need revalidation."""

    role: Role
    current: GenerationLease | None
    retained: tuple[GenerationLease, ...]
    pending: bool


@dataclass(frozen=True)
class RoleReset:
    """Generations positively deleted and committed, retained first, current last."""

    role: Role
    deleted: tuple[str, ...]


@dataclass(frozen=True)
class ProfileBinding:
    """Checked physical profile binding plus roles with unresolved journals."""

    home: FileIdentity
    sid: bytes
    profile_nonce: str
    epoch: int
    pending: tuple[Role, ...]


@dataclass(frozen=True)
class WindowsMemoryState:
    lease: GenerationLease | None
    marker: bytes | None
    optout: bytes | None
    wrapped_sha256: str | None

    @property
    def armed(self) -> bool:
        return self.marker is not None and self.optout is None


def windows_backend() -> NativeBackend:
    from . import _seckey_helper
    from ._seckey_backend import _SecKeyBackend

    ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_winkey_helper)
    if ops is None:
        raise CustodyError("Windows TPM helper unavailable; install the package-bound helper")
    return _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None)


def _read(tx: PrivateTransaction | None, name: str, limit: int = LIMIT) -> bytes | None:
    if tx is None:
        return None
    try:
        tx.stat(name)
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return None
        raise
    return tx.read_bytes(name, max_bytes=limit)


def _pending_name(role: Role) -> str:
    if role not in ROLES:
        raise CustodyError("unknown custody role")
    return f"windows-{role}.pending.json"


def _fingerprint(public: bytes) -> str:
    # Validate a real uncompressed P-256 point before recording authority.
    from cryptography.hazmat.primitives.asymmetric import ec

    if len(public) != 65 or public[0] != 4:
        raise CustodyError("invalid native public key")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
    except ValueError as exc:
        raise CustodyError("invalid native public key") from exc
    return hashlib.sha256(public).hexdigest()


@contextmanager
def windows_custody_session(
    home: Path,
    *,
    create: bool = False,
    canonical: CanonicalSession | None = None,
    backend: NativeBackend | None = None,
) -> Iterator[WindowsCustodySession]:
    """Own home -> mordred, or join an explicitly supplied checked coordinator."""
    with custody_scope(), ExitStack() as stack:
        if canonical is None:
            canonical = stack.enter_context(canonical_session(CanonicalPaths(home), scope="policy", create=create))
        else:
            # Directory admission/identity only: never recursively acquire the home lock.
            with open_optional_confidential_directory(home) as directory:
                identity = None if directory is None else directory.directory_identity()
                if identity != canonical.home_directory_identity():
                    raise CustodyError("canonical session belongs to another physical home")
        identity = canonical.home_directory_identity()
        tx = None
        if identity is not None:
            try:
                tx = stack.enter_context(canonical.borrow_mordred_transaction())
            except PrivateFSError as exc:
                if exc.reason != "missing" or create:
                    raise
        session = WindowsCustodySession(home, canonical, tx, identity, current_principal_id(), backend)
        _sessions[session] = _LiveSession(
            home, canonical, tx, identity, session._sid, (os.getpid(), threading.get_ident()), backend
        )
        session._bind_backend()
        try:
            yield session
            session.check()
        finally:
            session._live = False
            _sessions.pop(session, None)


class WindowsCustodySession:
    def __init__(
        self,
        home: Path,
        canonical: CanonicalSession,
        tx: PrivateTransaction | None,
        identity: FileIdentity | None,
        sid: bytes,
        backend: NativeBackend | None,
    ) -> None:
        self.home = home
        self.canonical = canonical
        self._tx = tx
        self._identity = identity
        self._sid = sid
        self._backend = backend
        self._live = True

    def check(self) -> None:
        record = _sessions.get(self)
        if not self._live or record is None:
            raise RuntimeError("Windows custody session is closed or unregistered")
        if record.process != (os.getpid(), threading.get_ident()):
            raise DatabaseRefused("Windows custody session changed process or thread")
        if (
            record.home != self.home
            or record.canonical is not self.canonical
            or record.tx is not self._tx
            or record.identity != self._identity
            or record.sid != self._sid
            or record.backend is not self._backend
        ):
            raise DatabaseRefused("Windows custody session binding changed")
        if (
            record.binding is not None
            and self._backend is not None
            and record.binding != _backend_binding(self._backend, "")
        ):
            raise DatabaseRefused("Windows native backend or store binding changed")
        if self.canonical.home_directory_identity() != self._identity or current_principal_id() != self._sid:
            raise CustodyError("Windows custody session identity changed")
        if self._tx is not None:
            self._tx.assert_private_admission()

    @property
    def backend(self) -> NativeBackend:
        self.check()
        if self._backend is None:
            self._backend = windows_backend()
            _sessions[self].backend = self._backend
            self._bind_backend()
        return self._backend

    def _bind_backend(self) -> None:
        # Only the concrete production backend can establish deletion-store
        # evidence. Other protocol implementations cannot receive authority.
        from ._seckey_backend import _SecKeyBackend

        if type(self._backend) is _SecKeyBackend:
            _sessions[self].binding = _backend_binding(self._backend, "")

    def _check_native_delete_owner(self, native_key_id: str, backend: NativeBackend) -> _NativeOwnerFacts:
        self.check()
        registered = _sessions[self]
        if backend is not self.backend or registered.binding != _backend_binding(backend, ""):
            raise DatabaseRefused("Windows native backend or store binding changed")
        manifest = self._manifest()
        if manifest is None:
            raise DatabaseRefused("Windows native ownership is absent")
        matches: list[tuple[Role, RoleRecord]] = []
        for role in ROLES:
            pending = self._pending(manifest, role)
            if pending is not None:
                if pending.record.native_key_id == native_key_id and pending.record.public_sha256 is not None:
                    matches.append((role, pending.record))
                # An unresolved role cannot authorize an unrelated generation.
                continue
            state = manifest.role(role)
            for record in state.retained + (() if state.current is None else (state.current,)):
                if record.native_key_id == native_key_id:
                    self.validate_lease(self.lease_for_native(role, native_key_id))
                    matches.append((role, record))
        if len(matches) != 1:
            raise DatabaseRefused("Windows native selector lacks exact checked ownership")
        role, record = matches[0]
        return _NativeOwnerFacts(
            home=self.home,
            role=role,
            generation=record.generation,
            database_home=self.home if role == "memory" else None,
        )

    def _memory_database_guard(self, database_lease: ExclusiveLease | None) -> None:
        self.check()
        from ._database_mutation import _assert_memory_database_mutation_safe

        _assert_memory_database_mutation_safe(home=self.home, database_lease=database_lease)

    def _transaction(self) -> PrivateTransaction:
        self.check()
        if self._tx is None:
            raise CustodyError("custody mutation requires an authorized existing directory")
        return self._tx

    def _manifest(self) -> Manifest | None:
        self.check()
        if _read(self._tx, SCHEMA_PENDING) is not None:
            raise CustodyError("custody schema upgrade requires explicit reconciliation")
        data = _read(self._tx, MANIFEST)
        if data is None:
            return None
        if self._identity is None:
            raise CustodyError("retained custody has no checked home")
        return parse_manifest(data, self._identity, self._sid)

    def upgrade_manifest_v2(self) -> None:
        """Resume a private metadata-only transaction without touching native keys."""
        self.check()
        raw = _read(self._tx, MANIFEST)
        journal_raw = _read(self._tx, SCHEMA_PENDING)
        if self._identity is None:
            raise CustodyError("schema upgrade requires a checked home")
        if raw is None:
            self._fresh_manifest_v2()
            return
        manifest = parse_manifest(raw, self._identity, self._sid)
        if any(_read(self._tx, _pending_name(role)) is not None for role in ROLES):
            raise CustodyError("reconcile pending role custody before schema upgrade")
        if manifest.version == 2 and journal_raw is None:
            return
        if manifest.version == 1:
            before = manifest
            after = replace(manifest, version=2, roles=(*manifest.roles, RoleState()))
        else:
            if manifest.role("mail") != RoleState():
                raise CustodyError("schema journal conflicts with mail ownership")
            before = replace(manifest, version=1, roles=manifest.roles[:3])
            after = manifest
        expected = SchemaUpgrade(
            "intent",
            hashlib.sha256(encode_manifest(before)).hexdigest(),
            hashlib.sha256(encode_manifest(after)).hexdigest(),
        )
        journal = self._schema_upgrade_intent(expected, journal_raw)
        if manifest.version == 1:
            if journal.phase != "intent":
                raise CustodyError("published schema journal conflicts with old manifest")
            self._save(after)
        if journal.phase != "published":
            self._publish(SCHEMA_PENDING, encode_schema_upgrade(replace(expected, phase="published")))
        self._remove(SCHEMA_PENDING)

    def _fresh_manifest_v2(self) -> None:
        # A missing manifest alone is not absence. Refuse all non-coordinator
        # entries, including unknown/staged ownership, source stores and backups.
        from .._database_inventory import scan_dependencies

        if self._transaction().list_names(max_entries=4096):
            raise CustodyError("retained custody without a manifest requires reconciliation")
        self._validate_memory(None)
        inventory = scan_dependencies(self.home)
        if not inventory.complete or inventory.entries:
            raise CustodyError("retained database state without custody requires reconciliation")
        if self._identity is None:
            raise CustodyError("schema initialization requires a checked home")
        manifest = new_manifest(self._identity, self._sid)
        self._save(replace(manifest, version=2, roles=(*manifest.roles, RoleState())), create=True)

    def _schema_upgrade_intent(self, expected: SchemaUpgrade, raw: bytes | None) -> SchemaUpgrade:
        if raw is None:
            self._publish(SCHEMA_PENDING, encode_schema_upgrade(expected), create=True)
            return expected
        journal = parse_schema_upgrade(raw)
        if replace(journal, phase="intent") != expected:
            raise CustodyError("schema journal conflicts with retained ownership")
        return journal

    def _pending(self, manifest: Manifest, role: Role) -> Pending | None:
        data = _read(self._tx, _pending_name(role))
        return None if data is None else parse_pending(data, manifest, role)

    def _publish(self, name: str, data: bytes, *, create: bool = False) -> None:
        tx = self._transaction()
        with self.canonical.publication_receipt() as receipt:
            if create:
                tx.create_bytes(name, data)
            else:
                tx.replace_bytes(name, data)
            receipt.mark_published()
            if tx.read_bytes(name, max_bytes=LIMIT) != data:
                raise PrivateFSError("unsafe", "custody_publication", commit_state="uncertain")

    def _save(self, manifest: Manifest, *, create: bool = False) -> None:
        # Apply the same strict parser to in-memory proposals before publication.
        data = encode_manifest(manifest)
        parse_manifest(data, manifest.home, manifest.sid)
        self._publish(MANIFEST, data, create=create)

    def _journal(self, pending: Pending, *, create: bool = False) -> None:
        self._publish(_pending_name(pending.role), encode_pending(pending), create=create)

    def _remove(self, name: str) -> None:
        tx = self._transaction()
        tx.delete_file(name, expected_identity=tx.stat(name).identity)

    def _validate_memory(self, key: bytes | None) -> None:
        if key is not None and (not isinstance(key, bytes) or len(key) != 32):
            raise CustodyError("memory key must be exactly 32 bytes")
        if self._identity is None:
            return
        for snapshot in inventory_memory_files(self.home):
            if looks_like_magic_line(snapshot.data.decode("utf-8", "surrogateescape")):
                if key is None:
                    raise CustodyError("sealed memory requires explicit authenticated key adoption")
                try:
                    unseal(snapshot.data, key=key, name=snapshot.name)
                except MemoryCryptoError as exc:
                    raise CustodyError("retained memory does not authenticate") from exc

    def _fresh_memory(self, key: bytes | None) -> None:
        for name in (WRAPPED, MARKER, OPTOUT, _pending_name("memory")):
            if _read(self._tx, name) is not None:
                raise CustodyError("retained memory custody requires reconciliation, never regeneration")
        self._validate_memory(key)

    def _ensure_manifest(self) -> Manifest:
        manifest = self._manifest()
        if manifest is None:
            if any(_read(self._tx, _pending_name(role)) is not None for role in ROLES):
                raise CustodyError("orphan custody journal must be preserved")
            if self._identity is None:
                raise CustodyError("custody requires a checked existing home")
            manifest = new_manifest(self._identity, self._sid)
            self._save(manifest, create=True)
        return manifest

    def lease(self, role: Role, *, generation: str | None = None) -> GenerationLease:
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("custody ownership is absent")
        if self._pending(manifest, role) is not None:
            raise CustodyError("custody role has an unresolved journal")
        state = manifest.role(role)
        record = state.current
        if generation is not None:
            record = next(
                (
                    r
                    for r in state.retained + (() if state.current is None else (state.current,))
                    if r.generation == generation
                ),
                None,
            )
        if record is None or record.public_sha256 is None:
            raise CustodyError("custody generation is not owned")
        return GenerationLease(
            manifest.profile_nonce,
            role,
            record.generation,
            record.epoch,
            record.key_id,
            record.native_key_id,
            record.public_sha256,
        )

    def lease_for_native(self, role: Role, native_key_id: str) -> GenerationLease:
        """Resolve only an exact current/retained selector in this checked profile.

        Header input never authorizes arbitrary native lookup. Reuse ``lease``
        so unresolved journals and incomplete records refuse identically.
        """
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("custody ownership is absent")
        state = manifest.role(role)
        records = state.retained + (() if state.current is None else (state.current,))
        for record in records:
            if record.native_key_id == native_key_id:
                return self.lease(role, generation=record.generation)
        raise CustodyError("native selector is not owned by this custody role/profile")

    def validate_lease(self, lease: GenerationLease) -> None:
        if self.lease(lease.role, generation=lease.generation) != lease:
            raise CustodyError("custody generation lease changed")

    def profile_binding(self) -> ProfileBinding:
        """Bound manifest identity, SID, nonce and epoch; no inventory or native call."""
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("custody ownership is absent")
        pending = tuple(role for role in ROLES if self._pending(manifest, role) is not None)
        return ProfileBinding(manifest.home, manifest.sid, manifest.profile_nonce, manifest.epoch, pending)

    def memory_state(self) -> WindowsMemoryState:
        """Checked flat state only; no inventory, enrollment or native operation."""
        manifest = self._manifest()
        marker = _read(self._tx, MARKER, 4096)
        optout = _read(self._tx, OPTOUT, 4096)
        wrapped = _read(self._tx, WRAPPED, wrap.HEADER_LEN)
        if manifest is None or manifest.role("memory") == RoleState():
            if any(value is not None for value in (marker, optout, wrapped, _read(self._tx, _pending_name("memory")))):
                raise CustodyError("retained memory state has no committed ownership")
            lease = None
        else:
            lease = self.lease("memory")
            if wrapped is None:
                raise CustodyError("retained memory ownership has lost its wrapper")
        return WindowsMemoryState(
            lease, marker, optout, None if wrapped is None else hashlib.sha256(wrapped).hexdigest()
        )

    def backend_for(self, lease: GenerationLease) -> NativeBackend:
        self.validate_lease(lease)
        backend = self.backend
        if _fingerprint(backend.get_enclave_public_key(lease.native_key_id)) != lease.public_sha256:
            raise CustodyError("native public key differs from retained ownership")
        return backend

    def memory_source_record(self) -> tuple[GenerationLease, bytes]:
        """Observe one committed source without native lookup or hook arming."""
        manifest = self._manifest()
        if manifest is None or manifest.role("memory").retained:
            raise CustodyError("database memory source requires one committed generation")
        lease = self.lease("memory")
        wrapped = _read(self._tx, WRAPPED, wrap.HEADER_LEN)
        if wrapped is None:
            raise CustodyError("database memory source wrapper is absent")
        try:
            wrap._parse_header(wrapped, lease.native_key_id)
        except WrapParseError as exc:
            raise CustodyError("database memory source wrapper is invalid") from exc
        return lease, wrapped

    def load_memory_key(self) -> bytes:
        lease = self.lease("memory")
        blob = _read(self._tx, WRAPPED, wrap.HEADER_LEN)
        if blob is None:
            raise CustodyError("retained memory ownership has lost its wrapper; refusing regeneration")
        return wrap.unwrap_dek(
            blob, lease.native_key_id, backend=self.backend_for(lease), audit_sink=lambda entry: None
        )

    def resolve_memory_key(self) -> bytes | None:
        manifest = self._manifest()
        if manifest is not None and manifest.role("memory") != RoleState():
            return self.load_memory_key()
        self._fresh_memory(None)
        # Orphan journals for other roles still cannot be hidden as fresh state.
        if manifest is None and any(_read(self._tx, _pending_name(role)) is not None for role in ROLES):
            raise CustodyError("orphan custody state")
        return None

    def _begin(
        self, role: Role, *, retain_current: bool = False, database_lease: ExclusiveLease | None = None
    ) -> tuple[Manifest, Pending]:
        if role == "memory":
            self._memory_database_guard(database_lease)
        manifest = self._ensure_manifest()
        if self._pending(manifest, role) is not None:
            raise CustodyError("pending custody enrollment requires explicit reconciliation")
        state = manifest.role(role)
        if (state.current is not None or state.retained) and not retain_current:
            raise CustodyError("custody role already has retained ownership")
        if retain_current and role == "memory":
            raise CustodyError("memory generation rotation requires migration")
        if retain_current and state.current is not None and sum(len(manifest.role(r).retained) for r in ROLES) >= 64:
            raise CustodyError("retained custody generation limit reached")
        pending = Pending(manifest.profile_nonce, role, "create", "intent", new_record(manifest, role))
        self._journal(pending, create=True)
        return manifest, pending

    def _verify(
        self,
        pending: Pending,
        *,
        generated_public: bytes | None = None,
        database_lease: ExclusiveLease | None = None,
    ) -> Pending:
        with _native_creation_handoff(pending.record.native_key_id):
            public = self.backend.get_enclave_public_key(pending.record.native_key_id)
            fingerprint = _fingerprint(public)
            if generated_public is not None and generated_public != public:
                raise CustodyError("native creation public key changed")
            if pending.record.public_sha256 is not None and pending.record.public_sha256 != fingerprint:
                raise CustodyError("journaled native public key changed")
            # A public lookup is not positive possession; prove exact ECDH in RAM.
            challenge = secrets.token_bytes(32)
            proof = wrap.wrap_dek(challenge, pending.record.native_key_id, backend=self.backend)
            if (
                wrap.unwrap_dek(
                    proof, pending.record.native_key_id, backend=self.backend, audit_sink=lambda entry: None
                )
                != challenge
            ):
                raise CustodyError("native possession proof failed")
            verified = replace(pending, phase="verified", record=replace(pending.record, public_sha256=fingerprint))
            if pending.role == "memory":
                self._memory_database_guard(database_lease)
            self._journal(verified)
            return verified

    def _commit(
        self, manifest: Manifest, pending: Pending, *, database_lease: ExclusiveLease | None = None
    ) -> GenerationLease:
        if pending.role == "memory":
            self._memory_database_guard(database_lease)
        state = manifest.role(pending.role)
        if state.current != pending.record:
            retained = state.retained + (() if state.current is None else (state.current,))
            manifest = manifest.with_role(
                pending.role, RoleState(pending.record, retained), epoch=max(manifest.epoch, pending.record.epoch)
            )
            self._save(manifest)
        self._remove(_pending_name(pending.role))
        return self.lease(pending.role)

    def _publish_memory_key(
        self, pending: Pending, key: bytes, *, database_lease: ExclusiveLease | None = None
    ) -> None:
        blob = wrap.wrap_dek(key, pending.record.native_key_id, backend=self.backend)
        if (
            wrap.unwrap_dek(blob, pending.record.native_key_id, backend=self.backend, audit_sink=lambda entry: None)
            != key
        ):
            raise CustodyError("memory wrap verification failed")
        self._memory_database_guard(database_lease)
        self._publish(WRAPPED, blob, create=True)

    def enroll_memory(self, *, adopted_key: bytes | None = None, database_lease: ExclusiveLease | None = None) -> bytes:
        self._memory_database_guard(database_lease)
        self._fresh_memory(adopted_key)
        backend = self.backend  # Discover the executable before any native intent exists.
        manifest, pending = self._begin("memory", database_lease=database_lease)
        # The durable intent can expose newly observed database dependencies.
        # Refuse before creating a native key while retaining that evidence.
        self._memory_database_guard(database_lease)
        with self.canonical.publication_receipt() as receipt:
            # The native call can publish even if its response is lost. Keep
            # subsequent ledger failures sticky through the owning coordinator.
            receipt.mark_published()
            public = backend.generate_enclave_key(pending.record.native_key_id, unattended=True)
            pending = self._verify(pending, generated_public=public, database_lease=database_lease)
            key = secrets.token_bytes(32) if adopted_key is None else adopted_key
            self._publish_memory_key(pending, key, database_lease=database_lease)
            self._commit(manifest, pending, database_lease=database_lease)
            return key

    def enroll_role(self, role: Role, *, retain_current: bool = False) -> GenerationLease:
        if role == "memory":
            raise CustodyError("use explicit memory enrollment")
        backend = self.backend
        manifest, pending = self._begin(role, retain_current=retain_current)
        with self.canonical.publication_receipt() as receipt:
            receipt.mark_published()
            public = backend.generate_enclave_key(pending.record.native_key_id, unattended=True)
            return self._commit(manifest, self._verify(pending, generated_public=public))

    def _delete_guard(self, role: Role, *, erase_authorized: bool, deleted: bool = False) -> None:
        if role == "memory":
            require_stopped_windows_gateways(self.home)
            if _read(self._tx, MARKER) is not None or (not deleted and _read(self._tx, OPTOUT) is None):
                raise CustodyError("memory must be explicitly disabled before deleting custody")
            self._validate_memory(None)
        elif not erase_authorized:
            raise CustodyError("retained audit or Telegram history requires explicit erasure authorization")

    def delete_role(
        self,
        lease: GenerationLease,
        *,
        erase_authorized: bool = False,
        database_lease: ExclusiveLease | None = None,
    ) -> None:
        if lease.role == "memory":
            self._memory_database_guard(database_lease)
        self.validate_lease(lease)
        self._delete_guard(lease.role, erase_authorized=erase_authorized)
        manifest = self._manifest()
        assert manifest is not None
        if manifest.epoch == MAX_EPOCH:
            raise CustodyError("custody lifecycle epoch exhausted; refusing irreversible deletion")
        record = RoleRecord(lease.generation, lease.epoch, lease.key_id, lease.native_key_id, lease.public_sha256)
        pending = Pending(manifest.profile_nonce, lease.role, "delete", "intent", record)
        backend = self.backend
        owner = _issue_native_owner(self, native_key_id=lease.native_key_id, backend=backend)
        self.backend_for(lease)
        # Check final inventory before publishing even the deletion intent.
        with _owned_delete_scope(owner, backend=backend, database_lease=database_lease):
            pass
        self._journal(pending, create=True)
        with self.canonical.publication_receipt() as receipt:
            receipt.mark_published()
            with _owned_delete_scope(owner, backend=backend, database_lease=database_lease) as deletion:
                backend.delete_enclave_key(lease.native_key_id, deletion=deletion)
            pending = replace(pending, phase="deleted")
            if pending.role == "memory":
                self._memory_database_guard(database_lease)
            self._journal(pending)
            self._finish_delete(manifest, pending, database_lease=database_lease)

    def _finish_delete(
        self, manifest: Manifest, pending: Pending, *, database_lease: ExclusiveLease | None = None
    ) -> None:
        if pending.phase != "deleted":
            raise CustodyError("native deletion has not been positively recorded")
        if pending.role == "memory":
            self._memory_database_guard(database_lease)
            if _read(self._tx, WRAPPED, wrap.HEADER_LEN) is not None:
                self._remove(WRAPPED)
            if _read(self._tx, OPTOUT) is not None:
                self._remove(OPTOUT)
        state = manifest.role(pending.role)
        current = state.current
        if current is not None and current.generation == pending.record.generation:
            if current != pending.record:
                raise CustodyError("deletion journal conflicts with current ownership")
            current = None
        retained = tuple(row for row in state.retained if row.generation != pending.record.generation)
        if current != state.current or retained != state.retained:
            self._save(manifest.with_role(pending.role, RoleState(current, retained), epoch=manifest.epoch + 1))
        self._remove(_pending_name(pending.role))

    def role_status(self, role: Role) -> RoleStatus:
        """Observe one role from the complete checked manifest; no native operation."""
        _pending_name(role)
        manifest = self._manifest()
        if manifest is None:
            if any(_read(self._tx, _pending_name(name)) is not None for name in ROLES):
                raise CustodyError("orphan custody journal must be preserved")
            return RoleStatus(role, None, (), False)
        state = manifest.role(role)

        def observed(record: RoleRecord) -> GenerationLease:
            if record.public_sha256 is None:
                raise CustodyError("custody generation is not owned")
            return GenerationLease(
                manifest.profile_nonce,
                role,
                record.generation,
                record.epoch,
                record.key_id,
                record.native_key_id,
                record.public_sha256,
            )

        return RoleStatus(
            role,
            None if state.current is None else observed(state.current),
            tuple(observed(record) for record in state.retained),
            self._pending(manifest, role) is not None,
        )

    def _reset_leases(self, role: Role, *, erase_authorized: bool) -> tuple[GenerationLease, ...]:
        status = self.role_status(role)
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("custody ownership is absent; nothing to reset")
        for name in ROLES:
            self._pending(manifest, name)  # validate every role journal before mutation
        if status.pending:
            raise CustodyError("custody role has an unresolved journal; reconcile before reset")
        leases = status.retained + (() if status.current is None else (status.current,))
        if not leases:
            raise CustodyError("custody role has no owned generation to reset")
        if role == "memory":
            self._memory_reset_guard(status)
        elif not erase_authorized:
            raise CustodyError("audit or Telegram reset requires explicit erasure authorization")
        return leases

    def _memory_reset_guard(self, status: RoleStatus) -> None:
        """Memory reset never crypto-shreds; ``erase_authorized`` relaxes nothing here."""
        if status.retained:
            # Flat memory owns one wrapper; retained memory records are unexpected.
            raise CustodyError("memory reset refuses unexpected retained memory generations; reconcile them in C6")
        # ``memory_state`` fails closed on a lost wrapper or retained evidence.
        if self.memory_state().marker is not None:
            raise CustodyError("memory reset refuses while a memory marker exists; disable memory through C6 first")
        try:
            self._validate_memory(None)
        except CustodyError as exc:
            raise CustodyError(
                "memory reset refuses while sealed memory remains; decrypt it through the C6 disable ceremony first"
            ) from exc

    def reset_role(
        self,
        role: Role,
        *,
        erase_authorized: bool = False,
        database_lease: ExclusiveLease | None = None,
    ) -> RoleReset:
        """Delete every owned generation of exactly one role through ``delete_role``.

        All refusals happen before the first deletion journal. Each generation
        uses its own ``delete_role`` journal, so an ambiguous native result
        stays unresolved and blocks the next reset; a failure before that
        journal leaves the generation owned. Memory files are never decrypted
        or deleted; other roles and the permanent directory lock are untouched.
        Audit/Telegram reset does not consult the gateway inventory (callers gate).
        """
        if role == "memory":
            self._memory_database_guard(database_lease)
        leases = self._reset_leases(role, erase_authorized=erase_authorized)
        deleted: list[str] = []
        for lease in leases:
            try:
                self.delete_role(lease, erase_authorized=erase_authorized, database_lease=database_lease)
            except BaseException as exc:
                exc.add_note(
                    f"Windows {role} custody reset stopped after {len(deleted)} confirmed deletion(s); "
                    "if the failed generation's intent journal was written it is retained for explicit "
                    "reconciliation, otherwise no deletion journal was written and that generation remains owned"
                )
                raise
            deleted.append(lease.generation)
        return RoleReset(role, tuple(deleted))

    def reconcile_pending(
        self,
        role: Role,
        *,
        adopted_key: bytes | None = None,
        erase_authorized: bool = False,
        database_lease: ExclusiveLease | None = None,
    ) -> GenerationLease | None:
        if role == "memory":
            self._memory_database_guard(database_lease)
        manifest = self._manifest()
        if manifest is None:
            raise CustodyError("journal cannot be reconciled without bound profile ownership")
        pending = self._pending(manifest, role)
        if pending is None:
            raise CustodyError("no custody journal to reconcile")
        if pending.operation == "delete":
            self._delete_guard(role, erase_authorized=erase_authorized, deleted=pending.phase == "deleted")
            if pending.phase != "deleted":
                # A missing key after a lost deletion result is ambiguous. Do not
                # retry an irreversible native action or infer successful absence.
                raise CustodyError("native deletion outcome is unresolved; preserve the intent journal")
            self._finish_delete(manifest, pending, database_lease=database_lease)
            return None
        current = manifest.role(role).current
        if current is not None and current.generation == pending.record.generation and current != pending.record:
            raise CustodyError("journal conflicts with committed custody")
        blob = _read(self._tx, WRAPPED, wrap.HEADER_LEN) if role == "memory" else None
        key = adopted_key
        if role == "memory":
            key = self._recovery_memory_key(pending, blob, adopted_key)
        pending = self._verify(pending, database_lease=database_lease)
        if role == "memory" and blob is None:
            self._publish_memory_key(
                pending, secrets.token_bytes(32) if key is None else key, database_lease=database_lease
            )
        return self._commit(manifest, pending, database_lease=database_lease)

    def _recovery_memory_key(self, pending: Pending, blob: bytes | None, adopted_key: bytes | None) -> bytes | None:
        key = adopted_key
        if blob is not None:
            key = wrap.unwrap_dek(
                blob, pending.record.native_key_id, backend=self.backend, audit_sink=lambda entry: None
            )
            if adopted_key is not None and adopted_key != key:
                raise CustodyError("adopted key conflicts with retained wrapper")
        elif _read(self._tx, MARKER) is not None or _read(self._tx, OPTOUT) is not None:
            raise CustodyError("retained memory marker without wrapper cannot be reconciled")
        self._validate_memory(key)
        return key


def load_windows_memory_key(*, home: Path, backend: NativeBackend | None = None) -> bytes:
    with windows_custody_session(home, backend=backend) as session:
        return session.load_memory_key()


def resolve_windows_memory_key(*, home: Path) -> bytes | None:
    with windows_custody_session(home) as session:
        return session.resolve_memory_key()


def upgrade_manifest_v2(*, home: Path) -> None:
    """Explicitly upgrade or initialize fresh custody; never called by read/status."""
    with windows_custody_session(home, create=True) as session:
        session.upgrade_manifest_v2()
