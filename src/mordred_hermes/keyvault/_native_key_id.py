"""Profile-scoped native wrapping-key identifiers.

The public/keyvault ``key_id`` is a logical wire identifier.  It is bound into
MRKW/MREN blobs and portable backups and therefore must remain stable across
machines.  Native key stores are machine-global on some backends (notably the
macOS Keychain), so using that logical id as the physical lookup id lets two
``HERMES_HOME`` profiles collide.

New keyvaults store the deterministic physical id returned by
:func:`scoped_native_key_id` in their metadata.  Metadata written by older
versions has no such field and continues to address the legacy logical id for
read/ECDH compatibility.  Absence is the *only* legacy marker: a present value
must exactly match the id derived for the current root, preventing edited
metadata from selecting or deleting an arbitrary native key.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from ._exceptions import WrapKeyNotFound

if TYPE_CHECKING:
    from ._native_deletion import NativeDeletePermit, ValidatedNativeOwner
    from .wrap import NativeBackend

NATIVE_KEY_ID_FIELD: Final = "native_key_id"
"""Metadata/header field carrying the physical native-store identifier."""

PENDING_NATIVE_KEY_FIELD: Final = "pending_native_key"
"""Top-level meta field journaling ownership before native generation."""

AUDIT_KEY_FIELD: Final = "audit_key"
"""Top-level committed ownership record for the scoped audit wrapping key."""

PENDING_AUDIT_KEY_FIELD: Final = "pending_audit_key"
"""Top-level pre-generation ownership journal for the audit wrapping key."""

_NATIVE_OWNERSHIP_META_FIELDS: Final = frozenset(
    {
        PENDING_NATIVE_KEY_FIELD,
        AUDIT_KEY_FIELD,
        PENDING_AUDIT_KEY_FIELD,
    }
)
"""Top-level fields proving or journaling profile-owned native keys."""

_NATIVE_KEY_ID_PREFIX: Final = "mordred-hermes.native.v1."
_RESERVED_MAIN_KEY_IDS: Final = frozenset({"mordred.audit-log"})
"""Logical ids owned by internal auxiliary keys, never by the main vault."""


class NativeKeyIdMismatch(ValueError):
    """A persisted physical id does not belong to this profile/logical id."""


class InvalidMainKeyId(ValueError):
    """A caller supplied an unusable or internally-reserved main key id."""


def validate_main_key_id(logical_key_id: object) -> str:
    """Validate and return a logical id suitable for the main keyvault key.

    The audit-log wrapping key shares the profile-scoped native namespace
    with the main wrapping key, so allowing its reserved logical id here
    would collapse two trust roles onto one physical key.  Empty ids are
    rejected as well: they cannot be represented by the durable pending-key
    journal used to recover interrupted provisioning.
    """

    if not isinstance(logical_key_id, str) or not logical_key_id:
        raise InvalidMainKeyId("key_id must be a non-empty string")
    try:
        logical_key_id.encode("utf-8")
    except UnicodeEncodeError:
        # JSON can represent lone UTF-16 surrogates, but every key-id hash and
        # wire format in this package is defined over UTF-8. Reject such a
        # value at the common boundary instead of leaking a raw codec error
        # later during hashing or native-selector derivation.
        raise InvalidMainKeyId("key_id must be valid UTF-8 text") from None
    if logical_key_id in _RESERVED_MAIN_KEY_IDS:
        raise InvalidMainKeyId("key_id is reserved for an internal keyvault role")
    return logical_key_id


def has_native_key_ownership_state(meta: Mapping[str, object]) -> bool:
    """Return whether metadata contains any main or auxiliary ownership.

    A keyvault is fresh only when both its main ``keys`` mapping and every
    top-level provisioning/ownership record are absent or empty.  In
    particular, a manually damaged or interrupted profile must not be
    re-initialized merely because its main row disappeared while an audit-key
    record survived.
    """

    return bool(meta.get("keys")) or any(field in meta for field in _NATIVE_OWNERSHIP_META_FIELDS)


def _normalized_root(root: Path) -> str:
    """Return a canonical profile spelling without following the root leaf.

    Resolving only the parent makes benign aliases such as macOS ``/tmp`` →
    ``/private/tmp`` (or an explicitly symlinked home directory) select one
    physical native key.  The managed keyvault root itself remains unresolved;
    keyvault path-safety checks reject a symlink planted at that leaf.
    """

    absolute = Path(os.path.abspath(os.fspath(root)))
    return os.fspath(absolute.parent.resolve(strict=False) / absolute.name)


def _native_key_id_for_root_name(root_name: str, logical_key_id: str) -> str:
    """Derive the physical id from an already-normalized profile name."""

    if not isinstance(logical_key_id, str) or not logical_key_id:
        raise NativeKeyIdMismatch("logical native key id must be a non-empty string")
    try:
        logical_bytes = logical_key_id.encode("utf-8")
    except UnicodeEncodeError:
        raise NativeKeyIdMismatch("logical native key id must be valid UTF-8 text") from None
    # Filesystem paths use the platform's filesystem encoding with
    # surrogateescape. ``os.fsencode`` therefore remains deterministic for a
    # valid POSIX byte path that is not representable as strict UTF-8.
    root_bytes = os.fsencode(root_name)
    profile_digest = hashlib.sha256(b"mordred-hermes.native-profile.v1\0" + root_bytes).hexdigest()[:32]
    logical_digest = hashlib.sha256(b"mordred-hermes.native-logical.v1\0" + logical_bytes).hexdigest()[:32]
    return f"{_NATIVE_KEY_ID_PREFIX}{profile_digest}.{logical_digest}"


def scoped_native_key_id(root: Path, logical_key_id: str) -> str:
    """Physical native-store id unique to ``root`` and ``logical_key_id``.

    Both components are hashed independently with domain separation.  The
    cleartext profile path and logical id therefore never cross the native
    helper/Keychain boundary.
    """

    return _native_key_id_for_root_name(_normalized_root(root), logical_key_id)


def persisted_native_key_id(
    root: Path,
    logical_key_id: str,
    persisted: object,
) -> str:
    """Resolve and validate a persisted physical id.

    The caller invokes this only when the field is present.  Its value must be
    a string equal to the deterministic current-profile id; arbitrary,
    cross-profile, or JSON-null identifiers fail closed.
    """

    expected = scoped_native_key_id(root, logical_key_id)
    if persisted == expected:
        return expected

    # Backward compatibility for scoped rows written before profile paths
    # canonicalized parent-directory aliases.  Accept only the deterministic
    # id for this exact absolute spelling; new writes always use ``expected``.
    legacy_root_name = os.path.abspath(os.fspath(root))
    legacy_expected = _native_key_id_for_root_name(legacy_root_name, logical_key_id)
    if persisted != legacy_expected:
        raise NativeKeyIdMismatch("native_key_id does not match this keyvault profile and logical key id")
    return legacy_expected


def native_key_id_from_row(
    root: Path,
    logical_key_id: str,
    row: Mapping[str, object],
) -> str:
    """Resolve a metadata row, treating only a missing field as legacy."""

    if NATIVE_KEY_ID_FIELD not in row:
        return logical_key_id
    return persisted_native_key_id(root, logical_key_id, row[NATIVE_KEY_ID_FIELD])


def pending_native_key_from_meta(
    root: Path,
    meta: Mapping[str, object],
) -> tuple[str, str] | None:
    """Validate and return the durable pre-generation ownership journal."""

    if PENDING_NATIVE_KEY_FIELD not in meta:
        return None
    pending = meta[PENDING_NATIVE_KEY_FIELD]
    if not isinstance(pending, Mapping) or set(pending) != {"key_id", NATIVE_KEY_ID_FIELD}:
        raise NativeKeyIdMismatch("pending native-key ownership journal is malformed")
    logical_key_id = pending["key_id"]
    if not isinstance(logical_key_id, str) or not logical_key_id:
        raise NativeKeyIdMismatch("pending native-key logical id is malformed")
    physical = persisted_native_key_id(root, logical_key_id, pending[NATIVE_KEY_ID_FIELD])
    return logical_key_id, physical


def add_pending_native_key(
    root: Path,
    meta: dict[str, object],
    logical_key_id: str,
) -> str:
    """Add the pre-generation journal to ``meta`` and return its physical id."""

    validate_main_key_id(logical_key_id)
    if PENDING_NATIVE_KEY_FIELD in meta:
        raise NativeKeyIdMismatch("a pending native-key ownership journal already exists")
    physical = scoped_native_key_id(root, logical_key_id)
    meta[PENDING_NATIVE_KEY_FIELD] = {
        "key_id": logical_key_id,
        NATIVE_KEY_ID_FIELD: physical,
    }
    return physical


def _audit_key_record_from_meta(
    root: Path,
    meta: Mapping[str, object],
    *,
    field: str,
    logical_key_id: str,
) -> str | None:
    """Validate one exact audit ownership record and return its physical id."""

    if field not in meta:
        return None
    record = meta[field]
    if not isinstance(record, Mapping) or set(record) != {"key_id", NATIVE_KEY_ID_FIELD}:
        raise NativeKeyIdMismatch(f"{field} ownership record is malformed")
    if record["key_id"] != logical_key_id:
        raise NativeKeyIdMismatch(f"{field} logical id does not match the audit key")
    return persisted_native_key_id(root, logical_key_id, record[NATIVE_KEY_ID_FIELD])


def pending_audit_key_from_meta(
    root: Path,
    meta: Mapping[str, object],
    logical_key_id: str,
) -> str | None:
    """Validate and return the audit key's pre-generation journal."""

    return _audit_key_record_from_meta(
        root,
        meta,
        field=PENDING_AUDIT_KEY_FIELD,
        logical_key_id=logical_key_id,
    )


def committed_audit_key_from_meta(
    root: Path,
    meta: Mapping[str, object],
    logical_key_id: str,
) -> str | None:
    """Validate and return the audit key's durable ownership record."""

    return _audit_key_record_from_meta(
        root,
        meta,
        field=AUDIT_KEY_FIELD,
        logical_key_id=logical_key_id,
    )


def add_pending_audit_key(
    root: Path,
    meta: dict[str, object],
    logical_key_id: str,
) -> str:
    """Add the audit key's pre-generation journal and return its physical id."""

    if PENDING_AUDIT_KEY_FIELD in meta:
        raise NativeKeyIdMismatch("a pending audit-key ownership journal already exists")
    physical = scoped_native_key_id(root, logical_key_id)
    meta[PENDING_AUDIT_KEY_FIELD] = {
        "key_id": logical_key_id,
        NATIVE_KEY_ID_FIELD: physical,
    }
    return physical


def add_committed_audit_key(
    root: Path,
    meta: dict[str, object],
    logical_key_id: str,
    native_key_id: str,
) -> None:
    """Publish the audit ownership row while retaining its pending journal."""

    expected_pending = pending_audit_key_from_meta(root, meta, logical_key_id)
    if expected_pending != native_key_id:
        raise NativeKeyIdMismatch("audit-key ownership commit does not match its pending journal")
    persisted_native_key_id(root, logical_key_id, native_key_id)
    meta[AUDIT_KEY_FIELD] = {
        "key_id": logical_key_id,
        NATIVE_KEY_ID_FIELD: native_key_id,
    }


def bind_backend_to_root(backend: NativeBackend, root: Path) -> NativeBackend:
    """Bind helper-backed production I/O to ``root``'s native blob store.

    PyObjC/software backends are machine-global and need only the scoped
    physical id.  File-backed SE/TPM helpers additionally select their store
    through an environment variable; the production backend exposes a private
    clone seam so an explicit API ``home=`` cannot accidentally write into the
    ambient ``HERMES_HOME`` store.  Third-party/test backends are returned
    unchanged.
    """

    binder = getattr(backend, "_for_keyvault_root", None)
    if callable(binder):
        bound = binder(root)
        return cast("NativeBackend", bound)
    return backend


class _LegacyReadFallbackBackend:
    """Read a legacy key from the bound store, then its historical store.

    Before explicit high-level ``home=`` was propagated to file-backed
    helpers, those helpers selected their store from ambient ``HERMES_HOME``.
    A legacy metadata row has no profile-scoped physical id, so it is safe to
    try that original backend only after the correctly root-bound lookup says
    the logical id is absent.  Scoped ids must never use this fallback.

    Generation and deletion deliberately stay bound to the selected profile;
    this adapter only broadens public-key/ECDH reads needed to recover and
    migrate old data.
    """

    __slots__ = ("_fallback", "_primary")

    def __init__(self, primary: NativeBackend, fallback: NativeBackend) -> None:
        self._primary = primary
        self._fallback = fallback

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        return self._primary.generate_enclave_key(key_id, unattended=unattended)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        try:
            return self._primary.get_enclave_public_key(key_id)
        except WrapKeyNotFound:
            return self._fallback.get_enclave_public_key(key_id)

    def delete_enclave_key(self, key_id: str, *, deletion: NativeDeletePermit | None = None) -> None:
        self._primary.delete_enclave_key(key_id, deletion=deletion)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        try:
            return self._primary.enclave_ecdh(key_id, peer_pub)
        except WrapKeyNotFound:
            return self._fallback.enclave_ecdh(key_id, peer_pub)


def backend_for_persisted_key(
    backend: NativeBackend,
    root: Path,
    logical_key_id: str,
    native_key_id: str,
) -> NativeBackend:
    """Bind a backend to ``root``, with read fallback only for legacy rows.

    ``native_key_id == logical_key_id`` is the validated legacy marker
    returned by :func:`native_key_id_from_row` (or an equivalent legacy audit
    header).  Current scoped ids use the root-bound backend exclusively, so an
    unrelated ambient helper store can never satisfy a missing scoped lookup.
    """

    bound = bind_backend_to_root(backend, root)
    if native_key_id != logical_key_id or bound is backend:
        return bound
    return _LegacyReadFallbackBackend(bound, backend)


def _checked_main_logical(logical: object) -> str:
    value = validate_main_key_id(logical)
    # These namespaces belong to independent managed custody producers. Their
    # opaque selectors must never gain main-key permission through a metadata row.
    if value.startswith(("mordred-hermes.", "mordred.windows.", "mordred.memory", "mordred.vault")):
        raise NativeKeyIdMismatch("managed native selectors cannot be generic main keys")
    return value


def _unique_ownership_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NativeKeyIdMismatch("ownership record contains duplicate JSON fields")
        result[key] = value
    return result


def _checked_metadata_targets(root: Path) -> dict[str, str]:
    """Read exact profile ownership; never infer a key from a known name."""
    from . import _storage
    from .log_encryption import AUDIT_LOG_KEY_ID

    json.loads(_storage.safe_read(root / "meta.json"), object_pairs_hook=_unique_ownership_object)
    meta = _storage.load_meta(root)
    targets: dict[str, str] = {}
    pending = pending_native_key_from_meta(root, meta)
    for key_hash, row in meta["keys"].items():
        if not isinstance(row, dict):
            raise NativeKeyIdMismatch("main ownership row is malformed")
        logical = _checked_main_logical(row.get("key_id"))
        if key_hash != hashlib.sha256(logical.encode()).digest()[:16].hex() or NATIVE_KEY_ID_FIELD not in row:
            raise NativeKeyIdMismatch("main ownership hash or scoped selector is missing")
        physical = persisted_native_key_id(root, logical, row[NATIVE_KEY_ID_FIELD])
        if pending != (logical, physical):
            _storage._check_dir_mode(root / "digests")
            if len(_storage.safe_read(root / "digests" / f"{key_hash}.commit")) != 32:
                raise NativeKeyIdMismatch("main ownership digest commit is malformed")
        targets[logical] = physical
    if pending is not None:
        logical = _checked_main_logical(pending[0])
        if logical in targets and targets[logical] != pending[1]:
            raise NativeKeyIdMismatch("main ownership records disagree")
        targets[logical] = pending[1]
    audit = committed_audit_key_from_meta(root, meta, AUDIT_LOG_KEY_ID)
    pending_audit = pending_audit_key_from_meta(root, meta, AUDIT_LOG_KEY_ID)
    if audit is not None and pending_audit is not None and audit != pending_audit:
        raise NativeKeyIdMismatch("audit ownership records disagree")
    if audit is not None or pending_audit is not None:
        targets[AUDIT_LOG_KEY_ID] = audit if audit is not None else cast(str, pending_audit)
    return dict(sorted(targets.items()))


def _checked_keyvault_role(root: Path, native_key_id: str, *, reset: bool) -> Literal["main", "audit"]:
    from . import _storage
    from .log_encryption import AUDIT_LOG_KEY_ID

    if reset:
        # The reset parser checks exact schema, scoped selectors and physical
        # root identity. A journal is authoritative only inside checked custody.
        from ..wizard.keyvault_cli import _load_reset_journal

        journal = _load_reset_journal(root)
        if journal.metadata_incomplete or journal.retained_legacy:
            raise NativeKeyIdMismatch("reset ownership is ambiguous")
        try:
            current = root.lstat()
        except FileNotFoundError:
            pass
        else:
            if (current.st_dev, current.st_ino) != journal.root_identity:
                raise NativeKeyIdMismatch("reset journal root identity changed")
        targets = journal.key_ids
    else:
        _storage.assert_keyvault_active(root)
        targets = _checked_metadata_targets(root)
    for logical, physical in targets.items():
        if logical != AUDIT_LOG_KEY_ID:
            _checked_main_logical(logical)
        if physical == native_key_id:
            return "audit" if logical == AUDIT_LOG_KEY_ID else "main"
    raise NativeKeyIdMismatch("native selector has no exact checked keyvault owner")


def checked_native_owner(custody: object, *, native_key_id: str, backend: NativeBackend) -> ValidatedNativeOwner:
    """Issue only through the fixed trusted, live transaction adapter."""
    from ._native_deletion import _issue_native_owner

    return _issue_native_owner(custody, native_key_id=native_key_id, backend=backend)


def _checked_creation_pending(
    root: Path,
    key_id: str,
    native_key_id: str,
    *,
    initial_meta: bytes,
    allow_intermediate: bool,
) -> None:
    """Validate one fresh pending main/audit owner, retaining failed-row rollback."""
    from . import _storage
    from .log_encryption import AUDIT_LOG_KEY_ID

    _checked_metadata_targets(root)  # Duplicate keys and malformed other owners refuse.
    meta = _storage.load_meta(root)
    initial = json.loads(initial_meta, object_pairs_hook=_unique_ownership_object) if initial_meta else {}
    if native_key_id != scoped_native_key_id(root, key_id):
        raise NativeKeyIdMismatch("creation selector is not scoped to the checked root")
    if key_id == AUDIT_LOG_KEY_ID:
        if pending_audit_key_from_meta(root, meta, key_id) != native_key_id:
            raise NativeKeyIdMismatch("exact pending audit owner is required")
        if PENDING_AUDIT_KEY_FIELD in initial or AUDIT_KEY_FIELD in initial:
            raise NativeKeyIdMismatch("resumed or committed audit custody cannot obtain a creation receipt")
        if committed_audit_key_from_meta(root, meta, key_id) is not None and not allow_intermediate:
            raise NativeKeyIdMismatch("existing committed audit owner cannot obtain rollback")
        if pending_native_key_from_meta(root, meta) is not None or len(meta["keys"]) != 1:
            raise NativeKeyIdMismatch("audit provisioning requires committed main custody")
    else:
        _checked_main_creation_pending(root, key_id, native_key_id, meta, initial, allow_intermediate)


def _checked_main_creation_pending(
    root: Path,
    key_id: str,
    native_key_id: str,
    meta: Mapping[str, Any],
    initial: Mapping[str, Any],
    allow_intermediate: bool,
) -> None:
    from . import _storage

    validate_main_key_id(key_id)
    if pending_native_key_from_meta(root, meta) != (key_id, native_key_id):
        raise NativeKeyIdMismatch("exact pending main owner is required")
    if has_native_key_ownership_state(initial):
        raise NativeKeyIdMismatch("resumed or committed main custody cannot obtain a creation receipt")
    if not allow_intermediate:
        for name in ("digests", "ciphertexts"):
            directory = root / name
            _storage._check_dir_mode(directory)
            if any(directory.iterdir()):
                raise NativeKeyIdMismatch("retained main artifacts cannot obtain a new creation receipt")
    rows = meta["keys"]
    if rows and (not allow_intermediate or len(rows) != 1 or key_id not in _checked_metadata_targets(root)):
        raise NativeKeyIdMismatch("existing main owner cannot obtain rollback")


def _assert_creation_backend_bound(backend: NativeBackend, root: Path) -> None:
    from .._database_contracts import DatabaseRefused
    from ._seckey_backend import _SecKeyBackend
    from ._seckey_helper import _HelperSecKeyOps

    if type(backend) is not _SecKeyBackend:
        raise DatabaseRefused("creation ownership requires the production backend")
    expected = _SecKeyBackend._for_keyvault_root(backend, root)
    for actual, selected in (
        (backend._ops, expected._ops),
        (backend._legacy_ops, expected._legacy_ops),
        (backend._sw_ops, expected._sw_ops),
    ):
        if isinstance(actual, _HelperSecKeyOps) and (
            not isinstance(selected, _HelperSecKeyOps)
            or actual._env_override is None
            or selected._env_override is None
            or actual._env_override[0] != selected._env_override[0]
            or Path(actual._env_override[1]).resolve() != Path(selected._env_override[1]).resolve()
        ):
            raise DatabaseRefused("creation backend is not bound to the checked custody store")
