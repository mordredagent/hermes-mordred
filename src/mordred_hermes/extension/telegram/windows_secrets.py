"""Windows Telegram credentials sealed under the custody ``telegram`` role (C10b).

The Windows counterpart of :class:`.tee.TeeSecretStore`, selected by
:func:`.tee.default_secret_store` on ``win32``. The payload and file layout are
unchanged: :func:`.secrets.encode` JSON sealed into
``<home>/mordred/telegram/credentials.sealed`` as
``MTC1 || u16 len || wrap_blob || nonce(12) || AES-256-GCM`` plus the
non-secret ``credentials.meta.json``. Only the wrap differs: ``wrap_blob`` is
the 127-byte MRKW wrap of a fresh data key to the *current* generation of the
independent C5a ``telegram`` role, under the existing logical key id
``mordred-hermes.telegram.credentials.v1`` and the role's profile-scoped
native selector (checked home identity, token SID, profile/generation nonces).

Rules enforced here:

- **Load-only custody.** Every operation opens ``windows_custody_session`` with
  ``create=False``, requires a committed ``telegram`` role, validates its lease
  and the exact native public fingerprint, and never generates a key. An
  absent role refuses ``telegram_not_enrolled`` (the explicit enrollment
  ceremony belongs to the wizard); a failed native lookup refuses
  ``tee_unavailable`` and is never treated as absence.
- **No per-use presence.** Windows custody is machine-bound; a presence request
  refuses ``presence_unsupported`` (the C5e ``presence`` capability) before any
  native call, and never silently becomes unattended.
- **Checked files.** Reads are bounded and identity-checked; writes are staged
  private create-no-replace or checked replacement inside the Telegram
  directory transaction, reported to the owning custody receipt. Lock order is
  home -> mordred -> telegram. Unsafe state refuses; nothing repairs an ACL.
- **No cache, no plaintext logs.** Each load is a fresh native unwrap; unwrap
  audit entries are buffered and emitted only after the custody scope exits.
  Failures are content-free codes.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import secrets as _secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..._private_fs import PrivateFSError
from . import _windows_archive as checked
from . import tee
from .secrets import TelegramSecrets, TelegramSecretsError, decode, encode

if TYPE_CHECKING:
    from ..._config_io import PublicationReceipt
    from ...keyvault._windows_custody import GenerationLease, WindowsCustodySession
    from ...keyvault.wrap import NativeBackend

SEALED_LIMIT = 65536
META_LIMIT = 16384
_SEALED = tee._SEALED_NAME
_META = tee._META_NAME
#: ``_publish`` expectation that replaces whatever is sealed (``store``).
_ANY = object()
#: Codes for definite (uncommitted) checked-storage failures, shared with ``store``.
_DEFINITE = {"missing": "store_missing", "io": "store_io", "busy": "store_busy"}

Snapshot = tee.Snapshot
AuditSink = Callable[[dict[str, Any]], None]


class _ReceiptRecorder:
    """Report child-directory publications to the owning custody receipt."""

    def __init__(self, receipt: PublicationReceipt) -> None:
        self._receipt = receipt

    def published(self) -> None:
        self._receipt.mark_published()

    def uncertain(self, error: PrivateFSError) -> None:
        self._receipt.mark_uncertain(error)


def _classified(exc: Exception) -> TelegramSecretsError | None:
    """Content-free code for a custody/filesystem/native failure, or ``None``."""
    from ..._config_io import PolicyPendingError
    from ...keyvault._exceptions import WrapAuthCancelled, WrapError, WrapIntegrityError, WrapParseError
    from ...keyvault._windows_profile import CustodyError
    from ...keyvault.wrap import NativeBackendError

    if isinstance(exc, TelegramSecretsError):
        return None
    if isinstance(exc, PrivateFSError):
        if exc.commit_state == "uncertain":
            code = "custody_uncertain"
        elif exc.reason in ("unsafe", "access_denied", "unsupported"):
            code = "custody_unsafe"
        else:
            # Definite, uncommitted failures keep their own classification.
            code = _DEFINITE.get(exc.reason, "custody_uncertain")
    elif isinstance(exc, PolicyPendingError):
        code = "custody_uncertain"
    elif isinstance(exc, CustodyError):
        # Copied/foreign/malformed ownership, lost role binding or changed key.
        code = "custody_broken"
    elif isinstance(exc, WrapAuthCancelled):
        code = "tee_auth_cancelled"
    elif isinstance(exc, (WrapIntegrityError, WrapParseError)):
        code = "secrets_corrupt"
    elif isinstance(exc, (WrapError, NativeBackendError)):
        code = "tee_unavailable"
    else:
        return None
    return TelegramSecretsError(code)


@contextmanager
def _translated() -> Iterator[None]:
    """Translate only after every inner custody/filesystem context has exited."""
    try:
        yield
    except Exception as exc:
        mapped = _classified(exc)
        if mapped is None:
            raise
        raise mapped from exc


def _token(sealed: bytes | None) -> bytes | None:
    return None if sealed is None else hashlib.sha256(sealed).digest()


def _same(left: bytes | None, right: bytes | None) -> bool:
    if left is None or right is None:
        return left is None and right is None
    return hmac.compare_digest(left, right)


def _require_telegram_lease(lease: GenerationLease) -> None:
    from ...keyvault._windows_profile import CustodyError

    if lease.role != "telegram" or lease.key_id != tee.KEY_ID:
        raise CustodyError("Telegram credentials require the telegram custody role")


def _telegram_role(session: WindowsCustodySession) -> tuple[GenerationLease, NativeBackend]:
    """Current telegram lease plus its fingerprint-verified backend; never generates."""
    status = session.role_status("telegram")
    if status.pending:
        raise TelegramSecretsError("custody_uncertain")
    if status.current is None:
        raise TelegramSecretsError("telegram_not_enrolled")
    lease = session.lease("telegram")
    _require_telegram_lease(lease)
    _discover_helper(session)
    return lease, session.backend_for(lease)


def _discover_helper(session: WindowsCustodySession) -> None:
    """Load-only helper discovery; a changed session identity stays broken custody."""
    from ...keyvault._windows_profile import CustodyError

    try:
        _ = session.backend
    except CustodyError as exc:
        session.check()  # re-raises "session identity changed" as broken custody
        raise TelegramSecretsError("tee_unavailable") from exc


def _meta_dict(raw: bytes | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        meta = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None
    return meta if isinstance(meta, dict) else None


class WindowsCustodySecretStore:
    """Read/modify/write the custody-sealed Telegram credentials on Windows.

    Same duck-typed interface as :class:`.tee.TeeSecretStore` (``load``,
    ``load_snapshot``, ``update``, ``update_from_snapshot``, ``store``,
    ``flags``, ``sync_scope``, ``save_sync_scope``, ``ensure_key``,
    ``invalidate``) except ``delete_key``: the native role is reset only by
    ``store.wipe_archive(forget=True)``.
    """

    def __init__(
        self,
        home: Path | None = None,
        *,
        backend: NativeBackend | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._home = None if home is None else Path(home)
        self._backend = backend
        self._audit_sink = audit_sink if audit_sink is not None else tee._audit_sink

    # -- paths and scopes -------------------------------------------------------------

    def _resolved_home(self) -> Path:
        if self._home is not None:
            return self._home
        from ..._home import hermes_home

        return hermes_home()

    @property
    def root(self) -> Path:
        return self._resolved_home() / "mordred" / "telegram"

    @contextmanager
    def _custody(self) -> Iterator[WindowsCustodySession]:
        from ...keyvault._windows_custody import windows_custody_session

        with windows_custody_session(self._resolved_home(), backend=self._backend) as session:
            yield session

    def _emit(self, entries: list[dict[str, Any]]) -> None:
        for entry in entries:
            with contextlib.suppress(Exception):
                self._audit_sink(entry)

    # -- seal / unseal ------------------------------------------------------------------

    @staticmethod
    def _seal(plaintext: bytes, lease: GenerationLease, backend: NativeBackend) -> bytes:
        from ...keyvault import wrap

        dek = _secrets.token_bytes(32)
        blob = wrap.wrap_dek(dek, lease.key_id, backend=backend, native_key_id=lease.native_key_id)
        return tee._pack(blob, dek, plaintext)

    @staticmethod
    def _unseal(
        sealed: bytes, lease: GenerationLease, backend: NativeBackend, entries: list[dict[str, Any]]
    ) -> TelegramSecrets:
        from ...keyvault import wrap

        blob, nonce, body = tee._unpack(sealed)
        # The authorization boundary: ECDH inside the role's CNG key.
        dek = wrap.unwrap_dek(
            blob, lease.key_id, audit_sink=entries.append, backend=backend, native_key_id=lease.native_key_id
        )
        return decode(tee._decrypt(dek, nonce, body))

    def _read_sealed(self) -> bytes | None:
        with checked.transaction(self.root) as tx:
            return None if tx is None else checked.read_optional(tx, _SEALED, SEALED_LIMIT)

    def _publish(
        self,
        session: WindowsCustodySession,
        sealed: bytes | None,
        value: TelegramSecrets | None,
        *,
        expected: object,
    ) -> None:
        """Publish (or remove, for ``None``) the sealed file and its metadata."""
        with session.canonical.publication_receipt() as receipt:
            recorder = _ReceiptRecorder(receipt)
            with checked.transaction(self.root, create=sealed is not None, recorder=recorder) as tx:
                if tx is None:
                    if expected is not _ANY and expected is not None:
                        raise TelegramSecretsError("custody_uncertain")
                    return
                current = checked.read_optional(tx, _SEALED, SEALED_LIMIT)
                wanted = expected if isinstance(expected, bytes) else None
                if expected is not _ANY and not _same(wanted, _token(current)):
                    # Cooperating writers hold home -> mordred; a change means an
                    # unexpected writer. Refuse instead of overwriting it.
                    raise TelegramSecretsError("custody_uncertain")
                if sealed is None or value is None:
                    for name in (_SEALED, _META):
                        checked.remove(tx, name, recorder)
                    return
                previous = _meta_dict(checked.read_optional(tx, _META, META_LIMIT))
                checked.publish(tx, _SEALED, sealed, recorder, limit=SEALED_LIMIT)
                meta = json.dumps(tee._meta_document(value, previous)).encode("utf-8")
                checked.publish(tx, _META, meta, recorder, limit=META_LIMIT)

    # -- custody key --------------------------------------------------------------------

    def ensure_key(self, *, require_presence: bool = True) -> None:
        """Verify the enrolled role; never creates a key.

        Per-use presence is excluded on Windows: requesting it refuses before
        any native call instead of silently creating or using an unattended key.
        """
        if require_presence:
            from ...keyvault._windows_capability import KeyvaultUnsupportedOnWindows

            raise TelegramSecretsError("presence_unsupported") from KeyvaultUnsupportedOnWindows(
                "presence", "telegram_ensure_key"
            )
        with _translated(), self._custody() as session:
            _telegram_role(session)

    # -- public API ---------------------------------------------------------------------

    def load(self, *, fresh: bool = True) -> TelegramSecrets | None:
        """Unseal through the role's CNG key. Never cached (``fresh`` is ignored)."""
        del fresh
        return self.load_snapshot()[0]

    def load_snapshot(self) -> Snapshot:
        """:meth:`load` plus the SHA-256 token of the sealed file that was unsealed."""
        entries: list[dict[str, Any]] = []
        try:
            with _translated(), self._custody() as session:
                session.role_status("telegram")  # a broken manifest refuses even when unconfigured
                sealed = self._read_sealed()
                if sealed is None:
                    return None, None
                lease, backend = _telegram_role(session)
                return self._unseal(sealed, lease, backend, entries), _token(sealed)
        finally:
            self._emit(entries)

    def update(self, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]) -> TelegramSecrets | None:
        """Unseal (one native unwrap), apply ``mutate`` and seal the result."""
        return self._update(None, mutate)

    def update_from_snapshot(
        self, snapshot: Snapshot, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]
    ) -> TelegramSecrets | None:
        """:meth:`update` reusing an unchanged snapshot without a second unwrap."""
        return self._update(snapshot, mutate)

    def _update(
        self, snapshot: Snapshot | None, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]
    ) -> TelegramSecrets | None:
        entries: list[dict[str, Any]] = []
        try:
            with _translated(), self._custody() as session:
                lease, backend = _telegram_role(session)
                sealed = self._read_sealed()
                token = _token(sealed)
                if snapshot is not None and _same(snapshot[1], token):
                    current = snapshot[0]
                else:
                    current = None if sealed is None else self._unseal(sealed, lease, backend, entries)
                updated = mutate(current)
                replacement = None if updated is None else self._seal(encode(updated), lease, backend)
                self._publish(session, replacement, updated, expected=token)
                return updated
        finally:
            self._emit(entries)

    def store(self, value: TelegramSecrets) -> None:
        """Seal *value* without unsealing first (first login / migration)."""
        with _translated(), self._custody() as session:
            lease, backend = _telegram_role(session)
            self._publish(session, self._seal(encode(value), lease, backend), value, expected=_ANY)

    def flags(self) -> dict[str, Any] | None:
        """Non-secret status flags, or ``None`` when not configured. No native call."""
        with _translated(), checked.transaction(self.root) as tx:
            if tx is None or not checked.present(tx, _SEALED):
                return None
            raw = checked.read_optional(tx, _META, META_LIMIT)
        if raw is None:
            return dict(tee._DEFAULT_FLAGS)
        try:
            meta = json.loads(raw.decode("utf-8"))
        except ValueError:
            return dict(tee._DEFAULT_FLAGS)
        return meta if isinstance(meta, dict) else None

    def sync_scope(self) -> dict[str, Any]:
        """The import scope chosen at setup (non-secret); empty = everything."""
        with _translated(), checked.transaction(self.root) as tx:
            raw = None if tx is None else checked.read_optional(tx, _META, META_LIMIT)
        scope = (_meta_dict(raw) or {}).get("sync_scope")
        return dict(scope) if isinstance(scope, dict) else {}

    def save_sync_scope(self, scope: dict[str, Any]) -> None:
        with _translated(), checked.transaction(self.root, create=True) as tx:
            assert tx is not None
            meta = _meta_dict(checked.read_optional(tx, _META, META_LIMIT)) or dict(tee._DEFAULT_FLAGS)
            meta["sync_scope"] = tee._scope_document(scope)
            checked.publish(tx, _META, json.dumps(meta).encode("utf-8"), checked.UNRECORDED, limit=META_LIMIT)

    def invalidate(self) -> None:
        """No-op: nothing is cached."""


def forget_telegram(home: Path, root: Path, *, backend: NativeBackend | None = None) -> None:
    """Windows ``logout --forget``; the caller holds the archive sync lock.

    Validates the complete custody manifest and refuses an unresolved telegram
    journal before deleting anything; then deletes the enumerated archive files,
    ``credentials.sealed`` and ``credentials.meta.json`` (reported to the custody
    receipt), and finally resets only the ``telegram`` role through C5e
    ``reset_role(..., erase_authorized=True)``. Nothing is unsealed; memory and
    audit roles, directories and permanent locks stay. An ambiguous native
    deletion keeps its intent journal and refuses the next forget.
    """
    from ...keyvault._windows_custody import windows_custody_session

    resetting = False
    try:
        with windows_custody_session(home, backend=backend) as session:
            leases = _forget_preflight(session)
            with session.canonical.publication_receipt() as receipt:
                # One validated plan: segments, index, then the sealed credentials.
                checked.wipe(root, _ReceiptRecorder(receipt), credentials=(_SEALED, _META))
            if leases:
                resetting = True
                session.reset_role("telegram", erase_authorized=True)
    except TelegramSecretsError:
        raise
    except Exception as exc:
        if resetting:
            # Every definite refusal was preflighted, so a failure from here on
            # follows the deletion journal: report it as uncertain, never as a
            # native outage, and keep the journal for explicit reconciliation.
            raise TelegramSecretsError("custody_uncertain") from exc
        mapped = _classified(exc)
        if mapped is None:
            raise
        raise mapped from exc


def _forget_preflight(session: WindowsCustodySession) -> tuple[GenerationLease, ...]:
    """Every ``reset_role`` refusal that can be checked, before anything is deleted.

    Validates the complete manifest and every role's journal, refuses an
    unresolved telegram journal, discovers the helper, verifies each owned
    generation's native fingerprint and checks epoch headroom for one deletion
    per generation. Returns the telegram generations to reset (possibly none).
    """
    from ...keyvault import _windows_profile as profile

    statuses = {role: session.role_status(role) for role in profile.ROLES}
    status = statuses["telegram"]
    if status.pending:
        raise TelegramSecretsError("custody_uncertain")
    leases = status.retained + (() if status.current is None else (status.current,))
    if not leases:
        return leases
    _discover_helper(session)
    for lease in leases:
        _require_telegram_lease(lease)
        session.backend_for(lease)
    manifest = session._manifest()  # read-only epoch headroom; delete_role rechecks per generation
    if manifest is None or manifest.epoch > profile.MAX_EPOCH - len(leases):
        raise profile.CustodyError("custody lifecycle epoch exhausted; refusing irreversible deletion")
    return leases
