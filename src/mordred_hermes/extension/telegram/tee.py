"""Telegram credentials sealed by the Secure Enclave (TEE) — and nothing else.

Everything that grants access to the account or the archive (API credentials,
the Telethon session, the archive key, the LLM API key) is stored in ONE file,
``<home>/mordred/telegram/credentials.sealed``:

    MTC1 || u16 len || wrap_blob || nonce(12) || AES-256-GCM(json)

``wrap_blob`` is the keyvault's ECIES wrap (:func:`keyvault.wrap.wrap_dek`) of a
fresh 32-byte data key under a P-256 key that lives inside the Secure Enclave.
Opening the file therefore requires an ECDH *inside the Enclave*
(:func:`keyvault.wrap.unwrap_dek`) — the private key never leaves the chip, so
the file is useless on any other machine or without this device's Enclave.

Rules enforced here:

- **Hardware only.** The backend is built from the signed Enclave helper
  (``hermes-mordred keyvault enable-se``) with NO software-key namespace and NO
  legacy fallback. Without the helper, every read and write is refused with
  ``tee_unavailable``; there is no plaintext or software-key fallback.
- **The Enclave is used on every connection.** Nothing decrypted from the
  sealed file is cached: each ``load()`` is a fresh Enclave ECDH. Callers open
  the credentials right before connecting to Telegram (or the LLM) and drop
  them afterwards.
- **Optional user presence.** The Enclave key is created with a Touch ID /
  passcode requirement unless the operator opts out, so each unseal can
  demand the owner's presence.

Non-secret flags for the status screen (logged in? which LLM?) live in
``credentials.meta.json`` so polling never touches the Enclave.

Windows has no Enclave/TPM helper here: :func:`default_secret_store` selects
:class:`.windows_secrets.WindowsCustodySecretStore`, which keeps this exact
file layout but wraps to the independent C5a custody ``telegram`` role.
"""

from __future__ import annotations

import json
import secrets as _secrets
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..._database_contracts import DatabaseRefused
from ...keyvault._telegram_custody import (
    KEY_ID,
    TelegramAuthentication,
    TelegramSnapshotChanged,
    assert_no_pending_forget,
    authenticate_telegram_source,
    checked_telegram_home,
    pending_telegram_forget,
    telegram_credential_transaction,
)
from ...keyvault._telegram_custody import (
    _decrypt as _decrypt,
)
from ...keyvault._telegram_custody import (
    _pack as _pack,
)
from ...keyvault._telegram_custody import (
    _unpack as _unpack,
)
from .secrets import TelegramSecrets, TelegramSecretsError, encode

_SEALED_NAME = "credentials.sealed"
_META_NAME = "credentials.meta.json"
Snapshot = tuple[TelegramSecrets | None, TelegramAuthentication | None]
_DEFAULT_FLAGS: dict[str, Any] = {"version": 1, "logged_in": False, "llm_backend": None, "llm_model": None}


def _meta_document(value: TelegramSecrets, previous: dict[str, Any] | None) -> dict[str, Any]:
    """Non-secret flags for *value*, keeping a previously saved sync scope."""
    meta: dict[str, Any] = {
        "version": 1,
        "logged_in": value.session is not None,
        "api_configured": value.has_api,
        "llm_backend": value.llm_backend(),
        "llm_model": value.llm_model(),
    }
    if previous and isinstance(previous.get("sync_scope"), dict):
        meta["sync_scope"] = previous["sync_scope"]
    return meta


def _scope_document(scope: dict[str, Any]) -> dict[str, Any]:
    return {
        "include_channels": scope.get("include_channels") is not False,
        "include_archived": scope.get("include_archived") is True,
        "limit_per_dialog": scope.get("limit_per_dialog"),
        "since_days": scope.get("since_days"),
        "max_group_size": scope.get("max_group_size", 100),
    }


def _home() -> Path:
    from ..._home import hermes_home

    return hermes_home()


def hardware_backend(home: Path | None = None) -> Any:
    """Enclave-only backend: the signed helper, no software/legacy namespaces."""
    from ...keyvault import _seckey_helper
    from ...keyvault._seckey_backend import _SecKeyBackend

    if sys.platform == "darwin":
        ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_sekey_helper)
    elif sys.platform == "linux":
        ops = _seckey_helper._helper_ops_or_none(_seckey_helper.find_tpmkey_helper)
    else:
        ops = None
    if ops is None:
        raise TelegramSecretsError("tee_unavailable")
    base = home if home is not None else _home()
    backend = _SecKeyBackend(ops=ops, legacy_ops=None, sw_ops=None)
    return backend._for_keyvault_root(base / "mordred" / "keyvault")


def _audit_sink(entry: dict[str, Any]) -> None:
    try:
        import logging

        from ..._audit_support import build_audit_writer, safe_audit_append

        writer = build_audit_writer(_home() / "mordred" / "audit.log")
        safe_audit_append(writer, entry, logger=logging.getLogger(__name__))
    except Exception:
        pass


class TeeSecretStore:
    """Read/modify/write the Enclave-sealed Telegram credentials.

    Same interface as the former vault store (``load`` / ``update``), plus
    :meth:`flags` for non-secret status and :meth:`ensure_key`.
    """

    def __init__(
        self,
        root: Path | None = None,
        *,
        backend_factory: Callable[[], Any] | None = None,
        audit_sink: Callable[[dict[str, Any]], None] = _audit_sink,
    ) -> None:
        self._root = root
        self._backend_factory = backend_factory or (lambda: hardware_backend(self._home()))
        self._audit_sink = audit_sink
        self._native_backend: Any = None

    # -- paths ----------------------------------------------------------------

    def _home(self) -> Path:
        from .store import StoreError, _windows

        if _windows():
            raise StoreError("store_path_unsafe")
        root = self._root if self._root is not None else _home() / "mordred/telegram"
        if root.name != "telegram" or root.parent.name != "mordred":
            raise DatabaseRefused("Telegram requires its canonical profile directory")
        return checked_telegram_home(root.parent.parent)

    def _backend(self) -> Any:
        if self._native_backend is None:
            self._native_backend = self._backend_factory()
        return self._native_backend

    def _dir(self, *, create: bool = False) -> Path:
        home = self._home()
        return checked_telegram_home(home, create=create) / "mordred/telegram"

    @property
    def sealed_path(self) -> Path:
        return self._dir() / _SEALED_NAME

    @property
    def meta_path(self) -> Path:
        return self._dir() / _META_NAME

    def _read_path(self, name: str) -> Path:
        return self._dir() / name

    # -- Enclave key ----------------------------------------------------------

    def ensure_key(self, *, require_presence: bool = True) -> None:
        """Create the Enclave key if it does not exist yet."""
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError, WrapKeyNotFound

        home = self._home()
        backend = self._backend()
        with telegram_credential_transaction(home=home, backend=backend, create=True):
            try:
                wrap.get_wrapping_key_public(KEY_ID, backend=backend)
                return
            except WrapKeyNotFound:
                if self.sealed_path.exists():
                    raise DatabaseRefused(
                        "Telegram source exists without its native key; retain it for repair"
                    ) from None
            except WrapError as exc:
                raise TelegramSecretsError("tee_unavailable") from exc
            try:
                wrap.generate_wrapping_key(KEY_ID, backend=backend, unattended=not require_presence)
            except WrapError as exc:
                raise TelegramSecretsError("tee_unavailable") from exc

    def delete_key(self) -> None:
        raise DatabaseRefused("Telegram deletion requires authenticated forget custody")

    # -- seal / unseal ----------------------------------------------------------

    def _seal(self, plaintext: bytes) -> bytes:
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError

        dek = _secrets.token_bytes(32)
        try:
            # Offline: uses the Enclave PUBLIC key; no prompt.
            blob = wrap.wrap_dek(dek, KEY_ID, backend=self._backend())
        except WrapError as exc:
            raise TelegramSecretsError("tee_unavailable") from exc
        return _pack(blob, dek, plaintext)

    def _unseal(self, sealed: bytes) -> bytes:
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapAuthCancelled, WrapError

        blob, nonce, body = _unpack(sealed)
        try:
            # The authorization boundary: ECDH inside the Secure Enclave.
            dek = wrap.unwrap_dek(blob, KEY_ID, audit_sink=self._audit_sink, backend=self._backend())
        except WrapAuthCancelled as exc:
            raise TelegramSecretsError("tee_auth_cancelled") from exc
        except WrapError as exc:
            raise TelegramSecretsError("tee_unavailable") from exc
        return _decrypt(dek, nonce, body)

    # -- public API -------------------------------------------------------------

    def load(self, *, fresh: bool = True) -> TelegramSecrets | None:
        """Every load authenticates fresh; no plaintext or private-key cache."""
        del fresh
        return self.load_snapshot()[0]

    def load_snapshot(self) -> Snapshot:
        home = self._home()
        assert_no_pending_forget(home)
        if not self.sealed_path.exists() and not self.sealed_path.is_symlink():
            return None, None
        return authenticate_telegram_source(home=home, backend=self._backend(), audit_sink=self._audit_sink)

    def update(self, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]) -> TelegramSecrets | None:
        for _attempt in range(3):
            snapshot = self.load_snapshot()
            try:
                return self._update_checked(snapshot, mutate)
            except TelegramSnapshotChanged:
                continue  # release custody before fresh authentication
        raise DatabaseRefused("Telegram source changed repeatedly; update refused")

    def _update_checked(
        self, snapshot: Snapshot, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]
    ) -> TelegramSecrets | None:
        current, authentication = snapshot
        with telegram_credential_transaction(
            home=self._home(), backend=self._backend(), authenticated=authentication, create=True
        ) as custody:
            if authentication is None:
                if current is not None:
                    raise DatabaseRefused("Telegram snapshot has no issued authentication")
                custody.check_absence()
            updated = mutate(current)
            if updated is None:
                raise DatabaseRefused("Telegram removal requires explicit authenticated forget")
            return self._write_locked(updated, custody)

    def update_from_snapshot(
        self, snapshot: Snapshot, mutate: Callable[[TelegramSecrets | None], TelegramSecrets | None]
    ) -> TelegramSecrets | None:
        try:
            return self._update_checked(snapshot, mutate)
        except TelegramSnapshotChanged:
            return self.update(mutate)

    def _write_locked(self, updated: TelegramSecrets, custody: Any) -> TelegramSecrets:
        from .store import _ensure_gitignored

        _ensure_gitignored(self._dir())
        meta = _meta_document(updated, self._read_meta())
        custody.write_source(self._seal(encode(updated)), json.dumps(meta).encode("utf-8"))
        return updated

    def _write(self, updated: TelegramSecrets | None) -> TelegramSecrets | None:
        if updated is None:
            raise DatabaseRefused("Telegram removal requires explicit authenticated forget")
        self.store(updated)
        return updated

    def store(self, value: TelegramSecrets) -> None:
        with telegram_credential_transaction(home=self._home(), backend=self._backend(), create=True) as custody:
            self._write_locked(value, custody)

    def _write_meta(self, value: TelegramSecrets) -> None:
        with telegram_credential_transaction(home=self._home(), backend=self._backend()) as custody:
            custody.write_metadata(json.dumps(_meta_document(value, self._read_meta())).encode("utf-8"))

    def forget_from_snapshot(self, snapshot: Snapshot) -> None:
        from .store import _posix_archive_lock, _prepare_archive_wipe, _wipe_archive_locked

        home = self._home()
        _current, authentication = snapshot
        # Archive is first and nonblocking. Sync credential writes never take it.
        with (
            _posix_archive_lock(self._dir(), allow_pending=True) as archive,
            telegram_credential_transaction(
                home=home, backend=self._backend(), authenticated=authentication, _resume=True
            ) as custody,
        ):
            journal = custody.forget_journal()
            if journal is not None and journal["phase"] != "deleted":
                raise DatabaseRefused("Telegram native deletion was interrupted; intent retained for repair")
            _prepare_archive_wipe(archive)
            if journal is None:
                custody.validate(authentication)
                custody.delete_native_key()
            custody.clean_source()
            _wipe_archive_locked(archive)
            custody.finish_forget()

    def _read_meta(self) -> dict[str, Any] | None:
        from ...keyvault._telegram_custody import _read

        try:
            observed = _read(self._read_path(_META_NAME))
            if observed is None:
                return None
            meta = json.loads(observed[0])
        except ValueError:
            return None
        return meta if isinstance(meta, dict) else None

    def sync_scope(self) -> dict[str, Any]:
        """The import scope chosen at setup (non-secret); empty = everything."""
        assert_no_pending_forget(self._home())
        meta = self._read_meta() or {}
        scope = meta.get("sync_scope")
        return dict(scope) if isinstance(scope, dict) else {}

    def save_sync_scope(self, scope: dict[str, Any]) -> None:
        with telegram_credential_transaction(home=self._home(), backend=self._backend(), create=True) as custody:
            meta = self._read_meta() or dict(_DEFAULT_FLAGS)
            meta["sync_scope"] = _scope_document(scope)
            custody.write_metadata(json.dumps(meta).encode("utf-8"))

    def flags(self) -> dict[str, Any] | None:
        """Non-secret status flags, or ``None`` when not configured. No Enclave, and nothing is created."""
        if pending_telegram_forget(self._home()):
            return {**_DEFAULT_FLAGS, "forget_pending": True}
        path = self._read_path(_META_NAME)
        if path.is_symlink() or not self._read_path(_SEALED_NAME).exists():
            return None
        try:
            meta = json.loads(path.read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            return dict(_DEFAULT_FLAGS)
        return meta if isinstance(meta, dict) else None

    def invalidate(self) -> None:
        """No-op: nothing is cached."""


def default_secret_store() -> Any:
    """The platform's production Telegram credential store (the C10b seam).

    ``win32`` gets the custody-role store; macOS/Linux keep the Enclave/TPM
    store unchanged. Callers that construct ``TeeSecretStore()`` directly on
    Windows are refused by the raw-directory guard before any filesystem use.
    """
    from .store import _platform

    if _platform() == "win32":
        from .windows_secrets import WindowsCustodySecretStore

        return WindowsCustodySecretStore()
    return TeeSecretStore()
