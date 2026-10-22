"""Hardware-sealed IMAP credentials for the mail collector (macOS only).

The address, the app password, the IMAP host and port, the own addresses and
the mailboxes chosen at ``mail setup`` live in ONE file,
``<home>/mordred/mail/credentials.sealed``::

    MMC1 || u16 len || wrap_blob || nonce(12) || AES-256-GCM(json)

``wrap_blob`` is the keyvault ECIES wrap (:func:`mordred_hermes.keyvault.wrap.wrap_dek`)
of a fresh data key under the Secure Enclave key with the logical role
:data:`KEY_ID`; opening the file is an ECDH inside the Enclave, through the same
hardware-only backend the Telegram credentials use
(:func:`mordred_hermes.extension.telegram.tee.hardware_backend`: the signed
helper, no software key, no legacy fallback). Nothing decrypted is cached:
every :meth:`MailSecretStore.load` is a fresh unwrap (Touch ID unless the key
was created with ``--no-touch-id``). Python cannot zero immutable strings; the
caller keeps the unsealed value in one scope for one fetch and drops it.

``credentials.meta.json`` next to it holds non-secret flags (account label,
Gmail path, mailbox roles, presence) so status and the Hermes tool's
availability check never touch the Enclave and never see the address.

Other platforms refuse with ``unsupported_platform`` before any filesystem use
(``mordred.db`` is macOS-only, and Windows custody roles are frozen by C5a).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets as _secrets
import stat
import struct
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

__all__ = [
    "ACCOUNT_RE",
    "KEY_ID",
    "MailCredentials",
    "MailSecretStore",
    "MailSecretsError",
    "decode",
    "encode",
    "mail_dir",
]

KEY_ID: Final = "mordred-hermes.mail.credentials.v1"
_MAGIC: Final = b"MMC1"
_NONCE_LEN: Final = 12
_AAD: Final = b"mordred-mail-credentials-v1"
_SEALED_NAME: Final = "credentials.sealed"
_META_NAME: Final = "credentials.meta.json"
_SCHEMA_VERSION: Final = 1
_MAX_SEALED_BYTES: Final = 64 * 1024
#: The account label used in uids and cursor keys: one lowercase ``import_meta`` key component.
ACCOUNT_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
_ROLES: Final = frozenset({"all", "inbox", "sent"})
_GITIGNORE: Final = b"# Mordred mail credentials: sealed, never version-controlled.\n*\n"


class MailSecretsError(RuntimeError):
    """Stable, content-free failure code (never carries secret material)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class MailCredentials:
    """The unsealed credentials. ``mailboxes`` maps a role (``all``/``inbox``/``sent``) to the wire name."""

    address: str = field(repr=False)
    app_password: str = field(repr=False)
    imap_host: str = field(repr=False)
    imap_port: int
    own_addresses: tuple[str, ...] = field(repr=False)
    account: str
    gmail: bool
    mailboxes: dict[str, str] = field(repr=False)

    def __post_init__(self) -> None:
        if not ACCOUNT_RE.fullmatch(self.account):
            raise MailSecretsError("secrets_corrupt")
        if not self.mailboxes or not set(self.mailboxes) <= _ROLES:
            raise MailSecretsError("secrets_corrupt")
        if isinstance(self.imap_port, bool) or not 0 < self.imap_port < 65536:
            raise MailSecretsError("secrets_corrupt")

    def __repr__(self) -> str:  # never let a traceback or log line print secrets
        return f"MailCredentials(account={self.account!r}, gmail={self.gmail}, roles={sorted(self.mailboxes)})"

    @property
    def roles(self) -> tuple[str, ...]:
        """Configured mailbox roles in fetch order (a generic sent folder after the inbox)."""
        return tuple(role for role in ("all", "inbox", "sent") if role in self.mailboxes)


def encode(value: MailCredentials) -> bytes:
    payload = {
        "version": _SCHEMA_VERSION,
        "address": value.address,
        "app_password": value.app_password,
        "imap_host": value.imap_host,
        "imap_port": value.imap_port,
        "own_addresses": list(value.own_addresses),
        "account": value.account,
        "gmail": value.gmail,
        "mailboxes": dict(value.mailboxes),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise MailSecretsError("secrets_corrupt")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise MailSecretsError("secrets_corrupt")
    return tuple(value)


def decode(blob: bytes) -> MailCredentials:
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise MailSecretsError("secrets_corrupt") from None
    if not isinstance(payload, dict) or payload.get("version") != _SCHEMA_VERSION:
        raise MailSecretsError("secrets_corrupt")
    mailboxes = payload.get("mailboxes")
    port = payload.get("imap_port")
    gmail = payload.get("gmail")
    if not isinstance(mailboxes, dict) or not all(isinstance(v, str) and v for v in mailboxes.values()):
        raise MailSecretsError("secrets_corrupt")
    if not isinstance(port, int) or not isinstance(gmail, bool):
        raise MailSecretsError("secrets_corrupt")
    return MailCredentials(
        address=_string(payload, "address"),
        app_password=_string(payload, "app_password"),
        imap_host=_string(payload, "imap_host"),
        imap_port=port,
        own_addresses=_strings(payload.get("own_addresses")),
        account=_string(payload, "account"),
        gmail=gmail,
        mailboxes={str(k): str(v) for k, v in mailboxes.items()},
    )


def _platform() -> str:
    return sys.platform


def _home() -> Path:
    from ..._home import hermes_home

    return hermes_home()


def mail_dir(home: Path | None = None) -> Path:
    return (home if home is not None else _home()) / "mordred" / "mail"


def ensure_private_dir(path: Path) -> Path:
    """``path`` as a 0700 directory (never a symlink) with a ``*`` ``.gitignore``."""
    if path.is_symlink():
        raise MailSecretsError("store_path_unsafe")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise MailSecretsError("store_path_unsafe")
    os.chmod(path, 0o700)
    ignore = path / ".gitignore"
    if not ignore.exists():
        from ...keyvault._storage import atomic_write

        atomic_write(ignore, _GITIGNORE)
    return path


def _pack(blob: bytes, dek: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = _secrets.token_bytes(_NONCE_LEN)
    return _MAGIC + struct.pack(">H", len(blob)) + blob + nonce + AESGCM(dek).encrypt(nonce, plaintext, _AAD)


def _unpack(sealed: bytes) -> tuple[bytes, bytes, bytes]:
    header = len(_MAGIC) + 2
    if len(sealed) < header or not sealed.startswith(_MAGIC):
        raise MailSecretsError("secrets_corrupt")
    (blob_len,) = struct.unpack(">H", sealed[len(_MAGIC) : header])
    blob = sealed[header : header + blob_len]
    nonce = sealed[header + blob_len : header + blob_len + _NONCE_LEN]
    body = sealed[header + blob_len + _NONCE_LEN :]
    if len(blob) != blob_len or len(nonce) != _NONCE_LEN or len(body) < 16:
        raise MailSecretsError("secrets_corrupt")
    return blob, nonce, body


def _hardware_backend(home: Path | None) -> Any:
    from ...extension.telegram.secrets import TelegramSecretsError
    from ...extension.telegram.tee import hardware_backend

    try:
        return hardware_backend(home)
    except TelegramSecretsError:
        raise MailSecretsError("tee_unavailable") from None


def _audit_sink(entry: dict[str, Any]) -> None:
    from .._audit import append

    append(entry)


class MailSecretStore:
    """Seal, unseal and forget the mail credentials (macOS Secure Enclave custody)."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        backend_factory: Callable[[], Any] | None = None,
        audit_sink: Callable[[dict[str, Any]], None] = _audit_sink,
        platform: Callable[[], str] | None = None,
    ) -> None:
        self._root = root
        self._backend_factory = backend_factory or (lambda: _hardware_backend(None))
        self._audit_sink = audit_sink
        self._platform = platform or (lambda: _platform())

    def _check_platform(self) -> None:
        if self._platform() != "darwin":
            raise MailSecretsError("unsupported_platform")

    def _dir(self, *, create: bool) -> Path:
        self._check_platform()
        path = self._root if self._root is not None else mail_dir()
        return ensure_private_dir(path) if create else path

    @property
    def sealed_path(self) -> Path:
        return self._dir(create=False) / _SEALED_NAME

    @property
    def meta_path(self) -> Path:
        return self._dir(create=False) / _META_NAME

    # -- Enclave key ------------------------------------------------------------------------

    def ensure_key(self, *, require_presence: bool = True) -> None:
        """Create the Enclave key if it does not exist yet (presence applies only to a new key)."""
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError, WrapKeyNotFound

        self._check_platform()
        backend = self._backend_factory()
        try:
            wrap.get_wrapping_key_public(KEY_ID, backend=backend)
            return
        except WrapKeyNotFound:
            pass
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None
        try:
            wrap.generate_wrapping_key(KEY_ID, backend=backend, unattended=not require_presence)
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None

    # -- seal / unseal ----------------------------------------------------------------------

    def _seal(self, plaintext: bytes) -> bytes:
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError

        dek = _secrets.token_bytes(32)
        try:
            blob = wrap.wrap_dek(dek, KEY_ID, backend=self._backend_factory())  # public key only: no prompt
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None
        return _pack(blob, dek, plaintext)

    def _unseal(self, sealed: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapAuthCancelled, WrapError

        blob, nonce, body = _unpack(sealed)
        try:
            dek = wrap.unwrap_dek(blob, KEY_ID, audit_sink=self._audit_sink, backend=self._backend_factory())
        except WrapAuthCancelled:
            raise MailSecretsError("tee_auth_cancelled") from None
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None
        try:
            return AESGCM(dek).decrypt(nonce, body, _AAD)
        except InvalidTag:
            raise MailSecretsError("secrets_corrupt") from None

    def _read_sealed(self) -> bytes | None:
        path = self.sealed_path
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_SEALED_BYTES:
            raise MailSecretsError("secrets_corrupt")
        return path.read_bytes()

    def load(self) -> MailCredentials | None:
        """Unseal through the Enclave (a fresh unwrap every call); ``None`` when not configured."""
        sealed = self._read_sealed()
        return None if sealed is None else decode(self._unseal(sealed))

    def store(self, value: MailCredentials, *, require_presence: bool = True) -> None:
        """Seal ``value`` (replacing any earlier credentials) and write the non-secret flags."""
        from ...keyvault._storage import atomic_write

        self._dir(create=True)
        atomic_write(self.sealed_path, self._seal(encode(value)))
        flags = {
            "version": _SCHEMA_VERSION,
            "account": value.account,
            "gmail": value.gmail,
            "roles": list(value.roles),
            "touch_id": require_presence,
        }
        atomic_write(self.meta_path, json.dumps(flags, sort_keys=True).encode("utf-8"))

    def flags(self) -> dict[str, Any] | None:
        """Non-secret flags, or ``None`` when no credentials are sealed. Never touches the Enclave."""
        try:
            sealed, meta = self.sealed_path, self.meta_path
        except MailSecretsError:
            return None
        if sealed.is_symlink() or meta.is_symlink() or not sealed.is_file():
            return None
        try:
            value = json.loads(meta.read_text("utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(value, dict) or not isinstance(value.get("account"), str):
            return None
        if not ACCOUNT_RE.fullmatch(value["account"]):
            return None
        return value

    def forget(self) -> None:
        """Delete the sealed file, the flags and the Enclave key (absent is fine)."""
        from ...keyvault import wrap

        for path in (self.sealed_path, self.meta_path):
            path.unlink(missing_ok=True)
        with contextlib.suppress(Exception):  # no key, or no helper: the sealed file is already gone
            wrap.delete_wrapping_key(KEY_ID, backend=self._backend_factory())


def own_address_list(address: str, extra: Sequence[str]) -> tuple[str, ...]:
    """The account address plus ``extra``, lowercased, de-duplicated and sorted."""
    return tuple(sorted({address.strip().lower(), *(item.strip().lower() for item in extra if item.strip())}))
