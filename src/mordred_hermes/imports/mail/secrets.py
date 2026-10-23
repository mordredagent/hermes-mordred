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
Gmail path, mailbox roles, presence, and a random ``setup_id`` naming this
setup) so status and the Hermes tool's availability check never touch the
Enclave and never see the address; ``mail forget`` uses ``setup_id`` to tell
the credentials it resolved from ones a concurrent ``mail setup`` installed.
:meth:`MailSecretStore.store` writes both files under staging names first and
renames them in order (sealed file, then flags); a failure removes whatever it
wrote. A sealed file without readable flags (a crash between the two renames,
or a damaged flags file) is a distinct state: :meth:`MailSecretStore.flags`
raises ``credentials_left`` instead of reporting "not configured".
:meth:`MailSecretStore.forget` deletes the sealed file, the flags and the
Enclave key whatever the flags say, and :meth:`MailSecretStore.residue` sees
any sealed or flags file in any form.

An existing Enclave key keeps the Touch ID policy it was created with, which
the Enclave cannot report. When this store creates the key it records the
policy next to the credentials (``enclave-key.json``: the public key's SHA-256
and the policy, nothing secret), and :meth:`MailSecretStore.ensure_key`
returns the EFFECTIVE policy: the requested one for a key it created, the
recorded one for an existing key the record names, ``None`` when unknown. With
``replace=True`` (``mail setup``, under the writer lock, with no credentials
sealed: a key left by a failed setup) it deletes an existing key first
(``touch_id_policy_mismatch`` when that is impossible). The flags record the
effective policy.

``<home>/mordred/mail/generation`` (0600, a random token, nothing secret) names
the setup generation: every seal and every ``mail forget`` rewrites it under the
writer lock and it survives forget, so a setup flow can tell that the mailbox
was set up or removed while it waited (:func:`setup_generation`,
:func:`new_setup_generation`).

The sealed payload is validated on every load: port 993 only (implicit TLS),
a DNS host name, mailbox names that are printable ASCII without control
characters (they are sent as quoted strings), at least one own address.

Other platforms refuse with ``unsupported_platform`` before any filesystem use
(``mordred.db`` is macOS-only, and Windows custody roles are frozen by C5a).
"""

from __future__ import annotations

import contextlib
import hashlib
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
    "new_setup_generation",
    "setup_generation",
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
#: The only port: implicit TLS (``imap.IMAPS_PORT``).
IMAPS_PORT: Final = 993
_MAX_MAILBOX_CHARS: Final = 1000
_GITIGNORE: Final = b"# Mordred mail credentials: sealed, never version-controlled.\n*\n"
#: Staging names of :meth:`MailSecretStore.store` (dot files: never read as credentials, removed by forget).
_STAGED_GLOB: Final = ".credentials.*.staged"
#: The policy of the Enclave key this store created: ``{"public_sha256", "touch_id"}`` (nothing secret).
_KEY_RECORD_NAME: Final = "enclave-key.json"
_GENERATION_NAME: Final = "generation"
_GENERATION_RE: Final = re.compile(r"[0-9a-f]{32}")
#: :func:`setup_generation` before the first seal or forget of a home.
GENERATION_ABSENT: Final = "absent"


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
        from ._imap_codec import safe_mailbox_name
        from .imap import valid_host

        if not ACCOUNT_RE.fullmatch(self.account):
            raise MailSecretsError("secrets_corrupt")
        if not self.mailboxes or not set(self.mailboxes) <= _ROLES:
            raise MailSecretsError("secrets_corrupt")
        if not all(safe_mailbox_name(name) and len(name) <= _MAX_MAILBOX_CHARS for name in self.mailboxes.values()):
            raise MailSecretsError("secrets_corrupt")  # a name that could frame an IMAP command
        if isinstance(self.imap_port, bool) or self.imap_port != IMAPS_PORT:
            raise MailSecretsError("secrets_corrupt")
        if not valid_host(self.imap_host) or not self.own_addresses:
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

    @property
    def key_record_path(self) -> Path:
        return self._dir(create=False) / _KEY_RECORD_NAME

    def ensure_key(self, *, require_presence: bool = True, replace: bool = False) -> bool | None:
        """Make sure the Enclave key exists; return its EFFECTIVE Touch ID policy, ``None`` when unknown.

        A key created here has the requested policy, recorded and returned. An
        existing key keeps its own policy: the recorded one is returned when the
        record names this very key (its public key), else ``None``.
        ``replace=True`` deletes an existing key first (only when no credentials
        are sealed and the caller holds the writer lock, as ``mail setup`` does)
        and raises ``touch_id_policy_mismatch`` when it cannot be deleted.
        """
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError, WrapKeyNotFound

        self._check_platform()
        backend = self._backend_factory()
        try:
            public: bytes | None = wrap.get_wrapping_key_public(KEY_ID, backend=backend)
        except WrapKeyNotFound:
            public = None
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None
        if public is not None and not replace:
            return self._recorded_policy(public)
        if public is not None:
            try:
                wrap.delete_wrapping_key(KEY_ID, backend=backend)
            except Exception:  # never stringified: a Keychain refusal is only a code
                raise MailSecretsError("touch_id_policy_mismatch") from None
        try:
            public = wrap.generate_wrapping_key(KEY_ID, backend=backend, unattended=not require_presence)
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None
        self._record_policy(public, require_presence)
        return require_presence

    def _record_policy(self, public: bytes, require_presence: bool) -> None:
        from ...keyvault._storage import atomic_write

        record = {"public_sha256": hashlib.sha256(public).hexdigest(), "touch_id": require_presence}
        atomic_write(self._dir(create=True) / _KEY_RECORD_NAME, json.dumps(record, sort_keys=True).encode("utf-8"))

    def _recorded_policy(self, public: bytes) -> bool | None:
        try:
            value = json.loads(self.key_record_path.read_text("utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(value, dict) or value.get("public_sha256") != hashlib.sha256(public).hexdigest():
            return None  # no record, or the record of another key
        policy = value.get("touch_id")
        return policy if isinstance(policy, bool) else None

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
        """Seal ``value`` (replacing any earlier credentials) and write the non-secret flags.

        ``require_presence`` is recorded as the flags' ``touch_id``: pass the
        policy :meth:`ensure_key` returned. Both files are written under staging
        names, then renamed in order (sealed file, then flags); on any failure
        everything this call wrote is removed and the error re-raised.
        """
        from ...keyvault._storage import atomic_write

        folder = self._dir(create=True)
        sealed = self._seal(encode(value))  # the Enclave wrap first: an Enclave failure writes nothing
        flags = {
            "version": _SCHEMA_VERSION,
            "account": value.account,
            "gmail": value.gmail,
            "roles": list(value.roles),
            "touch_id": require_presence,
            "setup_id": _secrets.token_hex(16),
        }
        token = _secrets.token_hex(8)
        staged = [folder / f".{_SEALED_NAME}.{token}.staged", folder / f".{_META_NAME}.{token}.staged"]
        written: list[Path] = []
        try:
            for path, data in zip(staged, (sealed, json.dumps(flags, sort_keys=True).encode("utf-8")), strict=True):
                written.append(path)
                atomic_write(path, data)
            for path, final in zip(staged, (self.sealed_path, self.meta_path), strict=True):
                os.replace(path, final)
                written.append(final)
            _sync_directory(folder)
        except BaseException:
            for path in written:
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)
            raise

    def flags(self) -> dict[str, Any] | None:
        """Non-secret flags, or ``None`` when no credentials are sealed. Never touches the Enclave.

        A sealed file whose flags are missing, unreadable or invalid raises
        ``MailSecretsError("credentials_left")``: it is neither configured nor
        absent (``mail forget`` removes it).
        """
        try:
            sealed, meta = self.sealed_path, self.meta_path
        except MailSecretsError:
            return None
        try:
            os.lstat(sealed)
        except FileNotFoundError:
            return None
        except OSError:
            raise MailSecretsError("credentials_left") from None
        value = _read_flags(sealed, meta)
        if value is None:
            raise MailSecretsError("credentials_left")
        return value

    def residue(self) -> bool:
        """True while a sealed file or a flags file exists in any form (valid, corrupt or a symlink).

        Unlike :meth:`flags` this never depends on the flags being readable, so
        ``mail forget`` can tell "nothing was set up" from "credentials whose
        flags are missing or corrupt". Never touches the Enclave.
        """
        try:
            paths = (self.sealed_path, self.meta_path)
        except MailSecretsError:
            return False
        for path in paths:
            try:
                os.lstat(path)
            except FileNotFoundError:
                continue
            return True
        return False

    def forget(self) -> bool:
        """Delete the sealed file, the flags and the Enclave key, whatever the flags say (absent is fine).

        Returns ``False`` when the Enclave key could not be deleted (no helper, a
        Keychain error): the sealed file is gone already, so the key unwraps
        nothing, and a retry deletes it. A file that cannot be removed raises.
        """
        from ...keyvault import wrap

        for path in (self.sealed_path, self.meta_path, self.key_record_path):
            path.unlink(missing_ok=True)
        for path in self.sealed_path.parent.glob(_STAGED_GLOB):  # left by a store() that was killed
            path.unlink(missing_ok=True)
        try:
            wrap.delete_wrapping_key(KEY_ID, backend=self._backend_factory())  # idempotent: no key is fine
        except Exception:
            return False
        return True


def setup_generation(home: Path) -> str:
    """The token naming ``home``'s current mail setup generation (:data:`GENERATION_ABSENT` before any)."""
    path = mail_dir(home) / _GENERATION_NAME
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return GENERATION_ABSENT
    if not stat.S_ISREG(info.st_mode):
        raise MailSecretsError("store_path_unsafe")
    value = path.read_text("ascii", errors="replace").strip()
    return value if _GENERATION_RE.fullmatch(value) else "unreadable"


def new_setup_generation(home: Path) -> str:
    """Rewrite ``home``'s setup generation (0600, a fresh random token); every seal and every forget does."""
    from ...keyvault._storage import atomic_write

    token = _secrets.token_hex(16)
    atomic_write(ensure_private_dir(mail_dir(home)) / _GENERATION_NAME, token.encode("ascii"))
    return token


def _read_flags(sealed: Path, meta: Path) -> dict[str, Any] | None:
    """The flags of a regular sealed file, or ``None`` when they are missing, unreadable or invalid."""
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


def _sync_directory(folder: Path) -> None:
    """Flush the directory entries of the renames (POSIX; a directory cannot be opened elsewhere)."""
    if os.name != "posix":
        return
    fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def own_address_list(address: str, extra: Sequence[str]) -> tuple[str, ...]:
    """The account address plus ``extra``, lowercased, de-duplicated and sorted."""
    return tuple(sorted({address.strip().lower(), *(item.strip().lower() for item in extra if item.strip())}))
