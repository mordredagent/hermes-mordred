"""Native, independent IMAP credentials with the existing MMC1/AES-GCM format.

The mail role uses ``mail_backend(home=...)`` on POSIX and genuine Windows
custody sessions with explicit v2 enrollment. Native credentials use checked
private filesystem handles, stable mail writer/custody locks, and fresh unwrap
on each load. Public metadata never authenticates deletion or chooses an account
for row erasure. Authenticated retirement journals intent, deletes the native
key first, records acknowledgement, and only then removes the sealed source.
Ambiguous deletion retains evidence; acknowledged POSIX cleanup can resume.

``generation`` survives retirement and invalidates pending setup flows. Existing
native key policy is preserved; an orphan key is retained for checked repair,
never deleted without a source proof. Explicit portable backend injection keeps
the historical fixture seam, without issuing any production native authority.
No root database key, memory source, credential cache, or plaintext spool is used.
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
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from ...keyvault._mail_custody import WindowsMailStore

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


@contextlib.contextmanager
def _mail_native_refusals() -> Iterator[None]:
    """Normalize expected custody refusals without granting or retrying authority.

    Public setup consumers already sanitize MailSecretsError through their
    MailSetupError/sever_chain boundary. Keep cancellation and corrupt wraps
    distinct from unavailable native ownership, just as the portable path does.
    """
    from ..._config_io import PolicyPendingError
    from ..._database_contracts import DatabaseRefused
    from ..._private_fs import PrivateFSError
    from ...keyvault._exceptions import WrapAuthCancelled, WrapError, WrapIntegrityError, WrapParseError
    from ...keyvault._windows_profile import CustodyError
    from ...keyvault.wrap import NativeBackendError

    try:
        yield
    except WrapAuthCancelled:
        code = "tee_auth_cancelled"
    except (WrapIntegrityError, WrapParseError):
        code = "secrets_corrupt"
    except (WrapError, NativeBackendError, DatabaseRefused, CustodyError):
        code = "tee_unavailable"
    except (PrivateFSError, PolicyPendingError):
        code = "store_path_unsafe"
    else:
        return
    raise MailSecretsError(code) from None


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
    from ...keyvault._mail_key import mail_backend

    return mail_backend(home=_home() if home is None else home)


def _audit_sink(entry: dict[str, Any]) -> None:
    from .._audit import append

    append(entry)


class MailSecretStore:
    """Seal, unseal and retire independent native mail credentials."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        backend_factory: Callable[[], Any] | None = None,
        audit_sink: Callable[[dict[str, Any]], None] = _audit_sink,
        platform: Callable[[], str] | None = None,
    ) -> None:
        self._root = root
        self._backend_factory = backend_factory or (lambda: _hardware_backend(self._profile_home()))
        self._native_backend: Any = None
        self._injected = backend_factory is not None
        self._windows_store: WindowsMailStore | None = None
        self._audit_sink = audit_sink
        self._platform = platform or (lambda: _platform())

    def _check_platform(self) -> None:
        if self._platform() not in {"darwin", "linux", "win32"}:
            raise MailSecretsError("unsupported_platform")

    def _profile_home(self) -> Path:
        from ...keyvault._mail_custody import checked_home

        return checked_home(self._root if self._root is not None else mail_dir())

    def _backend(self) -> Any:
        from ...keyvault._mail_key import _MailBackend

        if self._native_backend is None:
            selected = self._backend_factory()
            self._native_backend = selected._backend if type(selected) is _MailBackend else selected
        return self._native_backend

    def _native(self) -> bool:
        from ...keyvault._seckey_backend import _SecKeyBackend

        return not self._injected or type(self._backend()) is _SecKeyBackend

    def _windows(self) -> WindowsMailStore:
        from ...keyvault._mail_custody import WindowsMailStore

        home = self._profile_home()
        if self._windows_store is None or self._windows_store.home != home:
            self._windows_store = WindowsMailStore(
                home, backend=self._backend() if self._injected else None, audit_sink=self._audit_sink
            )
        return self._windows_store

    def load_snapshot(self) -> tuple[MailCredentials | None, Any]:
        with _mail_native_refusals():
            return self._load_snapshot()

    def _load_snapshot(self) -> tuple[MailCredentials | None, Any]:
        self._check_platform()
        if self._platform() == "win32":
            return self._windows().load_snapshot()
        if not self._native():
            sealed = self._read_sealed()
            return (None if sealed is None else decode(self._unseal(sealed))), None
        from ..._private_fs import PrivateFSError, open_private_directory
        from ...keyvault._mail_custody import JOURNAL, SEALED, authenticate_mail_source, read

        home = self._profile_home()
        try:
            with open_private_directory(home / "mordred/mail") as directory:
                if read(directory, JOURNAL) is not None:
                    from ..._database_contracts import DatabaseRefused

                    raise DatabaseRefused("mail retirement pending; evidence retained")
                if read(directory, SEALED) is None:
                    return None, None
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return None, None
            raise
        entries: list[dict[str, Any]] = []
        try:
            return authenticate_mail_source(home=home, backend=self._backend(), entries=entries)
        finally:
            for entry in entries:
                self._audit_sink(entry)

    def forget_from_snapshot(self, snapshot: tuple[MailCredentials | None, Any]) -> bool:
        with _mail_native_refusals():
            from ...keyvault._mail_custody import check_snapshot_home
            from .imap_sync import mail_writer_scope

            home = self._profile_home()
            check_snapshot_home(snapshot[1], home)
            with mail_writer_scope(home):
                return self._forget_from_snapshot(snapshot)

    def _forget_from_snapshot(self, snapshot: tuple[MailCredentials | None, Any]) -> bool:
        if self._platform() == "win32":
            return bool(self._windows().forget_from_snapshot(snapshot))
        from ..._database_contracts import DatabaseRefused
        from ...keyvault._mail_custody import JOURNAL, META, SEALED, mail_credential_transaction, read

        with mail_credential_transaction(
            home=self._profile_home(), backend=self._backend(), authenticated=snapshot[1], resume=True
        ) as custody:
            if read(custody.transaction, JOURNAL) is not None:
                custody.cleanup()
            elif read(custody.transaction, SEALED) is not None:
                custody.retire()
            else:
                if read(custody.transaction, META) is not None:
                    raise DatabaseRefused("mail metadata without a source requires reconciliation")
                # Absence of a source is never proof authorizing orphan-key deletion.
                from ...keyvault._exceptions import WrapKeyNotFound

                try:
                    self._backend().get_enclave_public_key(KEY_ID)
                except WrapKeyNotFound:
                    return True
                raise DatabaseRefused("mail native key has no authenticated source; retained for repair")
        return True

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

    def _prepare_setup(self, *, require_presence: bool) -> None:
        with _mail_native_refusals():
            if self._platform() == "win32":
                if require_presence:
                    raise MailSecretsError("presence_unsupported")
                self._windows().prepare_setup()

    def ensure_key(self, *, require_presence: bool = True, replace: bool = False) -> bool | None:
        with _mail_native_refusals():
            self._check_platform()
            self._prepare_setup(require_presence=require_presence)
            if self._platform() == "win32" or self._native():
                from .imap_sync import mail_writer_scope

                with mail_writer_scope(self._profile_home()):
                    return self._ensure_key(require_presence=require_presence, replace=replace)
            return self._ensure_key(require_presence=require_presence, replace=replace)

    def _ensure_key(self, *, require_presence: bool = True, replace: bool = False) -> bool | None:
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
        if self._platform() == "win32":
            return self._windows().ensure_key(require_presence=require_presence, replace=replace)
        if self._native():
            return self._ensure_posix_key(require_presence=require_presence, replace=replace)
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
                backend.delete_enclave_key(KEY_ID)
            except Exception:  # never stringified: a Keychain refusal is only a code
                raise MailSecretsError("touch_id_policy_mismatch") from None
        try:
            public = wrap.generate_wrapping_key(KEY_ID, backend=backend, unattended=not require_presence)
        except WrapError:
            raise MailSecretsError("tee_unavailable") from None
        try:
            self._record_policy(public, require_presence)
        except (OSError, MailSecretsError):
            # A key whose policy is not recorded would read as "unknown" forever: never leave one behind.
            with contextlib.suppress(Exception):
                backend.delete_enclave_key(KEY_ID)
            raise MailSecretsError("store_path_unsafe") from None
        return require_presence

    def _ensure_posix_key(self, *, require_presence: bool, replace: bool) -> bool | None:
        from ..._database_contracts import DatabaseRefused
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapKeyNotFound
        from ...keyvault._mail_custody import SEALED, mail_credential_transaction, publish, read

        with mail_credential_transaction(home=self._profile_home(), backend=self._backend(), create=True) as custody:
            try:
                public = wrap.get_wrapping_key_public(KEY_ID, backend=self._backend())
            except WrapKeyNotFound:
                if read(custody.transaction, SEALED) is not None:
                    raise DatabaseRefused("mail source lacks its native key; retained for repair") from None
                public = wrap.generate_wrapping_key(KEY_ID, backend=self._backend(), unattended=not require_presence)
                record = {"public_sha256": hashlib.sha256(public).hexdigest(), "touch_id": require_presence}
                publish(custody.transaction, _KEY_RECORD_NAME, json.dumps(record).encode())
                return require_presence
            policy = self._recorded_policy(public)
            if replace and policy != require_presence:
                raise MailSecretsError("touch_id_policy_mismatch")
            return policy

    def _record_policy(self, public: bytes, require_presence: bool) -> None:
        from ...keyvault._storage import atomic_write

        record = {"public_sha256": hashlib.sha256(public).hexdigest(), "touch_id": require_presence}
        atomic_write(self._dir(create=True) / _KEY_RECORD_NAME, json.dumps(record, sort_keys=True).encode("utf-8"))

    def _recorded_policy(self, public: bytes) -> bool | None:
        if self._native():
            from ..._private_fs import open_private_directory
            from ...keyvault._mail_custody import read

            with open_private_directory(self.key_record_path.parent) as directory:
                item = read(directory, _KEY_RECORD_NAME)
            raw = None if item is None else item[0]
            try:
                value = None if raw is None else json.loads(raw)
            except ValueError:
                return None
        else:
            try:
                value = json.loads(self.key_record_path.read_text("utf-8"))
            except (OSError, ValueError):
                return None
        if not isinstance(value, dict) or value.get("public_sha256") != hashlib.sha256(public).hexdigest():
            return None
        policy = value.get("touch_id")
        return policy if isinstance(policy, bool) else None

    # -- seal / unseal ----------------------------------------------------------------------

    def _seal(self, plaintext: bytes) -> bytes:
        from ...keyvault import wrap
        from ...keyvault._exceptions import WrapError

        dek = _secrets.token_bytes(32)
        try:
            blob = wrap.wrap_dek(dek, KEY_ID, backend=self._backend())  # public key only: no prompt
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
            dek = wrap.unwrap_dek(blob, KEY_ID, audit_sink=self._audit_sink, backend=self._backend())
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
        return self.load_snapshot()[0]

    def store(self, value: MailCredentials, *, require_presence: bool = True) -> None:
        with _mail_native_refusals():
            self._check_platform()
            if self._platform() == "win32" and require_presence:
                raise MailSecretsError("presence_unsupported")
            if self._platform() == "win32" or self._native():
                from .imap_sync import mail_writer_scope

                with mail_writer_scope(self._profile_home()):
                    self._store(value, require_presence=require_presence)
            else:
                self._store(value, require_presence=require_presence)

    def _store(self, value: MailCredentials, *, require_presence: bool = True) -> None:
        """Seal ``value`` (replacing any earlier credentials) and write the non-secret flags.

        ``require_presence`` is recorded as the flags' ``touch_id``: pass the
        policy :meth:`ensure_key` returned. Both files are written under staging
        names, then renamed in order (sealed file, then flags); on any failure
        everything this call wrote is removed and the error re-raised.
        """
        from ...keyvault._storage import atomic_write

        self._check_platform()
        if self._platform() == "win32":
            self._windows().store(value, require_presence=require_presence)
            return
        if self._native():
            from ...keyvault._mail_custody import mail_credential_transaction, publish

            flags = {
                "version": _SCHEMA_VERSION,
                "account": value.account,
                "gmail": value.gmail,
                "roles": list(value.roles),
                "touch_id": require_presence,
                "setup_id": _secrets.token_hex(16),
            }
            with mail_credential_transaction(
                home=self._profile_home(), backend=self._backend(), create=True
            ) as custody:
                sealed = self._seal(encode(value))
                flags["sealed_sha256"] = hashlib.sha256(sealed).hexdigest()
                publish(custody.transaction, _SEALED_NAME, sealed)
                publish(custody.transaction, _META_NAME, json.dumps(flags, sort_keys=True).encode())
            return
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
        with _mail_native_refusals():
            return self._flags()

    def _flags(self) -> dict[str, Any] | None:
        """Non-secret flags, or ``None`` when no credentials are sealed. Never touches the Enclave.

        A sealed file whose flags are missing, unreadable or invalid raises
        ``MailSecretsError("credentials_left")``: it is neither configured nor
        absent (``mail forget`` removes it).
        """
        root = self._root if self._root is not None else mail_dir()
        if not self._injected or root.parent.name == "mordred":
            return self._checked_flags(root)
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

    def _checked_flags(self, root: Path) -> dict[str, Any] | None:
        from ..._private_fs import PrivateFSError, open_private_directory
        from ...keyvault._mail_custody import JOURNAL, read

        try:
            with open_private_directory(root) as directory:
                if read(directory, JOURNAL) is not None:
                    raise MailSecretsError("credentials_left")
                sealed_item = read(directory, _SEALED_NAME)
                meta_item = read(directory, _META_NAME)
                if sealed_item is None:
                    return None
                value = None if meta_item is None else json.loads(meta_item[0])
                if (
                    not isinstance(value, dict)
                    or not isinstance(value.get("account"), str)
                    or not ACCOUNT_RE.fullmatch(value["account"])
                ):
                    raise MailSecretsError("credentials_left")
                digest = value.get("sealed_sha256")
                if digest is not None and digest != hashlib.sha256(sealed_item[0]).hexdigest():
                    raise MailSecretsError("credentials_left")
                return value
        except PrivateFSError as exc:
            if exc.reason == "missing":
                return None
            raise MailSecretsError("credentials_left") from exc
        except ValueError as exc:
            raise MailSecretsError("credentials_left") from exc

    def residue(self) -> bool:
        """True while any credential file is left: the sealed file, the flags or a staged copy, in any form.

        Unlike :meth:`flags` this never depends on the flags being readable, so
        ``mail forget`` can tell "nothing was set up" from "credentials whose
        flags are missing or corrupt", and a ``store`` whose cleanup failed is
        still seen through its staged files (``.credentials.*.staged``). It is the
        ``credentials_left`` state for everything but sealed credentials with
        readable flags. Never touches the Enclave.
        """
        return self.credential_files() or self.staged_files()

    def credential_files(self) -> bool:
        """True while the sealed file or the flags file exists in any form (a staged copy does not count)."""
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

    def staged_files(self) -> bool:
        """True while a staged copy of a seal (``.credentials.*.staged``) is left behind."""
        try:
            folder = self.sealed_path.parent
        except MailSecretsError:
            return False
        try:
            return any(True for _path in folder.glob(_STAGED_GLOB))
        except OSError:
            return True  # cannot tell: never report a clean directory

    def forget(self) -> bool:
        with _mail_native_refusals():
            self._check_platform()
            if self._platform() == "win32" or self._native():
                from .imap_sync import mail_writer_scope

                with mail_writer_scope(self._profile_home()):
                    return self._forget()
            return self._forget()

    def _forget(self) -> bool:
        """Delete the sealed file, the flags and the Enclave key, whatever the flags say (absent is fine).

        Returns ``False`` when the Enclave key could not be deleted (no helper, a
        Keychain error): the sealed file is gone already, so the key unwraps
        nothing, and a retry deletes it. A file that cannot be removed raises.
        """

        self._check_platform()
        if self._platform() == "win32":
            return bool(self._windows().forget())
        if self._native():
            from ..._private_fs import PrivateFSError, open_private_directory
            from ...keyvault._mail_custody import JOURNAL, read

            try:
                with open_private_directory(self._profile_home() / "mordred/mail") as directory:
                    pending = read(directory, JOURNAL) is not None
            except PrivateFSError as exc:
                if exc.reason == "missing":
                    return True
                raise
            return self.forget_from_snapshot((None, None) if pending else self.load_snapshot())
        for path in (self.sealed_path, self.meta_path, self.key_record_path):
            path.unlink(missing_ok=True)
        for path in self.sealed_path.parent.glob(_STAGED_GLOB):  # left by a store() that was killed
            path.unlink(missing_ok=True)
        try:
            self._backend().delete_enclave_key(KEY_ID)  # explicit portable fixture backend only
        except Exception:
            return False
        return True


def setup_generation(home: Path) -> str:
    """Read checked setup metadata through the public mail refusal boundary."""
    with _mail_native_refusals():
        return _setup_generation(home)


def _setup_generation(home: Path) -> str:
    """Read the checked public setup generation without creating any files."""
    from ..._private_fs import PrivateFSError, open_private_directory
    from ...keyvault._mail_custody import read

    try:
        with open_private_directory(mail_dir(home)) as directory:
            item = read(directory, _GENERATION_NAME)
    except PrivateFSError as exc:
        if exc.reason == "missing":
            return GENERATION_ABSENT
        raise MailSecretsError("store_path_unsafe") from exc
    if item is None:
        return GENERATION_ABSENT
    value = item[0].decode("ascii", errors="replace").strip()
    return value if _GENERATION_RE.fullmatch(value) else "unreadable"


def new_setup_generation(home: Path) -> str:
    """Publish checked setup metadata through the public mail refusal boundary."""
    with _mail_native_refusals():
        return _new_setup_generation(home)


def _new_setup_generation(home: Path) -> str:
    """Publish a checked private random token; it survives credential retirement."""
    from ..._private_fs import open_private_directory
    from ...keyvault._mail_custody import publish

    token = _secrets.token_hex(16)
    folder = mail_dir(home)
    missing = []
    cursor = folder
    while not cursor.exists() and not cursor.is_symlink():
        missing.append(cursor)
        cursor = cursor.parent
    for path in reversed(missing):
        with open_private_directory(path, create=True):
            pass
    with open_private_directory(folder) as directory, directory.transaction() as tx:
        publish(tx, _GENERATION_NAME, token.encode("ascii"))
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
