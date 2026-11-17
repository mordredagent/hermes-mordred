"""Retire mail credentials and optionally erase the authenticated account's rows.

Native flows capture the protected store's owning database authority before the
shared mail writer. The actual MMC1 payload supplies the account; flags cannot
redirect erasure. Under the same writer, checked credential custody invalidates
pending setup generations and retires the native source first. Database row and
cursor deletion then occurs after credential custody exits, while the writer
still excludes replacement setup/import/sync. No root memory key is touched.

``force_orphan`` (``mail forget --yes --force-orphan``) is the one explicit
repair for a native key left without a sealed source, or a sealed source whose
native key is definitively absent. It runs the custody's own orphan checks under
the same writer, never authenticates or reads a source, and never touches rows or
cursors (their named ``--account`` retry stays separate), so it refuses
``rows``/``account``. The explicit portable secret-store fixture seam retains its
original row-first contract (its forget already retires unconditionally). All
outward failures remain content-free MailForgetError codes.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .imap_sync import CURSOR_PREFIX, FetchStop, fetch_lock
from .secrets import ACCOUNT_RE, MailSecretsError, new_setup_generation

__all__ = ["Forgotten", "MailForgetError", "audit_entry", "forget"]

#: The identity of sealed credentials whose flags are missing or unreadable: present, label unknown.
_UNIDENTIFIED: Final = ("", "")

OpenStore = Callable[[Path], Any]
WriterLock = Callable[[Path], contextlib.AbstractContextManager[None]]


class MailForgetError(Exception):
    """A content-free forget refusal: ``invalid_account``, ``account_mismatch``, ``credentials_changed``,
    ``credentials_left``, ``sync_in_progress``, ``store_path_unsafe``, ``force_orphan_exclusive``, a store
    code (``mail_orphan_key`` among them) or ``fetch_failed``."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Forgotten:
    """What a forget did, as counts and codes."""

    account: str | None  # the label whose rows and cursors were handled (None: no label known)
    deleted_messages: int
    cursors_deleted: int
    cursors_left: str | None  # the store code that left the cursors behind
    had_credentials: bool
    unidentified: bool  # the requested row/cursor erasure target could not be identified
    key_gone: bool
    orphan_key_retired: bool = False  # force_orphan only: a native key without a source was deleted

    @property
    def warnings(self) -> tuple[str, ...]:
        """What remains for the owner to do, as codes (empty: everything asked for is gone)."""
        codes: list[str] = []
        if not self.key_gone:
            codes.append("key_left")
        if self.unidentified and self.account is None:
            codes.append("account_unknown")
        if self.cursors_left is not None:
            codes.append(self.cursors_left)
        return tuple(codes)


def audit_entry(done: Forgotten, *, rows: bool) -> dict[str, Any]:
    """The ``mail.forget`` audit event (counts and flags only)."""
    return {
        "event": "mail.forget",
        "decision": "allow",
        "reason": None,
        "rows": rows,
        "messages_deleted": done.deleted_messages,
        "unidentified": done.unidentified,
    }


def _code(exc: BaseException, fallback: str) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code.isascii() and code.replace("_", "").isalnum() else fallback


def _default_open_store(home: Path) -> Any:
    from .. import store as store_module

    return store_module.open_import_store(home)


def _identity(secret_store: Any) -> tuple[str, str] | None:
    """Which setup the sealed credentials are: (account label, setup id); :data:`_UNIDENTIFIED`; or ``None``."""
    try:
        flags = secret_store.flags()
    except MailSecretsError:
        flags = None  # credentials_left: a sealed file without readable flags
    if flags:
        return str(flags.get("account")), str(flags.get("setup_id", ""))
    # Staged copies of a failed seal are not credentials: forget removes them, but they name no account.
    credential_files = getattr(secret_store, "credential_files", secret_store.residue)
    return _UNIDENTIFIED if credential_files() else None


def _target(account: str | None, sealed: tuple[str, str] | None) -> str | None:
    """The label whose rows and cursors are deleted: the sealed one, or ``account`` once it cannot be read."""
    if sealed is not None and sealed[0]:
        if account is not None and account != sealed[0]:
            raise MailForgetError("account_mismatch")  # the sealed credentials belong to another label
        return sealed[0]
    return account


def _forget_store(open_store: OpenStore, home: Path, account: str, rows: bool) -> tuple[int, int, str | None]:
    """(messages deleted, cursors deleted, the code that left cursors behind); rows first, then cursors."""
    try:
        store = open_store(home)
    except Exception as exc:
        if rows:
            raise MailForgetError(_code(exc, "import_store_unavailable")) from None
        return 0, 0, _code(exc, "import_store_unavailable")
    return _delete_store_rows(store, account, rows)


def _delete_store_rows(store: Any, account: str, rows: bool) -> tuple[int, int, str | None]:
    deleted = 0
    try:
        if rows:
            deleted = int(store.delete_source("mail", account))
        keys = list(store.meta_items(f"{CURSOR_PREFIX}.{account}."))
        for key in keys:
            store.delete_meta(key)
    except Exception as exc:
        if rows:
            raise MailForgetError(_code(exc, "import_store_unavailable")) from None
        return deleted, 0, _code(exc, "import_store_unavailable")
    return deleted, len(keys), None


def _locked_forget(
    secret_store: Any,
    home: Path,
    account: str | None,
    rows: bool,
    resolved: tuple[str, str] | None,
    open_store: OpenStore,
) -> Forgotten:
    """Under the lock: re-check the setup, delete rows and cursors, then the credentials (last, unconditionally)."""
    sealed = _identity(secret_store)
    if sealed != resolved:
        raise MailForgetError("credentials_changed")  # a setup ran since this forget started: touch nothing
    label = _target(account, sealed)
    new_setup_generation(home)  # before anything goes: a setup flow that started earlier can no longer seal
    deleted, cursors, left = _forget_store(open_store, home, label, rows) if label else (0, 0, None)
    key_gone = secret_store.forget() is not False  # the sealed file, the flags and the Enclave key, whatever is left
    if secret_store.residue():
        raise MailForgetError("credentials_left")  # never report success while a sealed file remains
    return Forgotten(label, deleted, cursors, left, sealed is not None, sealed == _UNIDENTIFIED, key_gone)


def _native_forget(
    secret_store: Any, home: Path, account: str | None, rows: bool, open_store: OpenStore, lock: WriterLock
) -> Forgotten:
    # Capture the actual owning store (and its lifetime root SH authority)
    # before writer/custody locks. Never retarget a replacement global provider.
    if secret_store._profile_home() != home:
        raise MailForgetError("credentials_changed")
    try:
        store = open_store(home)
        left = None
    except Exception as exc:
        if rows:
            raise MailForgetError(_code(exc, "import_store_unavailable")) from None
        store, left = None, _code(exc, "import_store_unavailable")
    from ...keyvault._mail_custody import pending_mail_retirement

    pending = pending_mail_retirement(home)
    snapshot = (None, None) if pending else secret_store.load_snapshot()
    credentials = snapshot[0]
    label = account if credentials is None else credentials.account
    if account is not None and credentials is not None and account != credentials.account:
        raise MailForgetError("account_mismatch")
    from .imap_sync import mail_writer_scope

    with lock(home), mail_writer_scope(home):
        # This validates the actual MMC1 source, advances generation under its
        # checked custody, and retires native first. Metadata cannot pick rows.
        key_gone = secret_store.forget_from_snapshot(snapshot)
        if secret_store.residue():
            raise MailForgetError("credentials_left")
        # Credential custody has exited; every SQL operation reuses the store's
        # captured authority while this same mail writer remains held.
        deleted, cursors = 0, 0
        if store is not None and label is not None:
            deleted, cursors, left = _delete_store_rows(store, label, rows)
        # Retirement may already have removed its journal/account before SQL
        # failed or the process stopped. Absence cannot prove requested erasure;
        # require an explicit named retry when no authenticated target survives.
        return Forgotten(label, deleted, cursors, left, credentials is not None or pending, label is None, key_gone)


def _orphan_forget(secret_store: Any, home: Path, lock: WriterLock) -> Forgotten:
    """The explicit orphan repair: credential custody only, no source read, no rows or cursors."""
    if secret_store._profile_home() != home:
        raise MailForgetError("credentials_changed")
    from .imap_sync import mail_writer_scope

    with lock(home), mail_writer_scope(home):
        had = bool(secret_store.credential_files())
        had_key = bool(secret_store.native_key_present())
        key_gone = secret_store.forget(force_orphan=True) is not False
        if secret_store.residue():
            raise MailForgetError("credentials_left")
    # A removed keyless source may leave its account's rows and cursors: only
    # the named retry (`--account LABEL`) erases them, so say the label is unknown.
    return Forgotten(None, 0, 0, None, had, had, key_gone, orphan_key_retired=had_key and key_gone)


def forget(
    secret_store: Any,
    home: Path,
    *,
    account: str | None = None,
    rows: bool = False,
    open_store: OpenStore = _default_open_store,
    lock: WriterLock = fetch_lock,
    force_orphan: bool = False,
) -> Forgotten:
    """Remove the mail setup (see the module docstring); every refusal is a :class:`MailForgetError`."""
    if account is not None and (not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account)):
        raise MailForgetError("invalid_account")
    if force_orphan and (rows or account is not None):
        raise MailForgetError("force_orphan_exclusive")
    try:
        from .secrets import MailSecretStore

        if type(secret_store) is MailSecretStore and (secret_store._platform() == "win32" or secret_store._native()):
            if force_orphan:
                return _orphan_forget(secret_store, home, lock)
            return _native_forget(secret_store, home, account, rows, open_store, lock)
        resolved = _identity(secret_store)  # the target, decided before waiting for the lock
        _target(account, resolved)
        with lock(home):
            return _locked_forget(secret_store, home, account, rows, resolved, open_store)
    except MailForgetError:
        raise
    except FetchStop as exc:
        raise MailForgetError(exc.code) from None
    except (MailSecretsError, OSError) as exc:
        raise MailForgetError(_code(exc, "store_path_unsafe")) from None
    except Exception as exc:  # never stringified: only a code survives
        raise MailForgetError(_code(exc, "fetch_failed")) from None
