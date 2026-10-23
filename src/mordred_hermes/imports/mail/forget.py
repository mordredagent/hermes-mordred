"""Remove the IMAP mail setup: the account's rows (optional), its cursors, then the credentials and the key (macOS).

Shared by ``hermes-mordred mail forget`` and the Desktop page (SPEC "Desktop mail and
ceremony pages (2026-10-23)"). The order makes a failed forget retryable: rows and
cursors go first, the sealed credentials, their flags and the Enclave key last.

- The target is resolved before the per-home mail writer lock
  (:func:`~.imap_sync.fetch_lock`, ``sync_in_progress`` when held) and re-checked
  under it: if a ``mail setup`` replaced the credentials meanwhile (``setup_id``),
  nothing is deleted (``credentials_changed``), so a concurrent setup is never undone.
- The label whose rows and cursors are deleted is the sealed one; ``account``
  names it once the credentials are gone (``account_mismatch`` when it names
  another label than the sealed one; ``invalid_account`` when it is not a label).
- ``rows=True`` first deletes the account's mail rows (``delete_source``) and stops
  with the store's code, touching nothing, when the store refuses. Callers ask the
  owner to confirm that deletion (``mail forget --yes``, the page's
  ``delete my data`` phrase) BEFORE calling.
- The sealed file, the flags and the Enclave key are deleted whatever the flags
  say. Credentials whose flags are missing or corrupt are still deleted and
  reported as unidentified (``account_unknown``: their rows and cursors need
  ``account``). A sealed file that remains is ``credentials_left`` (never a
  success); a key that could not be deleted is reported (``key_left``; a retry
  deletes it).

Pending setup flows of another process are out of reach here: the Desktop page
calls :meth:`~.setup_flow.MailSetupFlows.cancel_all` itself. Failures are
:class:`MailForgetError` codes; nothing here logs or returns an address.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .imap_sync import CURSOR_PREFIX, FetchStop, fetch_lock
from .secrets import ACCOUNT_RE, MailSecretsError

__all__ = ["Forgotten", "MailForgetError", "audit_entry", "forget"]

#: The identity of sealed credentials whose flags are missing or unreadable: present, label unknown.
_UNIDENTIFIED: Final = ("", "")

OpenStore = Callable[[Path], Any]
WriterLock = Callable[[Path], contextlib.AbstractContextManager[None]]


class MailForgetError(Exception):
    """A content-free forget refusal: ``invalid_account``, ``account_mismatch``, ``credentials_changed``,
    ``credentials_left``, ``sync_in_progress``, ``store_path_unsafe``, a store code or ``fetch_failed``."""

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
    unidentified: bool  # credentials were present but their label could not be read
    key_gone: bool

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
    return _UNIDENTIFIED if secret_store.residue() else None


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
    deleted, cursors, left = _forget_store(open_store, home, label, rows) if label else (0, 0, None)
    key_gone = secret_store.forget() is not False  # the sealed file, the flags and the Enclave key, whatever is left
    if secret_store.residue():
        raise MailForgetError("credentials_left")  # never report success while a sealed file remains
    return Forgotten(label, deleted, cursors, left, sealed is not None, sealed == _UNIDENTIFIED, key_gone)


def forget(
    secret_store: Any,
    home: Path,
    *,
    account: str | None = None,
    rows: bool = False,
    open_store: OpenStore = _default_open_store,
    lock: WriterLock = fetch_lock,
) -> Forgotten:
    """Remove the mail setup (see the module docstring); every refusal is a :class:`MailForgetError`."""
    if account is not None and (not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account)):
        raise MailForgetError("invalid_account")
    try:
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
