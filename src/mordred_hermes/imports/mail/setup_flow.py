"""Step-wise IMAP mail setup shared by ``hermes-mordred mail setup`` and the Desktop page (macOS).

SPEC "Desktop mail and ceremony pages (2026-10-23)", "Mail setup flow"; modelled on
:mod:`mordred_hermes.extension.telegram.login_flow`. ``mail setup`` is a thin
terminal driver over :class:`MailSetupFlows`, so the two entry points cannot drift.

:meth:`MailSetupFlows.start` validates what the owner typed (a Gmail app password
loses its spaces and must then be 16 characters, checked before any connection).
Everything else runs under the per-home mail writer lock
(:func:`~.imap_sync.fetch_lock`; ``sync_in_progress`` while a fetch, an import, a
forget or another setup holds it), so admission and sealing are one decision:

1. sealed credentials, or any residue of them, refuse (``mail_already_configured``:
   the owner removes them first with ``mail forget``);
2. the Enclave key is made fresh with the requested Touch ID policy BEFORE the
   server is contacted: with no credentials sealed, a key left by a failed setup
   protects nothing and is replaced, since an existing key's policy cannot be read
   back (``touch_id_policy_mismatch`` when it cannot be deleted);
3. one read-only login (``LOGIN``, ``LIST``, ``LOGOUT``) and the mailboxes:

   - Gmail (``X-GM-EXT-1``): All Mail (its ``\\All`` special use, else its usual
     name), sealed at once (``step == "done"``); when neither identifies it, the
     owner is asked which folder it is (``step == "folders"``,
     ``question == "all_mail"``), as ``mail setup`` always did;
   - another server with a ``\\Sent`` special-use folder: ``INBOX`` and that
     folder, sealed at once;
   - another server without one: ``question == "sent"`` (choosing none is fine).

A flow waiting for the owner's choice lives in this process's memory only, at most
:data:`MAX_PENDING_FLOWS` at once (``mail_setup_busy``), for :data:`FLOW_TTL_SECONDS`.
The address and the app password are held by a provisional record the registry
alone references; :class:`MailCredentials` is built only from the choice, and
every reference is dropped on finish, cancel and expiry (expired flows are reaped
on every call). :meth:`MailSetupFlows.finish` re-takes the lock, re-checks that the
flow has not expired and that no credentials were sealed meanwhile (a terminal
``mail setup`` wins: ``mail_already_configured``), makes the key fresh again (it
may have been deleted or replaced since) and seals.

Residual window: a ``mail forget`` in another process (the CLI) cannot reach this
process's pending flows. A flow started before such a forget can still be
finished, and seals, until its TTL ends; the Desktop page calls
:meth:`MailSetupFlows.cancel_all` itself when it removes the mailbox.

Nothing is written before the seal and a failed seal removes what it wrote, so a
refusal, a cancel or an expiry leaves no ``credentials.*`` file. Failures are
:class:`MailSetupError` codes (:data:`SETUP_ERROR_CODES`) with an optional
:data:`~.imap.IMAP_HINTS` member. Nothing here logs, and no ``repr`` shows an
address, a password, a host, a flow id or a folder name.
"""

from __future__ import annotations

import contextlib
import secrets as _secrets
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol

from .imap import IMAP_HINTS, IMAPS_PORT, ImapError, ImapStopped
from .imap import valid_host as _dns_name
from .imap_sync import FetchStop, fetch_lock
from .owner import own_address
from .secrets import ACCOUNT_RE, MailCredentials, MailSecretsError, own_address_list

if TYPE_CHECKING:
    from ._imap_codec import ListEntry
    from .imap import ImapSession

__all__ = [
    "FLOW_TTL_SECONDS",
    "GMAIL_HOST",
    "MAX_EXTRA_ADDRESSES",
    "MAX_PENDING_FLOWS",
    "SETUP_ERROR_CODES",
    "MailSetupError",
    "MailSetupFlow",
    "MailSetupFlows",
    "SetupFolder",
    "check_account",
    "check_address",
    "check_extra_addresses",
    "check_host",
    "check_password",
    "default_host",
    "display_name",
]

#: How long a flow waiting for the owner's folder choice is kept (as :class:`~...telegram.login_flow.LoginFlow`).
FLOW_TTL_SECONDS: Final = 600.0
#: Flows waiting for a choice (or being started) at once; one more is ``mail_setup_busy``.
MAX_PENDING_FLOWS: Final = 2
GMAIL_HOST: Final = "imap.gmail.com"
GMAIL_DOMAINS: Final = frozenset({"gmail.com", "googlemail.com"})
#: Google shows an app password as four groups of four letters; any other length is not one.
GMAIL_APP_PASSWORD_CHARS: Final = 16
MAX_PASSWORD_CHARS: Final = 256
MAX_EXTRA_ADDRESSES: Final = 20
MAX_DISPLAY_CHARS: Final = 200
DEFAULT_ACCOUNT: Final = "mail"
ALL_MAIL_FALLBACKS: Final = ("[Gmail]/All Mail", "[Google Mail]/All Mail")
#: The codes a :class:`MailSetupError` can carry.
SETUP_ERROR_CODES: Final = frozenset(
    {
        "invalid_address",
        "invalid_host",
        "invalid_account",
        "invalid_password",
        "too_many_addresses",
        "mail_already_configured",
        "mail_setup_flow_expired",
        "mail_setup_busy",
        "invalid_selection",
        "sync_in_progress",
        "store_path_unsafe",
        "tee_unavailable",
        "tee_auth_cancelled",
        "touch_id_policy_mismatch",
        "imap_unreachable",
        "imap_auth_failed",
        "imap_protocol",
        "imap_command_refused",
        "routing_unavailable",
        "egress_unsupported",
    }
)
_IMAP_CODES: Final = frozenset(
    {
        "imap_unreachable",
        "imap_auth_failed",
        "imap_protocol",
        "imap_command_refused",
        "routing_unavailable",
        "egress_unsupported",
    }
)
_SECRET_CODES: Final = frozenset(
    {"tee_unavailable", "tee_auth_cancelled", "store_path_unsafe", "touch_id_policy_mismatch"}
)
_LOCK_CODES: Final = frozenset({"sync_in_progress", "store_path_unsafe"})

SetupStep = Literal["folders", "done"]
#: What a ``folders`` step asks: which folder is All Mail (Gmail), or which is the sent folder (others).
SetupQuestion = Literal["all_mail", "sent"]
Connect = Callable[[str, int], "ImapSession"]
WriterLock = Callable[[Path], contextlib.AbstractContextManager[None]]


class MailSetupError(Exception):
    """A content-free setup refusal: a :data:`SETUP_ERROR_CODES` code and an optional IMAP hint."""

    def __init__(self, code: str, hint: str | None = None) -> None:
        if code not in SETUP_ERROR_CODES:
            raise ValueError("unknown mail setup code")
        super().__init__(code)
        self.code = code
        self.hint = hint if hint in IMAP_HINTS else None


class SetupSecretStore(Protocol):
    """What the flow needs of :class:`~.secrets.MailSecretStore`."""

    def residue(self) -> bool: ...

    def ensure_key(self, *, require_presence: bool = True, replace: bool = False) -> bool | None: ...

    def store(self, value: MailCredentials, *, require_presence: bool = True) -> None: ...

    def forget(self) -> bool: ...


@dataclass(frozen=True)
class SetupFolder:
    """A folder the owner may pick: ``name`` is its wire name (an opaque id), ``display`` is safe to show."""

    name: str
    display: str

    def __repr__(self) -> str:  # folder names can be personal: never in a traceback or a log line
        return "SetupFolder(<hidden>)"


@dataclass(eq=False)
class MailSetupFlow:
    """What a caller sees of a setup: never the address, the password or the host."""

    flow_id: str
    account: str
    presence: bool  # Touch ID on every unseal (False: an unattended key, for cron)
    gmail: bool
    step: SetupStep
    question: SetupQuestion | None  # set while ``step == "folders"``
    folders: tuple[SetupFolder, ...]  # the choices while ``step == "folders"``; empty once done
    roles: tuple[str, ...]  # the sealed mailbox roles once done
    created: float

    def __repr__(self) -> str:  # never the id, a folder name or anything the owner typed
        return (
            f"MailSetupFlow(step={self.step!r}, question={self.question!r}, gmail={self.gmail}, "
            f"account={self.account!r}, folders={len(self.folders)}, presence={self.presence})"
        )


@dataclass(frozen=True)
class _Request:
    """What the owner typed, validated (the address and the password: never printed)."""

    address: str
    host: str
    account: str
    own: tuple[str, ...]
    password: str
    presence: bool

    def __repr__(self) -> str:
        return f"_Request(account={self.account!r}, presence={self.presence})"


@dataclass(frozen=True)
class _Provisional:
    """The probe's result waiting for the owner's choice; :class:`MailCredentials` is built from the choice."""

    request: _Request
    inbox: str
    choices: frozenset[str]

    def __repr__(self) -> str:
        return f"_Provisional(choices={len(self.choices)})"


@dataclass(frozen=True)
class _Entry:
    flow: MailSetupFlow
    provisional: _Provisional

    def __repr__(self) -> str:
        return f"_Entry({self.flow!r})"


# --------------------------------------------------------------------------- #
# Validators (the CLI checks each answer with these as it is typed)
# --------------------------------------------------------------------------- #


def check_address(raw: object) -> str:
    """The owner's address, stripped and lowercased; ``invalid_address`` otherwise."""
    if not isinstance(raw, str):
        raise MailSetupError("invalid_address")
    try:
        return own_address(raw)
    except ValueError:
        raise MailSetupError("invalid_address") from None


def check_extra_addresses(items: object) -> list[str]:
    """Other own addresses (blank items dropped): at most :data:`MAX_EXTRA_ADDRESSES`, each valid."""
    if isinstance(items, str | bytes) or not isinstance(items, Sequence):
        raise MailSetupError("invalid_address")
    present = [item for item in items if not (isinstance(item, str) and not item.strip())]
    if len(present) > MAX_EXTRA_ADDRESSES:
        raise MailSetupError("too_many_addresses")
    return [check_address(item) for item in present]


def default_host(address: str) -> str | None:
    """``imap.gmail.com`` for a Gmail address; other providers have no default."""
    return GMAIL_HOST if address.rpartition("@")[2].lower() in GMAIL_DOMAINS else None


def check_host(raw: object) -> str:
    """A DNS host name, stripped and lowercased; ``invalid_host`` otherwise."""
    value = raw.strip().lower() if isinstance(raw, str) else ""
    if not _dns_name(value):
        raise MailSetupError("invalid_host")
    return value


def check_password(raw: object, host: str) -> str:
    """1 to 256 printable characters; on Gmail's host the whitespace Google shows is removed first."""
    if not isinstance(raw, str):
        raise MailSetupError("invalid_password")
    value = "".join(raw.split()) if host == GMAIL_HOST else raw
    if not value or len(value) > MAX_PASSWORD_CHARS or not value.isprintable():
        raise MailSetupError("invalid_password")
    return value


def check_account(raw: object) -> str:
    """The account label: one lowercase key component (``[a-z][a-z0-9_]{0,31}``)."""
    if not isinstance(raw, str) or not ACCOUNT_RE.fullmatch(raw):
        raise MailSetupError("invalid_account")
    return raw


def display_name(text: str) -> str:
    """A folder name safe for a terminal or a page: at most 200 characters, escaped unless printable."""
    text = text[:MAX_DISPLAY_CHARS]
    if text.isprintable():
        return text
    return text.encode("unicode_escape").decode("ascii")[:MAX_DISPLAY_CHARS]


def _validated(
    address: object,
    imap_host: object,
    account: object,
    extra_addresses: object,
    app_password: object,
    presence: object,
) -> _Request:
    owner = check_address(address)
    if imap_host is None or (isinstance(imap_host, str) and not imap_host.strip()):
        host = default_host(owner)
        if host is None:
            raise MailSetupError("invalid_host")
    else:
        host = check_host(imap_host)
    label = check_account(account)
    extra = check_extra_addresses(extra_addresses)
    password = check_password(app_password, host)
    if host == GMAIL_HOST and len(password) != GMAIL_APP_PASSWORD_CHARS:
        # Probably the account password: refused before it is sent anywhere.
        raise MailSetupError("imap_auth_failed", hint="gmail_app_password_length")
    # Anything but an explicit False keeps Touch ID: the safe reading of a malformed choice.
    return _Request(owner, host, label, own_address_list(owner, extra), password, presence is not False)


# --------------------------------------------------------------------------- #
# Mailboxes
# --------------------------------------------------------------------------- #


def _special(entries: Sequence[ListEntry], attribute: str) -> str | None:
    return next((entry.name for entry in entries if attribute in entry.attributes and entry.selectable), None)


def _all_mail(entries: Sequence[ListEntry]) -> str | None:
    names = {entry.name for entry in entries}
    return _special(entries, "\\all") or next((name for name in ALL_MAIL_FALLBACKS if name in names), None)


def _inbox(entries: Sequence[ListEntry]) -> str:
    return next((entry.name for entry in entries if entry.name.upper() == "INBOX"), "INBOX")


def _mailboxes(inbox: str, sent: str | None) -> dict[str, str]:
    mailboxes = {"inbox": inbox}
    if sent is not None and sent != inbox:
        mailboxes["sent"] = sent
    return mailboxes


def _credentials(request: _Request, mailboxes: Mapping[str, str], *, gmail: bool) -> MailCredentials:
    try:
        return MailCredentials(
            address=request.address,
            app_password=request.password,
            imap_host=request.host,
            imap_port=IMAPS_PORT,
            own_addresses=request.own,
            account=request.account,
            gmail=gmail,
            mailboxes=dict(mailboxes),
        )
    except MailSecretsError:
        raise MailSetupError("imap_protocol") from None  # a mailbox name the sealed payload would refuse


def _selected(entry: _Entry, selection: object) -> dict[str, str]:
    """The mailboxes for the owner's choice; a choice the flow never offered is ``invalid_selection``."""
    question, provisional = entry.flow.question, entry.provisional
    if selection is None and question == "sent":
        return {"inbox": provisional.inbox}  # no sent folder: own messages are recognised by address only
    if not isinstance(selection, str) or selection not in provisional.choices:
        raise MailSetupError("invalid_selection")
    return {"all": selection} if question == "all_mail" else _mailboxes(provisional.inbox, selection)


# --------------------------------------------------------------------------- #
# Failures and defaults
# --------------------------------------------------------------------------- #


def _imap_refusal(exc: ImapError) -> MailSetupError:
    """An IMAP failure as a setup code; the login hint passes through (a stopped probe is ``imap_unreachable``)."""
    if isinstance(exc, ImapStopped):
        return MailSetupError("imap_unreachable")
    return MailSetupError(exc.code if exc.code in _IMAP_CODES else "imap_protocol", hint=exc.hint)


def _secrets_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code in _SECRET_CODES:
        return code
    return "store_path_unsafe" if isinstance(exc, OSError) else "tee_unavailable"


def _default_connect(host: str, port: int) -> ImapSession:
    from . import imap

    return imap.connect(host, port)


def _default_home() -> Path:
    from ..._home import hermes_home

    return hermes_home()


# --------------------------------------------------------------------------- #
# The flows
# --------------------------------------------------------------------------- #


class MailSetupFlows:
    """The mail setups of this process: in memory only, at most :data:`MAX_PENDING_FLOWS`, each with a TTL."""

    def __init__(
        self,
        secret_store: SetupSecretStore,
        *,
        connect: Connect = _default_connect,
        lock: WriterLock = fetch_lock,
        home: Callable[[], Path] = _default_home,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._secret_store = secret_store
        self._connect = connect
        self._lock = lock
        self._home = home
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._starting = 0
        self._guard = threading.Lock()

    def __repr__(self) -> str:
        with self._guard:
            return f"MailSetupFlows(pending={len(self._entries)})"

    # -- steps ----------------------------------------------------------------------------------

    def start(
        self,
        *,
        address: str,
        imap_host: str | None = None,
        account: str = DEFAULT_ACCOUNT,
        extra_addresses: Sequence[str] = (),
        app_password: str,
        presence: bool = True,
    ) -> MailSetupFlow:
        """Validate; under the writer lock: admission, a fresh key, one read-only login, then a seal or a question."""
        self._reap()
        request = _validated(address, imap_host, account, extra_addresses, app_password, presence)
        with self._slot():
            with self._locked():
                self._refuse_if_configured()
                effective = self._fresh_key(request.presence)  # before the server is contacted
                gmail, entries = self._probe(request)
                flow, provisional, mailboxes = self._plan(request, gmail, entries)
                if mailboxes is not None:
                    creds = _credentials(request, mailboxes, gmail=gmail)
                    self._seal(creds, effective)
                    flow.roles = creds.roles
            if provisional is not None:
                with self._guard:
                    self._entries[flow.flow_id] = _Entry(flow, provisional)
        return flow

    def finish(self, flow_id: str, *, selection: str | None) -> MailSetupFlow:
        """Seal the owner's choice under the writer lock (``None``: no sent folder; never for All Mail)."""
        entry = self._entry(flow_id)
        creds = _credentials(entry.provisional.request, _selected(entry, selection), gmail=entry.flow.gmail)
        with self._locked():
            entry = self._entry(flow_id)  # still pending: not cancelled or expired while waiting for the lock
            if self._configured():
                self._drop(flow_id)
                raise MailSetupError("mail_already_configured")  # a setup elsewhere sealed first: it wins
            effective = self._fresh_key(entry.flow.presence)  # the key may have been deleted or replaced since
            self._seal(creds, effective)
        self._drop(flow_id)
        flow = entry.flow
        flow.step, flow.question, flow.folders, flow.roles = "done", None, (), creds.roles
        return flow

    def get(self, flow_id: str) -> MailSetupFlow:
        """A flow waiting for the owner's choice; ``mail_setup_flow_expired`` when there is none."""
        return self._entry(flow_id).flow

    def cancel(self, flow_id: str) -> None:
        """Forget a pending flow and the password it holds (an unknown id is fine)."""
        self._reap()
        self._drop(flow_id)

    def cancel_all(self) -> None:
        """Forget every pending flow (the mailbox was removed)."""
        with self._guard:
            self._entries.clear()

    # -- the server -----------------------------------------------------------------------------

    def _probe(self, request: _Request) -> tuple[bool, list[ListEntry]]:
        """One read-only session: ``LOGIN``, ``LIST``, ``LOGOUT``; the Gmail capability and the folders."""
        try:
            session = self._connect(request.host, IMAPS_PORT)
        except ImapError as exc:
            raise _imap_refusal(exc) from None
        try:
            session.login(request.address, request.password)
            return session.gmail, session.list_mailboxes()
        except ImapError as exc:
            raise _imap_refusal(exc) from None
        finally:
            session.logout()

    def _plan(
        self, request: _Request, gmail: bool, entries: Sequence[ListEntry]
    ) -> tuple[MailSetupFlow, _Provisional | None, dict[str, str] | None]:
        """The flow, and either the provisional record of a question or the mailboxes to seal now."""
        folders = tuple(SetupFolder(entry.name, display_name(entry.display)) for entry in entries if entry.selectable)
        inbox = _inbox(entries)
        if gmail:
            chosen = _all_mail(entries)
            if chosen is not None:
                return self._flow(request, gmail=True), None, {"all": chosen}
            if not folders:
                raise MailSetupError("imap_protocol")
            return self._question(request, "all_mail", folders, inbox, gmail=True)
        sent = _special(entries, "\\sent")
        if sent is None and folders:
            return self._question(request, "sent", folders, inbox, gmail=False)
        return self._flow(request, gmail=False), None, _mailboxes(inbox, sent)

    def _question(
        self, request: _Request, question: SetupQuestion, folders: tuple[SetupFolder, ...], inbox: str, *, gmail: bool
    ) -> tuple[MailSetupFlow, _Provisional, None]:
        flow = self._flow(request, gmail=gmail, step="folders", question=question, folders=folders)
        return flow, _Provisional(request, inbox, frozenset(folder.name for folder in folders)), None

    def _flow(
        self,
        request: _Request,
        *,
        gmail: bool,
        step: SetupStep = "done",
        question: SetupQuestion | None = None,
        folders: tuple[SetupFolder, ...] = (),
    ) -> MailSetupFlow:
        return MailSetupFlow(
            flow_id=_secrets.token_urlsafe(16),
            account=request.account,
            presence=request.presence,
            gmail=gmail,
            step=step,
            question=question,
            folders=folders,
            roles=(),
            created=self._clock(),
        )

    # -- the secret store -----------------------------------------------------------------------

    def _configured(self) -> bool:
        try:
            return bool(self._secret_store.residue())
        except (MailSecretsError, OSError):
            raise MailSetupError("store_path_unsafe") from None

    def _refuse_if_configured(self) -> None:
        if self._configured():
            raise MailSetupError("mail_already_configured")

    def _fresh_key(self, presence: bool) -> bool:
        """A new Enclave key with the requested policy (no credentials are sealed: the old key guards nothing)."""
        try:
            effective = self._secret_store.ensure_key(require_presence=presence, replace=True)
        except (MailSecretsError, OSError) as exc:
            raise MailSetupError(_secrets_code(exc)) from None
        return presence if effective is None else bool(effective)

    def _seal(self, creds: MailCredentials, presence: bool) -> None:
        """Seal under the lock; a failure removes whatever it wrote (nothing was there before it)."""
        try:
            self._secret_store.store(creds, require_presence=presence)
        except BaseException as exc:
            with contextlib.suppress(Exception):
                if self._secret_store.residue():
                    self._secret_store.forget()
            if isinstance(exc, MailSecretsError | OSError):
                raise MailSetupError(_secrets_code(exc)) from None
            raise

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            with self._lock(self._home()):
                yield
        except FetchStop as stop:
            raise MailSetupError(stop.code if stop.code in _LOCK_CODES else "store_path_unsafe") from None

    # -- the registry ---------------------------------------------------------------------------

    @contextlib.contextmanager
    def _slot(self) -> Iterator[None]:
        """One of the :data:`MAX_PENDING_FLOWS` places while a start runs (refused before the server)."""
        with self._guard:
            if len(self._entries) + self._starting >= MAX_PENDING_FLOWS:
                raise MailSetupError("mail_setup_busy")
            self._starting += 1
        try:
            yield
        finally:
            with self._guard:
                self._starting -= 1

    def _entry(self, flow_id: object) -> _Entry:
        self._reap()
        with self._guard:
            entry = self._entries.get(flow_id) if isinstance(flow_id, str) else None
        if entry is None:
            raise MailSetupError("mail_setup_flow_expired")
        return entry

    def _drop(self, flow_id: object) -> None:
        if isinstance(flow_id, str):
            with self._guard:
                self._entries.pop(flow_id, None)

    def _reap(self) -> None:
        now = self._clock()
        with self._guard:
            for flow_id in [key for key, entry in self._entries.items() if now - entry.flow.created > FLOW_TTL_SECONDS]:
                del self._entries[flow_id]
