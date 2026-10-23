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
2. the setup generation (:func:`~.secrets.setup_generation`) is noted, and the
   Enclave key is made fresh with the requested Touch ID policy BEFORE the server
   is contacted: with no credentials sealed, a key left by a failed setup protects
   nothing and is replaced (``touch_id_policy_mismatch`` when it cannot be
   deleted); the flow keeps the EFFECTIVE policy :meth:`~.secrets.MailSecretStore.ensure_key`
   returned;
3. one read-only login (``LOGIN``, ``LIST``, ``LOGOUT``) and the mailboxes:

   - Gmail (``X-GM-EXT-1``): All Mail (its ``\\All`` special use, else its usual
     name), sealed at once (``step == "done"``); when neither identifies it, the
     owner is asked which folder it is (``step == "folders"``,
     ``question == "all_mail"``), as ``mail setup`` always did;
   - another server with a ``\\Sent`` special-use folder: ``INBOX`` and that
     folder, sealed at once;
   - another server without one: ``question == "sent"`` (choosing none is fine).

A setup holds a slot of this process from the moment ``start`` reserves it (before
the probe), one at a time (a second ``start`` is ``mail_setup_busy``; ``cancel``
frees it); a flow waiting for the owner's choice keeps it for
:data:`FLOW_TTL_SECONDS`. ``cancel``/``cancel_all`` reach a setup that is still
probing or sealing: it ends with ``mail_setup_cancelled`` and seals nothing. The
address and the app password are held by a provisional record the registry alone
references; :class:`MailCredentials` is
built only from the choice, and every reference is dropped on finish, cancel and
expiry. Expired flows are reaped on every call and by :meth:`MailSetupFlows.reap`
(the Desktop backend calls it periodically, and :meth:`~MailSetupFlows.cancel_all`
on shutdown). :meth:`MailSetupFlows.finish` re-takes the lock and re-checks, in
order: the flow has not expired; no credentials were sealed meanwhile (a terminal
``mail setup`` wins: ``mail_already_configured``); the setup generation is the one
``start`` noted (a ``mail forget`` or a setup in any process rewrote it:
``mail_setup_stale``); the key still has the policy ``start`` recorded
(``ensure_key`` again, recreating a deleted key with that policy;
``touch_id_policy_mismatch`` otherwise). Every seal rewrites the generation, so a
flow of another process that waited across it goes stale too.

Nothing is written before the seal and a failed seal removes what it wrote, so a
refusal, a cancel or an expiry leaves no ``credentials.*`` file; :meth:`MailSetupFlows.seal_stage`
tells a caller interrupted mid-way whether anything was stored. Failures are
:class:`MailSetupError` codes (:data:`SETUP_ERROR_CODES`) with an optional
:data:`~.imap.IMAP_HINTS` member, raised with no cause, context or inner
traceback (:func:`~.imap.sever_chain`), so no server text rides along. Nothing here logs, and no ``repr`` shows an
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
from typing import TYPE_CHECKING, Final, Literal, NoReturn, Protocol

from .imap import IMAP_HINTS, IMAPS_PORT, ImapError, ImapStopped, sever_chain
from .imap import valid_host as _dns_name
from .imap_sync import FetchStop, fetch_lock
from .owner import own_address
from .secrets import (
    ACCOUNT_RE,
    MailCredentials,
    MailSecretsError,
    new_setup_generation,
    own_address_list,
    setup_generation,
)

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
MAX_PENDING_FLOWS: Final = 1
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
        "mail_setup_stale",
        "mail_setup_cancelled",
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
#: How far a seal got: nothing stored, credentials stored, or a failed seal whose files could not be removed.
SealStage = Literal["pre_seal", "sealed", "cleanup_failed"]
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
    generation: str  # the setup generation ``start`` saw
    policy: bool  # the key's effective Touch ID policy at ``start``

    def __repr__(self) -> str:
        return f"_Provisional(choices={len(self.choices)})"


@dataclass(frozen=True)
class _Entry:
    flow: MailSetupFlow
    provisional: _Provisional

    def __repr__(self) -> str:
        return f"_Entry({self.flow!r})"


@dataclass(eq=False)
class _Slot:
    """One setup of this process, from the reservation in ``start`` to its finish, cancel or expiry."""

    flow_id: str
    cancelled: bool = False
    entry: _Entry | None = None  # set while the flow waits for the owner's choice

    def end(self) -> None:
        """No longer this process's business: a running setup stops, the password is dropped."""
        self.cancelled = True
        self.entry = None

    def __repr__(self) -> str:
        return f"_Slot(pending={self.entry is not None}, cancelled={self.cancelled})"


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
    """The mail setups of this process: in memory only, at most :data:`MAX_PENDING_FLOWS`, each with a TTL.

    Every setup holds a slot from the moment ``start`` reserves it (before the
    probe) until it is finished, cancelled or expired, so :meth:`cancel_all`
    reaches a setup that is still probing. A slot's ``cancelled`` flag is checked
    under the registry mutex right before the setup becomes pending and while it
    seals (the seal itself runs under that mutex, so a ``cancel`` either stops it
    or returns after it): a cancelled setup ends with ``mail_setup_cancelled``
    and seals nothing. Every :class:`MailSetupError` leaving ``start`` and
    ``finish`` is :func:`~.imap.sever_chain`-ed.
    """

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
        self._slots: dict[str, _Slot] = {}
        self._guard = threading.Lock()
        self._stage = threading.local()

    def __repr__(self) -> str:
        with self._guard:
            return f"MailSetupFlows(pending={sum(slot.entry is not None for slot in self._slots.values())})"

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
        failure: MailSetupError
        try:
            return self._start(_validated(address, imap_host, account, extra_addresses, app_password, presence))
        except MailSetupError as exc:
            failure = exc
        raise sever_chain(failure)

    def finish(self, flow_id: str, *, selection: str | None) -> MailSetupFlow:
        """Seal the owner's choice under the writer lock (``None``: no sent folder; never for All Mail)."""
        failure: MailSetupError
        try:
            return self._finish(flow_id, selection)
        except MailSetupError as exc:
            failure = exc
        raise sever_chain(failure)

    def get(self, flow_id: str) -> MailSetupFlow:
        """A flow waiting for the owner's choice; ``mail_setup_flow_expired`` when there is none."""
        entry = self._pending(flow_id).entry
        assert entry is not None  # _pending returns pending slots only
        return entry.flow

    def cancel(self, flow_id: str) -> None:
        """Forget a setup and the password it holds; a setup still running ends ``mail_setup_cancelled``."""
        self.reap()
        if isinstance(flow_id, str):
            with self._guard:
                slot = self._slots.pop(flow_id, None)
                if slot is not None:
                    slot.end()

    def cancel_all(self) -> None:
        """Forget every setup, pending or still probing (the mailbox was removed, or the backend stops)."""
        with self._guard:
            for slot in self._slots.values():
                slot.end()
            self._slots.clear()

    def reap(self) -> None:
        """Drop every flow past its TTL (each call does this; the Desktop backend also calls it periodically)."""
        now = self._clock()
        with self._guard:
            for flow_id, slot in list(self._slots.items()):
                if slot.entry is not None and now - slot.entry.flow.created > FLOW_TTL_SECONDS:
                    del self._slots[flow_id]
                    slot.end()

    def seal_stage(self) -> SealStage:
        """How far the calling thread's last ``start`` or ``finish`` got with sealing (for its message).

        ``pre_seal``: nothing is stored; ``sealed``: the credentials are stored;
        ``cleanup_failed``: a seal failed and what it wrote could not be removed.
        """
        stage: SealStage = getattr(self._stage, "value", "pre_seal")
        return stage

    # -- the two halves -------------------------------------------------------------------------

    def _start(self, request: _Request) -> MailSetupFlow:
        self._stage.value = "pre_seal"
        self.reap()
        slot = self._reserve()
        pending = False
        try:
            with self._locked():
                self._refuse_if_configured()
                generation = self._generation()
                policy = self._fresh_key(request.presence)  # before the server is contacted
                gmail, entries = self._probe(request)
                flow, question, mailboxes = self._plan(slot.flow_id, request, gmail, entries, policy)
                if mailboxes is not None:
                    creds = _credentials(request, mailboxes, gmail=gmail)
                    self._seal_unless_cancelled(slot, creds, policy)
                    flow.roles = creds.roles
            if question is not None:
                inbox, choices = question
                with self._guard:
                    if slot.cancelled:
                        raise MailSetupError("mail_setup_cancelled")
                    slot.entry = _Entry(flow, _Provisional(request, inbox, choices, generation, policy))
                    pending = True
            return flow
        finally:
            if not pending:
                self._release(slot)

    def _finish(self, flow_id: str, selection: object) -> MailSetupFlow:
        self._stage.value = "pre_seal"
        entry = self._pending_entry(flow_id)
        creds = _credentials(entry.provisional.request, _selected(entry, selection), gmail=entry.flow.gmail)
        with self._locked():
            slot = self._pending(flow_id)  # still pending: not cancelled or expired while waiting for the lock
            provisional = entry.provisional
            if self._configured():
                self._refuse(flow_id, "mail_already_configured")  # a setup elsewhere sealed first: it wins
            if self._generation() != provisional.generation:
                self._refuse(flow_id, "mail_setup_stale")  # set up or forgotten since this flow started
            if self._key_policy(provisional.policy) != provisional.policy:
                self._refuse(flow_id, "touch_id_policy_mismatch")  # another setup replaced the key meanwhile
            self._seal_unless_cancelled(slot, creds, provisional.policy)
        self._release(slot)
        flow = entry.flow
        flow.step, flow.question, flow.folders, flow.roles = "done", None, (), creds.roles
        return flow

    # -- the server -----------------------------------------------------------------------------

    def _probe(self, request: _Request) -> tuple[bool, list[ListEntry]]:
        """One read-only session: ``LOGIN``, ``LIST``, ``LOGOUT``; the Gmail capability and the folders."""
        failure: MailSetupError
        try:
            session = self._connect(request.host, IMAPS_PORT)
        except ImapError as exc:
            failure = _imap_refusal(exc)
        else:
            try:
                session.login(request.address, request.password)
                return session.gmail, session.list_mailboxes()
            except ImapError as exc:
                failure = _imap_refusal(exc)
            finally:
                session.logout()
        raise sever_chain(failure)

    def _plan(
        self, flow_id: str, request: _Request, gmail: bool, entries: Sequence[ListEntry], policy: bool
    ) -> tuple[MailSetupFlow, tuple[str, frozenset[str]] | None, dict[str, str] | None]:
        """The flow, and either the question's (inbox, choices) or the mailboxes to seal now."""
        folders = tuple(SetupFolder(entry.name, display_name(entry.display)) for entry in entries if entry.selectable)
        choices = (_inbox(entries), frozenset(folder.name for folder in folders))
        if gmail:
            chosen = _all_mail(entries)
            if chosen is not None:
                return self._flow(flow_id, request, policy, gmail=True), None, {"all": chosen}
            if not folders:
                raise MailSetupError("imap_protocol")
            flow = self._flow(flow_id, request, policy, gmail=True, question="all_mail", folders=folders)
            return flow, choices, None
        sent = _special(entries, "\\sent")
        if sent is None and folders:
            return self._flow(flow_id, request, policy, gmail=False, question="sent", folders=folders), choices, None
        return self._flow(flow_id, request, policy, gmail=False), None, _mailboxes(choices[0], sent)

    def _flow(
        self,
        flow_id: str,
        request: _Request,
        policy: bool,
        *,
        gmail: bool,
        question: SetupQuestion | None = None,
        folders: tuple[SetupFolder, ...] = (),
    ) -> MailSetupFlow:
        return MailSetupFlow(
            flow_id=flow_id,
            account=request.account,
            presence=policy,
            gmail=gmail,
            step="done" if question is None else "folders",
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

    def _key_policy(self, presence: bool) -> bool | None:
        """The key's effective policy now (a deleted key is recreated with ``presence``); ``None``: unknown."""
        try:
            return self._secret_store.ensure_key(require_presence=presence)
        except (MailSecretsError, OSError) as exc:
            raise MailSetupError(_secrets_code(exc)) from None

    def _generation(self) -> str:
        try:
            return setup_generation(self._home())
        except (MailSecretsError, OSError):
            raise MailSetupError("store_path_unsafe") from None

    def _refuse(self, flow_id: str, code: str) -> NoReturn:
        self.cancel(flow_id)
        raise MailSetupError(code)

    def _seal_unless_cancelled(self, slot: _Slot, creds: MailCredentials, presence: bool) -> None:
        """Seal while holding the registry mutex: a cancel either stops the seal or returns after it."""
        with self._guard:
            if slot.cancelled:
                raise MailSetupError("mail_setup_cancelled")
            self._seal(creds, presence)

    def _seal(self, creds: MailCredentials, presence: bool) -> None:
        """Seal under the lock, then rewrite the setup generation; a failure removes what it wrote.

        The generation changes only with a seal that succeeded, so a ``finish``
        whose seal failed can be retried; flows that waited across a successful
        seal, in any process, go stale. The calling thread's :meth:`seal_stage`
        follows each step.
        """
        stage = self._stage
        try:
            self._secret_store.store(creds, require_presence=presence)
            stage.value = "sealed"
            new_setup_generation(self._home())
        except BaseException as exc:
            stage.value = "cleanup_failed"
            with contextlib.suppress(Exception):
                if self._secret_store.residue():
                    self._secret_store.forget()
                if not self._secret_store.residue():
                    stage.value = "pre_seal"
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

    def _reserve(self) -> _Slot:
        """A slot for a starting setup, registered before the probe (refused before the server when full)."""
        with self._guard:
            if len(self._slots) >= MAX_PENDING_FLOWS:
                raise MailSetupError("mail_setup_busy")
            slot = _Slot(_secrets.token_urlsafe(16))
            self._slots[slot.flow_id] = slot
        return slot

    def _release(self, slot: _Slot) -> None:
        with self._guard:
            if self._slots.get(slot.flow_id) is slot:
                del self._slots[slot.flow_id]
            slot.end()

    def _pending(self, flow_id: object) -> _Slot:
        self.reap()
        with self._guard:
            slot = self._slots.get(flow_id) if isinstance(flow_id, str) else None
            if slot is None or slot.entry is None:
                raise MailSetupError("mail_setup_flow_expired")
        return slot

    def _pending_entry(self, flow_id: object) -> _Entry:
        entry = self._pending(flow_id).entry
        if entry is None:  # cancelled between the two reads
            raise MailSetupError("mail_setup_flow_expired")
        return entry
