"""Read-only IMAP client for the mail collector: route, TLS, command allowlist, bounded session.

Transport (SPEC "IMAP sync (2026-10-22)"):

- The route comes from :func:`mordred_hermes.extension.egress.resolve_route` for
  the sealed host, the same resolver Mordred's Telegram and Venice clients use
  (Tor needs a loopback SOCKS proxy, a VPN needs the live network runtime, no
  proxy environment variable is read here). That module returns a route, not a
  socket, so the socket is built here: a direct TCP connection, or SOCKS5 with
  remote DNS (the hostname is sent to the proxy, never resolved locally). When
  the route carries proxy credentials (the Tor stream-isolation token) only
  username/password authentication is offered, and a proxy that answers "no
  authentication" is refused (``egress_unsupported``): the isolation token is
  never silently dropped. Any other proxy kind refuses with ``egress_unsupported``.
- TLS is implicit on port 993 only (:data:`IMAPS_PORT`; any other port is
  refused) with :func:`ssl.create_default_context`: certificate and hostname
  verification on, TLS 1.2 or newer, SNI set to the sealed host. ``STARTTLS``
  and referrals are never used.
- Authentication is ``LOGIN`` inside that TLS connection and nothing else:
  ``AUTHENTICATE`` is not on the allowlist, so there is no mechanism
  negotiation that could fall back to something weaker, and a server that
  advertises ``LOGINDISABLED`` is ``imap_auth_failed``.

Protocol: :class:`_CommandGuard` refuses, before anything is sent, every command
outside ``CAPABILITY``, ``LOGIN``, ``LIST`` (``"" "*"`` only), ``EXAMINE`` (one
quoted name), ``UID SEARCH``, ``UID FETCH`` (``BODY.PEEK[]`` and metadata items
only), ``NOOP`` and ``LOGOUT`` (no arguments), and every argument that contains
CR, LF or NUL (no second command can be framed into an argument) — so no
``SELECT``, ``STORE``, ``COPY``, ``EXPUNGE`` or ``APPEND`` and no ``BODY[]``
(which would set ``\\Seen``) can ever leave the process. imaplib's debug output
and command log are disabled.

Bounds (:class:`IoLimits`, enforced inside imaplib's own ``read``/``readline``):

- a soft deadline checked before every command (``ImapStopped("time_budget")``;
  nothing was sent, so the connection stays clean for a polite ``LOGOUT``), a
  hard deadline (soft plus at most :data:`HARD_GRACE_S`) enforced by a watchdog
  thread that shuts the socket down, so a server trickling bytes cannot keep a
  read alive, and a socket timeout per operation that never reaches past it;
- a :class:`CancelToken` that shuts the socket down at once (``"cancelled"``);
- a literal's announced size is checked BEFORE anything is read: a literal over
  the room left in the command's literal budget (:data:`MAX_BATCH_LITERAL_BYTES`
  for a body fetch) or in the session's byte budget aborts the connection
  (``imap_protocol``) without reading it; one over :data:`MAX_LITERAL_BYTES`
  that fits is read in 64 KiB chunks and discarded
  (:class:`._imap_codec.DrainedLiteral`); response lines count against a
  per-command budget too.

Errors are :class:`ImapError` codes: ``imap_unreachable``, ``imap_auth_failed``,
``imap_protocol``, ``imap_command_refused``, ``egress_unsupported``,
``routing_unavailable``; :class:`ImapStopped` (a deadline or a cancellation,
``reason``) is not a server failure.
"""

from __future__ import annotations

import contextlib
import imaplib
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final

from ._imap_codec import (
    DrainedLiteral,
    ImapProtocolError,
    ListEntry,
    Value,
    body_bytes,
    fetch_records,
    gmail_labels,
    is_drained,
    list_entries,
    number,
    quote_mailbox,
    search_uids,
)

__all__ = [
    "DEFAULT_PORT",
    "GMAIL_CAPABILITY",
    "IMAPS_PORT",
    "MAX_BATCH_LITERAL_BYTES",
    "MAX_LITERAL_BYTES",
    "MAX_RUN_BYTES",
    "CancelToken",
    "Fetched",
    "ImapError",
    "ImapSession",
    "ImapStopped",
    "IoLimits",
    "MailboxStatus",
    "connect",
    "open_route_socket",
    "socks5_connect",
    "tls_context",
]

IMAPS_PORT: Final = 993
DEFAULT_PORT: Final = IMAPS_PORT
GMAIL_CAPABILITY: Final = "X-GM-EXT-1"
SOCKET_TIMEOUT_S: Final = 30.0
#: Budget of a session opened without explicit limits (``mail setup``'s probe).
SESSION_BUDGET_S: Final = 120.0
#: Grace after the soft deadline before the watchdog cuts an in-flight command.
HARD_GRACE_S: Final = 30.0
LOGOUT_GRACE_S: Final = 5.0
_WATCHDOG_SLACK_S: Final = 0.25
_MIB: Final = 1024 * 1024
#: The largest literal kept (a message over it is skipped; equals ``source.MAX_MESSAGE_BYTES``).
MAX_LITERAL_BYTES: Final = 25 * _MIB
#: Literal bytes (kept and drained) one body ``UID FETCH`` may deliver.
MAX_BATCH_LITERAL_BYTES: Final = 64 * _MIB
#: Literal bytes any other command may deliver.
MAX_COMMAND_LITERAL_BYTES: Final = 16 * _MIB
#: Response-line bytes one command may deliver (imaplib bounds each line to 1 MB).
MAX_COMMAND_LINE_BYTES: Final = 16 * _MIB
#: Every byte one session may read (the fetch plans batches well below it).
MAX_RUN_BYTES: Final = 2048 * _MIB
_DRAIN_CHUNK: Final = 64 * 1024
_ALLOWED_COMMANDS: Final = frozenset({"CAPABILITY", "LOGIN", "LIST", "EXAMINE", "UID", "NOOP", "LOGOUT"})
_NO_ARGUMENTS: Final = frozenset({"CAPABILITY", "NOOP", "LOGOUT"})
_LIST_ARGUMENTS: Final = ('""', '"*"')
_FRAMING_CHARS: Final = frozenset("\r\n\0")
_QUOTED_RE: Final = re.compile(r'"(?:[^"\\\x00-\x1f\x7f]|\\["\\])*"')
_FETCH_ITEMS: Final = frozenset({"UID", "RFC822.SIZE", "BODY.PEEK[]", "X-GM-LABELS", "X-GM-THRID", "X-GM-MSGID"})
_UID_SET_RE: Final = re.compile(r"(?:\d{1,10}|\*)(?::(?:\d{1,10}|\*))?(?:,(?:\d{1,10}|\*)(?::(?:\d{1,10}|\*))?)*")
_SEARCH_ARG_RE: Final = re.compile(r"UID|SINCE|BEFORE|ALL|\d{1,2}-[A-Z][a-z]{2}-\d{4}")
_HOST_LABEL: Final = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE: Final = re.compile(rf"(?=.{{1,253}}\Z){_HOST_LABEL}(?:\.{_HOST_LABEL})+")
_IMAP_COMMAND: Final[Any] = getattr(imaplib.IMAP4, "_command")  # noqa: B009 - private, absent from typeshed


class ImapError(Exception):
    """A content-free IMAP failure code (never server text)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ImapStopped(ImapError):
    """The session stopped for its deadline (``time_budget``) or a cancellation (``cancelled``)."""

    def __init__(self, reason: str) -> None:
        super().__init__("imap_stopped")
        self.reason = reason


def valid_host(host: str) -> bool:
    """A DNS hostname (letters, digits, hyphens; at least two labels)."""
    return isinstance(host, str) and _HOST_RE.fullmatch(host) is not None


# --- bounds ---------------------------------------------------------------------------------------


class CancelToken:
    """Set from any thread to stop a fetch; registered hooks (the live socket's shutdown) run at once."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._hooks: list[Callable[[], None]] = []

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        with self._lock:
            self._event.set()
            hooks = list(self._hooks)
        for hook in hooks:
            with contextlib.suppress(Exception):
                hook()

    def add_hook(self, hook: Callable[[], None]) -> None:
        with self._lock:
            if not self._event.is_set():
                self._hooks.append(hook)
                return
        with contextlib.suppress(Exception):
            hook()  # already cancelled: run it now

    def remove_hook(self, hook: Callable[[], None]) -> None:
        with self._lock, contextlib.suppress(ValueError):
            self._hooks.remove(hook)


@dataclass
class IoLimits:
    """The bounds of one session: deadlines on ``clock``, cancellation, timeouts and the byte budget."""

    deadline: float
    hard_deadline: float
    clock: Callable[[], float] = time.monotonic
    cancel: CancelToken | None = None
    op_timeout: float = SOCKET_TIMEOUT_S
    max_literal: int = MAX_LITERAL_BYTES
    max_run: int = MAX_RUN_BYTES
    run_bytes: int = 0

    @classmethod
    def for_budget(
        cls, budget_s: float, *, clock: Callable[[], float] = time.monotonic, cancel: CancelToken | None = None
    ) -> IoLimits:
        """Soft deadline ``budget_s`` from now; the hard one adds at most :data:`HARD_GRACE_S`."""
        start = clock()
        grace = min(HARD_GRACE_S, max(budget_s, 0.0))
        return cls(deadline=start + budget_s, hard_deadline=start + budget_s + grace, clock=clock, cancel=cancel)

    def stop_reason(self, *, hard: bool) -> str | None:
        """``cancelled``, ``time_budget`` (the soft, or with ``hard`` the hard, deadline passed) or ``None``."""
        if self.cancel is not None and self.cancel.cancelled:
            return "cancelled"
        if self.clock() >= (self.hard_deadline if hard else self.deadline):
            return "time_budget"
        return None

    def io_timeout(self) -> float:
        """The socket timeout for the next blocking operation: never past the hard deadline."""
        return max(min(self.op_timeout, self.hard_deadline - self.clock()), 0.01)

    def remaining(self) -> float:
        """Seconds until the hard deadline."""
        return self.hard_deadline - self.clock()

    def extend(self, seconds: float) -> None:
        """A short new window (``LOGOUT`` after a stop): both deadlines move to ``seconds`` from now."""
        self.deadline = self.hard_deadline = self.clock() + seconds


# --- transport ------------------------------------------------------------------------------------


def tls_context() -> ssl.SSLContext:
    """Certificate and hostname verification on, TLS 1.2 or newer."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


Remaining = Callable[[], float]


def _no_deadline() -> float:
    return SOCKET_TIMEOUT_S


def _recv_exact(sock: socket.socket, size: int, remaining: Remaining = _no_deadline) -> bytes:
    """``size`` bytes; no ``recv`` waits past the deadline (``remaining()`` seconds away)."""
    data = bytearray()
    while len(data) < size:
        left = remaining()
        if left <= 0:
            raise ImapError("imap_unreachable")
        sock.settimeout(min(left, SOCKET_TIMEOUT_S))
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ImapError("imap_unreachable")
        data.extend(chunk)
    return bytes(data)


def _socks_auth(sock: socket.socket, username: str, password: str, remaining: Remaining) -> None:
    user, secret = username.encode("utf-8"), password.encode("utf-8")
    if not 0 < len(user) < 256 or len(secret) > 255:
        raise ImapError("egress_unsupported")
    sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    if _recv_exact(sock, 2, remaining)[1] != 0:
        raise ImapError("imap_unreachable")


def _socks_bound_address(sock: socket.socket, atyp: int, remaining: Remaining) -> None:
    if atyp == 1:
        _recv_exact(sock, 4 + 2, remaining)
    elif atyp == 4:
        _recv_exact(sock, 16 + 2, remaining)
    elif atyp == 3:
        _recv_exact(sock, _recv_exact(sock, 1, remaining)[0] + 2, remaining)
    else:
        raise ImapError("imap_unreachable")


def socks5_handshake(
    sock: socket.socket,
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    remaining: Remaining = _no_deadline,
) -> None:
    """RFC 1928 ``CONNECT`` by hostname (remote DNS); RFC 1929 username/password, required when configured."""
    name = host.encode("ascii")
    authenticated = username is not None or password is not None
    methods = b"\x02" if authenticated else b"\x00"  # never offer "no authentication" with credentials
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _recv_exact(sock, 2, remaining)
    if version != 5:
        raise ImapError("imap_unreachable")
    if method not in methods:
        # Credentials are configured but the proxy picked another method: the isolation token would be lost.
        raise ImapError("egress_unsupported" if authenticated else "imap_unreachable")
    if method == 2:
        _socks_auth(sock, username or "", password or "", remaining)
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    version, reply, _reserved, atyp = _recv_exact(sock, 4, remaining)
    if version != 5 or reply != 0:
        raise ImapError("imap_unreachable")
    _socks_bound_address(sock, atyp, remaining)


def socks5_connect(
    proxy: Any, host: str, port: int, timeout: float, remaining: Remaining = _no_deadline
) -> socket.socket:
    """A TCP connection to ``host:port`` through the SOCKS5 ``proxy`` (an :class:`~...extension.egress.SocksProxy`)."""
    sock = socket.create_connection((proxy.host, proxy.port), timeout)
    try:
        socks5_handshake(sock, host, port, proxy.username, proxy.password, remaining)
        sock.settimeout(timeout)
    except BaseException:
        sock.close()
        raise
    return sock


def _default_route(host: str) -> Any:
    from ...extension.egress import resolve_route

    return resolve_route(host)


def open_route_socket(
    host: str,
    port: int,
    timeout: float,
    *,
    route_resolver: Callable[[str], Any] = _default_route,
    remaining: Remaining = _no_deadline,
) -> socket.socket:
    """A connected TCP socket to ``host:port`` over the route the network policy selects."""
    from ...extension.egress import EgressError, socks_proxy

    try:
        route = route_resolver(host)
    except EgressError:
        raise ImapError("routing_unavailable") from None
    if route.http_proxy_url is not None:
        raise ImapError("egress_unsupported")
    try:
        if route.socks_proxy_url is not None:
            url = str(route.socks_proxy_url)
            if url.startswith("socks5h://"):  # resolve_route already normalizes; remote DNS is always used here
                url = "socks5://" + url[len("socks5h://") :]
            try:
                proxy = socks_proxy(url)
            except EgressError:
                raise ImapError("egress_unsupported") from None
            return socks5_connect(proxy, host, port, timeout, remaining)
        return socket.create_connection((host, port), timeout)
    except OSError:
        raise ImapError("imap_unreachable") from None


# --- guarded imaplib ------------------------------------------------------------------------------


def _text(arg: object) -> str:
    return arg.decode("ascii", "replace") if isinstance(arg, bytes) else str(arg)


def _check_uid_command(args: Sequence[object]) -> None:
    if len(args) < 2:
        raise ImapError("imap_command_refused")
    sub = _text(args[0]).upper()
    if sub == "SEARCH":
        if not all(_SEARCH_ARG_RE.fullmatch(_text(arg)) or _UID_SET_RE.fullmatch(_text(arg)) for arg in args[1:]):
            raise ImapError("imap_command_refused")
        return
    if sub != "FETCH" or len(args) != 3 or not _UID_SET_RE.fullmatch(_text(args[1])):
        raise ImapError("imap_command_refused")
    items = _text(args[2]).strip()
    if not (items.startswith("(") and items.endswith(")")):
        raise ImapError("imap_command_refused")
    if not set(items[1:-1].upper().split()) <= _FETCH_ITEMS:
        raise ImapError("imap_command_refused")


def _framed(arg: object) -> bool:
    """True when ``arg`` could end the command line early (CR, LF or NUL) or is not text at all."""
    if isinstance(arg, bytes):
        return bool(_FRAMING_CHARS & set(arg.decode("latin-1")))
    if isinstance(arg, str):
        return bool(_FRAMING_CHARS & set(arg))
    return True


def _check_command(verb: str, args: Sequence[object]) -> None:
    """Raise ``imap_command_refused`` for anything outside the read-only allowlist (see the module docstring)."""
    present = [arg for arg in args if arg is not None]  # imaplib skips None arguments
    if verb not in _ALLOWED_COMMANDS or any(_framed(arg) for arg in present):
        raise ImapError("imap_command_refused")
    if verb in _NO_ARGUMENTS and present:
        raise ImapError("imap_command_refused")
    if verb == "LIST" and tuple(_text(arg) for arg in present) != _LIST_ARGUMENTS:
        raise ImapError("imap_command_refused")
    if verb == "EXAMINE" and (len(present) != 1 or not _QUOTED_RE.fullmatch(_text(present[0]))):
        raise ImapError("imap_command_refused")
    if verb == "LOGIN" and len(present) != 2:
        raise ImapError("imap_command_refused")
    if verb == "UID":
        _check_uid_command(present)


class _CommandGuard:
    """The allowlist, the framing check and the byte and time bounds inside imaplib's own I/O."""

    literal: str | None  # imaplib's pending literal (set by ``append``)
    sock: socket.socket
    file: Any
    _limits: IoLimits
    _literal_cap: int
    _literal_used: int
    _line_used: int
    _next_literal_cap: int | None
    _poisoned: bool
    _live_sock: socket.socket | None
    _watchdog: threading.Timer | None

    def _guard_setup(self, limits: IoLimits | None) -> None:
        self._limits = limits if limits is not None else IoLimits.for_budget(SESSION_BUDGET_S)
        self._literal_cap, self._literal_used, self._line_used = MAX_COMMAND_LITERAL_BYTES, 0, 0
        self._next_literal_cap = None
        self._poisoned = False
        self._live_sock = None
        self._watchdog = None

    @property
    def limits(self) -> IoLimits:
        return self._limits

    @property
    def poisoned(self) -> bool:
        """True once a response was abandoned mid-stream: the connection can only be shut down."""
        return self._poisoned

    def expect_literals(self, cap: int) -> None:
        """The literal budget of the NEXT command (a body fetch gets :data:`MAX_BATCH_LITERAL_BYTES`)."""
        self._next_literal_cap = cap

    # -- commands ---------------------------------------------------------------------------

    def _command(self, name: str, *args: object) -> Any:
        verb = str(name).upper()
        try:
            _check_command(verb, args)
            reason = self._limits.stop_reason(hard=False)
            if reason is not None:
                raise ImapStopped(reason)  # nothing was sent: the connection stays clean
        except ImapError:
            self.literal = None  # an APPEND's message must never ride along with the next command
            self._next_literal_cap = None
            raise
        self._literal_cap = self._next_literal_cap or MAX_COMMAND_LITERAL_BYTES
        self._next_literal_cap = None
        self._literal_used = self._line_used = 0
        return _IMAP_COMMAND(self, name, *args)

    def _mesg(self, *_args: object, **_kwargs: object) -> None:
        return None  # imaplib's debug printer: never echo protocol lines

    def _log(self, *_args: object, **_kwargs: object) -> None:
        return None  # imaplib's in-memory command log: never keep protocol lines

    # -- bounded I/O (imaplib reads every response line and literal through these) ----------

    def _abandon(self, error: ImapError) -> ImapError:
        self._poisoned = True
        return error

    def _before_io(self) -> None:
        reason = self._limits.stop_reason(hard=True)
        if reason is not None:
            raise self._abandon(ImapStopped(reason))
        with contextlib.suppress(OSError, AttributeError):
            self.sock.settimeout(self._limits.io_timeout())

    def _interrupted(self) -> None:
        """After a short read or an I/O error: a stop (watchdog, cancellation) is reported as such."""
        self._poisoned = True
        reason = self._limits.stop_reason(hard=True)
        if reason is not None:
            raise ImapStopped(reason)

    def _count(self, size: int, *, literal: bool) -> None:
        limits = self._limits
        limits.run_bytes += size
        if literal:
            self._literal_used += size
        else:
            self._line_used += size
        if self._line_used > MAX_COMMAND_LINE_BYTES or limits.run_bytes > limits.max_run:
            raise self._abandon(ImapError("imap_protocol"))

    def readline(self) -> bytes:
        self._before_io()
        try:
            line: bytes = imaplib.IMAP4.readline(self)  # type: ignore[arg-type]
        except BaseException:
            self._interrupted()
            raise
        if not line.endswith(b"\n"):
            self._interrupted()
        self._count(len(line), literal=False)
        return line

    def read(self, size: int) -> bytes:
        """A literal of ``size`` bytes, checked against every budget BEFORE anything is read or allocated."""
        limits = self._limits
        room = min(self._literal_cap - self._literal_used, limits.max_run - limits.run_bytes)
        if size > room:
            raise self._abandon(ImapError("imap_protocol"))  # never read: the stream is abandoned
        if size > limits.max_literal:
            self._drain(size)
            return DrainedLiteral(size)
        self._before_io()
        try:
            data: bytes = imaplib.IMAP4.read(self, size)  # type: ignore[arg-type]
        except BaseException:
            self._interrupted()
            raise
        if len(data) != size:
            self._interrupted()
            raise self._abandon(ImapError("imap_unreachable"))
        self._count(size, literal=True)
        return data

    def _drain(self, size: int) -> None:
        """Read ``size`` bytes in bounded chunks and keep none of them."""
        left = size
        while left:
            self._before_io()
            try:
                chunk = self.file.read(min(_DRAIN_CHUNK, left))
            except BaseException:
                self._interrupted()
                raise
            if not chunk:
                self._interrupted()
                raise self._abandon(ImapError("imap_unreachable"))
            left -= len(chunk)
            self._count(len(chunk), literal=True)

    # -- watchdog and cancellation ----------------------------------------------------------

    def _attach(self, sock: socket.socket) -> None:
        """``sock`` is the live connection: the watchdog and a cancellation can shut it down."""
        self._live_sock = sock
        self._arm_watchdog()
        if self._limits.cancel is not None:
            self._limits.cancel.add_hook(self._interrupt)

    def _interrupt(self) -> None:
        """Shut the TCP connection down so that any blocked read returns at once."""
        sock = self._live_sock
        if sock is not None:
            with contextlib.suppress(OSError, ValueError):
                socket.socket.shutdown(sock, socket.SHUT_RDWR)

    def _arm_watchdog(self) -> None:
        self._disarm_watchdog()
        delay = max(self._limits.remaining(), 0.0) + _WATCHDOG_SLACK_S
        timer = threading.Timer(delay, self._interrupt)
        timer.name, timer.daemon = "mordred-imap-watchdog", True
        self._watchdog = timer
        timer.start()

    def _disarm_watchdog(self) -> None:
        timer, self._watchdog = self._watchdog, None
        if timer is not None:
            timer.cancel()
            if timer is not threading.current_thread():
                timer.join()

    def grace(self, seconds: float) -> None:
        """A short new window for a polite ``LOGOUT`` after a stop."""
        self._limits.extend(seconds)
        if self._live_sock is not None:
            self._arm_watchdog()

    def release(self) -> None:
        """Stop the watchdog and drop the cancellation hook (the connection is over)."""
        self._disarm_watchdog()
        if self._limits.cancel is not None:
            self._limits.cancel.remove_hook(self._interrupt)

    def _stopped_or(self, error: BaseException) -> BaseException:
        reason = self._limits.stop_reason(hard=True)
        return ImapStopped(reason) if reason is not None else error

    def shutdown(self) -> None:
        try:
            imaplib.IMAP4.shutdown(self)  # type: ignore[arg-type]
        finally:
            self.release()


class GuardedIMAP4(_CommandGuard, imaplib.IMAP4):
    """Plain IMAP over an already connected socket (tests; the TLS variant is :class:`GuardedIMAP4SSL`)."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        raw_socket: Callable[[float | None], socket.socket],
        timeout: float,
        limits: IoLimits | None = None,
    ):
        self._raw_socket = raw_socket
        self._guard_setup(limits)
        super().__init__(host, port, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        sock = self._raw_socket(timeout)
        self._attach(sock)
        return sock


class GuardedIMAP4SSL(_CommandGuard, imaplib.IMAP4_SSL):
    """Implicit-TLS IMAP whose TCP socket comes from the egress route (direct or SOCKS5)."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        raw_socket: Callable[[float | None], socket.socket],
        ssl_context: ssl.SSLContext,
        timeout: float,
        limits: IoLimits | None = None,
    ):
        self._raw_socket = raw_socket
        self._guard_setup(limits)
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        context: ssl.SSLContext = self.ssl_context
        raw = self._raw_socket(timeout)
        try:
            wrapped = context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
        except BaseException:
            raw.close()
            raise
        self._attach(wrapped)  # the handshake below runs under the watchdog and the cancellation too
        try:
            handshake = getattr(wrapped, "do_handshake", None)
            if handshake is not None:
                wrapped.settimeout(self._limits.io_timeout())
                handshake()
        except BaseException as exc:
            self.release()
            with contextlib.suppress(OSError):
                wrapped.close()
            raise self._stopped_or(exc) from None
        return wrapped


# --- session --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MailboxStatus:
    uidvalidity: int
    uidnext: int | None
    exists: int


@dataclass(frozen=True, slots=True)
class Fetched:
    """One fetched message: its UID, raw bytes and (Gmail) labels and thread id; ``oversize``: drained unread."""

    uid: int
    data: bytes
    labels: tuple[str, ...]
    thread_id: str | None
    oversize: bool = False

    def __repr__(self) -> str:
        return f"Fetched(uid={self.uid}, bytes={len(self.data)}, oversize={self.oversize})"


def _ok(result: tuple[str, list[Any]]) -> list[Any]:
    typ, data = result
    if typ != "OK":
        raise ImapError("imap_protocol")
    return data


@contextlib.contextmanager
def _mapped() -> Iterator[None]:
    """imaplib and socket failures → content-free :class:`ImapError` codes."""
    try:
        yield
    except ImapError:
        raise
    except ImapProtocolError:
        raise ImapError("imap_protocol") from None
    except imaplib.IMAP4.abort:
        raise ImapError("imap_unreachable") from None
    except imaplib.IMAP4.error:
        raise ImapError("imap_protocol") from None
    except (OSError, EOFError):
        raise ImapError("imap_unreachable") from None
    except (ValueError, TypeError, UnicodeError):
        raise ImapError("imap_protocol") from None


class ImapSession:
    """Read-only operations over one guarded connection."""

    def __init__(self, conn: imaplib.IMAP4) -> None:
        self._conn = conn

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(str(item).upper() for item in getattr(self._conn, "capabilities", ()))

    @property
    def gmail(self) -> bool:
        return GMAIL_CAPABILITY in self.capabilities

    @property
    def bytes_read(self) -> int:
        """Every byte this session has read so far (response lines and literals)."""
        conn = self._conn
        return conn.limits.run_bytes if isinstance(conn, _CommandGuard) else 0

    def login(self, user: str, password: str) -> None:
        """``LOGIN`` inside the implicit-TLS connection: the only mechanism, so nothing can downgrade it."""
        if "LOGINDISABLED" in self.capabilities:
            raise ImapError("imap_auth_failed")
        try:
            self._conn.login(user, password)
        except ImapError:
            raise
        except imaplib.IMAP4.abort:
            raise ImapError("imap_unreachable") from None
        except imaplib.IMAP4.error:
            raise ImapError("imap_auth_failed") from None
        except OSError:
            raise ImapError("imap_unreachable") from None
        except (UnicodeError, ValueError):
            raise ImapError("imap_auth_failed") from None
        with _mapped():
            # Refreshed after login: servers may advertise more (Gmail's X-GM-EXT-1) once authenticated.
            words = _capability_words(_ok(self._conn.capability()))
            if words:
                self._conn.capabilities = tuple(words)

    def list_mailboxes(self) -> list[ListEntry]:
        with _mapped():
            return list_entries(_ok(self._conn.list('""', '"*"')))

    def examine(self, name: str) -> MailboxStatus:
        with _mapped():
            data = [item for item in _ok(self._conn.select(quote_mailbox(name), readonly=True)) if item is not None]
            exists = number(data[-1]) if data else 0
            validity = self._response_number("UIDVALIDITY")
            if validity is None or validity <= 0:
                raise ImapError("imap_protocol")
            return MailboxStatus(validity, self._response_number("UIDNEXT"), exists)

    def _response_number(self, code: str) -> int | None:
        _typ, data = self._conn.response(code)
        values = [item for item in data if item is not None]
        if not values:
            return None
        text = values[-1].split()[0] if isinstance(values[-1], bytes) and values[-1].split() else b""
        return number(text)

    def search(self, *criteria: str) -> list[int]:
        with _mapped():
            return search_uids(_ok(self._conn.uid("SEARCH", *criteria)))

    def sizes(self, uids: Sequence[int]) -> dict[int, int]:
        """``UID FETCH (UID RFC822.SIZE)``: no literal is downloaded."""
        if not uids:
            return {}
        result: dict[int, int] = {}
        with _mapped():
            for item in fetch_records(_ok(self._conn.uid("FETCH", _uid_set(uids), "(UID RFC822.SIZE)"))):
                if "UID" in item and "RFC822.SIZE" in item:
                    result[number(item["UID"])] = number(item["RFC822.SIZE"])
        return result

    def fetch(self, uids: Sequence[int], *, gmail: bool) -> list[Fetched]:
        """``UID FETCH (UID BODY.PEEK[] ...)`` — never ``BODY[]``, so nothing is marked read.

        The response may carry at most :data:`MAX_BATCH_LITERAL_BYTES` of literals; a body
        over :data:`MAX_LITERAL_BYTES` is drained unread and comes back with ``oversize``.
        """
        if not uids:
            return []
        items = "(UID BODY.PEEK[] X-GM-LABELS X-GM-THRID X-GM-MSGID)" if gmail else "(UID BODY.PEEK[])"
        wanted = set(uids)
        found: list[Fetched] = []
        with _mapped():
            if isinstance(self._conn, _CommandGuard):
                self._conn.expect_literals(MAX_BATCH_LITERAL_BYTES)
            for item in fetch_records(_ok(self._conn.uid("FETCH", _uid_set(uids), items))):
                if "UID" not in item or "BODY[]" not in item:
                    continue  # an unsolicited FETCH (flags of another message)
                uid = number(item["UID"])
                if uid not in wanted:
                    continue
                if is_drained(item["BODY[]"]):
                    found.append(Fetched(uid, b"", (), None, oversize=True))
                    continue
                found.append(Fetched(uid, body_bytes(item["BODY[]"]), *_gmail_facts(item, gmail)))
        return found

    def logout(self) -> None:
        """End the session: a polite ``LOGOUT`` within a short grace, or a plain shutdown after a broken read."""
        conn = self._conn
        try:
            if isinstance(conn, _CommandGuard):
                if conn.poisoned:
                    raise ImapError("imap_protocol")  # the stream is mid-response: no polite goodbye
                conn.grace(LOGOUT_GRACE_S)
            conn.logout()
        except Exception:  # best effort: the session ends either way
            with contextlib.suppress(Exception):
                conn.shutdown()
        finally:
            if isinstance(conn, _CommandGuard):
                conn.release()


def _capability_words(data: Sequence[object]) -> list[str]:
    words: list[str] = []
    for line in data:
        if isinstance(line, bytes):
            words.extend(word.decode("ascii", "replace").upper() for word in line.split())
    return words


def _gmail_facts(item: dict[str, Value], gmail: bool) -> tuple[tuple[str, ...], str | None]:
    if not gmail:
        return (), None
    labels = gmail_labels(item["X-GM-LABELS"]) if "X-GM-LABELS" in item else ()
    thread = str(number(item["X-GM-THRID"])) if item.get("X-GM-THRID") is not None else None
    return labels, thread


def _uid_set(uids: Sequence[int]) -> str:
    """A compact UID set (``1:5,9``) for an ascending or descending list."""
    ordered = sorted(set(uids))
    ranges: list[str] = []
    start = previous = ordered[0]
    for uid in ordered[1:]:
        if uid == previous + 1:
            previous = uid
            continue
        ranges.append(f"{start}:{previous}" if previous != start else str(start))
        start = previous = uid
    ranges.append(f"{start}:{previous}" if previous != start else str(start))
    return ",".join(ranges)


def connect(
    host: str,
    port: int,
    *,
    limits: IoLimits | None = None,
    route_resolver: Callable[[str], Any] = _default_route,
) -> ImapSession:
    """Open the implicit-TLS connection (port 993 only) over the egress route; failures are :class:`ImapError`."""
    if not valid_host(host) or port != IMAPS_PORT:
        raise ImapError("imap_unreachable")
    bounds = limits if limits is not None else IoLimits.for_budget(SESSION_BUDGET_S)

    def raw(_timeout: float | None) -> socket.socket:
        return open_route_socket(
            host, port, bounds.io_timeout(), route_resolver=route_resolver, remaining=bounds.remaining
        )

    try:
        conn = GuardedIMAP4SSL(
            host, port, raw_socket=raw, ssl_context=tls_context(), timeout=bounds.op_timeout, limits=bounds
        )
    except ImapError:
        raise
    except ssl.SSLError:
        raise ImapError("imap_unreachable") from None
    except (imaplib.IMAP4.error, OSError, EOFError):
        raise ImapError("imap_unreachable") from None
    return ImapSession(conn)
