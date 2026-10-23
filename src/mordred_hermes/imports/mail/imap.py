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
- connection establishment runs under the same bounds (:class:`Link`, armed
  before the route is resolved): the route lookup and ``getaddrinfo`` each run
  in a helper daemon thread that is waited for only until the hard deadline or
  a cancellation (a stalled lookup is abandoned), the TCP connect is
  non-blocking and polled, each address for at most ``min(op_timeout,
  remaining)`` so a stalled address never starves the next one, and the
  SOCKS5 exchange and the TLS handshake read from a socket the watchdog and a
  cancellation shut down. A connection that is not open by the hard deadline
  is ``imap_unreachable``; a cancellation is ``ImapStopped("cancelled")``;
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
``reason``) is not a server failure. A refused ``LOGIN`` also carries a
``hint`` from :data:`IMAP_HINTS`, taken from the bracketed RFC 5530 response
code only (``[AUTHENTICATIONFAILED]``, ``[ALERT]``) or the ``LOGINDISABLED``
capability; the server's text after the code is never kept, logged or returned
(Gmail's alert text holds a support URL and sometimes the account name).
"""

from __future__ import annotations

import contextlib
import errno
import imaplib
import re
import selectors
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final, TypeVar

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
    "IMAP_HINTS",
    "MAX_BATCH_LITERAL_BYTES",
    "MAX_LITERAL_BYTES",
    "MAX_RUN_BYTES",
    "CancelToken",
    "Fetched",
    "ImapError",
    "ImapSession",
    "ImapStopped",
    "IoLimits",
    "Link",
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
WATCHDOG_NAME: Final = "mordred-imap-watchdog"
RESOLVER_NAME: Final = "mordred-imap-resolver"
ROUTE_RESOLVER_NAME: Final = "mordred-imap-route"
_WATCHDOG_SLACK_S: Final = 0.25
#: How often a pending TCP connect looks at the cancellation and the deadline.
_CONNECT_POLL_S: Final = 0.05
#: ``connect_ex`` results of a non-blocking connect that is still under way (or already done).
_CONNECTING: Final = frozenset(
    {0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK)}
)
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
_T = TypeVar("_T")

#: Why a login was refused, for the owner's remediation text (closed: anything else is ``None``).
IMAP_HINTS: Final = frozenset({"authentication_failed", "server_alert", "login_disabled", "gmail_app_password_length"})
#: An RFC 5530 response code opening a tagged reply's text; only the code is ever read.
_RESPONSE_CODE_RE: Final = re.compile(r"^\[([A-Z][A-Z0-9-]{1,30})\]")
_RESPONSE_CODE_HINTS: Final = {"AUTHENTICATIONFAILED": "authentication_failed", "ALERT": "server_alert"}


class ImapError(Exception):
    """A content-free IMAP failure code (never server text), with an optional :data:`IMAP_HINTS` member."""

    def __init__(self, code: str, hint: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.hint = hint if hint in IMAP_HINTS else None


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


def _getaddrinfo(host: str, port: int) -> list[Any]:
    """The system resolver (a seam: tests replace it with one that never answers)."""
    return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)


def _new_selector() -> selectors.BaseSelector:
    return selectors.DefaultSelector()


def _shutdown(sock: socket.socket) -> None:
    """Shut ``sock`` down so that a blocked read or handshake returns at once (never a TLS goodbye)."""
    with contextlib.suppress(OSError, ValueError):
        socket.socket.shutdown(sock, socket.SHUT_RDWR)


class Link:
    """The bounds of one connection, from the route lookup to ``LOGOUT``.

    :meth:`arm` starts the watchdog (the hard deadline) and hooks the cancellation
    BEFORE anything touches the network. Either one then shuts down the socket the
    link holds (:meth:`hold`) and wakes a :meth:`bounded` wait, so the route lookup,
    DNS, the TCP connect, the SOCKS5 exchange, the TLS handshake and every command
    end by the absolute deadline. During establishment a deadline is ``imap_unreachable`` and a
    cancellation ``ImapStopped("cancelled")`` (:meth:`failure`).
    """

    def __init__(self, limits: IoLimits) -> None:
        self.limits = limits
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._wake: threading.Event | None = None
        self._fired = False
        self._watchdog: threading.Timer | None = None
        self._hooked = False

    # -- watchdog and cancellation ----------------------------------------------------------

    def arm(self) -> None:
        """(Re)start the watchdog at the hard deadline; hook the cancellation (once)."""
        self.disarm()
        timer = threading.Timer(max(self.limits.remaining(), 0.0) + _WATCHDOG_SLACK_S, self.interrupt)
        timer.name, timer.daemon = WATCHDOG_NAME, True
        self._watchdog = timer
        timer.start()
        cancel = self.limits.cancel
        if cancel is not None and not self._hooked:
            self._hooked = True
            cancel.add_hook(self.interrupt)  # runs at once when already cancelled

    def disarm(self) -> None:
        timer, self._watchdog = self._watchdog, None
        if timer is not None:
            timer.cancel()
            if timer is not threading.current_thread():
                timer.join()

    def release(self) -> None:
        """Stop the watchdog and drop the cancellation hook (the connection is over)."""
        self.disarm()
        cancel = self.limits.cancel
        if cancel is not None and self._hooked:
            self._hooked = False
            cancel.remove_hook(self.interrupt)

    def interrupt(self) -> None:
        """Shut the held socket down and wake a resolver wait (the watchdog or a cancellation; any thread)."""
        with self._lock:
            self._fired = True
            sock, wake = self._sock, self._wake
        if wake is not None:
            wake.set()
        if sock is not None:
            _shutdown(sock)

    # -- the socket ---------------------------------------------------------------------------

    @property
    def holding(self) -> bool:
        return self._sock is not None

    def hold(self, sock: socket.socket) -> None:
        """``sock`` is the connection now: an interrupt shuts it down (at once when one already fired)."""
        with self._lock:
            self._sock = sock
            fired = self._fired
        if fired:
            _shutdown(sock)

    def drop(self, sock: socket.socket | None = None) -> None:
        """Close ``sock`` (a failed attempt; default: the held socket) and stop holding it."""
        with self._lock:
            target = self._sock if sock is None else sock
            if self._sock is target:
                self._sock = None
        if target is not None:
            with contextlib.suppress(OSError):
                target.close()

    # -- bounds -------------------------------------------------------------------------------

    def remaining(self) -> float:
        return self.limits.remaining()

    def timeout(self) -> float:
        return self.limits.io_timeout()

    def cancelled(self) -> bool:
        cancel = self.limits.cancel
        return cancel is not None and cancel.cancelled

    def failure(self) -> ImapError:
        """What an interrupted or failed establishment step is: a cancellation, else ``imap_unreachable``."""
        return ImapStopped("cancelled") if self.cancelled() else ImapError("imap_unreachable")

    def check(self) -> None:
        """Raise :meth:`failure` once cancelled, interrupted or past the hard deadline."""
        if self.cancelled() or self._fired or self.remaining() <= 0:
            raise self.failure()

    # -- establishment ------------------------------------------------------------------------

    def bounded(self, call: Callable[[], _T], *, name: str) -> _T:
        """``call()`` in a daemon helper thread, waited for until the hard deadline or a cancellation.

        A call that has not returned by then is abandoned (its thread ends whenever
        the call returns) and the attempt is :meth:`failure`; an exception the call
        raised is re-raised here. The route lookup and ``getaddrinfo`` run this way,
        so neither can hold a connection attempt past its deadline.
        """
        self.check()
        wake = threading.Event()
        box: dict[str, Any] = {}

        def work() -> None:
            try:
                box["value"] = call()
            except Exception as exc:  # handed to the waiting thread, never stringified here
                box["error"] = exc
            finally:
                wake.set()

        with self._lock:
            fired, self._wake = self._fired, wake
        try:
            if not fired:
                threading.Thread(target=work, name=name, daemon=True).start()
                wake.wait(max(self.remaining(), 0.0))
        finally:
            with self._lock:
                self._wake = None
        self.check()
        if "error" in box:
            raise box["error"]
        if "value" not in box:
            raise self.failure()  # woken without an answer: an interrupt raced the deadline check
        value: _T = box["value"]
        return value

    def resolve(self, host: str, port: int) -> list[Any]:
        """``getaddrinfo`` under :meth:`bounded`; a failed or empty lookup is ``imap_unreachable``."""
        try:
            found = self.bounded(lambda: list(_getaddrinfo(host, port)), name=RESOLVER_NAME)
        except ImapError:
            raise
        except Exception:  # a failed lookup is reported as a code, never stringified
            raise ImapError("imap_unreachable") from None
        if not found:
            raise ImapError("imap_unreachable")
        return found

    def connect_tcp(self, host: str, port: int) -> socket.socket:
        """A TCP connection to the first address of ``host`` that answers before the deadline.

        Each address gets at most ``min(op_timeout, remaining)`` (:meth:`_connect_one`),
        so a stalled first address cannot use up the budget of the ones after it.
        """
        for family, kind, proto, _name, address in self.resolve(host, port):
            self.check()
            with contextlib.suppress(OSError):  # refused, unreachable or timed out: the next address
                return self._connect_one(family, kind, proto, address)
        self.check()
        raise ImapError("imap_unreachable")

    def _connect_one(self, family: int, kind: int, proto: int, address: Any) -> socket.socket:
        """A non-blocking connect, polled so that the deadline, a cancellation and its own timeout end it.

        The attempt's own limit is ``min(op_timeout, remaining)``: past it the attempt
        is a ``TimeoutError`` (the caller tries the next address); past the hard
        deadline or after a cancellation it is :meth:`failure`.
        """
        clock = self.limits.clock
        attempt_end = clock() + min(self.limits.op_timeout, max(self.remaining(), 0.0))
        sock = socket.socket(family, kind, proto)
        try:
            self.hold(sock)
            sock.setblocking(False)
            code = sock.connect_ex(address)
            if code not in _CONNECTING:
                raise OSError(code, "connect")
            with _new_selector() as selector:
                selector.register(sock, selectors.EVENT_WRITE)
                while not selector.select(min(_CONNECT_POLL_S, max(attempt_end - clock(), 0.0))):
                    self.check()
                    if clock() >= attempt_end:
                        raise TimeoutError(errno.ETIMEDOUT, "connect")
            self.check()
            code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if code:
                raise OSError(code, "connect")
            sock.settimeout(self.timeout())
        except BaseException:
            self.drop(sock)
            raise
        return sock


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


def socks5_connect(proxy: Any, host: str, port: int, link: Link) -> socket.socket:
    """A TCP connection to ``host:port`` through the SOCKS5 ``proxy`` (an :class:`~...extension.egress.SocksProxy`).

    The proxy connection is held by ``link``, so the method selection, the
    authentication and the ``CONNECT`` reply are cut by the deadline and by a
    cancellation like any other read.
    """
    sock = link.connect_tcp(proxy.host, proxy.port)
    try:
        socks5_handshake(sock, host, port, proxy.username, proxy.password, link.remaining)
        link.check()
        sock.settimeout(link.timeout())
    except BaseException as exc:
        link.drop(sock)
        if isinstance(exc, Exception) and link.cancelled():
            raise ImapStopped("cancelled") from None
        if isinstance(exc, OSError):
            raise link.failure() from None
        raise
    return sock


def _default_route(host: str) -> Any:
    from ...extension.egress import resolve_route

    return resolve_route(host)


def open_route_socket(
    host: str,
    port: int,
    link: Link,
    *,
    route_resolver: Callable[[str], Any] = _default_route,
) -> socket.socket:
    """A connected TCP socket to ``host:port`` over the route the network policy selects, bounded by ``link``."""
    from ...extension.egress import EgressError, socks_proxy

    try:
        route = link.bounded(lambda: route_resolver(host), name=ROUTE_RESOLVER_NAME)
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
            return socks5_connect(proxy, host, port, link)
        return link.connect_tcp(host, port)
    except OSError:
        raise link.failure() from None


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
    _link: Link

    def _guard_setup(self, limits: IoLimits | None) -> None:
        self._limits = limits if limits is not None else IoLimits.for_budget(SESSION_BUDGET_S)
        self._literal_cap, self._literal_used, self._line_used = MAX_COMMAND_LITERAL_BYTES, 0, 0
        self._next_literal_cap = None
        self._poisoned = False
        self._link = Link(self._limits)

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

    # -- watchdog, cancellation and establishment -----------------------------------------------

    def grace(self, seconds: float) -> None:
        """A short new window for a polite ``LOGOUT`` after a stop."""
        self._limits.extend(seconds)
        if self._link.holding:
            self._link.arm()

    def release(self) -> None:
        """Stop the watchdog and drop the cancellation hook (the connection is over)."""
        self._link.release()

    def _establish(self, open_socket: Callable[[Link], socket.socket]) -> socket.socket:
        """``open_socket(link)`` with the watchdog and the cancellation armed BEFORE it touches the network."""
        link = self._link
        link.arm()
        try:
            sock = open_socket(link)
            link.check()
        except BaseException as exc:
            self.release()
            link.drop()
            raise self._establish_failure(exc) from None
        return sock

    def _establish_failure(self, exc: BaseException) -> BaseException:
        """A cancellation stays ``cancelled``; a deadline, a reset or a TLS failure is ``imap_unreachable``."""
        if isinstance(exc, ImapStopped) or not isinstance(exc, Exception):
            return exc
        if self._link.cancelled():
            return ImapStopped("cancelled")
        return exc if isinstance(exc, ImapError) else ImapError("imap_unreachable")

    def shutdown(self) -> None:
        try:
            imaplib.IMAP4.shutdown(self)  # type: ignore[arg-type]
        finally:
            self.release()


class GuardedIMAP4(_CommandGuard, imaplib.IMAP4):
    """Plain IMAP over the socket ``raw_socket(link)`` opens (tests; the TLS variant is :class:`GuardedIMAP4SSL`)."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        raw_socket: Callable[[Link], socket.socket],
        timeout: float,
        limits: IoLimits | None = None,
    ):
        self._raw_socket = raw_socket
        self._guard_setup(limits)
        super().__init__(host, port, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        def open_socket(link: Link) -> socket.socket:
            sock = self._raw_socket(link)
            link.hold(sock)
            return sock

        return self._establish(open_socket)


class GuardedIMAP4SSL(_CommandGuard, imaplib.IMAP4_SSL):
    """Implicit-TLS IMAP whose TCP socket ``raw_socket(link)`` opens over the egress route (direct or SOCKS5)."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        raw_socket: Callable[[Link], socket.socket],
        ssl_context: ssl.SSLContext,
        timeout: float,
        limits: IoLimits | None = None,
    ):
        self._raw_socket = raw_socket
        self._guard_setup(limits)
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        return self._establish(self._tls_socket)

    def _tls_socket(self, link: Link) -> socket.socket:
        """The route socket wrapped in TLS; the handshake reads from a socket the link can shut down."""
        context: ssl.SSLContext = self.ssl_context
        raw = self._raw_socket(link)
        link.hold(raw)
        try:
            wrapped = context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
        except BaseException:
            link.drop(raw)
            raise
        link.hold(wrapped)  # the raw socket object is detached now: interrupts reach the TLS socket
        try:
            handshake = getattr(wrapped, "do_handshake", None)
            if handshake is not None:
                wrapped.settimeout(link.timeout())
                handshake()
        except BaseException:
            link.drop(wrapped)
            raise
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
        """``LOGIN`` inside the implicit-TLS connection: the only mechanism, so nothing can downgrade it.

        A refusal is ``imap_auth_failed`` with the hint of its response code
        (:func:`_login_hint`). The failure is raised outside the handler, so the
        imaplib error holding the server's text is not even its ``__context__``.
        """
        if "LOGINDISABLED" in self.capabilities:
            raise ImapError("imap_auth_failed", hint="login_disabled")
        failure: ImapError | None = None
        try:
            self._conn.login(user, password)
        except ImapError:
            raise
        except imaplib.IMAP4.abort:
            failure = ImapError("imap_unreachable")
        except imaplib.IMAP4.error as exc:
            failure = ImapError("imap_auth_failed", hint=_login_hint(exc))
        except OSError:
            failure = ImapError("imap_unreachable")
        except (UnicodeError, ValueError):
            failure = ImapError("imap_auth_failed")
        if failure is not None:
            setattr(self._conn, "mo", None)  # noqa: B010 - imaplib's last regex match still holds the reply line
            raise failure
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


def _login_hint(exc: BaseException) -> str | None:
    """The :data:`IMAP_HINTS` member for a refused ``LOGIN``, from its response code only.

    imaplib raises ``error(<reply text>)`` with the tagged reply's bytes, so
    ``str(exc)`` reads ``b'[ALERT] ...'``; the raw first argument is matched
    instead. Only the bracketed code is read; nothing of the text is returned.
    """
    first = exc.args[0] if exc.args else None
    if isinstance(first, bytes):
        text = first[:34].decode("ascii", "replace")
    elif isinstance(first, str):
        text = first[:34]
    else:
        return None
    match = _RESPONSE_CODE_RE.match(text)
    return _RESPONSE_CODE_HINTS.get(match.group(1)) if match else None


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
    """Open the implicit-TLS connection (port 993 only) over the egress route; failures are :class:`ImapError`.

    Everything up to the server greeting (route, DNS, TCP, SOCKS5, TLS, greeting)
    runs under ``limits``: a connection that is not open by the hard deadline is
    ``imap_unreachable``, a cancellation ``ImapStopped("cancelled")``.
    """
    if not valid_host(host) or port != IMAPS_PORT:
        raise ImapError("imap_unreachable")
    bounds = limits if limits is not None else IoLimits.for_budget(SESSION_BUDGET_S)

    def raw(link: Link) -> socket.socket:
        return open_route_socket(host, port, link, route_resolver=route_resolver)

    try:
        conn = GuardedIMAP4SSL(
            host, port, raw_socket=raw, ssl_context=tls_context(), timeout=bounds.op_timeout, limits=bounds
        )
    except ImapStopped as stopped:
        if stopped.reason == "cancelled":
            raise
        raise ImapError("imap_unreachable") from None  # the deadline passed before the session was open
    except ImapError:
        raise
    except ssl.SSLError:
        raise ImapError("imap_unreachable") from None
    except (imaplib.IMAP4.error, OSError, EOFError):
        raise ImapError("imap_unreachable") from None
    return ImapSession(conn)
