"""Read-only IMAP client for the mail collector: route, TLS, command allowlist, session.

Transport (SPEC "IMAP sync (2026-10-22)"):

- The route comes from :func:`mordred_hermes.extension.egress.resolve_route` for
  the sealed host, the same resolver Mordred's Telegram and Venice clients use
  (Tor needs a loopback SOCKS proxy, a VPN needs the live network runtime, no
  proxy environment variable is read here). That module returns a route, not a
  socket, so the socket is built here: a direct TCP connection, or SOCKS5 with
  remote DNS (the hostname is sent to the proxy, never resolved locally) and the
  route's proxy credentials (the Tor stream-isolation token). Any other proxy
  kind refuses with ``egress_unsupported``.
- TLS is implicit (port 993 by default) with :func:`ssl.create_default_context`:
  certificate and hostname verification on, TLS 1.2 or newer, SNI set to the
  sealed host. ``STARTTLS`` and referrals are never used.

Protocol: :class:`_CommandGuard` refuses, before anything is sent, every command
outside ``CAPABILITY``, ``LOGIN``/``AUTHENTICATE``, ``LIST``, ``EXAMINE``,
``UID SEARCH``, ``UID FETCH`` (``BODY.PEEK[]`` and metadata items only), ``NOOP``
and ``LOGOUT`` — so no ``SELECT``, ``STORE``, ``COPY``, ``EXPUNGE`` or ``APPEND``
and no ``BODY[]`` (which would set ``\\Seen``) can ever leave the process.
imaplib's debug output and command log are disabled. Errors are
:class:`ImapError` codes: ``imap_unreachable``, ``imap_auth_failed``,
``imap_protocol``, ``imap_command_refused``, ``egress_unsupported``,
``routing_unavailable``.
"""

from __future__ import annotations

import contextlib
import imaplib
import re
import socket
import ssl
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final

from ._imap_codec import (
    ImapProtocolError,
    ListEntry,
    Value,
    body_bytes,
    fetch_records,
    gmail_labels,
    list_entries,
    number,
    quote_mailbox,
    search_uids,
)

__all__ = [
    "DEFAULT_PORT",
    "GMAIL_CAPABILITY",
    "Fetched",
    "ImapError",
    "ImapSession",
    "MailboxStatus",
    "connect",
    "open_route_socket",
    "socks5_connect",
    "tls_context",
]

DEFAULT_PORT: Final = 993
GMAIL_CAPABILITY: Final = "X-GM-EXT-1"
SOCKET_TIMEOUT_S: Final = 30.0
_ALLOWED_COMMANDS: Final = frozenset(
    {"CAPABILITY", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "UID", "NOOP", "LOGOUT"}
)
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


def valid_host(host: str) -> bool:
    """A DNS hostname (letters, digits, hyphens; at least two labels)."""
    return isinstance(host, str) and _HOST_RE.fullmatch(host) is not None


# --- transport ------------------------------------------------------------------------------------


def tls_context() -> ssl.SSLContext:
    """Certificate and hostname verification on, TLS 1.2 or newer."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if context.minimum_version < ssl.TLSVersion.TLSv1_2:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ImapError("imap_unreachable")
        data.extend(chunk)
    return bytes(data)


def _socks_auth(sock: socket.socket, username: str, password: str) -> None:
    user, secret = username.encode("utf-8"), password.encode("utf-8")
    if not 0 < len(user) < 256 or len(secret) > 255:
        raise ImapError("egress_unsupported")
    sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    if _recv_exact(sock, 2)[1] != 0:
        raise ImapError("imap_unreachable")


def _socks_bound_address(sock: socket.socket, atyp: int) -> None:
    if atyp == 1:
        _recv_exact(sock, 4 + 2)
    elif atyp == 4:
        _recv_exact(sock, 16 + 2)
    elif atyp == 3:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    else:
        raise ImapError("imap_unreachable")


def socks5_handshake(sock: socket.socket, host: str, port: int, username: str | None, password: str | None) -> None:
    """RFC 1928 ``CONNECT`` by hostname (remote DNS), RFC 1929 username/password when the route has them."""
    name = host.encode("ascii")
    methods = b"\x00\x02" if username is not None else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _recv_exact(sock, 2)
    if version != 5 or method not in methods:
        raise ImapError("imap_unreachable")
    if method == 2:
        _socks_auth(sock, username or "", password or "")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    version, reply, _reserved, atyp = _recv_exact(sock, 4)
    if version != 5 or reply != 0:
        raise ImapError("imap_unreachable")
    _socks_bound_address(sock, atyp)


def socks5_connect(proxy: Any, host: str, port: int, timeout: float) -> socket.socket:
    """A TCP connection to ``host:port`` through the SOCKS5 ``proxy`` (an :class:`~...extension.egress.SocksProxy`)."""
    sock = socket.create_connection((proxy.host, proxy.port), timeout)
    try:
        socks5_handshake(sock, host, port, proxy.username, proxy.password)
    except BaseException:
        sock.close()
        raise
    return sock


def _default_route(host: str) -> Any:
    from ...extension.egress import resolve_route

    return resolve_route(host)


def open_route_socket(
    host: str, port: int, timeout: float, *, route_resolver: Callable[[str], Any] = _default_route
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
            return socks5_connect(proxy, host, port, timeout)
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


class _CommandGuard:
    """Refuse every command outside the read-only allowlist before it is sent; no debug output."""

    literal: str | None  # imaplib's pending literal (set by ``append``)

    def _command(self, name: str, *args: object) -> Any:
        verb = str(name).upper()
        try:
            if verb not in _ALLOWED_COMMANDS:
                raise ImapError("imap_command_refused")
            if verb == "UID":
                _check_uid_command(args)
        except ImapError:
            self.literal = None  # an APPEND's message must never ride along with the next command
            raise
        return _IMAP_COMMAND(self, name, *args)

    def _mesg(self, *_args: object, **_kwargs: object) -> None:
        return None  # imaplib's debug printer: never echo protocol lines

    def _log(self, *_args: object, **_kwargs: object) -> None:
        return None  # imaplib's in-memory command log: never keep protocol lines


class GuardedIMAP4(_CommandGuard, imaplib.IMAP4):
    """Plain IMAP over an already connected socket (tests; the TLS variant is :class:`GuardedIMAP4SSL`)."""

    def __init__(self, host: str, port: int, *, raw_socket: Callable[[float | None], socket.socket], timeout: float):
        self._raw_socket = raw_socket
        super().__init__(host, port, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        return self._raw_socket(timeout)


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
    ):
        self._raw_socket = raw_socket
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        context: ssl.SSLContext = self.ssl_context
        return context.wrap_socket(self._raw_socket(timeout), server_hostname=self.host)


# --- session --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MailboxStatus:
    uidvalidity: int
    uidnext: int | None
    exists: int


@dataclass(frozen=True, slots=True)
class Fetched:
    """One fetched message: its UID, raw bytes and (Gmail) labels and thread id."""

    uid: int
    data: bytes
    labels: tuple[str, ...]
    thread_id: str | None

    def __repr__(self) -> str:
        return f"Fetched(uid={self.uid}, bytes={len(self.data)})"


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

    def login(self, user: str, password: str) -> None:
        if "LOGINDISABLED" in self.capabilities:
            raise ImapError("imap_auth_failed")
        try:
            self._conn.login(user, password)
        except imaplib.IMAP4.abort:
            raise ImapError("imap_unreachable") from None
        except imaplib.IMAP4.error:
            raise ImapError("imap_auth_failed") from None
        except OSError:
            raise ImapError("imap_unreachable") from None
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
        """``UID FETCH (UID BODY.PEEK[] ...)`` — never ``BODY[]``, so nothing is marked read."""
        if not uids:
            return []
        items = "(UID BODY.PEEK[] X-GM-LABELS X-GM-THRID X-GM-MSGID)" if gmail else "(UID BODY.PEEK[])"
        wanted = set(uids)
        found: list[Fetched] = []
        with _mapped():
            for item in fetch_records(_ok(self._conn.uid("FETCH", _uid_set(uids), items))):
                if "UID" not in item or "BODY[]" not in item:
                    continue  # an unsolicited FETCH (flags of another message)
                uid = number(item["UID"])
                if uid not in wanted:
                    continue
                found.append(Fetched(uid, body_bytes(item["BODY[]"]), *_gmail_facts(item, gmail)))
        return found

    def logout(self) -> None:
        try:
            self._conn.logout()
        except Exception:  # best effort: the session ends either way
            with contextlib.suppress(Exception):
                self._conn.shutdown()


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
    timeout: float = SOCKET_TIMEOUT_S,
    route_resolver: Callable[[str], Any] = _default_route,
) -> ImapSession:
    """Open the implicit-TLS connection over the egress route; failures are :class:`ImapError` codes."""
    if not valid_host(host) or not 0 < port < 65536:
        raise ImapError("imap_unreachable")

    def raw(sock_timeout: float | None) -> socket.socket:
        return open_route_socket(host, port, sock_timeout or timeout, route_resolver=route_resolver)

    try:
        conn = GuardedIMAP4SSL(host, port, raw_socket=raw, ssl_context=tls_context(), timeout=timeout)
    except ImapError:
        raise
    except ssl.SSLError:
        raise ImapError("imap_unreachable") from None
    except (imaplib.IMAP4.error, OSError, EOFError):
        raise ImapError("imap_unreachable") from None
    return ImapSession(conn)
