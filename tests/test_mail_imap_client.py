"""IMAP codec, egress transport, TLS settings and the read-only command allowlist."""

from __future__ import annotations

import contextlib
import imaplib
import socket
import ssl
import threading
import time
import tracemalloc
from typing import Any

import pytest

from mordred_hermes.extension.egress import EgressError, EgressRoute
from mordred_hermes.imports.mail import imap
from mordred_hermes.imports.mail._imap_codec import (
    ImapProtocolError,
    Literal,
    decode_mutf7,
    encode_mutf7,
    fetch_records,
    gmail_labels,
    list_entries,
    parse_values,
    quote_mailbox,
    search_uids,
)
from mordred_hermes.imports.mail.imap import (
    CancelToken,
    GuardedIMAP4,
    GuardedIMAP4SSL,
    ImapError,
    ImapSession,
    ImapStopped,
    IoLimits,
    Link,
)
from tests._fake_imap import FakeImapServer, FakeMailbox, FakeMessage, mail

# --- modified UTF-7 and labels --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("wire", "text"),
    [("INBOX", "INBOX"), ("&-", "&"), ("Tom &- Jerry", "Tom & Jerry"), ("&ZeVnLIqe-", "日本語")],
)
def test_modified_utf7_round_trip(wire: str, text: str) -> None:
    assert decode_mutf7(wire) == text
    assert encode_mutf7(text) == wire


@pytest.mark.parametrize("bad", ["&ZeVnLIqe", "&!!!-", "café"])
def test_malformed_modified_utf7_is_a_protocol_error(bad: str) -> None:
    with pytest.raises(ImapProtocolError):
        decode_mutf7(bad)


def test_gmail_system_labels_are_canonical_and_custom_labels_decoded() -> None:
    [record] = fetch_records([b'1 (UID 9 X-GM-LABELS (\\sent "\\\\Important" &ZeVnLIqe- "Sent" Work) X-GM-THRID 123)'])
    labels = gmail_labels(record["X-GM-LABELS"])
    assert labels == ("\\Sent", "\\Important", "日本語", "Sent", "Work")


def test_fetch_records_handle_trailers_literals_and_unsolicited_lines() -> None:
    data: list[Any] = [
        (b"1 (X-GM-THRID 5 BODY[] {5}", b"hello"),
        b" UID 7)",
        b"2 (FLAGS (\\Seen))",
        (b"3 (UID 9 BODY[] {3}", b"abc"),
        b")",
    ]
    first, flags, third = fetch_records(data)
    assert first["UID"] == b"7" and first["BODY[]"] == Literal(b"hello") and first["X-GM-THRID"] == b"5"
    assert "UID" not in flags
    assert third["BODY[]"] == Literal(b"abc")


@pytest.mark.parametrize(
    "data",
    [
        [(b"1 (UID 7 BODY[] {9}", b"short")],  # wrong literal length, no closing line
        [b"1 (UID 7"],  # unbalanced
        [b"1 UID 7)"],
    ],
)
def test_malformed_fetch_data_is_a_protocol_error(data: list[Any]) -> None:
    with pytest.raises(ImapProtocolError):
        fetch_records(data)


def test_list_entries_parse_special_use_nil_delimiters_and_literal_names() -> None:
    entries = list_entries(
        [
            b'(\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"',
            b"(\\Noselect) NIL Archive",
            (b'(\\HasNoChildren) "/" {11}', b"&ZeVnLIqe-x"),
            b"",
        ]
    )
    assert [(entry.name, entry.selectable) for entry in entries] == [
        ("[Gmail]/Sent Mail", True),
        ("Archive", False),
        ("&ZeVnLIqe-x", True),
    ]
    assert "\\sent" in entries[0].attributes
    assert entries[2].display == "日本語x"


def test_search_uids_and_quoting() -> None:
    assert search_uids([b"3 1 2", None, b"2 9"]) == [1, 2, 3, 9]
    with pytest.raises(ImapProtocolError):
        search_uids([b"1 two"])
    assert quote_mailbox('a "b" \\c') == '"a \\"b\\" \\\\c"'
    with pytest.raises(ImapProtocolError):
        quote_mailbox("bad\r\nLOGOUT")
    assert parse_values([b'NIL "x" (a b)']) == [None, b"x", [b"a", b"b"]]


# --- transport ------------------------------------------------------------------------------------


def test_tls_context_verifies_certificates_and_hostnames() -> None:
    context = imap.tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_the_ssl_client_wraps_the_route_socket_with_sni_of_the_sealed_host() -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1)})
    wrapped: list[tuple[Any, str | None]] = []

    class RecordingContext:
        def wrap_socket(self, sock: socket.socket, server_hostname: str | None = None, **_kw: Any) -> socket.socket:
            wrapped.append((sock, server_hostname))
            return sock  # the fake server speaks plain IMAP (no do_handshake: nothing to negotiate)

    conn = GuardedIMAP4SSL(
        "imap.example.com",
        993,
        raw_socket=server.connect,
        ssl_context=RecordingContext(),  # type: ignore[arg-type]
        timeout=5.0,
    )
    conn.logout()
    assert [name for _sock, name in wrapped] == ["imap.example.com"]


@contextlib.contextmanager
def _armed(budget: float = 5.0, cancel: CancelToken | None = None) -> Any:
    """A link armed as the guarded client arms it (watchdog and cancellation hook), released afterwards."""
    link = Link(IoLimits.for_budget(budget, cancel=cancel))
    link.arm()
    try:
        yield link
    finally:
        link.release()
        link.drop()


def _listener() -> tuple[socket.socket, tuple[str, int]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    return listener, listener.getsockname()


def _resolving_to(address: tuple[str, int], seen: list[tuple[str, int]] | None = None) -> Any:
    def resolve(host: str, port: int) -> list[Any]:
        if seen is not None:
            seen.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)]

    return resolve


def test_direct_route_connects_to_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    listener, address = _listener()
    seen: list[tuple[str, int]] = []
    monkeypatch.setattr(imap, "_getaddrinfo", _resolving_to(address, seen))
    try:
        with _armed() as link:
            sock = imap.open_route_socket(
                "imap.example.com", 993, link, route_resolver=lambda _h: EgressRoute(None, None)
            )
            accepted, _ = listener.accept()
            sock.sendall(b"ping")
            assert accepted.recv(4) == b"ping"
            accepted.close()
    finally:
        listener.close()
    assert seen == [("imap.example.com", 993)]  # resolved in the helper thread, by name


@pytest.mark.parametrize(
    ("route", "code"),
    [
        (EgressRoute(None, "http://127.0.0.1:8080"), "egress_unsupported"),
        (EgressRoute("socks4://127.0.0.1:9050", None), "egress_unsupported"),
    ],
)
def test_other_proxy_kinds_are_refused(route: EgressRoute, code: str) -> None:
    with _armed() as link, pytest.raises(ImapError) as raised:
        imap.open_route_socket("imap.example.com", 993, link, route_resolver=lambda _h: route)
    assert raised.value.code == code


def test_a_routing_refusal_is_routing_unavailable() -> None:
    def refuse(_host: str) -> EgressRoute:
        raise EgressError()

    with _armed() as link, pytest.raises(ImapError) as raised:
        imap.open_route_socket("imap.example.com", 993, link, route_resolver=refuse)
    assert raised.value.code == "routing_unavailable"


def _socks_server(listener: socket.socket, seen: list[bytes], *, auth: bool) -> None:
    conn, _ = listener.accept()
    with conn:
        greeting = conn.recv(3)
        seen.append(greeting)
        if auth:
            conn.sendall(b"\x05\x02")
            request = conn.recv(256)
            seen.append(request)
            conn.sendall(b"\x01\x00")
        else:
            conn.sendall(b"\x05\x00")
        connect = conn.recv(300)
        seen.append(connect)
        conn.sendall(b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01" + b"\x03\xe1")
        conn.sendall(b"* OK ready\r\n")
        conn.recv(10)


@pytest.mark.parametrize(("auth", "scheme"), [(False, "socks5"), (True, "socks5"), (False, "socks5h")])
def test_socks5_route_sends_the_hostname_for_remote_dns(auth: bool, scheme: str) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen: list[bytes] = []
    thread = threading.Thread(target=_socks_server, args=(listener, seen), kwargs={"auth": auth}, daemon=True)
    thread.start()
    credentials = "iso%20user:token@" if auth else ""
    route = EgressRoute(f"{scheme}://{credentials}127.0.0.1:{port}", None)
    with _armed() as link:
        sock = imap.open_route_socket("imap.example.com", 993, link, route_resolver=lambda _h: route)
        try:
            assert sock.recv(64) == b"* OK ready\r\n"
        finally:
            sock.close()
            thread.join(5)
            listener.close()
    name = b"imap.example.com"
    assert seen[-1] == b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (993).to_bytes(2, "big")
    if auth:
        assert seen[0] == b"\x05\x01\x02"  # with credentials, "no authentication" is never offered
        assert seen[1] == b"\x01\x08iso user\x05token"
    else:
        assert seen[0] == b"\x05\x01\x00"


# --- the read-only command allowlist --------------------------------------------------------------


@pytest.fixture
def connected() -> tuple[GuardedIMAP4, FakeImapServer]:
    box = FakeMailbox(uidvalidity=3, messages={1: FakeMessage(mail(1))})
    server = FakeImapServer({"INBOX": box})
    conn = GuardedIMAP4("imap.example.com", 993, raw_socket=server.connect, timeout=5.0)
    conn.login("owner@example.com", "app-password-1")
    conn.select('"INBOX"', readonly=True)
    return conn, server


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.select('"INBOX"'),  # SELECT (read-write)
        lambda c: c.store("1", "+FLAGS", "(\\Seen)"),
        lambda c: c.uid("STORE", "1", "+FLAGS", "(\\Seen)"),
        lambda c: c.uid("FETCH", "1", "(BODY[])"),
        lambda c: c.uid("FETCH", "1", "(RFC822)"),
        lambda c: c.uid("FETCH", "1 BODY[]", "(UID)"),
        lambda c: c.uid("COPY", "1", "Trash"),
        lambda c: c.copy("1", "Trash"),
        lambda c: c.expunge(),
        lambda c: c.append("INBOX", None, None, b"x"),
        lambda c: c.xatom("XLIST", '""', '"*"'),
        lambda c: c.uid("SEARCH", "UID", "1:*", "TEXT", "x"),
    ],
)
def test_state_changing_commands_never_leave_the_process(call: Any, connected: Any) -> None:
    conn, server = connected
    before = list(server.commands)
    with pytest.raises(ImapError) as raised:
        call(conn)
    assert raised.value.code == "imap_command_refused"
    assert server.commands == before and server.violations == []
    conn.logout()


def test_imaplib_debug_output_is_silenced(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(imaplib, "Debug", 5)
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages={1: FakeMessage(mail(1))})})
    session = server.session()
    session.login("owner@example.com", "app-password-1")
    session.examine("INBOX")
    assert session.fetch([1], gmail=False)[0].uid == 1
    session.logout()
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert not getattr(session._conn, "_cmd_log", {})  # imaplib's in-memory protocol log stays empty


def test_login_failure_and_unreachable_are_codes() -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1)})
    session = server.session()
    with pytest.raises(ImapError) as raised:
        session.login("owner@example.com", "wrong")
    assert raised.value.code == "imap_auth_failed"
    session.logout()
    with pytest.raises(ImapError) as raised:
        imap.connect("not a host", 993)
    assert raised.value.code == "imap_unreachable"


# --- login failure hints (response code only, never the server's text) ------------------------------

#: Server text after the response code: a support URL and the account name, as Gmail's alerts carry.
ALERT_CANARY = "ALERTCANARY-owner@example.com-https://support.example.com/answer/185833"


@pytest.mark.parametrize(
    ("reply", "hint"),
    [
        ("NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)", "authentication_failed"),
        (f"NO [ALERT] Application-specific password required: {ALERT_CANARY} (Failure)", "server_alert"),
        ("NO [AUTHORIZATIONFAILED] not for this account", None),  # a code without a hint
        ("NO [CONTACTADMIN]", None),
        ("NO Invalid credentials", None),  # no bracketed code at all
        ("NO [alert] lower case is not a response code", None),
        ("NO see [ALERT] later in the text", None),  # the code must open the text
        ("BAD [ALERT] a syntax error", None),  # imaplib reports BAD as its own text
    ],
)
def test_login_failure_hint_comes_from_the_response_code_only(reply: str, hint: str | None) -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1)}, login_failure=reply)
    session = server.session()
    with pytest.raises(ImapError) as raised:
        session.login("owner@example.com", "wrong")
    session.logout()
    assert (raised.value.code, raised.value.hint) == ("imap_auth_failed", hint)
    assert raised.value.args == ("imap_auth_failed",)


def test_the_server_text_after_the_code_is_never_kept(caplog: pytest.LogCaptureFixture) -> None:
    import logging
    import traceback

    caplog.set_level(logging.DEBUG)
    server = FakeImapServer({"INBOX": FakeMailbox(1)}, login_failure=f"NO [ALERT] {ALERT_CANARY} (Failure)")
    session = server.session()
    with pytest.raises(ImapError) as raised:
        session.login("owner@example.com", "wrong")
    error = raised.value
    assert (error.code, error.hint) == ("imap_auth_failed", "server_alert")
    assert error.__cause__ is None and error.__context__ is None  # the imaplib error (with the text) is dropped
    rendered = [str(error), repr(error), repr(error.args), repr(vars(error)), caplog.text]
    rendered.append("".join(traceback.format_exception(error)))
    assert [text for text in rendered if "ALERTCANARY" in text] == []
    assert getattr(session._conn, "mo", None) is None  # imaplib's last regex match held the response line
    session.logout()


def test_logindisabled_is_auth_failed_with_its_hint_and_never_sends_login() -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(1)}, capabilities=("LOGINDISABLED",))
    session = server.session()
    with pytest.raises(ImapError) as raised:
        session.login("owner@example.com", "app-password-1")
    session.logout()
    assert (raised.value.code, raised.value.hint) == ("imap_auth_failed", "login_disabled")
    assert "LOGIN" not in server.verbs


def test_hints_are_a_closed_set() -> None:
    expected = {"authentication_failed", "server_alert", "login_disabled", "gmail_app_password_length"}
    assert expected == imap.IMAP_HINTS
    assert ImapError("imap_auth_failed", hint="anything else").hint is None
    assert ImapError("imap_unreachable").hint is None
    assert ImapStopped("time_budget").hint is None
    error = ImapError("imap_auth_failed", hint="gmail_app_password_length")
    assert (str(error), error.args) == ("imap_auth_failed", ("imap_auth_failed",))
    assert error.hint == "gmail_app_password_length"


@pytest.mark.parametrize(
    ("args", "hint"),
    [
        ((b"[AUTHENTICATIONFAILED] x",), "authentication_failed"),
        (("[ALERT] text",), "server_alert"),
        ((b"[ALERT]",), "server_alert"),
        ((b"\xff[ALERT] x",), None),
        ((b"[" + b"A" * 32 + b"] x",), None),  # longer than any response code
        ((), None),
        ((42,), None),
    ],
)
def test_the_response_code_is_read_from_the_raw_reply(args: tuple[object, ...], hint: str | None) -> None:
    assert imap._login_hint(imaplib.IMAP4.error(*args)) == hint


# --- framing, authentication, port ----------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.xatom("NOOP", "\r\nZ1 STORE 1 +FLAGS (\\Seen)"),  # a second command framed into an argument
        lambda c: c.xatom("NOOP", "x"),  # NOOP, CAPABILITY and LOGOUT take no argument
        lambda c: c.list('""', '"*"\r\nZ2 STORE 1 +FLAGS (\\Seen)'),
        lambda c: c.list('"[Gmail]"', '"*"'),  # LIST is fixed to "" "*"
        lambda c: c.select('"INBOX"\r\nZ3 EXPUNGE', readonly=True),
        lambda c: c.select("INBOX", readonly=True),  # EXAMINE takes one quoted name only
        lambda c: c.uid("SEARCH", "UID", "1:*\r\nZ4 STORE 1 +FLAGS (\\Seen)"),
        lambda c: c.uid("SEARCH", "UID", "1:*", "SINCE", "1-Oct-2026\x00"),
        lambda c: c.uid("FETCH", "1", "(UID)\nZ5 EXPUNGE"),
        lambda c: c.authenticate("PLAIN", lambda _challenge: b"\0user\0pass"),  # LOGIN is the only mechanism
    ],
)
def test_framing_injection_and_unlisted_arguments_never_leave_the_process(call: Any, connected: Any) -> None:
    conn, server = connected
    before = list(server.commands)
    with pytest.raises(ImapError) as raised:
        call(conn)
    assert raised.value.code == "imap_command_refused"
    assert server.commands == before and server.violations == []
    conn.logout()


def test_list_names_that_could_frame_a_command_are_dropped() -> None:
    entries = list_entries(
        [
            (b'(\\HasNoChildren) "/" {14}', b"INBOX\r\nZ1 NOOP"),
            b"",
            (b'(\\HasNoChildren \\Sent) "/" {5}', b"Se\x00nt"),
            b"",
            b'(\\HasNoChildren) "/" "Archive"',
        ]
    )
    assert [entry.name for entry in entries] == ["Archive"]
    with pytest.raises(ImapProtocolError):
        quote_mailbox("Tab\tName")


def test_connect_refuses_every_port_but_993() -> None:
    for port in (143, 465, 0, 994):
        with pytest.raises(ImapError) as raised:
            imap.connect("imap.example.com", port)
        assert raised.value.code == "imap_unreachable"


def _downgrading_proxy(listener: socket.socket, seen: list[bytes]) -> None:
    conn, _ = listener.accept()
    with conn:
        seen.append(conn.recv(16))
        conn.sendall(b"\x05\x00")  # "no authentication": the isolation credentials would be dropped
        conn.settimeout(2.0)
        with contextlib.suppress(OSError):
            seen.append(conn.recv(300))


def test_a_proxy_that_drops_the_configured_authentication_is_refused() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen: list[bytes] = []
    thread = threading.Thread(target=_downgrading_proxy, args=(listener, seen), daemon=True)
    thread.start()
    route = EgressRoute(f"socks5://iso:token@127.0.0.1:{port}", None)
    try:
        with _armed() as link, pytest.raises(ImapError) as raised:
            imap.open_route_socket("imap.example.com", 993, link, route_resolver=lambda _h: route)
    finally:
        thread.join(5)
        listener.close()
    assert raised.value.code == "egress_unsupported"
    assert seen[0] == b"\x05\x01\x02"
    assert all(b"imap.example.com" not in item for item in seen)  # no CONNECT was ever sent


# --- literal limits, deadlines and cancellation -----------------------------------------------------

MiB = 1024 * 1024


def _logged_in(server: FakeImapServer, limits: IoLimits | None = None) -> ImapSession:
    session = server.session(limits)
    session.login("owner@example.com", "app-password-1")
    session.examine("INBOX")
    return session


def _guard_threads() -> list[str]:
    return [thread.name for thread in threading.enumerate() if thread.name == "mordred-imap-watchdog"]


def test_an_announced_literal_over_the_budget_is_refused_before_any_read(monkeypatch: pytest.MonkeyPatch) -> None:
    # RFC822.SIZE says 1 byte, the FETCH announces a 256 MiB literal (and would never send it).
    lie = FakeMessage(b"x", size=1, literal=256 * MiB)
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages={1: lie})})
    session = _logged_in(server)
    reads: list[int] = []
    real_read = imaplib.IMAP4.read

    def spy(self: Any, size: int) -> bytes:
        reads.append(size)
        return real_read(self, size)

    monkeypatch.setattr(imaplib.IMAP4, "read", spy)
    assert session.sizes([1]) == {1: 1}
    tracemalloc.start()
    started = time.monotonic()
    try:
        with pytest.raises(ImapError) as raised:
            session.fetch([1], gmail=False)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raised.value.code == "imap_protocol"
    assert reads == [] and peak < 4 * MiB and time.monotonic() - started < 2.0
    commands = len(server.commands)
    session.logout()
    assert len(server.commands) == commands  # the stream is mid-literal: shut down, no LOGOUT on it
    assert _guard_threads() == []


def test_a_literal_over_25_mib_that_fits_is_drained_unread() -> None:
    messages = {
        1: FakeMessage(mail(1)),
        2: FakeMessage(b"y" * (30 * MiB), size=1),  # under-reported: the literal is 30 MiB
        3: FakeMessage(mail(3)),
    }
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages=messages)})
    session = _logged_in(server)
    fetched = {item.uid: item for item in session.fetch([1, 2, 3], gmail=False)}
    assert fetched[2].oversize and fetched[2].data == b""
    assert not fetched[1].oversize and fetched[3].data == mail(3)
    session.logout()
    assert server.verbs[-1] == "LOGOUT"  # the stream stayed in step: a polite goodbye


def test_literals_beyond_64_mib_per_response_abort_the_connection() -> None:
    messages = {uid: FakeMessage(b"z" * (20 * MiB), size=1) for uid in range(1, 5)}  # 80 MiB, announced 4 bytes
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages=messages)})
    session = _logged_in(server)
    with pytest.raises(ImapError) as raised:
        session.fetch([1, 2, 3, 4], gmail=False)
    assert raised.value.code == "imap_protocol"
    session.logout()


def test_a_trickling_server_cannot_outlast_the_hard_deadline() -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages={1: FakeMessage(mail(1))})})
    server.trickle_s = 0.01  # one byte every 10 ms: no socket timeout ever fires
    session = _logged_in(server, IoLimits.for_budget(0.5))
    started = time.monotonic()
    with pytest.raises(ImapStopped) as raised:
        session.fetch([1], gmail=False)
    elapsed = time.monotonic() - started
    assert raised.value.reason == "time_budget" and elapsed < 3.0
    assert server.trickled > 5  # the server really kept sending
    session.logout()
    assert server.closed.wait(5) and _guard_threads() == []


def test_a_cancellation_shuts_the_socket_at_once() -> None:
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages={1: FakeMessage(mail(1))})})
    server.trickle_s = 0.01
    cancel = CancelToken()
    session = _logged_in(server, IoLimits.for_budget(60.0, cancel=cancel))
    timer = threading.Timer(0.3, cancel.cancel)
    timer.start()
    started = time.monotonic()
    with pytest.raises(ImapStopped) as raised:
        session.fetch([1], gmail=False)
    timer.join()
    assert raised.value.reason == "cancelled" and time.monotonic() - started < 3.0
    session.logout()
    assert server.closed.wait(5) and _guard_threads() == []


def test_the_soft_deadline_stops_before_the_next_command_and_logout_stays_polite() -> None:
    now = [0.0]
    server = FakeImapServer({"INBOX": FakeMailbox(uidvalidity=3, messages={1: FakeMessage(mail(1))})})
    session = _logged_in(server, IoLimits.for_budget(60.0, clock=lambda: now[0]))
    now[0] = 61.0
    before = list(server.commands)
    with pytest.raises(ImapStopped) as raised:
        session.search("UID", "1:*")
    assert raised.value.reason == "time_budget" and server.commands == before  # nothing was sent
    session.logout()
    assert server.verbs[-1] == "LOGOUT"


# --- the deadline and cancellation cover connection establishment ------------------------------------
#
# Each stage stalls for ever: a route lookup or a resolver that never returns, a TCP connect that never
# completes, a SOCKS5 proxy that never answers the method selection, a TLS peer that never answers the
# ClientHello.
# With a 0.2 s budget (hard deadline 0.4 s) the attempt is imap_unreachable well within a second; a
# cancellation is ImapStopped("cancelled") at once. No watchdog and no non-daemon thread survives.

_STAGES = ("route", "dns", "tcp", "socks", "tls")


class _NeverReady:
    """A selector whose socket never becomes writable: a TCP connect that never completes."""

    def __enter__(self) -> _NeverReady:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def register(self, *_args: object, **_kwargs: object) -> None:
        return None

    def select(self, timeout: float | None = None) -> list[Any]:
        time.sleep(timeout or 0.0)
        return []


def _silent_peer(listener: socket.socket, release: threading.Event) -> None:
    """Accept every connection, read what arrives and never answer (until the test releases it)."""
    listener.settimeout(0.05)
    held: list[socket.socket] = []
    while not release.is_set():
        try:
            conn, _ = listener.accept()
        except OSError:
            continue
        conn.settimeout(0.05)
        held.append(conn)
        with contextlib.suppress(OSError):
            conn.recv(1024)  # the SOCKS greeting or the ClientHello: read, never answered
    for conn in held:
        conn.close()


@contextlib.contextmanager
def _stalled(stage: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Route resolver for ``imap.connect`` with ``stage`` stalled; everything is released afterwards."""
    release = threading.Event()
    listener, address = _listener()
    peer = threading.Thread(target=_silent_peer, args=(listener, release), daemon=True)
    peer.start()
    route = EgressRoute(None, None)

    def resolver(_host: str) -> EgressRoute:
        if stage == "route":
            release.wait(30)  # the network policy never answers
        return route

    if stage == "dns":

        def never(_host: str, _port: int) -> list[Any]:
            release.wait(30)
            return []

        monkeypatch.setattr(imap, "_getaddrinfo", never)
    elif stage == "socks":
        route = EgressRoute(f"socks5://127.0.0.1:{address[1]}", None)
    else:
        monkeypatch.setattr(imap, "_getaddrinfo", _resolving_to(address))
        if stage == "tcp":
            monkeypatch.setattr(imap, "_new_selector", _NeverReady)
    try:
        yield resolver
    finally:
        release.set()
        peer.join(5)
        listener.close()


def _non_daemon_threads() -> set[threading.Thread]:
    return {thread for thread in threading.enumerate() if not thread.daemon}


@pytest.mark.parametrize("stage", _STAGES)
def test_a_stalled_connection_stage_ends_at_the_deadline(stage: str, monkeypatch: pytest.MonkeyPatch) -> None:
    before = _non_daemon_threads()
    with _stalled(stage, monkeypatch) as route:
        started = time.monotonic()
        with pytest.raises(ImapError) as raised:
            imap.connect("imap.example.com", 993, limits=IoLimits.for_budget(0.2), route_resolver=route)
        elapsed = time.monotonic() - started
    assert not isinstance(raised.value, ImapStopped) and raised.value.code == "imap_unreachable"
    assert elapsed < 1.0
    assert _guard_threads() == [] and _non_daemon_threads() == before
    helpers = (imap.RESOLVER_NAME, imap.ROUTE_RESOLVER_NAME)
    assert all(t.daemon for t in threading.enumerate() if t.name in helpers)  # abandoned, never joined


@pytest.mark.parametrize("stage", _STAGES)
def test_a_cancellation_ends_a_stalled_connection_stage_at_once(stage: str, monkeypatch: pytest.MonkeyPatch) -> None:
    before = _non_daemon_threads()
    cancel = CancelToken()
    with _stalled(stage, monkeypatch) as route:
        timer = threading.Timer(0.15, cancel.cancel)
        timer.start()
        started = time.monotonic()
        with pytest.raises(ImapStopped) as raised:
            imap.connect("imap.example.com", 993, limits=IoLimits.for_budget(60.0, cancel=cancel), route_resolver=route)
        elapsed = time.monotonic() - started
        timer.join()
    assert raised.value.reason == "cancelled" and elapsed < 1.0
    assert _guard_threads() == [] and _non_daemon_threads() == before


def test_a_connection_cancelled_before_it_starts_never_touches_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups: list[tuple[str, int]] = []
    routes: list[str] = []
    monkeypatch.setattr(imap, "_getaddrinfo", _resolving_to(("127.0.0.1", 9), lookups))
    cancel = CancelToken()
    cancel.cancel()

    def route(host: str) -> EgressRoute:
        routes.append(host)
        return EgressRoute(None, None)

    with pytest.raises(ImapStopped) as raised:
        imap.connect("imap.example.com", 993, limits=IoLimits.for_budget(60.0, cancel=cancel), route_resolver=route)
    assert raised.value.reason == "cancelled" and lookups == [] and routes == [] and _guard_threads() == []


def test_a_route_lookup_failure_inside_the_helper_is_routing_unavailable() -> None:
    def refuse(_host: str) -> EgressRoute:
        raise EgressError()

    with pytest.raises(ImapError) as raised:
        imap.connect("imap.example.com", 993, limits=IoLimits.for_budget(5.0), route_resolver=refuse)
    assert raised.value.code == "routing_unavailable" and _guard_threads() == []


def test_a_stalled_first_address_leaves_the_budget_to_the_next_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each address gets min(op_timeout, remaining): the second address answers well within the budget."""
    listener, address = _listener()
    entry = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)
    monkeypatch.setattr(imap, "_getaddrinfo", lambda _host, _port: [entry, entry])
    selectors_made: list[str] = []

    def first_stalls() -> Any:
        selectors_made.append("stalled" if not selectors_made else "real")
        return _NeverReady() if selectors_made[-1] == "stalled" else imap.selectors.DefaultSelector()

    monkeypatch.setattr(imap, "_new_selector", first_stalls)
    limits = IoLimits.for_budget(5.0)
    limits.op_timeout = 0.3
    link = Link(limits)
    link.arm()
    try:
        started = time.monotonic()
        sock = link.connect_tcp("imap.example.com", 993)
        elapsed = time.monotonic() - started
        accepted = [listener.accept()[0] for _ in range(2)]  # the stalled attempt reached the backlog too
        sock.sendall(b"ping")
        assert b"ping" in b"".join(_drain(conn) for conn in accepted)
        for conn in accepted:
            conn.close()
    finally:
        link.release()
        link.drop()
        listener.close()
    assert selectors_made == ["stalled", "real"]
    assert 0.25 <= elapsed < 2.0  # the first attempt gave up at op_timeout, not at the 5 s budget


def _drain(conn: socket.socket) -> bytes:
    conn.settimeout(0.5)
    try:
        return conn.recv(16)
    except OSError:
        return b""
