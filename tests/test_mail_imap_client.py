"""IMAP codec, egress transport, TLS settings and the read-only command allowlist."""

from __future__ import annotations

import imaplib
import socket
import ssl
import threading
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
from mordred_hermes.imports.mail.imap import GuardedIMAP4, GuardedIMAP4SSL, ImapError
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
        def wrap_socket(self, sock: socket.socket, server_hostname: str | None = None) -> socket.socket:
            wrapped.append((sock, server_hostname))
            return sock  # the fake server speaks plain IMAP

    conn = GuardedIMAP4SSL(
        "imap.example.com",
        993,
        raw_socket=server.connect,
        ssl_context=RecordingContext(),  # type: ignore[arg-type]
        timeout=5.0,
    )
    conn.logout()
    assert [name for _sock, name in wrapped] == ["imap.example.com"]


def test_direct_route_connects_to_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, float]] = []

    def fake_connect(address: Any, timeout: float) -> str:
        calls.append((address, timeout))
        return "sock"

    monkeypatch.setattr(imap.socket, "create_connection", fake_connect)
    sock = imap.open_route_socket("imap.example.com", 993, 7.0, route_resolver=lambda _h: EgressRoute(None, None))
    assert sock == "sock" and calls == [(("imap.example.com", 993), 7.0)]


@pytest.mark.parametrize(
    ("route", "code"),
    [
        (EgressRoute(None, "http://127.0.0.1:8080"), "egress_unsupported"),
        (EgressRoute("socks4://127.0.0.1:9050", None), "egress_unsupported"),
    ],
)
def test_other_proxy_kinds_are_refused(route: EgressRoute, code: str) -> None:
    with pytest.raises(ImapError) as raised:
        imap.open_route_socket("imap.example.com", 993, 5.0, route_resolver=lambda _h: route)
    assert raised.value.code == code


def test_a_routing_refusal_is_routing_unavailable() -> None:
    def refuse(_host: str) -> EgressRoute:
        raise EgressError()

    with pytest.raises(ImapError) as raised:
        imap.open_route_socket("imap.example.com", 993, 5.0, route_resolver=refuse)
    assert raised.value.code == "routing_unavailable"


def _socks_server(listener: socket.socket, seen: list[bytes], *, auth: bool) -> None:
    conn, _ = listener.accept()
    with conn:
        greeting = conn.recv(3 if not auth else 4)
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
    sock = imap.open_route_socket("imap.example.com", 993, 5.0, route_resolver=lambda _h: route)
    try:
        assert sock.recv(64) == b"* OK ready\r\n"
    finally:
        sock.close()
        thread.join(5)
        listener.close()
    name = b"imap.example.com"
    assert seen[-1] == b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (993).to_bytes(2, "big")
    if auth:
        assert seen[0] == b"\x05\x02\x00\x02"
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
