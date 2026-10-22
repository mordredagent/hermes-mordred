"""A scripted IMAP4rev1 server for offline tests of the mail collector.

The real :mod:`imaplib` client (through :class:`~mordred_hermes.imports.mail.imap.GuardedIMAP4`)
talks to this server over a ``socket.socketpair()``, so the protocol parsing in
the collector is exercised for real. Every command line is recorded; any
command that would change server state (``SELECT``, ``STORE``, ``COPY``,
``EXPUNGE``, ``APPEND``, ...) or a body fetch without ``.PEEK`` is recorded as a
violation and answered ``BAD``. Fixture text uses RFC 2606 domains only.

Adversarial knobs: ``FakeMessage.literal`` announces a literal size other than
the bytes sent (a lie the client must catch before reading), ``trickle_s``
answers a body fetch with a huge literal and then one byte per interval for
ever (a server that never lets a read time out), and ``raw_labels`` sends the
``X-GM-LABELS`` list verbatim.
"""

from __future__ import annotations

import datetime as dt
import re
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from mordred_hermes.imports.mail._imap_codec import encode_mutf7
from mordred_hermes.imports.mail.imap import GuardedIMAP4, ImapSession, IoLimits

_FORBIDDEN = {"SELECT", "STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "CREATE", "DELETE", "RENAME", "CLOSE", "XLIST"}
_ALLOWED = {"CAPABILITY", "LOGIN", "LIST", "EXAMINE", "UID", "NOOP", "LOGOUT"}
_MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTHS = {name: n for n, name in enumerate(_MONTH_NAMES, 1)}


@dataclass
class FakeMessage:
    data: bytes
    labels: tuple[str, ...] = ()
    thread_id: int | None = None
    msg_id: int | None = None
    size: int | None = None  # reported RFC822.SIZE (defaults to len(data))
    date: dt.date = dt.date(2026, 10, 1)
    literal: int | None = None  # announced BODY[] literal size (defaults to len(data))
    raw_labels: bytes | None = None  # the X-GM-LABELS list as sent, verbatim


@dataclass
class FakeMailbox:
    uidvalidity: int
    messages: dict[int, FakeMessage] = field(default_factory=dict)
    attributes: tuple[str, ...] = ()
    uidnext: int | None = None

    def next_uid(self) -> int:
        if self.uidnext is not None:
            return self.uidnext
        return max(self.messages, default=0) + 1


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == " ":
            i += 1
        elif char == '"':
            j, value = i + 1, []
            while text[j] != '"':
                if text[j] == "\\":
                    j += 1
                value.append(text[j])
                j += 1
            out.append("".join(value))
            i = j + 1
        elif char == "(":
            depth, j = 0, i
            while True:
                depth += text[j] == "("
                depth -= text[j] == ")"
                j += 1
                if depth == 0:
                    break
            out.append(text[i:j])
            i = j
        else:
            j = text.find(" ", i)
            j = len(text) if j == -1 else j
            out.append(text[i:j])
            i = j
    return out


def _date(text: str) -> dt.date:
    day, month, year = text.split("-")
    return dt.date(int(year), _MONTHS[month], int(day))


def _uid_set(spec: str, highest: int) -> set[int]:
    found: set[int] = set()
    for part in spec.split(","):
        bounds = [highest if value == "*" else int(value) for value in part.split(":")]
        low, high = min(bounds), max(bounds)
        found.update(range(low, high + 1))
    return found


def _label_atom(label: str) -> bytes:
    if label.startswith("\\"):
        return label.encode("ascii")
    encoded = encode_mutf7(label)
    return b'"' + encoded.replace("\\", "\\\\").replace('"', '\\"').encode("ascii") + b'"'


class FakeImapServer:
    """One mailbox store, any number of sequential connections."""

    def __init__(
        self,
        mailboxes: dict[str, FakeMailbox],
        *,
        gmail: bool = False,
        user: str = "owner@example.com",
        password: str = "app-password-1",
        send_uidnext: bool = True,
        uid_after_body: bool = False,
        unsolicited_flags: bool = False,
    ) -> None:
        self.mailboxes = mailboxes
        self.gmail = gmail
        self.user = user
        self.password = password
        self.send_uidnext = send_uidnext
        self.uid_after_body = uid_after_body
        self.unsolicited_flags = unsolicited_flags
        self.commands: list[str] = []
        self.violations: list[str] = []
        self.on_body_fetch: Callable[[list[int]], None] | None = None
        self.fail_body_fetch_after: int | None = None
        self.trickle_s: float | None = None
        self.trickled = 0
        self.closed = threading.Event()
        self._body_fetches = 0
        self._selected: FakeMailbox | None = None
        self._threads: list[threading.Thread] = []

    # -- client side ------------------------------------------------------------------------

    def connect(self, _link: object = None) -> socket.socket:
        """A connected client socket (the ``raw_socket`` of the guarded client; its link is unused)."""
        client, server = socket.socketpair()
        thread = threading.Thread(target=self._serve, args=(server,), daemon=True)
        thread.start()
        self._threads.append(thread)
        return client

    def session(self, limits: IoLimits | None = None) -> ImapSession:
        conn = GuardedIMAP4("imap.example.com", 993, raw_socket=self.connect, timeout=5.0, limits=limits)
        return ImapSession(conn)

    def join(self, timeout: float = 5.0) -> None:
        for thread in self._threads:
            thread.join(timeout)

    @property
    def verbs(self) -> list[str]:
        """``UID FETCH``, ``EXAMINE``, ... for every recorded command."""
        out = []
        for line in self.commands:
            parts = line.split(" ")
            verb = parts[1].upper() if len(parts) > 1 else ""
            out.append(f"UID {parts[2].upper()}" if verb == "UID" and len(parts) > 2 else verb)
        return out

    def body_fetch_sets(self) -> list[str]:
        return [
            line.split(" ")[3] for line in self.commands if " UID FETCH " in line.upper() and "BODY" in line.upper()
        ]

    # -- server side ------------------------------------------------------------------------

    def _serve(self, sock: socket.socket) -> None:
        stream = sock.makefile("rb")
        try:
            caps = b"IMAP4rev1 AUTH=PLAIN" + (b" X-GM-EXT-1" if self.gmail else b"")
            sock.sendall(b"* OK [CAPABILITY " + caps + b"] fake ready\r\n")
            while True:
                line = stream.readline()
                if not line:
                    return
                text = line.decode("ascii").rstrip("\r\n")
                if not self._handle(sock, text, caps):
                    return
        except OSError:
            return
        finally:
            stream.close()
            sock.close()
            self.closed.set()

    def _record(self, text: str) -> None:
        parts = text.split(" ")
        if len(parts) >= 4 and parts[1].upper() == "LOGIN":
            text = " ".join([*parts[:3], "<password>"])
        self.commands.append(text)

    def _handle(self, sock: socket.socket, text: str, caps: bytes) -> bool:
        self._record(text)
        tag, _, rest = text.partition(" ")
        verb, _, args = rest.partition(" ")
        verb = verb.upper()
        reply = sock.sendall
        if verb in _FORBIDDEN or verb not in _ALLOWED:
            self.violations.append(verb)
            reply(f"{tag} BAD forbidden\r\n".encode())
            return True
        if verb == "CAPABILITY":
            reply(b"* CAPABILITY " + caps + b"\r\n" + f"{tag} OK done\r\n".encode())
        elif verb == "LOGIN":
            user, password = _tokens(args)
            ok = (user, password) == (self.user, self.password)
            reply(f"{tag} {'OK LOGIN completed' if ok else 'NO [AUTHENTICATIONFAILED] bad'}\r\n".encode())
        elif verb == "LIST":
            for name, box in self.mailboxes.items():
                attrs = " ".join(("\\HasNoChildren", *box.attributes))
                reply(f'* LIST ({attrs}) "/" "{name}"\r\n'.encode())
            reply(f"{tag} OK LIST done\r\n".encode())
        elif verb == "EXAMINE":
            self._examine(reply, tag, _tokens(args)[0])
        elif verb == "UID":
            self._uid(reply, tag, args)
        elif verb == "NOOP":
            reply(f"{tag} OK\r\n".encode())
        elif verb == "LOGOUT":
            reply(b"* BYE bye\r\n" + f"{tag} OK LOGOUT\r\n".encode())
            return False
        return True

    def _examine(self, reply: Callable[[bytes], None], tag: str, name: str) -> None:
        box = self.mailboxes.get(name)
        if box is None:
            reply(f"{tag} NO no such mailbox\r\n".encode())
            return
        self._selected = box
        lines = [f"* {len(box.messages)} EXISTS", "* 0 RECENT", f"* OK [UIDVALIDITY {box.uidvalidity}] ok"]
        if self.send_uidnext:
            lines.append(f"* OK [UIDNEXT {box.next_uid()}] ok")
        lines.append(f"{tag} OK [READ-ONLY] EXAMINE completed")
        reply(("\r\n".join(lines) + "\r\n").encode())

    def _uid(self, reply: Callable[[bytes], None], tag: str, args: str) -> None:
        box = self._selected
        sub, _, rest = args.partition(" ")
        if box is None:
            reply(f"{tag} BAD no mailbox\r\n".encode())
            return
        highest = max(box.messages, default=0)
        if sub.upper() == "SEARCH":
            parts = rest.split(" ")
            uids = _uid_set(parts[parts.index("UID") + 1], highest) if "UID" in parts else set(box.messages)
            uids &= set(box.messages)
            if "SINCE" in parts:
                since = _date(parts[parts.index("SINCE") + 1])
                uids = {uid for uid in uids if box.messages[uid].date >= since}
            if "BEFORE" in parts:
                before = _date(parts[parts.index("BEFORE") + 1])
                uids = {uid for uid in uids if box.messages[uid].date < before}
            reply(("* SEARCH " + " ".join(str(uid) for uid in sorted(uids))).rstrip().encode() + b"\r\n")
            reply(f"{tag} OK SEARCH done\r\n".encode())
            return
        if sub.upper() != "FETCH":
            self.violations.append(f"UID {sub}")
            reply(f"{tag} BAD\r\n".encode())
            return
        spec, _, items = rest.partition(" ")
        upper = items.upper()
        if re.search(r"BODY\[", upper) and "BODY.PEEK[" not in upper:
            self.violations.append("BODY[]")
            reply(f"{tag} BAD\r\n".encode())
            return
        wanted = sorted(_uid_set(spec, highest) & set(box.messages))
        if "BODY.PEEK[]" in upper:
            self._body_fetches += 1
            if self.on_body_fetch is not None:
                self.on_body_fetch(wanted)
            if self.fail_body_fetch_after is not None and self._body_fetches > self.fail_body_fetch_after:
                reply(b"* 1 FETCH (UID 1 BODY[] {99999}\r\nshort")  # a truncated literal, then hang up
                raise OSError("hang up")
            if self.trickle_s is not None:
                self._trickle(reply)
        order = sorted(box.messages)
        for uid in wanted:
            reply(self._fetch_line(order.index(uid) + 1, uid, box.messages[uid], upper))
            if self.unsolicited_flags:
                reply(b"* 1 FETCH (FLAGS (\\Seen))\r\n")
        reply(f"{tag} OK FETCH done\r\n".encode())

    def _trickle(self, reply: Callable[[bytes], None]) -> None:
        """A 1 MiB literal, one byte per interval, until the client hangs up (never a quiet socket)."""
        reply(b"* 1 FETCH (UID 1 BODY[] {1048576}\r\n")
        while True:
            reply(b"x")
            self.trickled += 1
            time.sleep(self.trickle_s or 0.01)

    def _fetch_line(self, seq: int, uid: int, msg: FakeMessage, items: str) -> bytes:
        head: list[bytes] = []
        if self.gmail and "X-GM-THRID" in items and msg.thread_id is not None:
            head.append(b"X-GM-THRID %d" % msg.thread_id)
        if self.gmail and "X-GM-MSGID" in items:
            head.append(b"X-GM-MSGID %d" % (msg.msg_id or uid))
        if self.gmail and "X-GM-LABELS" in items:
            labels = msg.raw_labels if msg.raw_labels is not None else b" ".join(_label_atom(x) for x in msg.labels)
            head.append(b"X-GM-LABELS (" + labels + b")")
        uid_item = b"UID %d" % uid
        if "RFC822.SIZE" in items:
            head.append(b"RFC822.SIZE %d" % (msg.size if msg.size is not None else len(msg.data)))
        if "BODY.PEEK[]" not in items:
            return b"* %d FETCH (" % seq + b" ".join([uid_item, *head]) + b")\r\n"
        announced = msg.literal if msg.literal is not None else len(msg.data)
        body = b"BODY[] {%d}\r\n" % announced + msg.data
        if self.uid_after_body:
            return b"* %d FETCH (" % seq + b" ".join(head) + b" " + body + b" " + uid_item + b")\r\n"
        return b"* %d FETCH (" % seq + b" ".join([uid_item, *head]) + b" " + body + b")\r\n"


def mail(
    n: int,
    *,
    subject: str = "SUBJCANARY",
    body: str = "BODYCANARY",
    sender: str = "Taro Tanaka <taro@example.net>",
    to: str = "Owner <owner@example.com>",
    references: str | None = None,
    extra_headers: str = "",
    date: str = "Thu, 01 Oct 2026 10:00:00 +0900",
) -> bytes:
    """A small RFC 5322 message with RFC 2606 addresses."""
    refs = f"References: <{references}>\r\nIn-Reply-To: <{references}>\r\n" if references else ""
    text = (
        f"From: {sender}\r\nTo: {to}\r\nSubject: {subject} {n}\r\nDate: {date}\r\n"
        f"Message-ID: <msg{n}@example.net>\r\n{refs}{extra_headers}"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        f"{body} number {n}\r\n"
    )
    return text.encode("utf-8")
