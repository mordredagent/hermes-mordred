"""Minimal loopback HTTP server used as a relay target by integration tests.

The SOCKS5h verification tests (TODO §0.8 L110-122) need a real HTTP
endpoint behind the :mod:`_socks5_inspector` proxy so the client-side
request completes with a genuine ``200`` response — proving the full
``client → socks5h → inspector → resolved host → server`` chain, not
just that the proxy saw a CONNECT.

Dependency-free: stdlib :mod:`http.server` on a daemon thread, bound to
``127.0.0.1`` on an ephemeral port, torn down on ``with``-block exit.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

_OK_BODY: Final = b"mordred-ok"


@dataclass(frozen=True, slots=True)
class HttpTarget:
    """Address of a running loopback HTTP server.

    ``ok_body`` is the exact bytes the server returns for any ``GET`` so
    callers can assert on a full round trip.
    """

    host: str
    port: int
    ok_body: bytes = _OK_BODY

    @property
    def url(self) -> str:
        """A ``GET``-able URL whose host component is a *hostname*.

        Uses the literal ``host`` (default ``"localhost"``) so ``socks5h``
        clients must hand the name to the proxy for server-side
        resolution — an IP literal would defeat the whole test.
        """
        return f"http://{self.host}:{self.port}/"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_OK_BODY)))
        self.end_headers()
        self.wfile.write(_OK_BODY)

    def log_message(self, *_args: object) -> None:
        """Silence the per-request stderr logging."""


class _DualStackServer(ThreadingHTTPServer):
    """HTTP server reachable on both IPv4 and IPv6 loopback.

    ``localhost`` resolves to ``127.0.0.1`` *and* ``::1`` on a typical
    box; a client (or the SOCKS relay) may connect via either. Binding
    a v4-only socket would make the v6 attempt fail with "connection
    refused" and mask the real ATYP result. An ``AF_INET6`` socket with
    ``IPV6_V6ONLY=0`` accepts v4-mapped connections too.
    """

    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        with contextlib.suppress(OSError):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


@contextmanager
def http_target(host: str = "localhost") -> Iterator[HttpTarget]:
    """Run an HTTP server on loopback for the duration of the block.

    ``host`` is the *name* callers should use when building the request
    URL (default ``"localhost"``); the socket binds dual-stack loopback
    so the request reaches it whether the client resolves the name to
    IPv4 or IPv6.
    """
    server = _DualStackServer(("::", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield HttpTarget(host=host, port=server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)
