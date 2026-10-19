"""A real loopback HTTP peer for Telegram transport tests, with no model dependency."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from typing import Any


class _NumericLoopbackServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        # HTTPServer's hostname lookup can block on host DNS even for numeric loopback.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class LocalLlmServer:
    def __init__(
        self,
        *,
        status: int = 200,
        api_key: str | None = None,
        delay: float = 0,
        response: bytes | Callable[[dict[str, Any]], bytes] | None = None,
        truncate: bool = False,
        chunked: bool = False,
    ) -> None:
        self.requests: list[dict[str, Any]] = []
        self.release = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append(
                    {"path": self.path, "authorization": self.headers.get("Authorization"), "body": json.loads(body)}
                )
                if delay:
                    owner.release.wait(delay)
                actual_status = status
                if api_key is not None and self.headers.get("Authorization") != f"Bearer {api_key}":
                    actual_status = 401
                payload = response(json.loads(body)) if callable(response) else response
                if payload is None:
                    payload = (
                        b'data: {"choices":[{"delta":{"content":"The budget moved."}}]}\n\ndata: [DONE]\n\n'
                        if actual_status == 200
                        else b"SERVER-SECRET: message contents and credentials"
                    )
                self.send_response(actual_status)
                self.send_header("Content-Type", "text/event-stream")
                if chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(payload) + (100 if truncate else 0)))
                if 300 <= actual_status < 400:
                    self.send_header("Location", "/redirect-target")
                self.end_headers()
                try:
                    self.wfile.write(payload)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = _NumericLoopbackServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.endpoint = self.origin + "/v1"

    def __enter__(self) -> LocalLlmServer:
        self.thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
