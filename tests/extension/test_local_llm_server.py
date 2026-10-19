"""The loopback HTTP peer must not wait for reverse DNS."""

from __future__ import annotations

import json
import socket
from http.client import HTTPConnection

from tests.extension.local_llm_server import LocalLlmServer


def test_numeric_loopback_peer_serves_http_without_reverse_dns(monkeypatch):
    def refuse_dns(*args, **kwargs):
        raise AssertionError("numeric loopback must not request reverse DNS")

    monkeypatch.setattr(socket, "getfqdn", refuse_dns)
    body = {"model": "local-test", "messages": [{"role": "user", "content": "hello"}]}
    with LocalLlmServer() as peer:
        host, port = peer.server.server_address
        assert host == peer.server.server_name == "127.0.0.1"
        assert port == peer.server.server_port and port > 0
        assert peer.endpoint == f"http://127.0.0.1:{port}/v1"
        connection = HTTPConnection(host, port, timeout=2)
        try:
            connection.request("POST", "/v1/chat/completions", json.dumps(body), {"Content-Type": "application/json"})
            response = connection.getresponse()
            assert response.status == 200
            assert response.read() == (
                b'data: {"choices":[{"delta":{"content":"The budget moved."}}]}\n\ndata: [DONE]\n\n'
            )
        finally:
            connection.close()
        assert peer.requests == [{"path": "/v1/chat/completions", "authorization": None, "body": body}]
    assert not peer.thread.is_alive()
