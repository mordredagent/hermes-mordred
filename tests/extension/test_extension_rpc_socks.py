"""Exercise wallet routing through the local SOCKS wire inspector.

Loopback-only and runtime-pinned, so it stays in the default suite: this is the
only test proving Requests really sends the isolation credentials and hands the
RPC hostname to the proxy.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from mordred_hermes.extension import rpc
from mordred_hermes.network import api as network_api
from tests.integration import _socks5_inspector as inspector_module
from tests.integration._http_target import http_target


def test_rpc_socks_wire_keeps_isolation_credentials_and_remote_dns(monkeypatch):
    from gateway.platforms import base

    authenticated = []

    def authenticate(client):
        recv = inspector_module._recv_exact
        version, count = recv(client, 2)
        assert version == 5
        assert 2 in recv(client, count)
        client.sendall(b"\x05\x02")
        assert recv(client, 1) == b"\x01"
        username = recv(client, recv(client, 1)[0])
        password = recv(client, recv(client, 1)[0])
        authenticated.append((username, password))
        client.sendall(b"\x01\x00")

    monkeypatch.setattr(inspector_module, "_negotiate_no_auth", authenticate)
    monkeypatch.setattr(inspector_module, "_relay_host", lambda host: "127.0.0.1")
    monkeypatch.setattr(network_api, "status", lambda: SimpleNamespace(active_path="tor", ready=True))
    monkeypatch.setattr(network_api, "is_dropped", lambda: False)
    real_getaddrinfo = socket.getaddrinfo

    def no_destination_dns(host, *args, **kwargs):
        assert host != "rpc.example.com", "RPC hostname leaked to the local resolver"
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", no_destination_dns)
    with http_target() as target, inspector_module.socks5_inspector() as inspector:
        monkeypatch.setattr(
            base, "resolve_proxy_url", lambda **kwargs: f"socks5://isolate%40user:p%3Ass@127.0.0.1:{inspector.port}"
        )
        # The local origin deliberately speaks HTTP: TLS must fail only AFTER
        # SOCKS authentication and CONNECT, without weakening RPC TLS policy.
        with pytest.raises(rpc.JsonRpcError, match="rpc_request_failed"):
            rpc.call(f"https://rpc.example.com:{target.port}", "eth_chainId", [], timeout=10)
    assert authenticated == [(b"isolate@user", b"p:ss")]
    assert len(inspector.captures) == 1
    assert inspector.last_capture.is_remote_dns
    assert inspector.last_capture.dest_host == "rpc.example.com"
    assert inspector.last_capture.dest_port == target.port
