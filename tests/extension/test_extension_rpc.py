"""RPC field-filling and broadcast, with the JSON-RPC transport stubbed."""

from __future__ import annotations

import logging
import sys
import types

import pytest

from mordred_hermes.extension import extension_rpc


@pytest.fixture
def fake_rpc(monkeypatch):
    sent = {}

    def fake_call(rpc_url, method, params, timeout=30.0):
        if method == "eth_getTransactionCount":
            return "0x5"
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": hex(10_000_000_000)}  # 10 gwei base
        if method == "eth_maxPriorityFeePerGas":
            return hex(1_000_000_000)  # 1 gwei tip
        if method == "eth_estimateGas":
            return hex(21000)
        if method == "eth_sendRawTransaction":
            sent["raw"] = params[0]
            return "0xtxhash"
        raise AssertionError(f"unexpected method {method}")

    monkeypatch.setattr(extension_rpc, "call", fake_call)
    return sent


def test_fill_transaction_1559(fake_rpc):
    tx = {"to": "0x" + "11" * 20, "value": "0x0"}
    filled = extension_rpc.fill_transaction("http://rpc", tx, "0x" + "ab" * 20, 1)
    assert filled["nonce"] == "0x5"
    assert filled["maxPriorityFeePerGas"] == hex(1_000_000_000)
    # maxFee = base*2 + tip = 21 gwei
    assert filled["maxFeePerGas"] == hex(10_000_000_000 * 2 + 1_000_000_000)
    # gas estimate +20%
    assert int(filled["gas"], 16) == 21000 + 21000 // 5


def test_fill_preserves_explicit_fields(fake_rpc):
    tx = {"to": "0x0", "nonce": "0x9", "gas": "0x5208", "gasPrice": "0x3b9aca00"}
    filled = extension_rpc.fill_transaction("http://rpc", tx, "0xabc", 1)
    assert filled["nonce"] == "0x9"
    assert filled["gas"] == "0x5208"
    assert filled["gasPrice"] == "0x3b9aca00"
    assert "maxFeePerGas" not in filled  # legacy preserved, no 1559 injected


def test_send_raw(fake_rpc):
    assert extension_rpc.send_raw_transaction("http://rpc", "0xdeadbeef") == "0xtxhash"
    assert fake_rpc["raw"] == "0xdeadbeef"


# --------------------------------------------------------------------------- #
# Proxy resolution (_proxies): gateway-routed vs env fallback
# --------------------------------------------------------------------------- #


def _rpc_warnings(caplog):
    return [r for r in caplog.records if r.name == extension_rpc.logger.name and r.levelno >= logging.WARNING]


def test_proxies_prefers_gateway_resolution_no_warning(monkeypatch, caplog):
    """The happy path resolves through the gateway and logs nothing."""
    gateway = types.ModuleType("gateway")
    platforms = types.ModuleType("gateway.platforms")
    base = types.ModuleType("gateway.platforms.base")
    base.resolve_proxy_url = lambda target_hosts=None: "socks5h://127.0.0.1:9050"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway", gateway)
    monkeypatch.setitem(sys.modules, "gateway.platforms", platforms)
    monkeypatch.setitem(sys.modules, "gateway.platforms.base", base)
    monkeypatch.setattr(extension_rpc, "_fallback_warned", False)

    with caplog.at_level(logging.WARNING):
        proxies = extension_rpc._proxies()

    assert proxies == {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    assert _rpc_warnings(caplog) == []


def test_proxies_fallback_to_env_warns_once(monkeypatch, caplog):
    """Losing the gateway resolver silently rerouted RPC egress off the
    Tor/VPN path with no log line — it must warn (once per process, so a
    multi-call broadcast doesn't spam) and still honor HTTPS_PROXY."""
    monkeypatch.setitem(sys.modules, "gateway", None)  # import raises immediately
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8118")
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.setattr(extension_rpc, "_fallback_warned", False)

    with caplog.at_level(logging.WARNING, logger=extension_rpc.logger.name):
        first = extension_rpc._proxies()
        second = extension_rpc._proxies()

    assert first == second == {"http": "http://127.0.0.1:8118", "https": "http://127.0.0.1:8118"}
    warnings = _rpc_warnings(caplog)
    assert len(warnings) == 1
    assert "fall" in warnings[0].getMessage()  # "falls back"


def test_proxies_fallback_direct_connection_warns(monkeypatch, caplog):
    """No resolver AND no env proxy = a DIRECT connection; the warning must
    say so — that is the worst-case privacy regression."""
    monkeypatch.setitem(sys.modules, "gateway", None)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.setattr(extension_rpc, "_fallback_warned", False)

    with caplog.at_level(logging.WARNING, logger=extension_rpc.logger.name):
        assert extension_rpc._proxies() is None

    warnings = _rpc_warnings(caplog)
    assert len(warnings) == 1
    assert "DIRECT" in warnings[0].getMessage()
