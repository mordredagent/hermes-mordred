"""RPC field-filling and broadcast, with the JSON-RPC transport stubbed."""

from __future__ import annotations

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
