"""Deterministic sign-request analysis (risk + ABI decode)."""

from __future__ import annotations

from gateway.extension_api import analyze_sign

_ADDR = "0x" + "ab" * 20


def _transfer_data(to_hex_no0x: str, amount: int) -> str:
    return "0xa9059cbb" + "00" * 12 + to_hex_no0x + amount.to_bytes(32, "big").hex()


def test_personal_sign_low_risk():
    analysis, decoded = analyze_sign("personal_sign", ["0xdeadbeef", _ADDR])
    assert analysis["risk"] == "low"
    assert decoded == {}


def test_erc20_transfer_decoded():
    data = _transfer_data("11" * 20, 100)
    analysis, decoded = analyze_sign("eth_sendTransaction", [{"to": _ADDR, "data": data, "value": "0x0"}])
    assert decoded["function"] == "transfer(address,uint256)"
    assert decoded["args"]["amount"] == "100"
    assert analysis["risk"] == "medium"


def test_unlimited_approve_high_risk():
    max_uint = (1 << 256) - 1
    data = "0x095ea7b3" + "00" * 12 + "22" * 20 + max_uint.to_bytes(32, "big").hex()
    analysis, decoded = analyze_sign("eth_sendTransaction", [{"to": _ADDR, "data": data}])
    assert decoded["function"] == "approve(address,uint256)"
    assert analysis["risk"] == "high"
    assert any("無制限" in w for w in analysis["warnings"])


def test_plain_eth_transfer():
    analysis, _ = analyze_sign(
        "eth_sendTransaction", [{"to": _ADDR, "value": hex(2 * 10**18)}]
    )
    assert analysis["risk"] == "medium"  # >= 1 ETH
    assert "ETH" in analysis["summary"]
