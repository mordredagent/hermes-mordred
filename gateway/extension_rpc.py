"""Minimal EVM JSON-RPC client for the Mordred extension wallet (SPEC §5.3).

Used to fill missing transaction fields (nonce / gas / fees / chainId) and to
broadcast the signed raw transaction. Honors the gateway's configured proxy
(Tor via ``mordred_network``) so RPC egress follows the same path as the rest
of Hermes — the extension itself never talks to an RPC node.

Synchronous (``requests``); callers invoke it from a thread executor.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Public fallback endpoints; users should set their own via wallet.json `rpc`.
DEFAULT_RPC: dict[int, str] = {
    1: "https://cloudflare-eth.com",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
}


class JsonRpcError(Exception):
    pass


def _proxies() -> Optional[dict[str, str]]:
    """Proxy dict for requests, honoring the gateway's resolved proxy/Tor."""
    try:
        from gateway.platforms.base import resolve_proxy_url

        url = resolve_proxy_url(target_hosts=None)
    except Exception:  # noqa: BLE001
        import os

        url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    return {"http": url, "https": url} if url else None


def call(rpc_url: str, method: str, params: list[Any], *, timeout: float = 30.0) -> Any:
    import requests

    resp = requests.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        proxies=_proxies(),
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data and data["error"]:
        raise JsonRpcError(str(data["error"]))
    return data.get("result")


def _to_int(hexstr: Any) -> int:
    if hexstr is None:
        return 0
    if isinstance(hexstr, int):
        return hexstr
    s = str(hexstr)
    return int(s, 16) if s.startswith("0x") else int(s)


# --------------------------------------------------------------------------- #
# Field filling
# --------------------------------------------------------------------------- #


def get_nonce(rpc_url: str, address: str) -> int:
    return _to_int(call(rpc_url, "eth_getTransactionCount", [address, "pending"]))


def estimate_gas(rpc_url: str, tx: dict[str, Any], from_address: str) -> int:
    call_obj = {"from": from_address}
    for k in ("to", "value", "data"):
        if tx.get(k) not in (None, ""):
            call_obj[k] = tx[k]
    gas = _to_int(call(rpc_url, "eth_estimateGas", [call_obj]))
    return gas + gas // 5  # +20% headroom


def fee_data(rpc_url: str) -> dict[str, int]:
    """Return EIP-1559 fees from the latest block + priority fee suggestion."""
    block = call(rpc_url, "eth_getBlockByNumber", ["latest", False]) or {}
    base = _to_int(block.get("baseFeePerGas"))
    try:
        tip = _to_int(call(rpc_url, "eth_maxPriorityFeePerGas", []))
    except Exception:  # noqa: BLE001 — node may not support it
        tip = 1_500_000_000  # 1.5 gwei
    if base:
        return {"maxPriorityFeePerGas": tip, "maxFeePerGas": base * 2 + tip}
    gas_price = _to_int(call(rpc_url, "eth_gasPrice", []))
    return {"gasPrice": gas_price}


def fill_transaction(
    rpc_url: str, tx: dict[str, Any], from_address: str, chain_id: int
) -> dict[str, Any]:
    """Return a copy of ``tx`` with nonce/gas/fee fields filled where missing."""
    out = dict(tx)
    if out.get("nonce") in (None, ""):
        out["nonce"] = hex(get_nonce(rpc_url, from_address))
    has_1559 = out.get("maxFeePerGas") not in (None, "")
    has_legacy = out.get("gasPrice") not in (None, "")
    if not has_1559 and not has_legacy:
        out.update({k: hex(v) for k, v in fee_data(rpc_url).items()})
    if out.get("gas") in (None, ""):
        out["gas"] = hex(estimate_gas(rpc_url, out, from_address))
    return out


def send_raw_transaction(rpc_url: str, raw_hex: str) -> str:
    """Broadcast and return the transaction hash."""
    return str(call(rpc_url, "eth_sendRawTransaction", [raw_hex]))
