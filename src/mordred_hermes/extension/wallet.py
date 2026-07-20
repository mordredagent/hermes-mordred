"""Wallet signer helpers and sign-request analysis for the Mordred Extension
API (:mod:`mordred_hermes.extension.api`).

Split out of ``api.py`` (which stayed over the repo's 800-line cap) — these
members are module-level and state-free: the keyvault wallet signer helpers
(run in an executor since Touch ID can block) and the deterministic
sign-request risk/decode analysis. ``api.py`` imports them by name so
``_Connection`` keeps calling them as bare names resolved through its own
module globals.
"""

from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------- #
# Sign helpers (run in executor — keyvault calls may block on Touch ID)
# --------------------------------------------------------------------------- #


def _get_address() -> str:
    from mordred_hermes.keyvault import extension_sign

    return extension_sign.get_address()


def _do_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
) -> str:
    from mordred_hermes.keyvault import extension_sign

    if method == "personal_sign":
        return extension_sign.personal_sign(str(params[0]))
    if method == "eth_signTypedData_v4":
        return extension_sign.sign_typed_data_v4(params[1])
    if method == "eth_sendTransaction":
        return _send_transaction(params[0] if params else {}, chain_id_hex, rpc_url)
    raise ValueError(f"unsupported_method:{method}")


def _send_transaction(tx: dict[str, Any], chain_id_hex: str | None = None, rpc_url: str | None = None) -> str:
    """Full eth_sendTransaction: fill missing fields via RPC, sign in the
    keyvault, broadcast, and return the transaction hash (SPEC §5.3).

    The active chain/RPC are taken from the extension request when present
    (custom RPC, §5.6), else from wallet.json. If no RPC is configured/reachable
    the flow falls back to returning the signed raw tx (still keyvault-signed)."""
    from mordred_hermes.keyvault import extension_sign

    from . import rpc as extension_rpc

    chain_id = int(chain_id_hex, 16) if chain_id_hex else extension_sign.chain_id_int()
    rpc_url = rpc_url or extension_sign.rpc_url_for(chain_id)

    if rpc_url:
        try:
            from_address = extension_sign.get_address()
            filled = extension_rpc.fill_transaction(rpc_url, tx, from_address, chain_id)
            raw = extension_sign.sign_transaction(filled, chain_id=chain_id)["raw"]
            return extension_rpc.send_raw_transaction(rpc_url, raw)
        except Exception as exc:
            raise RuntimeError(f"broadcast_failed: {exc}") from exc

    # No RPC configured — sign only (caller may broadcast the raw tx manually).
    out = extension_sign.sign_transaction(tx, chain_id=chain_id)
    return out["raw"]


def _wallet_chain_id_hex() -> str:
    try:
        from mordred_hermes.keyvault import extension_sign

        return hex(extension_sign.chain_id_int())
    except Exception:
        return "0x1"


# --------------------------------------------------------------------------- #
# Deterministic sign-request analysis (risk + decode). An LLM pass can replace
# this later; keeping it deterministic makes it testable and offline-safe.
# --------------------------------------------------------------------------- #

_ERC20_TRANSFER = "a9059cbb"
_ERC20_APPROVE = "095ea7b3"
_MAX_UINT = (1 << 256) - 1


def analyze_sign(method: str, params: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if method == "personal_sign":
        return ({"risk": "low", "summary": "メッセージ署名(資産移動なし)", "warnings": []}, {})
    if method == "eth_signTypedData_v4":
        return (
            {"risk": "medium", "summary": "EIP-712 typed data 署名", "warnings": ["許可(permit)の可能性に注意"]},
            {"function": "eth_signTypedData_v4"},
        )
    if method == "eth_sendTransaction":
        return _analyze_tx(params[0] if params else {})
    return ({"risk": "medium", "summary": method, "warnings": []}, {})


def _analyze_tx(tx: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    data = str(tx.get("data") or "").removeprefix("0x")
    to = tx.get("to")
    value = _hex_to_int(tx.get("value"))
    warnings: list[str] = []
    decoded: dict[str, Any] = {}
    risk = "low"

    if data[:8] == _ERC20_TRANSFER and len(data) >= 8 + 128:
        recipient = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {"function": "transfer(address,uint256)", "args": {"to": recipient, "amount": str(amount)}}
        risk = "medium"
        summary = f"ERC-20 transfer: {amount} → {recipient}"
    elif data[:8] == _ERC20_APPROVE and len(data) >= 8 + 128:
        spender = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {"function": "approve(address,uint256)", "args": {"spender": spender, "amount": str(amount)}}
        if amount >= _MAX_UINT:
            risk = "high"
            warnings.append("無制限の approve(残高全額を引き出せる権限)です")
        else:
            risk = "medium"
        summary = f"ERC-20 approve: {spender}"
    elif value > 0:
        risk = "medium" if value >= 10**18 else "low"
        summary = f"ETH 送金: {value / 10**18:g} ETH → {to}"
    elif data:
        risk = "medium"
        summary = f"コントラクト呼び出し: {to}"
    else:
        summary = f"トランザクション → {to}"

    return ({"risk": risk, "summary": summary, "warnings": warnings}, decoded)


def _hex_to_int(v: Any) -> int:
    if v is None or v == "":
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return 0
