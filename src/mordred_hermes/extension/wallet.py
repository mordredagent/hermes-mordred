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

import json
import secrets
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# Sign helpers (run in executor — keyvault calls may block on Touch ID)
# --------------------------------------------------------------------------- #

_ACCOUNT_BOUND_METHODS = frozenset({"personal_sign", "eth_signTypedData_v4"})


@dataclass(frozen=True, slots=True)
class _PreparedSign:
    """Approval-time snapshot passed from preparation to signing."""

    params: list[Any]
    chain_id: str | None
    rpc_url: str | None
    rpc_endpoint: str | None
    expected_signer: str | None


def _get_address() -> str:
    from mordred_hermes.keyvault import extension_sign

    return extension_sign.get_address()


def _get_account_snapshot() -> tuple[str, str]:
    from mordred_hermes.keyvault import extension_sign

    address, chain_id = extension_sign.account_snapshot()
    return address, hex(chain_id)


def _addresses_match(left: str, right: str) -> bool:
    """Compare Ethereum addresses without changing the canonical display form."""
    return left.casefold() == right.casefold()


def _validated_account_bound_params(
    method: str,
    params: list[Any],
) -> tuple[int, str, str | dict[str, Any]]:
    """Return ``(account_index, requested_account, payload)`` for RPC methods."""
    if method == "personal_sign":
        if len(params) != 2 or not isinstance(params[0], str) or not isinstance(params[1], str):
            raise ValueError("invalid_personal_sign_params")
        return 1, params[1], params[0]
    if method == "eth_signTypedData_v4":
        if len(params) != 2 or not isinstance(params[0], str) or not isinstance(params[1], (str, dict)):
            raise ValueError("invalid_eth_signTypedData_v4_params")
        return 0, params[0], params[1]
    raise ValueError(f"unsupported_method:{method}")


def _assert_current_signer(expected_signer: str) -> None:
    from mordred_hermes.keyvault import extension_sign

    if not _addresses_match(extension_sign.get_address(), expected_signer):
        raise RuntimeError("wallet_signer_changed")


def _recover_personal_signer(message: str, signature: str) -> str:
    from eth_account import Account
    from eth_account.messages import encode_defunct

    signable = encode_defunct(hexstr=message) if message.startswith("0x") else encode_defunct(text=message)
    return str(Account.recover_message(signable, signature=signature))


def _recover_typed_data_signer(typed_data: str | dict[str, Any], signature: str) -> str:
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    data = json.loads(typed_data) if isinstance(typed_data, str) else typed_data
    return str(Account.recover_message(encode_typed_data(full_message=data), signature=signature))


def _recover_transaction_signer(raw_transaction: str) -> str:
    from eth_account import Account

    return str(Account.recover_transaction(raw_transaction))


def _assert_recovered_signer(actual_signer: str, expected_signer: str) -> None:
    if not _addresses_match(actual_signer, expected_signer):
        raise RuntimeError("wallet_signer_changed")


def _freeze_transaction_signer(tx: dict[str, Any], expected_signer: str) -> None:
    supplied_from = tx.get("from")
    if supplied_from not in (None, "") and not _addresses_match(str(supplied_from), expected_signer):
        raise ValueError("transaction_from_mismatch")
    tx["from"] = expected_signer


def _do_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
    expected_signer: str | None = None,
) -> str:
    from mordred_hermes.keyvault import extension_sign

    if method in _ACCOUNT_BOUND_METHODS:
        if expected_signer is None:
            raise ValueError("missing_expected_signer")
        _account_index, requested_signer, payload = _validated_account_bound_params(method, params)
        if not _addresses_match(requested_signer, expected_signer):
            raise RuntimeError("signer_snapshot_mismatch")
        _assert_current_signer(expected_signer)
        if method == "personal_sign":
            if not isinstance(payload, str):
                raise ValueError("invalid_personal_sign_params")
            signature = extension_sign.personal_sign(payload)
            try:
                actual_signer = _recover_personal_signer(payload, signature)
            except Exception as exc:
                raise RuntimeError("signature_signer_verification_failed") from exc
        else:
            signature = extension_sign.sign_typed_data_v4(payload)
            try:
                actual_signer = _recover_typed_data_signer(payload, signature)
            except Exception as exc:
                raise RuntimeError("signature_signer_verification_failed") from exc
        _assert_recovered_signer(actual_signer, expected_signer)
        return signature
    if method == "eth_sendTransaction":
        if expected_signer is None:
            raise ValueError("missing_expected_signer")
        return _send_prepared_transaction(
            params[0] if params else {},
            chain_id_hex,
            rpc_url,
            expected_signer=expected_signer,
        )
    raise ValueError(f"unsupported_method:{method}")


def _resolve_chain_id(chain_id_hex: str | None) -> int:
    from mordred_hermes.keyvault import extension_sign

    try:
        chain_id = int(chain_id_hex, 16) if chain_id_hex else extension_sign.chain_id_int()
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_chain_id") from exc
    if chain_id <= 0:
        raise ValueError("invalid_chain_id")
    return chain_id


def _prepare_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
) -> _PreparedSign:
    """Freeze all signer- and transaction-affecting fields before approval.

    Account-bound message methods validate their standard parameter order and
    canonicalize the requested account to the exact keyvault address.
    ``eth_sendTransaction`` additionally freezes nonce, gas, fees, chain and RPC
    URL. The signer is retained separately for an approval-time recheck.
    """
    if method in _ACCOUNT_BOUND_METHODS:
        return _prepare_account_bound_sign(method, params, chain_id_hex, rpc_url)
    if method == "eth_sendTransaction":
        return _prepare_transaction_sign(params, chain_id_hex, rpc_url)
    return _PreparedSign(params, chain_id_hex, rpc_url, None, None)


def _prepare_account_bound_sign(
    method: str,
    params: list[Any],
    chain_id_hex: str | None,
    rpc_url: str | None,
) -> _PreparedSign:
    account_index, requested_signer, _payload = _validated_account_bound_params(method, params)

    from mordred_hermes.keyvault import extension_sign

    expected_signer = extension_sign.get_address()
    if not _addresses_match(requested_signer, expected_signer):
        raise ValueError(f"{method}_account_mismatch")
    frozen_params = list(params)
    frozen_params[account_index] = expected_signer
    return _PreparedSign(frozen_params, chain_id_hex, rpc_url, None, expected_signer)


def _prepare_transaction_sign(
    params: list[Any],
    chain_id_hex: str | None,
    rpc_url: str | None,
) -> _PreparedSign:
    if not params or not isinstance(params[0], dict):
        raise ValueError("invalid_transaction_params")

    from mordred_hermes.keyvault import extension_sign

    from . import rpc as extension_rpc

    configured_chain_id = extension_sign.chain_id_int()
    chain_id = _resolve_chain_id(chain_id_hex)
    if chain_id != configured_chain_id:
        raise ValueError("transaction_chain_id_not_allowed")
    tx = dict(params[0])
    supplied_chain = tx.get("chainId")
    if supplied_chain not in (None, ""):
        supplied_chain_text = str(supplied_chain)
        try:
            supplied_chain_id = (
                int(supplied_chain_text, 16) if supplied_chain_text.startswith("0x") else int(supplied_chain_text)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_transaction_chain_id") from exc
        if supplied_chain_id != chain_id:
            raise ValueError("transaction_chain_id_mismatch")

    # Reject unsupported transaction types/fields and conflicting fee models
    # before a malformed request can trigger any configured-RPC traffic.
    preflight_tx = dict(tx)
    # ``from`` is compared case-insensitively with the keyvault address and
    # replaced by that canonical address below; validate the frozen value, not
    # a harmless alternate spelling supplied by the extension.
    preflight_tx.pop("from", None)
    extension_sign.validate_transaction_request(preflight_tx, chain_id=chain_id)
    configured_rpc = extension_sign.rpc_url_for(chain_id)
    if rpc_url:
        # A paired extension may report the dapp's selected RPC, but it cannot
        # make the host contact an arbitrary endpoint before approval. Only an
        # exact operator-selected wallet endpoint is eligible.
        extension_rpc._rpc_endpoint_display(rpc_url)
        if configured_rpc is None or not secrets.compare_digest(rpc_url, configured_rpc):
            raise ValueError("rpc_endpoint_not_allowed")
    resolved_rpc = configured_rpc
    if resolved_rpc is None:
        # ``eth_sendTransaction`` promises a broadcast transaction hash. A raw
        # signed RLP blob is not a compatible success result; sign-only needs a
        # separate protocol method.
        raise ValueError("transaction_rpc_required")
    rpc_endpoint = extension_rpc._rpc_endpoint_display(resolved_rpc)
    expected_signer = extension_sign.get_address()
    _freeze_transaction_signer(tx, expected_signer)
    tx = extension_rpc.fill_transaction(resolved_rpc, tx, expected_signer, chain_id)
    # The RPC filler currently preserves all caller fields. Canonicalize again
    # at the boundary so even a future implementation cannot replace the signer
    # that the user is about to approve.
    tx["from"] = expected_signer

    # sign_transaction takes chain_id separately and verifies tx["chainId"].
    # Include the canonical value in the approved snapshot for the user, then
    # run the same canonicalizer sign_transaction uses.  This removes fields
    # the signer cannot represent only by rejecting them — never by silently
    # dropping or coercing them after the approval prompt.
    frozen_chain_id = hex(chain_id)
    tx["chainId"] = frozen_chain_id
    tx = extension_sign.canonicalize_transaction(tx, chain_id=chain_id)
    return _PreparedSign([tx], frozen_chain_id, resolved_rpc, rpc_endpoint, expected_signer)


def _send_prepared_transaction(
    tx: dict[str, Any],
    chain_id_hex: str | None = None,
    rpc_url: str | None = None,
    *,
    expected_signer: str,
) -> str:
    """Sign an already-approved transaction and broadcast it.

    Missing nonce/gas/fee fields are never filled here: doing so after the
    approval prompt would sign content the user did not review. The keyvault
    address is re-resolved immediately before signing so changing wallet.json
    or its selected account cannot turn approval for one signer into a signature
    from another. ``eth_sendTransaction`` has no raw-transaction success mode:
    the frozen RPC must still serve the approved chain immediately before send.
    """
    from mordred_hermes.keyvault import extension_sign

    chain_id = _resolve_chain_id(chain_id_hex)
    if not rpc_url:
        raise RuntimeError("transaction_rpc_required")
    tx_signer = tx.get("from")
    if not isinstance(tx_signer, str) or not _addresses_match(tx_signer, expected_signer):
        raise RuntimeError("transaction_signer_mismatch")
    _assert_current_signer(expected_signer)
    canonical_tx = extension_sign.canonicalize_transaction(tx, chain_id=chain_id)
    if canonical_tx != tx:
        raise RuntimeError("transaction_snapshot_not_canonical")
    signed = extension_sign.sign_transaction(canonical_tx, chain_id=chain_id)
    try:
        actual_signer = _recover_transaction_signer(signed["raw"])
    except Exception as exc:
        raise RuntimeError("signature_signer_verification_failed") from exc
    _assert_recovered_signer(actual_signer, expected_signer)
    from . import rpc as extension_rpc

    try:
        remote_hash = extension_rpc.send_raw_transaction(
            rpc_url,
            signed["raw"],
            expected_chain_id=chain_id,
        )
    except Exception as exc:
        raise RuntimeError(f"broadcast_failed: {exc}") from exc
    if remote_hash.casefold() != signed["hash"].casefold():
        raise RuntimeError("broadcast_failed: RPC returned a mismatched transaction hash")
    return remote_hash


# --------------------------------------------------------------------------- #
# Deterministic sign-request analysis (risk + decode). An LLM pass can replace
# this later; keeping it deterministic makes it testable and offline-safe.
# --------------------------------------------------------------------------- #

_ERC20_TRANSFER = "a9059cbb"
_ERC20_APPROVE = "095ea7b3"
_ERC20_CALLDATA_HEX_LEN = 8 + 64 + 64
_MAX_UINT = (1 << 256) - 1


def _is_canonical_erc20_call(data: str, selector: str) -> bool:
    """Recognize the exact selector/length with a canonical ABI address word."""
    return len(data) == _ERC20_CALLDATA_HEX_LEN and data[:8] == selector and data[8:32] == "0" * 24


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

    contract_context = {
        "contract": to,
        "native_value_wei": str(value),
    }
    context_summary = f"contract: {to}; native value: {value} wei"
    context_warning = f"呼び出し先コントラクト: {to} / ネイティブETH: {value} wei"

    if to is not None and _is_canonical_erc20_call(data, _ERC20_TRANSFER):
        recipient = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {
            "function": "transfer(address,uint256)",
            **contract_context,
            "args": {"to": recipient, "amount": str(amount)},
        }
        warnings.append(context_warning)
        risk = "high" if value > 0 else "medium"
        if value > 0:
            warnings.append("ERC-20呼び出しと同時にネイティブETHを送金します")
        summary = f"ERC-20 transfer: {amount} → {recipient} ({context_summary})"
    elif to is not None and _is_canonical_erc20_call(data, _ERC20_APPROVE):
        spender = "0x" + data[8 + 24 : 8 + 64]
        amount = int(data[8 + 64 : 8 + 128], 16)
        decoded = {
            "function": "approve(address,uint256)",
            **contract_context,
            "args": {"spender": spender, "amount": str(amount)},
        }
        warnings.append(context_warning)
        if amount >= _MAX_UINT:
            risk = "high"
            warnings.append("無制限の approve(残高全額を引き出せる権限)です")
        else:
            risk = "medium"
        if value > 0:
            risk = "high"
            warnings.append("ERC-20呼び出しと同時にネイティブETHを送金します")
        summary = f"ERC-20 approve: {spender} ({context_summary})"
    elif data:
        decoded = contract_context
        warnings.append(context_warning)
        risk = "high" if value > 0 else "medium"
        summary = f"コントラクト呼び出し ({context_summary})"
    elif value > 0:
        risk = "medium" if value >= 10**18 else "low"
        summary = f"ETH 送金: {value} wei → {to}"
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
