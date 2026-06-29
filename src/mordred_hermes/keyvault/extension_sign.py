"""Extension signing API — sign_only surface for the Mordred Extension.

The browser extension never holds an Ethereum private key; it forwards
``personal_sign`` / ``eth_signTypedData_v4`` / ``eth_sendTransaction`` requests
over the gateway WebSocket and Hermes signs them here. The private scalar stays
inside the keyvault (Secure Enclave on macOS Apple Silicon): we use
``eth_account`` only to compute the 32-byte signing hash and to assemble the
result, then sign the hash via :mod:`mordred_hermes.keyvault.ethereum`.

Account selection: ``~/.hermes/extension/wallet.json`` may pin an account; if
absent and exactly one HD seed is stored, account ``m/44'/60'/0'/0/0`` is used.

See ``Mordred-Extension/SPEC.ja.md`` §5.5.
"""

from __future__ import annotations

import contextlib
import json
import logging
from pathlib import Path
from typing import Any

from . import ethereum

_log = logging.getLogger(__name__)
_KEY_ID_DEFAULT = "default"

# Public fallback RPC endpoints; users should set their own via wallet.json.
_DEFAULT_RPC: dict[int, str] = {
    1: "https://cloudflare-eth.com",
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
}


class WalletNotConfigured(Exception):
    """No Ethereum account is configured/discoverable for the extension."""


class TransactionFieldsMissing(Exception):
    """A transaction is missing fields Hermes cannot fill without an RPC node."""

    def __init__(self, missing: list[str]) -> None:
        super().__init__("missing transaction fields: " + ", ".join(missing))
        self.missing = missing


# --------------------------------------------------------------------------- #
# Backend / config
# --------------------------------------------------------------------------- #


def se_available() -> bool:
    try:
        from . import native

        return bool(native.is_secure_enclave_available())
    except Exception:
        return False


def _backend() -> Any:
    from ._seckey_backend import _SecKeyBackend

    return _SecKeyBackend()


def _audit_sink(entry: dict[str, Any]) -> None:
    # Best-effort: extension signs are audited at DEBUG. A full audit-log writer
    # can be slotted in here later without changing the call sites.
    _log.debug("extension_sign audit: %s", entry.get("event", "?"))


def _ext_dir() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "extension"


def _load_wallet_cfg() -> dict[str, Any]:
    try:
        data = json.loads((_ext_dir() / "wallet.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def set_wallet(cfg: dict[str, Any]) -> None:
    """Persist the extension wallet config (used by setup tooling)."""
    import os

    d = _ext_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / "wallet.json"
    path.write_text(json.dumps(cfg), "utf-8")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def chain_id_int() -> int:
    cfg = _load_wallet_cfg()
    cid = cfg.get("chain_id", 1)
    return int(cid, 16) if isinstance(cid, str) and cid.startswith("0x") else int(cid)


def rpc_url_for(chain_id: int) -> str | None:
    """Resolve the JSON-RPC URL for a chain from wallet.json (`rpc` map or
    `rpc_url`), falling back to the built-in public endpoints."""
    cfg = _load_wallet_cfg()
    rpc_map = cfg.get("rpc") or {}
    url = rpc_map.get(str(chain_id)) or rpc_map.get(hex(chain_id)) or cfg.get("rpc_url")
    if url:
        return str(url)
    return _DEFAULT_RPC.get(chain_id)


def _resolve_account() -> dict[str, Any]:
    cfg = _load_wallet_cfg()
    if cfg.get("kind"):
        return cfg
    key_id = cfg.get("key_id", _KEY_ID_DEFAULT)
    seeds = ethereum.list_seed_envelope_ids(key_id)
    if len(seeds) == 1:
        return {
            "kind": "hd",
            "key_id": key_id,
            "seed_envelope_id": seeds[0],
            "index": 0,
            "account": 0,
            "change": 0,
        }
    raise WalletNotConfigured(
        "No extension wallet configured. Run `hermes-mordred keyvault eth ...` to "
        "create a key, then pin it in ~/.hermes/extension/wallet.json."
        if not seeds
        else "Multiple HD seeds stored; pin one in ~/.hermes/extension/wallet.json."
    )


# --------------------------------------------------------------------------- #
# Hash signing (delegates to the SE-backed keyvault)
# --------------------------------------------------------------------------- #


def _sign_hash(message_hash: bytes) -> ethereum.EthereumSignature:
    acct = _resolve_account()
    backend, sink = _backend(), _audit_sink
    if acct["kind"] == "hd":
        return ethereum.sign_hash_hd(
            acct["key_id"],
            acct["seed_envelope_id"],
            int(acct.get("index", 0)),
            message_hash,
            backend=backend,
            audit_sink=sink,
            account=int(acct.get("account", 0)),
            change=int(acct.get("change", 0)),
        )
    return ethereum.sign_hash(
        acct["key_id"],
        acct["envelope_id"],
        message_hash,
        backend=backend,
        audit_sink=sink,
    )


def get_address() -> str:
    acct = _resolve_account()
    backend, sink = _backend(), _audit_sink
    if acct["kind"] == "hd":
        address, _path = ethereum.derive_ethereum_key(
            acct["key_id"],
            acct["seed_envelope_id"],
            int(acct.get("index", 0)),
            backend=backend,
            audit_sink=sink,
            account=int(acct.get("account", 0)),
            change=int(acct.get("change", 0)),
        )
        return address
    return ethereum.get_ethereum_address(acct["key_id"], acct["envelope_id"], backend=backend, audit_sink=sink)


# --------------------------------------------------------------------------- #
# EIP-191 / EIP-712 message signing
# --------------------------------------------------------------------------- #


def personal_sign(message: str) -> str:
    """EIP-191 ``personal_sign``. ``message`` is the DApp param (hex or text)."""
    from eth_account.messages import _hash_eip191_message, encode_defunct

    signable = encode_defunct(hexstr=message) if message.startswith("0x") else encode_defunct(text=message)
    sig = _sign_hash(_hash_eip191_message(signable))
    return "0x" + sig.hex


def sign_typed_data_v4(typed_data: str | dict[str, Any]) -> str:
    """EIP-712 ``eth_signTypedData_v4``. Accepts the JSON string or dict."""
    from eth_account.messages import _hash_eip191_message, encode_typed_data

    data = json.loads(typed_data) if isinstance(typed_data, str) else typed_data
    sig = _sign_hash(_hash_eip191_message(encode_typed_data(full_message=data)))
    return "0x" + sig.hex


# --------------------------------------------------------------------------- #
# Transaction signing (raw signed tx; broadcasting is out of scope in v1)
# --------------------------------------------------------------------------- #


def _to_int(v: Any) -> int:
    if v is None or v == "":
        return 0
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s, 16) if s.startswith("0x") else int(s)


def _rlp_int(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""


def _addr_bytes(to: Any) -> bytes:
    if not to:
        return b""  # contract creation
    return bytes.fromhex(str(to).removeprefix("0x"))


def _data_bytes(data: Any) -> bytes:
    if not data:
        return b""
    return bytes.fromhex(str(data).removeprefix("0x"))


def sign_transaction(tx: dict[str, Any], *, chain_id: int = 1) -> dict[str, str]:
    """Sign a transaction, returning ``{"raw": "0x..", "hash": "0x.."}``.

    Hermes has no RPC node wired in v1, so ``nonce``/``gas``/fee fields must be
    present in ``tx`` (most DApps that call ``eth_sendTransaction`` supply them).
    EIP-1559 (``maxFeePerGas``) and legacy (``gasPrice``) are both supported.
    Broadcasting the returned raw tx over Tor is a follow-up (SPEC §5.3).
    """
    import rlp
    from eth_hash.auto import keccak

    is_1559 = "maxFeePerGas" in tx or tx.get("type") in (2, "0x2")
    required = ["nonce", "gas"] + (["maxFeePerGas", "maxPriorityFeePerGas"] if is_1559 else ["gasPrice"])
    missing = [f for f in required if tx.get(f) in (None, "")]
    if missing:
        raise TransactionFieldsMissing(missing)

    nonce = _to_int(tx["nonce"])
    gas = _to_int(tx["gas"])
    to = _addr_bytes(tx.get("to"))
    value = _to_int(tx.get("value"))
    data = _data_bytes(tx.get("data"))

    if is_1559:
        max_prio = _to_int(tx["maxPriorityFeePerGas"])
        max_fee = _to_int(tx["maxFeePerGas"])
        unsigned = [
            _rlp_int(chain_id),
            _rlp_int(nonce),
            _rlp_int(max_prio),
            _rlp_int(max_fee),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            [],
        ]
        sighash = keccak(b"\x02" + rlp.encode(unsigned))
        sig = _sign_hash(sighash)
        y = sig.v - 27
        r = int.from_bytes(sig.r, "big")
        s_int = int.from_bytes(sig.s, "big")
        signed = [*unsigned, _rlp_int(y), _rlp_int(r), _rlp_int(s_int)]
        raw = b"\x02" + rlp.encode(signed)
    else:
        gas_price = _to_int(tx["gasPrice"])
        unsigned = [
            _rlp_int(nonce),
            _rlp_int(gas_price),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            _rlp_int(chain_id),
            b"",
            b"",
        ]
        sighash = keccak(rlp.encode(unsigned))
        sig = _sign_hash(sighash)
        v = (sig.v - 27) + 35 + 2 * chain_id
        signed = [
            _rlp_int(nonce),
            _rlp_int(gas_price),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            _rlp_int(v),
            _rlp_int(int.from_bytes(sig.r, "big")),
            _rlp_int(int.from_bytes(sig.s, "big")),
        ]
        raw = rlp.encode(signed)

    return {"raw": "0x" + raw.hex(), "hash": "0x" + keccak(raw).hex()}
