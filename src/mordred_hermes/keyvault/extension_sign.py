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
import functools
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import ethereum

if TYPE_CHECKING:
    from ..privacy_check.audit import Writer

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


def _ext_dir() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "extension"


def _audit_log_path() -> Path:
    """``<HERMES_BASE>/mordred/audit.log`` — the same file ``network`` /
    ``llm_guard`` / ``privacy_check`` append to.

    Resolved the same way :func:`_ext_dir` already resolves the hermes home
    (a fresh ``hermes_constants.get_hermes_home()`` call, not the
    import-time-frozen :data:`mordred_hermes._home.HERMES_BASE`) so this
    module keeps its existing import-cheapness contract: no package-root
    import pulls in the profile-aware home resolution at module-import time.
    ``.parent.parent`` of this path is ``<HERMES_BASE>``, matching
    :func:`mordred_hermes._audit_support.build_audit_writer`'s
    ``keyvault_home = path.parent.parent`` contract.
    """
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "mordred" / "audit.log"


@functools.lru_cache(maxsize=1)
def _audit_writer() -> Writer:
    """Module-local reference to the shared extension-sign audit writer.

    Zero-arg (unlike ``network`` / ``llm_guard``'s ``_build_audit_writer(path)``)
    because this module deliberately never freezes ``HERMES_BASE`` at import
    time (see :func:`_audit_log_path`); the path is recomputed on the first
    call. The local cache preserves the test ``cache_clear()`` API, while
    :mod:`mordred_hermes._audit_support` owns the normalized-path singleton so
    clearing this cache never closes a writer another plugin is using. The
    :mod:`mordred_hermes._audit_support` import happens here, at first call,
    not at module scope, so plugin discovery stays cheap.
    """
    from .._audit_support import build_audit_writer

    return build_audit_writer(_audit_log_path())


def _audit_sink(entry: dict[str, Any]) -> None:
    """Best-effort audit for extension-driven Enclave key use.

    The extension is the one path where a remote DApp — over the gateway
    WebSocket — drives Secure-Enclave key use directly: ``personal_sign`` /
    ``eth_signTypedData_v4`` / ``eth_sendTransaction`` all route through
    :func:`_sign_hash` / :func:`get_address`, which pass this sink to the wrap
    layer as ``audit_sink``. Without this, the ``keyvault.unwrap_authorized`` /
    ``keyvault.unwrap_denied`` events that same wrap layer emits for every
    other Enclave use (and that :func:`...keyvault.log_encryption.decrypt_log_file`
    records durably) were silently dropped for the extension path, leaving no
    tamper-evident trail for fund-moving operations. Now appended to the same
    encryption-aware ``audit.log`` writer ``network`` / ``llm_guard`` /
    ``privacy_check`` use (see :func:`_audit_writer`).

    A signing operation must NEVER fail because the audit write failed — the
    same contract every other ``audit_sink`` call site in this package
    honors (``wrap.unwrap_dek``, ``recovery``, ``seed_display``) — so this
    catches broadly, including a possible failure to construct the writer
    itself. The DEBUG log line stays unconditional: it is cheap and aids live
    debugging even when the durable write fails.
    """
    _log.debug("extension_sign audit: %s", entry.get("event", "?"))
    try:
        from .._audit_support import safe_audit_append

        safe_audit_append(_audit_writer(), entry, logger=_log)
    except Exception as exc:  # best-effort: never fail a sign over an audit issue
        _log.error("extension_sign audit writer unavailable: %s", exc)


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


def _eip191_hash(signable: Any) -> bytes:
    """32-byte EIP-191 signing hash of an ``eth_account`` ``SignableMessage``.

    Reconstructed from the message's public fields rather than eth_account's
    private ``_hash_eip191_message``: that underscore-prefixed helper is not part
    of the package's public API and has moved across releases, so a routine
    dependency bump could silently break all extension message signing (and,
    because CI does not install the ``ethereum`` extra, the break would not
    surface until runtime on a user's machine). ``SignableMessage`` is a public
    ``NamedTuple`` and the ``0x19 ‖ version ‖ header ‖ body`` layout is the
    EIP-191 spec itself, so this is stable. Verified byte-identical to
    ``_hash_eip191_message`` for both ``encode_defunct`` and ``encode_typed_data``.
    """
    from eth_hash.auto import keccak

    # bytes(...): eth-hash is untyped in the CI env (the ``ethereum`` extra isn't
    # installed there), so keccak(...) is ``Any`` and returning it directly trips
    # mypy --strict's no-any-return. keccak already yields bytes at runtime.
    return bytes(keccak(b"\x19" + signable.version + signable.header + signable.body))


def personal_sign(message: str) -> str:
    """EIP-191 ``personal_sign``. ``message`` is the DApp param (hex or text)."""
    from eth_account.messages import encode_defunct

    signable = encode_defunct(hexstr=message) if message.startswith("0x") else encode_defunct(text=message)
    sig = _sign_hash(_eip191_hash(signable))
    return "0x" + sig.hex


def sign_typed_data_v4(typed_data: str | dict[str, Any]) -> str:
    """EIP-712 ``eth_signTypedData_v4``. Accepts the JSON string or dict."""
    from eth_account.messages import encode_typed_data

    data = json.loads(typed_data) if isinstance(typed_data, str) else typed_data
    sig = _sign_hash(_eip191_hash(encode_typed_data(full_message=data)))
    return "0x" + sig.hex


# --------------------------------------------------------------------------- #
# Transaction signing (raw signed tx; broadcasting is out of scope in v1)
# --------------------------------------------------------------------------- #

_MAX_TRANSACTION_QUANTITY = (1 << 256) - 1
_TRANSACTION_FIELDS = frozenset(
    {
        "type",
        "chainId",
        "nonce",
        "gas",
        "gasPrice",
        "maxPriorityFeePerGas",
        "maxFeePerGas",
        "to",
        "value",
        "data",
        "accessList",
        "from",
    }
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _transaction_quantity(field: str, value: Any) -> int:
    """Parse one unsigned Ethereum JSON-RPC quantity without coercion.

    ``bool``, floats, signed strings and objects with a surprising ``__str__``
    are deliberately rejected.  The old permissive conversion made negative
    values serialize as zero and let the approval prompt describe a different
    transaction from the bytes that were ultimately signed.
    """
    if isinstance(value, bool):
        raise ValueError(f"invalid_transaction_quantity:{field}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        if value.startswith("0x"):
            digits = value[2:]
            if not digits or any(char not in _HEX_DIGITS for char in digits):
                raise ValueError(f"invalid_transaction_quantity:{field}")
            number = int(digits, 16)
        else:
            if not value or not value.isascii() or not value.isdecimal():
                raise ValueError(f"invalid_transaction_quantity:{field}")
            number = int(value, 10)
    else:
        raise ValueError(f"invalid_transaction_quantity:{field}")
    if number < 0 or number > _MAX_TRANSACTION_QUANTITY:
        raise ValueError(f"invalid_transaction_quantity:{field}")
    return number


def _canonical_address(field: str, value: Any, *, allow_empty: bool) -> str | None:
    if allow_empty and value in (None, ""):
        return None
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"invalid_transaction_address:{field}")
    digits = value[2:]
    if len(digits) != 40 or any(char not in _HEX_DIGITS for char in digits):
        raise ValueError(f"invalid_transaction_address:{field}")
    return "0x" + digits.lower()


def _canonical_data(value: Any) -> str:
    if value in (None, ""):
        return "0x"
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("invalid_transaction_data")
    digits = value[2:]
    if len(digits) % 2 or any(char not in _HEX_DIGITS for char in digits):
        raise ValueError("invalid_transaction_data")
    return "0x" + digits.lower()


def _validated_transaction_chain_id(tx: dict[str, Any], chain_id: int) -> int:
    parsed_chain_id = _transaction_quantity("chainId", chain_id)
    if parsed_chain_id == 0:
        raise ValueError("invalid_transaction_chain_id")
    supplied_chain_id = tx.get("chainId")
    if supplied_chain_id not in (None, "") and _transaction_quantity("chainId", supplied_chain_id) != parsed_chain_id:
        raise ValueError("transaction_chain_id_mismatch")
    return parsed_chain_id


def _transaction_fee_mode(tx: dict[str, Any]) -> str | None:
    """Return ``legacy`` / ``eip1559`` or ``None`` when fees are unspecified."""
    supplied_type = tx.get("type")
    explicit_type: int | None = None
    if supplied_type not in (None, ""):
        explicit_type = _transaction_quantity("type", supplied_type)
        if explicit_type not in (0, 2):
            raise ValueError("unsupported_transaction_type")

    has_legacy_fee = tx.get("gasPrice") not in (None, "")
    has_max_fee = tx.get("maxFeePerGas") not in (None, "")
    has_priority_fee = tx.get("maxPriorityFeePerGas") not in (None, "")
    has_eip1559_fee = has_max_fee or has_priority_fee
    if has_legacy_fee and has_eip1559_fee:
        raise ValueError("conflicting_transaction_fee_fields")
    if explicit_type == 0 and has_eip1559_fee:
        raise ValueError("conflicting_transaction_fee_fields")
    if explicit_type == 2 and has_legacy_fee:
        raise ValueError("conflicting_transaction_fee_fields")
    if explicit_type == 2 or (explicit_type is None and has_eip1559_fee):
        return "eip1559"
    if explicit_type == 0 or has_legacy_fee:
        return "legacy"
    return None


def _validate_present_transaction_values(tx: dict[str, Any]) -> None:
    if "accessList" in tx and tx["accessList"] != []:
        raise ValueError("unsupported_transaction_access_list")
    for field in ("nonce", "gas", "gasPrice", "maxPriorityFeePerGas", "maxFeePerGas"):
        if tx.get(field) not in (None, ""):
            _transaction_quantity(field, tx[field])
    if "value" in tx:
        _transaction_quantity("value", tx["value"])
    if tx.get("to") not in (None, ""):
        _canonical_address("to", tx["to"], allow_empty=True)
    if tx.get("from") not in (None, ""):
        _canonical_address("from", tx["from"], allow_empty=False)
    if "data" in tx:
        _canonical_data(tx["data"])

    if tx.get("maxPriorityFeePerGas") not in (None, "") and tx.get("maxFeePerGas") not in (None, ""):
        max_priority_fee = _transaction_quantity("maxPriorityFeePerGas", tx["maxPriorityFeePerGas"])
        max_fee = _transaction_quantity("maxFeePerGas", tx["maxFeePerGas"])
        if max_priority_fee > max_fee:
            raise ValueError("transaction_priority_fee_exceeds_max_fee")


def validate_transaction_request(tx: dict[str, Any], *, chain_id: int) -> str | None:
    """Validate every caller-supplied field without requiring RPC-filled ones.

    This preflight is shared by the RPC filler and final canonicalizer so an
    unsupported type, conflicting fee model, malformed quantity/address/data,
    or ignored field is rejected before any request reaches the configured RPC.
    """
    if not isinstance(tx, dict):
        raise ValueError("invalid_transaction")
    unknown = sorted(field for field in tx if field not in _TRANSACTION_FIELDS)
    if unknown:
        raise ValueError("unsupported_transaction_fields:" + ",".join(unknown))

    _validated_transaction_chain_id(tx, chain_id)
    fee_mode = _transaction_fee_mode(tx)
    _validate_present_transaction_values(tx)
    if "accessList" in tx and fee_mode != "eip1559":
        raise ValueError("transaction_access_list_requires_type_2")
    return fee_mode


def _validate_transaction_shape(tx: dict[str, Any], *, is_eip1559: bool) -> None:
    required = ["nonce", "gas"]
    if is_eip1559:
        required.extend(("maxFeePerGas", "maxPriorityFeePerGas"))
    else:
        required.append("gasPrice")
    missing = [field for field in required if tx.get(field) in (None, "")]
    if missing:
        raise TransactionFieldsMissing(missing)


def _canonical_fee_fields(tx: dict[str, Any], *, is_eip1559: bool) -> dict[str, str]:
    if not is_eip1559:
        return {"gasPrice": hex(_transaction_quantity("gasPrice", tx["gasPrice"]))}
    max_priority_fee = _transaction_quantity("maxPriorityFeePerGas", tx["maxPriorityFeePerGas"])
    max_fee = _transaction_quantity("maxFeePerGas", tx["maxFeePerGas"])
    if max_priority_fee > max_fee:
        raise ValueError("transaction_priority_fee_exceeds_max_fee")
    return {
        "maxPriorityFeePerGas": hex(max_priority_fee),
        "maxFeePerGas": hex(max_fee),
    }


def canonicalize_transaction(tx: dict[str, Any], *, chain_id: int = 1) -> dict[str, Any]:
    """Validate and freeze the exact transaction representation Hermes signs.

    Only legacy EIP-155 transactions and type-2 EIP-1559 transactions with an
    empty access list are supported.  Returning a JSON-friendly canonical dict
    gives the approval UI and :func:`sign_transaction` one shared source of
    truth: unsupported or ignored fields can no longer appear in the prompt and
    then disappear from the signed bytes.
    """
    fee_mode = validate_transaction_request(tx, chain_id=chain_id)
    parsed_chain_id = _transaction_quantity("chainId", chain_id)
    is_eip1559 = fee_mode == "eip1559"
    _validate_transaction_shape(tx, is_eip1559=is_eip1559)

    canonical: dict[str, Any] = {
        "type": "0x2" if is_eip1559 else "0x0",
        "chainId": hex(parsed_chain_id),
        "nonce": hex(_transaction_quantity("nonce", tx["nonce"])),
        **_canonical_fee_fields(tx, is_eip1559=is_eip1559),
    }
    canonical.update(
        {
            "gas": hex(_transaction_quantity("gas", tx["gas"])),
            "to": _canonical_address("to", tx.get("to"), allow_empty=True),
            "value": hex(_transaction_quantity("value", tx.get("value", 0))),
            "data": _canonical_data(tx.get("data")),
        }
    )
    if is_eip1559:
        canonical["accessList"] = []
    supplied_from = tx.get("from")
    if supplied_from not in (None, ""):
        canonical["from"] = _canonical_address("from", supplied_from, allow_empty=False)
    return canonical


def _rlp_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative_transaction_quantity")
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def sign_transaction(tx: dict[str, Any], *, chain_id: int = 1) -> dict[str, str]:
    """Sign a transaction, returning ``{"raw": "0x..", "hash": "0x.."}``.

    All nonce/gas/fee fields must already be present. The extension wallet fills
    and freezes them through its configured RPC before user approval, then
    broadcasts the returned bytes only after rechecking the chain. Direct
    callers remain responsible for filling those fields. EIP-1559
    (``maxFeePerGas``) and legacy (``gasPrice``) are both supported.
    """
    import rlp
    from eth_hash.auto import keccak

    canonical = canonicalize_transaction(tx, chain_id=chain_id)
    is_1559 = canonical["type"] == "0x2"
    signing_chain_id = int(canonical["chainId"], 16)
    nonce = int(canonical["nonce"], 16)
    gas = int(canonical["gas"], 16)
    to_value = canonical["to"]
    to = b"" if to_value is None else bytes.fromhex(to_value[2:])
    value = int(canonical["value"], 16)
    data = bytes.fromhex(canonical["data"][2:])

    if is_1559:
        max_prio = int(canonical["maxPriorityFeePerGas"], 16)
        max_fee = int(canonical["maxFeePerGas"], 16)
        unsigned = [
            _rlp_int(signing_chain_id),
            _rlp_int(nonce),
            _rlp_int(max_prio),
            _rlp_int(max_fee),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            canonical["accessList"],
        ]
        sighash = keccak(b"\x02" + rlp.encode(unsigned))
        sig = _sign_hash(sighash)
        y = sig.v - 27
        r = int.from_bytes(sig.r, "big")
        s_int = int.from_bytes(sig.s, "big")
        signed = [*unsigned, _rlp_int(y), _rlp_int(r), _rlp_int(s_int)]
        raw = b"\x02" + rlp.encode(signed)
    else:
        gas_price = int(canonical["gasPrice"], 16)
        unsigned = [
            _rlp_int(nonce),
            _rlp_int(gas_price),
            _rlp_int(gas),
            to,
            _rlp_int(value),
            data,
            _rlp_int(signing_chain_id),
            b"",
            b"",
        ]
        sighash = keccak(rlp.encode(unsigned))
        sig = _sign_hash(sighash)
        v = (sig.v - 27) + 35 + 2 * signing_chain_id
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
