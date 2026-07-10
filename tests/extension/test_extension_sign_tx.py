"""Transaction signing correctness — assemble the raw tx via the keyvault hash
signer, then recover the sender with eth_account as an independent oracle."""

from __future__ import annotations

import pytest

# Web3 signing is an optional feature (mordred-hermes[ethereum] + eth-account).
# Skip the whole module when those deps aren't installed (e.g. base CI env).
eth_keys = pytest.importorskip("eth_keys")
pytest.importorskip("eth_account")
pytest.importorskip("rlp")
from eth_account import Account  # noqa: E402

from mordred_hermes.keyvault import extension_sign  # noqa: E402
from mordred_hermes.keyvault.ethereum import EthereumSignature  # noqa: E402

_PRIV = eth_keys.keys.PrivateKey(b"\x42" * 32)
_ADDR = _PRIV.public_key.to_checksum_address()


@pytest.fixture(autouse=True)
def _stub_signer(monkeypatch):
    def fake_sign_hash(message_hash: bytes) -> EthereumSignature:
        sig = _PRIV.sign_msg_hash(message_hash)
        return EthereumSignature(
            v=sig.v + 27,
            r=sig.r.to_bytes(32, "big"),
            s=sig.s.to_bytes(32, "big"),
        )

    monkeypatch.setattr(extension_sign, "_sign_hash", fake_sign_hash)


def test_legacy_tx_recovers_sender():
    tx = {
        "nonce": "0x0",
        "gasPrice": "0x3b9aca00",
        "gas": "0x5208",
        "to": "0x1111111111111111111111111111111111111111",
        "value": "0xde0b6b3a7640000",  # 1 ETH
        "data": "0x",
    }
    out = extension_sign.sign_transaction(tx, chain_id=1)
    assert out["raw"].startswith("0x")
    assert Account.recover_transaction(out["raw"]) == _ADDR


def test_eip1559_tx_recovers_sender():
    tx = {
        "type": "0x2",
        "nonce": 5,
        "maxPriorityFeePerGas": "0x3b9aca00",
        "maxFeePerGas": "0x77359400",
        "gas": "0x5208",
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0x0",
        "data": "0xa9059cbb",
    }
    out = extension_sign.sign_transaction(tx, chain_id=11155111)
    assert Account.recover_transaction(out["raw"]) == _ADDR


def test_missing_fields_raises():
    with pytest.raises(extension_sign.TransactionFieldsMissing) as ei:
        extension_sign.sign_transaction({"to": "0x" + "00" * 20, "value": "0x1"}, chain_id=1)
    assert "gas" in ei.value.missing


def test_personal_sign_recovers_signer(monkeypatch):
    msg = "Login to Mordred"
    out = extension_sign.personal_sign(msg)
    assert Account.recover_message(__import__("eth_account").messages.encode_defunct(text=msg), signature=out) == _ADDR
