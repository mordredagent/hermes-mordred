"""Tests for ``hermes-mordred keyvault eth {new,derive,address}``.

The dedicated Ethereum-key CLI surface over
:mod:`mordred_hermes.keyvault.ethereum`:

- ``eth new``     — generate a fresh random secp256k1 key.
- ``eth derive``  — BIP-44 HD account from the stored ``bip39.seed.v1`` seed.
- ``eth address`` — read back the EIP-55 address for a stored envelope.

The private key never leaves the keyvault: every command returns only the
checksum address and the opaque ``envelope_id`` handle.

These tests use ``FakeBackend`` (software P-256 stand-in for the Secure
Enclave) and inject ``backend`` / ``audit_sink`` / ``home`` exactly as the
``keyvault recover`` tests do. The backend-coupled paths need the optional
``eth-keys`` extra, so the module is import-skipped when it is absent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.keyvault.ethereum import store_seed_phrase
from mordred_hermes.wizard import keyvault_eth_cli
from tests._keyvault_fakes import FakeBackend

pytest.importorskip("eth_keys")

# Foundry / Hardhat default mnemonic — a valid 12-word BIP-39 phrase whose
# account 0 (m/44'/60'/0'/0/0) is the well-known address below. Using a
# fixed vector lets us assert the *exact* derivation, not just shape.
_TEST_MNEMONIC = "test test test test test test test test test test test junk"
_TEST_ADDRESS_0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"  # lower-cased for comparison


def _backend(tmp_path: Path) -> tuple[FakeBackend, list[dict], dict]:
    """Return (backend, audit_log, kwargs) wired to ``tmp_path``."""
    backend = FakeBackend()
    backend.generate_enclave_key("default")
    root = _storage.resolve_keyvault_dir(tmp_path)
    _storage.ensure_layout(root)
    key_hash = hashlib.sha256(b"default").digest()[:16].hex()
    _storage.atomic_write(root / "digests" / f"{key_hash}.commit", b"\x00" * 32)
    meta = _storage.load_meta(root)
    meta["keys"][key_hash] = {"key_id": "default", "created_at": "2026-01-01T00:00:00Z"}
    _storage.save_meta(root, meta)
    log: list[dict] = []
    kwargs: dict = {"backend": backend, "audit_sink": log.append, "home": tmp_path}
    return backend, log, kwargs


# ---------------------------------------------------------------------------
# eth new — generate a random secp256k1 key
# ---------------------------------------------------------------------------


def test_eth_new_prints_address_and_stores_one_envelope(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    rc = keyvault_eth_cli.eth_new(as_json=False, **kw)
    assert rc == 0
    out = capsys.readouterr().out
    assert "0x" in out
    assert len(list(tmp_path.rglob("*.gcm"))) == 1, "expected exactly one ciphertext envelope"


def test_eth_new_json_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    rc = keyvault_eth_cli.eth_new(as_json=True, **kw)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["address"].startswith("0x")
    assert len(payload["address"]) == 42
    assert payload["key_id"] == "default"
    assert isinstance(payload["envelope_id"], str)
    assert len(payload["envelope_id"]) == 22


def test_eth_new_two_keys_differ(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    keyvault_eth_cli.eth_new(as_json=True, **kw)
    first = json.loads(capsys.readouterr().out)
    keyvault_eth_cli.eth_new(as_json=True, **kw)
    second = json.loads(capsys.readouterr().out)
    assert first["address"] != second["address"]
    assert first["envelope_id"] != second["envelope_id"]


# ---------------------------------------------------------------------------
# eth address — read back the address for a stored envelope
# ---------------------------------------------------------------------------


def test_eth_address_matches_new(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    keyvault_eth_cli.eth_new(as_json=True, **kw)
    created = json.loads(capsys.readouterr().out)

    rc = keyvault_eth_cli.eth_address(created["envelope_id"], as_json=True, **kw)
    assert rc == 0
    read = json.loads(capsys.readouterr().out)
    assert read["address"] == created["address"]
    assert read["envelope_id"] == created["envelope_id"]


def test_eth_address_unknown_envelope_returns_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    rc = keyvault_eth_cli.eth_address("A" * 22, as_json=False, **kw)
    assert rc == 1


def test_eth_address_malformed_envelope_returns_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    rc = keyvault_eth_cli.eth_address("../escape", as_json=False, **kw)
    assert rc == 1


# ---------------------------------------------------------------------------
# eth derive — HD account from the stored seed
# ---------------------------------------------------------------------------


def test_eth_derive_known_address_and_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    store_seed_phrase("default", _TEST_MNEMONIC, **kw)

    rc = keyvault_eth_cli.eth_derive(index=0, as_json=True, **kw)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["address"].lower() == _TEST_ADDRESS_0
    assert payload["path"] == "m/44'/60'/0'/0/0"
    assert payload["index"] == 0


def test_eth_derive_distinct_indexes_distinct_addresses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    store_seed_phrase("default", _TEST_MNEMONIC, **kw)

    keyvault_eth_cli.eth_derive(index=0, as_json=True, **kw)
    addr0 = json.loads(capsys.readouterr().out)["address"]
    keyvault_eth_cli.eth_derive(index=1, as_json=True, **kw)
    addr1 = json.loads(capsys.readouterr().out)["address"]
    assert addr0 != addr1


def test_eth_derive_no_seed_returns_1_with_actionable_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    rc = keyvault_eth_cli.eth_derive(index=0, as_json=False, **kw)
    assert rc == 1
    err = capsys.readouterr().err
    assert "init" in err.lower()


def test_eth_derive_multiple_seeds_requires_explicit_id(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, kw = _backend(tmp_path)
    id1 = store_seed_phrase("default", _TEST_MNEMONIC, **kw)
    store_seed_phrase("default", _TEST_MNEMONIC, **kw)  # second seed → ambiguous

    rc = keyvault_eth_cli.eth_derive(index=0, as_json=False, **kw)
    assert rc == 1
    err = capsys.readouterr().err
    assert "seed-envelope-id" in err

    # An explicit envelope id resolves the ambiguity.
    rc2 = keyvault_eth_cli.eth_derive(index=0, seed_envelope_id=id1, as_json=True, **kw)
    assert rc2 == 0
    assert json.loads(capsys.readouterr().out)["address"].lower() == _TEST_ADDRESS_0


# ---------------------------------------------------------------------------
# error paths — an Enclave / extra failure maps to rc 1, not a traceback
# ---------------------------------------------------------------------------


def test_eth_new_enclave_failure_returns_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.keyvault import ethereum
    from mordred_hermes.keyvault._exceptions import WrapError

    _, _, kw = _backend(tmp_path)

    def boom(*_a: object, **_k: object) -> tuple[str, str]:
        raise WrapError("enclave unavailable")

    monkeypatch.setattr(ethereum, "generate_ethereum_key", boom)
    rc = keyvault_eth_cli.eth_new(as_json=False, **kw)
    assert rc == 1
    assert "Ethereum key" in capsys.readouterr().err


def test_eth_derive_enclave_failure_returns_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.keyvault import ethereum
    from mordred_hermes.keyvault._exceptions import WrapError

    _, _, kw = _backend(tmp_path)
    store_seed_phrase("default", _TEST_MNEMONIC, **kw)

    def boom(*_a: object, **_k: object) -> tuple[str, str]:
        raise WrapError("enclave unavailable")

    monkeypatch.setattr(ethereum, "derive_ethereum_key", boom)
    rc = keyvault_eth_cli.eth_derive(index=0, as_json=False, **kw)
    assert rc == 1
    assert "derive" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# argparse adapters — delegate to the business functions
# ---------------------------------------------------------------------------


def test_cli_eth_new_adapter_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def fake(*, key_id: str, as_json: bool) -> int:
        seen["key_id"] = key_id
        seen["as_json"] = as_json
        return 0

    monkeypatch.setattr(keyvault_eth_cli, "eth_new", fake)
    rc = keyvault_eth_cli.cli_eth_new(argparse.Namespace(key_id="default", json=True))
    assert rc == 0
    assert seen == {"key_id": "default", "as_json": True}


def test_cli_eth_derive_adapter_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def fake(**kwargs: object) -> int:
        seen.update(kwargs)
        return 0

    monkeypatch.setattr(keyvault_eth_cli, "eth_derive", fake)
    rc = keyvault_eth_cli.cli_eth_derive(
        argparse.Namespace(
            key_id="default",
            index=3,
            account=0,
            change=0,
            seed_envelope_id=None,
            json=False,
        )
    )
    assert rc == 0
    assert seen["index"] == 3
    assert seen["as_json"] is False


def test_cli_eth_address_adapter_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    def fake(envelope_id: str, *, key_id: str, as_json: bool) -> int:
        seen["envelope_id"] = envelope_id
        seen["key_id"] = key_id
        seen["as_json"] = as_json
        return 0

    monkeypatch.setattr(keyvault_eth_cli, "eth_address", fake)
    rc = keyvault_eth_cli.cli_eth_address(argparse.Namespace(envelope_id="A" * 22, key_id="default", json=True))
    assert rc == 0
    assert seen == {"envelope_id": "A" * 22, "key_id": "default", "as_json": True}


# ---------------------------------------------------------------------------
# Parser wiring — `keyvault eth ...` is registered on the mordred tree and
# routes to the right adapter (cli._add_keyvault -> add_eth_subparsers).
# ---------------------------------------------------------------------------


def _mordred_parser() -> argparse.ArgumentParser:
    """Build an isolated ``hermes mordred`` parser the same way Hermes would."""
    from mordred_hermes.wizard.cli import _setup_subparser

    root = argparse.ArgumentParser(prog="hermes")
    sub = root.add_subparsers(dest="command")
    plugin_parser = sub.add_parser("mordred")
    _setup_subparser(plugin_parser)
    return root


def test_parser_routes_eth_new() -> None:
    ns = _mordred_parser().parse_args(["mordred", "keyvault", "eth", "new", "--json"])
    assert ns.func is keyvault_eth_cli.cli_eth_new
    assert ns.key_id == "default"
    assert ns.json is True


def test_parser_routes_eth_derive_with_options() -> None:
    ns = _mordred_parser().parse_args(["mordred", "keyvault", "eth", "derive", "--index", "2", "--account", "1"])
    assert ns.func is keyvault_eth_cli.cli_eth_derive
    assert ns.index == 2
    assert ns.account == 1
    assert ns.change == 0
    assert ns.seed_envelope_id is None


def test_parser_routes_eth_address_requires_envelope_id() -> None:
    parser = _mordred_parser()
    ns = parser.parse_args(["mordred", "keyvault", "eth", "address", "--envelope-id", "A" * 22])
    assert ns.func is keyvault_eth_cli.cli_eth_address
    assert ns.envelope_id == "A" * 22
    with pytest.raises(SystemExit):
        parser.parse_args(["mordred", "keyvault", "eth", "address"])  # --envelope-id is required
