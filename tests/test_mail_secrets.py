"""Enclave-sealed IMAP credentials: round trip, flags without secrets, platform refusal, forget."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.imports.mail import secrets
from mordred_hermes.imports.mail.secrets import KEY_ID, MailCredentials, MailSecretsError, MailSecretStore
from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists, WrapKeyNotFound
from tests._mail_sync_helpers import PASSWORD, generic_creds, gmail_creds
from tests._platform_test_helpers import require_posix_tee


class FakeEnclave:
    """NativeBackend stand-in (the private key never leaves this object), as in the Telegram tests."""

    def __init__(self) -> None:
        self.keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.unattended: dict[str, bool | None] = {}
        self.ecdh_calls = 0

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        if key_id in self.keys:
            raise WrapKeyAlreadyExists(key_id)
        self.keys[key_id] = ec.generate_private_key(ec.SECP256R1())
        self.unattended[key_id] = unattended
        return self.get_enclave_public_key(key_id)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        if key_id not in self.keys:
            raise WrapKeyNotFound(key_id)
        return self.keys[key_id].public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def delete_enclave_key(self, key_id: str) -> None:
        self.keys.pop(key_id, None)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        if key_id not in self.keys:
            raise WrapKeyNotFound(key_id)
        self.ecdh_calls += 1
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self.keys[key_id].exchange(ec.ECDH(), peer)


def sealed_store(root: Path, enclave: FakeEnclave, platform: str = "darwin") -> MailSecretStore:
    return MailSecretStore(root, backend_factory=lambda: enclave, audit_sink=lambda _e: None, platform=lambda: platform)


@pytest.fixture
def enclave() -> FakeEnclave:
    require_posix_tee()
    return FakeEnclave()


def test_round_trip_unseals_fresh_every_time(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    assert store.load() is None and store.flags() is None
    store.ensure_key(require_presence=False)
    assert enclave.unattended == {KEY_ID: True}
    creds = generic_creds()
    store.store(creds, require_presence=False)
    assert store.load() == creds
    assert store.load() == creds
    assert enclave.ecdh_calls == 2  # nothing is cached
    sealed = store.sealed_path.read_bytes()
    assert sealed.startswith(b"MMC1")
    for secret in (b"owner@example.com", PASSWORD.encode(), b"imap.example.com", b"Sent Items"):
        assert secret not in sealed
    assert (tmp_path / "mail").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "mail" / ".gitignore").exists()


def test_flags_never_hold_the_address_host_or_password(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds("work"))
    flags = store.flags()
    assert flags is not None
    setup_id = flags.pop("setup_id")
    assert flags == {"account": "work", "gmail": True, "roles": ["all"], "touch_id": True, "version": 1}
    assert isinstance(setup_id, str) and len(setup_id) == 32  # names this setup; a new setup gets a new one
    store.store(gmail_creds("work"))
    assert store.flags()["setup_id"] != setup_id  # type: ignore[index]
    text = store.meta_path.read_text("utf-8")
    assert "@" not in text and PASSWORD not in text and "imap" not in text
    calls = enclave.ecdh_calls
    store.flags()
    assert enclave.ecdh_calls == calls  # status never touches the Enclave


def test_repr_hides_secrets() -> None:
    text = repr(gmail_creds())
    assert "owner@example.com" not in text and PASSWORD not in text and "imap.example.com" not in text


def test_other_platforms_are_refused_before_any_file_use(tmp_path: Path, enclave: FakeEnclave) -> None:
    root = tmp_path / "mail"
    store = sealed_store(root, enclave, platform="linux")
    for call in (store.load, lambda: store.store(gmail_creds()), store.ensure_key, store.forget):
        with pytest.raises(MailSecretsError) as raised:
            call()
        assert raised.value.code == "unsupported_platform"
    assert store.flags() is None
    assert not root.exists()


@pytest.mark.parametrize("damage", [b"", b"XXXX\x00\x01a", None])
def test_a_damaged_sealed_file_is_secrets_corrupt(tmp_path: Path, enclave: FakeEnclave, damage: bytes | None) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds())
    if damage is None:
        sealed = bytearray(store.sealed_path.read_bytes())
        sealed[-1] ^= 1
        damage = bytes(sealed)
    store.sealed_path.write_bytes(damage)
    with pytest.raises(MailSecretsError) as raised:
        store.load()
    assert raised.value.code == "secrets_corrupt"


def test_forget_removes_the_files_and_the_key(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds())
    store.forget()
    assert not store.sealed_path.exists() and not store.meta_path.exists()
    assert KEY_ID not in enclave.keys
    assert store.forget() is True  # absent is fine


@pytest.mark.parametrize("damage", ["corrupt", "missing", "symlink"])
def test_forget_and_residue_ignore_unreadable_flags(tmp_path: Path, enclave: FakeEnclave, damage: str) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds())
    store.meta_path.unlink()
    if damage == "corrupt":
        store.meta_path.write_text("{not json")
    elif damage == "symlink":
        store.meta_path.symlink_to(tmp_path / "elsewhere.json")
    assert store.flags() is None and store.residue()  # unreadable flags, credentials still on disk
    assert store.forget() is True
    assert not store.residue() and not store.sealed_path.exists() and KEY_ID not in enclave.keys


def test_forget_reports_a_key_it_could_not_delete(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds())

    def broken(_key_id: str) -> None:
        raise OSError("keychain unavailable")

    enclave.delete_enclave_key = broken  # type: ignore[method-assign]
    assert store.forget() is False
    assert not store.residue()  # the files are gone either way


def test_decode_refuses_malformed_payloads() -> None:
    good = secrets.encode(gmail_creds())
    assert secrets.decode(good) == gmail_creds()
    for bad in (b"{}", b"not json", good.replace(b'"gmail":true', b'"gmail":"yes"'), good.replace(b'"mail"', b'"Bad"')):
        with pytest.raises(MailSecretsError):
            secrets.decode(bad)


def test_invalid_records_are_refused() -> None:
    base: dict[str, Any] = {
        "address": "a@example.com",
        "app_password": "x",
        "imap_host": "imap.example.com",
        "imap_port": 993,
        "own_addresses": ("a@example.com",),
        "gmail": False,
    }
    for account, boxes in (("Work", {"inbox": "INBOX"}), ("work", {}), ("work", {"trash": "Trash"})):
        with pytest.raises(MailSecretsError):
            MailCredentials(**base, account=account, mailboxes=boxes)
    # Mailbox names are sent as quoted strings: no CR, LF, NUL or other control characters, ASCII only.
    for name in ("INBOX\r\nA1 STORE 1 +FLAGS (\\Seen)", "Sent\x00", "Tab\tbed", "Gesendete Objekte\u00e9", ""):
        with pytest.raises(MailSecretsError):
            MailCredentials(**base, account="work", mailboxes={"inbox": name})


@pytest.mark.parametrize("port", [143, 465, 0, 994])
def test_only_port_993_is_ever_loaded(port: int) -> None:
    good = secrets.encode(gmail_creds())
    with pytest.raises(MailSecretsError) as raised:
        secrets.decode(good.replace(b'"imap_port":993', b'"imap_port":%d' % port))
    assert raised.value.code == "secrets_corrupt"
