"""Enclave-sealed IMAP credentials: round trip, flags without secrets, platform refusal, forget."""

from __future__ import annotations

import json
import os
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
    with pytest.raises(MailSecretsError) as raised:  # unreadable flags, credentials still on disk: a distinct state
        store.flags()
    assert raised.value.code == "credentials_left" and store.residue()
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


# --- no residue on failure, and the residue state -------------------------------------------------


def _files(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir()) if folder.exists() else []


@pytest.mark.parametrize("fault", ["flags_write", "flags_rename", "directory_sync"])
def test_a_failure_between_the_two_writes_leaves_nothing(
    tmp_path: Path, enclave: FakeEnclave, fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mordred_hermes.keyvault import _storage

    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    real_write, real_replace = _storage.atomic_write, os.replace
    writes: list[Path] = []

    def atomic_write(path: Path, data: bytes) -> None:
        if path.name.startswith(".credentials."):
            writes.append(path)
            if fault == "flags_write" and len(writes) == 2:
                raise OSError("disk full")  # the sealed file is staged, the flags are not
        real_write(path, data)

    def replace(src: Any, dst: Any) -> None:
        if fault == "flags_rename" and Path(dst) == store.meta_path:
            raise OSError("rename failed")
        real_replace(src, dst)

    def sync(_folder: Path) -> None:
        raise OSError("fsync failed")

    monkeypatch.setattr(_storage, "atomic_write", atomic_write)
    monkeypatch.setattr(os, "replace", replace)
    if fault == "directory_sync":
        monkeypatch.setattr(secrets, "_sync_directory", sync)
    with pytest.raises(OSError):
        store.store(gmail_creds())
    assert [name for name in _files(tmp_path / "mail") if "credentials" in name] == []  # nor a staged file
    assert store.flags() is None and not store.residue()
    assert [path.name.split(".")[2] for path in writes] == ["sealed", "meta"]  # both staged before any rename


def test_store_writes_through_staging_names_in_order(
    tmp_path: Path, enclave: FakeEnclave, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    real_replace = os.replace
    renamed: list[str] = []

    def replace(src: Any, dst: Any) -> None:
        if Path(dst).parent == tmp_path / "mail":
            renamed.append(Path(dst).name)
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", replace)
    store.store(gmail_creds())
    assert [name for name in renamed if not name.startswith(".")] == ["credentials.sealed", "credentials.meta.json"]
    assert _files(tmp_path / "mail") == [
        ".gitignore",
        "credentials.meta.json",
        "credentials.sealed",
        "enclave-key.json",
    ]


def test_a_sealed_file_without_flags_is_credentials_left_and_flags_alone_are_not_configured(
    tmp_path: Path, enclave: FakeEnclave
) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds())
    meta = store.meta_path.read_bytes()
    store.meta_path.unlink()  # a crash between the two renames
    with pytest.raises(MailSecretsError) as raised:
        store.flags()
    assert raised.value.code == "credentials_left" and store.residue()
    store.meta_path.write_bytes(meta)
    store.sealed_path.unlink()  # a forget interrupted between its two deletions
    assert store.flags() is None and store.residue()


def test_forget_removes_staged_leftovers(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    store.store(gmail_creds())
    (tmp_path / "mail" / ".credentials.sealed.0011223344556677.staged").write_bytes(b"MMC1")
    assert store.forget() is True
    assert _files(tmp_path / "mail") == [".gitignore"]


# --- the Enclave key's Touch ID policy ------------------------------------------------------------------


def test_ensure_key_returns_the_effective_policy(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    assert store.ensure_key(require_presence=False) is False and enclave.unattended == {KEY_ID: True}
    assert store.ensure_key(require_presence=True) is False  # kept: its recorded policy, not the requested one
    assert enclave.unattended == {KEY_ID: True}
    assert store.ensure_key(require_presence=True, replace=True) is True
    assert enclave.unattended == {KEY_ID: False}  # a fresh key with the requested policy
    record = json.loads(store.key_record_path.read_text("utf-8"))
    assert set(record) == {"public_sha256", "touch_id"} and record["touch_id"] is True
    assert (store.key_record_path.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize(
    "record", ["{corrupt", '{"public_sha256": "00", "touch_id": true}', '{"touch_id": "yes"}', None]
)
def test_a_key_without_its_own_record_has_an_unknown_policy(
    tmp_path: Path, enclave: FakeEnclave, record: str | None
) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key(require_presence=True)
    if record is None:
        store.key_record_path.unlink()
    elif 'touch_id": "yes' in record:
        value = json.loads(store.key_record_path.read_text("utf-8"))
        store.key_record_path.write_text(json.dumps({**value, "touch_id": "yes"}))
    else:
        store.key_record_path.write_text(record)
    assert store.ensure_key(require_presence=True) is None


def test_forget_removes_the_key_record(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key()
    assert store.key_record_path.exists()
    assert store.forget() is True and not store.key_record_path.exists()


def test_the_setup_generation_is_a_private_random_token(tmp_path: Path) -> None:
    home = tmp_path / "home"
    assert secrets.setup_generation(home) == secrets.GENERATION_ABSENT and not home.exists()
    first = secrets.new_setup_generation(home)
    path = home / "mordred" / "mail" / "generation"
    assert secrets.setup_generation(home) == first and len(first) == 32
    assert (path.stat().st_mode & 0o777) == 0o600 and (path.parent.stat().st_mode & 0o777) == 0o700
    assert secrets.new_setup_generation(home) not in (first, secrets.setup_generation(home) + "x")
    path.write_text("garbage")
    assert secrets.setup_generation(home) == "unreadable"
    path.unlink()
    path.mkdir()
    with pytest.raises(MailSecretsError) as raised:
        secrets.setup_generation(home)
    assert raised.value.code == "store_path_unsafe"


def test_a_key_that_cannot_be_replaced_is_a_policy_mismatch(tmp_path: Path, enclave: FakeEnclave) -> None:
    store = sealed_store(tmp_path / "mail", enclave)
    store.ensure_key(require_presence=False)

    def broken(_key_id: str) -> None:
        raise OSError("keychain unavailable")

    enclave.delete_enclave_key = broken  # type: ignore[method-assign]
    with pytest.raises(MailSecretsError) as raised:
        store.ensure_key(require_presence=True, replace=True)
    assert raised.value.code == "touch_id_policy_mismatch" and enclave.unattended == {KEY_ID: True}


def test_an_unavailable_enclave_is_tee_unavailable(tmp_path: Path, enclave: FakeEnclave) -> None:
    from mordred_hermes.keyvault._exceptions import WrapError

    def unavailable(_key_id: str) -> bytes:
        raise WrapError("helper missing")

    enclave.get_enclave_public_key = unavailable  # type: ignore[method-assign]
    with pytest.raises(MailSecretsError) as raised:
        sealed_store(tmp_path / "mail", enclave).ensure_key()
    assert raised.value.code == "tee_unavailable"
