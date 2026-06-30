"""Tests for the ``MVLT`` generic encrypted-file container (vault at-rest codec).

Replaces the earlier env-specific ``MENV`` codec: encrypts arbitrary file
*bytes* (``.env``, ``config.yaml``, an individual memory file) under the SE+KEK
master key, rather than ``KEY=value`` entries.

A single Secure-Enclave unwrap (:func:`kek.open_master_key`) yields a
:class:`kek.MasterKey`; the codec then runs software AES-GCM over the whole file
at memory speed. These run cross-platform — :class:`FakeBackend` performs a real
P-256 ECDH so the seal/open path (and therefore the master key) is genuine on
Linux CI too; only the hardware Secure Enclave is stubbed.

Wire format ``MVLT`` v1::

    line 0   header   {"fmt":"MVLT","ver":1,"key_id":<str>,"wmk":<b64>,"name":<str>}
    \n
    body              base64( nonce(12) ‖ ciphertext ‖ tag(16) )

The body's AES-GCM AAD binds it to ``SHA-256(header)`` *and* the file's logical
``name``, so a blob cannot be lifted onto another logical file, replayed under a
tampered header, or have its name rewritten to match a different decode target.
"""

from __future__ import annotations

import base64
import json

import pytest

from mordred_hermes.keyvault import file_container, kek

from ._keyvault_fakes import FakeBackend

_KEY_ID = "mvlt-test-key"


@pytest.fixture
def backend() -> FakeBackend:
    b = FakeBackend()
    b.generate_enclave_key(_KEY_ID)
    return b


@pytest.fixture
def sealed(backend: FakeBackend) -> tuple[bytes, kek.MasterKey]:
    """Return ``(wmk, master)`` from one full seal/open round-trip."""
    wmk = kek.seal_master_key(_KEY_ID, backend=backend)
    master = kek.open_master_key(wmk, _KEY_ID, backend=backend)
    return wmk, master


# ---------------------------------------------------------------------------
# round-trip
# ---------------------------------------------------------------------------


def test_round_trip(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    data = b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\n"
    blob = file_container.encode(master, data, key_id=_KEY_ID, wmk=wmk, name=".env")
    assert file_container.decode(blob, master, name=".env") == data


def test_binary_content_round_trips(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    data = bytes(range(256)) * 4  # includes \n (0x0a) and NUL (0x00)
    blob = file_container.encode(master, data, key_id=_KEY_ID, wmk=wmk, name="config.yaml")
    assert file_container.decode(blob, master, name="config.yaml") == data


def test_empty_content_round_trips(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = file_container.encode(master, b"", key_id=_KEY_ID, wmk=wmk, name=".env")
    assert file_container.decode(blob, master, name=".env") == b""


def test_tree_relative_name_round_trips(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A memory file's relative path (with slashes) is a valid logical name."""
    wmk, master = sealed
    data = b"# note\n"
    blob = file_container.encode(master, data, key_id=_KEY_ID, wmk=wmk, name="notes/2026/foo.md")
    assert file_container.decode(blob, master, name="notes/2026/foo.md") == data


# ---------------------------------------------------------------------------
# wire format
# ---------------------------------------------------------------------------


def test_header_is_mvlt_v1(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = file_container.encode(master, b"x", key_id=_KEY_ID, wmk=wmk, name=".env")
    header = json.loads(blob.split(b"\n", 1)[0])
    assert header["fmt"] == "MVLT"
    assert header["ver"] == 1
    assert header["key_id"] == _KEY_ID
    assert header["name"] == ".env"
    assert base64.b64decode(header["wmk"], validate=True) == wmk


def test_body_carries_no_plaintext(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    secret = b"super-secret-token-value"
    blob = file_container.encode(master, secret, key_id=_KEY_ID, wmk=wmk, name=".env")
    assert secret not in blob


# ---------------------------------------------------------------------------
# integrity / tamper
# ---------------------------------------------------------------------------


def test_tampered_body_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = file_container.encode(master, b"value", key_id=_KEY_ID, wmk=wmk, name=".env")
    header_b, _, b64 = blob.partition(b"\n")
    raw = bytearray(base64.b64decode(b64))
    raw[-1] ^= 0x01  # flip a tag bit
    tampered = header_b + b"\n" + base64.b64encode(bytes(raw))
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(tampered, master, name=".env")


def test_tampered_header_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = file_container.encode(master, b"value", key_id=_KEY_ID, wmk=wmk, name=".env")
    header_b, _, b64 = blob.partition(b"\n")
    header = json.loads(header_b)
    header["key_id"] = "different-key"  # AAD binds to SHA-256(header)
    tampered = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n" + b64
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(tampered, master, name=".env")


def test_wrong_name_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A blob sealed for ``.env`` must not decode under another logical name."""
    wmk, master = sealed
    blob = file_container.encode(master, b"v", key_id=_KEY_ID, wmk=wmk, name=".env")
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(blob, master, name="config.yaml")


def test_name_swapped_in_header_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """Rewriting the header ``name`` to match the decode target still fails:
    the AAD bound the original name into the ciphertext tag."""
    wmk, master = sealed
    blob = file_container.encode(master, b"v", key_id=_KEY_ID, wmk=wmk, name=".env")
    header_b, _, b64 = blob.partition(b"\n")
    header = json.loads(header_b)
    header["name"] = "config.yaml"
    swapped = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n" + b64
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(swapped, master, name="config.yaml")


def test_wrong_master_rejected(backend: FakeBackend) -> None:
    """A blob sealed under one master must not decode under a different master."""
    wmk_a = kek.seal_master_key(_KEY_ID, backend=backend)
    master_a = kek.open_master_key(wmk_a, _KEY_ID, backend=backend)
    blob = file_container.encode(master_a, b"v", key_id=_KEY_ID, wmk=wmk_a, name=".env")

    wmk_b = kek.seal_master_key(_KEY_ID, backend=backend)
    master_b = kek.open_master_key(wmk_b, _KEY_ID, backend=backend)
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(blob, master_b, name=".env")


# ---------------------------------------------------------------------------
# malformed input
# ---------------------------------------------------------------------------


def test_empty_blob_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    _wmk, master = sealed
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(b"", master, name=".env")


def test_plaintext_file_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A legacy plaintext file must be refused, not silently misread."""
    _wmk, master = sealed
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(b"FOO=bar\n", master, name=".env")


def test_non_base64_body_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = file_container.encode(master, b"v", key_id=_KEY_ID, wmk=wmk, name=".env")
    header_b, _, _b64 = blob.partition(b"\n")
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(header_b + b"\nnot valid base64!!!", master, name=".env")


# ---------------------------------------------------------------------------
# encode-side validation
# ---------------------------------------------------------------------------


def test_empty_name_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    with pytest.raises(ValueError, match="name"):
        file_container.encode(master, b"x", key_id=_KEY_ID, wmk=wmk, name="")


def test_empty_name_on_decode_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """decode mirrors encode-side name validation (name is a security boundary)."""
    wmk, master = sealed
    blob = file_container.encode(master, b"v", key_id=_KEY_ID, wmk=wmk, name=".env")
    with pytest.raises(ValueError, match="name"):
        file_container.decode(blob, master, name="")


def test_short_body_rejected_as_encrypted_file_error(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A body that base64-decodes to fewer bytes than nonce(12)+tag(16) must
    surface as EncryptedFileError, not a raw ValueError from the cipher layer."""
    wmk, master = sealed
    blob = file_container.encode(master, b"v", key_id=_KEY_ID, wmk=wmk, name=".env")
    header_b, _, _b64 = blob.partition(b"\n")
    short_body = base64.b64encode(b"\x00\x00\x00\x00")  # 4 bytes < 28-byte minimum token
    with pytest.raises(file_container.EncryptedFileError):
        file_container.decode(header_b + b"\n" + short_body, master, name=".env")
