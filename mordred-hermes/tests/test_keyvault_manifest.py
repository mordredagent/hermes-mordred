"""Tests for the ``MVMF`` vault manifest codec (integrity-critical registry).

The manifest is the vault's tamper-evident registry: the ONE canonical
SE-wrapped master (``wmk``), the enrolled-file set with each file's
ciphertext digest, and a monotonic ``generation`` counter. The codec
authenticates the whole body with :meth:`kek.MasterKey.mac` (HMAC-SHA256
under a master-derived subkey) so an offline attacker who tampers the
on-disk manifest cannot forge a valid tag without the master.

This codec is only one half of the rollback/substitution defence. The
vault layer additionally pins ``SHA-256(wmk)`` and ``generation`` in a
device-bound Keychain anchor (an offline attacker can read the disk but
cannot write the locked Keychain), which is what stops an attacker from
swapping in a whole vault sealed under *their own* SE key, or rolling
the manifest back to an older but validly-MAC'd snapshot. The codec here
only guarantees: body authenticity under the master + carrying the
generation so the vault layer can compare it to the anchor.

These run cross-platform — :class:`FakeBackend` performs a real P-256
ECDH so the seal/open path (and therefore the master key) is genuine on
Linux CI too; only the hardware Secure Enclave is stubbed.
"""

from __future__ import annotations

import base64
import json

import pytest

from mordred_hermes.keyvault import kek, manifest

from ._keyvault_fakes import FakeBackend

_KEY_ID = "mvmf-test-key"


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


def _manifest(wmk: bytes, *, generation: int = 1, files: dict[str, str] | None = None) -> manifest.VaultManifest:
    return manifest.VaultManifest(
        key_id=_KEY_ID,
        wmk=wmk,
        files={".env": "a" * 64, "config.yaml": "b" * 64} if files is None else files,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# round-trip
# ---------------------------------------------------------------------------


def test_round_trip(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    m = _manifest(wmk, generation=3)
    blob = manifest.encode(m, master)
    out = manifest.decode(blob, master)
    assert out.key_id == _KEY_ID
    assert out.wmk == wmk
    assert out.files == {".env": "a" * 64, "config.yaml": "b" * 64}
    assert out.generation == 3


def test_empty_vault_round_trips(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A vault with no enrolled files yet is a valid manifest."""
    wmk, master = sealed
    m = _manifest(wmk, generation=0, files={})
    out = manifest.decode(manifest.encode(m, master), master)
    assert out.files == {}
    assert out.generation == 0


def test_generation_is_preserved(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    out = manifest.decode(manifest.encode(_manifest(wmk, generation=42), master), master)
    assert out.generation == 42


# ---------------------------------------------------------------------------
# wire format
# ---------------------------------------------------------------------------


def test_body_is_mvmf_v1(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk), master)
    body = json.loads(blob.partition(b"\n")[0])
    assert body["fmt"] == "MVMF"
    assert body["ver"] == 1
    assert body["key_id"] == _KEY_ID
    assert base64.b64decode(body["wmk"], validate=True) == wmk
    assert body["generation"] == 1
    assert body["files"] == {".env": "a" * 64, "config.yaml": "b" * 64}


# ---------------------------------------------------------------------------
# integrity / tamper
# ---------------------------------------------------------------------------


def test_tampered_body_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """Editing a file digest in the body must break the MAC."""
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk), master)
    body_b, _, b64tag = blob.partition(b"\n")
    body = json.loads(body_b)
    body["files"][".env"] = "c" * 64  # swap in a different (older) digest
    tampered = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n" + b64tag
    with pytest.raises(manifest.ManifestError):
        manifest.decode(tampered, master)


def test_tampered_tag_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk), master)
    body_b, _, b64tag = blob.partition(b"\n")
    raw = bytearray(base64.b64decode(b64tag))
    raw[-1] ^= 0x01
    tampered = body_b + b"\n" + base64.b64encode(bytes(raw))
    with pytest.raises(manifest.ManifestError):
        manifest.decode(tampered, master)


def test_generation_rollback_breaks_mac(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """Rewinding the in-body generation without re-MACing must be rejected
    (the vault layer also pins it in the Keychain, but the body MAC alone
    already catches an in-place edit)."""
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk, generation=9), master)
    body_b, _, b64tag = blob.partition(b"\n")
    body = json.loads(body_b)
    body["generation"] = 1
    rolled = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n" + b64tag
    with pytest.raises(manifest.ManifestError):
        manifest.decode(rolled, master)


def test_wrong_master_rejected(backend: FakeBackend) -> None:
    """A manifest MAC'd under one master must not verify under another."""
    wmk_a = kek.seal_master_key(_KEY_ID, backend=backend)
    master_a = kek.open_master_key(wmk_a, _KEY_ID, backend=backend)
    blob = manifest.encode(_manifest(wmk_a), master_a)

    wmk_b = kek.seal_master_key(_KEY_ID, backend=backend)
    master_b = kek.open_master_key(wmk_b, _KEY_ID, backend=backend)
    with pytest.raises(manifest.ManifestError):
        manifest.decode(blob, master_b)


# ---------------------------------------------------------------------------
# malformed / structural
# ---------------------------------------------------------------------------


def test_missing_separator_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    _wmk, master = sealed
    with pytest.raises(manifest.ManifestError):
        manifest.decode(b"not-a-manifest", master)


def test_empty_blob_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    _wmk, master = sealed
    with pytest.raises(manifest.ManifestError):
        manifest.decode(b"", master)


def test_non_base64_tag_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    body_b = manifest.encode(_manifest(wmk), master).partition(b"\n")[0]
    with pytest.raises(manifest.ManifestError):
        manifest.decode(body_b + b"\nnot valid base64!!!", master)


def test_unsupported_version_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A correctly-MAC'd body with an unknown ``ver`` is rejected AFTER the
    MAC check (a future format must not be silently misparsed)."""
    wmk, master = sealed
    body = {
        "fmt": "MVMF",
        "ver": 2,
        "key_id": _KEY_ID,
        "wmk": base64.b64encode(wmk).decode("ascii"),
        "files": {},
        "generation": 0,
    }
    body_b = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    tag = master.mac(body_b, info=manifest._MANIFEST_MAC_INFO)
    blob = body_b + b"\n" + base64.b64encode(tag)
    with pytest.raises(manifest.ManifestError):
        manifest.decode(blob, master)


def test_files_must_be_object(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A correctly-MAC'd body whose ``files`` is not an object is rejected."""
    wmk, master = sealed
    body = {
        "fmt": "MVMF",
        "ver": 1,
        "key_id": _KEY_ID,
        "wmk": base64.b64encode(wmk).decode("ascii"),
        "files": ["not", "an", "object"],
        "generation": 0,
    }
    body_b = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    tag = master.mac(body_b, info=manifest._MANIFEST_MAC_INFO)
    blob = body_b + b"\n" + base64.b64encode(tag)
    with pytest.raises(manifest.ManifestError):
        manifest.decode(blob, master)


# ---------------------------------------------------------------------------
# encode-side validation
# ---------------------------------------------------------------------------


def test_empty_key_id_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    with pytest.raises(ValueError, match="key_id"):
        manifest.encode(manifest.VaultManifest(key_id="", wmk=wmk, files={}, generation=0), master)


def test_negative_generation_rejected(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    with pytest.raises(ValueError, match="generation"):
        manifest.encode(manifest.VaultManifest(key_id=_KEY_ID, wmk=wmk, files={}, generation=-1), master)


# ---------------------------------------------------------------------------
# parse_unverified — two-phase bootstrap (extract wmk to obtain the master)
# ---------------------------------------------------------------------------
#
# The vault layer cannot verify the manifest MAC until it has the master,
# and it cannot get the master without the wmk, which lives in the manifest.
# parse_unverified breaks that chicken-and-egg: it extracts wmk + generation
# WITHOUT authenticating, so the caller can unwrap the master and THEN call
# decode() to authenticate. It must therefore never be trusted on its own —
# the vault additionally pins SHA-256(wmk) + generation in the device-bound
# anchor (which an offline attacker cannot write) before trusting the wmk.


def test_parse_unverified_extracts_wmk_and_generation(sealed: tuple[bytes, kek.MasterKey]) -> None:
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk, generation=8), master)
    # No master argument — this is the pre-master bootstrap.
    out = manifest.parse_unverified(blob)
    assert out.wmk == wmk
    assert out.generation == 8
    assert out.key_id == _KEY_ID


def test_parse_unverified_does_not_check_mac(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """A tampered tag must NOT stop parse_unverified — authenticity is the
    job of decode() once the master is available. (The vault's anchor pin
    is what makes trusting the extracted wmk safe.)"""
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk), master)
    body_b, _, b64tag = blob.partition(b"\n")
    raw = bytearray(base64.b64decode(b64tag))
    raw[-1] ^= 0x01  # corrupt the tag
    tampered = body_b + b"\n" + base64.b64encode(bytes(raw))
    out = manifest.parse_unverified(tampered)  # must NOT raise
    assert out.wmk == wmk


def test_parse_unverified_still_rejects_structural_garbage(sealed: tuple[bytes, kek.MasterKey]) -> None:
    """It skips the MAC, not the structure: a non-manifest blob still fails
    (otherwise the vault would feed junk into the unwrap path)."""
    for bad in (b"", b"no-separator", b"{}\n" + base64.b64encode(b"x" * 32)):
        with pytest.raises(manifest.ManifestError):
            manifest.parse_unverified(bad)


# ---------------------------------------------------------------------------
# digest shape: files values must be sha256 hex (codex impl-review P2)
# ---------------------------------------------------------------------------
#
# A files value is used verbatim to build blobs/<digest>.blob, so a digest that
# is not 64-char lowercase hex is both malformed and a path-traversal vector.
# Enforce the shape at the codec — the single chokepoint both decode() and
# parse_unverified() pass through.

_BAD_DIGESTS = [
    "a" * 63,  # too short
    "a" * 65,  # too long
    "g" * 64,  # right length, non-hex character
    "A" * 64,  # uppercase — not what sha256 hexdigest() emits
    "../../../etc/passwd",  # path-traversal shaped
    "",  # empty
]


@pytest.mark.parametrize("bad", _BAD_DIGESTS)
def test_decode_rejects_non_hex_digest_values(sealed: tuple[bytes, kek.MasterKey], bad: str) -> None:
    """A non-hex digest is rejected even with a valid MAC."""
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk, files={".env": bad}), master)
    with pytest.raises(manifest.ManifestError):
        manifest.decode(blob, master)


@pytest.mark.parametrize("bad", _BAD_DIGESTS)
def test_parse_unverified_rejects_non_hex_digest_values(sealed: tuple[bytes, kek.MasterKey], bad: str) -> None:
    """parse_unverified keeps the digest-shape check — it feeds the unwrap path
    before the MAC is verified."""
    wmk, master = sealed
    blob = manifest.encode(_manifest(wmk, files={".env": bad}), master)
    with pytest.raises(manifest.ManifestError):
        manifest.parse_unverified(blob)
