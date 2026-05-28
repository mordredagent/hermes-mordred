"""RED tests for Phase 4 PR6: ``keyvault.log_encryption``.

SPEC.md §Audit log policy / §Audit-log encryption coupling + PLAN.md L549:

- :class:`EncryptedWriter` is an AES-GCM-encrypting implementation of the
  Phase 1 ``Writer`` Protocol frozen in
  :mod:`mordred_hermes.privacy_check.audit`. Phase 4 factory-swaps it in
  for :class:`~mordred_hermes.privacy_check.audit.NDJSONWriter`.
- The audit-log data-encryption key (DEK) is **keyvault-wrapped** — only
  the wrapped blob touches disk (in the file header); the plaintext DEK
  lives in process memory for the writer's lifetime.
- Each entry is encrypted independently and written as one base64 line so
  a single ``append`` stays whole-entry atomic and no whole-file rewrite
  is ever needed.
- :func:`decrypt_log_file` is the reader side the ``audit decrypt`` CLI
  (PR8) drives; it unwraps the DEK through the Secure Enclave
  authorization boundary (``wrap.unwrap_dek``).

These tests use a software ``FakeBackend`` P-256 keypair store (copied
from ``test_keyvault_wrap.py``) in place of the Secure Enclave so the
crypto / wire-format paths are exercised with real AES-GCM + AES-KW.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mordred_hermes.keyvault import log_encryption as le
from mordred_hermes.keyvault._exceptions import WrapError, WrapKeyNotFound
from mordred_hermes.keyvault.wrap import NativeBackendError, NativeErrorCode

AuditSink = Callable[[dict[str, Any]], None]


class FakeBackend:
    """Software P-256 keypair store standing in for the Secure Enclave.

    Mirrors ``test_keyvault_wrap.FakeBackend`` — ``enclave_ecdh`` performs
    real ECDH; ``denied_reason`` simulates an authorization-prompt denial.
    """

    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.denied_reason: NativeErrorCode | None = None
        self.calls: list[tuple[str, str]] = []

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        self.calls.append(("generate", key_id))
        if key_id in self._keys:
            raise WrapKeyNotFound(f"key {key_id!r} already exists")
        priv = ec.generate_private_key(ec.SECP256R1())
        self._keys[key_id] = priv
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def get_enclave_public_key(self, key_id: str) -> bytes:
        self.calls.append(("get_pub", key_id))
        if key_id not in self._keys:
            raise WrapKeyNotFound(f"no key for {key_id!r}")
        return self._keys[key_id].public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def delete_enclave_key(self, key_id: str) -> None:
        self.calls.append(("delete", key_id))
        self._keys.pop(key_id, None)

    def enclave_ecdh(self, key_id: str, peer_pub: bytes) -> bytes:
        self.calls.append(("ecdh", key_id))
        if self.denied_reason is not None:
            raise NativeBackendError(self.denied_reason)
        if key_id not in self._keys:
            raise WrapKeyNotFound(f"no key for {key_id!r}")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._keys[key_id].exchange(ec.ECDH(), peer)


@pytest.fixture
def backend() -> FakeBackend:
    """A FakeBackend with the audit-log wrapping key pre-generated."""
    be = FakeBackend()
    be.generate_enclave_key(le.AUDIT_LOG_KEY_ID)
    return be


@pytest.fixture
def captured_audit() -> tuple[list[dict[str, Any]], AuditSink]:
    entries: list[dict[str, Any]] = []

    def sink(entry: dict[str, Any]) -> None:
        entries.append(entry)

    return entries, sink


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


# ---------------------------------------------------------------------------
# Writer Protocol conformance + basic roundtrip
# ---------------------------------------------------------------------------


def test_encrypted_writer_satisfies_writer_surface(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    assert callable(w.append)
    assert callable(w.close)


def test_roundtrip_single_entry(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "keyvault.unwrap_authorized", "decision": "allow"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert len(entries) == 1
    assert entries[0]["event"] == "keyvault.unwrap_authorized"
    assert entries[0]["decision"] == "allow"


def test_roundtrip_multiple_entries_preserves_order(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    for i in range(5):
        w.append({"event": "policy.strict.clearnet", "seq": i})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert [e["seq"] for e in entries] == [0, 1, 2, 3, 4]


def test_non_ascii_entry_roundtrips(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet", "note": "ネットワーク遮断"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert entries[0]["note"] == "ネットワーク遮断"


# ---------------------------------------------------------------------------
# Encryption: plaintext never hits disk
# ---------------------------------------------------------------------------


def test_append_does_not_write_plaintext(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "keyvault.unwrap_authorized", "secret_marker": "TOPSECRET-XYZ"})
    w.close()

    raw = log_path.read_bytes()
    assert b"TOPSECRET-XYZ" not in raw
    assert b"unwrap_authorized" not in raw


def test_dek_is_wrapped_not_plaintext_in_header(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    header_line = log_path.read_bytes().split(b"\n", 1)[0]
    header = json.loads(header_line)
    assert header["fmt"] == "MRAL"
    assert header["ver"] == le.FORMAT_VERSION
    assert header["key_id"] == le.AUDIT_LOG_KEY_ID

    wrapped = base64.b64decode(header["wdek"])
    # The header carries a wrap.py MRKW blob (127 bytes), not a raw DEK.
    assert wrapped[:4] == b"MRKW"
    assert len(wrapped) == 127


def test_header_is_first_line_only(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "a"})
    w.append({"event": "b"})
    w.close()

    lines = log_path.read_bytes().splitlines()
    assert len(lines) == 3  # 1 header + 2 entries
    assert json.loads(lines[0])["fmt"] == "MRAL"
    # entry lines are opaque base64, not JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(lines[1])


# ---------------------------------------------------------------------------
# ``ts`` injection contract (Writer Protocol invariant #1)
# ---------------------------------------------------------------------------

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def test_ts_injected_with_millisecond_precision(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert _TS_RE.match(entries[0]["ts"])


def test_caller_supplied_ts_is_preserved(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"ts": "2020-01-01T00:00:00.000Z", "event": "policy.strict.clearnet"})
    w.close()

    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert entries[0]["ts"] == "2020-01-01T00:00:00.000Z"


# ---------------------------------------------------------------------------
# File mode (Writer Protocol invariant #3)
# ---------------------------------------------------------------------------


def test_active_file_is_mode_0600(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()
    assert (log_path.stat().st_mode & 0o777) == 0o600


def test_parent_dir_created_mode_0700(tmp_path: Path, backend: FakeBackend) -> None:
    nested = tmp_path / "mordred" / "audit.log"
    w = le.EncryptedWriter(nested, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()
    assert (nested.parent.stat().st_mode & 0o777) == 0o700


# ---------------------------------------------------------------------------
# Entry size cap
# ---------------------------------------------------------------------------


def test_oversized_entry_rejected(log_path: Path, backend: FakeBackend) -> None:
    w = le.EncryptedWriter(log_path, backend=backend)
    with pytest.raises(ValueError, match="bytes"):
        w.append({"event": "policy.strict.clearnet", "blob": "x" * 5000})


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tampered_entry_line_rejected(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    lines = log_path.read_bytes().splitlines()
    entry = bytearray(base64.b64decode(lines[1]))
    entry[-1] ^= 0x01  # flip a tag bit
    lines[1] = base64.b64encode(bytes(entry))
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises((le.AuditLogDecryptError, InvalidTag)):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_tampered_header_rejected(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    lines = log_path.read_bytes().splitlines()
    header = json.loads(lines[0])
    wrapped = bytearray(base64.b64decode(header["wdek"]))
    wrapped[-1] ^= 0x01  # corrupt the wrapped DEK
    header["wdek"] = base64.b64encode(bytes(wrapped)).decode()
    lines[0] = json.dumps(header).encode()
    log_path.write_bytes(b"\n".join(lines) + b"\n")

    with pytest.raises((le.AuditLogDecryptError, WrapError, InvalidTag)):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_plaintext_ndjson_file_is_rejected_by_reader(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    log_path.write_text('{"ts":"2026-05-16T00:00:00.000Z","event":"policy.strict.clearnet"}\n')
    with pytest.raises(le.AuditLogDecryptError):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_empty_file_is_rejected_by_reader(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    log_path.write_bytes(b"")
    with pytest.raises(le.AuditLogDecryptError):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_entry_from_another_file_cannot_be_spliced_in(
    tmp_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    """AAD binds each entry to its file header — cross-file replay fails."""
    _, sink = captured_audit
    path_a = tmp_path / "a.log"
    path_b = tmp_path / "b.log"

    wa = le.EncryptedWriter(path_a, backend=backend)
    wa.append({"event": "policy.strict.clearnet", "src": "A"})
    wa.close()
    wb = le.EncryptedWriter(path_b, backend=backend)
    wb.append({"event": "policy.strict.clearnet", "src": "B"})
    wb.close()

    stolen = path_a.read_bytes().splitlines()[1]
    b_lines = path_b.read_bytes().splitlines()
    b_lines.append(stolen)
    path_b.write_bytes(b"\n".join(b_lines) + b"\n")

    with pytest.raises((le.AuditLogDecryptError, InvalidTag)):
        le.decrypt_log_file(path_b, backend=backend, audit_sink=sink)


# ---------------------------------------------------------------------------
# Authorization boundary: unwrap emits audit
# ---------------------------------------------------------------------------


def test_decrypt_emits_unwrap_authorized_audit(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    entries, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    # wrap.unwrap_dek emits event=keyvault.unwrap_dek, reason=keyvault.unwrap_authorized
    assert any(e.get("reason") == "keyvault.unwrap_authorized" for e in entries)


def test_decrypt_denied_when_authorization_cancelled(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    backend.denied_reason = "user_cancelled"
    with pytest.raises((le.AuditLogDecryptError, WrapError)):
        le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)


def test_writer_never_calls_authorization_boundary(log_path: Path, backend: FakeBackend) -> None:
    """``wrap_dek`` is offline — writing never triggers ``enclave_ecdh``."""
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()
    assert not any(op == "ecdh" for op, _ in backend.calls)


# ---------------------------------------------------------------------------
# Rotation + retention
# ---------------------------------------------------------------------------


def test_size_cap_rotation_produces_decryptable_files(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    _, sink = captured_audit
    w = le.EncryptedWriter(log_path, backend=backend, rotate_bytes=600)
    for i in range(8):
        w.append({"event": "policy.strict.clearnet", "seq": i})
    w.close()

    rotated = sorted(p for p in log_path.parent.iterdir() if p.name != log_path.name)
    assert rotated, "expected at least one rotated file"

    # active file still decrypts
    active = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert active, "active file should hold entries"

    # rotated (gzipped) files decrypt too — fresh DEK + header each
    total = len(active)
    for rp in rotated:
        total += len(le.decrypt_log_file(rp, backend=backend, audit_sink=sink))
    assert total == 8


def test_date_change_triggers_rotation(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = captured_audit
    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-16")
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet", "day": 1})

    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-17")
    w.append({"event": "policy.strict.clearnet", "day": 2})
    w.close()

    rotated = [p for p in log_path.parent.iterdir() if p.name != log_path.name]
    assert len(rotated) == 1
    active = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert [e["day"] for e in active] == [2]


def test_rotated_gzip_file_decrypts(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sink = captured_audit
    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-16")
    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet", "day": 1})
    monkeypatch.setattr(le, "_today_utc_date", lambda: "2026-05-17")
    w.append({"event": "policy.strict.clearnet", "day": 2})
    w.close()

    gz = log_path.with_name("audit.log.2026-05-16.gz")
    assert gz.exists()
    assert gz.read_bytes()[:2] == b"\x1f\x8b"  # gzip magic
    rotated = le.decrypt_log_file(gz, backend=backend, audit_sink=sink)
    assert [e["day"] for e in rotated] == [1]


# ---------------------------------------------------------------------------
# Pre-existing file handling
# ---------------------------------------------------------------------------


def test_legacy_plaintext_file_is_rotated_aside(
    log_path: Path,
    backend: FakeBackend,
    captured_audit: tuple[list[dict[str, Any]], AuditSink],
) -> None:
    """A pre-Phase-4 plaintext NDJSON file is moved aside, not overwritten."""
    _, sink = captured_audit
    log_path.write_text('{"ts":"2026-05-15T00:00:00.000Z","event":"legacy.entry"}\n')

    w = le.EncryptedWriter(log_path, backend=backend)
    w.append({"event": "policy.strict.clearnet"})
    w.close()

    # active file is now a fresh encrypted log
    entries = le.decrypt_log_file(log_path, backend=backend, audit_sink=sink)
    assert entries[0]["event"] == "policy.strict.clearnet"

    # the legacy plaintext survives in a rotated file
    rotated = [p for p in log_path.parent.iterdir() if p.name != log_path.name]
    assert len(rotated) == 1
    blob = rotated[0]
    data = gzip.decompress(blob.read_bytes()) if blob.suffix == ".gz" else blob.read_bytes()
    assert b"legacy.entry" in data
