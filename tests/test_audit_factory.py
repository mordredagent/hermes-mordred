"""Tests for the privacy_check audit-writer factory (Phase 4 PR10 step-E).

L465: once the keyvault is initialized, privacy_check must construct an
:class:`EncryptedWriter` instead of an :class:`NDJSONWriter` so the audit
log is AES-GCM-encrypted at rest.

``make_audit_writer`` is **fail-open**: an uninitialized keyvault, a
corrupt keyvault, a missing audit-log wrapping key, or an unavailable
native backend all fall back to :class:`NDJSONWriter` so privacy_check
never stops auditing.
"""

from __future__ import annotations

import json
from pathlib import Path

from mordred_hermes.keyvault import _storage
from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID, EncryptedWriter, decrypt_log_file
from mordred_hermes.privacy_check.audit import NDJSONWriter, make_audit_writer
from tests._keyvault_fakes import FakeBackend

#: The degraded-marker reason an encrypted→plaintext audit downgrade emits.
_DOWNGRADE_REASON = "mordred.degraded.audit_encryption_unavailable"


def _audit_reasons(log_path: Path) -> list[str]:
    """Return the ``reason`` of every NDJSON entry in ``log_path`` (or [])."""
    if not log_path.exists():
        return []
    reasons: list[str] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            reasons.append(str(json.loads(line).get("reason", "")))
    return reasons


def _init_meta(home: Path) -> None:
    """Mark the keyvault initialized — a ``meta.json`` carrying one key row."""
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    meta["keys"]["00112233445566778899aabbccddeeff"] = {
        "key_id": "default",
        "created_at": "2026-05-16T00:00:00Z",
    }
    _storage.save_meta(root, meta)


class TestMakeAuditWriter:
    def test_uninitialized_keyvault_returns_ndjson(self, tmp_path: Path) -> None:
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path)
        assert isinstance(writer, NDJSONWriter)

    def test_initialized_with_audit_key_returns_encrypted(self, tmp_path: Path) -> None:
        _init_meta(tmp_path)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=backend)
        assert isinstance(writer, EncryptedWriter)

    def test_initialized_without_audit_key_falls_back_to_ndjson(self, tmp_path: Path) -> None:
        _init_meta(tmp_path)
        backend = FakeBackend()  # AUDIT_LOG_KEY_ID intentionally not generated
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=backend)
        assert isinstance(writer, NDJSONWriter)

    def test_corrupt_keyvault_falls_back_to_ndjson(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ this is not valid json", encoding="utf-8")
        writer = make_audit_writer(tmp_path / "audit.log", keyvault_home=tmp_path, backend=FakeBackend())
        assert isinstance(writer, NDJSONWriter)

    def test_initialized_without_audit_key_emits_downgrade_marker(self, tmp_path: Path) -> None:
        """An encrypted→plaintext downgrade must leave a trace in the audit log.

        The keyvault is initialized, so encryption was *expected*; the
        missing audit-log wrapping key forces a plaintext fallback. That
        downgrade is security-relevant and must be visible in the trail,
        not only in Python logging.
        """
        _init_meta(tmp_path)
        log_path = tmp_path / "audit.log"
        backend = FakeBackend()  # AUDIT_LOG_KEY_ID intentionally not generated

        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=backend)

        assert isinstance(writer, NDJSONWriter)
        assert _DOWNGRADE_REASON in _audit_reasons(log_path)

    def test_corrupt_keyvault_emits_downgrade_marker(self, tmp_path: Path) -> None:
        """A corrupt keyvault also emits the downgrade marker."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ this is not valid json", encoding="utf-8")
        log_path = tmp_path / "audit.log"

        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=FakeBackend())

        assert isinstance(writer, NDJSONWriter)
        assert _DOWNGRADE_REASON in _audit_reasons(log_path)

    def test_uninitialized_keyvault_emits_no_downgrade_marker(self, tmp_path: Path) -> None:
        """A never-initialized keyvault is the baseline, not a downgrade.

        The pre-keyvault plaintext NDJSON path must stay silent — emitting
        a degraded marker on every session of an install that never had a
        keyvault would be noise, not signal.
        """
        log_path = tmp_path / "audit.log"

        writer = make_audit_writer(log_path, keyvault_home=tmp_path)

        assert isinstance(writer, NDJSONWriter)
        assert _DOWNGRADE_REASON not in _audit_reasons(log_path)

    def test_factory_encrypted_writer_roundtrips(self, tmp_path: Path) -> None:
        """A factory-produced EncryptedWriter writes a decryptable MRAL log."""
        _init_meta(tmp_path)
        backend = FakeBackend()
        backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        log_path = tmp_path / "audit.log"
        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=backend)
        writer.append({"event": "policy.strict.clearnet"})
        writer.close()
        entries = decrypt_log_file(log_path, backend=backend, audit_sink=lambda entry: None)
        assert entries[0]["event"] == "policy.strict.clearnet"
