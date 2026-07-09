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

    def test_downgrade_preserves_existing_encrypted_log(self, tmp_path: Path) -> None:
        """A degraded fallback must not corrupt an existing MRAL log.

        Codex PR #40 review (P1): if ``audit.log`` is already a Phase 4
        ``MRAL``-encrypted file and the keyvault later breaks, the fallback
        ``NDJSONWriter`` must not ``O_APPEND`` plaintext onto the ciphertext
        stream — that would make ``audit decrypt`` fail for the whole file.
        The encrypted log is rotated aside (still decryptable) and a fresh
        plaintext ``audit.log`` is started.
        """
        _init_meta(tmp_path)
        log_path = tmp_path / "audit.log"

        # A prior session wrote an encrypted MRAL log.
        enc_backend = FakeBackend()
        enc_backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        enc = make_audit_writer(log_path, keyvault_home=tmp_path, backend=enc_backend)
        assert isinstance(enc, EncryptedWriter)
        enc.append({"event": "policy.strict.clearnet"})
        enc.close()

        # The keyvault breaks (audit-log wrapping key gone) — degraded path.
        broken = FakeBackend()  # AUDIT_LOG_KEY_ID intentionally not generated
        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=broken)
        assert isinstance(writer, NDJSONWriter)

        # The MRAL log was rotated aside, not appended onto — and the
        # original encrypted entry is still decryptable.
        rotated = sorted(p for p in tmp_path.iterdir() if p.name.startswith("audit.log."))
        assert rotated, "the encrypted log must be rotated aside, not corrupted"
        entries = decrypt_log_file(rotated[-1], backend=enc_backend, audit_sink=lambda e: None)
        assert entries[0]["event"] == "policy.strict.clearnet"

        # The fresh active log is plaintext NDJSON carrying the downgrade marker.
        assert _DOWNGRADE_REASON in _audit_reasons(log_path)

    def test_uninitialized_with_stale_encrypted_log_rotates_it_aside(self, tmp_path: Path) -> None:
        """A de-initialized keyvault must also not corrupt a stale MRAL log.

        If the keyvault made encrypted logs and was later de-initialized,
        ``make_audit_writer`` returns an ``NDJSONWriter`` via the
        keyvault-uninitialized path — which must also rotate the stale
        ``MRAL`` log aside rather than append plaintext onto it. This path
        stays silent (no downgrade marker — an uninitialized keyvault is
        the baseline).
        """
        _init_meta(tmp_path)
        log_path = tmp_path / "audit.log"
        enc_backend = FakeBackend()
        enc_backend.generate_enclave_key(AUDIT_LOG_KEY_ID)
        enc = make_audit_writer(log_path, keyvault_home=tmp_path, backend=enc_backend)
        enc.append({"event": "policy.strict.tor"})
        enc.close()

        # De-initialize the keyvault: drop every key row.
        root = _storage.resolve_keyvault_dir(tmp_path)
        meta = _storage.load_meta(root)
        meta["keys"].clear()
        _storage.save_meta(root, meta)

        writer = make_audit_writer(log_path, keyvault_home=tmp_path, backend=enc_backend)
        assert isinstance(writer, NDJSONWriter)

        rotated = sorted(p for p in tmp_path.iterdir() if p.name.startswith("audit.log."))
        assert rotated, "the stale encrypted log must be rotated aside"
        entries = decrypt_log_file(rotated[-1], backend=enc_backend, audit_sink=lambda e: None)
        assert entries[0]["event"] == "policy.strict.tor"
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


class TestSharedBuildAuditWriter:
    """``_audit_support.build_audit_writer`` — the factory ``network`` /
    ``llm_guard`` use for the shared ``audit.log`` — must route through
    ``privacy_check.audit.make_audit_writer`` (audit HIGH #3). Otherwise those
    two plugins write plaintext NDJSON lines into an MRAL-encrypted log,
    leaking audit metadata at rest and breaking ``audit decrypt`` for the whole
    day's trail.
    """

    def test_delegates_to_make_audit_writer_with_log_bound_home(self, monkeypatch, tmp_path: Path) -> None:
        import mordred_hermes.privacy_check.audit as pc_audit
        from mordred_hermes import _audit_support

        seen: list[tuple[Path, Path]] = []
        sentinel = object()

        def fake_make(path: Path, *, keyvault_home: Path) -> object:
            seen.append((path, keyvault_home))
            return sentinel

        # build_audit_writer imports make_audit_writer lazily from this module,
        # so patching the attribute here is what the delegation resolves to.
        monkeypatch.setattr(pc_audit, "make_audit_writer", fake_make)
        audit_path = tmp_path / "mordred" / "audit.log"
        result = _audit_support.build_audit_writer(audit_path)
        assert result is sentinel
        # Encryption state is bound to THIS log's HERMES_BASE
        # (audit_path.parent.parent), matching privacy_check — not the ambient
        # default home.
        assert seen == [(audit_path, tmp_path)]
