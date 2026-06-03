"""Phase 4 PR4 step-E RED — ``api.export_backup`` / ``api.import_backup``.

Implementation lands in step-E GREEN. The ciphertext-rewrap manifest
contract is frozen in SPEC.md §"export_backup / import_backup
(ciphertext-rewrap manifest, codex BLOCKER #1)" (L768-897):

- ``export_backup`` walks every ``.gcm`` envelope, unwraps each DEK,
  re-encrypts the plaintext under a *portable* manifest AAD (no per-device
  MRKW prefix), packs a JSON manifest, and wraps it in a PR2 ``MRKV`` blob
  whose passphrase-derived KEK protects the manifest (and the DEKs it
  carries) at rest.
- ``import_backup`` verifies the embedded verification digest BEFORE any
  KDF / decryption (PR2 verify-before-decrypt), then on the destination
  device generates a fresh Enclave key, re-wraps each DEK against it, and
  reconstructs every MREN envelope.

Enclave authorization is abstracted by the ``FakeBackend`` reused from
``test_keyvault_wrap`` — a software P-256 keypair store. Two distinct
``FakeBackend`` instances + two ``home`` roots model two physical
devices, which is the only honest way to exercise cross-machine
recovery: the source Enclave key is non-exportable, so the destination
must reconstruct everything from the passphrase-protected manifest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _storage, api, backup
from mordred_hermes.keyvault.backup import BackupCorrupt
from mordred_hermes.keyvault.recovery import RecoveryDigestMismatch

# Software Enclave stand-in — see module docstring of test_keyvault_wrap.
from tests.test_keyvault_wrap import FakeBackend

# Canonical inputs. ASCII so the split-normalization layer is a no-op and
# the digest is stable regardless of NFKD behavior.
SEED = "test seed phrase one two three four"
PASSPHRASE = "correct horse battery staple"
POW = bytes(range(32))


# ----------------------------- fixtures -----------------------------


@pytest.fixture
def audit() -> tuple[list[dict[str, Any]], Any]:
    log: list[dict[str, Any]] = []

    def sink(entry: dict[str, Any]) -> None:
        log.append(dict(entry))

    return log, sink


def _init_device(home: Path, backend: FakeBackend, sink: Any) -> str:
    """Generate a keyvault key on a device rooted at ``home``."""
    _handle, digest = api.prepare_generate(SEED, PASSPHRASE, POW)
    result = api.generate(SEED, PASSPHRASE, POW, digest, backend=backend, audit_sink=sink, home=home)
    return result.key_id


def _key_id_hash_hex(key_id: str) -> str:
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


# ----------------------------- export blob shape -----------------------------


class TestExportBlob:
    def test_export_returns_parseable_mrkv_blob(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)

        blob = api.export_backup(key_id, PASSPHRASE, backend=backend, audit_sink=sink, home=home)

        assert blob[:4] == b"MRKV"
        # The PR2 backup parser must accept it without complaint.
        parsed = backup.parse_header(blob)
        assert parsed.version == backup.VERSION

    def test_export_embeds_commit_verification_digest(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """The blob's embedded digest is the one written to
        ``digests/<kid>.commit`` at generate time — that is what
        ``import_backup`` recomputes and checks against."""
        _log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)

        commit_path = home / "mordred" / "keyvault" / "digests" / f"{_key_id_hash_hex(key_id)}.commit"
        commit_digest = _storage.safe_read(commit_path)

        blob = api.export_backup(key_id, PASSPHRASE, backend=backend, audit_sink=sink, home=home)
        assert backup.parse_header(blob).verification_digest == commit_digest

    def test_export_emits_backup_exported(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        log.clear()

        api.export_backup(key_id, PASSPHRASE, backend=backend, audit_sink=sink, home=home)

        exported = [e for e in log if e.get("reason") == "keyvault.backup_exported"]
        assert len(exported) == 1

    def test_export_audit_fields_match_policy(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        """POLICY.md #24: event=keyvault.backup_export, decision=allow,
        key_id_hash, blob_version=1, kdf_id=1, envelope_count."""
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        api.encrypt(key_id, b"one", "alpha", backend=backend, audit_sink=sink, home=home)
        api.encrypt(key_id, b"two", "beta", backend=backend, audit_sink=sink, home=home)
        log.clear()

        api.export_backup(key_id, PASSPHRASE, backend=backend, audit_sink=sink, home=home)

        entry = next(e for e in log if e.get("reason") == "keyvault.backup_exported")
        assert entry["event"] == "keyvault.backup_export"
        assert entry["decision"] == "allow"
        assert entry["blob_version"] == 1
        assert entry["kdf_id"] == 1
        assert entry["envelope_count"] == 2
        # key_id_hash is the 16-char audit hex prefix, never the cleartext id.
        assert entry["key_id_hash"] and key_id not in str(entry["key_id_hash"])

    def test_export_empty_keyvault_envelope_count_zero(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        log, sink = audit
        backend = FakeBackend()
        home = tmp_path / "deviceA"
        key_id = _init_device(home, backend, sink)
        log.clear()

        blob = api.export_backup(key_id, PASSPHRASE, backend=backend, audit_sink=sink, home=home)

        assert blob[:4] == b"MRKV"
        entry = next(e for e in log if e.get("reason") == "keyvault.backup_exported")
        assert entry["envelope_count"] == 0

    def test_export_sink_failure_on_backup_exported_is_suppressed(self, tmp_path: Path) -> None:
        """POLICY.md #24: success-path emit suppressed via
        contextlib.suppress — the blob is already in hand."""
        backend = FakeBackend()
        home = tmp_path / "deviceA"

        def init_sink(_entry: dict[str, Any]) -> None:
            return None

        _handle, digest = api.prepare_generate(SEED, PASSPHRASE, POW)
        result = api.generate(SEED, PASSPHRASE, POW, digest, backend=backend, audit_sink=init_sink, home=home)

        def failing_sink(entry: dict[str, Any]) -> None:
            if entry.get("reason") == "keyvault.backup_exported":
                raise RuntimeError("audit log disk full")

        blob = api.export_backup(result.key_id, PASSPHRASE, backend=backend, audit_sink=failing_sink, home=home)
        assert blob[:4] == b"MRKV"


# ----------------------------- cross-machine roundtrip -----------------------------


class TestCrossMachineRoundtrip:
    def test_single_envelope_roundtrip(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        # Device A: generate, encrypt, export.
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        eid = api.encrypt(key_id, b"the-secret-payload", "vault", backend=backend_a, audit_sink=sink, home=home_a)
        blob = api.export_backup(key_id, PASSPHRASE, backend=backend_a, audit_sink=sink, home=home_a)

        # Device B: a fresh Enclave + a fresh home — the source key is gone.
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )
        assert imported == key_id

        recovered = api.decrypt(imported, eid, "vault", backend=backend_b, audit_sink=sink, home=home_b)
        assert recovered == b"the-secret-payload"

    def test_multiple_purposes_roundtrip(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        items = {
            "alpha": b"payload-alpha",
            "beta": b"payload-beta-longer-value",
            "gamma": b"",
        }
        eids = {
            purpose: api.encrypt(key_id, pt, purpose, backend=backend_a, audit_sink=sink, home=home_a)
            for purpose, pt in items.items()
        }
        blob = api.export_backup(key_id, PASSPHRASE, backend=backend_a, audit_sink=sink, home=home_a)

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )

        for purpose, expected in items.items():
            got = api.decrypt(imported, eids[purpose], purpose, backend=backend_b, audit_sink=sink, home=home_b)
            assert got == expected

    def test_empty_keyvault_roundtrip_key_usable_after_import(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """Exporting a keyvault with zero envelopes still transports the
        key; the destination can encrypt + decrypt afterwards."""
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        blob = api.export_backup(key_id, PASSPHRASE, backend=backend_a, audit_sink=sink, home=home_a)

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )

        eid = api.encrypt(imported, b"post-import", "fresh", backend=backend_b, audit_sink=sink, home=home_b)
        assert api.decrypt(imported, eid, "fresh", backend=backend_b, audit_sink=sink, home=home_b) == b"post-import"

    def test_import_creates_meta_row_and_commit_digest(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        api.encrypt(key_id, b"x", "p", backend=backend_a, audit_sink=sink, home=home_a)
        blob = api.export_backup(key_id, PASSPHRASE, backend=backend_a, audit_sink=sink, home=home_a)

        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"
        imported = api.import_backup(
            blob, PASSPHRASE, seed_phrase=SEED, pow_bytes=POW, backend=backend_b, audit_sink=sink, home=home_b
        )

        root_b = home_b / "mordred" / "keyvault"
        meta = _storage.load_meta(root_b)
        assert _key_id_hash_hex(imported) in meta["keys"]
        commit = root_b / "digests" / f"{_key_id_hash_hex(imported)}.commit"
        assert _storage.safe_read(commit) == backup.parse_header(blob).verification_digest


# ----------------------------- import rejection paths -----------------------------


class TestImportRejection:
    def _exported_blob(self, tmp_path: Path, sink: Any) -> bytes:
        backend_a = FakeBackend()
        home_a = tmp_path / "deviceA"
        key_id = _init_device(home_a, backend_a, sink)
        api.encrypt(key_id, b"secret", "p", backend=backend_a, audit_sink=sink, home=home_a)
        return api.export_backup(key_id, PASSPHRASE, backend=backend_a, audit_sink=sink, home=home_a)

    def test_wrong_passphrase_raises_recovery_mismatch(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                "wrong-passphrase-entirely",
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

    def test_wrong_seed_phrase_raises_recovery_mismatch(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                PASSPHRASE,
                seed_phrase="totally different seed phrase here now",
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

    def test_corrupt_blob_raises_backup_corrupt(self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]) -> None:
        _log, sink = audit
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(BackupCorrupt):
            api.import_backup(
                b"this is not a valid MRKV backup blob at all",
                PASSPHRASE,
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )

    def test_digest_mismatch_creates_no_enclave_key(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        """Verify-before-decrypt: a mismatch must reject BEFORE the
        destination Enclave key is generated (SPEC import step 2 — steps
        1-5 are pre-mutation)."""
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                "wrong-passphrase",
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )
        assert backend_b.calls == [], "no Enclave operation may run on a rejected import"

    def test_digest_mismatch_writes_no_ciphertexts(
        self, tmp_path: Path, audit: tuple[list[dict[str, Any]], Any]
    ) -> None:
        _log, sink = audit
        blob = self._exported_blob(tmp_path, sink)
        backend_b = FakeBackend()
        home_b = tmp_path / "deviceB"

        with pytest.raises(RecoveryDigestMismatch):
            api.import_backup(
                blob,
                "wrong-passphrase",
                seed_phrase=SEED,
                pow_bytes=POW,
                backend=backend_b,
                audit_sink=sink,
                home=home_b,
            )
        cipher_dir = home_b / "mordred" / "keyvault" / "ciphertexts" / _key_id_hash_hex("default")
        assert not cipher_dir.exists()


# ----------------------------- audit reason freeze -----------------------------


def test_backup_exported_is_now_in_freeze() -> None:
    """Step-E lands the ``api.export_backup`` emit site, so #24
    ``keyvault.backup_exported`` graduates into the ``ReasonCode`` Literal
    (POLICY.md freeze discipline: freeze a code only once it has an emit
    site). This replaces the prior
    ``test_backup_exported_deliberately_not_frozen_yet``."""
    from typing import get_args

    from mordred_hermes.privacy_check._audit_reasons import ReasonCode

    assert "keyvault.backup_exported" in get_args(ReasonCode)


class TestImportBackupManifestValidation:
    """``import_backup`` must reject a structurally-malformed (but AES-GCM-
    authenticated) manifest with ``BackupCorrupt`` BEFORE generating the
    destination Enclave key — not propagate a raw ``KeyError`` / ``TypeError``
    and generate-then-roll-back a phantom key.
    """

    def _import_crafted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        manifest_json: bytes,
        backend: FakeBackend,
    ) -> str:
        # Bypass the real recovery (digest verify + AES-GCM decrypt) so the
        # crafted manifest reaches api's post-decrypt validation directly.
        monkeypatch.setattr(api.recovery, "import_backup", lambda *a, **k: manifest_json)
        return api.import_backup(
            b"dummy-blob",
            "passphrase",
            seed_phrase="abandon " * 24,
            pow_bytes=b"\x00" * 32,
            backend=backend,
            audit_sink=lambda e: None,
            home=tmp_path,
        )

    def test_missing_key_id_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "envelopes": []}).encode("utf-8")
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == [], "no Enclave key may be generated for a malformed manifest"

    def test_envelopes_not_a_list_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "key_id": "default", "envelopes": "nope"}).encode("utf-8")
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []

    def test_key_id_not_str_is_backup_corrupt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        backend = FakeBackend()
        bad = json.dumps({"version": 1, "key_id": 123, "envelopes": []}).encode("utf-8")
        with pytest.raises(BackupCorrupt):
            self._import_crafted(monkeypatch, tmp_path, bad, backend)
        assert backend.calls == []
