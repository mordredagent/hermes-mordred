"""Tests for the durable ``confirm_generate`` lifecycle phase."""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import re
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage, api, wrap
from tests._keyvault_fakes import FakeBackend
from tests._keyvault_lifecycle_helpers import (
    _FAR_PAST,
    _PLACEHOLDER_DIGEST,
    _SPEC_PASSPHRASE,
    _SPEC_POW,
    _SPEC_SEED,
    _AuditCapture,
    _FailingAuditCapture,
    _make_handle,
)

# ============================ confirm_generate (durable phase) ============================
#
# Contract frozen in SPEC.md §"PR4 API contract / Two-phase generate" +
# POLICY.md §"Phase 4 PR4 step-0 freeze" (audit codes #21-23):
#
#     def confirm_generate(handle, user_confirmed_digest, *, key_id=None,
#                          backend, audit_sink, home=None) -> GenerateResult:
#         # Verifies user_confirmed_digest matches handle._expected_digest
#         #   via hmac.compare_digest.
#         # Mismatch: emit keyvault.init_denied, raise VerificationDigestMismatch,
#         #   NO Keychain / filesystem mutation.
#         # Match:
#         #   1. Emit keyvault.init_started (durability barrier — sink failure aborts).
#         #   2. wrap.generate_wrapping_key(key_id, backend=...).
#         #   3. Write meta.json + digests/<key_id_hash_hex>.commit atomically
#         #      under keyvault_lock. Rollback (delete Enclave key) on any failure.
#         #   4. Emit keyvault.init_completed (sink failure suppressed).
#
# NOTE: ``backend`` is keyword-only and REQUIRED here (no default), matching
# the merged ``encrypt`` / ``decrypt`` surface. Keeping backend selection at
# the caller makes the hardware boundary explicit and keeps tests injectable.


_ISO8601_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _prepared(
    seed: str = _SPEC_SEED,
    passphrase: str = _SPEC_PASSPHRASE,
    pow_bytes: bytes = _SPEC_POW,
) -> tuple[Any, bytes]:
    """A fresh ``(handle, expected_digest)`` pair from prepare_generate.

    confirm_generate is a pure reader of the handle (it does not consume),
    so a handle could be reused — but each test mints its own pair anyway
    to keep tests independent.
    """
    return api.prepare_generate(seed, passphrase, pow_bytes)


def _storage_key_id_hash(key_id: str) -> str:
    """The 32-hex-char on-disk hash (meta.json key + digests/<...>.commit)."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def audit() -> _AuditCapture:
    return _AuditCapture()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """Hermes home root; the keyvault lives at ``home/mordred/keyvault``.
    confirm_generate creates the layout itself (no pre-created fixture).
    """
    return tmp_path


@pytest.fixture
def kv_root(home: Path) -> Path:
    return home / "mordred" / "keyvault"


class TestGenerateResult:
    """``GenerateResult`` is the frozen return type of confirm_generate /
    generate — carries the resolved key_id (the caller may have passed
    None), its on-disk hash, and the creation timestamp.
    """

    def test_is_frozen_dataclass(self) -> None:
        assert dataclasses.is_dataclass(api.GenerateResult)
        result = api.GenerateResult(
            key_id="default",
            key_id_hash="00" * 16,
            created_at="2026-05-15T07:30:00Z",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.key_id = "other"  # type: ignore[misc]

    def test_carries_the_three_fields(self) -> None:
        result = api.GenerateResult(
            key_id="default",
            key_id_hash="ab" * 16,
            created_at="2026-05-15T07:30:00Z",
        )
        assert result.key_id == "default"
        assert result.key_id_hash == "ab" * 16
        assert result.created_at == "2026-05-15T07:30:00Z"


class TestConfirmGenerateHappyPath:
    """Digest matches → Enclave key created, meta.json + digests commit
    persisted, init_started/init_completed emitted in order.
    """

    def test_returns_generate_result(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert isinstance(result, api.GenerateResult)

    def test_default_key_id_resolves_to_default(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert result.key_id == "default"

    def test_explicit_key_id_used_verbatim(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(
            handle, digest, key_id="signing-key", backend=backend, audit_sink=audit, home=home
        )
        assert result.key_id == "signing-key"

    def test_key_id_hash_is_sha256_prefix_hex(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert result.key_id_hash == _storage_key_id_hash("default")
        assert len(result.key_id_hash) == 32  # 16 bytes hex-encoded

    def test_created_at_is_iso8601_utc(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert _ISO8601_UTC_RE.match(result.created_at), result.created_at
        datetime.datetime.strptime(result.created_at, "%Y-%m-%dT%H:%M:%SZ")

    def test_enclave_key_is_generated(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        root = _storage.resolve_keyvault_dir(home)
        pub = wrap.get_wrapping_key_public(
            "default",
            backend=backend,
            native_key_id=_native_key_id.scoped_native_key_id(root, "default"),
        )
        assert len(pub) == 65  # SEC1 uncompressed P-256

    def test_meta_json_row_written(self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        meta = _storage.load_meta(kv_root)
        entry = meta["keys"][result.key_id_hash]
        assert entry["key_id"] == "default"
        assert entry["created_at"] == result.created_at

    def test_digest_commit_file_written(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        commit_path = kv_root / "digests" / f"{result.key_id_hash}.commit"
        assert commit_path.exists()
        assert _storage.safe_read(commit_path) == digest

    def test_audit_emits_started_then_completed(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert [e["reason"] for e in audit.log] == [
            "keyvault.init_started",
            "keyvault.init_completed",
        ]

    def test_init_started_fields(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        started = audit.log[0]
        assert started["event"] == "keyvault.init"
        assert started["decision"] == "allow"
        assert started["reason"] == "keyvault.init_started"
        assert started["key_id_hash"] == wrap._audit_key_id_hex("default")

    def test_init_completed_fields(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, digest = _prepared()
        api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        completed = audit.log[1]
        assert completed["event"] == "keyvault.init"
        assert completed["decision"] == "allow"
        assert completed["reason"] == "keyvault.init_completed"
        assert completed["key_id_hash"] == wrap._audit_key_id_hex("default")
        assert completed["verification_digest_hex_prefix"] == digest[:8].hex()

    def test_confirm_does_not_consume_the_handle(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        """confirm_generate is a pure reader of the handle (codex pre-merge
        P1): it reads ``_expected_digest`` + ``_deadline`` but never calls
        ``consume()``. ``consume()`` is the *display flow's* egress for the
        seed; if confirm_generate also consumed, a real
        prepare → display-seed (consume) → confirm flow could not complete.
        The handle's seed payload is therefore still intact after a confirm.
        """
        handle, digest = _prepared()
        api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        # The handle was NOT consumed — consume() still works (and returns
        # the normalized seed), proving confirm_generate left it untouched.
        assert handle.consume() == _SPEC_SEED


class TestConfirmGenerateMismatch:
    """User-confirmed digest does NOT match → init_denied + raise, no mutation."""

    def test_wrong_digest_raises_verification_mismatch(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path
    ) -> None:
        handle, _digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch):
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=audit, home=home)

    def test_mismatch_emits_only_init_denied(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, _digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch):
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=audit, home=home)
        assert [e["reason"] for e in audit.log] == ["keyvault.init_denied"]

    def test_init_denied_fields(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, _digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch):
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=audit, home=home)
        denied = audit.log[0]
        assert denied["event"] == "keyvault.init"
        assert denied["decision"] == "block"
        assert denied["reason"] == "keyvault.init_denied"
        assert denied["key_id_hash"] == wrap._audit_key_id_hex("default")

    def test_mismatch_generates_no_enclave_key(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle, _digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch):
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=audit, home=home)
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound; key never created
            wrap.get_wrapping_key_public("default", backend=backend)

    def test_mismatch_touches_no_filesystem_state(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        """POLICY.md #23: init_denied is emitted before any filesystem
        state is touched — the keyvault layout is never even created.
        """
        handle, _digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch):
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=audit, home=home)
        assert not kv_root.exists()

    def test_mismatch_leaves_handle_reusable(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        """confirm_generate does not consume the handle (codex P1), so a
        mismatch does not burn it — the caller can retry confirm_generate
        with the corrected digest and succeed (e.g. the user fixed a
        transcription typo). No fresh prepare_generate is required.
        """
        handle, digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch):
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=audit, home=home)
        # Retry with the correct digest on the SAME handle — succeeds.
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert isinstance(result, api.GenerateResult)


class TestConfirmGenerateKeyIdValidation:
    """Invalid main-key ids fail before audit, filesystem, or native mutation."""

    @pytest.mark.parametrize("key_id", ["", "mordred.audit-log", "\ud800"])
    def test_empty_or_reserved_key_id_is_rejected_before_mutation(
        self,
        key_id: str,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
    ) -> None:
        handle, digest = _prepared()

        with pytest.raises(_native_key_id.InvalidMainKeyId):
            api.confirm_generate(
                handle,
                digest,
                key_id=key_id,
                backend=backend,
                audit_sink=audit,
                home=home,
            )

        assert backend.calls == []
        assert audit.log == []
        assert not kv_root.exists()


class TestConfirmGenerateAuditFailure:
    """The 3 audit emits have 3 distinct sink-failure policies."""

    def test_init_started_sink_failure_aborts_the_init(self, backend: FakeBackend, home: Path) -> None:
        """init_started is the durability barrier: if the sink raises, the
        whole init aborts — no Enclave key, no meta.json.
        """
        sink = _FailingAuditCapture("keyvault.init_started")
        handle, digest = _prepared()
        with pytest.raises(RuntimeError) as excinfo:
            api.confirm_generate(handle, digest, backend=backend, audit_sink=sink, home=home)
        assert excinfo.value is sink.boom
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound
            wrap.get_wrapping_key_public("default", backend=backend)

    def test_init_started_sink_failure_writes_no_meta(self, backend: FakeBackend, home: Path, kv_root: Path) -> None:
        sink = _FailingAuditCapture("keyvault.init_started")
        handle, digest = _prepared()
        with pytest.raises(RuntimeError):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=sink, home=home)
        assert not kv_root.exists()

    def test_init_completed_sink_failure_is_suppressed(self, backend: FakeBackend, home: Path, kv_root: Path) -> None:
        """init_completed fires after the init is already durable — a sink
        exception is suppressed, confirm_generate still returns normally.
        """
        sink = _FailingAuditCapture("keyvault.init_completed")
        handle, digest = _prepared()
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=sink, home=home)
        assert isinstance(result, api.GenerateResult)
        meta = _storage.load_meta(kv_root)
        assert result.key_id_hash in meta["keys"]
        pub = wrap.get_wrapping_key_public(
            "default",
            backend=backend,
            native_key_id=_native_key_id.scoped_native_key_id(kv_root, "default"),
        )
        assert len(pub) == 65

    def test_init_denied_sink_failure_chains_as_context(self, backend: FakeBackend, home: Path) -> None:
        """If the sink raises while emitting init_denied, that exception is
        chained as ``__context__`` on the VerificationDigestMismatch.
        """
        sink = _FailingAuditCapture("keyvault.init_denied")
        handle, _digest = _prepared()
        with pytest.raises(api.VerificationDigestMismatch) as excinfo:
            api.confirm_generate(handle, b"\x11" * 32, backend=backend, audit_sink=sink, home=home)
        assert excinfo.value.__context__ is sink.boom


class TestConfirmGenerateRollback:
    """A failure in the durable phase (after the Enclave key exists) rolls
    back cleanly — Enclave key deleted, no stale filesystem state.

    Transaction order (codex pre-merge P2): the digest commit file is
    written FIRST, then ``meta.json`` LAST. ``meta.json`` is the commit
    point — ``atomic_write`` replaces it atomically (tmp+rename), so a
    failure leaves the prior ``meta.json`` intact. Rollback therefore only
    has to delete the Enclave key and the orphaned commit file; it never
    has to repair a half-written ``meta.json``.
    """

    def test_meta_write_failure_rolls_back_enclave_key(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handle, digest = _prepared()

        def boom_save_meta(root: Path, meta: dict[str, Any]) -> None:
            raise OSError("disk full while writing meta.json")

        monkeypatch.setattr(_storage, "save_meta", boom_save_meta)
        with pytest.raises(OSError, match="disk full"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound; key rolled back
            wrap.get_wrapping_key_public("default", backend=backend)

    def test_meta_write_failure_leaves_no_stale_filesystem_state(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """codex P2: a meta-write failure must not leave a digests/<kid>.commit
        file (written first, in the same transaction) advertising a key whose
        Keychain item was just rolled back. meta.json itself stays clean
        because save_meta replaces it atomically.
        """
        handle, digest = _prepared()
        key_id_hash = _storage_key_id_hash("default")

        def boom_save_meta(root: Path, meta: dict[str, Any]) -> None:
            raise OSError("disk full while writing meta.json")

        monkeypatch.setattr(_storage, "save_meta", boom_save_meta)
        with pytest.raises(OSError, match="disk full"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        # The commit file written earlier in the transaction is removed.
        assert not (kv_root / "digests" / f"{key_id_hash}.commit").exists()
        # meta.json carries no row for the rolled-back key.
        meta = _storage.load_meta(kv_root)
        assert key_id_hash not in meta["keys"]

    def test_commit_file_write_failure_rolls_back(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If the digest commit file (written FIRST) fails, the Enclave key
        is rolled back and meta.json never gained a row.
        """
        handle, digest = _prepared()
        key_id_hash = _storage_key_id_hash("default")
        real_atomic_write = _storage.atomic_write

        def selective_boom(path: Path, data: bytes) -> None:
            if str(path).endswith(".commit"):
                raise OSError("disk full while writing commit file")
            real_atomic_write(path, data)

        monkeypatch.setattr(_storage, "atomic_write", selective_boom)
        with pytest.raises(OSError, match="commit file"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound; key rolled back
            wrap.get_wrapping_key_public("default", backend=backend)
        meta = _storage.load_meta(kv_root)
        assert key_id_hash not in meta["keys"]

    def test_meta_write_failure_reraises_original_error(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handle, digest = _prepared()

        def boom_save_meta(root: Path, meta: dict[str, Any]) -> None:
            raise OSError("disk full while writing meta.json")

        monkeypatch.setattr(_storage, "save_meta", boom_save_meta)
        with pytest.raises(OSError, match="disk full"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)

    def test_save_meta_partial_commit_is_repaired(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """codex pre-merge P2: save_meta's atomic rename can commit the new
        meta.json before a later fsync raises. The rollback must re-open
        meta.json and drop the row so it does not advertise a key whose
        Keychain item was rolled back. Simulated by a save_meta that really
        writes, then raises.
        """
        handle, digest = _prepared()
        key_id_hash = _storage_key_id_hash("default")
        real_save_meta = _storage.save_meta

        save_count = 0

        def commit_then_boom(root: Path, meta: dict[str, Any]) -> None:
            nonlocal save_count
            save_count += 1
            real_save_meta(root, meta)  # the atomic rename commits meta.json
            if save_count == 2:  # row + pending ownership commit
                raise OSError("parent-dir fsync failed after meta.json was committed")

        monkeypatch.setattr(_storage, "save_meta", commit_then_boom)
        with pytest.raises(OSError, match="fsync failed"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        # The row that briefly landed on disk has been repaired away.
        meta = _storage.load_meta(kv_root)
        assert key_id_hash not in meta["keys"]
        # And the Enclave key was rolled back too.
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound
            wrap.get_wrapping_key_public("default", backend=backend)

    def test_post_replace_failure_and_delete_failure_retains_row_plus_pending_fail_closed(
        self,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class DeleteFailBackend(FakeBackend):
            def delete_enclave_key(self, key_id: str) -> None:
                self.calls.append(("delete", key_id))
                raise OSError("native delete transport failed")

        backend = DeleteFailBackend()
        handle, digest = _prepared()
        key_id_hash = _storage_key_id_hash("default")
        real_save_meta = _storage.save_meta
        save_count = 0

        def ownership_commit_then_boom(root: Path, meta: dict[str, Any]) -> None:
            nonlocal save_count
            save_count += 1
            real_save_meta(root, meta)
            if save_count == 2:
                raise OSError("parent-dir fsync failed after ownership rename")

        monkeypatch.setattr(_storage, "save_meta", ownership_commit_then_boom)
        with pytest.raises(OSError, match="ownership rename"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)

        meta = _storage.load_meta(kv_root)
        physical = _native_key_id.scoped_native_key_id(kv_root, "default")
        assert meta["keys"][key_id_hash][_native_key_id.NATIVE_KEY_ID_FIELD] == physical
        assert _native_key_id.pending_native_key_from_meta(kv_root, meta) == ("default", physical)

        backend.calls.clear()
        with pytest.raises(_storage.KeyvaultCorruptError, match="provisioning is incomplete"):
            api.encrypt(
                "default",
                b"must-not-use-uncertain-key",
                "secret",
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        assert backend.calls == []

    def test_pending_cleanup_failure_leaves_owned_key_fail_closed_without_rollback(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handle, digest = _prepared()
        real_save_meta = _storage.save_meta
        save_count = 0

        def fail_before_pending_cleanup(root: Path, meta: dict[str, Any]) -> None:
            nonlocal save_count
            save_count += 1
            if save_count == 3:
                raise OSError("pending cleanup write failed")
            real_save_meta(root, meta)

        monkeypatch.setattr(_storage, "save_meta", fail_before_pending_cleanup)
        with pytest.raises(OSError, match="pending cleanup"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)

        meta = _storage.load_meta(kv_root)
        assert _native_key_id.PENDING_NATIVE_KEY_FIELD in meta
        assert not any(operation == "delete" for operation, _key_id in backend.calls)
        with pytest.raises(_storage.KeyvaultCorruptError, match="provisioning is incomplete"):
            api.encrypt(
                "default",
                b"blocked",
                "secret",
                backend=backend,
                audit_sink=audit,
                home=home,
            )

    def test_post_replace_pending_cleanup_error_accepts_verified_visible_commit(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        handle, digest = _prepared()
        real_save_meta = _storage.save_meta
        save_count = 0

        def cleanup_commit_then_boom(root: Path, meta: dict[str, Any]) -> None:
            nonlocal save_count
            save_count += 1
            real_save_meta(root, meta)
            if save_count == 3:
                raise OSError("parent-dir fsync failed after pending cleanup")

        monkeypatch.setattr(_storage, "save_meta", cleanup_commit_then_boom)
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)

        assert result.key_id == "default"
        assert _native_key_id.PENDING_NATIVE_KEY_FIELD not in _storage.load_meta(kv_root)
        envelope_id = api.encrypt(
            "default",
            b"committed",
            "secret",
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert envelope_id


class TestConfirmGenerateHandleExpiry:
    """An expired handle is rejected before any digest check or audit emit."""

    def test_expired_handle_raises_seed_display_expired(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path
    ) -> None:
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            api.confirm_generate(handle, _PLACEHOLDER_DIGEST, backend=backend, audit_sink=audit, home=home)

    def test_expired_handle_emits_no_audit(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            api.confirm_generate(handle, _PLACEHOLDER_DIGEST, backend=backend, audit_sink=audit, home=home)
        assert audit.log == []

    def test_expired_handle_touches_no_filesystem(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            api.confirm_generate(handle, _PLACEHOLDER_DIGEST, backend=backend, audit_sink=audit, home=home)
        assert not kv_root.exists()

    def test_expired_handle_payload_is_wiped(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        """codex pre-merge P2: when confirm_generate is the first code path
        to observe an expired handle (the display flow never consumed it),
        the seed bytes must be wiped — they must not outlive the deadline.
        """
        handle = _make_handle(deadline=_FAR_PAST)
        original_payload = handle._payload  # type: ignore[attr-defined]
        assert any(b != 0 for b in original_payload)  # sanity: starts non-zero
        with pytest.raises(api.SeedDisplayExpired):
            api.confirm_generate(handle, _PLACEHOLDER_DIGEST, backend=backend, audit_sink=audit, home=home)
        assert all(b == 0 for b in original_payload), "expired handle's seed payload must be wiped"


class TestConfirmGenerateReInit:
    """v1 keyvault is single-key (SPEC Story 5). Once any key is
    initialized, a second confirm_generate is rejected by the re-init
    guard — checked under the keyvault lock against meta["keys"] (codex
    pre-merge P2) — and the existing key is NOT disturbed.
    """

    def test_pending_reset_journal_rejects_before_init_started(
        self,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
    ) -> None:
        kv_root.parent.mkdir(mode=0o700, parents=True)
        with _storage.keyvault_lifecycle_lock(kv_root):
            _storage.write_reset_journal(kv_root, b"pending reset")
        handle, digest = _prepared()

        with pytest.raises(_storage.KeyvaultResetInProgressError, match="reset"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)

        assert audit.log == []
        assert backend.calls == []
        assert not kv_root.exists()

    @pytest.mark.parametrize(
        "field",
        [
            _native_key_id.AUDIT_KEY_FIELD,
            _native_key_id.PENDING_AUDIT_KEY_FIELD,
        ],
    )
    def test_residual_audit_ownership_rejects_before_any_mutation(
        self,
        field: str,
        backend: FakeBackend,
        audit: _AuditCapture,
        home: Path,
        kv_root: Path,
    ) -> None:
        _storage.ensure_layout(kv_root)
        meta = _storage.load_meta(kv_root)
        meta[field] = {"residual": True}
        _storage.save_meta(kv_root, meta)
        before_meta = _storage.safe_read(kv_root / "meta.json")
        handle, digest = _prepared()

        with pytest.raises(RuntimeError, match="already initialized"):
            api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)

        assert audit.log == []
        assert backend.calls == []
        assert _storage.safe_read(kv_root / "meta.json") == before_meta
        assert list((kv_root / "digests").iterdir()) == []

    def test_reinit_same_key_id_rejected(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        h1, d1 = _prepared()
        api.confirm_generate(h1, d1, backend=backend, audit_sink=audit, home=home)
        h2, d2 = _prepared()
        with pytest.raises(RuntimeError, match="already initialized"):
            api.confirm_generate(h2, d2, backend=backend, audit_sink=audit, home=home)

    def test_reinit_with_different_key_id_rejected(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        """codex P2: a second confirm with a DIFFERENT explicit key_id must
        not slip past — the re-init guard keys off "any key exists", not a
        per-key_id duplicate check, so it cannot append a second meta row.
        """
        h1, d1 = _prepared()
        api.confirm_generate(h1, d1, backend=backend, audit_sink=audit, home=home)
        h2, d2 = _prepared()
        with pytest.raises(RuntimeError, match="already initialized"):
            api.confirm_generate(h2, d2, key_id="second-key", backend=backend, audit_sink=audit, home=home)
        # meta.json still has exactly the one original key.
        meta = _storage.load_meta(kv_root)
        assert len(meta["keys"]) == 1
        assert _storage_key_id_hash("second-key") not in meta["keys"]

    def test_reinit_attempt_preserves_existing_key(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        """A rejected re-init must NOT delete or disturb the legitimate
        existing key — the rollback path only cleans up keys THIS call
        created, and the re-init guard rejects before any key is generated.
        """
        h1, d1 = _prepared()
        first = api.confirm_generate(h1, d1, backend=backend, audit_sink=audit, home=home)
        h2, d2 = _prepared()
        with pytest.raises(RuntimeError, match="already initialized"):
            api.confirm_generate(h2, d2, backend=backend, audit_sink=audit, home=home)
        pub = wrap.get_wrapping_key_public(
            "default",
            backend=backend,
            native_key_id=_native_key_id.scoped_native_key_id(kv_root, "default"),
        )
        assert len(pub) == 65
        meta = _storage.load_meta(kv_root)
        assert first.key_id_hash in meta["keys"]
