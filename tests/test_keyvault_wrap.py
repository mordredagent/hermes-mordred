"""RED tests for Phase 4 PR3 step-B: ``wrap_dek`` / ``unwrap_dek``.

Contract is frozen in SPEC.md §Wrap wire format & algorithm (Phase 4
PR3 freeze, 2026-05-14): 127-byte blob, raw P-256 ECDH + HKDF-SHA256 +
AES-KW (RFC 3394), HKDF ``info`` binds every non-secret field for
integrity (codex review HIGH-2 — AES-KW has no AAD).

These tests use a ``FakeBackend`` that simulates the Secure Enclave
with a software P-256 keypair (from ``cryptography``). The Enclave
authorization boundary is the only thing the Protocol abstracts: HKDF,
AES-KW, and wire-format parsing are exercised with real crypto so a
buggy mock cannot mask format / KDF drift (codex review MEDIUM-4).

Negative tests cover (codex review LOW-1):

- Invalid EC point import (wrong prefix, off-curve).
- Wrong ``key_id`` (``key_id_hash`` mismatch).
- Tampered ``ephemeral_pub`` / ``wrapped_dek`` (integrity).
- Missing Keychain item (``WrapKeyNotFound``).
- Auth cancelled / failed (``WrapAuthCancelled`` with translated
  ``native_error_code``).
- Audit-sink exception chaining.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from mordred_hermes.keyvault._exceptions import WrapKeyAlreadyExists, WrapKeyNotFound
from mordred_hermes.keyvault.wrap import NativeBackendError, NativeErrorCode

AuditSink = Callable[[dict[str, Any]], None]


class FakeBackend:
    """Software P-256 keypair store, stands in for the Secure Enclave.

    Each ``key_id`` maps to a freshly generated ``cryptography`` P-256
    private key. ``enclave_ecdh`` performs real ECDH against a supplied
    peer public key. Authorization failure paths are simulated by
    setting ``denied_reason`` before the call.

    review-fix-1 MEDIUM-2: ``WrapKeyNotFound`` and ``NativeBackendError``
    are imported at module level (not deferred inside each method).
    No real circularity exists — ``_exceptions`` and ``wrap`` have no
    test-file dependencies — so the deferred form only served to hide
    typos from mypy. Module-level imports let mypy catch a rename or
    move at collect time instead of test runtime.
    """

    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        # Narrowed to ``NativeErrorCode | None`` (review-fix-2 MEDIUM-1)
        # — only the 5 frozen translated codes can be assigned, so a
        # typo in a test value surfaces at mypy time.
        self.denied_reason: NativeErrorCode | None = None
        self.calls: list[tuple[str, str]] = []  # (op, key_id)

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        self.calls.append(("generate", key_id))
        if key_id in self._keys:
            raise WrapKeyAlreadyExists(f"key {key_id!r} already exists")
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
        self._keys.pop(key_id, None)  # idempotent

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
    return FakeBackend()


@pytest.fixture
def captured_audit() -> tuple[list[dict[str, Any]], AuditSink]:
    entries: list[dict[str, Any]] = []

    def sink(entry: dict[str, Any]) -> None:
        entries.append(entry)

    return entries, sink


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------


class TestWireFormat:
    """SPEC.md §Wrap wire format & algorithm byte layout:
    ``MRKW|version(1)|alg_suite(1)|key_id_hash(16)|ephemeral_pub(65)|
    wrapped_dek(40)`` = 127 bytes."""

    def test_blob_is_127_bytes_for_version_1(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        assert len(blob) == 127

    def test_blob_starts_with_mrkw_magic(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        assert blob[:4] == b"MRKW"

    def test_blob_version_and_alg_suite_bytes(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        assert blob[4] == 1  # version
        assert blob[5] == 1  # alg_suite (P256+HKDF-SHA256+AES-KW)

    def test_key_id_hash_is_sha256_prefix(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        expected = hashlib.sha256(b"k1").digest()[:16]
        assert blob[6:22] == expected

    def test_ephemeral_pub_is_sec1_uncompressed_p256(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        ephemeral_pub = blob[22:87]
        assert len(ephemeral_pub) == 65
        assert ephemeral_pub[0] == 0x04  # uncompressed prefix per SEC1

    def test_wrapped_dek_is_40_bytes(self, backend: FakeBackend) -> None:
        """RFC 3394 AES-KW for a 32-byte input → 40-byte output (8 bytes
        of fixed AIV are prepended inside AES-KW)."""
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        assert len(blob[87:]) == 40

    def test_wrap_is_non_deterministic(self, backend: FakeBackend) -> None:
        """Codex BLOCKER-2 follow-up: wrap MUST generate a fresh ephemeral
        keypair every call. Two calls with the same DEK and key_id produce
        different blobs."""
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        dek = secrets.token_bytes(32)
        blob1 = wrap_dek(dek, "k1", backend=backend)
        blob2 = wrap_dek(dek, "k1", backend=backend)

        assert blob1 != blob2
        assert blob1[22:87] != blob2[22:87]  # different ephemeral_pub


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_unwrap_recovers_original_dek(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        dek = secrets.token_bytes(32)
        blob = wrap_dek(dek, "k1", backend=backend)

        recovered = unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        assert recovered == dek

    @pytest.mark.parametrize("iteration", range(20))
    def test_round_trip_random_deks(
        self,
        iteration: int,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key(f"k{iteration}", backend=backend)
        dek = secrets.token_bytes(32)
        blob = wrap_dek(dek, f"k{iteration}", backend=backend)

        assert unwrap_dek(blob, f"k{iteration}", audit_sink=sink, backend=backend) == dek


# ---------------------------------------------------------------------------
# parse_header rejections
# ---------------------------------------------------------------------------


class TestParseRejections:
    """All rejections surface as :class:`WrapParseError` and happen BEFORE
    any Enclave call — so a tampered blob never triggers a biometric
    prompt (UX + privacy)."""

    def _good_blob(self, backend: FakeBackend, key_id: str = "k1") -> bytes:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key(key_id, backend=backend)
        return wrap_dek(secrets.token_bytes(32), key_id, backend=backend)

    def test_wrong_length_rejected(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        with pytest.raises(WrapParseError):
            unwrap_dek(b"too short", "k1", audit_sink=sink, backend=backend)

    def test_wrong_magic_rejected(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        blob = self._good_blob(backend)
        tampered = b"XXXX" + blob[4:]

        with pytest.raises(WrapParseError):
            unwrap_dek(tampered, "k1", audit_sink=sink, backend=backend)

    def test_unknown_version_rejected(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        blob = self._good_blob(backend)
        tampered = blob[:4] + b"\x02" + blob[5:]

        with pytest.raises(WrapParseError):
            unwrap_dek(tampered, "k1", audit_sink=sink, backend=backend)

    def test_unknown_alg_suite_rejected(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        blob = self._good_blob(backend)
        tampered = blob[:5] + b"\xff" + blob[6:]

        with pytest.raises(WrapParseError):
            unwrap_dek(tampered, "k1", audit_sink=sink, backend=backend)

    def test_wrong_key_id_hash_rejected(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """If caller passes ``key_id="k1"`` but the blob's ``key_id_hash``
        is for ``"k2"``, parser rejects with WrapParseError BEFORE any
        Enclave lookup (codex MEDIUM-4: integrity binding catches this
        but parse-level check surfaces it as a clearer error)."""
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        blob = self._good_blob(backend, key_id="k2")

        with pytest.raises(WrapParseError):
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

    def test_invalid_ec_point_rejected(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """ephemeral_pub must start with 0x04 (uncompressed SEC1) and lie on
        the curve. A flipped first byte → invalid point."""
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        blob = self._good_blob(backend)
        tampered = blob[:22] + b"\x05" + blob[23:]  # 0x05 prefix = compressed, not uncompressed

        with pytest.raises(WrapParseError):
            unwrap_dek(tampered, "k1", audit_sink=sink, backend=backend)

    def test_parse_rejections_do_not_call_backend_ecdh(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """A parse failure must never trigger the Enclave authorization
        prompt (would be UX-bad and could leak info about which fields
        an attacker tampered with)."""
        from mordred_hermes.keyvault._exceptions import WrapParseError
        from mordred_hermes.keyvault.wrap import unwrap_dek

        _, sink = captured_audit
        with pytest.raises(WrapParseError):
            unwrap_dek(b"X" * 127, "k1", audit_sink=sink, backend=backend)

        ecdh_calls = [c for c in backend.calls if c[0] == "ecdh"]
        assert ecdh_calls == []


# ---------------------------------------------------------------------------
# Integrity (HKDF info binding)
# ---------------------------------------------------------------------------


class TestIntegrity:
    def test_tampered_ephemeral_pub_causes_integrity_error(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """Flipping a byte in ephemeral_pub must either (a) fail SEC1
        decode (WrapParseError), or (b) decode to a different point on
        the curve, producing a different KEK after HKDF → AES-KW AIV
        check fails (WrapIntegrityError). We test path (b) by flipping
        a byte in the Y coordinate (which usually stays on-curve enough
        for SEC1 to accept it but produces a different ECDH output)."""
        from mordred_hermes.keyvault._exceptions import (
            WrapIntegrityError,
            WrapParseError,
        )
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        # Flip a byte in the last coord byte — may or may not stay on-curve.
        tampered = blob[:86] + bytes([blob[86] ^ 0x01]) + blob[87:]

        with pytest.raises((WrapIntegrityError, WrapParseError)):
            unwrap_dek(tampered, "k1", audit_sink=sink, backend=backend)

    def test_tampered_wrapped_dek_causes_integrity_error(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """A flipped byte in wrapped_dek changes the AES-KW input; the
        AIV check at unwrap detects it."""
        from mordred_hermes.keyvault._exceptions import WrapIntegrityError
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        tampered = blob[:90] + bytes([blob[90] ^ 0x01]) + blob[91:]

        with pytest.raises(WrapIntegrityError):
            unwrap_dek(tampered, "k1", audit_sink=sink, backend=backend)


# ---------------------------------------------------------------------------
# Authorization (Enclave prompt)
# ---------------------------------------------------------------------------


class TestAuthorization:
    def test_successful_unwrap_emits_authorized_audit(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        entries, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        unwrap_entries = [e for e in entries if e.get("reason") == "keyvault.unwrap_authorized"]
        assert len(unwrap_entries) == 1
        entry = unwrap_entries[0]
        assert entry["event"] == "keyvault.unwrap_dek"
        assert entry["decision"] == "allow"
        assert "key_id_hash" in entry
        # key_id_hash is a hex prefix of SHA-256(key_id) — never the cleartext
        assert "k1" not in entry["key_id_hash"]
        assert len(entry["key_id_hash"]) == 16  # 8 bytes * 2 hex chars

    def test_user_cancelled_emits_denied_audit_and_raises(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapAuthCancelled
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        entries, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        backend.denied_reason = "user_cancelled"

        with pytest.raises(WrapAuthCancelled):
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        denied = [e for e in entries if e.get("reason") == "keyvault.unwrap_denied"]
        assert len(denied) == 1
        entry = denied[0]
        assert entry["decision"] == "block"
        assert entry["native_error_code"] == "user_cancelled"

    @pytest.mark.parametrize(
        "reason",
        ["user_cancelled", "auth_failed", "biometry_lockout", "passcode_not_set"],
    )
    def test_denied_audit_translates_native_error_codes(
        self,
        reason: str,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapAuthCancelled
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        entries, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        backend.denied_reason = reason

        with pytest.raises(WrapAuthCancelled):
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        assert entries[-1]["native_error_code"] == reason


# ---------------------------------------------------------------------------
# Keychain management
# ---------------------------------------------------------------------------


class TestKeychainManagement:
    def test_generate_then_lookup_returns_same_pub(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            get_wrapping_key_public,
        )

        generate_wrapping_key("k1", backend=backend)
        pub = get_wrapping_key_public("k1", backend=backend)

        assert len(pub) == 65
        assert pub[0] == 0x04

    def test_generate_returns_sec1_public_key(self, backend: FakeBackend) -> None:
        """review LOW-3: ``generate_wrapping_key`` returns the SEC1
        uncompressed public key so PR4's ``api.generate`` need not issue a
        second ``get_wrapping_key_public`` round-trip just to display it."""
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            get_wrapping_key_public,
        )

        pub = generate_wrapping_key("k1", backend=backend)

        assert isinstance(pub, bytes)
        assert len(pub) == 65
        assert pub[0] == 0x04
        assert pub == get_wrapping_key_public("k1", backend=backend)

    def test_delete_then_lookup_raises_key_not_found(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
        from mordred_hermes.keyvault.wrap import (
            delete_wrapping_key,
            generate_wrapping_key,
            get_wrapping_key_public,
        )

        generate_wrapping_key("k1", backend=backend)
        delete_wrapping_key("k1", backend=backend)

        with pytest.raises(WrapKeyNotFound):
            get_wrapping_key_public("k1", backend=backend)

    def test_delete_is_idempotent(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import delete_wrapping_key

        delete_wrapping_key("never-existed", backend=backend)  # must not raise

    def test_wrap_for_unknown_key_raises_key_not_found(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
        from mordred_hermes.keyvault.wrap import wrap_dek

        with pytest.raises(WrapKeyNotFound):
            wrap_dek(secrets.token_bytes(32), "unknown", backend=backend)

    def test_unwrap_for_unknown_key_raises_key_not_found(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """After ``generate_wrapping_key("k1")`` + wrap, deleting k1 means
        unwrap can't find the private key. The error happens at the
        Enclave-lookup boundary, AFTER parse but BEFORE successful ECDH."""
        from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
        from mordred_hermes.keyvault.wrap import (
            delete_wrapping_key,
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        delete_wrapping_key("k1", backend=backend)

        with pytest.raises(WrapKeyNotFound):
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_dek_must_be_32_bytes(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import generate_wrapping_key, wrap_dek

        generate_wrapping_key("k1", backend=backend)
        with pytest.raises(ValueError):
            wrap_dek(b"too short", "k1", backend=backend)
        with pytest.raises(ValueError):
            wrap_dek(secrets.token_bytes(31), "k1", backend=backend)
        with pytest.raises(ValueError):
            wrap_dek(secrets.token_bytes(33), "k1", backend=backend)


# ---------------------------------------------------------------------------
# Audit-sink exception chaining
# ---------------------------------------------------------------------------


class TestAuditSinkExceptions:
    def test_audit_sink_raise_on_denied_chains_via_context(self, backend: FakeBackend) -> None:
        """If the audit sink itself raises while recording a denial, the
        sink exception is chained as ``__context__`` on the surface
        :class:`WrapAuthCancelled` so callers' denial-handlers stay
        correct (mirrors PR2 ``recovery.py`` code-reviewer HIGH-1)."""
        from mordred_hermes.keyvault._exceptions import WrapAuthCancelled
        from mordred_hermes.keyvault.wrap import (
            NativeBackendError,
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        backend.denied_reason = "user_cancelled"

        def bad_sink(_: dict[str, Any]) -> None:
            raise OSError("simulated disk full")

        with pytest.raises(WrapAuthCancelled) as excinfo:
            unwrap_dek(blob, "k1", audit_sink=bad_sink, backend=backend)

        # The OSError is recorded as __context__ (chained automatically
        # by Python when one exception is raised inside an except handler
        # for another), not __cause__ (explicit chain).
        ctx = excinfo.value.__context__
        assert isinstance(ctx, OSError)
        assert "disk full" in str(ctx)

        # review-fix-1 MEDIUM-3: ``__cause__`` (explicit ``raise X from Y``)
        # must be the NativeBackendError so callers introspecting the chain
        # see the native signal; ``__context__`` (implicit, the sink failure)
        # must be a distinct object. Without these assertions a future
        # refactor that swaps the two passes the existing test silently.
        cause = excinfo.value.__cause__
        assert isinstance(cause, NativeBackendError)
        assert cause.code == "user_cancelled"
        assert cause is not excinfo.value.__context__


# ---------------------------------------------------------------------------
# review-fix-1 RED additions (HIGH-1, HIGH-3, MEDIUM-1)
# ---------------------------------------------------------------------------


class TestKeyNotFoundIsPreAuthorization:
    """Review HIGH-1: ``WrapAuthCancelled`` docstring (``_exceptions.py:101-105``)
    promises that a ``NativeBackendError("key_not_found")`` mid-unwrap raises
    the more specific :class:`WrapKeyNotFound` (no audit entry, because
    missing-key is pre-authorization per SPEC.md §Wrap wire format & algorithm
    "Algorithm — unwrap_dek" step 2). The current code raises
    :class:`WrapAuthCancelled` unconditionally for every backend denial code,
    contradicting both the docstring and SPEC. Branch on the code to fix.
    """

    def test_key_not_found_raises_wrap_key_not_found_not_auth_cancelled(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        from mordred_hermes.keyvault._exceptions import WrapAuthCancelled, WrapKeyNotFound
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        backend.denied_reason = "key_not_found"

        with pytest.raises(WrapKeyNotFound) as excinfo:
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        # Specifically NOT WrapAuthCancelled — callers that catch
        # ``except WrapKeyNotFound`` must catch this; callers catching
        # ``except WrapAuthCancelled`` (the prompt-denied category) must NOT.
        assert not isinstance(excinfo.value, WrapAuthCancelled)

    def test_key_not_found_emits_no_audit_entry(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """SPEC.md §Wrap wire format & algorithm "Algorithm — unwrap_dek"
        step 2: pre-authorization failures do not emit audit. The
        ``keyvault.unwrap_denied`` reason code is for prompt-denied flows
        (user_cancelled / auth_failed / biometry_lockout / passcode_not_set),
        not for missing-key flows."""
        from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        entries, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        backend.denied_reason = "key_not_found"

        with pytest.raises(WrapKeyNotFound):
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        assert entries == [], (
            f"key_not_found path must emit NO audit entries (got {entries!r}); "
            "audit emission is reserved for prompt-denied flows."
        )

    def test_key_not_found_chains_native_backend_error_via_cause(
        self,
        backend: FakeBackend,
        captured_audit: tuple[list[dict[str, Any]], AuditSink],
    ) -> None:
        """The underlying ``NativeBackendError`` must still be reachable via
        ``__cause__`` so callers can introspect the native signal — matches
        the denial-path chaining contract."""
        from mordred_hermes.keyvault._exceptions import WrapKeyNotFound
        from mordred_hermes.keyvault.wrap import (
            NativeBackendError,
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        _, sink = captured_audit
        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)
        backend.denied_reason = "key_not_found"

        with pytest.raises(WrapKeyNotFound) as excinfo:
            unwrap_dek(blob, "k1", audit_sink=sink, backend=backend)

        cause = excinfo.value.__cause__
        assert isinstance(cause, NativeBackendError)
        assert cause.code == "key_not_found"


class TestNativeBackendProtocolRuntimeCheckable:
    """Review HIGH-3: every other ``Protocol`` in this repo used structurally
    (``wizard/policy_writer.py``, ``wizard/credentials_writer.py``,
    ``wizard/env_file_writer.py``) carries ``@runtime_checkable``. PR4's
    ``api.py`` may need ``isinstance(backend, NativeBackend)`` to discriminate
    between the production ``_SecKeyBackend`` and a test fake; without the
    decorator that check silently returns ``False``.
    """

    def test_fake_backend_passes_isinstance_native_backend(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import NativeBackend

        assert isinstance(backend, NativeBackend)

    def test_object_without_methods_fails_isinstance_native_backend(self) -> None:
        from mordred_hermes.keyvault.wrap import NativeBackend

        class NotABackend:
            """Bare object missing every ``NativeBackend`` method — must be rejected."""

        assert not isinstance(NotABackend(), NativeBackend)


class TestNativeBackendErrorClosedSet:
    """Review-fix-2 MEDIUM-1 (codex second pass on the implementation):
    ``NativeBackendError`` was accepting arbitrary ``str`` codes, leaving
    POLICY.md's "never raw OSStatus into the audit log" guarantee as
    convention-only. A PR4 production backend bug that calls
    ``NativeBackendError(str(some_osstatus_int))`` would leak biometric-
    attempt state via the audit emit at ``wrap._emit_unwrap_denied``.

    Fix: closed ``NativeErrorCode`` ``Literal`` enforced at runtime by
    a frozenset lookup in ``NativeBackendError.__init__``. Unknown codes
    raise :class:`ValueError` at construction time — fail-fast at the
    backend boundary instead of leaking through the audit boundary.

    The 5 frozen codes match POLICY.md code #20 ``native_error_code``:
    ``user_cancelled`` / ``auth_failed`` / ``biometry_lockout`` /
    ``passcode_not_set`` / ``key_not_found``. ``key_not_found`` stays in
    the closed set because :func:`unwrap_dek` branches on it (raising
    :class:`WrapKeyNotFound` before any audit emit, per the HIGH-1 fix);
    the closed-set check happens at NativeBackendError construction,
    which is upstream of the audit-emit decision.
    """

    @pytest.mark.parametrize(
        "code",
        ["user_cancelled", "auth_failed", "biometry_lockout", "passcode_not_set", "key_not_found"],
    )
    def test_construct_succeeds_for_each_frozen_code(self, code: str) -> None:
        from mordred_hermes.keyvault.wrap import NativeBackendError

        exc = NativeBackendError(code)
        assert exc.code == code
        assert str(exc) == code

    def test_construct_rejects_unknown_string(self) -> None:
        from mordred_hermes.keyvault.wrap import NativeBackendError

        with pytest.raises(ValueError, match="must be one of"):
            NativeBackendError("not_a_real_code")

    def test_construct_rejects_raw_osstatus_int_as_string(self) -> None:
        """Specifically the failure mode codex MEDIUM-1 warned about:
        a buggy backend stringifies an ``OSStatus`` value
        (e.g. ``str(-25293)`` for ``errSecAuthFailed``) and passes it
        unchanged. The closed-set check must reject any non-translated
        form so the raw int never reaches the audit log."""
        from mordred_hermes.keyvault.wrap import NativeBackendError

        with pytest.raises(ValueError):
            NativeBackendError("-25293")  # errSecAuthFailed
        with pytest.raises(ValueError):
            NativeBackendError("-128")  # errSecUserCancelled

    def test_construct_rejects_empty_string(self) -> None:
        from mordred_hermes.keyvault.wrap import NativeBackendError

        with pytest.raises(ValueError):
            NativeBackendError("")

    def test_construct_rejects_close_but_invalid_codes(self) -> None:
        """Catch typos that look plausible — ``user_canceled`` (US
        spelling), ``auth_fail`` (truncated), ``BIOMETRY_LOCKOUT``
        (wrong case). The frozen set is canonical and case-sensitive."""
        from mordred_hermes.keyvault.wrap import NativeBackendError

        for bogus in ("user_canceled", "auth_fail", "BIOMETRY_LOCKOUT", "userCancelled"):
            with pytest.raises(ValueError):
                NativeBackendError(bogus)


class TestAuthorizedAuditSinkResilience:
    """Review MEDIUM-1: the success path calls ``audit_sink(...)`` bare. If the
    sink raises (disk full, fd exhausted, log-rotation race), the exception
    propagates raw and the caller loses the freshly-computed DEK — despite
    ECDH and AES-KW having succeeded. Asymmetric with ``_emit_unwrap_denied``,
    which wraps the sink call in ``try/except Exception``.

    Fix: same ``except Exception`` envelope on the success path, with
    deliberate swallow. The DEK has been computed; the sink failure is
    operationally distinct from "unwrap failed" — the caller MUST receive the
    DEK so they can proceed. Audit-log gaps caused by sink failure are
    recoverable; lost DEKs are not.
    """

    def test_authorized_audit_sink_failure_still_returns_dek(self, backend: FakeBackend) -> None:
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        generate_wrapping_key("k1", backend=backend)
        dek = secrets.token_bytes(32)
        blob = wrap_dek(dek, "k1", backend=backend)

        def bad_sink(_: dict[str, Any]) -> None:
            raise OSError("simulated disk full during authorized audit emit")

        recovered = unwrap_dek(blob, "k1", audit_sink=bad_sink, backend=backend)

        assert recovered == dek, (
            "success-path audit sink failure must not lose the DEK — the "
            "caller cannot recover the value once it has been computed"
        )

    def test_authorized_audit_sink_failure_does_not_propagate(self, backend: FakeBackend) -> None:
        """A ``unwrap_dek`` call on the success path must never propagate the
        sink exception. The denial path chains via ``__context__`` because
        there's a primary exception to attach to; the success path has only
        a return value and must deliver it intact."""
        from mordred_hermes.keyvault.wrap import (
            generate_wrapping_key,
            unwrap_dek,
            wrap_dek,
        )

        generate_wrapping_key("k1", backend=backend)
        blob = wrap_dek(secrets.token_bytes(32), "k1", backend=backend)

        def bad_sink(_: dict[str, Any]) -> None:
            raise RuntimeError("audit log rotation in progress")

        # If the implementation propagates the sink exception, this would
        # raise RuntimeError; the assertion verifies we receive the DEK
        # without exception.
        result = unwrap_dek(blob, "k1", audit_sink=bad_sink, backend=backend)
        assert len(result) == 32
