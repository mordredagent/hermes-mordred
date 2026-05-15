"""mordred_hermes.keyvault.api — public Python API surface.

Steps landed so far:

- step-A: split-normalization helpers + ``verify_digest`` wrapper.
- step-B: ``_storage`` module (file-safety helpers; consumed by api.py).
- step-C: MREN envelope wire format + ``encrypt`` / ``decrypt`` (managed
  storage; per-ciphertext DEK wrapped under the Enclave wrapping key).

Step-D lifecycle surface (lands across PR4c-1 / PR4c-2):

- PR4c-1 (landed): ``SeedDisplayHandle`` + ``SeedDisplayExpired`` +
  ``prepare_generate`` — the in-memory phase, pure with respect to disk.
- PR4c-2 (pending): ``confirm_generate`` / ``generate`` /
  ``export_backup`` / ``import_backup`` — the durable phases.

Authoritative contract lives in ``mordred-docs/mordred/SPEC.md``
§"PR4 API contract & MREN envelope wire format". Codex pre-implementation
review (3 BLOCKER + 5 HIGH) drove the split normalization in this
module: applying ``casefold`` and whitespace-collapse uniformly to the
passphrase weakens entropy, so the two normalizers diverge intentionally.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, SupportsIndex

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import _storage, wrap
from ._exceptions import WrapParseError
from .digest import VerificationDigestMismatch, compute_digest
from .digest import verify_digest as _digest_verify
from .wrap import AuditSink, NativeBackend

__all__ = [
    "GenerateResult",
    "SeedDisplayExpired",
    "SeedDisplayHandle",
    "VerificationDigestMismatch",
    "confirm_generate",
    "decrypt",
    "encrypt",
    "generate",
    "prepare_generate",
    "verify_digest",
]

# Default seed-display TTL per SPEC.md §"SeedDisplayHandle (opaque)".
# 60 seconds matches PR5's planned screen-blackout window; prepare_generate
# bakes the deadline into the returned handle so the wipe-on-expiry path is
# reachable from realistic call sites.
_SEED_DISPLAY_DEFAULT_TTL_SECONDS = 60.0

# The verification digest is always a 32-byte BLAKE3 output (SPEC.md
# §"Key generation and verification digest"). SeedDisplayHandle validates
# its ``expected_digest`` against this so a wrong-length value cannot reach
# confirm_generate's hmac.compare_digest as a silent always-mismatch.
_VERIFICATION_DIGEST_LEN = 32

# Resolved key_id when the caller passes ``key_id=None`` to confirm_generate
# / generate. v1 keyvault is single-key per user (SPEC Story 5 — one
# keyvault initialization); a deterministic literal keeps the wizard flow
# and re-init detection simple.
_DEFAULT_KEY_ID = "default"


# ----------------------------- SeedDisplayHandle (PR4 step-D) -----------------------------
# Opaque-class contract frozen in SPEC.md §"PR4 API contract / SeedDisplayHandle
# (opaque, codex BLOCKER #3)". PR5 will relocate this class to ``seed_display.py``
# and layer screen-blackout / 60s timer / screenshot detection on top; the
# external contract (slots, redacted repr, raising __eq__, __hash__ = None,
# one-shot consume() with in-place wipe + deadline guard) MUST hold verbatim
# after the relocation.


class SeedDisplayExpired(Exception):
    """``SeedDisplayHandle.consume()`` was called after the deadline elapsed.

    Raised by :meth:`SeedDisplayHandle.consume` when ``time.monotonic()``
    has passed the handle's ``deadline_monotonic``. The handle's internal
    bytearray is wiped before the exception propagates so the seed does
    not survive an expired display window in process memory.
    """


class SeedDisplayHandle:
    """Opaque container for a normalized seed phrase during the display flow.

    The naive shape — a frozen dataclass with ``seed_phrase: str`` — would
    leak the seed via four channels:

    1. ``repr`` / ``str`` (auto-generated to echo all fields).
    2. ``__eq__`` against attacker-supplied strings (comparison oracle).
    3. Hash-based memoization (long-lived retention in dict / set).
    4. Stray ``handle.seed_phrase = ...`` assignment landing in ``__dict__``.

    Each is blocked here: a fixed redacted repr, an ``__eq__`` that raises
    ``TypeError``, ``__hash__ = None``, and ``__slots__`` pinning the
    attribute set. ``consume()`` is the only egress; it is one-shot and
    zero-fills the payload bytearray in-place so any other reference into
    the same buffer also observes zero bytes after release.
    """

    # __slots__ order matches SPEC.md §"SeedDisplayHandle (opaque)" with two
    # PR4-step-D extensions:
    #   - ``_expected_digest`` (4th slot) carries the BLAKE3 digest computed
    #     at prepare_generate time so confirm_generate can verify the
    #     user-typed digest via hmac.compare_digest without re-running the
    #     algorithm.
    #   - ``_lock`` (5th slot) is a per-handle threading.Lock that serializes
    #     consume() so the one-shot guarantee holds even if the handle is
    #     shared across threads (codex pre-merge P2, 2026-05-15).
    # The first three slots are SPEC-ordered; ruff's natural-sort lint is
    # suppressed because the test pins the exact tuple value (see
    # test_slots_value_is_exact_five_tuple). SPEC.md §"SeedDisplayHandle
    # (opaque)" carries a matching "Step-D extension" callout.
    __slots__ = ("_payload", "_consumed", "_deadline", "_expected_digest", "_lock")  # noqa: RUF023

    def __init__(
        self,
        normalized_seed: str,
        deadline_monotonic: float,
        expected_digest: bytes,
    ) -> None:
        # Coerce to immutable bytes FIRST, then validate the byte length of
        # the coerced value. Two reasons the order matters:
        #   - ``len()`` on a non-byte-width memoryview counts elements, not
        #     bytes, so validating the raw argument would mis-measure such
        #     inputs (codex pre-merge P3, 2026-05-15).
        #   - ``bytes(...)`` decouples the handle from any caller-retained
        #     mutable alias (bytearray / memoryview) so the compare target
        #     cannot be mutated post-construction (codex pre-merge P2).
        # hmac.compare_digest (used by confirm_generate) accepts unequal-
        # length operands and returns False, so a wrong-length digest would
        # otherwise become a silent always-mismatch — fail loudly here.
        digest = bytes(expected_digest)
        if len(digest) != _VERIFICATION_DIGEST_LEN:
            raise ValueError(f"expected_digest must be exactly {_VERIFICATION_DIGEST_LEN} bytes, got {len(digest)}")
        # Store the seed as a wipeable bytearray (str is immutable, so
        # bytearray is the only way to actually zero the bytes in place).
        self._payload = bytearray(normalized_seed.encode("utf-8"))
        self._consumed = False
        # Absolute monotonic timestamp — caller computes
        # ``time.monotonic() + ttl`` (default ttl = 60.0s per SPEC).
        self._deadline = deadline_monotonic
        self._expected_digest = digest
        # Serializes consume() — the check / decode / wipe / set section is
        # not atomic, so without this two threads sharing a handle could
        # both pass the one-shot guard and release the seed twice.
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "<SeedDisplayHandle redacted>"

    def __eq__(self, other: object) -> bool:
        # Raising rather than returning False eliminates the comparison
        # oracle entirely. Identity (``is``) is not routed through __eq__
        # and continues to work for the legitimate same-object check.
        raise TypeError("SeedDisplayHandle does not support equality (would leak via comparison oracle)")

    # Setting __hash__ to None at the class level makes instances unhashable —
    # hash() / set / dict-key use all raise TypeError. This prevents the
    # handle from accidentally landing in a memoization cache that would
    # extend the seed's residency past the intended display window.
    __hash__ = None  # type: ignore[assignment]

    # ----- copy / pickle blocked (codex pre-merge P2-1, 2026-05-15) -----
    # A slotted handle is copyable and picklable by default because
    # Python's machinery walks ``__slots__`` and serializes each entry.
    # Without these guards, ``copy.deepcopy(handle)`` would produce a
    # duplicate that can ``consume()`` again after the original was
    # wiped, and ``pickle.dumps(handle)`` would emit a blob containing
    # the raw seed bytes. Both bypass the opaque/one-shot contract, so
    # we raise TypeError from each entry point. The exception fires
    # before any output is produced, so partial pickle buffers cannot
    # leak the seed either.

    def __copy__(self) -> NoReturn:
        raise TypeError("SeedDisplayHandle is opaque and not copyable")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise TypeError("SeedDisplayHandle is opaque and not copyable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("SeedDisplayHandle is opaque and not picklable")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("SeedDisplayHandle is opaque and not picklable")

    # On Python 3.11+ slotted objects inherit ``object.__getstate__``, which
    # returns ``(None, {"_payload": bytearray(...), ...})`` — a direct
    # seed-leak channel that bypasses ``consume()`` and is NOT routed
    # through the ``__reduce*__`` guards above. A generic state dumper (or
    # any caller invoking ``handle.__getstate__()`` directly) would read the
    # seed bytes from an unconsumed handle. Block it, and block
    # ``__setstate__`` for symmetry so a handle can never be repopulated
    # from an external state dict (codex pre-merge P2, 2026-05-15).

    def __getstate__(self) -> NoReturn:
        raise TypeError("SeedDisplayHandle is opaque and does not expose its state")

    def __setstate__(self, state: object) -> NoReturn:
        raise TypeError("SeedDisplayHandle is opaque and does not expose its state")

    def consume(self) -> str:
        """Return the normalized seed exactly once, wiping the payload.

        Subsequent calls raise :class:`RuntimeError`. If
        ``time.monotonic()`` has passed the deadline, the payload is
        wiped and :class:`SeedDisplayExpired` is raised instead of
        returning the seed.

        The whole check / decode / wipe / set section runs under
        ``self._lock`` so the one-shot guarantee holds even when the
        handle is shared across threads — exactly one caller receives
        the seed, every other caller raises.
        """
        with self._lock:
            if self._consumed:
                raise RuntimeError("handle already consumed")

            if time.monotonic() > self._deadline:
                # Wipe BEFORE raising so the seed bytes do not survive in
                # process memory just because the display window timed out.
                self._wipe()
                self._consumed = True
                raise SeedDisplayExpired("SeedDisplayHandle expired before consume()")

            # Decode-then-wipe: hold the str on the local stack frame, then
            # zero the underlying bytearray. The returned str is a fresh
            # object; mutating the bytearray does not affect it.
            seed = self._payload.decode("utf-8")
            self._wipe()
            self._consumed = True
            return seed

    def _wipe(self) -> None:
        # In-place zero-fill via slice assignment — overwrites the existing
        # buffer rather than rebinding ``_payload`` to a new bytearray, so
        # any aliased reference into the same buffer also observes zeros.
        self._payload[:] = bytes(len(self._payload))


# ----------------------------- MREN envelope constants -----------------------------
# Wire format frozen in SPEC.md §"PR4 API contract / MREN envelope".

_ENVELOPE_MAGIC = b"MREN"
_ENVELOPE_VERSION = 1
_KEY_ID_HASH_LEN = 16
_PURPOSE_HASH_LEN = 16
_WRAPPED_DEK_LEN = 127  # PR3 MRKW blob, SPEC §"Wrap wire format & algorithm"
_AES_BLOB_LEN_FIELD_LEN = 4
_ENVELOPE_AAD_LEN = 4 + 1 + _KEY_ID_HASH_LEN + _PURPOSE_HASH_LEN + _WRAPPED_DEK_LEN  # 164
_ENVELOPE_HEADER_LEN = _ENVELOPE_AAD_LEN + _AES_BLOB_LEN_FIELD_LEN  # 168

_DEK_LEN = 32
_AES_NONCE_LEN = 12
_AES_TAG_LEN = 16
_ENVELOPE_ID_RAND_BYTES = 16


def _normalize_seed_phrase(s: str) -> str:
    """Normalize a seed phrase: NFKD + strip Cf chars + casefold + collapse whitespace.

    BIP39 word-list tolerance — the canonical word list is lowercase ASCII
    and word-separated by a single ASCII space; mixed case and runs of
    whitespace (incl. compatibility-decomposed NBSP / ideographic space)
    are operator-typo noise and are folded away.

    Unicode Cf-category chars (Format) are also stripped: ZWSP / ZWJ /
    ZWNJ / BOM / LRM / RLM / Mongolian Vowel Separator / soft hyphen are
    invisible to the user and are NFKD-stable, so without an explicit
    drop step a clipboard-injected ZWSP would silently produce a different
    digest from typed-by-hand input (code-reviewer MEDIUM-1, 2026-05-15).
    """
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Cf")
    return " ".join(stripped.casefold().split())


def _normalize_passphrase(s: str) -> str:
    """Normalize a passphrase: NFKD only.

    BIP39 reference behavior (no casefold, no whitespace collapse, no Cf
    strip). Case is significant; whitespace is preserved; Cf-category chars
    (ZWSP / ZWJ / BOM / soft hyphen / …) are preserved. Trimming any of
    these would conflate distinct entropy choices. A user who chose to
    embed an invisible char did so intentionally and must reproduce the
    exact bytes on recovery. See codex review HIGH #1 and code-reviewer
    MEDIUM-1.
    """
    return unicodedata.normalize("NFKD", s)


def verify_digest(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    *,
    expected: bytes,
) -> None:
    """Verify the verification digest with split normalization applied.

    Inputs are normalized at this layer before reaching ``compute_digest``.
    The length-confusion guard (Codex review #6) is inherited from
    :func:`mordred_hermes.keyvault.digest.verify_digest`: any ``expected`` of
    length != 32 raises :exc:`VerificationDigestMismatch` (which is re-
    exported from this module for caller convenience).
    """
    _digest_verify(
        _normalize_seed_phrase(seed_phrase),
        _normalize_passphrase(passphrase),
        pow_bytes,
        expected=expected,
    )


def prepare_generate(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
) -> tuple[SeedDisplayHandle, bytes]:
    """Compute the verification digest in-memory and package the normalized
    seed for the display flow.

    Two-phase generate (SPEC.md §"PR4 API contract / Two-phase generate",
    codex BLOCKER #2): a single-call ``generate(seed, passphrase, pow)``
    would create Keychain state and write meta.json before the user has
    confirmed the digest via the offline channel. Splitting into
    ``prepare_generate`` (this function, pure with respect to disk) and
    ``confirm_generate`` (the durable phase, fail-closed on mismatch)
    closes that hole.

    Returns:
        A tuple of ``(handle, expected_digest)``:

        - ``handle``: opaque :class:`SeedDisplayHandle` holding the
          normalized seed bytes with a default 60s deadline. PR5 will
          consume this handle through the screen-blackout / 60s timer /
          screenshot-detection display flow.
        - ``expected_digest``: 32-byte BLAKE3 digest. The user verifies
          this against the digest computed independently on the offline
          medium, then passes it back to :func:`confirm_generate` /
          :func:`generate` to finalize.

    NOT performed by this function: Keychain creation, meta.json write,
    digests/<kid>.commit, audit-sink emission. The signature reflects
    that purity — no ``audit_sink`` / ``backend`` / ``home`` parameters.
    """
    normalized_seed = _normalize_seed_phrase(seed_phrase)
    normalized_passphrase = _normalize_passphrase(passphrase)
    expected_digest = compute_digest(normalized_seed, normalized_passphrase, pow_bytes)
    handle = SeedDisplayHandle(
        normalized_seed,
        time.monotonic() + _SEED_DISPLAY_DEFAULT_TTL_SECONDS,
        expected_digest,
    )
    return handle, expected_digest


@dataclass(frozen=True, slots=True)
class GenerateResult:
    """Outcome of a successful :func:`confirm_generate` / :func:`generate`.

    - ``key_id``: the resolved key identifier. The caller may have passed
      ``key_id=None``; this field reports what was actually used (the
      ``"default"`` literal in that case).
    - ``key_id_hash``: the 32-hex-char on-disk hash
      (``SHA-256(key_id)[:16].hex()``) — the ``meta.json`` row key and the
      ``digests/<key_id_hash>.commit`` filename stem.
    - ``created_at``: ISO 8601 UTC timestamp (``...Z``, second precision)
      recorded in the ``meta.json`` row.
    """

    key_id: str
    key_id_hash: str
    created_at: str


def _utc_now_iso() -> str:
    """Current UTC time as an ISO 8601 string with a ``Z`` suffix.

    Second precision — the timestamp is operator-facing provenance, not a
    high-resolution event clock.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit_init_denied(audit_sink: AuditSink, *, key_id: str) -> Exception | None:
    """Best-effort emit of the ``keyvault.init_denied`` audit entry.

    Returns the sink's exception (only :class:`Exception` subclasses) so
    :func:`confirm_generate` can chain it as ``__context__`` on the
    :class:`VerificationDigestMismatch` it is about to raise — mirrors the
    PR2 recovery ``_emit_mismatch`` / PR3 ``_emit_unwrap_denied`` policy.

    The ``except Exception`` is intentional: KeyboardInterrupt / SystemExit
    / GeneratorExit are control-flow exceptions that must propagate
    untouched so CLI shutdown stays clean.
    """
    try:
        audit_sink(
            {
                "event": "keyvault.init",
                "decision": "block",
                "reason": "keyvault.init_denied",
                "key_id_hash": wrap._audit_key_id_hex(key_id),
            }
        )
    except Exception as exc:
        return exc
    return None


def confirm_generate(
    handle: SeedDisplayHandle,
    user_confirmed_digest: bytes,
    *,
    key_id: str | None = None,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> GenerateResult:
    """Finalize key generation once the verification digest is confirmed.

    The durable half of two-phase generate (SPEC.md §"Two-phase generate",
    codex BLOCKER #2). :func:`prepare_generate` computed the digest in
    memory; the user transcribed the seed and confirmed the digest via the
    offline channel; this function commits the durable state — but only if
    ``user_confirmed_digest`` matches.

    Flow:

    1. ``handle.consume()`` — enforces the one-shot contract (a second
       ``confirm_generate`` on the same handle raises :class:`RuntimeError`),
       the display deadline (an expired handle raises
       :class:`SeedDisplayExpired`), and wipes the seed bytes.
    2. ``hmac.compare_digest`` against the digest baked into the handle.
       On mismatch: emit ``keyvault.init_denied`` and raise
       :class:`VerificationDigestMismatch` — NO Keychain / filesystem
       mutation (POLICY.md #23). A sink failure during the denied emit is
       chained as ``__context__`` on the raised exception.
    3. On match — the durable phase:

       a. Emit ``keyvault.init_started``. This is the durability barrier:
          if the audit sink raises here the whole init aborts (fail-closed,
          POLICY.md #21) — no key, no ``meta.json`` row.
       b. ``wrap.generate_wrapping_key`` — create the Enclave keypair.
          A duplicate ``key_id`` raises here (the backend's duplicate
          guard); this is OUTSIDE the rollback scope so a pre-existing
          legitimate key is never deleted.
       c. Under ``keyvault_lock``: write the ``meta.json`` row and
          ``digests/<key_id_hash>.commit`` atomically. Any failure here
          rolls back — deletes the Enclave key created in (b) — then
          re-raises.
       d. Emit ``keyvault.init_completed``. The init is already durable,
          so a sink failure is suppressed (POLICY.md #22); a line is
          written to stderr for the operator.

    ``backend`` is keyword-only and required (no default), matching the
    merged ``encrypt`` / ``decrypt`` surface. SPEC.md sketches it as
    ``NativeBackend | None = None``; api.py standardizes on a required
    backend — the production ``_SecKeyBackend`` is a later step and does
    not exist yet, so there is no sensible ``None`` fallback.
    """
    resolved_key_id = key_id if key_id is not None else _DEFAULT_KEY_ID

    # 1. Consume the handle. This enforces one-shot use (RuntimeError on a
    #    second confirm), the display deadline (SeedDisplayExpired), and
    #    wipes the seed bytes prepare_generate stashed for PR5's display
    #    flow. confirm_generate does not need the seed itself — the
    #    verification digest is the gate — so the returned value is dropped.
    handle.consume()

    # 2. Defense-in-depth digest check (hmac.compare_digest — constant time).
    #    Same-module access to the handle's private digest slot.
    verification_digest = handle._expected_digest
    if not hmac.compare_digest(user_confirmed_digest, verification_digest):
        sink_exc = _emit_init_denied(audit_sink, key_id=resolved_key_id)
        mismatch = VerificationDigestMismatch("user-confirmed digest does not match the prepared verification digest")
        # Chain the sink failure (if any) as __context__ — not __cause__ —
        # so it stays diagnosable without displacing the primary mismatch
        # signal. Matches the PR2 recovery._emit_mismatch pattern (an
        # explicit assignment because ``raise X from Y`` sets __cause__).
        if sink_exc is not None:
            mismatch.__context__ = sink_exc
        raise mismatch

    # 3a. init_started — durability barrier. NO try/except: a sink exception
    #     propagates and aborts the init before any Keychain / filesystem
    #     mutation (fail-closed — POLICY.md #21).
    audit_sink(
        {
            "event": "keyvault.init",
            "decision": "allow",
            "reason": "keyvault.init_started",
            "key_id_hash": wrap._audit_key_id_hex(resolved_key_id),
        }
    )

    # 3b. Create the Enclave wrapping key. OUTSIDE the rollback scope: if
    #     this raises (e.g. duplicate key_id) the key either was not created
    #     or belongs to a prior init — it must NOT be deleted.
    wrap.generate_wrapping_key(resolved_key_id, backend=backend)

    # 3c. Persist meta.json + digests/<key_id_hash>.commit atomically under
    #     the keyvault lock. Any failure after the key exists rolls it back.
    created_at = _utc_now_iso()
    key_id_hash_hex = _hash_id(resolved_key_id).hex()
    try:
        root = _storage.resolve_keyvault_dir(home)
        _storage.ensure_layout(root)
        with _storage.keyvault_lock(root):
            meta = _storage.load_meta(root)
            meta["keys"][key_id_hash_hex] = {
                "key_id": resolved_key_id,
                "created_at": created_at,
            }
            _storage.save_meta(root, meta)
            _storage.atomic_write(
                root / "digests" / f"{key_id_hash_hex}.commit",
                verification_digest,
            )
    except BaseException:
        # Rollback: delete the orphaned Enclave key so a retry can re-init
        # cleanly. ``BaseException`` (not ``Exception``) so a KeyboardInterrupt
        # mid-write still triggers cleanup before propagating. If the delete
        # itself fails, that exception propagates with the original chained.
        wrap.delete_wrapping_key(resolved_key_id, backend=backend)
        raise

    # 3d. init_completed — success-path emit. The init is already durable,
    #     so a sink exception is suppressed (POLICY.md #22); a single line
    #     on stderr lets the operator investigate without losing the key.
    try:
        audit_sink(
            {
                "event": "keyvault.init",
                "decision": "allow",
                "reason": "keyvault.init_completed",
                "key_id_hash": wrap._audit_key_id_hex(resolved_key_id),
                "verification_digest_hex_prefix": verification_digest[:8].hex(),
            }
        )
    except Exception as exc:  # success-path suppress (POLICY.md #22)
        print(
            f"keyvault.init_completed audit emit failed (init already durable, key_id_hash={key_id_hash_hex}): {exc!r}",
            file=sys.stderr,
        )

    return GenerateResult(
        key_id=resolved_key_id,
        key_id_hash=key_id_hash_hex,
        created_at=created_at,
    )


def generate(
    seed_phrase: str,
    passphrase: str,
    pow_bytes: bytes,
    expected_digest: bytes,
    *,
    key_id: str | None = None,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> GenerateResult:
    """Non-interactive convenience wrapper: prepare → confirm in one call.

    Tests and future automation use this. The wizard CLI MUST use the
    two-phase form (:func:`prepare_generate` then :func:`confirm_generate`)
    so the user transcribes the seed and confirms the verification digest
    via the offline channel before anything durable is created.

    ``generate`` delegates fully to :func:`confirm_generate` — it does not
    pre-check the digest itself. confirm_generate consumes the handle,
    compares ``expected_digest`` against the handle's prepared digest, and
    emits ``keyvault.init_denied`` on a mismatch. (SPEC.md sketched an
    early in-``generate`` check that raised without an audit emit;
    delegating is simpler and gives a non-interactive mismatch the same
    audit trail as the interactive path.)
    """
    handle, _expected = prepare_generate(seed_phrase, passphrase, pow_bytes)
    return confirm_generate(
        handle,
        expected_digest,
        key_id=key_id,
        backend=backend,
        audit_sink=audit_sink,
        home=home,
    )


# ----------------------------- MREN envelope helpers (step-C) -----------------------------


def _validate_purpose(purpose: str) -> None:
    """Reject any purpose string that could escape the storage layout or
    appear inside an audit log as a control sequence.

    Allowed: alphanumeric, dash, underscore, dot (but not the bare
    relative-path components ``"."`` / ``".."``). Rejected: empty string,
    path separators (``/`` / ``\\``), control characters (``\\x00``-``\\x1f``
    / ``\\x7f``), and the relative-path components ``"."`` / ``".."``.
    """
    if not purpose:
        raise ValueError("purpose must not be empty")
    if purpose in {".", ".."}:
        raise ValueError("purpose must not be a relative-path component")
    if "/" in purpose or "\\" in purpose:
        raise ValueError("purpose must not contain path separators")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in purpose):
        raise ValueError("purpose must not contain control characters")


def _hash_id(value: str) -> bytes:
    """Return the first 16 bytes of ``sha256(value.encode("utf-8"))``.

    Used for both ``key_id_hash`` and ``purpose_hash`` (same algorithm
    and width).
    """
    return hashlib.sha256(value.encode("utf-8")).digest()[:_KEY_ID_HASH_LEN]


def _new_envelope_id() -> str:
    """Return a URL-safe base64 string of 16 random bytes (22 chars, no padding)."""
    raw = secrets.token_bytes(_ENVELOPE_ID_RAND_BYTES)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Exactly 22 URL-safe-base64 chars (alphabet ``[A-Za-z0-9_-]``, no padding).
# Matches the output of :func:`_new_envelope_id` and rejects any caller-supplied
# value containing path separators, traversal sequences, or wrong length.
_ENVELOPE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")


def _validate_envelope_id(envelope_id: str) -> None:
    """Reject ``envelope_id`` values that could escape the managed storage path.

    Codex pre-merge P1: ``envelope_id`` was appended verbatim into the
    filesystem path. A caller supplying ``"../something"`` or ``"a/b"``
    would make :func:`decrypt` open a ``.gcm`` file outside the keyvault
    tree. Rejecting anything that does not match the exact format
    produced by :func:`_new_envelope_id` is the simplest correct fix.
    """
    if not _ENVELOPE_ID_RE.match(envelope_id):
        raise ValueError("invalid envelope_id: must be 22 URL-safe-base64 characters (no padding)")


def _envelope_path_for(root: Path, key_id: str, purpose: str, envelope_id: str) -> Path:
    """Construct the on-disk path for an MREN envelope."""
    return root / "ciphertexts" / _hash_id(key_id).hex() / _hash_id(purpose).hex() / f"{envelope_id}.gcm"


def _encode_envelope(
    dek: bytes,
    plaintext: bytes,
    key_id: str,
    purpose: str,
    wrapped_dek_blob: bytes,
) -> bytes:
    """Build an MREN envelope (AAD-bound AES-GCM) from a pre-wrapped DEK.

    Layout (SPEC.md §"PR4 API contract / MREN envelope"):

        magic(4) || version(1) || key_id_hash(16) || purpose_hash(16) ||
        wrapped_dek(127) || aes_blob_len(4 BE) ||
        aes_blob = nonce(12) || ciphertext(N) || tag(16)

    AAD = the first 164 bytes; AES-GCM tag therefore covers every field
    except ``aes_blob`` itself.
    """
    if len(wrapped_dek_blob) != _WRAPPED_DEK_LEN:
        raise ValueError(f"wrapped_dek must be exactly {_WRAPPED_DEK_LEN} bytes")
    aad = _ENVELOPE_MAGIC + bytes([_ENVELOPE_VERSION]) + _hash_id(key_id) + _hash_id(purpose) + wrapped_dek_blob
    # Use ``if/raise`` rather than ``assert`` so the check is not stripped
    # under ``python -O`` / ``PYTHONOPTIMIZE=1`` (in-tree code-reviewer MEDIUM).
    if len(aad) != _ENVELOPE_AAD_LEN:
        raise AssertionError(f"internal error: assembled AAD is {len(aad)} bytes, expected {_ENVELOPE_AAD_LEN}")
    nonce = secrets.token_bytes(_AES_NONCE_LEN)
    ct_tag = AESGCM(dek).encrypt(nonce, plaintext, aad)
    aes_blob = nonce + ct_tag
    return aad + len(aes_blob).to_bytes(_AES_BLOB_LEN_FIELD_LEN, "big") + aes_blob


def _parse_envelope(
    blob: bytes,
    expected_key_id: str,
    expected_purpose: str,
) -> tuple[bytes, bytes, bytes]:
    """Validate the MREN header and return ``(aad, wrapped_dek_blob, aes_blob)``.

    Raises :exc:`mordred_hermes.keyvault._exceptions.WrapParseError` on any
    structural mismatch, magic/version disagreement, key_id_hash mismatch,
    or purpose_hash mismatch. The purpose_hash compare uses
    :func:`hmac.compare_digest` so cross-purpose attempts cannot be
    distinguished by timing (the wrap layer is then never reached, so the
    user is not prompted — codex HIGH #2).
    """
    if len(blob) < _ENVELOPE_HEADER_LEN:
        raise WrapParseError(f"envelope too short: {len(blob)} bytes, expected at least {_ENVELOPE_HEADER_LEN}")
    if blob[0:4] != _ENVELOPE_MAGIC:
        raise WrapParseError(f"envelope magic mismatch: {blob[0:4]!r}")
    if blob[4] != _ENVELOPE_VERSION:
        raise WrapParseError(f"envelope version mismatch: {blob[4]}")

    expected_kid_hash = _hash_id(expected_key_id)
    if not hmac.compare_digest(blob[5 : 5 + _KEY_ID_HASH_LEN], expected_kid_hash):
        raise WrapParseError("envelope key_id_hash does not match expected key_id")

    expected_purpose_hash = _hash_id(expected_purpose)
    purpose_offset = 5 + _KEY_ID_HASH_LEN
    if not hmac.compare_digest(
        blob[purpose_offset : purpose_offset + _PURPOSE_HASH_LEN],
        expected_purpose_hash,
    ):
        raise WrapParseError("envelope purpose_hash does not match expected purpose")

    wrapped_dek_start = purpose_offset + _PURPOSE_HASH_LEN
    wrapped_dek_blob = blob[wrapped_dek_start : wrapped_dek_start + _WRAPPED_DEK_LEN]
    aes_blob_len_offset = wrapped_dek_start + _WRAPPED_DEK_LEN  # = 164
    declared_len = int.from_bytes(blob[aes_blob_len_offset : aes_blob_len_offset + _AES_BLOB_LEN_FIELD_LEN], "big")
    if len(blob) != _ENVELOPE_HEADER_LEN + declared_len:
        raise WrapParseError(
            f"envelope aes_blob_len mismatch: header says {declared_len}, actual {len(blob) - _ENVELOPE_HEADER_LEN}"
        )
    # codex second-pass P2-A: aes_blob must hold at least one AES-GCM nonce
    # plus the 16-byte tag. Anything shorter is structurally invalid; reject
    # BEFORE unwrap_dek so a truncated envelope cannot spend a biometric
    # prompt and emit keyvault.unwrap_authorized only to fail at AES-GCM.
    if declared_len < _AES_NONCE_LEN + _AES_TAG_LEN:
        raise WrapParseError(
            f"envelope aes_blob too short: {declared_len} bytes, "
            f"need at least {_AES_NONCE_LEN + _AES_TAG_LEN} (nonce + tag)"
        )
    # ``safe_read`` returns ``bytes``; slicing ``bytes`` returns ``bytes`` —
    # the explicit wrap is redundant (in-tree code-reviewer NIT-1).
    aad = blob[:_ENVELOPE_AAD_LEN]
    aes_blob = blob[_ENVELOPE_HEADER_LEN:]
    return aad, wrapped_dek_blob, aes_blob


def encrypt(
    key_id: str,
    plaintext: bytes,
    purpose: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Encrypt ``plaintext`` under a fresh per-call DEK; return ``envelope_id``.

    The DEK is wrapped offline via :func:`mordred_hermes.keyvault.wrap.wrap_dek`
    (no biometric prompt, no audit emit). The resulting envelope is persisted
    to ``<keyvault>/ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm``
    via the step-B atomic-write helpers under ``keyvault_lock``.
    Returns the URL-safe-base64 ``envelope_id`` (22 chars, no padding).

    ``audit_sink`` is accepted so this surface matches the rest of the
    api.py contract; codex OD-3 specifies that ``encrypt`` does NOT emit
    audit entries at this layer (no authorization gate, and the wrap
    layer never emits on the wrap path).
    """
    del audit_sink  # documented no-op for encrypt; reserved for symmetry with decrypt
    _validate_purpose(purpose)
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)

    dek = secrets.token_bytes(_DEK_LEN)
    try:
        wrapped_dek_blob = wrap.wrap_dek(dek, key_id, backend=backend)
        envelope = _encode_envelope(dek, plaintext, key_id, purpose, wrapped_dek_blob)
    finally:
        # Best-effort wipe — Python bytes are immutable so we cannot zero
        # them in place; leaving the reference unbound lets the GC reclaim
        # sooner than a function-level local would.
        del dek

    envelope_id = _new_envelope_id()

    key_id_hash_hex = _hash_id(key_id).hex()
    purpose_hash_hex = _hash_id(purpose).hex()
    key_dir = root / "ciphertexts" / key_id_hash_hex
    purpose_dir = key_dir / purpose_hash_hex
    envelope_path = purpose_dir / f"{envelope_id}.gcm"

    with _storage.keyvault_lock(root):
        # codex pre-merge P2-1: validate any pre-existing directory before
        # writing inside it. Without this an attacker who pre-creates the
        # key_dir as a symlink (or with wrong mode) could redirect the
        # envelope into attacker-controlled territory.
        #
        # Cross-module private access (in-tree code-reviewer LOW-3,
        # 2026-05-15): ``_storage._check_dir_mode`` is intentionally
        # consumed across the api.py / _storage.py boundary inside the
        # same ``mordred_hermes.keyvault`` package. The underscore prefix
        # signals "package-internal", not "module-internal" — the same
        # pattern PR3 uses for ``_exceptions.py`` shared between
        # ``native.py`` and ``wrap.py``. Step-G may promote the helper to
        # ``_storage.validate_existing_dir`` if a third call site appears.
        if key_dir.exists() or key_dir.is_symlink():
            _storage._check_dir_mode(key_dir)
        else:
            key_dir.mkdir(mode=0o700)
            os.chmod(key_dir, 0o700)
        if purpose_dir.exists() or purpose_dir.is_symlink():
            _storage._check_dir_mode(purpose_dir)
        else:
            purpose_dir.mkdir(mode=0o700)
            os.chmod(purpose_dir, 0o700)
        _storage.atomic_write(envelope_path, envelope)

    return envelope_id


def decrypt(
    key_id: str,
    envelope_id: str,
    purpose: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    """Decrypt an MREN envelope and return the plaintext.

    Reads ``ciphertexts/<key_id_hash_hex>/<purpose_hash_hex>/<envelope_id>.gcm``;
    rejects mismatched ``key_id_hash`` or ``purpose_hash`` with
    :exc:`WrapParseError` *before* calling
    :func:`mordred_hermes.keyvault.wrap.unwrap_dek` so a cross-purpose
    replay attempt does not spend a biometric prompt (codex HIGH #2).

    On purpose match the wrap layer is invoked, which may prompt the user
    for biometric authorization and emits exactly one
    ``keyvault.unwrap_authorized`` or ``keyvault.unwrap_denied`` audit
    entry via the supplied ``audit_sink``. ``decrypt`` does NOT
    double-emit at the api layer (codex OD-3).
    """
    _validate_purpose(purpose)
    _validate_envelope_id(envelope_id)
    root = _storage.resolve_keyvault_dir(home)
    envelope_path = _envelope_path_for(root, key_id, purpose, envelope_id)

    # codex second-pass P2-B: O_NOFOLLOW in safe_read only protects the
    # final .gcm component. Refuse symlinked intermediate dirs (key_dir /
    # purpose_dir) explicitly so an attacker who has swapped one of them
    # for a symlink cannot redirect the read into attacker territory.
    # Each existing dir must also be mode 0o700.
    key_dir = envelope_path.parent.parent
    purpose_dir = envelope_path.parent
    if key_dir.exists() or key_dir.is_symlink():
        _storage._check_dir_mode(key_dir)
    if purpose_dir.exists() or purpose_dir.is_symlink():
        _storage._check_dir_mode(purpose_dir)

    blob = _storage.safe_read(envelope_path)
    aad, wrapped_dek_blob, aes_blob = _parse_envelope(blob, key_id, purpose)
    dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
    try:
        nonce = aes_blob[:_AES_NONCE_LEN]
        ct_tag = aes_blob[_AES_NONCE_LEN:]
        return AESGCM(dek).decrypt(nonce, ct_tag, aad)
    finally:
        del dek
