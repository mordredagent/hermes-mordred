"""mordred_hermes.keyvault.api — public Python API surface.

Steps landed so far:

- step-A: split-normalization helpers + ``verify_digest`` wrapper.
- step-B: ``_storage`` module (file-safety helpers; consumed by api.py).
- step-C: MREN envelope wire format + ``encrypt`` / ``decrypt`` (managed
  storage; per-ciphertext DEK wrapped under the Enclave wrapping key).

Step-D lifecycle surface:

- ``SeedDisplayHandle`` + ``SeedDisplayExpired`` + ``prepare_generate`` —
  the in-memory phase, pure with respect to disk.
- ``confirm_generate`` / ``generate`` — the durable key-generation phase,
  fail-closed on a verification-digest mismatch.

Step-E adds ``export_backup`` / ``import_backup`` — the ciphertext-rewrap
manifest that makes a keyvault recoverable on a second device even though
the Secure Enclave wrapping key is non-exportable. See SPEC.md
§"export_backup / import_backup (ciphertext-rewrap manifest)".

Authoritative contract lives in ``mordred-docs/mordred/SPEC.md``
§"PR4 API contract & MREN envelope wire format". Codex pre-implementation
review (3 BLOCKER + 5 HIGH) drove the split normalization in this
module: applying ``casefold`` and whitespace-collapse uniformly to the
passphrase weakens entropy, so the two normalizers diverge intentionally.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, SupportsIndex

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import _storage, backup, crypto, recovery, wrap
from ._envelope_codec import (
    _AES_NONCE_LEN,
    _encode_envelope,
    _encode_envelope_from_hashes,
    _hash_id,
    _parse_envelope,
    _split_envelope,
)
from .backup import BackupCorrupt
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
    "export_backup",
    "generate",
    "import_backup",
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
# (opaque, codex BLOCKER #3)". The class stays here in api.py (kept to avoid
# breaking api.py consumers — PR7 decision); the screen-blackout / 60s timer /
# screenshot-detection flow that consumes it lives in ``seed_display.py``
# (:func:`display_seed`). The external contract (slots, redacted repr, raising
# __eq__, __hash__ = None, one-shot consume() with in-place wipe + deadline
# guard) holds verbatim.


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

    def expected_digest(self) -> bytes:
        """Return the prepared verification digest — confirm_generate's
        read-only egress from the handle.

        Distinct from :meth:`consume` (the display flow's egress for the
        seed):

        - It does NOT consume the handle or wipe the seed on the success
          path, so a real ``prepare → display-seed (consume) → confirm``
          flow works and confirm_generate can read the digest whether or
          not the display flow already ran.
        - The deadline guard fires only while the seed is still live
          (``not self._consumed``). The deadline bounds how long the SEED
          stays in memory; once :meth:`consume` has wiped it the deadline
          is moot — the digest itself is not sensitive — so a slow user
          who confirms after the display window still succeeds. An
          expired handle whose seed was NEVER consumed is wiped here
          before :class:`SeedDisplayExpired` is raised, so a never-shown
          seed does not outlive its deadline.

        Runs under the same per-handle lock as :meth:`consume`.
        """
        with self._lock:
            if not self._consumed and time.monotonic() > self._deadline:
                # Expired and the seed was never consumed/displayed — wipe
                # it so it does not survive past the deadline, then reject.
                self._wipe()
                raise SeedDisplayExpired("SeedDisplayHandle expired before confirm")
            return self._expected_digest

    def _wipe(self) -> None:
        # In-place zero-fill via slice assignment — overwrites the existing
        # buffer rather than rebinding ``_payload`` to a new bytearray, so
        # any aliased reference into the same buffer also observes zeros.
        self._payload[:] = bytes(len(self._payload))


# ----------------------------- DEK / envelope-id constants -----------------------------
# The MREN wire-format constants (magic, version, field widths, AAD/header
# lengths, nonce/tag sizes) live in ``_envelope_codec``. These two stay here
# because ``encrypt`` / ``_new_envelope_id`` own them, not the codec.

_DEK_LEN = 32
_ENVELOPE_ID_RAND_BYTES = 16

# ----------------------------- backup manifest constants (step-E) -----------------------------
# Frozen in SPEC.md §"export_backup / import_backup (ciphertext-rewrap
# manifest)". The portable manifest AAD deliberately OMITS the per-device
# MRKW wrapped-DEK prefix that the MREN envelope AAD carries — that prefix
# changes on every machine, so a manifest entry decrypted on the import
# device could never reconstruct it. ``manifest_aad`` instead binds only
# fields that are recomputable from ``(key_id, purpose_hash)``, so a
# tampered manifest ``key_id`` / ``purpose_hash_hex`` flips the GCM tag.
_MANIFEST_MAGIC = b"MRMN"
_MANIFEST_VERSION = 1


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
          normalized seed bytes with a default 60s deadline.
          ``seed_display.display_seed`` consumes this handle through the
          screen-blackout / 60s timer / screenshot-detection display flow.
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
    unattended: bool | None = None,
) -> GenerateResult:
    """Finalize key generation once the verification digest is confirmed.

    The durable half of two-phase generate (SPEC.md §"Two-phase generate",
    codex BLOCKER #2). :func:`prepare_generate` computed the digest in
    memory; the user transcribed the seed and confirmed the digest via the
    offline channel; this function commits the durable state — but only if
    ``user_confirmed_digest`` matches.

    Flow:

    1. Read the prepared digest via ``handle.expected_digest()`` — the
       confirm-side egress. It does NOT consume the handle (``consume()``
       is the display flow's egress, so a real prepare → display-seed →
       confirm flow works); but on an expired deadline it wipes the seed
       payload before raising :class:`SeedDisplayExpired`.
    2. ``hmac.compare_digest`` against that digest. On mismatch: emit
       ``keyvault.init_denied`` and raise :class:`VerificationDigestMismatch`
       — NO Keychain / filesystem mutation (POLICY.md #23). A sink failure
       during the denied emit is chained as ``__context__`` on the raised
       exception.
    3. Re-init guard — v1 keyvault is single-key (SPEC Story 5). Reject
       with :class:`RuntimeError` if any key already exists. Checked once
       unlocked (before ``init_started``, so a rejected re-init leaves no
       dangling audit event) and re-checked authoritatively under the lock.
    4. On match — the durable phase:

       a. Emit ``keyvault.init_started``. Durability barrier: if the audit
          sink raises here the whole init aborts (fail-closed, POLICY.md
          #21) — no key, no ``meta.json`` row.
       b. Under ``keyvault_lock`` (a single hold): re-check the re-init
          guard (TOCTOU-safe), then ``wrap.generate_wrapping_key`` to
          create the Enclave keypair. Key generation is OUTSIDE the inner
          rollback scope so a duplicate-key raise never deletes a
          pre-existing key.
       c. Still under the lock: write ``digests/<key_id_hash>.commit``
          FIRST, then the ``meta.json`` row LAST (the transaction commit
          point). Any failure rolls back — delete the Enclave key, remove
          the commit file, best-effort repair the ``meta.json`` row — then
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

    # 1. Read the prepared digest via the handle's confirm-side egress.
    #    ``expected_digest()`` checks the display deadline and, on expiry,
    #    wipes the seed payload before raising SeedDisplayExpired. It does
    #    NOT consume the handle — ``consume()`` is the display flow's
    #    egress, so a real prepare → display-seed → confirm flow works
    #    whether or not the display flow already consumed (codex P1).
    verification_digest = handle.expected_digest()

    # 2. Defense-in-depth digest check (hmac.compare_digest — constant time).
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

    # 3. Re-init guard (advisory pre-check). v1 keyvault is single-key
    #    (SPEC Story 5): reject if any key already exists, BEFORE emitting
    #    init_started, so a rejected re-init leaves no dangling init_started
    #    in the audit log. Re-checked authoritatively under the lock below.
    #    ``load_meta`` on a missing meta.json returns an empty keyvault and
    #    does not mutate the filesystem.
    root = _storage.resolve_keyvault_dir(home)
    if _storage.load_meta(root)["keys"]:
        raise RuntimeError("keyvault already initialized — v1 supports a single key")

    # 4a. init_started — durability barrier. NO try/except: a sink exception
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

    # 4b. Durable phase — the re-init re-check, key generation, and the
    #     commit/meta writes all run under a SINGLE keyvault-lock hold so
    #     the re-init guard is TOCTOU-safe against a concurrent init.
    #     The commit file is written FIRST and meta.json LAST: meta.json is
    #     the transaction commit point (codex P2). ``save_meta`` replaces
    #     meta.json via atomic_write (tmp+rename); a clean failure leaves
    #     the prior meta.json intact, and the rollback additionally repairs
    #     the row in the rare case the atomic rename committed before a
    #     later fsync raised.
    _storage.ensure_layout(root)
    created_at = _utc_now_iso()
    key_id_hash_hex = _hash_id(resolved_key_id).hex()
    commit_path: Path | None = None
    with _storage.keyvault_lock(root):
        # Authoritative re-init guard — TOCTOU-safe under the lock.
        meta = _storage.load_meta(root)
        if meta["keys"]:
            raise RuntimeError("keyvault already initialized — v1 supports a single key")

        # Create the Enclave wrapping key. OUTSIDE the inner rollback try:
        # if this raises (e.g. a meta/Keychain inconsistency surfacing as a
        # duplicate) the key belongs elsewhere and must NOT be deleted.
        wrap.generate_wrapping_key(resolved_key_id, backend=backend, unattended=unattended)

        try:
            commit_path = root / "digests" / f"{key_id_hash_hex}.commit"
            _storage.atomic_write(commit_path, verification_digest)
            meta["keys"][key_id_hash_hex] = {
                "key_id": resolved_key_id,
                "created_at": created_at,
            }
            _storage.save_meta(root, meta)
        except BaseException:
            # Rollback — best-effort, so the ORIGINAL failure always
            # propagates via the bare ``raise``. ``BaseException`` (not
            # ``Exception``) so a KeyboardInterrupt mid-write still triggers
            # cleanup. Three steps, each independently suppressed:
            #  - delete the orphaned Enclave key;
            #  - remove the digest commit file if it was written;
            #  - repair meta.json: save_meta's atomic rename may have
            #    committed the new meta.json before a later fsync raised,
            #    so re-read and drop the row if it landed (codex P2).
            with contextlib.suppress(Exception):
                wrap.delete_wrapping_key(resolved_key_id, backend=backend)
            if commit_path is not None:
                with contextlib.suppress(OSError):
                    commit_path.unlink(missing_ok=True)
            with contextlib.suppress(Exception):
                repaired = _storage.load_meta(root)
                if repaired["keys"].pop(key_id_hash_hex, None) is not None:
                    _storage.save_meta(root, repaired)
            raise

    # 4c. init_completed — success-path emit. The init is already durable,
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
    unattended: bool | None = None,
) -> GenerateResult:
    """Non-interactive convenience wrapper: prepare → confirm in one call.

    Tests and future automation use this. The wizard CLI MUST use the
    two-phase form (:func:`prepare_generate` then :func:`confirm_generate`)
    so the user transcribes the seed and confirms the verification digest
    via the offline channel before anything durable is created.

    ``generate`` delegates fully to :func:`confirm_generate` — it does not
    pre-check the digest itself. confirm_generate reads the handle's
    prepared digest (via ``expected_digest()`` — it does not consume the
    handle), compares ``expected_digest`` against it, and emits
    ``keyvault.init_denied`` on a mismatch. (SPEC.md sketched an early
    in-``generate`` check that raised without an audit emit; delegating is
    simpler and gives a non-interactive mismatch the same audit trail as
    the interactive path.)
    """
    handle, _expected = prepare_generate(seed_phrase, passphrase, pow_bytes)
    try:
        return confirm_generate(
            handle,
            expected_digest,
            key_id=key_id,
            backend=backend,
            audit_sink=audit_sink,
            home=home,
            unattended=unattended,
        )
    finally:
        # generate() is non-interactive — there is no display flow to call
        # consume(), and confirm_generate only reads the handle. Wipe the
        # seed payload here so it does not linger in memory until GC, on
        # both the success and the raise paths. consume() performs the
        # wipe; SeedDisplayExpired (an already-expired handle) is suppressed
        # since the wipe is the only thing this finally needs.
        with contextlib.suppress(SeedDisplayExpired):
            handle.consume()


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


# ----------------------------- backup / restore (step-E) -----------------------------


def _ensure_managed_subdir(path: Path) -> None:
    """Create ``path`` at mode ``0o700``, or validate it if it exists.

    Mirrors the per-directory guard :func:`encrypt` applies before writing
    an envelope: an attacker who pre-creates the directory as a symlink (or
    with a loose mode) is rejected rather than silently written through.
    """
    if path.exists() or path.is_symlink():
        _storage._check_dir_mode(path)
    else:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)


def export_backup(
    key_id: str,
    passphrase: str,
    *,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> bytes:
    """Export the whole keyvault as a portable, passphrase-protected blob.

    Cross-machine recovery is non-trivial because the Secure Enclave
    wrapping key is non-exportable (codex BLOCKER #1): an envelope's
    Enclave-wrapped DEK can never be unwrapped on a second device. So
    ``export_backup`` builds a *ciphertext-rewrap manifest* — see SPEC.md
    §"export_backup / import_backup":

    1. Walk every ``ciphertexts/<key_id_hash>/<purpose_hash>/*.gcm``
       envelope; unwrap each DEK through :func:`wrap.unwrap_dek` (one
       biometric prompt per envelope on real hardware).
    2. Decrypt the envelope under its original per-device AAD, then
       re-encrypt the plaintext under a *portable* ``manifest_aad`` that
       omits the per-device MRKW prefix (so the import device can rebuild
       it from ``key_id`` + ``purpose_hash`` alone).
    3. Pack every DEK + portable ciphertext into a canonical-JSON manifest.
    4. Wrap the manifest in a PR2 ``MRKV`` blob whose Argon2id KEK is
       derived from ``passphrase`` — that is what protects the DEKs at
       rest — embedding the keyvault's verification digest so
       :func:`import_backup` can verify-before-decrypt.

    The returned bytes are the caller's to persist (the wizard's
    ``hermes mordred keyvault export`` writes them to a user-chosen path).

    Emits exactly one ``keyvault.backup_exported`` audit entry (POLICY.md
    #24); a sink failure on that emit is suppressed since the blob is
    already in hand.
    """
    root = _storage.resolve_keyvault_dir(home)
    key_id_hash = _hash_id(key_id)
    key_id_hash_hex = key_id_hash.hex()

    # The verification digest written at generate time — read it first so a
    # not-yet-initialized key fails fast (FileNotFoundError) before any walk.
    verification_digest = _storage.safe_read(root / "digests" / f"{key_id_hash_hex}.commit")

    cipher_root = root / "ciphertexts" / key_id_hash_hex
    entries: list[dict[str, str]] = []

    # Hold the keyvault lock for the whole walk so the manifest is a
    # consistent snapshot — a concurrent encrypt() cannot add a half-written
    # envelope mid-export.
    with _storage.keyvault_lock(root):
        if cipher_root.exists() or cipher_root.is_symlink():
            _storage._check_dir_mode(cipher_root)
            for gcm_path in sorted(cipher_root.glob("*/*.gcm")):
                _storage._check_dir_mode(gcm_path.parent)
                blob = _storage.safe_read(gcm_path)
                aad, purpose_hash, wrapped_dek_blob, aes_blob = _split_envelope(blob, key_id_hash)
                dek = wrap.unwrap_dek(wrapped_dek_blob, key_id, audit_sink=audit_sink, backend=backend)
                try:
                    plaintext = AESGCM(dek).decrypt(aes_blob[:_AES_NONCE_LEN], aes_blob[_AES_NONCE_LEN:], aad)
                    # Portable AAD — no per-device MRKW prefix, so the import
                    # device reconstructs it from key_id + purpose_hash.
                    manifest_aad = _MANIFEST_MAGIC + key_id_hash + purpose_hash
                    manifest_aes_blob = crypto.encrypt(dek, plaintext, aad=manifest_aad)
                    entries.append(
                        {
                            "purpose_hash_hex": purpose_hash.hex(),
                            "envelope_id": gcm_path.stem,
                            "dek_hex": dek.hex(),
                            "manifest_aes_blob_b64": base64.b64encode(manifest_aes_blob).decode("ascii"),
                        }
                    )
                finally:
                    del dek

    manifest_json = json.dumps(
        {"version": _MANIFEST_VERSION, "key_id": key_id, "envelopes": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    out = backup.export(manifest_json, passphrase, verification_digest=verification_digest)

    # Best-effort memory hygiene: every unwrapped DEK is now sealed inside
    # ``out``. Python cannot zero immutable ``bytes`` / ``str``, but dropping
    # the plaintext manifest and the per-entry ``dek_hex`` strings shortens
    # their heap lifetime instead of pinning all DEKs for the whole call.
    envelope_count = len(entries)
    for _entry in entries:
        _entry.clear()
    entries.clear()
    del manifest_json

    # Success-path emit — the blob is already built, so a sink failure must
    # not lose it (POLICY.md #24: suppress via contextlib.suppress).
    with contextlib.suppress(Exception):
        audit_sink(
            {
                "event": "keyvault.backup_export",
                "decision": "allow",
                "reason": "keyvault.backup_exported",
                "key_id_hash": wrap._audit_key_id_hex(key_id),
                "blob_version": backup.VERSION,
                "kdf_id": backup.KDF_ID_ARGON2ID,
                "envelope_count": envelope_count,
            }
        )
    return out


def import_backup(
    blob: bytes,
    passphrase: str,
    *,
    seed_phrase: str,
    pow_bytes: bytes,
    backend: NativeBackend,
    audit_sink: AuditSink,
    home: Path | None = None,
) -> str:
    """Restore a keyvault from an :func:`export_backup` blob on this device.

    Verify-before-decrypt (SPEC.md §"export_backup / import_backup", PR2
    Codex review #4): the verification digest is recomputed from the
    transcribed ``(seed_phrase, passphrase, pow_bytes)`` and checked against
    the digest embedded in the blob BEFORE any KDF / decryption runs. A
    mismatch raises :class:`RecoveryDigestMismatch` with NO Enclave or
    filesystem mutation — steps 1-5 are pre-mutation.

    On a digest match:

    1. Decrypt the manifest, generate a fresh Enclave wrapping key for the
       imported ``key_id`` on THIS device.
    2. For each manifest entry: decrypt the portable ciphertext under its
       ``manifest_aad``, re-wrap the DEK against the new Enclave key, and
       reconstruct the MREN envelope bound to this device's AAD.
    3. Write ``digests/<kid>.commit`` then the ``meta.json`` row (the
       transaction commit point) under the keyvault lock.

    Any failure after the Enclave key is created rolls back — the
    ciphertext tree and the Enclave key are removed, and a ``meta.json``
    row is dropped if it landed — then the original exception re-raises.

    Returns the imported ``key_id``. Raises
    :class:`mordred_hermes.keyvault.backup.BackupCorrupt` for a structurally
    invalid blob or an unsupported manifest version.
    """
    # Steps 1-4 (pre-mutation): recompute the digest with split
    # normalization, then let recovery.import_backup do the length guard +
    # structural parse + verify-before-decrypt + manifest decryption. It
    # raises RecoveryDigestMismatch / BackupCorrupt before any mutation.
    recomputed_digest = compute_digest(
        _normalize_seed_phrase(seed_phrase),
        _normalize_passphrase(passphrase),
        pow_bytes,
    )
    manifest_json = recovery.import_backup(
        blob,
        passphrase,
        recomputed_digest=recomputed_digest,
        audit_sink=audit_sink,
    )

    # 5. Parse + validate the manifest. It was just AES-GCM-authenticated,
    #    so the contents are trusted; only the version gate is enforced.
    manifest = json.loads(manifest_json)
    if not isinstance(manifest, dict) or manifest.get("version") != _MANIFEST_VERSION:
        raise BackupCorrupt("unsupported or malformed backup manifest")
    # Validate the authenticated manifest's shape BEFORE generating the
    # destination Enclave key (below): a malformed field must fail closed as
    # BackupCorrupt, not raise a raw KeyError/TypeError that generates and
    # then rolls back a phantom Enclave key (security review finding).
    imported_key_id = manifest.get("key_id")
    if not isinstance(imported_key_id, str) or not imported_key_id:
        raise BackupCorrupt("backup manifest missing or invalid 'key_id'")
    envelopes_raw = manifest.get("envelopes")
    if not isinstance(envelopes_raw, list):
        raise BackupCorrupt("backup manifest missing or invalid 'envelopes'")
    envelopes: list[dict[str, str]] = envelopes_raw

    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    new_key_id_hash = _hash_id(imported_key_id)
    new_key_id_hash_hex = new_key_id_hash.hex()
    commit_path = root / "digests" / f"{new_key_id_hash_hex}.commit"

    # 6. Create the destination Enclave key. OUTSIDE the rollback try: if
    #    this raises (e.g. the key already exists) there is nothing yet to
    #    roll back and the pre-existing key must NOT be deleted.
    backend.generate_enclave_key(imported_key_id)

    try:
        with _storage.keyvault_lock(root):
            # 7. Rebuild every envelope against this device's Enclave key.
            for entry in envelopes:
                _validate_envelope_id(entry["envelope_id"])
                purpose_hash = bytes.fromhex(entry["purpose_hash_hex"])
                manifest_aes_blob = base64.b64decode(entry["manifest_aes_blob_b64"])
                dek = bytes.fromhex(entry["dek_hex"])
                try:
                    manifest_aad = _MANIFEST_MAGIC + new_key_id_hash + purpose_hash
                    plaintext = crypto.decrypt(dek, manifest_aes_blob, aad=manifest_aad)
                    new_wrapped_dek = wrap.wrap_dek(dek, imported_key_id, backend=backend)
                    envelope_bytes = _encode_envelope_from_hashes(
                        dek, plaintext, new_key_id_hash, purpose_hash, new_wrapped_dek
                    )
                finally:
                    del dek
                key_dir = root / "ciphertexts" / new_key_id_hash_hex
                purpose_dir = key_dir / purpose_hash.hex()
                _ensure_managed_subdir(key_dir)
                _ensure_managed_subdir(purpose_dir)
                _storage.atomic_write(purpose_dir / f"{entry['envelope_id']}.gcm", envelope_bytes)

            # 8. Commit digest FIRST, meta.json row LAST — meta.json is the
            #    transaction commit point (mirrors confirm_generate).
            _storage.atomic_write(commit_path, recomputed_digest)
            meta = _storage.load_meta(root)
            meta["keys"][new_key_id_hash_hex] = {
                "key_id": imported_key_id,
                "created_at": _utc_now_iso(),
            }
            _storage.save_meta(root, meta)
    except BaseException:
        # Rollback — best-effort, each step independently suppressed so the
        # ORIGINAL failure always propagates via the bare ``raise``.
        # ``BaseException`` so a KeyboardInterrupt mid-import still cleans up.
        with contextlib.suppress(Exception):
            shutil.rmtree(root / "ciphertexts" / new_key_id_hash_hex, ignore_errors=True)
        with contextlib.suppress(OSError):
            commit_path.unlink(missing_ok=True)
        with contextlib.suppress(Exception):
            backend.delete_enclave_key(imported_key_id)
        with contextlib.suppress(Exception):
            repaired = _storage.load_meta(root)
            if repaired["keys"].pop(new_key_id_hash_hex, None) is not None:
                _storage.save_meta(root, repaired)
        raise

    return imported_key_id
