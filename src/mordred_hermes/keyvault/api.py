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

Authoritative contract lives in ``docs/dev/SPEC.md``
§"PR4 API contract & MREN envelope wire format". Codex pre-implementation
review (3 BLOCKER + 5 HIGH) drove the split normalization in this
module: applying ``casefold`` and whitespace-collapse uniformly to the
passphrase weakens entropy, so the two normalizers diverge intentionally.
"""

from __future__ import annotations

import contextlib
import hmac
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, SupportsIndex

from . import _native_key_id, _secret_ops, _storage, wrap
from ._audit_emit import chain_and_raise, emit_capture
from ._envelope_codec import (
    _hash_id,
)

# The secret-operations layer (encrypt/decrypt + export/import_backup) was
# extracted into ``_secret_ops`` to keep this module under the size guideline.
# Re-exported here so the public API paths (``api.encrypt`` etc.) are unchanged.
from ._secret_ops import decrypt, encrypt, export_backup, import_backup
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
    PR2 recovery ``_emit_mismatch`` / PR3 ``_emit_unwrap_denied`` policy,
    documented once in :mod:`._audit_emit`.
    """
    return emit_capture(
        audit_sink,
        {
            "event": "keyvault.init",
            "decision": "block",
            "reason": "keyvault.init_denied",
            "key_id_hash": wrap._audit_key_id_hex(key_id),
        },
    )


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
       with :class:`RuntimeError` if any main or auxiliary native-key
       ownership state already exists. Checked once unlocked (before
       ``init_started``, so a rejected re-init leaves no dangling audit
       event) and re-checked authoritatively under the lock.
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
          FIRST, then save the ``meta.json`` row while retaining its pending
          ownership journal. Failures through that ownership save roll back.
          A second durable save clears pending; cleanup failure never deletes
          the now-owned key, and any remaining pending marker blocks use.
       d. Emit ``keyvault.init_completed``. The init is already durable,
          so a sink failure is suppressed (POLICY.md #22); a line is
          written to stderr for the operator.

    ``backend`` is keyword-only and required, matching the ``encrypt`` /
    ``decrypt`` surface. Keeping backend selection outside this pure API makes
    the hardware trust boundary explicit and lets callers choose the supported
    Secure-Enclave, TPM-helper, or test implementation deliberately.
    """
    resolved_key_id = key_id if key_id is not None else _DEFAULT_KEY_ID

    # 1. Read the prepared digest via the handle's confirm-side egress.
    #    ``expected_digest()`` checks the display deadline and, on expiry,
    #    wipes the seed payload before raising SeedDisplayExpired. It does
    #    NOT consume the handle — ``consume()`` is the display flow's
    #    egress, so a real prepare → display-seed → confirm flow works
    #    whether or not the display flow already consumed (codex P1).
    verification_digest = handle.expected_digest()
    _native_key_id.validate_main_key_id(resolved_key_id)

    # 2. Defense-in-depth digest check (hmac.compare_digest — constant time).
    #    A sink failure during the denied emit is chained as __context__ so
    #    it stays diagnosable without displacing the primary mismatch signal
    #    (the PR2 recovery._emit_mismatch pattern — see _audit_emit).
    if not hmac.compare_digest(user_confirmed_digest, verification_digest):
        sink_exc = _emit_init_denied(audit_sink, key_id=resolved_key_id)
        chain_and_raise(
            VerificationDigestMismatch("user-confirmed digest does not match the prepared verification digest"),
            sink_exc,
        )

    # 3. Re-init guard (advisory pre-check). v1 keyvault is single-key
    #    (SPEC Story 5): reject if any key already exists, BEFORE emitting
    #    init_started, so a rejected re-init leaves no dangling init_started
    #    in the audit log. Re-checked authoritatively under the lock below.
    #    ``load_meta`` on a missing meta.json returns an empty keyvault and
    #    does not mutate the filesystem.
    root = _storage.resolve_keyvault_dir(home)
    _storage.assert_keyvault_active(root)
    preflight_meta = _storage.load_meta(root)
    if _native_key_id.has_native_key_ownership_state(preflight_meta):
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
    #     The commit file is written FIRST. Metadata then commits in two
    #     durable saves: row + pending ownership first, pending removal
    #     second. A post-rename fsync failure can therefore never expose an
    #     apparently complete row that lost the cleanup/rollback decision.
    _storage.ensure_layout(root)
    backend = _native_key_id.bind_backend_to_root(backend, root)
    created_at = _utc_now_iso()
    key_id_hash_hex = _hash_id(resolved_key_id).hex()
    commit_path: Path | None = None
    with _storage.keyvault_lock(root):
        # Authoritative re-init guard — TOCTOU-safe under the lock.
        meta = _storage.load_meta(root)
        if _native_key_id.has_native_key_ownership_state(meta):
            raise RuntimeError("keyvault already initialized — v1 supports a single key")

        # Journal deterministic ownership durably before native generation.
        # A helper may publish a key and then report a durability error; the
        # journal lets reset safely retry cleanup without guessing ownership.
        native_key_id = _native_key_id.add_pending_native_key(root, meta, resolved_key_id)
        _storage.save_meta(root, meta)

        # If generation raises, retain the pending journal: the backend may
        # have made the scoped key visible before reporting its error.
        wrap.generate_wrapping_key(
            resolved_key_id,
            backend=backend,
            unattended=unattended,
            native_key_id=native_key_id,
        )

        try:
            commit_path = root / "digests" / f"{key_id_hash_hex}.commit"
            _storage.atomic_write(commit_path, verification_digest)
            meta["keys"][key_id_hash_hex] = {
                "key_id": resolved_key_id,
                "created_at": created_at,
                _native_key_id.NATIVE_KEY_ID_FIELD: native_key_id,
            }
            # Ownership commit: retain the pending journal beside the row.
            # If save_meta publishes then reports an fsync error and native
            # rollback also fails, normal key use still sees pending and
            # fails closed.
            _storage.save_meta(root, meta)
        except BaseException:
            # Rollback — best-effort, so the ORIGINAL failure always
            # propagates via the bare ``raise``. ``BaseException`` (not
            # ``Exception``) so a KeyboardInterrupt mid-write still triggers
            # cleanup. confirm_generate wrote no ciphertext envelopes, so
            # only the Enclave key / commit file / meta.json row are undone
            # (the step-by-step rationale lives on ``_rollback_import``).
            _secret_ops._rollback_import(
                root,
                new_key_id_hash_hex=key_id_hash_hex,
                commit_path=commit_path,
                imported_key_id=resolved_key_id,
                native_key_id=native_key_id,
                backend=backend,
                remove_ciphertext_tree=False,
            )
            raise

        # Cleanup commit: once row + pending is durably owned, clearing only
        # the pending marker is never a reason to delete the key. The helper
        # accepts a post-replace error only when the visible row is complete
        # and pending-free; otherwise the error propagates and pending blocks
        # every normal operation until reset.
        _secret_ops._clear_pending_native_key_after_commit(
            root,
            key_id=resolved_key_id,
            key_id_hash_hex=key_id_hash_hex,
            native_key_id=native_key_id,
        )

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
        from .. import _term

        _term.emit_warn(
            f"keyvault.init_completed audit emit failed (init already durable, key_id_hash={key_id_hash_hex}): {exc!r}"
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
