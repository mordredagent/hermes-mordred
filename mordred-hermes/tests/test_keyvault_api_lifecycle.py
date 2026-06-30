"""Tests for ``mordred_hermes.keyvault.api`` lifecycle surface.

Phase 4 PR4 step-D, slice PR4c-1 (2026-05-15) — covers the first two
lifecycle entry points: ``SeedDisplayHandle`` opaque-class contract and
``prepare_generate`` (in-memory phase). The rest of step-D
(``confirm_generate`` → ``generate`` → ``export_backup`` →
``import_backup``) lands in PR4c-2 and later.

The ``SeedDisplayHandle`` contract is frozen in SPEC.md §"PR4 API
contract / SeedDisplayHandle (opaque, codex BLOCKER #3)", with two
step-D extensions landed in PR4c-1 (the 4th + 5th slots), both
documented in SPEC.md under the "Step-D extension" callout in the
same section.

    class SeedDisplayHandle:
        __slots__ = ("_payload", "_consumed", "_deadline",
                     "_expected_digest", "_lock")
        # __repr__ → "<SeedDisplayHandle redacted>"
        # __eq__   → raise TypeError(... comparison oracle ...)
        # __hash__ = None
        # __copy__ / __deepcopy__ / __reduce__ / __reduce_ex__ /
        #   __getstate__ / __setstate__ → raise TypeError (opaque)
        # consume(): one-shot, zero-fills _payload, second call raises
        #            RuntimeError; past deadline raises SeedDisplayExpired
        #            after wiping. Whole body runs under _lock so the
        #            one-shot guarantee holds across threads.
        # _expected_digest: 32-byte digest baked in by prepare_generate,
        #            read by confirm_generate for hmac.compare_digest
        #            against the user-typed digest.
        # _lock: per-handle threading.Lock serializing consume().

The class lives in ``api.py`` for PR4. PR5 will relocate it to
``seed_display.py`` and layer screen-blackout / 60s timer / screenshot
detection on top, but the opaque-class contract pinned here MUST hold
verbatim after the relocation.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime
import hashlib
import inspect
import io
import pickle
import re
import time
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _storage, api, wrap

# FakeBackend stands in for the real Secure Enclave — software P-256 keypair.
# Step-G will relocate it to a shared tests._keyvault_fakes module.
from tests.test_keyvault_wrap import FakeBackend

# ----------------------------- helpers / fixtures -----------------------------


_SEED = "abandon abandon abandon abandon abandon abandon"
# Far enough in the future that consume() never trips the deadline guard.
_FAR_FUTURE = 1.0e12
# Far enough in the past that any consume() trips the deadline guard.
_FAR_PAST = -1.0e12
# 32-byte placeholder digest for handle construction in tests that don't
# care about digest contents (only structural / consume / repr behavior).
_PLACEHOLDER_DIGEST = b"\x00" * 32


def _make_handle(
    seed: str = _SEED,
    deadline: float = _FAR_FUTURE,
    expected_digest: bytes = _PLACEHOLDER_DIGEST,
) -> Any:
    return api.SeedDisplayHandle(seed, deadline, expected_digest)


# ============================ structural contract ============================


class TestSlotsLayout:
    """``__slots__`` is the only allowed attribute surface (no ``__dict__``).

    Rationale: a stray ``handle.seed_phrase = ...`` assignment would
    silently leak the seed through ``__dict__`` introspection. ``__slots__``
    pins the attribute set at class-creation time, AttributeError fires
    on any other name.
    """

    def test_slots_value_is_exact_five_tuple(self) -> None:
        """The handle carries (seed bytes, consumed flag, deadline, expected
        digest, consume lock). The 4th slot makes confirm_generate's
        defense-in-depth digest check possible; the 5th (``_lock``)
        serializes ``consume()`` so the one-shot guarantee holds even if
        the handle is shared across threads.
        """
        assert api.SeedDisplayHandle.__slots__ == (
            "_payload",
            "_consumed",
            "_deadline",
            "_expected_digest",
            "_lock",
        )

    def test_instance_has_no_dict(self) -> None:
        handle = _make_handle()
        assert not hasattr(handle, "__dict__")

    def test_arbitrary_attribute_assignment_rejected(self) -> None:
        handle = _make_handle()
        with pytest.raises(AttributeError):
            handle.seed_phrase = _SEED  # type: ignore[attr-defined]

    def test_payload_starts_as_utf8_encoded_seed(self) -> None:
        """White-box: pin the bytearray initialization so wipe-tests below can
        compare against zero-fill in the same buffer.
        """
        handle = _make_handle()
        assert bytes(handle._payload) == _SEED.encode("utf-8")  # type: ignore[attr-defined]

    def test_expected_digest_stored_verbatim(self) -> None:
        """The third constructor argument is held on the instance for
        confirm_generate to compare against the user-typed digest.
        """
        digest = b"\xab" * 32
        handle = _make_handle(expected_digest=digest)
        assert handle._expected_digest == digest  # type: ignore[attr-defined]


# ============================ expected_digest length validation ============================


class TestExpectedDigestValidation:
    """``__init__`` rejects any ``expected_digest`` that is not 32 bytes.

    The verification digest is always a 32-byte BLAKE3 output. ``confirm_generate``
    (PR4c-2) compares the user-typed digest against ``_expected_digest`` via
    ``hmac.compare_digest``, which accepts unequal-length operands and just
    returns False — so a wrong-length value would silently produce a mismatch
    far from the construction-site bug. Validating at the constructor boundary
    surfaces a caller bug (e.g. a future ``import_backup`` reconstructing
    handles) immediately and loudly.
    """

    def test_too_short_digest_raises_valueerror(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            api.SeedDisplayHandle(_SEED, _FAR_FUTURE, b"\x00" * 31)

    def test_too_long_digest_raises_valueerror(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            api.SeedDisplayHandle(_SEED, _FAR_FUTURE, b"\x00" * 33)

    def test_empty_digest_raises_valueerror(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            api.SeedDisplayHandle(_SEED, _FAR_FUTURE, b"")

    def test_exactly_32_bytes_accepted(self) -> None:
        """The boundary value — exactly 32 bytes — must NOT raise."""
        handle = api.SeedDisplayHandle(_SEED, _FAR_FUTURE, b"\x00" * 32)
        assert handle._expected_digest == b"\x00" * 32  # type: ignore[attr-defined]

    def test_bytearray_digest_stored_as_immutable_bytes(self) -> None:
        """A 32-byte bytearray passes the length check; the handle must
        coerce it to immutable ``bytes`` rather than store the mutable
        object.
        """
        handle = api.SeedDisplayHandle(_SEED, _FAR_FUTURE, bytearray(32))
        assert type(handle._expected_digest) is bytes  # type: ignore[attr-defined]

    def test_mutating_caller_bytearray_does_not_affect_stored_digest(self) -> None:
        """confirm_generate (PR4c-2) compares the user-typed digest against
        ``_expected_digest``. If a caller passed a bytearray and retained a
        live alias, mutating that alias post-construction would change the
        compare target without touching the handle — a confirm-time TOCTOU.
        The constructor must copy the digest so the stored value is frozen
        for the handle's lifetime (codex pre-merge P2, 2026-05-15).
        """
        mutable = bytearray(b"\xaa" * 32)
        handle = api.SeedDisplayHandle(_SEED, _FAR_FUTURE, mutable)
        mutable[0] = 0x00  # mutate the caller's original buffer
        assert handle._expected_digest[0] == 0xAA  # type: ignore[attr-defined]
        assert handle._expected_digest == b"\xaa" * 32  # type: ignore[attr-defined]

    def test_nonbyte_width_memoryview_validated_by_byte_length(self) -> None:
        """``len()`` on a non-byte-width memoryview counts ELEMENTS, not
        bytes. A memoryview over a 2-byte-element array holding 16 elements
        is 32 bytes — it must be accepted. The constructor must coerce to
        ``bytes`` first, then validate the byte length of the coerced value
        (codex pre-merge P3, 2026-05-15).
        """
        from array import array

        # 16 elements x 2 bytes/element = 32 bytes; len(memoryview) == 16.
        view_32_bytes = memoryview(array("H", [0] * 16))
        assert len(view_32_bytes) == 16  # sanity: element count, not bytes
        assert view_32_bytes.nbytes == 32  # sanity: actual byte length
        handle = api.SeedDisplayHandle(_SEED, _FAR_FUTURE, view_32_bytes)
        assert handle._expected_digest == b"\x00" * 32  # type: ignore[attr-defined]

    def test_nonbyte_width_memoryview_wrong_byte_length_rejected(self) -> None:
        """The mirror case: a memoryview whose ELEMENT count is 32 but whose
        BYTE length is 64 must be rejected. Element-count validation would
        wrongly accept it; byte-length validation (post-coercion) rejects it.
        """
        from array import array

        # 32 elements x 2 bytes/element = 64 bytes; len(memoryview) == 32.
        view_64_bytes = memoryview(array("H", [0] * 32))
        assert len(view_64_bytes) == 32  # element count would pass a naive check
        assert view_64_bytes.nbytes == 64  # actual byte length is wrong
        with pytest.raises(ValueError, match="32 bytes"):
            api.SeedDisplayHandle(_SEED, _FAR_FUTURE, view_64_bytes)


# ============================ expected_digest() — confirm-side egress ============================


class TestExpectedDigestMethod:
    """``expected_digest()`` is confirm_generate's read-only egress from the
    handle: it returns the prepared verification digest WITHOUT consuming
    the handle (consume() is the display flow's egress), but wipes the seed
    payload if the handle has expired so a never-displayed seed does not
    outlive its deadline (codex pre-merge P2).
    """

    def test_returns_the_expected_digest(self) -> None:
        digest = b"\x5a" * 32
        handle = _make_handle(expected_digest=digest)
        assert handle.expected_digest() == digest

    def test_does_not_consume_the_handle(self) -> None:
        """Unlike consume(), expected_digest() leaves the handle usable —
        the display flow can still consume() the seed afterwards.
        """
        handle = _make_handle()
        handle.expected_digest()
        assert handle.consume() == _SEED

    def test_callable_repeatedly(self) -> None:
        """A pure read on the non-expired path — no one-shot guard."""
        handle = _make_handle(expected_digest=b"\x5a" * 32)
        assert handle.expected_digest() == b"\x5a" * 32
        assert handle.expected_digest() == b"\x5a" * 32

    def test_expired_raises_seed_display_expired(self) -> None:
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            handle.expected_digest()

    def test_expired_wipes_the_payload(self) -> None:
        """An expired, never-displayed handle must not keep the seed in
        memory past its deadline — expected_digest() wipes on expiry.
        """
        handle = _make_handle(deadline=_FAR_PAST)
        original_payload = handle._payload  # type: ignore[attr-defined]
        with pytest.raises(api.SeedDisplayExpired):
            handle.expected_digest()
        assert all(b == 0 for b in original_payload)

    def test_works_on_an_already_display_consumed_handle(self) -> None:
        """The real flow is prepare → display consume() → confirm. After the
        display flow consumed the seed, expected_digest() still returns the
        digest (consume wipes _payload, not _expected_digest).
        """
        digest = b"\x5a" * 32
        handle = _make_handle(expected_digest=digest)
        handle.consume()  # display flow renders + wipes the seed
        assert handle.expected_digest() == digest

    def test_expired_but_already_consumed_returns_digest(self) -> None:
        """The deadline bounds how long the SEED stays in memory. Once the
        display flow has consumed (and wiped) the seed, the deadline is
        moot — expected_digest() must return the digest even past the
        deadline, so a slow user who confirms after the 60s display window
        still succeeds (codex pre-merge P2).
        """
        digest = b"\x5a" * 32
        handle = _make_handle(deadline=_FAR_PAST, expected_digest=digest)
        # consume() on an expired handle raises, but still wipes the seed
        # and marks the handle consumed.
        with pytest.raises(api.SeedDisplayExpired):
            handle.consume()
        # The seed is already gone — expiry no longer applies.
        assert handle.expected_digest() == digest

    def test_expired_and_never_consumed_still_raises(self) -> None:
        """The mirror of the above: an expired handle whose seed was NEVER
        consumed must still raise — the deadline guard exists precisely to
        wipe a never-displayed seed.
        """
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            handle.expected_digest()


# ============================ repr / str (no leakage) ============================


class TestRedactedRepr:
    """The seed must never appear in ``repr`` or ``str``.

    A naive frozen dataclass would auto-derive ``repr`` that echoes
    every field, including the seed. The custom ``__repr__`` makes
    ``logging.debug(handle)`` / interactive-session inspection safe.
    """

    def test_repr_is_exact_redacted_marker(self) -> None:
        handle = _make_handle()
        assert repr(handle) == "<SeedDisplayHandle redacted>"

    def test_repr_does_not_leak_seed_substring(self) -> None:
        # Use a seed with a distinctive token so a partial leak would surface.
        handle = _make_handle("avocado banjo carbon dalmatian")
        assert "avocado" not in repr(handle)
        assert "banjo" not in repr(handle)

    def test_str_falls_back_to_repr_and_redacts(self) -> None:
        handle = _make_handle("uniqueseedmarker")
        assert "uniqueseedmarker" not in str(handle)
        assert str(handle) == "<SeedDisplayHandle redacted>"

    def test_repr_after_consume_still_redacted(self) -> None:
        handle = _make_handle()
        handle.consume()
        assert repr(handle) == "<SeedDisplayHandle redacted>"


# ============================ equality (always raises) ============================


class TestEqualityRaises:
    """``__eq__`` raises ``TypeError`` so no comparison oracle exists.

    A working ``__eq__`` would let an attacker bisect the seed by
    feeding candidate strings into ``handle == "guess"`` until True
    surfaces. Raising eliminates the channel entirely; identity (``is``)
    still works for the legitimate "is this the same handle" case.
    """

    def test_eq_against_self_raises_typeerror(self) -> None:
        handle = _make_handle()
        with pytest.raises(TypeError) as excinfo:
            handle == handle  # noqa: B015 — intentional: trigger __eq__
        assert "comparison oracle" in str(excinfo.value)

    def test_eq_against_other_handle_raises_typeerror(self) -> None:
        h1 = _make_handle()
        h2 = _make_handle()
        with pytest.raises(TypeError):
            h1 == h2  # noqa: B015 — intentional: trigger __eq__

    def test_eq_against_string_raises_typeerror(self) -> None:
        handle = _make_handle()
        with pytest.raises(TypeError):
            handle == _SEED  # noqa: B015 — intentional: trigger __eq__

    def test_ne_also_raises_typeerror(self) -> None:
        """``!=`` defaults to inverting ``__eq__`` — so it must also raise."""
        handle = _make_handle()
        with pytest.raises(TypeError):
            handle != "anything"  # noqa: B015 — intentional: trigger __ne__

    def test_identity_still_works(self) -> None:
        """``is`` is not affected by ``__eq__`` — legitimate same-object
        comparisons must still succeed.
        """
        handle = _make_handle()
        assert handle is handle
        assert handle is not _make_handle()


# ============================ hashability (unhashable) ============================


class TestUnhashable:
    """``__hash__ = None`` so handles cannot land in a dict / set by accident.

    Hash-based memoization is a long-lived-retention vector: a stale
    cache entry would extend the seed's residency in process memory
    far beyond the intentional 60-second display window. Blocking
    hashability prevents the entire class of bug.
    """

    def test_hash_attribute_is_none_at_class_level(self) -> None:
        assert api.SeedDisplayHandle.__hash__ is None

    def test_hash_call_raises_typeerror(self) -> None:
        handle = _make_handle()
        with pytest.raises(TypeError):
            hash(handle)

    def test_cannot_be_added_to_set(self) -> None:
        handle = _make_handle()
        with pytest.raises(TypeError):
            {handle}  # noqa: B018 — intentional: trigger set construction

    def test_cannot_be_used_as_dict_key(self) -> None:
        handle = _make_handle()
        with pytest.raises(TypeError):
            {handle: 1}  # noqa: B018 — intentional: trigger dict construction


# ============================ copy / pickle (blocked) ============================


class TestCopyPickleBlocked:
    """Default ``copy.copy`` / ``copy.deepcopy`` / ``pickle`` bypass the
    one-shot consume contract.

    Codex pre-merge P2 (2026-05-15): a slotted handle is copyable and
    picklable by default because Python's machinery walks ``__slots__``
    and serializes each entry. The duplicate can ``consume()`` again
    after the original was wiped, and the pickle bytes themselves
    contain the raw seed payload. Blocking these dunders is the only
    way to make "opaque + one-shot" actually mean what it says.
    """

    def test_copy_copy_raises_typeerror(self) -> None:
        handle = _make_handle("supersecret")
        with pytest.raises(TypeError) as excinfo:
            copy.copy(handle)
        # Error message mentions "opaque" so the failure mode is obvious.
        assert "opaque" in str(excinfo.value).lower()

    def test_copy_deepcopy_raises_typeerror(self) -> None:
        handle = _make_handle("supersecret")
        with pytest.raises(TypeError) as excinfo:
            copy.deepcopy(handle)
        assert "opaque" in str(excinfo.value).lower()

    def test_pickle_dumps_raises_typeerror(self) -> None:
        handle = _make_handle("supersecret")
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(handle)
        assert "opaque" in str(excinfo.value).lower()

    def test_reduce_directly_raises_typeerror(self) -> None:
        """``__reduce__`` is defined alongside ``__reduce_ex__``; exercise it
        directly so the dunder's behavior is pinned even though pickle
        reaches the class via ``__reduce_ex__`` in practice.
        """
        handle = _make_handle("supersecret")
        with pytest.raises(TypeError) as excinfo:
            handle.__reduce__()
        assert "opaque" in str(excinfo.value).lower()

    def test_pickle_dumps_does_not_leak_seed_in_partial_buffer(self) -> None:
        """Even if pickle.dumps raises, the seed must not have already
        landed in any partial buffer that's accessible to the caller.
        The TypeError must fire before any seed bytes are emitted.
        """
        handle = _make_handle("verysecretseedphrase")
        buffer = io.BytesIO()
        pickler = pickle.Pickler(buffer)
        with pytest.raises(TypeError):
            pickler.dump(handle)
        # Whatever pickle wrote before raising must not contain the seed.
        assert b"verysecretseedphrase" not in buffer.getvalue()

    def test_getstate_raises_typeerror(self) -> None:
        """On Python 3.11+ slotted objects inherit ``object.__getstate__``,
        which returns ``(None, {'_payload': bytearray(...), ...})`` — a
        direct seed-leak channel that bypasses ``consume()`` entirely (the
        copy/pickle guards only cover ``__reduce*__``). Block it
        (codex pre-merge P2, 2026-05-15).
        """
        handle = _make_handle("supersecret")
        with pytest.raises(TypeError) as excinfo:
            handle.__getstate__()
        assert "opaque" in str(excinfo.value).lower()

    def test_getstate_does_not_leak_seed(self) -> None:
        """Belt-and-suspenders: even if a future refactor changed the
        exception type, the call must not return the seed payload.
        """
        handle = _make_handle("verysecretseedphrase")
        try:
            state = handle.__getstate__()
        except TypeError:
            return  # blocked as intended
        pytest.fail(f"__getstate__ must raise, not return state: {state!r}")

    def test_setstate_raises_typeerror(self) -> None:
        """``__setstate__`` is blocked for symmetry — a reconstructed handle
        must never be populated from an external state dict.
        """
        handle = _make_handle("supersecret")
        with pytest.raises(TypeError) as excinfo:
            handle.__setstate__({})
        assert "opaque" in str(excinfo.value).lower()


# ============================ consume() — one-shot + zero-fill ============================


class TestConsumeOneShot:
    """``consume()`` returns the normalized seed exactly once, then wipes.

    The bytearray is wiped *in-place* (not replaced) so any other
    reference into ``_payload`` also observes zero bytes — important
    because ``ctypes.memmove`` or a debugger snapshot could hold a raw
    pointer into the same buffer.
    """

    def test_first_consume_returns_normalized_seed(self) -> None:
        handle = _make_handle()
        assert handle.consume() == _SEED

    def test_consume_zero_fills_payload_in_place(self) -> None:
        handle = _make_handle()
        # Capture the bytearray reference BEFORE consume so we can verify
        # the SAME buffer is wiped (not just replaced with a new bytearray).
        original_payload = handle._payload  # type: ignore[attr-defined]
        assert any(b != 0 for b in original_payload)  # sanity: starts non-zero
        handle.consume()
        assert all(b == 0 for b in original_payload), "payload must be wiped in-place after consume()"
        # Pin that the slot still holds the SAME bytearray object — a refactor
        # of _wipe to ``self._payload = bytearray(...)`` would leave the old
        # (aliased) buffer un-zeroed and silently pass the content check above.
        assert handle._payload is original_payload  # type: ignore[attr-defined]

    def test_consume_preserves_payload_length(self) -> None:
        """Wipe is zero-fill, not truncate — length stays equal to the
        encoded seed so timing on the buffer doesn't leak post-wipe."""
        handle = _make_handle()
        original_len = len(handle._payload)  # type: ignore[attr-defined]
        handle.consume()
        assert len(handle._payload) == original_len  # type: ignore[attr-defined]

    def test_second_consume_raises_runtimeerror(self) -> None:
        handle = _make_handle()
        handle.consume()
        with pytest.raises(RuntimeError) as excinfo:
            handle.consume()
        assert "already consumed" in str(excinfo.value)

    def test_consume_preserves_unicode_normalized_form(self) -> None:
        """The handle holds the *already-normalized* seed bytes; consume()
        returns the string as stored. Verify a non-ASCII seed round-trips
        through the bytearray encode/decode cycle without corruption.
        """
        japanese_seed = "あいう えお"  # NFKD-stable
        handle = _make_handle(japanese_seed)
        assert handle.consume() == japanese_seed


# ============================ consume() — deadline expiry ============================


class TestDeadlineExpiry:
    """consume() past the monotonic deadline raises ``SeedDisplayExpired``.

    Even when the user never interacts with the display, the handle's
    in-memory payload must be wiped after the 60s window. The deadline
    check fires inside ``consume()`` because that is the only ingress
    that releases the seed to a caller.
    """

    def test_seed_display_expired_is_exported(self) -> None:
        assert hasattr(api, "SeedDisplayExpired")
        assert issubclass(api.SeedDisplayExpired, Exception)

    def test_consume_past_deadline_raises_seeddisplayexpired(self) -> None:
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            handle.consume()

    def test_consume_past_deadline_still_wipes_payload(self) -> None:
        handle = _make_handle(deadline=_FAR_PAST)
        original_payload = handle._payload  # type: ignore[attr-defined]
        with pytest.raises(api.SeedDisplayExpired):
            handle.consume()
        assert all(b == 0 for b in original_payload), "expired consume() must still wipe the payload"

    def test_consume_after_expired_consume_raises(self) -> None:
        """Once an expired consume() has wiped + raised, the handle is
        terminally unusable — a follow-up call must also raise (either
        SeedDisplayExpired again, or RuntimeError "already consumed";
        both are acceptable as long as no seed comes back).
        """
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            handle.consume()
        with pytest.raises((api.SeedDisplayExpired, RuntimeError)):
            handle.consume()

    def test_consume_just_before_deadline_succeeds(self) -> None:
        """Sanity check that the deadline guard is not always-on. Use a
        deadline well ahead of the call site so any reasonable clock
        skew stays on the non-expired side.
        """
        handle = _make_handle(deadline=time.monotonic() + 30.0)
        assert handle.consume() == _SEED


# ============================ consume() — thread safety ============================


class TestConsumeThreadSafety:
    """``consume()`` is one-shot even when a handle is shared across threads.

    Codex pre-merge P2 (2026-05-15): the ``if self._consumed`` check and the
    later ``self._consumed = True`` set are separated by the deadline check,
    the decode, and the wipe. Without serialization, two threads can both
    pass the check before either sets the flag — both decode the live
    ``_payload`` and the seed is released twice. ``consume()`` must hold a
    per-handle lock across the whole check / decode / wipe / set section so
    exactly one caller ever receives the seed.
    """

    def test_concurrent_consume_releases_seed_at_most_once(self) -> None:
        """Burst many threads at one shared handle through a barrier so they
        all enter ``consume()`` as simultaneously as the scheduler allows.
        Exactly one call must return the seed; every other call must raise
        RuntimeError("already consumed"). A second successful return is the
        race this test guards against.

        ``sys.setswitchinterval`` is dropped to a very small value for the
        duration so the interpreter preempts threads aggressively inside the
        check / decode / wipe / set window — without that, the unlocked
        race almost never interleaves unfavorably and the test would pass
        even against the buggy code.
        """
        import sys
        import threading

        worker_count = 64
        handle = _make_handle("racetestseed")
        barrier = threading.Barrier(worker_count)
        results: list[str] = []
        errors: list[BaseException] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()  # release all workers as close to simultaneously as possible
            try:
                seed = handle.consume()
            except RuntimeError as exc:  # expected for all-but-one
                with results_lock:
                    errors.append(exc)
            else:
                with results_lock:
                    results.append(seed)

        original_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            threads = [threading.Thread(target=worker) for _ in range(worker_count)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(original_interval)

        # Exactly one worker may have received the seed.
        assert len(results) == 1, f"consume() released the seed {len(results)} times — must be exactly 1"
        assert results == ["racetestseed"]
        # Every other worker must have hit the one-shot guard.
        assert len(errors) == worker_count - 1
        assert all("already consumed" in str(e) for e in errors)


# ============================ prepare_generate (in-memory phase) ============================
#
# Contract frozen in SPEC.md §"PR4 API contract / Two-phase generate":
#
#     def prepare_generate(
#         seed_phrase: str,
#         passphrase: str,
#         pow_bytes: bytes,
#     ) -> tuple[SeedDisplayHandle, bytes]:
#         # In-memory only. Computes digest from normalized inputs.
#         # NO Keychain creation, NO meta.json write, NO digests/ commit,
#         # NO audit emit. Pure function with respect to disk state.
#
# Normalization split (SPEC.md §"Mordred normalization", codex HIGH #1):
#   - seed_phrase: NFKD + strip Cf chars + casefold + collapse whitespace
#   - passphrase: NFKD only — case and whitespace are entropy, must NOT collapse


# SPEC L355-362 canonical test vector — pinned in
# tests/test_keyvault_digest.py::TestSpecFixedVector and re-pinned here at the
# API layer so any normalization drift surfaces against the SPEC anchor.
_SPEC_SEED = "test seed"
_SPEC_PASSPHRASE = "test pass"
_SPEC_POW = bytes.fromhex("deadbeef") + b"\x00" * 28
_SPEC_DIGEST = bytes.fromhex("25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93")


class TestPrepareGenerateSignature:
    """``prepare_generate`` returns ``(SeedDisplayHandle, 32-byte digest)``.

    Pure function: no disk I/O, no audit_sink parameter, no backend
    parameter. The two-phase split exists so that nothing durable
    happens before the user has confirmed the digest via the offline
    channel (SPEC §"Key generation" mandates "mandatory and one-shot").
    """

    def test_returns_two_tuple(self) -> None:
        result = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_first_element_is_seed_display_handle(self) -> None:
        handle, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert isinstance(handle, api.SeedDisplayHandle)

    def test_second_element_is_bytes_of_length_32(self) -> None:
        _, digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert isinstance(digest, bytes)
        assert len(digest) == 32


class TestPrepareGenerateCanonicalVector:
    """ASCII canonical inputs reproduce SPEC.md §"Fixed test vector" digest.

    The digest table at SPEC L355-362 is the regression anchor for the
    whole compute_digest algorithm. Re-pinning the final digest at the
    api.py layer guards against silent normalization regressions that
    would only surface at recovery time.
    """

    def test_spec_vector_digest_matches(self) -> None:
        _, digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert digest == _SPEC_DIGEST


class TestPrepareGenerateDeterminism:
    """Same inputs → same digest. Different inputs → different digest."""

    def test_same_inputs_produce_same_digest(self) -> None:
        _, d1 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        _, d2 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert d1 == d2

    def test_different_seed_produces_different_digest(self) -> None:
        _, d1 = api.prepare_generate("seed one", _SPEC_PASSPHRASE, _SPEC_POW)
        _, d2 = api.prepare_generate("seed two", _SPEC_PASSPHRASE, _SPEC_POW)
        assert d1 != d2

    def test_different_passphrase_produces_different_digest(self) -> None:
        _, d1 = api.prepare_generate(_SPEC_SEED, "pass one", _SPEC_POW)
        _, d2 = api.prepare_generate(_SPEC_SEED, "pass two", _SPEC_POW)
        assert d1 != d2

    def test_different_pow_produces_different_digest(self) -> None:
        pow_a = bytes.fromhex("deadbeef") + b"\x00" * 28
        pow_b = bytes.fromhex("cafef00d") + b"\x00" * 28
        _, d1 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, pow_a)
        _, d2 = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, pow_b)
        assert d1 != d2


class TestPrepareGenerateSeedNormalization:
    """Seed phrase: NFKD + Cf-strip + casefold + whitespace-collapse.

    BIP39 word-list tolerance — typo-noise (mixed case, extra spaces,
    non-ASCII whitespace forms, invisible Cf chars from clipboard
    injection) collapses to the same digest as a clean reference input.
    """

    def test_seed_uppercase_collapses_via_casefold(self) -> None:
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, upper = api.prepare_generate("TEST SEED", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == upper

    def test_seed_extra_whitespace_collapses(self) -> None:
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, padded = api.prepare_generate("  test   seed  ", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == padded

    def test_seed_tab_whitespace_treated_as_space(self) -> None:
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, tabbed = api.prepare_generate("test\tseed", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == tabbed

    def test_seed_nbsp_collapses_via_nfkd(self) -> None:
        """U+00A0 NO-BREAK SPACE decomposes to U+0020 under NFKD, so the
        BIP39 word-list tolerance covers clipboard-typo NBSP transparently.
        """
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        # Build the NBSP form via explicit escape so the source file does not
        # carry an ambiguous literal (ruff RUF001 would flag that).
        nbsp_seed = "test\u00a0seed"
        _, nbsp = api.prepare_generate(nbsp_seed, _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == nbsp

    def test_seed_zwsp_stripped_via_cf_category(self) -> None:
        """U+200B ZERO WIDTH SPACE is Cf-category — NFKD-stable and not a
        whitespace split, so without explicit Cf-strip it would silently
        change the digest. The strip closes the clipboard-injection gap
        (code-reviewer MEDIUM-1, 2026-05-15).
        """
        _, ref = api.prepare_generate("test seed", _SPEC_PASSPHRASE, _SPEC_POW)
        _, with_zwsp = api.prepare_generate("te​st seed", _SPEC_PASSPHRASE, _SPEC_POW)
        assert ref == with_zwsp

    def test_seed_japanese_precomposed_equals_decomposed(self) -> None:
        """NFKD decomposes Japanese precomposed dakuon (e.g. が U+304C) into
        base + combining mark (か U+304B + U+3099). The two input forms
        must produce the same digest.
        """
        precomposed = "がぎぐげご"
        decomposed = "がぎぐげご"
        _, d_pre = api.prepare_generate(precomposed, _SPEC_PASSPHRASE, _SPEC_POW)
        _, d_dec = api.prepare_generate(decomposed, _SPEC_PASSPHRASE, _SPEC_POW)
        assert d_pre == d_dec


class TestPrepareGeneratePassphraseNormalization:
    """Passphrase: NFKD only. Case and whitespace are entropy.

    Casefold-collapse on the passphrase would conflate distinct Unicode
    strings; whitespace-collapse drops entropy. The split exists exactly
    so the passphrase preserves what the user actually typed (codex HIGH
    #1). NFKD is still applied so Japanese precomposed/decomposed
    equivalence holds.
    """

    def test_passphrase_case_change_changes_digest(self) -> None:
        """A casefold of the passphrase would silently mask a typo at
        recovery time. Recovery requires reproducing the exact case.
        """
        _, lower = api.prepare_generate(_SPEC_SEED, "secret", _SPEC_POW)
        _, upper = api.prepare_generate(_SPEC_SEED, "SECRET", _SPEC_POW)
        assert lower != upper

    def test_passphrase_extra_whitespace_changes_digest(self) -> None:
        _, single = api.prepare_generate(_SPEC_SEED, "a b", _SPEC_POW)
        _, double = api.prepare_generate(_SPEC_SEED, "a  b", _SPEC_POW)
        assert single != double

    def test_passphrase_zwsp_changes_digest(self) -> None:
        """Passphrase normalization does NOT strip Cf chars — a user who
        chose to embed an invisible char did so intentionally and must
        reproduce the exact bytes on recovery.
        """
        _, clean = api.prepare_generate(_SPEC_SEED, "secret", _SPEC_POW)
        _, with_zwsp = api.prepare_generate(_SPEC_SEED, "sec​ret", _SPEC_POW)
        assert clean != with_zwsp

    def test_passphrase_japanese_precomposed_equals_decomposed(self) -> None:
        """NFKD is applied to the passphrase, so Japanese precomposed and
        decomposed forms still produce the same digest — this is the only
        normalization gate that fires on the passphrase side.
        """
        precomposed = "がぎぐげご"
        decomposed = "がぎぐげご"
        _, d_pre = api.prepare_generate(_SPEC_SEED, precomposed, _SPEC_POW)
        _, d_dec = api.prepare_generate(_SPEC_SEED, decomposed, _SPEC_POW)
        assert d_pre == d_dec


class TestPrepareGenerateHandleBehavior:
    """The returned ``SeedDisplayHandle`` holds the *normalized* seed and
    expires roughly 60s from the call site (default TTL from SPEC).
    """

    def test_handle_consume_returns_normalized_seed(self) -> None:
        """Casefold and whitespace-collapse must have been applied to the
        bytes the handle carries — PR5's display flow renders this string
        back to the user, so it has to match what compute_digest hashed.
        """
        handle, _ = api.prepare_generate("  TEST   SEED  ", _SPEC_PASSPHRASE, _SPEC_POW)
        assert handle.consume() == "test seed"

    def test_consecutive_calls_return_distinct_handles(self) -> None:
        """No memoization — each call mints a fresh handle so a stale
        cached handle never leaks into a later display flow.
        """
        h1, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        h2, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert h1 is not h2

    def test_handle_deadline_is_approximately_60s_in_future(self) -> None:
        """Default TTL per SPEC: ``time.monotonic() + 60.0``. White-box
        check against ``_deadline`` so the wipe-on-expiry path is
        actually reachable from the value baked in here.
        """
        before = time.monotonic()
        handle, _ = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        after = time.monotonic()
        # The deadline must lie in the window [before+60, after+60] —
        # the only ambiguity is the time spent inside the call.
        deadline = handle._deadline  # type: ignore[attr-defined]
        assert before + 60.0 <= deadline <= after + 60.0

    def test_handle_carries_expected_digest_equal_to_returned_digest(self) -> None:
        """The (handle, expected_digest) pair is internally consistent —
        confirm_generate compares the user-typed digest against
        handle._expected_digest, so the value baked into the handle must
        equal the digest returned to the caller (i.e. the one shown to
        the user for offline transcription).
        """
        handle, returned_digest = api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        assert handle._expected_digest == returned_digest  # type: ignore[attr-defined]


class TestPrepareGenerateNoPersistence:
    """``prepare_generate`` is pure with respect to disk state.

    The two-phase contract exists precisely so the digest-mismatch case
    can be a clean "no-op" — no Keychain entry, no meta.json, no
    digests/<kid>.commit, no audit event. A passing test here is what
    licenses the contract that "if the digest doesn't match, nothing
    durable happened".
    """

    def test_no_files_created_anywhere(self, tmp_path: Any) -> None:
        """``prepare_generate`` has no ``home`` parameter — it cannot create
        keyvault files by construction. This snapshots a scratch directory
        before/after the call to assert no incidental disk writes occur.
        """
        # Snapshot the directory state, call prepare_generate, re-snapshot.
        before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
        api.prepare_generate(_SPEC_SEED, _SPEC_PASSPHRASE, _SPEC_POW)
        after = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
        assert before == after

    def test_signature_does_not_require_audit_or_backend(self) -> None:
        """``prepare_generate`` is positional-only on (seed, passphrase,
        pow_bytes). No keyword-only ``audit_sink`` / ``backend`` / ``home``
        — those are confirm_generate's surface.
        """
        sig = inspect.signature(api.prepare_generate)
        param_names = list(sig.parameters)
        assert param_names == ["seed_phrase", "passphrase", "pow_bytes"]


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
# the merged ``encrypt`` / ``decrypt`` surface. SPEC.md sketches it as
# ``NativeBackend | None = None``; api.py standardizes on a required backend
# (the production _SecKeyBackend is step-E and does not exist yet).


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


class _AuditCapture:
    """A callable audit sink that records every entry it receives.

    Used directly as the ``audit_sink`` argument; ``.log`` exposes the
    captured entries for assertions.
    """

    def __init__(self) -> None:
        self.log: list[dict[str, Any]] = []

    def __call__(self, entry: dict[str, Any]) -> None:
        self.log.append(entry)


class _FailingAuditCapture(_AuditCapture):
    """An ``_AuditCapture`` that raises ``self.boom`` when it sees an entry
    whose ``reason`` matches ``fail_on_reason`` — for exercising the three
    distinct sink-failure policies of confirm_generate's audit emits.
    """

    def __init__(self, fail_on_reason: str) -> None:
        super().__init__()
        self.fail_on_reason = fail_on_reason
        self.boom = RuntimeError(f"audit sink failed on {fail_on_reason}")

    def __call__(self, entry: dict[str, Any]) -> None:
        self.log.append(entry)
        if entry.get("reason") == self.fail_on_reason:
            raise self.boom


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
        pub = wrap.get_wrapping_key_public("default", backend=backend)
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
        pub = wrap.get_wrapping_key_public("default", backend=backend)
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

        def commit_then_boom(root: Path, meta: dict[str, Any]) -> None:
            real_save_meta(root, meta)  # the atomic rename commits meta.json
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
        pub = wrap.get_wrapping_key_public("default", backend=backend)
        assert len(pub) == 65
        meta = _storage.load_meta(kv_root)
        assert first.key_id_hash in meta["keys"]


# ============================ generate (non-interactive wrapper) ============================
#
# Contract frozen in SPEC.md §"PR4 API contract / Two-phase generate":
#
#     def generate(seed_phrase, passphrase, pow_bytes, expected_digest, *,
#                  key_id=None, backend, audit_sink, home=None) -> GenerateResult:
#         # prepare_generate → confirm_generate in one call.
#         # Tests / future automation use this; the wizard CLI MUST use the
#         # two-phase form so the user confirms the digest offline.
#
# Implementation note: generate delegates fully to confirm_generate (it does
# NOT pre-check the digest itself). confirm_generate reads the handle's
# prepared digest, compares expected_digest against it, and emits
# keyvault.init_denied on a mismatch. The SPEC sketch showed an early
# in-generate check that raised WITHOUT an audit emit; delegating is simpler
# and gives a non-interactive mismatch the same audit trail as the
# interactive path — a strict improvement, documented in the GREEN commit.


class TestGenerateSignature:
    """``generate`` is positional on (seed, passphrase, pow_bytes,
    expected_digest) then keyword-only (key_id, backend, audit_sink, home).
    """

    def test_signature_positional_then_keyword_only(self) -> None:
        sig = inspect.signature(api.generate)
        params = sig.parameters
        assert list(params) == [
            "seed_phrase",
            "passphrase",
            "pow_bytes",
            "expected_digest",
            "key_id",
            "backend",
            "audit_sink",
            "home",
            "unattended",
        ]
        assert params["expected_digest"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert params["backend"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["audit_sink"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["unattended"].kind is inspect.Parameter.KEYWORD_ONLY


class TestGenerateHappyPath:
    """Correct expected_digest → full prepare→confirm in one call."""

    def test_returns_generate_result(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert isinstance(result, api.GenerateResult)
        assert result.key_id == "default"

    def test_canonical_vector_succeeds(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        """The SPEC L355-362 fixed vector drives a full generate end to end:
        the digest prepare_generate computes for those inputs equals
        _SPEC_DIGEST, so generate finalizes successfully.
        """
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        commit_path = kv_root / "digests" / f"{result.key_id_hash}.commit"
        assert _storage.safe_read(commit_path) == _SPEC_DIGEST

    def test_explicit_key_id_used(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            key_id="automation-key",
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert result.key_id == "automation-key"

    def test_enclave_key_generated_and_meta_written(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        result = api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert len(wrap.get_wrapping_key_public("default", backend=backend)) == 65
        meta = _storage.load_meta(kv_root)
        assert result.key_id_hash in meta["keys"]

    def test_audit_emits_started_then_completed(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        assert [e["reason"] for e in audit.log] == [
            "keyvault.init_started",
            "keyvault.init_completed",
        ]


class TestGenerateMismatch:
    """A wrong expected_digest is rejected — the durable phase never runs."""

    def test_wrong_expected_digest_raises(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )

    def test_mismatch_emits_init_denied(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        """generate delegates to confirm_generate, so a non-interactive
        mismatch produces the same keyvault.init_denied audit trail as the
        interactive confirm_generate path.
        """
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        assert [e["reason"] for e in audit.log] == ["keyvault.init_denied"]

    def test_mismatch_generates_no_key(self, backend: FakeBackend, audit: _AuditCapture, home: Path) -> None:
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        with pytest.raises(Exception):  # noqa: B017 — WrapKeyNotFound; key never created
            wrap.get_wrapping_key_public("default", backend=backend)

    def test_mismatch_touches_no_filesystem(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, kv_root: Path
    ) -> None:
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        assert not kv_root.exists()


class TestGenerateWipesHandle:
    """``generate`` is non-interactive — there is no display flow to call
    ``SeedDisplayHandle.consume()``, and ``confirm_generate`` only reads
    the handle (it never consumes). ``generate`` must therefore wipe the
    internal handle's seed payload itself, on both the success and the
    mismatch paths, so the seed does not linger in memory until GC (codex
    pre-merge P2).
    """

    @staticmethod
    def _capture_handle(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        """Patch api.prepare_generate so the test can grab the handle that
        ``generate`` mints internally and never returns.
        """
        captured: list[Any] = []
        real_prepare = api.prepare_generate

        def capturing_prepare(seed: str, passphrase: str, pow_bytes: bytes) -> tuple[Any, bytes]:
            handle, digest = real_prepare(seed, passphrase, pow_bytes)
            captured.append(handle)
            return handle, digest

        monkeypatch.setattr(api, "prepare_generate", capturing_prepare)
        return captured

    def test_generate_wipes_handle_seed_on_success(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_handle(monkeypatch)
        api.generate(
            _SPEC_SEED,
            _SPEC_PASSPHRASE,
            _SPEC_POW,
            _SPEC_DIGEST,
            backend=backend,
            audit_sink=audit,
            home=home,
        )
        handle = captured[0]
        assert all(b == 0 for b in handle._payload), (  # type: ignore[attr-defined]
            "generate() must wipe the internal handle's seed payload on success"
        )

    def test_generate_wipes_handle_seed_on_mismatch(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_handle(monkeypatch)
        with pytest.raises(api.VerificationDigestMismatch):
            api.generate(
                _SPEC_SEED,
                _SPEC_PASSPHRASE,
                _SPEC_POW,
                b"\x22" * 32,
                backend=backend,
                audit_sink=audit,
                home=home,
            )
        handle = captured[0]
        assert all(b == 0 for b in handle._payload), (  # type: ignore[attr-defined]
            "generate() must wipe the internal handle's seed payload even when confirm raises"
        )


class TestConfirmGeneratePostDisplayDeadline:
    """A slow user: the display flow consumed the seed, the 60s window
    elapsed, then the user submits the confirmed digest. The seed is
    already wiped, so confirm_generate must NOT reject on expiry (codex
    pre-merge P2).
    """

    def test_confirm_succeeds_after_display_consume_past_deadline(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path
    ) -> None:
        digest = b"\x33" * 32
        handle = _make_handle(deadline=_FAR_PAST, expected_digest=digest)
        # The display flow consumed the seed; the handle was (or became)
        # expired — consume() raises but still wipes + marks consumed.
        with pytest.raises(api.SeedDisplayExpired):
            handle.consume()
        # The seed is already gone — confirm_generate must still finalize.
        result = api.confirm_generate(handle, digest, backend=backend, audit_sink=audit, home=home)
        assert isinstance(result, api.GenerateResult)

    def test_confirm_still_rejects_expired_never_consumed_handle(
        self, backend: FakeBackend, audit: _AuditCapture, home: Path
    ) -> None:
        """The mirror: an expired handle whose seed was never displayed is
        still rejected — the deadline guard wipes the never-shown seed.
        """
        handle = _make_handle(deadline=_FAR_PAST)
        with pytest.raises(api.SeedDisplayExpired):
            api.confirm_generate(handle, _PLACEHOLDER_DIGEST, backend=backend, audit_sink=audit, home=home)
