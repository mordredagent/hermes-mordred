"""Tests for the ``SeedDisplayHandle`` lifecycle and opaque-class contract.

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

The class remains in ``api.py``. ``seed_display.py`` layers the screen-blackout,
60s timer, and screenshot detection ceremony on top of this opaque handle.
"""

from __future__ import annotations

import copy
import io
import pickle
import time

import pytest

from mordred_hermes.keyvault import api
from tests._keyvault_lifecycle_helpers import (
    _FAR_FUTURE,
    _FAR_PAST,
    _SEED,
    _make_handle,
)

# ----------------------------- helpers / fixtures -----------------------------


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
