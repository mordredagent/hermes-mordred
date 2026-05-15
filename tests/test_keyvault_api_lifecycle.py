"""Tests for ``mordred_hermes.keyvault.api`` lifecycle surface.

Phase 4 PR4 step-D RED (2026-05-15) — implementation lands in step-D GREEN.

Scope: the two-phase generate flow + backup roundtrip. This first slice
pins only ``SeedDisplayHandle``; the rest of step-D (``prepare_generate``
→ ``confirm_generate`` → ``generate`` → ``export_backup`` →
``import_backup``) lands in subsequent RED→GREEN commits.

The ``SeedDisplayHandle`` contract is frozen in SPEC.md §"PR4 API
contract / SeedDisplayHandle (opaque, codex BLOCKER #3)":

    class SeedDisplayHandle:
        __slots__ = ("_payload", "_consumed", "_deadline")
        # __repr__ → "<SeedDisplayHandle redacted>"
        # __eq__   → raise TypeError(... comparison oracle ...)
        # __hash__ = None
        # consume(): one-shot, zero-fills _payload, second call raises
        #            RuntimeError; past deadline raises SeedDisplayExpired
        #            after wiping.

The class lives in ``api.py`` for PR4. PR5 will relocate it to
``seed_display.py`` and layer screen-blackout / 60s timer / screenshot
detection on top, but the opaque-class contract pinned here MUST hold
verbatim after the relocation.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from mordred_hermes.keyvault import api

# ----------------------------- helpers / fixtures -----------------------------


_SEED = "abandon abandon abandon abandon abandon abandon"
# Far enough in the future that consume() never trips the deadline guard.
_FAR_FUTURE = 1.0e12
# Far enough in the past that any consume() trips the deadline guard.
_FAR_PAST = -1.0e12


def _make_handle(
    seed: str = _SEED,
    deadline: float = _FAR_FUTURE,
) -> Any:
    return api.SeedDisplayHandle(seed, deadline)


# ============================ structural contract ============================


class TestSlotsLayout:
    """``__slots__`` is the only allowed attribute surface (no ``__dict__``).

    Rationale: a stray ``handle.seed_phrase = ...`` assignment would
    silently leak the seed through ``__dict__`` introspection. ``__slots__``
    pins the attribute set at class-creation time, AttributeError fires
    on any other name.
    """

    def test_slots_value_is_exact_three_tuple(self) -> None:
        assert api.SeedDisplayHandle.__slots__ == ("_payload", "_consumed", "_deadline")

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
