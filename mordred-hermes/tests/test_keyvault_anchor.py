"""Tests for the device-bound vault anchor (rollback + wmk-substitution pin).

The anchor is the freshness root the manifest MAC cannot be on its own.
Because ``wrap_dek`` is offline (public-key only), an attacker with disk
access can forge a whole manifest under a ``wmk`` they minted against the
victim's SE *public* key — the MAC verifies fine. What they cannot do is
*write* the device-bound Keychain anchor on a locked / powered-off device.

So the anchor stores two non-secret pins an offline attacker cannot move:

- ``SHA-256(wmk)`` — the canonical wmk fingerprint. A substituted /
  cross-vault wmk has a different fingerprint → rejected (Codex P1-a).
- ``generation`` — the monotonic counter. A rolled-back manifest+files
  snapshot carries an older generation than the anchor pins → rejected
  (Codex P1-b).

:func:`anchor.verify_anchor` enforces strict equality on both: the
manifest the vault is about to trust must match the exact ``(wmk, gen)``
the anchor pins. Crash-window reconciliation (anchor vs manifest write
ordering) is the vault layer's job, not this primitive's.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from mordred_hermes.keyvault import anchor

from ._keyvault_fakes import FakeAnchorStore

_LABEL = "mordred.vault.anchor.test"
_WMK_A = b"\x11" * 127  # stand-in for a 127-byte MRKW wmk blob
_WMK_B = b"\x22" * 127  # a different vault's / attacker's wmk


@pytest.fixture
def store() -> FakeAnchorStore:
    return FakeAnchorStore()


# ---------------------------------------------------------------------------
# write + verify round-trip
# ---------------------------------------------------------------------------


def test_write_then_verify_ok(store: FakeAnchorStore) -> None:
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=5)
    # Matching wmk + generation → no exception.
    anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=5)


def test_read_anchor_round_trips(store: FakeAnchorStore) -> None:
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=7)
    a = anchor.read_anchor(store, _LABEL)
    assert a.wmk_sha256 == hashlib.sha256(_WMK_A).digest()
    assert a.generation == 7


def test_write_overwrites_on_generation_bump(store: FakeAnchorStore) -> None:
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=1)
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=2)
    anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=2)
    with pytest.raises(anchor.AnchorMismatch):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=1)


# ---------------------------------------------------------------------------
# wire format
# ---------------------------------------------------------------------------


def test_anchor_serialization_format(store: FakeAnchorStore) -> None:
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=3)
    raw = store.read(_LABEL)
    assert raw is not None
    obj = json.loads(raw)
    assert obj["v"] == 1
    assert obj["wmk_sha256"] == hashlib.sha256(_WMK_A).hexdigest()
    assert obj["generation"] == 3


# ---------------------------------------------------------------------------
# substitution / rollback defence
# ---------------------------------------------------------------------------


def test_substituted_wmk_rejected(store: FakeAnchorStore) -> None:
    """Codex P1-a: a wmk swapped for one the attacker minted under their
    own SE key has a different fingerprint → AnchorMismatch."""
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=4)
    with pytest.raises(anchor.AnchorMismatch):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_B, generation=4)


def test_rolled_back_generation_rejected(store: FakeAnchorStore) -> None:
    """Codex P1-b: anchor pins gen 9; a restored older manifest claims gen 3."""
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=9)
    with pytest.raises(anchor.AnchorMismatch):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=3)


def test_advanced_generation_rejected(store: FakeAnchorStore) -> None:
    """A manifest claiming a generation higher than the anchor pins (forged
    forward, or anchor not yet updated) is also rejected — strict equality."""
    anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=3)
    with pytest.raises(anchor.AnchorMismatch):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=5)


# ---------------------------------------------------------------------------
# fail-closed: missing / corrupt anchor
# ---------------------------------------------------------------------------


def test_missing_anchor_raises(store: FakeAnchorStore) -> None:
    """An enrolled vault whose anchor is absent (never initialized, or the
    attacker deleted it to force a fallback) must fail closed."""
    with pytest.raises(anchor.AnchorMissing):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=1)


def test_read_missing_anchor_raises(store: FakeAnchorStore) -> None:
    with pytest.raises(anchor.AnchorMissing):
        anchor.read_anchor(store, _LABEL)


def test_corrupt_anchor_not_json_raises(store: FakeAnchorStore) -> None:
    store.write(_LABEL, b"not json at all")
    with pytest.raises(anchor.AnchorCorrupt):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=1)


def test_corrupt_anchor_missing_field_raises(store: FakeAnchorStore) -> None:
    store.write(_LABEL, json.dumps({"v": 1, "generation": 1}).encode("utf-8"))
    with pytest.raises(anchor.AnchorCorrupt):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=1)


def test_corrupt_anchor_bad_version_raises(store: FakeAnchorStore) -> None:
    store.write(
        _LABEL,
        json.dumps({"v": 2, "wmk_sha256": hashlib.sha256(_WMK_A).hexdigest(), "generation": 1}).encode("utf-8"),
    )
    with pytest.raises(anchor.AnchorCorrupt):
        anchor.verify_anchor(store, _LABEL, wmk=_WMK_A, generation=1)


def test_all_anchor_errors_share_base(store: FakeAnchorStore) -> None:
    """A caller can fail closed with a single ``except AnchorError``."""
    assert issubclass(anchor.AnchorMissing, anchor.AnchorError)
    assert issubclass(anchor.AnchorMismatch, anchor.AnchorError)
    assert issubclass(anchor.AnchorCorrupt, anchor.AnchorError)


# ---------------------------------------------------------------------------
# write-side validation
# ---------------------------------------------------------------------------


def test_write_negative_generation_rejected(store: FakeAnchorStore) -> None:
    with pytest.raises(ValueError, match="generation"):
        anchor.write_anchor(store, _LABEL, wmk=_WMK_A, generation=-1)


def test_write_empty_wmk_rejected(store: FakeAnchorStore) -> None:
    with pytest.raises(ValueError, match="wmk"):
        anchor.write_anchor(store, _LABEL, wmk=b"", generation=1)
