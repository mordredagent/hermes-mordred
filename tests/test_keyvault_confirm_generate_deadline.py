"""Deadline behavior after the seed display phase is complete."""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.keyvault import api
from tests._keyvault_fakes import FakeBackend
from tests._keyvault_lifecycle_helpers import (
    _FAR_PAST,
    _PLACEHOLDER_DIGEST,
    _AuditCapture,
    _make_handle,
)


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def audit() -> _AuditCapture:
    return _AuditCapture()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path


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
