"""Shared values and test doubles for keyvault lifecycle tests.

This module is intentionally not named ``test_*`` so pytest does not collect
it as a test module.
"""

from __future__ import annotations

from typing import Any

from mordred_hermes.keyvault import api

_SEED = "abandon abandon abandon abandon abandon abandon"
_FAR_FUTURE = 1.0e12
_FAR_PAST = -1.0e12
_PLACEHOLDER_DIGEST = b"\x00" * 32

_SPEC_SEED = "test seed"
_SPEC_PASSPHRASE = "test pass"
_SPEC_POW = bytes.fromhex("deadbeef") + b"\x00" * 28
_SPEC_DIGEST = bytes.fromhex("25c17b1e1b249dd278f6de52e6e0dddf855fe9943177c99c5428fc1c321b5c93")


def _make_handle(
    seed: str = _SEED,
    deadline: float = _FAR_FUTURE,
    expected_digest: bytes = _PLACEHOLDER_DIGEST,
) -> Any:
    return api.SeedDisplayHandle(seed, deadline, expected_digest)


class _AuditCapture:
    """Callable audit sink that records every entry it receives."""

    def __init__(self) -> None:
        self.log: list[dict[str, Any]] = []

    def __call__(self, entry: dict[str, Any]) -> None:
        self.log.append(entry)


class _FailingAuditCapture(_AuditCapture):
    """Audit capture that fails when a selected reason is emitted."""

    def __init__(self, fail_on_reason: str) -> None:
        super().__init__()
        self.fail_on_reason = fail_on_reason
        self.boom = RuntimeError(f"audit sink failed on {fail_on_reason}")

    def __call__(self, entry: dict[str, Any]) -> None:
        self.log.append(entry)
        if entry.get("reason") == self.fail_on_reason:
            raise self.boom
