"""Propagation contract for ``privacy_check`` strict-mode refusals."""

from __future__ import annotations

import pytest

from mordred_hermes.privacy_check._exceptions import MordredIntegrityRefused


def test_integrity_refusal_is_direct_base_exception() -> None:
    assert issubclass(MordredIntegrityRefused, BaseException)
    assert not issubclass(MordredIntegrityRefused, Exception)


def test_integrity_refusal_is_not_system_exit() -> None:
    assert not issubclass(MordredIntegrityRefused, SystemExit)


def test_integrity_refusal_escapes_exception_wrapper() -> None:
    def hermes_invoke_hook() -> None:
        try:
            raise MordredIntegrityRefused("disabled sibling under strict policy")
        except Exception:
            pytest.fail("MordredIntegrityRefused was swallowed by except Exception")

    with pytest.raises(MordredIntegrityRefused):
        hermes_invoke_hook()
