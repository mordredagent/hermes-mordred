"""Tests for ``mordred_hermes.network._exceptions``.

Two propagation regimes, mirroring the ``llm_guard`` design verified in
Phase 2 PR1 (Codex review H2):

- ``MordredNetworkError`` and its subclasses inherit :class:`Exception`.
  ``api.use(path)`` callers (CLI, internal Python API, tests) catch them
  to surface user-actionable errors without aborting the session.

- ``MordredPathBringupFailed`` and ``MordredPathDropped`` inherit
  :class:`BaseException` directly. Phase 3 PR2 will raise them from
  ``on_session_start`` and the liveness worker / ``pre_tool_call`` hook
  respectively. They must escape the ``except Exception:`` filter inside
  ``hermes_cli.plugins.invoke_hook`` (see
  ``mordred-docs/dev/HOOK_PAYLOADS.md`` §1) so strict-mode network
  refusals actually abort the session. They are *not* :class:`SystemExit`
  subclasses so cleanup-style ``except SystemExit:`` blocks do not mistake
  a strict-mode refusal for an ordinary CLI exit.

The classes are defined in PR1 (before PR2 wires the hooks) so the
propagation contract is testable up-front.
"""

from __future__ import annotations

import pytest


def test_network_error_is_exception_subclass() -> None:
    from mordred_hermes.network._exceptions import MordredNetworkError

    assert issubclass(MordredNetworkError, Exception)


def test_bringup_failed_subclass() -> None:
    from mordred_hermes.network._exceptions import BringupFailed, MordredNetworkError

    assert issubclass(BringupFailed, MordredNetworkError)
    assert issubclass(BringupFailed, Exception)


def test_already_switching_subclass() -> None:
    from mordred_hermes.network._exceptions import AlreadySwitching, MordredNetworkError

    assert issubclass(AlreadySwitching, MordredNetworkError)


def test_unknown_path_subclass() -> None:
    from mordred_hermes.network._exceptions import MordredNetworkError, UnknownPath

    assert issubclass(UnknownPath, MordredNetworkError)


def test_subclasses_caught_by_except_network_error() -> None:
    """``api.use(path)`` callers should be able to catch the base class."""
    from mordred_hermes.network._exceptions import (
        AlreadySwitching,
        BringupFailed,
        MordredNetworkError,
        UnknownPath,
    )

    for cls in (BringupFailed, AlreadySwitching, UnknownPath):
        try:
            raise cls("test")
        except MordredNetworkError:
            pass


def test_path_bringup_failed_is_base_exception() -> None:
    """Strict-mode on_session_start refusal must escape ``except Exception``."""
    from mordred_hermes.network._exceptions import MordredPathBringupFailed

    assert issubclass(MordredPathBringupFailed, BaseException)
    assert not issubclass(MordredPathBringupFailed, Exception)


def test_path_dropped_is_base_exception() -> None:
    """Strict-mode mid-session liveness drop must escape ``except Exception``."""
    from mordred_hermes.network._exceptions import MordredPathDropped

    assert issubclass(MordredPathDropped, BaseException)
    assert not issubclass(MordredPathDropped, Exception)


def test_path_bringup_failed_propagates_past_exception_wrapper() -> None:
    """Simulate Hermes ``invoke_hook`` ``except Exception:`` wrapper."""
    from mordred_hermes.network._exceptions import MordredPathBringupFailed

    def hermes_invoke_hook(callback: object) -> None:
        try:
            assert callable(callback)
            callback()
        except Exception:
            pytest.fail("MordredPathBringupFailed was incorrectly swallowed by except Exception")

    def handler() -> None:
        raise MordredPathBringupFailed("tor bootstrap timeout under strict policy")

    with pytest.raises(MordredPathBringupFailed):
        hermes_invoke_hook(handler)


def test_path_dropped_propagates_past_exception_wrapper() -> None:
    """Symmetric propagation test for the liveness-drop class."""
    from mordred_hermes.network._exceptions import MordredPathDropped

    def hermes_invoke_hook(callback: object) -> None:
        try:
            assert callable(callback)
            callback()
        except Exception:
            pytest.fail("MordredPathDropped was incorrectly swallowed by except Exception")

    def handler() -> None:
        raise MordredPathDropped("vpn handshake stale > 180s under strict policy")

    with pytest.raises(MordredPathDropped):
        hermes_invoke_hook(handler)


def test_refusal_classes_distinguishable_from_systemexit() -> None:
    """Strict refusals must not be caught by generic ``except SystemExit:``."""
    from mordred_hermes.network._exceptions import (
        MordredPathBringupFailed,
        MordredPathDropped,
    )

    assert not issubclass(MordredPathBringupFailed, SystemExit)
    assert not issubclass(MordredPathDropped, SystemExit)


def test_bringup_failed_is_not_base_exception_refusal() -> None:
    """``BringupFailed`` (API-level) is distinct from
    ``MordredPathBringupFailed`` (hook-level abort).

    A Python caller doing ``except MordredNetworkError`` should NOT
    accidentally catch the hook-level refusal.
    """
    from mordred_hermes.network._exceptions import (
        BringupFailed,
        MordredNetworkError,
        MordredPathBringupFailed,
    )

    assert not issubclass(MordredPathBringupFailed, MordredNetworkError)
    assert not issubclass(MordredPathBringupFailed, BringupFailed)


def test_path_dropped_separate_from_bringup() -> None:
    """``MordredPathDropped`` and ``MordredPathBringupFailed`` are siblings,
    not subclasses, so the audit reason emitted by each is unambiguous."""
    from mordred_hermes.network._exceptions import (
        MordredPathBringupFailed,
        MordredPathDropped,
    )

    assert not issubclass(MordredPathDropped, MordredPathBringupFailed)
    assert not issubclass(MordredPathBringupFailed, MordredPathDropped)
