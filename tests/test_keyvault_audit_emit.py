"""Tests for ``mordred_hermes.keyvault._audit_emit``.

The shared best-effort audit-emit + ``__context__``-chaining helpers that
back ``recovery._emit_mismatch``, ``wrap._emit_unwrap_denied``,
``api._emit_init_denied``, and ``seed_display._emit_abort``. The policy
(capture ``Exception``, never ``BaseException``; chain as ``__context__``
outside any ``except`` handler) is asserted here once — the consuming
modules' own tests cover the end-to-end surfaces.
"""

from __future__ import annotations

from typing import Any

import pytest

from mordred_hermes.keyvault._audit_emit import chain_and_raise, emit_capture

_ENTRY: dict[str, Any] = {"event": "keyvault.test", "decision": "block", "reason": "keyvault.test_reason"}


class _Primary(RuntimeError):
    pass


class _SinkFailure(OSError):
    pass


# ---------------------------------------------------------------------------
# emit_capture
# ---------------------------------------------------------------------------


def test_none_sink_is_noop_and_returns_none() -> None:
    assert emit_capture(None, dict(_ENTRY)) is None


def test_sink_receives_entry_verbatim_and_success_returns_none() -> None:
    captured: list[dict[str, Any]] = []
    assert emit_capture(captured.append, dict(_ENTRY)) is None
    assert captured == [_ENTRY]


def test_sink_exception_is_returned_not_raised() -> None:
    boom = _SinkFailure("audit disk full")

    def angry_sink(_entry: dict[str, Any]) -> None:
        raise boom

    assert emit_capture(angry_sink, dict(_ENTRY)) is boom


@pytest.mark.parametrize("control_flow_exc", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_control_flow_exceptions_propagate_uncaptured(control_flow_exc: type[BaseException]) -> None:
    """BaseException-but-not-Exception encodes "stop NOW" — capturing it into
    ``__context__`` would break Ctrl-C / sys.exit for every CLI on top of the
    keyvault (second-pass code-reviewer HIGH, 2026-05-14)."""

    def stopping_sink(_entry: dict[str, Any]) -> None:
        raise control_flow_exc()

    with pytest.raises(control_flow_exc):
        emit_capture(stopping_sink, dict(_ENTRY))


# ---------------------------------------------------------------------------
# chain_and_raise
# ---------------------------------------------------------------------------


def test_raises_primary_with_sink_exc_as_context() -> None:
    sink_exc = _SinkFailure("audit disk full")
    with pytest.raises(_Primary) as excinfo:
        chain_and_raise(_Primary("digest mismatch"), sink_exc)
    assert excinfo.value.__context__ is sink_exc
    # __context__ (implicit-style diagnostics), never __cause__ (explicit).
    assert excinfo.value.__cause__ is None


def test_raises_primary_cleanly_when_no_sink_exc() -> None:
    with pytest.raises(_Primary) as excinfo:
        chain_and_raise(_Primary("digest mismatch"), None)
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None


def test_preserves_caller_assigned_cause() -> None:
    """wrap.unwrap_dek assigns the native denial as ``__cause__`` before
    chaining the sink failure — both must survive, on the documented
    attributes, exactly as the pre-dedup call sites produced them."""
    native = ValueError("user_cancelled")
    sink_exc = _SinkFailure("audit disk full")
    primary = _Primary("auth cancelled")
    primary.__cause__ = native
    with pytest.raises(_Primary) as excinfo:
        chain_and_raise(primary, sink_exc)
    assert excinfo.value.__cause__ is native
    assert excinfo.value.__context__ is sink_exc
