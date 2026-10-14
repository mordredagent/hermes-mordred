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

from mordred_hermes.keyvault._audit_emit import emit_capture

_ENTRY: dict[str, Any] = {"event": "keyvault.test", "decision": "block", "reason": "keyvault.test_reason"}


# ---------------------------------------------------------------------------
# emit_capture
# ---------------------------------------------------------------------------


def test_none_sink_is_noop_and_returns_none() -> None:
    assert emit_capture(None, dict(_ENTRY)) is None


@pytest.mark.parametrize("control_flow_exc", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_control_flow_exceptions_propagate_uncaptured(control_flow_exc: type[BaseException]) -> None:
    """BaseException-but-not-Exception encodes "stop NOW" — capturing it into
    ``__context__`` would break Ctrl-C / sys.exit for every CLI on top of the
    keyvault (second-pass code-reviewer HIGH, 2026-05-14)."""

    def stopping_sink(_entry: dict[str, Any]) -> None:
        raise control_flow_exc()

    with pytest.raises(control_flow_exc):
        emit_capture(stopping_sink, dict(_ENTRY))
