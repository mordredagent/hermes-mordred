"""mordred_hermes.keyvault._audit_emit — best-effort audit emit + exception chaining.

The keyvault has one recurring shape around fail-closed decision points: a
block/abort audit entry is emitted *best-effort*, and the primary
safety-critical exception is then raised with any sink failure attached as
``__context__``. The policy lives here, once, instead of being restated at
every site (previously ``recovery._emit_mismatch``, ``wrap._emit_unwrap_denied``,
``api._emit_init_denied``, and ``seed_display._emit_abort`` each carried it):

**Why the sink exception is captured instead of allowed to escape**
(code-reviewer HIGH-1, 2026-05-14): the safety-critical invariant at each
call site is "the caller's surface exception is the primary signal, always"
(e.g. ``RecoveryDigestMismatch`` on a digest mismatch). If the sink raises
(disk-full audit log), letting that exception escape masks the primary
signal — a caller's ``except RecoveryDigestMismatch: show_user(...)``
handler would silently leak the AuditDiskFull through.

**Why ``except Exception``, not ``BaseException``** (second-pass
code-reviewer HIGH, 2026-05-14): :class:`BaseException` also contains
:class:`KeyboardInterrupt`, :class:`SystemExit`, and :class:`GeneratorExit`,
which encode "the user / runtime wants the program to stop NOW". Masking
those into a primary exception's ``__context__`` would break Ctrl-C handling
for any CLI built on top of the keyvault, and would let a sink that calls
``sys.exit(1)`` be silently overridden. Those must propagate cleanly.

**Why ``__context__`` is assigned outside any ``except`` handler**: CPython
unconditionally overwrites ``__context__`` on a ``raise`` executed inside an
active exception handler (``Python/ceval.c:do_raise`` →
``PyException_SetContext``). :func:`chain_and_raise` must therefore only be
invoked from normal control flow — every keyvault site captures the trigger
exception into a local first (or never had one) and raises after the handler
has exited, so the explicit assignment survives.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, NoReturn


def emit_capture(
    audit_sink: Callable[[dict[str, Any]], None] | None,
    entry: dict[str, Any],
) -> Exception | None:
    """Best-effort emit of ``entry``; return the sink's exception instead of raising.

    ``None`` sinks are a no-op (the entry is discarded). Only
    :class:`Exception` subclasses are captured — control-flow exceptions
    (``KeyboardInterrupt`` / ``SystemExit`` / ``GeneratorExit``) propagate
    untouched; see the module docstring for the full policy. The returned
    exception is meant to be handed to :func:`chain_and_raise` so it stays
    diagnosable as ``__context__`` without masking the primary signal.
    """
    if audit_sink is None:
        return None
    try:
        audit_sink(entry)
    except Exception as exc:
        # Broad catch (intentional): any *operational* failure of the sink
        # (RuntimeError, OSError, ValueError, ...) is captured for chaining.
        return exc
    return None


def chain_and_raise(primary: BaseException, sink_exc: Exception | None) -> NoReturn:
    """Raise ``primary``, chaining ``sink_exc`` (if any) as ``__context__``.

    ``__context__`` — not ``__cause__`` — so the sink failure stays
    diagnosable without displacing the primary signal; a caller that already
    assigned ``primary.__cause__`` (e.g. the native denial in
    ``wrap.unwrap_dek``) keeps it. MUST be called from normal control flow,
    never from inside an ``except`` handler, or the raise machinery
    overwrites the explicit ``__context__`` assignment (see module docstring).
    """
    if sink_exc is not None:
        primary.__context__ = sink_exc
    raise primary
