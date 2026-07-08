"""Shared fail-closed runtime gate for the destructive at-rest seals.

``encryption enable env`` and ``encryption enable config`` both delete the
plaintext after enrolling and rely on a macOS startup shim in the interpreter
that actually runs ``hermes`` to materialize it again. That interpreter is
usually NOT the venv driving this command, and the managed runtime venv is
recreated (dropping the non-PyPI mordred install) on every ``hermes``
self-update — so before any destructive step the seal probes that runtime and
refuses when the shim is missing.

The gate logic was previously duplicated line-for-line in
:mod:`.env_decrypt_cli` and :mod:`.config_decrypt_cli`. The two seals are the
same security decision and must never drift apart, so the shared core lives
here; each module supplies only its target-specific guidance text (whole
pre-wrapped lines, so the operator-facing messages stay byte-identical to the
text they replaced).

Heavy imports stay function-local so this module imports on any platform,
matching the wizard CLI convention.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from . import _term

if TYPE_CHECKING:
    from pathlib import Path

#: Runtime probe signature: called ``probe(home=...)`` -> ``(ok, detail)``.
#: Injectable so tests can fake the runtime check (matching the ``backend=`` /
#: ``store=`` injection style); each seal supplies its production probe.
RuntimeProbe = Callable[..., "tuple[bool, str]"]


def runtime_gate(
    *,
    home: Path,
    platform: str,
    runtime_probe: RuntimeProbe | None,
    force_runtime_unverified: bool,
    default_probe: RuntimeProbe,
    target: str,
    mechanism: str,
    rerun_tail: str,
) -> int:
    """Fail-closed macOS gate for a destructive seal of ``target``.

    Returns 1 (after printing actionable guidance) when the interpreter that
    runs ``hermes`` cannot handle a sealed ``target`` at startup, else 0. A
    no-op (0) off macOS — the plaintext is kept there anyway — and when
    ``force_runtime_unverified`` is set.

    ``mechanism`` is the caller's explanation of its startup shim and
    ``rerun_tail`` closes with its re-run / force guidance; both are
    newline-terminated-line blocks slotted verbatim into the message.
    """
    if platform != "darwin" or force_runtime_unverified:
        return 0
    ok, detail = (runtime_probe or default_probe)(home=home)
    if ok:
        return 0
    from ..keyvault._runtime_probe import discover_runtime_python

    runtime_python = discover_runtime_python(home=home) or (home / "hermes-agent" / "venv" / "bin" / "python3")
    _term.emit_error(
        f"refusing to vault-seal {target} — {detail}.\n"
        f"{mechanism}"
        "  (run from the repo root):\n"
        f"    uv pip install --python {runtime_python} -e './mordred-hermes[macos]'\n"
        f"{rerun_tail}"
    )
    return 1
