"""Interpreter-startup hook for config.yaml at-rest decrypt (ROADMAP v2-F8 Phase 2).

A ``.pth`` file shipped to the venv's site-packages root (see
``mordred-hermes/packaging/pth/``) runs a one-line guard at *every* interpreter
start in that environment and, only for a Hermes invocation, calls
:func:`run` here. ``run`` materializes the vault-enrolled ``config.yaml`` onto
disk *before* ``cli.py`` imports and eagerly reads it (the structural reason a
``register()``-time shim is too late — see :mod:`.keyvault._config_bootstrap`).

Two hard requirements, because this code can run in any interpreter sharing the
venv:

* **Engage narrowly** — only an actual Hermes console script (``hermes``,
  ``hermes-agent``, ``hermes-acp``, or ``hermes-mordred``; or an explicit
  ``MORDRED_CONFIG_DECRYPT=1`` override) is touched.
  pytest, pip, a bare REPL, or a venv merely *named* "hermes" are left completely
  alone, and the device key store is never probed for them. (``python -m
  hermes_cli`` is *not* covered: at site-init ``sys.argv[0]`` is still ``'-m'``,
  and it is not a runnable Hermes start anyway — ``hermes_cli`` ships no
  ``__main__``.)
* **Fail closed for Hermes** — if the decrypt raises (tampered / unopenable
  vault), abort startup with a clean message rather than let Hermes boot on a
  default or stale config. ``MORDRED_CONFIG_DECRYPT=0`` opts a Hermes process out
  entirely (recovery escape hatch).

This module does **not** run anything at import time; the ``.pth`` line calls
``run()`` explicitly. Importing it (e.g. in tests) is side-effect free.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence

__all__ = ["run"]

# Set to "1" to force-engage in a non-Hermes interpreter, "0" to opt a Hermes
# process out (recovery when a managed config.yaml has become unopenable).
_FORCE_ENV = "MORDRED_CONFIG_DECRYPT"


def _looks_like_hermes(argv: Sequence[str]) -> bool:
    """Whether ``argv`` is an actual Hermes CLI invocation.

    Precise on purpose: matches every console script shipped by hermes-agent
    that can construct an AIAgent (plus ``hermes-mordred``), tolerating a
    ``.py`` / ``.exe`` suffix, and a script path that lives *inside* the
    ``hermes_cli`` package dir (defensive, for a direct-path execution). A venv
    whose *directory* happens to contain "hermes" while running some other tool
    (e.g. ``.../hermes-venv/bin/pytest``) must NOT match — so the whole-path is
    only consulted for the ``hermes_cli`` package segment, never a loose
    substring.

    Note ``python -m hermes_cli`` is **not** matched: at ``.pth`` / site-init
    time ``sys.argv[0]`` is ``'-m'`` (the module name is not in ``argv`` yet; the
    runpy-resolved path arrives only afterward). It is moot regardless —
    ``hermes_cli`` ships no ``__main__``, so ``python -m hermes_cli`` is not a
    runnable Hermes start. Use a console script or ``MORDRED_CONFIG_DECRYPT=1``.
    """
    if not argv:
        return False
    arg0 = argv[0] or ""
    norm = arg0.replace("\\", "/")
    base = os.path.basename(norm)
    folded_base = base.casefold()
    if folded_base.endswith(".py"):
        base = base[:-3]
    elif folded_base.endswith(".exe"):
        base = base[:-4]
    if base.casefold() in ("hermes", "hermes-agent", "hermes-acp", "hermes-mordred"):
        return True
    return "/hermes_cli/" in norm or norm.endswith("/hermes_cli")


def _should_engage(argv: Sequence[str], environ: Mapping[str, str]) -> bool:
    """Resolve the engage decision: explicit env override wins, else process sniffing."""
    flag = environ.get(_FORCE_ENV)
    if flag == "0":
        return False
    if flag == "1":
        return True
    return _looks_like_hermes(argv)


def run(
    *,
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    installer: Callable[[], int] | None = None,
) -> bool:
    """Engage the config.yaml decrypt for a Hermes startup; no-op otherwise.

    Returns ``True`` when the installer ran (engaged), ``False`` when the
    interpreter was left untouched. Fail-closed: an installer error for an
    engaged (Hermes) process is turned into a clean ``SystemExit(1)`` so startup
    aborts instead of booting on a default/stale config; a deliberate
    ``SystemExit`` from the installer passes through unchanged.
    """
    argv = list(sys.argv) if argv is None else argv
    environ = os.environ if environ is None else environ
    if not _should_engage(argv, environ):
        return False

    if installer is None:
        from .keyvault._config_bootstrap import install_config_decrypt

        installer = install_config_decrypt

    try:
        installer()
    except SystemExit:
        raise
    except BaseException as exc:
        # Broad on purpose: an engaged Hermes process must fail closed on ANY
        # decrypt error (vault tamper, device-key denial, OSError) — abort
        # startup rather than boot on a default/stale config.
        sys.stderr.write(f"mordred: refusing to start — config.yaml at-rest decrypt failed: {exc}\n")
        raise SystemExit(1) from exc
    return True
