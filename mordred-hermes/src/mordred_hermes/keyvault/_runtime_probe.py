"""Runtime-interpreter probe for the at-rest ``.env`` seal (design note §8.2).

``encryption enable env`` deletes the plaintext ``~/.hermes/.env`` on macOS,
trusting the startup shim (:func:`._runtime_env.install_vault_env_decrypt`, wired
through the ``hermes_agent.plugins`` entry point) to re-inject the enrolled
secrets when ``hermes`` boots. That shim only runs if ``mordred_hermes`` is
installed in the interpreter that actually runs ``hermes`` — which is **not** the
interpreter running this CLI when the operator drives Mordred from a dev venv.
The managed runtime venv (``~/.hermes/hermes-agent/venv``) is uv-managed and
recreated on every ``hermes`` self-update, which silently drops the non-PyPI
``mordred_hermes``. The seal would then strand the operator: the plaintext is
gone but the runtime cannot decrypt the vault copy.

This module verifies, *before* the destructive delete, that the **runtime**
interpreter can actually run the injection shim. The caller (``env_decrypt_cli``)
refuses fail-closed when it cannot.

Heavy imports stay function-local; this module imports on any platform.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from .._home import hermes_home as _hermes_home

__all__ = ["discover_runtime_python", "runtime_config_decrypt_available", "runtime_env_injection_available"]

#: Env override: operator points us at the exact interpreter that runs ``hermes``.
RUNTIME_PYTHON_ENV = "MORDRED_HERMES_RUNTIME_PYTHON"

#: Seconds to wait for the probe subprocess before treating it as unavailable.
_PROBE_TIMEOUT_S = 20.0

#: Cap on launcher-wrapper indirection while resolving an interpreter (a bash
#: ``hermes`` that exec's a venv ``hermes`` that has a python shebang = depth 2).
_MAX_LAUNCHER_HOPS = 5

# The probe runs *inside the runtime interpreter*. It must prove the env-injection
# shim will both be DISCOVERED (its entry point is registered, so Hermes calls
# ``register()``) and WORK (the hot-path imports it performs at startup resolve).
# A bare ``import mordred_hermes`` is too weak: a stray ``src`` on ``PYTHONPATH``
# imports without the package being installed or entry-point-registered, which is
# exactly the false-positive that lets the seal strand the operator.
_PROBE_SRC = """
import sys
try:
    from importlib.metadata import entry_points
    eps = [e for e in entry_points(group="hermes_agent.plugins") if e.name == "mordred_keyvault"]
    if not eps:
        sys.stderr.write("mordred_keyvault plugin not registered in this runtime")
        sys.exit(11)
    plugin = eps[0].load()
    if not callable(getattr(plugin, "register", None)):
        sys.stderr.write("mordred_keyvault plugin exposes no register()")
        sys.exit(12)
    # The exact hot-path imports install_vault_env_decrypt -> inject_vault_env do
    # at startup (see keyvault._runtime_env). Importing them here catches a partial
    # install (mordred present but its crypto / pyobjc deps missing), not just a
    # total absence.
    import mordred_hermes.keyvault._runtime_env  # the shim module itself
    from mordred_hermes.keyvault import vault  # AES-GCM vault (cryptography / blake3 / argon2)
    from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend  # device key (pyobjc Security)
    from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorStore  # anchor store
    import dotenv  # .env parser
except Exception as exc:  # noqa: BLE001 - any failure means the shim won't run
    sys.stderr.write(repr(exc))
    sys.exit(13)
sys.exit(0)
"""

# The config.yaml analogue of ``_PROBE_SRC``. Unlike ``.env`` (an entry-point
# plugin Hermes calls at startup), ``config.yaml`` is materialized by a ``.pth``
# startup hook (``mordred_hermes_config_decrypt.pth`` -> ``_pth_bootstrap`` ->
# ``install_config_decrypt`` -> ``materialize_config``). So the probe must prove
# the hook is INSTALLED in this runtime's site-packages (else it never fires at
# boot) AND that the materialize hot-path imports resolve. The probe runs with
# ``MORDRED_CONFIG_DECRYPT=0`` (see caller), so the ``.pth`` is neutralized for the
# probe process itself and cannot open the vault / prompt Touch ID here.
_CONFIG_PROBE_SRC = """
import sys
try:
    from mordred_hermes.keyvault._config_bootstrap import config_hook_installed
    if not config_hook_installed():
        sys.stderr.write("config-decrypt .pth startup hook not installed in this runtime")
        sys.exit(21)
    # The exact hot-path imports the .pth hook performs at boot. Importing them
    # here catches a partial install (mordred present but its crypto / pyobjc deps
    # missing), not just a total absence.
    import mordred_hermes._pth_bootstrap  # the .pth target module
    from mordred_hermes.keyvault import _config_bootstrap  # materialize / reseal
    from mordred_hermes.keyvault import _storage, vault  # AES-GCM vault (cryptography / blake3 / argon2)
    from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend  # device key (pyobjc Security)
    from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorStore  # anchor store
except Exception as exc:  # noqa: BLE001 - any failure means the hook won't decrypt
    sys.stderr.write(repr(exc))
    sys.exit(22)
sys.exit(0)
"""


def _interpreter_from_shebang(rest: str) -> Path | None:
    """Parse the interpreter path out of a shebang body (after ``#!``)."""
    parts = shlex.split(rest)
    if not parts:
        return None
    # ``/usr/bin/env python3`` -> not a concrete runtime path; ``/path/bin/python`` -> the path.
    if parts[0].endswith("env") and len(parts) > 1:
        return None
    return Path(parts[0])


def _exec_target(launcher: Path) -> Path | None:
    """Return the ``bin/hermes`` a shell wrapper ``exec``s, if it is one."""
    try:
        text = launcher.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("exec "):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        for token in tokens[1:]:
            if token.startswith(("-", "$")):
                continue
            return Path(token)
    return None


def _sibling_python(launcher: Path) -> Path | None:
    """The ``python`` alongside a ``bin/hermes`` launcher, if present."""
    for name in ("python3", "python"):
        candidate = launcher.with_name(name)
        if candidate.exists():
            return candidate
    return None


def _within_current_prefix(path: Path) -> bool:
    """Whether ``path`` lives inside the interpreter running *this* CLI.

    Used to reject the sibling-python guess fallback when it would just point
    back at the dev venv driving this command — that venv has mordred (it must,
    to run this code) but is exactly the one that may NOT be the real ``hermes``
    runtime, so letting it validate itself is the false-pass we must avoid.
    """
    try:
        path.resolve().relative_to(Path(sys.prefix).resolve())
    except (ValueError, OSError):
        return False
    return True


def _python_for_launcher(path: Path) -> Path | None:
    """Resolve the Python interpreter behind a ``hermes`` launcher at ``path``.

    A ``hermes`` on ``$PATH`` is either a console script whose shebang names the
    venv's python, or a shell wrapper that ``exec``s another ``bin/hermes`` (the
    host wrapper does ``unset PYTHONPATH; exec "<venv>/bin/hermes" "$@"``). We
    follow the shebang / ``exec`` target without ever *executing* the launcher,
    then take the python next to the resolved ``bin/hermes``. Returns ``None`` if
    nothing resolvable is found within :data:`_MAX_LAUNCHER_HOPS`.
    """
    seen: set[Path] = set()
    current = path
    for _ in range(_MAX_LAUNCHER_HOPS):
        try:
            current = current.resolve()
        except OSError:
            return None
        if current in seen:
            return None
        seen.add(current)
        try:
            lines = current.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, UnicodeError):
            return None
        if not lines:
            return None
        shebang = lines[0]
        if shebang.startswith("#!"):
            interp = _interpreter_from_shebang(shebang[2:])
            if interp is not None and interp.name.startswith("python"):
                return interp if interp.exists() else None
        target = _exec_target(current)
        if target is None:
            # Not a recognizable wrapper: guess the python beside it — but never
            # the dev venv running this CLI (that would let it pose as the runtime).
            sibling = _sibling_python(current)
            if sibling is not None and _within_current_prefix(sibling):
                return None
            return sibling
        current = target
    return None


def _managed_runtime_python(home: Path) -> Path | None:
    """The python in Hermes's managed runtime venv, if it exists.

    This is the deterministic, non-shadowable signal: the host installs the
    Hermes runtime at ``<home>/hermes-agent/venv``. Preferring it over
    ``which hermes`` avoids validating the very dev venv whose mismatch with the
    runtime causes the bug.
    """
    base = home / "hermes-agent" / "venv" / "bin"
    for name in ("python3", "python"):
        candidate = base / name
        if candidate.exists():
            return candidate
    return None


def discover_runtime_python(home: Path | None = None, explicit: str | Path | None = None) -> Path | None:
    """Resolve the interpreter that actually runs ``hermes``, or ``None``.

    Order, most authoritative first:

    1. ``explicit`` argument or :data:`RUNTIME_PYTHON_ENV` — operator override.
    2. ``<home>/hermes-agent/venv/bin/python`` — Hermes's managed runtime venv
       (deterministic; not shadowable by an activated dev venv).
    3. the ``hermes`` launcher on ``$PATH`` — its shebang / ``exec`` target.

    Step 2 is deliberately tried before step 3 so an activated dev venv whose
    ``hermes`` shadows the host one cannot pose as the runtime.
    """
    home = _hermes_home() if home is None else home

    override = explicit if explicit is not None else os.environ.get(RUNTIME_PYTHON_ENV)
    if override:
        candidate = Path(override)
        return candidate if candidate.exists() else None

    managed = _managed_runtime_python(home)
    if managed is not None:
        return managed

    import shutil

    launcher = shutil.which("hermes")
    if launcher is not None:
        return _python_for_launcher(Path(launcher))
    return None


def _resolve_runtime_python(home: Path | None, runtime_python: Path | None) -> tuple[Path | None, str]:
    """Resolve the interpreter to probe, or ``(None, detail)`` when none is found.

    Shared by both capability probes: an explicit ``runtime_python`` wins, else
    :func:`discover_runtime_python` resolves it from ``home``.
    """
    home = _hermes_home() if home is None else home
    python = runtime_python if runtime_python is not None else discover_runtime_python(home=home)
    if python is None:
        return None, (
            "could not locate the interpreter that runs `hermes` "
            "(looked for <home>/hermes-agent/venv and `hermes` on PATH); "
            f"set {RUNTIME_PYTHON_ENV} to point at it"
        )
    return python, ""


def _run_runtime_probe(
    python: Path,
    probe_src: str,
    *,
    timeout: float,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str] | None, str]:
    """Run ``probe_src`` in ``python`` with a sanitized env.

    Returns ``(proc, error_detail)``: ``proc`` is ``None`` on a launch failure
    (``error_detail`` set), else the completed process (``error_detail`` empty).
    ``PYTHONPATH`` / ``PYTHONHOME`` are stripped so the probe sees exactly what the
    host's ``hermes`` wrapper sees (it ``unset``s both) — a stray ``PYTHONPATH``
    must not make a runtime look capable when it is not. ``extra_env`` is overlaid
    last (e.g. a hook-disable flag). Any timeout / OSError is a fail-closed miss.
    """
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    if extra_env:
        env.update(extra_env)
    try:
        # `python` is a resolved interpreter path (not user shell input); shell=False.
        proc = subprocess.run(
            [str(python), "-c", probe_src],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"probing the hermes runtime ({python}) timed out after {timeout:g}s"
    except OSError as exc:
        return None, f"could not run the hermes runtime ({python}): {exc}"
    return proc, ""


def runtime_env_injection_available(
    *,
    home: Path | None = None,
    runtime_python: Path | None = None,
    timeout: float = _PROBE_TIMEOUT_S,
) -> tuple[bool, str]:
    """Whether the Hermes runtime can decrypt a sealed ``.env`` at startup.

    Returns ``(ok, detail)``. ``ok`` is ``True`` only when the runtime
    interpreter has the ``mordred_keyvault`` plugin registered *and* the shim's
    hot-path imports resolve there. ``detail`` is a human-readable reason for the
    caller's fail-closed message. Any launch error, timeout, or non-zero exit is
    reported as **unavailable** (fail-closed): we never claim capability we could
    not prove.
    """
    python, locate_err = _resolve_runtime_python(home, runtime_python)
    if python is None:
        return False, locate_err
    proc, run_err = _run_runtime_probe(python, _PROBE_SRC, timeout=timeout)
    if proc is None:
        return False, run_err
    if proc.returncode == 0:
        return True, f"hermes runtime ({python}) can inject a sealed .env"
    reason = (proc.stderr or proc.stdout or "unknown error").strip()
    return False, f"the hermes runtime ({python}) cannot decrypt a sealed .env: {reason}"


def runtime_config_decrypt_available(
    *,
    home: Path | None = None,
    runtime_python: Path | None = None,
    timeout: float = _PROBE_TIMEOUT_S,
) -> tuple[bool, str]:
    """Whether the Hermes runtime can decrypt a sealed ``config.yaml`` at startup.

    The ``config.yaml`` analogue of :func:`runtime_env_injection_available`. ``ok``
    is ``True`` only when the runtime interpreter has the config-decrypt ``.pth``
    startup hook installed *and* the materialize hot-path imports resolve there.

    The probe runs with ``MORDRED_CONFIG_DECRYPT=0`` so the ``.pth`` hook is
    neutralized for the probe process itself — it cannot open the vault or prompt
    for Touch ID while we merely check capability (the explicit
    ``config_hook_installed()`` + import checks do the verification). Same
    ``PYTHONPATH`` / ``PYTHONHOME`` stripping and fail-closed semantics as the env
    probe.
    """
    python, locate_err = _resolve_runtime_python(home, runtime_python)
    if python is None:
        return False, locate_err
    proc, run_err = _run_runtime_probe(
        python, _CONFIG_PROBE_SRC, timeout=timeout, extra_env={"MORDRED_CONFIG_DECRYPT": "0"}
    )
    if proc is None:
        return False, run_err
    if proc.returncode == 0:
        return True, f"hermes runtime ({python}) can decrypt a sealed config.yaml"
    reason = (proc.stderr or proc.stdout or "unknown error").strip()
    return False, f"the hermes runtime ({python}) cannot decrypt a sealed config.yaml: {reason}"
