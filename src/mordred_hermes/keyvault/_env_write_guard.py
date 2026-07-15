"""Write-side guard: keep host ``.env`` writes from defeating the at-rest seal.

The host writes ``~/.hermes/.env`` in plaintext via
``hermes_cli.config.save_env_value`` (``hermes config set`` / setup flows). After
``encryption enable env`` has sealed and removed the plaintext on macOS, such a
write reintroduces a *partial* plaintext at rest: the host starts from an empty
file (the sealed plaintext was deleted), so the new file holds only the
just-written keys. Left alone that is two bugs at once — a plaintext secret back
on disk, and a file that would drop the other enrolled secrets if naively
re-enrolled.

This module wraps the host writer so that, on macOS, every successful write while
the env target is *sealed* is immediately reconciled back into the vault — merged,
not clobbered (see :func:`._env_reseal.reseal_env`) — and the plaintext
removed. So the read path (runtime injection) and the write path (config set)
agree: no plaintext secret persists, and no enrolled secret is lost.

The reseal core lives in :mod:`._env_reseal`, not
:mod:`mordred_hermes.wizard.env_decrypt_cli` (which merely calls the same core
now) — this module is reached from the ``on_session_start`` / ``on_session_end``
plugin hooks (:func:`mordred_hermes.keyvault.register`), so it must not carry a
runtime dependency on the wizard layer being importable.

``hermes_cli`` is a private, unstable host module — it ships no API stability
guarantee (the plugin deliberately *replicates* host metadata rather than
importing it; see :mod:`mordred_hermes._provider_identity`). So this wrapper is
defensive: a no-op when the host function is absent or not callable, **never**
raises into the host call, idempotent, and it re-binds references that other host
modules early-bound (e.g. ``from hermes_cli.config import save_env_value`` in
``hermes_cli.setup``) before we patched the module.

Heavy imports stay function-local so this module imports on any platform.
"""

from __future__ import annotations

import contextlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .._home import hermes_home as _hermes_home
from ._identity import default_vault_root
from ._runtime_env import _env_optout_marker_path

__all__ = ["install_env_write_guard", "reseal_stray_env_if_present"]

#: Attribute stamped on the wrapper so a second install is a no-op (idempotent).
_WRAPPED_FLAG = "_mordred_env_reseal_wrapped"

#: The host writer we wrap — the add/update path used by ``hermes config set`` and
#: setup. (Delete-while-sealed is out of scope: a key lives in the vault, not the
#: absent plaintext, so removing it needs the disable → edit → enable cycle.)
_HOST_WRITER = "save_env_value"


def install_env_write_guard(
    *,
    config_module: Any | None = None,
    platform: str | None = None,
    reconcile: Callable[[], None] | None = None,
) -> bool:
    """Wrap the host ``.env`` writer so writes are resealed into the vault.

    Returns ``True`` when the guard is installed (or already was), ``False`` for a
    no-op. A no-op when not on macOS (the sealed state is macOS-only), when
    ``hermes_cli.config`` is unavailable (older / vendored Hermes), or when the
    host writer is missing / not callable.

    ``config_module`` / ``platform`` / ``reconcile`` are injectable for tests; in
    production they default to the live host module, ``sys.platform``, and
    :func:`_reseal_quietly`.
    """
    platform = sys.platform if platform is None else platform
    if platform != "darwin":
        return False

    host: Any = config_module
    if host is None:
        try:
            from hermes_cli import config as _host_config
        except Exception:
            return False
        host = _host_config

    original = getattr(host, _HOST_WRITER, None)
    if not callable(original):
        return False
    if getattr(original, _WRAPPED_FLAG, False):
        return True  # already wrapped (idempotent)

    reconcile = _reseal_quietly if reconcile is None else reconcile

    import functools

    @functools.wraps(original)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        # The host write already committed; reconciliation must never turn a
        # successful `config set` into a failure, so swallow everything here.
        with contextlib.suppress(Exception):
            reconcile()
        return result

    setattr(_wrapped, _WRAPPED_FLAG, True)
    host.save_env_value = _wrapped

    # Re-bind early-bound references: a module that did
    # ``from hermes_cli.config import save_env_value`` before us holds the
    # original, which our module-level patch would not reach. Point those at the
    # wrapper too. (Modules imported *after* this resolve the wrapper via config.)
    for module in list(sys.modules.values()):
        if module is None or module is host:
            continue
        if getattr(module, _HOST_WRITER, None) is original:
            with contextlib.suppress(Exception):
                setattr(module, _HOST_WRITER, _wrapped)

    return True


def reseal_stray_env_if_present(
    *,
    home: Path | None = None,
    platform: str | None = None,
) -> bool:
    """Heal a stray plaintext ``~/.hermes/.env`` by resealing it into the vault.

    The *proactive* twin of :func:`install_env_write_guard`'s post-write reconcile:
    the write guard only catches drift created *through the host writer*, whereas
    this catches a plaintext simply *present on disk* — left by another path (e.g.
    ``gateway setup``) or from before the guard was installed. Wired onto the
    ``on_session_start`` / ``on_session_end`` plugin hooks by
    :func:`mordred_hermes.keyvault.register`.

    macOS only: off macOS the runtime read shim is a no-op, so removing the
    plaintext would strand the secrets — gate and bail. Also a no-op in the
    reversible *disabled* state (opt-out marker present: the on-disk plaintext is
    the intentional live copy, not drift) and when there is no plaintext at all —
    those cheap pre-checks keep the common case off the vault hot path, so no
    spurious device unlock (Touch ID) on every session.

    Returns ``True`` only when a plaintext ``.env`` existed before this call and is
    gone afterwards (an actual reseal). ``reseal`` returns ``0`` for both clean
    no-ops *and* success and keeps the plaintext in every non-clean case, so
    "did we reseal?" is "is the plaintext now gone?", not the return code. ``False``
    for every no-op or a reseal that failed / kept the plaintext. Never raises.

    ``home`` / ``platform`` are injectable for tests; in production they default to
    the live Hermes home and ``sys.platform``.
    """
    platform = sys.platform if platform is None else platform
    if platform != "darwin":
        return False
    home = _hermes_home() if home is None else home
    if _env_optout_marker_path(home).exists():
        return False  # disabled state: the plaintext is the intentional live copy
    env_path = home / ".env"
    if not env_path.is_file():
        return False  # no stray plaintext → nothing to reseal

    try:
        from ._env_reseal import reseal_env

        reseal_env(home=home, root=default_vault_root())
    except Exception as exc:
        # Surface a stranded plaintext rather than crashing the session boundary,
        # and let `encryption status` flag it as exposed.
        with contextlib.suppress(Exception):
            from .. import _term

            _term.emit_warn(
                f"could not reseal .env into the vault at a session boundary: {exc} — a plaintext copy "
                "may remain at rest; run `hermes-mordred encryption enable env`."
            )
        return False

    return not env_path.is_file()


def _reseal_quietly() -> None:
    """The write-guard's post-write ``reconcile`` callback.

    Delegates to :func:`reseal_stray_env_if_present`. The write path is already
    macOS-gated by :func:`install_env_write_guard`, so the helper's platform check
    is a redundant safety net here; the helper never raises into the host write.
    """
    reseal_stray_env_if_present()
