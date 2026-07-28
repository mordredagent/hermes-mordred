"""Interpreter-startup guards that cannot depend on plugin opt-in state.

Hermes entry-point plugins are opt-in through ``plugins.enabled``.  That is a
problem for the sibling-integrity gate itself: a missing or malformed allow
list loads no Mordred plugin, so no plugin gets a chance to report that the
guard is absent.  The wheel therefore ships a narrowly-gated ``.pth`` file
which calls :func:`run` for Hermes console processes before CLI imports.

The bootstrap does two cheap, process-local things:

* prepares the loopback ``NO_PROXY`` entries before Hermes constructs shared
  model clients; and
* wraps ``PluginManager.discover_and_load`` so every successful discovery
  contains at least one mandatory sibling-integrity callback, including after
  a ``force=True`` rescan clears the hook table.

No policy file is read here.  The callback imports and evaluates policy lazily
when Hermes fires ``on_session_start``.
"""

from __future__ import annotations

import functools
import os
import sys
from collections.abc import Callable
from typing import Any, Final, NoReturn, cast

from ._proxy_bypass import ensure_loopback_proxy_bypass

_WRAPPED_MARKER: Final = "__mordred_integrity_discovery_wrapper__"
_PRIVACY_HOOKS_MODULE: Final = "mordred_hermes.privacy_check.hooks"
_SAFE_MODE_TRUTHY: Final = frozenset({"1", "true", "yes", "on"})


def _safe_mode_enabled() -> bool:
    """Mirror Hermes's explicit plugin-recovery escape hatch."""
    return os.environ.get("HERMES_SAFE_MODE", "").strip().casefold() in _SAFE_MODE_TRUTHY


def _raise_runtime_refusal(context: str, exc: Exception) -> NoReturn:
    """Cross Hermes's broad ``except Exception`` boundaries on guard failure."""
    sys.stderr.write(f"mordred: refusing to start — {context}: {exc}\n")
    raise SystemExit(1) from exc


def _mandatory_integrity_hook(**kwargs: Any) -> None:
    """Lazy first-position bridge whose failures cannot be swallowed by Hermes.

    Policy refusals inherit directly from ``BaseException`` and therefore
    propagate untouched. Ordinary evaluation failures are process-startup
    failures and remain translated to ``SystemExit(1)``.
    """
    try:
        from .privacy_check.hooks import check_plugin_integrity

        check_plugin_integrity(**kwargs)
    except SystemExit:
        raise
    except Exception as exc:
        _raise_runtime_refusal("mandatory integrity evaluation failed", exc)


def _is_integrity_callback(callback: Callable[..., Any]) -> bool:
    """Whether an existing callback already runs the sibling-integrity gate."""
    if callback is _mandatory_integrity_hook:
        return True
    return getattr(callback, "__module__", "") == _PRIVACY_HOOKS_MODULE and getattr(callback, "__name__", "") in {
        "check_plugin_integrity",
        "on_session_start",
    }


def _ensure_integrity_callback(manager: Any) -> None:
    """Keep exactly one mandatory bridge at the front of the hook list."""
    if _safe_mode_enabled():
        return
    raw_hooks = getattr(manager, "_hooks", None)
    if not isinstance(raw_hooks, dict):
        raise RuntimeError("Hermes PluginManager has no mutable _hooks registry")
    hooks = cast(dict[str, list[Callable[..., Any]]], raw_hooks)
    callbacks = hooks.setdefault("on_session_start", [])
    if not isinstance(callbacks, list):
        raise RuntimeError("Hermes PluginManager on_session_start hook registry is not a mutable list")
    callbacks[:] = [callback for callback in callbacks if callback is not _mandatory_integrity_hook]
    callbacks.insert(0, _mandatory_integrity_hook)


def _install_plugin_discovery_wrapper() -> None:
    """Patch the supported Hermes 0.13+ manager shape, idempotently."""
    import hermes_cli.plugins as hermes_plugins

    manager_type = hermes_plugins.PluginManager
    current = manager_type.discover_and_load
    if bool(getattr(current, _WRAPPED_MARKER, False)):
        return
    original = cast(Callable[..., Any], current)

    @functools.wraps(original)
    def discover_and_load_with_integrity(manager: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(manager, *args, **kwargs)
        if _safe_mode_enabled():
            return result
        try:
            _ensure_integrity_callback(manager)
        except SystemExit:
            raise
        except Exception as exc:
            _raise_runtime_refusal("mandatory integrity hook installation failed", exc)
        return result

    setattr(discover_and_load_with_integrity, _WRAPPED_MARKER, True)
    manager_type.discover_and_load = discover_and_load_with_integrity

    # Normally the .pth hook runs before the singleton exists.  Cover embedded
    # callers that install the bootstrap after discovery as well.
    existing_manager = getattr(hermes_plugins, "_plugin_manager", None)
    if existing_manager is not None and bool(getattr(existing_manager, "_discovered", False)):
        _ensure_integrity_callback(existing_manager)


def install() -> None:
    """Install all early runtime guards for the current Hermes process."""
    ensure_loopback_proxy_bypass()
    _install_plugin_discovery_wrapper()


def run(*, installer: Callable[[], None] | None = None) -> bool:
    """``.pth`` entry point; fail closed if a mandatory guard cannot install."""
    try:
        (installer or install)()
    except SystemExit:
        raise
    except BaseException as exc:
        sys.stderr.write(f"mordred: refusing to start — runtime guard bootstrap failed: {exc}\n")
        raise SystemExit(1) from exc
    return True
