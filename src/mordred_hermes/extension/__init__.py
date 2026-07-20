"""Mordred browser-extension WebSocket API (ws://127.0.0.1:7788/ext).

Ported from the full-Hermes gateway layer into the mordred_hermes package so
the extension server ships with the plugin bundle. Hermes-runtime imports
(gateway.run, hermes_cli.models, gateway.platforms.base, hermes_constants)
are lazy and resolve only when running inside a live Hermes gateway.

Submodule access is **lazy** (PEP 562): importing this package does NOT pull in
``api`` (which needs the ``[extension]`` extra's ``aiohttp``). That lets
lightweight consumers — e.g. the ``mordred_e2e`` gateway hook, which only needs
``crypto``/``pairing`` — load on a base ``mordred-hermes[keyvault]`` install
without the WebSocket-server dependencies. ``api``/aiohttp are imported only when
that submodule is actually touched (``extension serve``).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

# Canonical submodules + the back-compat ``extension_*`` aliases (the original
# full-Hermes modules were named ``extension_api`` .. ``extension_rpc``).
_SUBMODULES = frozenset({"api", "chat", "crypto", "history", "pairing", "rpc"})
_ALIASES = {
    "extension_api": "api",
    "extension_chat": "chat",
    "extension_crypto": "crypto",
    "extension_history": "history",
    "extension_pairing": "pairing",
    "extension_rpc": "rpc",
}


def __getattr__(name: str) -> Any:
    """Import submodules (and their ``extension_*`` aliases) on first access."""
    target = name if name in _SUBMODULES else _ALIASES.get(name)
    if target is not None:
        mod = importlib.import_module(f".{target}", __name__)
        globals()[name] = mod  # cache so subsequent access skips __getattr__
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _SUBMODULES | set(_ALIASES))


if TYPE_CHECKING:  # keep static analysers / IDEs aware of the attributes
    from . import api, chat, crypto, history, pairing, rpc

    extension_api = api
    extension_chat = chat
    extension_crypto = crypto
    extension_history = history
    extension_pairing = pairing
    extension_rpc = rpc

__all__ = [
    "api",
    "chat",
    "crypto",
    "extension_api",
    "extension_chat",
    "extension_crypto",
    "extension_history",
    "extension_pairing",
    "extension_rpc",
    "history",
    "pairing",
    "rpc",
]
