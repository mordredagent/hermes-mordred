"""Mordred browser-extension WebSocket API (ws://127.0.0.1:7788/ext).

Ported from the full-Hermes gateway layer into the mordred_hermes package so
the extension server ships with the plugin bundle. Hermes-runtime imports
(gateway.run, hermes_cli.models, gateway.platforms.base, hermes_constants)
are lazy and resolve only when running inside a live Hermes gateway.
"""

from . import api, chat, crypto, history, pairing, rpc

# Back-compat aliases: the original full-Hermes modules were named
# ``extension_api`` .. ``extension_rpc``. Re-export those names so callers /
# tests written against the gateway layout keep working after the port.
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
