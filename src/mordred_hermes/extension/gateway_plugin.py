"""The ``e2e`` component of the ``mordred`` plugin: the read-only Telegram tools.

The component once carried the Slack/Discord end-to-end transport (inbound
decrypt in ``pre_gateway_dispatch``, outbound re-encryption, a guard around
Hermes's standalone sender). The browser extension no longer sets channel keys,
so that transport was removed and Slack/Discord messages pass through Hermes
unchanged. The component id stays ``e2e`` so existing status and integrity
records keep their meaning.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def register(ctx: Any) -> None:
    """Plugin entry point: the session-start integrity gate and the Telegram tools.

    The browser-extension WebSocket server ships as the standalone
    ``hermes-mordred extension serve`` command (``extension.api``); it does not
    need the gateway process.
    """
    from ..privacy_check.hooks import check_plugin_integrity

    ctx.register_hook("on_session_start", check_plugin_integrity)

    # Read-only Telegram tools; offered only to a Venice/loopback Hermes model.
    try:
        from .telegram.hermes_tools import register_tools

        register_tools(ctx)
    except Exception as e:
        logger.warning("mordred_e2e: Telegram tools not registered: %s", type(e).__name__)
