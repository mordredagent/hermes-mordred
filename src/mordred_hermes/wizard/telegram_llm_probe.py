"""Opt-in inference probe of the Telegram importer's saved local LLM configuration."""

from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlsplit, urlunsplit

from ..extension.telegram import service, venice
from ..extension.telegram.llm import LlmTarget
from .telegram_setup_cli import Check

_PROBE_TIMEOUT_SECONDS = 30.0


async def _probe(target: LlmTarget) -> None:
    from ..extension.egress import EgressRoute

    # Only fixed synthetic text: no archive, policy text or account information.
    session = service._default_http_session(EgressRoute(None, None), _PROBE_TIMEOUT_SECONDS)
    try:
        chunks = venice.stream_chat(
            session,
            target.config,
            [{"role": "user", "content": "Reply with just OK, without reasoning."}],
            max_tokens=64,
            backend="local",
            require_complete=True,
        )
        produced = False
        async with contextlib.aclosing(chunks), contextlib.aclosing(service._without_thinking(chunks)) as answer:
            async for text in answer:
                produced = produced or bool(text.strip())
        if not produced:
            raise venice.VeniceError(
                "llm_empty_answer", detail=venice.local_failure_detail(target.base_url, "invalid_response", 200)
            )
    finally:
        await session.close()


def check_saved_local_llm() -> Check:
    """Freshly unseal the saved target, then prove it can return visible streamed text."""
    from ..extension.telegram.tee import default_secret_store

    try:
        value = default_secret_store().load(fresh=True)
        if value is None:
            raise service.TelegramServiceError("llm_not_configured")
        target = service.TelegramService._target(value)
        del value
        if target.backend != "local":
            return Check(
                "privacy_llm",
                False,
                "--probe-llm supports only a saved local backend; no request sent",
                "Configure a local model with hermes-mordred telegram local-llm, or omit --probe-llm.",
            )
        asyncio.run(_probe(target))
    except Exception as exc:
        code = service.error_code(exc, "telegram_llm_probe_failed")
        detail = exc.detail if isinstance(exc, venice.VeniceError) else None
        summary = code
        fix = "Check the saved configuration with hermes-mordred telegram local-llm --help."
        if detail:
            summary += f" ({detail.get('failure')}) at {detail.get('endpoint', 'local endpoint')}"
            if "http_status" in detail:
                summary += f"; HTTP {detail['http_status']}"
            fix = str(detail["hint"])
        elif code == "tee_auth_cancelled":
            fix = "When ready, rerun --probe-llm and approve the credential unlock."
        elif code in ("tee_unavailable", "telegram_not_enrolled", "custody_uncertain"):
            fix = "Resolve the credential custody error reported by hermes-mordred telegram doctor first."
        return Check("privacy_llm", False, summary, fix)
    parts = urlsplit(target.base_url)
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    return Check("privacy_llm", True, f"local ({target.model}) at {origin}: streamed completion succeeded")
