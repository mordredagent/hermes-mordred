"""Venice.ai client for questions over imported Telegram messages.

Venice is used as the privacy LLM for this feature, under three rules that are
enforced here rather than left to configuration:

1. **Private models only.** Venice labels every model ``private`` (Venice-run
   inference with zero prompt/response retention) or ``anonymized`` (proxied
   to a third-party provider). Before each question the model's
   ``model_spec.privacy`` is read from ``GET /models`` and anything other than
   ``private`` is refused. An unknown model, an unreadable catalog, or a
   missing field all fail closed.
2. **No tools, no web search, no Venice system prompt.** Imported messages are
   untrusted third-party text. The request carries no ``tools`` so a prompt
   injection inside a message has nothing to call, and
   ``venice_parameters`` disables web search (which would send derived
   queries to a search provider) and Venice's own system prompt.
3. **Explicit egress route.** The caller passes an aiohttp session already
   bound to the network route the operator selected (Tor/VPN/clearnet);
   nothing here reads proxy environment variables.

Error messages raised from this module are stable codes (``VeniceError.code``)
and never contain prompt content, message text, or the API key.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Protocol

DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"
API_KEY_ENV = "VENICE_API_KEY"
MODEL_ENV = "MORDRED_TELEGRAM_VENICE_MODEL"
# A Venice-hosted (``private``) multilingual model with a large context window.
# The privacy check runs against the live catalog regardless, so a default that
# is later relabelled ``anonymized`` (or retired) is refused, not silently used.
DEFAULT_MODEL = "deepseek-v4-flash"

_CATALOG_TTL_SECONDS = 600.0
_MAX_SSE_LINE_CHARS = 1 << 20


class VeniceError(RuntimeError):
    """Stable, content-free failure code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VeniceConfig:
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL


@dataclass(frozen=True)
class ModelInfo:
    model_id: str
    privacy: str
    context_tokens: int


class _Response(Protocol):
    status: int

    async def json(self) -> Any: ...

    @property
    def content(self) -> Any: ...

    async def __aenter__(self) -> _Response: ...

    async def __aexit__(self, *exc: object) -> None: ...


class HttpSession(Protocol):
    """The subset of ``aiohttp.ClientSession`` this module uses."""

    def get(self, url: str, **kwargs: Any) -> Any: ...

    def post(self, url: str, **kwargs: Any) -> Any: ...


_catalog_cache: dict[tuple[str, str], tuple[float, ModelInfo]] = {}


def _headers(cfg: VeniceConfig) -> dict[str, str]:
    return {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"}


def _parse_model(entry: Any) -> ModelInfo | None:
    if not isinstance(entry, dict):
        return None
    model_id = entry.get("id")
    spec = entry.get("model_spec")
    if not isinstance(model_id, str) or not isinstance(spec, dict):
        return None
    privacy = spec.get("privacy")
    context = spec.get("availableContextTokens")
    if not isinstance(privacy, str):
        return None
    if not isinstance(context, int) or isinstance(context, bool) or context <= 0:
        context = 8192
    return ModelInfo(model_id=model_id, privacy=privacy, context_tokens=context)


async def _fetch_model(session: HttpSession, cfg: VeniceConfig) -> ModelInfo:
    try:
        async with session.get(f"{cfg.base_url}/models", params={"type": "text"}, headers=_headers(cfg)) as resp:
            _raise_for_status(resp.status)
            payload = await resp.json()
    except VeniceError:
        raise
    except Exception as exc:
        raise VeniceError("venice_unavailable") from exc
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise VeniceError("venice_unavailable")
    for entry in data:
        parsed = _parse_model(entry)
        if parsed is not None and parsed.model_id == cfg.model:
            return parsed
    raise VeniceError("venice_model_unknown")


async def require_private_model(session: HttpSession, cfg: VeniceConfig, *, now: float | None = None) -> ModelInfo:
    """Return the configured model's catalog entry, or raise unless ``private``."""
    stamp = time.monotonic() if now is None else now
    cache_key = (cfg.base_url, cfg.model)
    cached = _catalog_cache.get(cache_key)
    if cached is not None and stamp - cached[0] < _CATALOG_TTL_SECONDS:
        info = cached[1]
    else:
        info = await _fetch_model(session, cfg)
        _catalog_cache[cache_key] = (stamp, info)
    if info.privacy != "private":
        raise VeniceError("venice_model_not_private")
    return info


_STATUS_CODES = {
    401: "venice_unauthorized",
    402: "venice_insufficient_balance",
    429: "venice_rate_limited",
}


def _raise_for_status(status: int) -> None:
    if status != 200:
        raise VeniceError(_STATUS_CODES.get(status, "venice_unavailable"))


def build_request(cfg: VeniceConfig, messages: list[dict[str, str]], *, max_tokens: int) -> dict[str, Any]:
    """Build the chat-completions body. No ``tools`` key, ever."""
    return {
        "model": cfg.model,
        "messages": messages,
        "stream": True,
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "venice_parameters": {
            "include_venice_system_prompt": False,
            "enable_web_search": "off",
        },
    }


def _delta_text(line: str) -> str | None:
    """Return the content delta from one SSE ``data:`` line, or None."""
    if not line.startswith("data:"):
        return None
    data = line[5:].strip()
    if not data or data == "[DONE]":
        return None
    try:
        payload = json.loads(data)
    except ValueError:
        return None
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    delta = choices[0].get("delta")
    if not isinstance(delta, dict):
        return None
    content = delta.get("content")
    return content if isinstance(content, str) and content else None


async def _sse_lines(content: Any) -> AsyncIterator[str]:
    buffer = ""
    async for raw in content.iter_any():
        buffer += raw.decode("utf-8", errors="replace")
        if len(buffer) > _MAX_SSE_LINE_CHARS:
            raise VeniceError("venice_bad_response")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            yield line.strip()
    if buffer.strip():
        yield buffer.strip()


async def stream_chat(
    session: HttpSession, cfg: VeniceConfig, messages: list[dict[str, str]], *, max_tokens: int = 1500
) -> AsyncIterator[str]:
    """Stream the answer's text deltas from ``POST /chat/completions``."""
    body = build_request(cfg, messages, max_tokens=max_tokens)
    try:
        async with session.post(f"{cfg.base_url}/chat/completions", json=body, headers=_headers(cfg)) as resp:
            _raise_for_status(resp.status)
            async for line in _sse_lines(resp.content):
                text = _delta_text(line)
                if text is not None:
                    yield text
    except VeniceError:
        raise
    except Exception as exc:
        raise VeniceError("venice_unavailable") from exc
