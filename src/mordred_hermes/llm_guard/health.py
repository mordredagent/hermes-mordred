"""Cheap pre-request health probe for the local LLM endpoint.

Sole entry point: :func:`probe`. Hits ``{endpoint}/models`` with a short
timeout; on any failure it raises :class:`MordredLocalUnreachable` so the
caller (PR2 ``enforce`` handler) can decide whether to refuse the session
(strict) or degrade (lenient).

Why ``transport=`` injection: ``httpx.MockTransport`` is the built-in test
double; accepting it as a kwarg keeps the production path simple while
making tests fully deterministic (no real socket).
"""

from __future__ import annotations

import logging
from typing import Final

import httpx

from ._exceptions import MordredLocalUnreachable

_LOG = logging.getLogger("mordred.llm_guard.health")

DEFAULT_TIMEOUT_SECONDS: Final[float] = 2.0


def probe(
    *,
    endpoint: str,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """GET ``{endpoint}/models`` and raise on any failure.

    Args:
        endpoint: Base URL of the local OpenAI-compatible API
            (e.g. ``http://localhost:1234/v1``). A trailing slash is
            tolerated.
        transport: Optional ``httpx`` transport. Tests inject
            :class:`httpx.MockTransport`; production passes ``None`` to
            use the default network transport.
        timeout: Connect + read timeout in seconds. Default short.

    Raises:
        MordredLocalUnreachable: On any non-2xx status, connect failure,
            or timeout. The exception message includes a short reason.
    """
    url = endpoint.rstrip("/") + "/models"
    # This module probes only a previously validated local endpoint. Ambient
    # HTTP(S)_PROXY must never receive even the health request, regardless of
    # hook ordering or a user's pre-existing proxy environment.
    client_kwargs: dict[str, object] = {"timeout": timeout, "trust_env": False}
    if transport is not None:
        client_kwargs["transport"] = transport
    try:
        with httpx.Client(**client_kwargs) as client:  # type: ignore[arg-type]
            response = client.get(url)
    except httpx.TimeoutException as e:
        raise MordredLocalUnreachable(f"local LLM probe timed out: {e!s}") from e
    except httpx.RequestError as e:
        # ConnectError, ReadError, etc. — everything below the transport.
        raise MordredLocalUnreachable(f"local LLM probe failed: {e!s}") from e

    if response.status_code >= 400:
        raise MordredLocalUnreachable(f"local LLM probe returned HTTP {response.status_code}")

    _LOG.debug("local LLM probe ok: %s", url)
    return None
