"""Resolve Discord channel/thread metadata for the browser extension.

The Discord bot token stays on Hermes.  Callers receive only bounded channel
metadata needed to bind E2EE coverage to the correct parent text channel.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from mordred_hermes import __version__
from mordred_hermes._home import hermes_home

_API_ROOT = "https://discord.com/api/v10"
_SOURCE_URL = "https://github.com/InternetMaximalism/hermes-mordred"
_THREAD_TYPES = frozenset({10, 11, 12})
_SNOWFLAKE_RE = re.compile(r"[0-9]{1,20}")
# The browser extension gives the entire RPC eight seconds.  Keep route
# resolution plus both possible Discord requests below that wire deadline.
_RESOLUTION_TIMEOUT_SECONDS = 6.0
_PROTECTED_NETWORK_PATHS = frozenset({"tor", "vpn"})


@dataclass(frozen=True)
class DiscordChannelContext:
    guild_id: str
    channel_id: str
    channel_type: int
    channel_name: str
    parent_channel_id: str
    parent_channel_name: str


class DiscordContextError(RuntimeError):
    """Stable, content-free failure returned to the paired extension."""

    def __init__(self, code: str, *, retry_after_ms: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after_ms = retry_after_ms


@dataclass(frozen=True)
class _ClientRoute:
    connector: aiohttp.BaseConnector | None
    request_proxy: str | None


def _snowflake(value: Any) -> str | None:
    return value if isinstance(value, str) and _SNOWFLAKE_RE.fullmatch(value) else None


def _channel_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized[:256] if normalized else None


def _channel_type(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255 else None


def _retry_after_ms(response: aiohttp.ClientResponse, payload: Any) -> int:
    seconds: float | None = None
    if isinstance(payload, dict):
        raw = payload.get("retry_after")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw >= 0:
            seconds = float(raw)
    if seconds is None:
        raw_header = response.headers.get("Retry-After")
        try:
            seconds = max(0.0, float(raw_header)) if raw_header is not None else 1.0
        except ValueError:
            seconds = 1.0
    return min(3_600_000, max(0, int(seconds * 1000)))


async def _get_channel(
    session: aiohttp.ClientSession,
    token: str,
    channel_id: str,
    *,
    proxy: str | None,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bot {token}",
        "User-Agent": f"DiscordBot ({_SOURCE_URL}, {__version__})",
    }
    try:
        request_kwargs: dict[str, Any] = {"headers": headers}
        if proxy is not None:
            request_kwargs["proxy"] = proxy
        async with session.get(f"{_API_ROOT}/channels/{channel_id}", **request_kwargs) as response:
            try:
                payload: Any = await response.json(content_type=None)
            except (ValueError, aiohttp.ClientPayloadError):
                payload = None

            if response.status == 200:
                if not isinstance(payload, dict):
                    raise DiscordContextError("invalid_response")
                return payload
            if response.status == 401:
                raise DiscordContextError("discord_auth_failed")
            if response.status in {403, 404}:
                raise DiscordContextError("not_accessible")
            if response.status == 429:
                raise DiscordContextError(
                    "rate_limited",
                    retry_after_ms=_retry_after_ms(response, payload),
                )
            raise DiscordContextError("upstream_unavailable")
    except DiscordContextError:
        raise
    except (aiohttp.ClientError, TimeoutError) as exc:
        raise DiscordContextError("upstream_unavailable") from exc


def _validate_channel(
    payload: dict[str, Any],
    *,
    expected_channel_id: str,
    expected_guild_id: str,
) -> tuple[int, str]:
    if _snowflake(payload.get("id")) != expected_channel_id:
        raise DiscordContextError("invalid_response")
    if _snowflake(payload.get("guild_id")) != expected_guild_id:
        raise DiscordContextError("guild_mismatch")
    kind = _channel_type(payload.get("type"))
    name = _channel_name(payload.get("name"))
    if kind is None or name is None:
        raise DiscordContextError("invalid_response")
    return kind, name


def _tor_route_required() -> bool:
    """Return whether Discord must use Tor, failing closed on bad live state.

    The registered runtime is authoritative in a full Hermes process.  The
    standalone extension launcher has no plugin discovery, so it falls back to
    the persisted selection and still refuses direct egress when Tor is chosen.
    """

    from mordred_hermes.network import api as network_api
    from mordred_hermes.network._exceptions import MordredNetworkError

    try:
        status = network_api.status()
    except MordredNetworkError:
        try:
            from mordred_hermes.network.settings import read_default_path_strict

            return read_default_path_strict(hermes_home() / "config.yaml") == "tor"
        except Exception as exc:
            raise DiscordContextError("routing_unavailable") from exc
    except Exception as exc:
        raise DiscordContextError("routing_unavailable") from exc

    if status.active_path not in {"tor", "vpn", "clearnet"}:
        raise DiscordContextError("routing_unavailable")
    if status.active_path in _PROTECTED_NETWORK_PATHS and not status.ready:
        raise DiscordContextError("routing_unavailable")
    try:
        if status.active_path in _PROTECTED_NETWORK_PATHS and network_api.is_dropped():
            raise DiscordContextError("routing_unavailable")
    except DiscordContextError:
        raise
    except Exception as exc:
        raise DiscordContextError("routing_unavailable") from exc
    return status.active_path == "tor"


def _loopback_proxy_host(url: str) -> bool:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if host is None:
        return False
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _resolve_gateway_route() -> _ClientRoute:
    """Resolve one explicit aiohttp route for Discord API traffic.

    ``aiohttp`` does not consume proxy environment variables unless
    ``trust_env=True``.  Resolve the same gateway route used elsewhere, then
    pass it explicitly.  ``aiohttp-socks`` cannot parse ``socks5h://``;
    translating it to ``socks5://`` with ``rdns=True`` preserves remote DNS.
    """

    tor_required = _tor_route_required()
    try:
        from gateway.platforms.base import resolve_proxy_url

        proxy_url = resolve_proxy_url(target_hosts="discord.com")
    except Exception as exc:
        raise DiscordContextError("routing_unavailable") from exc

    if not proxy_url:
        if tor_required:
            raise DiscordContextError("routing_unavailable")
        return _ClientRoute(None, None)

    try:
        scheme = urlsplit(proxy_url).scheme.casefold()
    except ValueError as exc:
        raise DiscordContextError("routing_unavailable") from exc

    if scheme in {"socks5", "socks5h"}:
        if tor_required and not _loopback_proxy_host(proxy_url):
            raise DiscordContextError("routing_unavailable")
        socks_url = f"socks5://{proxy_url.split('://', 1)[1]}"
        try:
            from aiohttp_socks import ProxyConnector

            connector = ProxyConnector.from_url(socks_url, rdns=True)
        except (ImportError, ValueError) as exc:
            raise DiscordContextError("routing_unavailable") from exc
        return _ClientRoute(connector, None)

    if tor_required or scheme not in {"http", "https"}:
        raise DiscordContextError("routing_unavailable")
    return _ClientRoute(None, proxy_url)


async def resolve_discord_channel(
    guild_id: str,
    channel_id: str,
    *,
    token: str | None = None,
    session: aiohttp.ClientSession | None = None,
) -> DiscordChannelContext:
    """Return the route channel and its E2EE parent using Discord's bot API."""

    if _snowflake(guild_id) is None or _snowflake(channel_id) is None:
        raise DiscordContextError("invalid_request")
    owns_session = session is None
    try:
        async with asyncio.timeout(_RESOLUTION_TIMEOUT_SECONDS):
            resolved_token = token if token is not None else _configured_bot_token()
            resolved_token = resolved_token.strip()
            if not resolved_token:
                raise DiscordContextError("not_configured")

            request_proxy: str | None = None
            if session is None:
                client_route = await asyncio.to_thread(_resolve_gateway_route)
                request_proxy = client_route.request_proxy
                timeout = aiohttp.ClientTimeout(total=_RESOLUTION_TIMEOUT_SECONDS)
                session = aiohttp.ClientSession(
                    connector=client_route.connector,
                    timeout=timeout,
                    trust_env=False,
                )

            route = await _get_channel(
                session,
                resolved_token,
                channel_id,
                proxy=request_proxy,
            )
            kind, name = _validate_channel(
                route,
                expected_channel_id=channel_id,
                expected_guild_id=guild_id,
            )
            if kind not in _THREAD_TYPES:
                return DiscordChannelContext(
                    guild_id=guild_id,
                    channel_id=channel_id,
                    channel_type=kind,
                    channel_name=name,
                    parent_channel_id=channel_id,
                    parent_channel_name=name,
                )

            parent_id = _snowflake(route.get("parent_id"))
            if parent_id is None:
                raise DiscordContextError("invalid_response")
            parent = await _get_channel(
                session,
                resolved_token,
                parent_id,
                proxy=request_proxy,
            )
            _parent_kind, parent_name = _validate_channel(
                parent,
                expected_channel_id=parent_id,
                expected_guild_id=guild_id,
            )
            return DiscordChannelContext(
                guild_id=guild_id,
                channel_id=channel_id,
                channel_type=kind,
                channel_name=name,
                parent_channel_id=parent_id,
                parent_channel_name=parent_name,
            )
    except TimeoutError as exc:
        raise DiscordContextError("upstream_unavailable") from exc
    finally:
        if owns_session and session is not None:
            await session.close()


def _configured_bot_token() -> str:
    """Read the process environment, then the standard Hermes dotenv file."""

    configured = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    if configured:
        return configured
    try:
        from dotenv import dotenv_values

        path = hermes_home() / ".env"
        text = path.read_text("utf-8")
        value = dotenv_values(stream=io.StringIO(text), interpolate=False).get("DISCORD_BOT_TOKEN")
        return value.strip() if isinstance(value, str) else ""
    except (OSError, UnicodeError, ValueError):
        return ""
