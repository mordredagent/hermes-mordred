"""Discord bot-API context resolution for the browser extension."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from mordred_hermes.extension import discord_context
from mordred_hermes.extension.discord_context import (
    DiscordContextError,
    _configured_bot_token,
    resolve_discord_channel,
)


class _Response:
    def __init__(
        self,
        status: int,
        payload: Any,
        headers: dict[str, str] | None = None,
        delay: float = 0.0,
    ) -> None:
        self.status = status
        self.payload = payload
        self.headers = headers or {}
        self.delay = delay

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def json(self, *, content_type=None):
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.payload


class _Session:
    def __init__(self, responses: dict[str, _Response]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict[str, str], str | None]] = []
        self.closed = False

    def get(self, url: str, *, headers: dict[str, str], proxy: str | None = None):
        channel_id = url.rsplit("/", 1)[-1]
        self.requests.append((channel_id, headers, proxy))
        return self.responses[channel_id]

    async def close(self) -> None:
        self.closed = True


def test_plain_channel_resolves_to_itself_without_exposing_the_token():
    session = _Session(
        {
            "456": _Response(
                200,
                {"id": "456", "guild_id": "123", "type": 0, "name": "secure-ops"},
            )
        }
    )
    result = asyncio.run(resolve_discord_channel("123", "456", token="secret-bot-token", session=session))
    assert result.parent_channel_id == "456"
    assert result.parent_channel_name == "secure-ops"
    assert session.requests[0][1]["Authorization"] == "Bot secret-bot-token"
    assert "secret-bot-token" not in repr(result)


def test_thread_resolves_its_parent_channel_and_name():
    session = _Session(
        {
            "999": _Response(
                200,
                {
                    "id": "999",
                    "guild_id": "123",
                    "type": 11,
                    "name": "release thread",
                    "parent_id": "456",
                },
            ),
            "456": _Response(
                200,
                {"id": "456", "guild_id": "123", "type": 0, "name": "secure-ops"},
            ),
        }
    )
    result = asyncio.run(resolve_discord_channel("123", "999", token="token", session=session))
    assert result.channel_type == 11
    assert result.parent_channel_id == "456"
    assert result.parent_channel_name == "secure-ops"
    assert [request[0] for request in session.requests] == ["999", "456"]


def test_thread_resolution_uses_one_end_to_end_deadline(monkeypatch):
    session = _Session(
        {
            "999": _Response(
                200,
                {
                    "id": "999",
                    "guild_id": "123",
                    "type": 11,
                    "name": "release thread",
                    "parent_id": "456",
                },
                delay=0.08,
            ),
            "456": _Response(
                200,
                {"id": "456", "guild_id": "123", "type": 0, "name": "secure-ops"},
                delay=0.08,
            ),
        }
    )
    monkeypatch.setattr(discord_context, "_RESOLUTION_TIMEOUT_SECONDS", 0.12)

    with pytest.raises(DiscordContextError) as raised:
        asyncio.run(resolve_discord_channel("123", "999", token="token", session=session))
    assert raised.value.code == "upstream_unavailable"
    assert [request[0] for request in session.requests] == ["999", "456"]


def test_guild_mismatch_and_rate_limit_fail_with_stable_codes():
    mismatch = _Session(
        {
            "456": _Response(
                200,
                {"id": "456", "guild_id": "999", "type": 0, "name": "wrong guild"},
            )
        }
    )
    with pytest.raises(DiscordContextError, match="guild_mismatch"):
        asyncio.run(resolve_discord_channel("123", "456", token="token", session=mismatch))

    limited = _Session({"456": _Response(429, {"retry_after": 2.5})})
    with pytest.raises(DiscordContextError) as raised:
        asyncio.run(resolve_discord_channel("123", "456", token="token", session=limited))
    assert raised.value.code == "rate_limited"
    assert raised.value.retry_after_ms == 2500


def test_configured_token_falls_back_to_the_standard_hermes_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("DISCORD_BOT_TOKEN=from-dotenv\n", encoding="utf-8")
    assert _configured_bot_token() == "from-dotenv"


@pytest.mark.parametrize(
    ("export_value", "dotenv_content", "expected"),
    [
        pytest.param(
            "stale-export", "DISCORD_BOT_TOKEN=rotated-dotenv\n", "rotated-dotenv", id="dotenv_overrides_stale_export"
        ),
        pytest.param("stale-export", "DISCORD_BOT_TOKEN=\n", "", id="empty_dotenv_overrides_stale_export"),
        pytest.param("current-export", "OTHER=value\n", "current-export", id="export_used_when_dotenv_key_absent"),
        pytest.param(
            "current-export", "DISCORD_BOT_TOKEN\n", "current-export", id="bare_dotenv_token_does_not_override_export"
        ),
    ],
)
def test_configured_token_precedence(tmp_path, monkeypatch, export_value, dotenv_content, expected):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", export_value)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / ".env").write_text(dotenv_content, encoding="utf-8")
    assert _configured_bot_token() == expected


def test_tor_route_without_a_proxy_fails_closed(monkeypatch):
    monkeypatch.setattr(discord_context, "_tor_route_required", lambda: True)
    monkeypatch.setattr("gateway.platforms.base.resolve_proxy_url", lambda **_kwargs: None)

    with pytest.raises(DiscordContextError) as raised:
        discord_context._resolve_gateway_route()
    assert raised.value.code == "routing_unavailable"


def test_standalone_configured_vpn_fails_closed(tmp_path, monkeypatch):
    from mordred_hermes.network import api as network_api
    from mordred_hermes.network._exceptions import MordredNetworkError

    (tmp_path / "config.yaml").write_text(
        "plugins:\n  mordred_network:\n    default_path: vpn\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(discord_context, "hermes_home", lambda: tmp_path)

    def no_runtime():
        raise MordredNetworkError("runtime unavailable")

    proxy_called = False

    def resolve_proxy_url(**_kwargs):
        nonlocal proxy_called
        proxy_called = True
        return None

    monkeypatch.setattr(network_api, "status", no_runtime)
    monkeypatch.setattr("gateway.platforms.base.resolve_proxy_url", resolve_proxy_url)

    with pytest.raises(DiscordContextError) as raised:
        discord_context._resolve_gateway_route()
    assert raised.value.code == "routing_unavailable"
    assert proxy_called is False


def test_tor_socks5h_route_preserves_remote_dns_without_building_connector(monkeypatch):
    monkeypatch.setattr(discord_context, "_tor_route_required", lambda: True)
    monkeypatch.setattr(
        "gateway.platforms.base.resolve_proxy_url",
        lambda **_kwargs: "socks5h://route:route@127.0.0.1:9050",
    )

    route = discord_context._resolve_gateway_route()
    assert route.socks_proxy_url == "socks5://route:route@127.0.0.1:9050"
    assert route.request_proxy is None


def test_real_socks_connector_builds_on_running_event_loop():
    async def run():
        connector = discord_context._build_socks_connector("socks5://127.0.0.1:9050")
        assert connector is not None
        await connector.close()

    asyncio.run(run())


def test_owned_session_builds_socks_connector_on_event_loop_thread(monkeypatch):
    session = _Session(
        {
            "456": _Response(
                200,
                {"id": "456", "guild_id": "123", "type": 0, "name": "secure-ops"},
            )
        }
    )
    seen: dict[str, Any] = {}
    connector = object()

    def resolve_route() -> discord_context._ClientRoute:
        seen["resolution_thread"] = threading.get_ident()
        return discord_context._ClientRoute("socks5://127.0.0.1:9050", None)

    def from_url(url: str, **kwargs: Any) -> object:
        seen.update(connector_thread=threading.get_ident(), connector_url=url, **kwargs)
        return connector

    def session_factory(**kwargs: Any) -> _Session:
        seen["session_connector"] = kwargs["connector"]
        return session

    monkeypatch.setattr(discord_context, "_resolve_gateway_route", resolve_route)
    monkeypatch.setattr("aiohttp_socks.ProxyConnector.from_url", from_url)
    monkeypatch.setattr(discord_context.aiohttp, "ClientSession", session_factory)

    async def run():
        seen["loop_thread"] = threading.get_ident()
        return await resolve_discord_channel("123", "456", token="token")

    result = asyncio.run(run())
    assert result.parent_channel_id == "456"
    assert seen["resolution_thread"] != seen["loop_thread"]
    assert seen["connector_thread"] == seen["loop_thread"]
    assert seen["connector_url"] == "socks5://127.0.0.1:9050"
    assert seen["rdns"] is True
    assert seen["session_connector"] is connector
    assert session.closed is True


def test_owned_session_disables_ambient_env_and_uses_explicit_http_proxy(monkeypatch):
    session = _Session(
        {
            "456": _Response(
                200,
                {"id": "456", "guild_id": "123", "type": 0, "name": "secure-ops"},
            )
        }
    )
    seen: dict[str, Any] = {}

    def session_factory(**kwargs: Any) -> _Session:
        seen.update(kwargs)
        return session

    monkeypatch.setattr(
        discord_context,
        "_resolve_gateway_route",
        lambda: discord_context._ClientRoute(None, "http://127.0.0.1:8118"),
    )
    monkeypatch.setattr(discord_context.aiohttp, "ClientSession", session_factory)

    result = asyncio.run(resolve_discord_channel("123", "456", token="token"))
    assert result.parent_channel_id == "456"
    assert seen["trust_env"] is False
    assert session.requests[0][2] == "http://127.0.0.1:8118"
    assert session.closed is True
