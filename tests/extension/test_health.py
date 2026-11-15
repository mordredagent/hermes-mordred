"""``health``: each feature's state and reason, without unlocking, prompting or leaving the machine."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.desktop import _status_v4
from mordred_hermes.extension import health, pairing
from mordred_hermes.extension.telegram import hermes_tools


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The checks' inputs, each set per test: store sections, model config, SE, environment."""
    state: dict[str, Any] = {
        "sections": {"imports": {"available": True}, "mail": {"configured": False}},
        "chat_model": ("local-model", "http://127.0.0.1:9/v1"),
        "se": True,
    }
    monkeypatch.setattr(_status_v4, "imports_sections", lambda _home, _platform: state["sections"])
    monkeypatch.setattr(hermes_tools, "_configured_model", lambda: state["chat_model"])
    monkeypatch.setattr(pairing, "se_available", lambda: state["se"])
    for name in (
        "MORDRED_RECALL_LLM_ENDPOINT",
        "MORDRED_RECALL_LLM_MODEL",
        "MORDRED_RECALL_AGENT_ENDPOINT",
        "MORDRED_RECALL_AGENT_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    return state


def _collect(probe: Any = lambda _url: True, *, stub: bool = False, telegram: Any = None) -> dict[str, Any]:
    async def status() -> dict[str, Any]:
        if isinstance(telegram, Exception):
            raise telegram
        return telegram or {"logged_in": False}

    items = asyncio.run(
        health.collect(home=Path("/nonexistent"), chat_is_stub=stub, telegram_status=status, probe=probe)
    )
    assert [item["id"] for item in items] == list(health.FEATURES)
    return {item["id"]: (item["state"], item["code"]) for item in items}


def test_a_fresh_setup_reports_what_is_not_there_yet(settings: dict[str, Any]) -> None:
    probed: list[str] = []
    got = _collect(lambda url: probed.append(url) or True)
    assert got == {
        "search": ("ok", None),
        "headlines": ("off", "model_not_configured"),
        "recommend": ("off", "model_not_configured"),
        "chat": ("ok", None),
        "mail": ("off", "not_set_up"),
        "telegram": ("off", "not_logged_in"),
        "signing": ("ok", None),
    }
    # Only the loopback chat server was probed.
    assert probed == ["http://127.0.0.1:9/v1"]


def test_failures_read_as_down_with_their_reason(settings: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    settings["sections"] = {
        "imports": {"available": False, "code": "no_key"},
        "mail": {"configured": False, "residue": "credentials_left"},
    }
    settings["se"] = False
    monkeypatch.setenv("MORDRED_RECALL_LLM_ENDPOINT", "http://127.0.0.1:8081/v1")
    monkeypatch.setenv("MORDRED_RECALL_LLM_MODEL", "m")
    got = _collect(lambda _url: False, telegram={"logged_in": False, "last_error": "telegram_session_expired"})
    assert got["search"] == ("down", "no_key")
    assert got["mail"] == ("down", "credentials_left")
    # The recommender falls back to the headline model: both are down together.
    assert got["headlines"] == got["recommend"] == ("down", "model_unreachable")
    assert got["chat"] == ("down", "model_unreachable")
    assert got["telegram"] == ("down", "telegram_session_expired")
    assert got["signing"] == ("off", "software_keys")


def test_a_remote_chat_model_is_not_contacted(settings: dict[str, Any]) -> None:
    settings["chat_model"] = ("venice-model", "https://api.venice.ai/api/v1")
    probed: list[str] = []
    got = _collect(lambda url: probed.append(url) or True)
    assert got["chat"] == ("ok", "not_checked") and probed == []


def test_the_stub_chat_and_a_failing_check_are_down(settings: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_home: Any, _platform: Any) -> Any:
        raise RuntimeError("store exploded")

    monkeypatch.setattr(_status_v4, "imports_sections", broken)
    got = _collect(stub=True, telegram=RuntimeError("down"))
    assert got["chat"] == ("down", "runtime_missing")
    assert got["search"] == ("down", "check_failed") and got["mail"] == ("down", "check_failed")
    assert got["telegram"] == ("down", "telegram_unavailable")


def test_the_probe_asks_a_local_server_for_its_models() -> None:
    class Models(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            ok = self.path == "/v1/models"
            self.send_response(200 if ok else 404)
            self.end_headers()
            self.wfile.write(json.dumps({"data": []}).encode())

        def log_message(self, *_args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Models)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert health.probe_models(f"http://127.0.0.1:{server.server_port}/v1") is True
    finally:
        server.shutdown()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
    assert health.probe_models(f"http://127.0.0.1:{closed}/v1") is False


def test_an_approved_browser_gets_the_items_and_the_capability(settings: dict[str, Any], monkeypatch) -> None:
    import aiohttp

    from mordred_hermes.extension import api as extension_api
    from tests.extension._trust_helpers import Browser, receive, with_test_root

    with_test_root(monkeypatch)
    browser = Browser()

    async def main() -> tuple[dict[str, Any], dict[str, Any]]:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server = extension_api.ExtensionAPIServer(port=port)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{port}/ext"
                async with session.ws_connect(url, headers={"Origin": browser.origin}) as ws:
                    ok = await browser.connect(ws)
                    await ws.send_str(json.dumps({"id": "h1", "type": "health"}))
                    return ok, await receive(ws)
        finally:
            await server.stop()

    ok, reply = asyncio.run(main())
    assert health.HEALTH_CAPABILITY in ok["capabilities"]
    assert reply["id"] == "h1" and reply["type"] == "health_result"
    items = {item["id"]: item for item in reply["items"]}
    assert set(items) == set(health.FEATURES)
    # The built-in stub chat handler is not the real agent.
    assert items["chat"]["state"] == "down" and items["chat"]["code"] == "runtime_missing"
