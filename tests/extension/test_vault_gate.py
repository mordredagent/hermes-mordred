"""The vault gate of ``extension serve``: serving while the vault is locked, opening it on request."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp
import pytest

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension.vault_gate import LOCKED_REASON, VaultFatal, VaultGate
from mordred_hermes.keyvault._exceptions import WrapAuthCancelled
from tests.extension._trust_helpers import Browser, receive, with_test_root


class Opener:
    """Opens the vault on the scripted outcomes, one per call ("ok", "cancel" or "tamper")."""

    def __init__(self, *outcomes: str) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self) -> int:
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if outcome == "cancel":
            raise WrapAuthCancelled("prompt refused")
        if outcome == "tamper":
            raise RuntimeError("anchor missing at /secret/path")
        return 1


def test_a_refused_prompt_leaves_the_vault_locked_until_a_later_unlock() -> None:
    opener = Opener("cancel", "ok")
    gate = VaultGate(opener)
    opened: list[str] = []
    gate.on_open(lambda: opened.append("updater"))

    assert gate.open_at_start() == "locked" and not gate.is_open()
    assert opened == []
    assert gate.unlock() == "open" and gate.is_open()
    assert opened == ["updater"]
    # Open stays open: no further prompt, and a late listener runs at once.
    assert gate.unlock() == "open" and opener.calls == 2
    gate.on_open(lambda: opened.append("late"))
    assert opened == ["updater", "late"]


def test_a_vault_that_cannot_be_trusted_is_fatal_and_stays_so() -> None:
    gate = VaultGate(Opener("tamper"))
    stopped: list[bool] = []
    gate.on_fatal(lambda: stopped.append(True))

    with pytest.raises(VaultFatal) as fatal:
        gate.unlock()
    # Content-free: the cause's paths stay out of the message.
    assert "/secret/path" not in str(fatal.value)
    assert stopped == [True]
    with pytest.raises(VaultFatal):
        gate.unlock()


# --- the handshake while locked ----------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _echo(content: str, _context: dict[str, Any]) -> Any:
    yield f"echo:{content}"


def _run(gate: VaultGate, scenario: Callable[[aiohttp.ClientSession, str], Awaitable[Any]]) -> Any:
    async def main() -> Any:
        port = _free_port()
        server = extension_api.ExtensionAPIServer(port=port, chat_handler=_echo, vault_gate=gate)
        await server.start()
        try:
            async with aiohttp.ClientSession() as session:
                return await scenario(session, f"http://127.0.0.1:{port}/ext")
        finally:
            await server.stop()

    return asyncio.run(main())


async def _hello_reply(
    session: aiohttp.ClientSession, url: str, browser: Browser, *, unlock: bool = False
) -> dict[str, Any]:
    async with session.ws_connect(url, headers={"Origin": browser.origin}) as ws:
        challenge = await receive(ws)
        hello, _eph, _body = browser.hello(challenge)
        if unlock:
            hello["unlock"] = True
        await ws.send_str(json.dumps(hello))
        return await receive(ws)


def test_a_locked_server_answers_at_once_and_opens_only_when_asked(monkeypatch) -> None:
    with_test_root(monkeypatch)
    opener = Opener("cancel", "ok")
    gate = VaultGate(opener)
    gate.open_at_start()
    browser = Browser()

    async def scenario(session, url):
        plain = await _hello_reply(session, url, browser)
        calls_after_plain = opener.calls
        asked = await _hello_reply(session, url, browser, unlock=True)
        return plain, calls_after_plain, asked

    plain, calls_after_plain, asked = _run(gate, scenario)
    # An automatic reconnect never raises a prompt.
    assert plain == {"type": "auth_fail", "reason": LOCKED_REASON}
    assert calls_after_plain == 1
    # The unlock button's hello opens the vault, then the handshake goes on.
    assert asked["type"] == "auth2_unendorsed"
    assert opener.calls == 2 and gate.is_open()


def test_only_an_extension_may_ask_for_the_prompt(monkeypatch) -> None:
    with_test_root(monkeypatch)
    opener = Opener("cancel")
    gate = VaultGate(opener)
    gate.open_at_start()

    async def scenario(session, url):
        # The server's own localhost page (the only other origin it accepts).
        page = Browser(origin=url.removesuffix("/ext"))
        return await _hello_reply(session, url, page, unlock=True)

    assert _run(gate, scenario) == {"type": "auth_fail", "reason": LOCKED_REASON}
    assert opener.calls == 1


def test_a_refused_unlock_keeps_the_server_locked(monkeypatch) -> None:
    with_test_root(monkeypatch)
    gate = VaultGate(Opener("cancel", "cancel"))
    gate.open_at_start()
    browser = Browser()

    async def scenario(session, url):
        return await _hello_reply(session, url, browser, unlock=True)

    assert _run(gate, scenario) == {"type": "auth_fail", "reason": LOCKED_REASON}
    assert not gate.is_open()
