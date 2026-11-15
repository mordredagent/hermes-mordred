"""``health``: what this Hermes can do right now, feature by feature (codes only).

The extension shows one badge for the whole connection; this tells it which
parts work, so a missing model or a closed store reads as "partly available"
with a reason instead of an error after a click. Each item is::

    {"id": <feature>, "state": "ok" | "off" | "down", "code": <reason or None>}

- ``ok``: works.
- ``off``: not set up (no model configured, mail not signed in): nothing is
  broken, the feature is simply not there yet.
- ``down``: set up but failing now (the store cannot open, the model server
  does not answer).

Nothing here unlocks, prompts or leaves the machine: the store is opened
read-only through the gate that never unlocks (as ``imports_status`` does), a
local model server gets one short ``GET <base>/models`` on loopback, and a
remote chat model is reported as configured without being contacted.
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Final, Literal

State = Literal["ok", "off", "down"]

HEALTH_CAPABILITY: Final = "health_v1"
FEATURES: Final = ("search", "headlines", "recommend", "chat", "mail", "telegram", "signing")
PROBE_TIMEOUT_SECONDS: Final = 1.5

Probe = Callable[[str], bool]


def _item(feature: str, state: State, code: str | None = None) -> dict[str, Any]:
    return {"id": feature, "state": state, "code": code}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def probe_models(base_url: str) -> bool:
    """Whether a local OpenAI-compatible server answers ``GET <base>/models`` (no proxy, no redirect)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(f"{base_url.rstrip('/')}/models", timeout=PROBE_TIMEOUT_SECONDS) as response:
            json.loads(response.read(65536) or b"{}")
            return 200 <= int(response.status) < 300
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _search(home: Path, platform: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """``search`` from the read-only store, and ``mail`` from its sealed flags."""
    from ..desktop import _status_v4

    sections = _status_v4.imports_sections(home, platform)
    imports = sections.get("imports") or {}
    search = _item("search", "ok") if imports.get("available") else _item("search", "down", imports.get("code"))
    mail = sections.get("mail") or {}
    if mail.get("configured"):
        mail_item = _item("mail", "ok")
    elif mail.get("residue"):
        mail_item = _item("mail", "down", str(mail["residue"]))
    else:
        mail_item = _item("mail", "off", "not_set_up")
    return search, mail_item


def _local_model(feature: str, target: Any, probe: Probe) -> dict[str, Any]:
    if target is None:
        return _item(feature, "off", "model_not_configured")
    return _item(feature, "ok") if probe(target.base_url) else _item(feature, "down", "model_unreachable")


def _headlines(probe: Probe) -> dict[str, Any]:
    from ..extension.telegram.llm import LlmConfigError
    from ..recall.headlines import target_from_env

    try:
        return _local_model("headlines", target_from_env(), probe)
    except LlmConfigError:
        return _item("headlines", "down", "model_not_local")


def _recommend(probe: Probe) -> dict[str, Any]:
    from ..extension.telegram.llm import LlmConfigError
    from ..recall.recommend import target_from_environ

    try:
        return _local_model("recommend", target_from_environ(), probe)
    except LlmConfigError:
        return _item("recommend", "down", "model_not_local")


def _chat(chat_is_stub: bool, probe: Probe) -> dict[str, Any]:
    from .telegram import hermes_tools

    if chat_is_stub:
        return _item("chat", "down", "runtime_missing")
    model, base_url = hermes_tools._configured_model()
    if not model:
        return _item("chat", "off", "model_not_configured")
    if hermes_tools._classify_endpoint(base_url) == "local" and base_url:
        return _item("chat", "ok") if probe(base_url) else _item("chat", "down", "model_unreachable")
    # A remote provider is not contacted from here.
    return _item("chat", "ok", "not_checked")


async def _telegram(status: Callable[[], Awaitable[dict[str, Any]]] | None) -> dict[str, Any]:
    if status is None:
        return _item("telegram", "off", "telegram_unavailable")
    try:
        current = await status()
    except Exception:
        return _item("telegram", "down", "telegram_unavailable")
    if current.get("logged_in"):
        return _item("telegram", "ok")
    if current.get("last_error"):
        return _item("telegram", "down", str(current["last_error"]))
    return _item("telegram", "off", "not_logged_in")


def _signing() -> dict[str, Any]:
    from . import pairing

    return _item("signing", "ok") if pairing.se_available() else _item("signing", "off", "software_keys")


async def collect(
    *,
    home: Path,
    chat_is_stub: bool,
    telegram_status: Callable[[], Awaitable[dict[str, Any]]] | None,
    platform: str = sys.platform,
    probe: Probe = probe_models,
) -> list[dict[str, Any]]:
    """Every feature's item, in :data:`FEATURES` order; a check that fails reports ``down``."""

    def guarded(feature: str, check: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return check()
        except Exception:
            return _item(feature, "down", "check_failed")

    def store() -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            return _search(home, platform)
        except Exception:
            return _item("search", "down", "check_failed"), _item("mail", "down", "check_failed")

    (search, mail), headlines, recommend, chat, signing = await asyncio.gather(
        asyncio.to_thread(store),
        asyncio.to_thread(guarded, "headlines", lambda: _headlines(probe)),
        asyncio.to_thread(guarded, "recommend", lambda: _recommend(probe)),
        asyncio.to_thread(guarded, "chat", lambda: _chat(chat_is_stub, probe)),
        asyncio.to_thread(guarded, "signing", _signing),
    )
    telegram = await _telegram(telegram_status)
    by_id = {item["id"]: item for item in (search, mail, headlines, recommend, chat, telegram, signing)}
    return [by_id[feature] for feature in FEATURES]
