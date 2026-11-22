"""The extension chat's model: the local default, or a Venice model the user chose.

"Upgrade the chat AI" in the extension's settings switches the chat from the small
local model to a Venice model. Only a model Venice labels ``private`` can be chosen:
the chat hands it the user's memory, which the rest of Mordred gives only to
loopback or Venice-private models.

Storage
    ``<hermes home>/extension/chat_model.json`` holds the choice (backend, model)
    and the Venice API key sealed with AES-256-GCM under a key derived (HKDF,
    label :data:`PURPOSE`) from the agent-memory key. That key is the one the
    vault opens at start (Touch ID) to unlock the user's memory, so the API key is
    exactly as protected as the memory it reads, needs no other key or prompt, and
    is never written in the clear. Without the memory key nothing is stored.

Scope
    Only the ``extension serve`` process builds the chat agent from this choice
    (:func:`set_active`). Mordred's checks of which model may read imported history
    then see the model the chat actually runs (:func:`active`), not the one in
    ``config.yaml``; other Hermes processes are unaffected.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

_log = logging.getLogger(__name__)

PURPOSE: Final = b"mordred-extension-chat-venice-key-v1"
VENICE_HOST: Final = "api.venice.ai"
_FILE: Final = "chat_model.json"
_MAX_KEY_CHARS: Final = 512
_MAX_MODEL_CHARS: Final = 128
_MAX_FILE_BYTES: Final = 4096

_lock = threading.Lock()
_key_cache: dict[str, str] = {}
_active: dict[str, str] = {}


class ChatModelError(RuntimeError):
    """A stable, content-free failure code for the extension."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ChatModel:
    """The user's choice. ``sealed_key`` is the API key sealed with the memory key (base64)."""

    backend: str
    model: str
    sealed_key: str = field(repr=False)

    @property
    def base_url(self) -> str:
        from .telegram import venice

        return venice.DEFAULT_BASE_URL


# ---- the stored choice ------------------------------------------------------------------


def _dir() -> Path:
    from ..keyvault import extension_sign

    return extension_sign._ext_dir()


def load() -> ChatModel | None:
    """The stored choice, or ``None`` for the local default (also when the file is unusable)."""
    path = _dir() / _FILE
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        _log.warning("extension chat model: %s unreadable; using the local model", _FILE)
        return None
    try:
        data = json.loads(raw[: _MAX_FILE_BYTES + 1].decode("utf-8"))
        if len(raw) > _MAX_FILE_BYTES or not isinstance(data, dict) or data.get("version") != 2:
            raise ValueError
        choice = ChatModel(backend=data["backend"], model=data["model"], sealed_key=data["sealed_key"])
        if choice.backend != "venice" or not all(isinstance(v, str) and v for v in (choice.model, choice.sealed_key)):
            raise ValueError
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        _log.warning("extension chat model: %s invalid; using the local model", _FILE)
        return None
    return choice


def _write(choice: ChatModel) -> None:
    from ..keyvault._extension_config import _validate_extension_dir
    from ..keyvault._storage import atomic_write

    payload = json.dumps(
        {
            "version": 2,
            "backend": choice.backend,
            "model": choice.model,
            "sealed_key": choice.sealed_key,
        },
        sort_keys=True,
    ).encode("utf-8")
    directory = _dir()
    _validate_extension_dir(directory, create=True)
    try:
        atomic_write(directory / _FILE, payload)
    except OSError as exc:
        raise ChatModelError("chat_model_not_saved") from exc


def _memory_key() -> bytes:
    """The agent-memory key this process holds (the vault opened it at start)."""
    from .._core._home import hermes_home
    from ..keyvault._memory_key import resolve_memory_key

    try:
        key = resolve_memory_key(home=hermes_home(), platform=sys.platform, environ=os.environ)
    except Exception as exc:
        raise ChatModelError("memory_key_unavailable") from exc
    if not key:
        raise ChatModelError("memory_key_unavailable")
    return key


def _aead() -> Any:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PURPOSE).derive(_memory_key())
    return AESGCM(derived)


def _seal_key(api_key: str) -> str:
    """``api_key`` sealed for this Hermes home: base64(nonce || AES-256-GCM)."""
    nonce = secrets.token_bytes(12)
    sealed = _aead().encrypt(nonce, api_key.encode("utf-8"), PURPOSE)
    return base64.b64encode(nonce + sealed).decode("ascii")


def api_key(choice: ChatModel) -> str:
    """The Venice API key of ``choice`` (opened with the memory key; kept for this process)."""
    with _lock:
        cache_key = hashlib.sha256(choice.sealed_key.encode("ascii")).hexdigest()
        cached = _key_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            blob = base64.b64decode(choice.sealed_key, validate=True)
            key = str(_aead().decrypt(blob[:12], blob[12:], PURPOSE).decode("utf-8"))
        except ChatModelError:
            raise
        except Exception as exc:
            raise ChatModelError("chat_model_key_unavailable") from exc
        _key_cache[cache_key] = key
        return key


# ---- the model the chat runs (this process only) ----------------------------------------


def set_active(model: str | None, base_url: str | None) -> None:
    """Record the model the extension chat runs in this process (``None`` for the configured one)."""
    with _lock:
        _active.clear()
        if model and base_url:
            _active.update(model=model, base_url=base_url)


def active() -> tuple[str, str] | None:
    """``(model, base_url)`` the extension chat runs in this process, if it is not the configured one."""
    with _lock:
        if _active:
            return _active["model"], _active["base_url"]
    return None


# ---- Venice -------------------------------------------------------------------------------


async def _catalog() -> list[dict[str, Any]]:
    """Venice's public text-model catalog (no key), through Mordred's egress route."""
    from .egress import resolve_route
    from .telegram.service import _default_http_session, _ProxiedSession
    from .telegram.venice import DEFAULT_BASE_URL

    route = await asyncio.to_thread(resolve_route, VENICE_HOST)
    raw = _default_http_session(route, 30.0)
    try:
        session = _ProxiedSession(raw, route.http_proxy_url)
        async with session.get(f"{DEFAULT_BASE_URL}/models", params={"type": "text"}, allow_redirects=False) as resp:
            if resp.status != 200:
                raise ChatModelError("venice_unavailable")
            payload = await resp.json()
    except ChatModelError:
        raise
    except Exception as exc:
        raise ChatModelError("venice_unavailable") from exc
    finally:
        await raw.close()
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise ChatModelError("venice_unavailable")
    return [entry for entry in data if isinstance(entry, dict)]


async def private_models() -> list[dict[str, Any]]:
    """The models Venice labels ``private``: ``[{id, name, context_tokens}]``, in catalog order."""
    from .telegram.venice import _parse_model

    out = []
    for entry in await _catalog():
        parsed = _parse_model(entry)
        if parsed is None or parsed.privacy != "private":
            continue
        raw_spec = entry.get("model_spec")
        spec: dict[str, Any] = raw_spec if isinstance(raw_spec, dict) else {}
        name = spec.get("name") if isinstance(spec.get("name"), str) else parsed.model_id
        out.append({"id": parsed.model_id, "name": name, "context_tokens": parsed.context_tokens})
    return out


def guard_refuses_venice() -> bool:
    """Whether Mordred's LLM guard (strict mode) would refuse a chat on Venice."""
    try:
        from ..llm_guard._policy_settings import _read_policy_settings
        from ..llm_guard._registration import DEFAULT_POLICY_JSON_PATH, _read_policy_mode

        if _read_policy_mode(DEFAULT_POLICY_JSON_PATH) != "strict":
            return False
        settings = _read_policy_settings(DEFAULT_POLICY_JSON_PATH)
        return not (settings.allow_cloud_llm and "venice" in settings.cloud_allowlist)
    except Exception:
        return True  # unknown: say so rather than let the first chat fail


async def set_venice(api_key: str, model: str) -> ChatModel:
    """Choose ``model`` on Venice with ``api_key``; refuses a model Venice does not label private."""
    key = (api_key or "").strip()
    name = (model or "").strip()
    if not key or len(key) > _MAX_KEY_CHARS or any(c.isspace() for c in key):
        raise ChatModelError("venice_key_invalid")
    if not name or len(name) > _MAX_MODEL_CHARS:
        raise ChatModelError("venice_model_unknown")
    if guard_refuses_venice():
        raise ChatModelError("llm_guard_refuses_venice")
    if name not in {m["id"] for m in await private_models()}:
        raise ChatModelError("venice_model_not_private")
    sealed = await asyncio.to_thread(_seal_key, key)
    choice = ChatModel(backend="venice", model=name, sealed_key=sealed)
    await asyncio.to_thread(_write, choice)
    with _lock:
        _key_cache[hashlib.sha256(sealed.encode("ascii")).hexdigest()] = key
    _log.info("extension chat model: Venice model %s chosen", name)
    return choice


def clear() -> None:
    """Go back to the local model."""
    path = _dir() / _FILE
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ChatModelError("chat_model_not_saved") from exc
    with _lock:
        _key_cache.clear()
    _log.info("extension chat model: back to the local model")


def status() -> dict[str, Any]:
    """What the extension shows: which model the chat runs, and whether Venice could be chosen."""
    choice = load()
    return {
        "backend": choice.backend if choice else "local",
        "model": choice.model if choice else None,
        "guard_refuses_venice": guard_refuses_venice(),
    }
