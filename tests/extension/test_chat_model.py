"""The extension chat's model choice: storage, Venice checks, the agent, the reader gates, the wire."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import chat as extension_chat
from mordred_hermes.extension import chat_model
from mordred_hermes.extension.crypto import decrypt_message, encrypt_message_v2, hkdf_subkey, key_id
from mordred_hermes.extension.telegram import hermes_tools
from tests.extension._trust_helpers import authenticate

_PRIVATE = [{"id": "venice-private-1", "name": "Private One", "context_tokens": 32768}]


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """A temporary extension directory, a memory key, Venice's catalog faked, no guard."""
    sealed: list[str] = []
    real_seal = chat_model._seal_key

    def seal(key: str) -> str:
        sealed.append(key)
        return real_seal(key)

    async def models() -> list[dict[str, Any]]:
        return list(_PRIVATE)

    monkeypatch.setattr(chat_model, "_dir", lambda: tmp_path / "extension")
    monkeypatch.setattr(chat_model, "_memory_key", lambda: b"\x07" * 32)
    monkeypatch.setattr(chat_model, "_seal_key", seal)
    monkeypatch.setattr(chat_model, "private_models", models)
    monkeypatch.setattr(chat_model, "guard_refuses_venice", lambda: False)
    monkeypatch.setattr(
        "mordred_hermes.keyvault._extension_config._validate_extension_dir",
        lambda path, *, create: path.mkdir(parents=True, exist_ok=True) or True,
    )
    chat_model._key_cache.clear()
    chat_model.set_active(None, None)
    yield sealed
    chat_model._key_cache.clear()
    chat_model.set_active(None, None)


def test_a_private_venice_model_is_stored_without_its_key(store: list[str], tmp_path: Path) -> None:
    choice = asyncio.run(chat_model.set_venice(" sk-venice ", "venice-private-1"))

    assert store == ["sk-venice"]
    saved = (tmp_path / "extension" / "chat_model.json").read_text()
    assert "sk-venice" not in saved
    data = json.loads(saved)
    assert {k: data[k] for k in ("version", "backend", "model")} == {
        "version": 2,
        "backend": "venice",
        "model": "venice-private-1",
    }
    assert chat_model.load() == choice
    chat_model._key_cache.clear()  # a new process opens it with the memory key
    assert chat_model.api_key(choice) == "sk-venice"
    assert chat_model.status() == {"backend": "venice", "model": "venice-private-1", "guard_refuses_venice": False}


@pytest.mark.parametrize(
    ("key", "model", "code"),
    [
        ("", "venice-private-1", "venice_key_invalid"),
        ("sk with space", "venice-private-1", "venice_key_invalid"),
        ("sk-venice", "", "venice_model_unknown"),
        ("sk-venice", "venice-public-model", "venice_model_not_private"),
    ],
)
def test_bad_choices_are_refused_and_nothing_is_stored(
    store: list[str], tmp_path: Path, key: str, model: str, code: str
) -> None:
    with pytest.raises(chat_model.ChatModelError) as err:
        asyncio.run(chat_model.set_venice(key, model))
    assert err.value.code == code
    assert store == [] and chat_model.load() is None


def test_a_strict_llm_guard_without_venice_refuses_the_choice(
    store: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(chat_model, "guard_refuses_venice", lambda: True)
    with pytest.raises(chat_model.ChatModelError) as err:
        asyncio.run(chat_model.set_venice("sk-venice", "venice-private-1"))
    assert err.value.code == "llm_guard_refuses_venice"


def test_clear_goes_back_to_the_local_model(store: list[str]) -> None:
    asyncio.run(chat_model.set_venice("sk-venice", "venice-private-1"))
    chat_model.clear()
    assert chat_model.load() is None
    assert chat_model.status()["backend"] == "local"
    chat_model.clear()  # twice is fine


def test_an_unusable_file_means_the_local_model(store: list[str], tmp_path: Path) -> None:
    (tmp_path / "extension").mkdir(parents=True)
    (tmp_path / "extension" / "chat_model.json").write_text('{"version": 1, "backend": "other"}')
    assert chat_model.load() is None


def test_the_reader_gates_judge_the_model_the_chat_runs(store: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hermes_tools, "_configured_model", hermes_tools._configured_model)
    chat_model.set_active("venice-private-1", "https://api.venice.ai/api/v1")
    assert hermes_tools._configured_model() == ("venice-private-1", "https://api.venice.ai/api/v1")
    chat_model.set_active(None, None)
    assert hermes_tools._configured_model() != ("venice-private-1", "https://api.venice.ai/api/v1")


def test_the_agent_runs_on_the_chosen_model(store: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    import gateway.run as gateway_run
    import run_agent

    built: dict[str, Any] = {}

    class _Agent:
        def __init__(self, **kwargs: Any) -> None:
            built.clear()
            built.update(kwargs)

    monkeypatch.setattr(run_agent, "AIAgent", _Agent)
    monkeypatch.setattr(gateway_run, "_resolve_gateway_model", lambda _m: "local-2b")
    monkeypatch.setattr(
        gateway_run,
        "_resolve_runtime_agent_kwargs",
        lambda: {"provider": "custom", "base_url": "http://127.0.0.1:8082/v1", "api_key": "x", "max_tokens": 4096},
    )
    state: dict[str, Any] = {"agent": None, "sig": None}

    extension_chat._ensure_agent(object(), state)
    assert built["model"] == "local-2b" and built["base_url"] == "http://127.0.0.1:8082/v1"
    assert chat_model.active() is None

    asyncio.run(chat_model.set_venice("sk-venice", "venice-private-1"))
    extension_chat._ensure_agent(object(), state)  # the choice changed: rebuilt
    assert built["model"] == "venice-private-1"
    assert built["provider"] == "venice" and built["api_key"] == "sk-venice"
    assert built["base_url"] == "https://api.venice.ai/api/v1" and built["max_tokens"] == 4096
    assert chat_model.active() == ("venice-private-1", "https://api.venice.ai/api/v1")

    chat_model.clear()
    extension_chat._ensure_agent(object(), state)
    assert built["model"] == "local-2b" and chat_model.active() is None


# ---- the wire ------------------------------------------------------------------------

_AES = b"\x03" * 32
_EK = hkdf_subkey(_AES, "mordred-extchat-v1", "extchat")


class _FakeWS:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[dict[str, Any]] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


async def _no_chat(_content: str, _context: dict[str, Any]) -> Any:
    if False:
        yield ""


def _call(body: Any, *, sealed: bool = True, page: bool = False) -> dict[str, Any]:
    conn = extension_api._Connection(_FakeWS(), _no_chat, page_token="p" if page else None)
    if page:
        conn.authed = True
        conn._page_authenticated = True
    else:
        authenticate(conn, _EK)
    content = encrypt_message_v2(_EK, json.dumps(body), key_id(_EK)) if sealed else json.dumps(body)
    asyncio.run(conn.dispatch(json.dumps({"id": "m", "type": "chat_model_call", "content": content})))
    [frame] = conn.ws.sent
    return frame


def test_set_and_status_cross_the_wire_sealed(store: list[str]) -> None:
    frame = _call({"op": "set_venice", "api_key": "sk-venice", "model": "venice-private-1"})
    assert frame["type"] == "chat_model_result" and frame["ok"] is True
    assert json.loads(decrypt_message(_EK, frame["content"]))["backend"] == "venice"
    models = _call({"op": "models"})
    assert json.loads(decrypt_message(_EK, models["content"])) == {"models": _PRIVATE}


def test_a_plaintext_key_is_refused_and_codes_pass_through(store: list[str]) -> None:
    plain = _call({"op": "set_venice", "api_key": "sk-venice", "model": "venice-private-1"}, sealed=False)
    assert plain == {"id": "m", "type": "chat_model_result", "ok": False, "error": "invalid_request"}
    assert store == []
    refused = _call({"op": "set_venice", "api_key": "sk-venice", "model": "venice-public-model"})
    assert refused == {"id": "m", "type": "chat_model_result", "ok": False, "error": "venice_model_not_private"}
    assert _call({"op": "nope"})["error"] == "invalid_request"


def test_page_sessions_never_reach_the_chat_model(store: list[str]) -> None:
    frame = _call({"op": "status"}, page=True)
    assert frame == {"id": "m", "type": "error", "reason": "page_session_forbidden"}


def test_without_the_memory_key_nothing_is_stored(store: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def no_key() -> bytes:
        raise chat_model.ChatModelError("memory_key_unavailable")

    monkeypatch.setattr(chat_model, "_memory_key", no_key)
    with pytest.raises(chat_model.ChatModelError) as err:
        asyncio.run(chat_model.set_venice("sk-venice", "venice-private-1"))
    assert err.value.code == "memory_key_unavailable"
    assert chat_model.load() is None


def test_another_memory_key_cannot_open_the_api_key(store: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    choice = asyncio.run(chat_model.set_venice("sk-venice", "venice-private-1"))
    chat_model._key_cache.clear()
    monkeypatch.setattr(chat_model, "_memory_key", lambda: b"\x08" * 32)
    with pytest.raises(chat_model.ChatModelError) as err:
        chat_model.api_key(choice)
    assert err.value.code == "chat_model_key_unavailable"
