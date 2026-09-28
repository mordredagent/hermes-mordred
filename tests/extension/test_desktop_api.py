"""Mordred setup API for Hermes Desktop (desktop/api.py) and its installer."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from mordred_hermes.desktop import api, install  # noqa: E402
from mordred_hermes.extension.telegram import secrets  # noqa: E402

SECRET_HASH = "cd" * 16
SECRET_CODE = "54321"
SECRET_PASSWORD = "two-step-secret"
SECRET_VENICE = "venice-SECRET-key"


class _Store:
    def __init__(self) -> None:
        self.value: secrets.TelegramSecrets | None = None
        self.key = False

    def load(self, *, fresh: bool = True) -> secrets.TelegramSecrets | None:
        return self.value

    def ensure_key(self, *, require_presence: bool = True) -> None:
        self.key = True

    def store(self, value: secrets.TelegramSecrets) -> None:
        self.value = value

    def update(self, mutate: Any) -> Any:
        self.value = mutate(self.value)
        return self.value

    def flags(self) -> Any:
        return None


class _Client:
    def __init__(self, needs_password: bool) -> None:
        self.needs_password = needs_password
        self.session = "SESSION-STRING"
        self.disconnected = False

    async def connect(self) -> None:
        return None

    async def send_code_request(self, phone: str) -> None:
        return None

    async def sign_in(self, **kwargs: Any) -> Any:
        if "code" in kwargs:
            if kwargs["code"] != SECRET_CODE:
                raise type("PhoneCodeInvalidError", (Exception,), {})()
            if self.needs_password:
                raise type("SessionPasswordNeededError", (Exception,), {})()
        elif kwargs.get("password") != SECRET_PASSWORD:
            raise type("PasswordHashInvalidError", (Exception,), {})()
        return object()

    async def disconnect(self) -> None:
        self.disconnected = True


@pytest.fixture
def env(monkeypatch, tmp_path):
    from mordred_hermes.extension.telegram.login_flow import LoginFlows

    store = _Store()
    client = _Client(needs_password=True)
    monkeypatch.setattr(api, "_store", lambda: store)
    monkeypatch.setattr(
        api, "_FLOWS", LoginFlows(store, client_factory=lambda *a, **k: client, save_session=lambda c: c.session)
    )
    monkeypatch.setattr(api, "_home", lambda: tmp_path)
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: True
    )

    async def model_ok() -> dict[str, Any]:
        return {"model": "m", "kind": "venice", "private": True, "ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model_ok)
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/mordred")
    return SimpleNamespace(http=TestClient(app), store=store, client=client, tmp=tmp_path)


def _post(env: Any, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    response = env.http.post(f"/api/plugins/mordred{path}", json=body or {})
    assert response.status_code == 200  # Desktop logs non-2xx; failures are ok:false bodies
    return response.json()


def test_login_flow_seals_the_session_and_never_echoes_secrets(env):
    started = _post(
        env, "/telegram/login/start", {"phone": "+81 90 0000 0000", "api_id": "12345", "api_hash": SECRET_HASH}
    )
    assert started["ok"] and started["step"] == "code" and env.store.key
    wrong = _post(env, f"/telegram/login/{started['flow_id']}/code", {"code": "000"})
    assert wrong == {"ok": False, "error": "login_code_invalid"}
    step = _post(env, f"/telegram/login/{started['flow_id']}/code", {"code": SECRET_CODE})
    assert step == {"ok": True, "step": "password"}
    done = _post(env, f"/telegram/login/{started['flow_id']}/password", {"password": SECRET_PASSWORD})
    assert done == {"ok": True, "step": "done"}
    assert env.store.value.session == "SESSION-STRING" and env.store.value.api_hash == SECRET_HASH
    assert env.client.disconnected
    everything = json.dumps([started, wrong, step, done])
    for secret in (SECRET_HASH, SECRET_CODE, SECRET_PASSWORD, "SESSION-STRING"):
        assert secret not in everything
    assert (
        _post(env, f"/telegram/login/{started['flow_id']}/code", {"code": SECRET_CODE})["error"] == "login_flow_expired"
    )


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"phone": "not a phone", "api_id": "1", "api_hash": SECRET_HASH}, "invalid_phone"),
        ({"phone": "+1000000", "api_id": "x", "api_hash": SECRET_HASH}, "invalid_api_credentials"),
        ({"phone": "+1000000", "api_id": "1", "api_hash": "short"}, "invalid_api_credentials"),
    ],
)
def test_login_start_validation_returns_codes_only(env, body, code):
    result = _post(env, "/telegram/login/start", body)
    assert result == {"ok": False, "error": code}


def test_login_requires_memory_encryption(env, monkeypatch):
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: False
    )
    result = _post(env, "/telegram/login/start", {"phone": "+1000000", "api_id": "1", "api_hash": SECRET_HASH})
    assert result == {"ok": False, "error": "memory_encryption_required"}


def _configured(env) -> None:
    env.store.value = secrets.TelegramSecrets(api_id=1, api_hash=SECRET_HASH, store_key=b"k" * 32, session="s")


def test_venice_uses_hermes_key_without_returning_it(env):
    _configured(env)
    (env.tmp / "config.yaml").write_text(
        "model:\n  base_url: https://api.venice.ai/api/v1\n  key_env: HERMES_CUSTOM_API_VENICE_AI_API_KEY\n"
    )
    (env.tmp / ".env").write_text(f"HERMES_CUSTOM_API_VENICE_AI_API_KEY={SECRET_VENICE}\n")
    result = _post(env, "/llm/venice", {"use_hermes_key": True})
    assert result == {"ok": True}
    assert env.store.value.venice_api_key == SECRET_VENICE and env.store.value.backend == "venice"
    status = env.http.get("/api/plugins/mordred/status")
    assert SECRET_VENICE not in status.text


def test_venice_missing_hermes_key_and_manual_key(env):
    _configured(env)
    assert _post(env, "/llm/venice", {"use_hermes_key": True}) == {"ok": False, "error": "hermes_venice_key_missing"}
    assert _post(env, "/llm/venice", {"api_key": SECRET_VENICE, "model": "qwen3-6-27b"}) == {"ok": True}
    assert env.store.value.venice_model == "qwen3-6-27b"
    assert _post(env, "/llm/venice", {"api_key": ""}) == {"ok": False, "error": "invalid_request"}


def test_local_llm_must_be_loopback(env):
    _configured(env)
    assert _post(env, "/llm/local", {"endpoint": "http://10.0.0.5:11434/v1", "model": "m"}) == {
        "ok": False,
        "error": "local_endpoint_invalid",
    }
    ok = _post(env, "/llm/local", {"endpoint": "http://localhost:11434/v1", "model": "qwen3"})
    assert ok == {"ok": True, "endpoint": "http://127.0.0.1:11434/v1"}


def test_memory_enable_returns_a_generated_passphrase_once(env, monkeypatch):
    calls: list[str] = []
    state = {"on": False}

    def fake_enable(name: str):
        def enable(**kwargs: Any) -> int:
            calls.append(name)
            if name == "env":
                kwargs["prompt_io"].ask_password("Choose a vault recovery passphrase")
            state["on"] = name == "memory"
            return 0

        return enable

    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: state["on"]
    )
    monkeypatch.setattr("mordred_hermes.wizard.env_decrypt_cli.enable", fake_enable("env"))
    monkeypatch.setattr("mordred_hermes.wizard.memory_cli.enable", fake_enable("memory"))
    first = _post(env, "/memory/enable")
    assert calls == ["env", "memory"] and first["ok"] and first["restart_required"]
    words = first["recovery_passphrase"].split()
    assert len(words) == 8 and len(set(words)) >= 6
    assert _post(env, "/memory/enable") == {"ok": True, "already": True}


def test_passphrases_are_random():
    assert api.generate_recovery_passphrase() != api.generate_recovery_passphrase()


def test_sync_validates_days(env):
    assert _post(env, "/sync", {"days": 0}) == {"ok": False, "error": "invalid_request"}
    assert _post(env, "/sync", {"days": True}) == {"ok": False, "error": "invalid_request"}


def test_install_writes_folder_and_only_enables_mordred(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("# keep\nplugins:\n  enabled:\n    - mordred_e2e\n  disabled:\n    - mordred_keyvault\n")
    assert install.install(tmp_path) == 0
    folder = tmp_path / "plugins" / "mordred"
    assert (folder / "desktop" / "plugin.js").read_text().startswith("// Mordred setup for Hermes Desktop.")
    assert json.loads((folder / "dashboard" / "manifest.json").read_text())["name"] == "mordred"
    assert "from mordred_hermes.desktop.api import router" in (folder / "dashboard" / "plugin_api.py").read_text()
    assert not (folder / "plugin.yaml").exists()  # agent-plugin scanner must skip it
    text = config.read_text()
    assert "# keep" in text and "mordred_keyvault" in text and "- mordred\n" in text
    assert install.status(tmp_path) == 0
    assert install.uninstall(tmp_path) == 0
    assert not folder.exists() and "- mordred\n" not in config.read_text()


def test_login_refused_until_hermes_itself_uses_a_private_model(env, monkeypatch):
    async def not_private() -> dict[str, Any]:
        return {"model": "gpt", "kind": "other", "private": None, "ok": False}

    monkeypatch.setattr(api, "hermes_model_check", not_private)
    result = _post(env, "/telegram/login/start", {"phone": "+1000000", "api_id": "1", "api_hash": SECRET_HASH})
    assert result == {"ok": False, "error": "hermes_model_not_private"}


def test_question_model_can_be_set_before_telegram_and_survives_login(env):
    assert env.store.value is None
    assert _post(env, "/llm/venice", {"api_key": SECRET_VENICE}) == {"ok": True}
    assert env.store.value.has_api is False and env.store.value.venice_api_key == SECRET_VENICE
    started = _post(env, "/telegram/login/start", {"phone": "+1000000", "api_id": "12345", "api_hash": SECRET_HASH})
    _post(env, f"/telegram/login/{started['flow_id']}/code", {"code": SECRET_CODE})
    _post(env, f"/telegram/login/{started['flow_id']}/password", {"password": SECRET_PASSWORD})
    value = env.store.value
    assert (value.api_id, value.venice_api_key, value.session) == (12345, SECRET_VENICE, "SESSION-STRING")


def test_empty_secrets_roundtrip_and_reject_half_configured():
    empty = secrets.empty_secrets()
    assert secrets.decode(secrets.encode(empty)) == empty and not empty.has_api
    bad = json.loads(secrets.encode(empty))
    bad["session"] = "s"
    with pytest.raises(secrets.TelegramSecretsError):
        secrets.decode(json.dumps(bad).encode())


@pytest.mark.parametrize(
    ("base_url", "model", "catalog", "ok"),
    [
        ("http://127.0.0.1:11434/v1", "qwen3", None, True),
        ("https://api.openai.com/v1", "gpt", None, False),
        ("https://api.venice.ai/api/v1", "e2ee-deepseek-v4-flash", "private", True),
        ("https://api.venice.ai/api/v1", "claude-opus-5", "anonymized", False),
    ],
)
def test_hermes_model_check(monkeypatch, base_url, model, catalog, ok):
    import asyncio

    from mordred_hermes.extension.egress import EgressRoute
    from mordred_hermes.extension.telegram import venice

    api._MODEL_CACHE.clear()
    monkeypatch.setattr("mordred_hermes.extension.telegram.hermes_tools._configured_model", lambda: (model, base_url))
    monkeypatch.setattr("mordred_hermes.extension.egress.resolve_route", lambda _h: EgressRoute(None, None))

    class _Raw:
        async def close(self) -> None:
            return None

    monkeypatch.setattr("mordred_hermes.extension.telegram.service._default_http_session", lambda _r, _t: _Raw())

    async def catalog_check(_session: Any, cfg: Any) -> Any:
        if catalog != "private":
            raise venice.VeniceError("venice_model_not_private")
        return None

    monkeypatch.setattr(venice, "require_private_model", catalog_check)
    assert asyncio.run(api.hermes_model_check())["ok"] is ok
