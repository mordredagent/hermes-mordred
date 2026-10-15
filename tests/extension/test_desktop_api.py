"""Mordred setup API for Hermes Desktop (desktop/api.py) and its installer."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from mordred_hermes._private_fs import open_private_directory  # noqa: E402
from mordred_hermes.desktop import api, install  # noqa: E402
from mordred_hermes.extension.telegram import secrets  # noqa: E402
from tests._private_files import write_private  # noqa: E402

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
    home = tmp_path / "hermes-home"
    with open_private_directory(home, create=True):
        pass
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(api, "_store", lambda: store)
    monkeypatch.setattr(
        api, "_FLOWS", LoginFlows(store, client_factory=lambda *a, **k: client, save_session=lambda c: c.session)
    )
    monkeypatch.setattr(api, "_home", lambda: home)
    monkeypatch.setattr(api, "_JOBS", {})
    monkeypatch.setattr(
        "mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", lambda home=None: True
    )

    async def model_ok() -> dict[str, Any]:
        return {"model": "m", "kind": "venice", "private": True, "ok": True}

    monkeypatch.setattr(api, "hermes_model_check", model_ok)
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/mordred")
    # Background jobs must share a persistent event loop across requests.
    with TestClient(app) as http:
        yield SimpleNamespace(http=http, store=store, client=client, tmp=home)


@pytest.fixture
def posix_install(monkeypatch, tmp_path):
    """Legacy recursive-removal contract; real Windows placement has its own tests."""
    home = tmp_path / "hermes-home"
    with open_private_directory(home, create=True):
        pass
    monkeypatch.setattr(install, "_platform", lambda: "darwin")
    return home


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
    write_private(
        env.tmp / "config.yaml",
        b"model:\n  base_url: https://api.venice.ai/api/v1\n  key_env: HERMES_CUSTOM_API_VENICE_AI_API_KEY\n",
    )
    write_private(env.tmp / ".env", f"HERMES_CUSTOM_API_VENICE_AI_API_KEY={SECRET_VENICE}\n".encode())
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
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
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


def test_install_writes_folder_and_enables_the_single_mordred_plugin(posix_install):
    tmp_path = posix_install
    config = tmp_path / "config.yaml"
    write_private(
        config,
        b"# keep\nplugins:\n  enabled:\n    - other\n    - mordred_e2e\n  disabled:\n    - mordred_keyvault\n",
    )
    assert install.install(tmp_path) == 0
    folder = tmp_path / "plugins" / "mordred"
    page = tmp_path / "desktop-plugins" / "mordred" / "plugin.js"
    # The page goes through Hermes Desktop's disk door, which loads it enabled.
    assert page.read_text(encoding="utf-8").startswith("// Mordred setup for Hermes Desktop.")
    assert not (folder / "desktop").exists()
    assert json.loads((folder / "dashboard" / "manifest.json").read_text(encoding="utf-8"))["name"] == "mordred"
    assert "from mordred_hermes.desktop.api import router" in (folder / "dashboard" / "plugin_api.py").read_text(
        encoding="utf-8"
    )
    # No plugin.yaml: the folder must not become a directory plugin that
    # shadows the `mordred` entry point (Hermes prefers a directory plugin).
    assert not (folder / "plugin.yaml").exists()
    text = config.read_text(encoding="utf-8")
    # Legacy per-component names are migrated to the single plugin; other entries survive.
    assert "# keep" in text and "- other\n" in text and "- mordred\n" in text
    assert "mordred_e2e" not in text and "mordred_keyvault" not in text
    assert install.status(tmp_path) == 0
    assert install.uninstall(tmp_path) == 0
    # The page goes; the plugin (every Mordred protection) stays enabled.
    assert not folder.exists() and not page.parent.exists() and "- mordred\n" in config.read_text(encoding="utf-8")


def test_ensure_page_is_idempotent_and_drops_the_legacy_desktop_half(posix_install):
    tmp_path = posix_install
    legacy = tmp_path / "plugins" / "mordred" / "desktop"
    legacy.mkdir(parents=True)
    (legacy / "plugin.js").write_text("old", encoding="utf-8")
    assert install.ensure_page(tmp_path) is True
    assert not legacy.exists()
    assert (tmp_path / "desktop-plugins" / "mordred" / "plugin.js").is_file()
    assert install.ensure_page(tmp_path) is False  # nothing to rewrite
    assert not (tmp_path / "config.yaml").exists()  # never touches config


def test_plugin_register_places_the_page(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(install, "ensure_page", lambda home=None: calls.append(home) or True)
    from mordred_hermes import plugin

    class _Ctx:
        def register_hook(self, *a, **k):
            pass

        def __getattr__(self, name):
            return lambda *a, **k: None

    monkeypatch.setattr(plugin, "COMPONENTS", ())
    plugin.register(_Ctx())
    assert calls == [None]


def test_install_creates_a_missing_config(posix_install):
    tmp_path = posix_install
    assert install.install(tmp_path) == 0
    assert "- mordred\n" in (tmp_path / "config.yaml").read_text(encoding="utf-8")


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


def test_uninstall_plan_and_run_as_a_job(env, monkeypatch):
    import time as _time

    from mordred_hermes.wizard import uninstall_cli

    calls = []

    def fake_run(ctx, opts):
        calls.append((opts, ctx.prompt_io.ask_bool("?", False) if ctx.prompt_io else None, ctx.interactive))
        print("plan text" if opts.dry_run else "Done.")
        return 0

    monkeypatch.setattr(uninstall_cli, "run_uninstall", fake_run)
    plan = env.http.get("/api/plugins/mordred/uninstall/plan").json()
    assert plan["ok"] and all("plan text" in plan[k] for k in ("plan", "plan_purge", "plan_erase"))
    # Erasing without decrypting deletes data: it needs the typed phrase too.
    assert _post(env, "/uninstall", {"mode": "erase"}) == {"ok": False, "error": "uninstall_confirm_mismatch"}

    # Purging requires the exact typed phrase; nothing runs otherwise.
    assert _post(env, "/uninstall", {"purge_data": True, "confirm": "yes"}) == {
        "ok": False,
        "error": "uninstall_confirm_mismatch",
    }
    started = _post(env, "/uninstall", {"purge_data": True, "confirm": uninstall_cli.PURGE_PHRASE})
    assert started["ok"] and started["kind"] == "uninstall"
    for _ in range(50):
        job = env.http.get(f"/api/plugins/mordred/jobs/{started['job_id']}").json()
        if job["state"] != "running":
            break
        _time.sleep(0.05)
    assert job["state"] == "done" and "Done." in job["progress"]["summary"]
    opts, confirmed, interactive = calls[-1]
    assert opts.yes and opts.purge_data and not opts.dry_run and confirmed and interactive is False


def test_uninstall_answers_give_the_phrase_and_passphrase_only():
    answers = api._UninstallAnswers("recovery words", "delete my data")
    assert answers.ask_text("Type it") == "delete my data"
    assert answers.ask_password("Vault recovery passphrase") == "recovery words"
    assert answers.ask_bool("Uninstall?", False) is True


def test_uninstall_erase_mode_runs_with_erase_options(env, monkeypatch):
    import time as _time

    from mordred_hermes.wizard import uninstall_cli

    seen = []
    monkeypatch.setattr(uninstall_cli, "run_uninstall", lambda ctx, opts: seen.append(opts) or 0)
    started = _post(env, "/uninstall", {"mode": "erase", "confirm": uninstall_cli.PURGE_PHRASE})
    for _ in range(50):
        if env.http.get(f"/api/plugins/mordred/jobs/{started['job_id']}").json()["state"] != "running":
            break
        _time.sleep(0.05)
    assert seen and seen[-1].erase_encrypted and seen[-1].purge_data and seen[-1].yes


# -- package updates ------------------------------------------------------------------------


def _wait_job(env: Any, job_id: str) -> dict[str, Any]:
    import time as _time

    for _ in range(100):
        job = env.http.get(f"/api/plugins/mordred/jobs/{job_id}").json()
        if job["state"] != "running":
            return job
        _time.sleep(0.02)
    raise AssertionError("job never finished")


@pytest.fixture
def update_core(monkeypatch):
    """A fake installed Mordred and a recording ``_self_update`` seam."""
    from pathlib import Path

    from mordred_hermes import _self_update as core

    state = SimpleNamespace(
        installed=core.Installed("0.2.0a1", "pypi", None, False, ("macos",), False, "/env/bin/python3", True),
        refusal=None,
        cached=core.CheckResult("0.2.0a1", "0.2.0a3", True, "cache", 1_800_000_000.0),
        fresh=core.CheckResult("0.2.0a1", "0.2.0a4", True, "pypi", 1_800_000_100.0),
        apply_calls=[],
        apply_error=None,
        written=[],
        refresh_calls=0,
    )

    def refuse(current, uv, platform=None):
        if state.refusal is not None:
            raise state.refusal

    def check(**kw):
        state.refresh_calls += 1
        if isinstance(state.fresh, Exception):
            raise state.fresh
        return state.fresh

    def apply(target, **kw):
        state.apply_calls.append((target, kw))
        if state.apply_error is not None:
            raise state.apply_error
        return core.UpdateReport("0.2.0a1", target, ("macos",), steps=["freeze"], warnings=["w1"], member_recorded=True)

    monkeypatch.setattr(core, "installed", lambda home=None: state.installed)
    monkeypatch.setattr(core, "find_uv", lambda home=None, env=None: Path("/opt/uv"))
    monkeypatch.setattr(core, "refuse_if_unsupported", refuse)
    monkeypatch.setattr(core, "cached_check", lambda home=None, **kw: state.cached)
    monkeypatch.setattr(core, "hermes_receipt_check", lambda home=None, **kw: None)
    monkeypatch.setattr(core, "read_cache", lambda home=None, **kw: state.cached)
    monkeypatch.setattr(core, "check", check)
    monkeypatch.setattr(core, "write_cache", lambda result, home=None: state.written.append(result))
    monkeypatch.setattr(core, "apply", apply)
    return state


def test_update_check_reuses_cached_answer_and_refresh_asks_pypi(env, update_core):
    from mordred_hermes import __version__

    update_core.installed = update_core.installed.__class__(
        __version__, "pypi", None, False, ("macos",), False, "/env/bin/python3", True
    )
    res = env.http.get("/api/plugins/mordred/update/check").json()
    assert res["ok"] and res["supported"] is True and res["refusal"] is None
    assert res["running"] == __version__ and res["installed"] == __version__ and res["restart_required"] is False
    assert res["check"]["latest"] == "0.2.0a3" and res["check"]["source"] == "cache"
    assert update_core.refresh_calls == 0

    res = env.http.get("/api/plugins/mordred/update/check?refresh=1").json()
    assert res["check"]["latest"] == "0.2.0a4" and res["check"]["source"] == "pypi"
    assert update_core.refresh_calls == 1 and [w.latest for w in update_core.written] == ["0.2.0a4"]


def test_update_check_reports_restart_required_from_versions_on_disk(env, update_core):
    from mordred_hermes import __version__

    # On disk (dist-info) a newer version than the one this process imported.
    update_core.installed = update_core.installed.__class__(
        "9.9.9", "pypi", None, False, ("macos",), False, "/env/bin/python3", True
    )
    res = env.http.get("/api/plugins/mordred/update/check").json()
    assert res["installed"] == "9.9.9" and res["running"] == __version__
    assert res["restart_required"] is True


def test_update_check_reports_nothing_known_and_refusals(env, update_core):
    from mordred_hermes import _self_update as core

    update_core.cached = None
    update_core.refusal = core.UpdateRefused("windows", "no in-place updates on Windows")
    res = env.http.get("/api/plugins/mordred/update/check").json()
    assert res["ok"] and res["check"] is None
    assert res["supported"] is False and res["refusal"]["code"] == "update_unsupported_windows"
    assert "Windows" in res["refusal"]["message"]


def test_update_check_refresh_failure_keeps_the_cached_answer(env, update_core):
    from mordred_hermes import _self_update as core

    update_core.fresh = core.UpdateCheckFailed("offline")
    res = env.http.get("/api/plugins/mordred/update/check?refresh=1").json()
    # The page keeps the last valid answer and is told the manual check failed.
    assert res["ok"] and res["check"]["latest"] == "0.2.0a3" and res["check"]["source"] == "cache"
    assert res["check_error"].startswith("check failed")
    assert update_core.written == []  # a failed manual check never overwrites a valid answer
    # ... unless that answer is for another version, or itself a failure.
    update_core.cached = core.CheckResult("0.1.0a20", "0.2.0a3", True, "cache", 1.0)
    res = env.http.get("/api/plugins/mordred/update/check?refresh=1").json()
    assert res["check"] is None and res["check_error"].startswith("check failed")


def test_update_check_route_survives_a_broken_core(env, update_core, monkeypatch):
    from mordred_hermes import _self_update as core

    def boom(home=None, **kw):
        raise RuntimeError("metadata exploded")

    monkeypatch.setattr(core, "cached_check", boom)
    assert env.http.get("/api/plugins/mordred/update/check").json() == {"ok": False, "error": "update_check_failed"}


def test_update_check_with_unreadable_metadata_is_unsupported_not_fatal(env, update_core, monkeypatch):
    from mordred_hermes import _self_update as core

    def boom(home=None):
        raise RuntimeError("no dist-info")

    monkeypatch.setattr(core, "installed", boom)
    res = env.http.get("/api/plugins/mordred/update/check").json()
    assert res["ok"] and res["supported"] is False and res["check"] is None
    assert res["refusal"]["code"] == "update_refused" and "installed" not in res


def test_update_apply_runs_as_a_job_and_reports(env, update_core, monkeypatch):
    import threading

    from mordred_hermes import _self_update as core

    gate = threading.Event()
    real_apply = core.apply

    def gated_apply(target, **kw):
        gate.wait(5)
        return real_apply(target, **kw)

    monkeypatch.setattr(core, "apply", gated_apply)
    assert _post(env, "/update/apply", {}) == {"ok": False, "error": "invalid_request"}
    started = _post(env, "/update/apply", {"version": " 0.2.0a3 "})
    assert started["ok"] and started["kind"] == "update"
    again = _post(env, "/update/apply", {"version": "0.2.0a3"})
    assert again["job_id"] == started["job_id"]  # one update at a time
    gate.set()
    job = _wait_job(env, started["job_id"])
    assert job["state"] == "done"
    assert job["progress"]["report"]["target"] == "0.2.0a3" and job["progress"]["report"]["warnings"] == ["w1"]
    ((target, kw),) = update_core.apply_calls
    assert target == "0.2.0a3" and kw["current"] is update_core.installed and kw["uv"] == Path("/opt/uv")
    assert kw["home"] == env.tmp


def test_update_apply_refuses_before_starting_a_job(env, update_core):
    from mordred_hermes import _self_update as core

    assert _post(env, "/update/apply", {"version": "latest"}) == {"ok": False, "error": "update_bad_version"}
    assert _post(env, "/update/apply", {"version": "0.2.0a1"}) == {"ok": False, "error": "update_not_newer"}
    assert _post(env, "/update/apply", {"version": "0.1.0a20"}) == {"ok": False, "error": "update_not_newer"}
    update_core.refusal = core.UpdateRefused("source-install", "from a checkout")
    assert _post(env, "/update/apply", {"version": "0.2.0a3"}) == {"ok": False, "error": "update_source_install"}
    assert update_core.apply_calls == []


def test_update_and_uninstall_exclude_each_other(env, update_core, monkeypatch):
    import threading

    from mordred_hermes.wizard import uninstall_cli

    gate = threading.Event()

    def slow_apply(target, **kw):
        gate.wait(5)
        from mordred_hermes import _self_update as core

        return core.UpdateReport("0.2.0a1", target, ())

    monkeypatch.setattr("mordred_hermes._self_update.apply", slow_apply)
    monkeypatch.setattr(uninstall_cli, "run_uninstall", lambda ctx, opts: 0)
    started = _post(env, "/update/apply", {"version": "0.2.0a3"})
    assert started["ok"]
    assert _post(env, "/uninstall", {}) == {"ok": False, "error": "uninstall_busy"}
    gate.set()
    assert _wait_job(env, started["job_id"])["state"] == "done"
    # and the other way round
    gate.clear()

    def slow_uninstall(ctx, opts):
        gate.wait(5)
        return 0

    monkeypatch.setattr(uninstall_cli, "run_uninstall", slow_uninstall)
    removing = _post(env, "/uninstall", {})
    assert removing["ok"]
    assert _post(env, "/update/apply", {"version": "0.2.0a3"}) == {"ok": False, "error": "update_busy"}
    gate.set()
    assert _wait_job(env, removing["job_id"])["state"] == "done"


def test_update_apply_failure_carries_the_step_output(env, update_core):
    from mordred_hermes import _self_update as core

    update_core.apply_error = core.UpdateFailed("install-package", "resolver said no")
    started = _post(env, "/update/apply", {"version": "0.2.0a3"})
    job = _wait_job(env, started["job_id"])
    assert job["state"] == "failed" and job["error"] == "update_failed"
    assert job["progress"] == {
        "target": "0.2.0a3",
        "step": "install-package",
        "output": "resolver said no",
        "rolled_back": None,
        "rollback_output": "",
    }


def test_update_apply_failed_rollback_has_its_own_code(env, update_core):
    from mordred_hermes import _self_update as core

    update_core.apply_error = core.UpdateFailed("install-requirements", "no", rolled_back=False, rollback_output="rb")
    started = _post(env, "/update/apply", {"version": "0.2.0a3"})
    job = _wait_job(env, started["job_id"])
    assert job["state"] == "failed" and job["error"] == "update_rollback_failed"
    assert job["progress"]["rolled_back"] is False and job["progress"]["rollback_output"] == "rb"


def test_update_apply_refusal_inside_the_job_is_reported(env, update_core):
    from mordred_hermes import _self_update as core

    update_core.apply_error = core.UpdateRefused("no-uv", "uv vanished")
    started = _post(env, "/update/apply", {"version": "0.2.0a3"})
    job = _wait_job(env, started["job_id"])
    assert job["state"] == "failed" and job["error"] == "update_no_uv"
    assert job["progress"] == {"target": "0.2.0a3", "refusal": "uv vanished", "rolled_back": None}


def test_update_apply_hermes_floor_refusal_reports_a_failed_rollback(env, update_core):
    from mordred_hermes import _self_update as core

    update_core.apply_error = core.UpdateRefused(
        "hermes-too-old", "needs Hermes 0.30 (restoring FAILED)", rolled_back=False
    )
    started = _post(env, "/update/apply", {"version": "0.2.0a3"})
    job = _wait_job(env, started["job_id"])
    assert job["state"] == "failed" and job["error"] == "update_rollback_failed"
    update_core.apply_error = core.UpdateRefused("hermes-too-old", "needs Hermes 0.30 (restored)", rolled_back=True)
    started = _post(env, "/update/apply", {"version": "0.2.0a3"})
    assert _wait_job(env, started["job_id"])["error"] == "update_hermes_too_old"
