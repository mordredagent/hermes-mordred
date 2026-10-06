"""Desktop setup must not offer macOS-only Telegram setup on other hosts."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.desktop import api
from mordred_hermes.wizard import keyvault_native_cli, telegram_setup_cli


@pytest.mark.parametrize("platform", ["linux", "win32", "freebsd14"])
def test_unsupported_status_reports_platform_without_probing_setup(monkeypatch, platform):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported setup must not probe hardware, credentials, or a provider")

    monkeypatch.setattr(telegram_setup_cli, "run_checks", unexpected)
    monkeypatch.setattr(api, "hermes_model_check", unexpected)
    monkeypatch.setattr(api, "_store", unexpected)
    monkeypatch.setattr(api, "_hermes_venice_key", unexpected)

    result = asyncio.run(api.status())

    assert result["ok"] is True
    assert result["platform"] == platform
    assert result["telegram_supported"] is False
    assert result["checks"] == {}


def test_macos_status_keeps_setup_progress(monkeypatch):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(
        telegram_setup_cli,
        "run_checks",
        lambda: [telegram_setup_cli.Check("secure_enclave", True, "helper ready")],
    )

    async def model():
        return {"ok": True, "kind": "local", "model": "local-test"}

    monkeypatch.setattr(api, "hermes_model_check", model)
    monkeypatch.setattr(api, "_store", lambda: SimpleNamespace(flags=lambda: {"api_configured": True}))
    monkeypatch.setattr(api, "_hermes_venice_key", lambda: None)

    result = asyncio.run(api.status())

    assert result["platform"] == "darwin"
    assert result["telegram_supported"] is True
    assert result["checks"]["secure_enclave"] == {"ok": True, "detail": "helper ready"}
    assert result["hermes_model"]["ok"] is True
    assert result["telegram_api"] is True


@pytest.mark.parametrize("platform", ["linux", "win32", "freebsd14"])
@pytest.mark.parametrize("handler", [api.enclave_build, api.memory_enable])
def test_unsupported_setup_refuses_before_starting_work(monkeypatch, platform, handler):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform=platform))

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported setup must not start a build or access the vault")

    monkeypatch.setattr(api, "_start_job", unexpected)
    monkeypatch.setattr(api, "generate_recovery_passphrase", unexpected)
    monkeypatch.setattr("mordred_hermes.extension.telegram.memory_guard.memory_encryption_active", unexpected)

    response = asyncio.run(handler())

    assert response.status_code == 200
    assert json.loads(response.body) == {"ok": False, "error": "telegram_platform_unsupported"}


@pytest.mark.parametrize("return_code, state, error", [(0, "done", None), (1, "failed", "enclave_build_failed")])
def test_macos_enclave_build_still_reports_job_result(monkeypatch, return_code, state, error):
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(api, "_JOBS", {})
    monkeypatch.setattr(api, "_emit", lambda *args: None)
    # The hardware builder is the only platform-dependent operation here.
    monkeypatch.setattr(keyvault_native_cli, "enable_se", lambda: return_code)

    async def run():
        started = await api.enclave_build()
        async with asyncio.timeout(5):
            while api._JOBS[started["job_id"]].state == "running":
                await asyncio.sleep(0.01)
        return await api.job_status(started["job_id"])

    result = asyncio.run(run())

    assert result["state"] == state
    assert result["error"] == error
