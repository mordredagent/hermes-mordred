"""Windows refuses unported package-manager profile I/O and automatic repair."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes.desktop import install, member


class NoProfileIOPath(type(Path())):
    """A profile path whose first filesystem operation exposes a missing gate."""

    def __getattribute__(self, name):
        if name in {
            "is_file",
            "is_dir",
            "is_symlink",
            "exists",
            "resolve",
            "mkdir",
            "read_text",
            "read_bytes",
            "write_text",
            "write_bytes",
            "unlink",
            "rename",
            "replace",
            "stat",
            "lstat",
            "open",
        }:
            raise AssertionError(f"unsupported Windows member reached filesystem operation: {name}")
        return super().__getattribute__(name)


@pytest.mark.parametrize("operation", [member.ensure_member, member.remove_member])
def test_windows_member_mutations_refuse_before_profile_io(monkeypatch, operation):
    monkeypatch.setattr(member, "_platform", lambda: "win32", raising=False)
    with pytest.raises(NotImplementedError, match="Windows"):
        operation(NoProfileIOPath("unsafe-profile/plugins/mordred"))


def test_windows_member_status_reports_unsupported_without_inspecting_profile(monkeypatch):
    monkeypatch.setattr(member, "_platform", lambda: "win32", raising=False)
    result = member.member_status(NoProfileIOPath("unsafe-profile/plugins/mordred"))
    assert result["supported"] is False and result["present"] is None and result["valid"] is False
    assert result["reason"] == "not-ported-on-windows"
    assert "Windows installer" in result["remedy"] and "existing Hermes home" in result["remedy"]


@pytest.mark.parametrize("force", [False, True])
def test_windows_startup_does_not_discover_or_create_a_member(monkeypatch, force):
    monkeypatch.setattr(install, "_platform", lambda: "win32")

    def forbidden():
        pytest.fail("unsupported Windows member reached home or package-manager discovery")

    monkeypatch.setattr(install, "_home", forbidden)
    monkeypatch.setattr(member, "pm_managed", forbidden)
    assert install.ensure_member(force=force) is False


def load_fallback(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    shim = Path(install.__file__).parent / "assets" / "dashboard" / "plugin_api.py"
    monkeypatch.setitem(sys.modules, "mordred_hermes.desktop.api", None)
    spec = importlib.util.spec_from_file_location("windows_pm_fallback_test", shim)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="win32", prefix=sys.prefix, version=sys.version))
    monkeypatch.setattr(module, "_MEMBER", NoProfileIOPath(tmp_path / "plugins" / "mordred"))
    return module


def test_windows_fallback_reports_platform_and_unsupported_member_without_profile_io(monkeypatch, tmp_path):
    module = load_fallback(monkeypatch, tmp_path)
    result = asyncio.run(module.status())
    assert result["error"] == "mordred_not_installed"
    assert result["environment"]["platform"] == "win32"
    assert result["member"]["supported"] is False and result["member"]["present"] is None
    assert result["member"]["reason"] == "not-ported-on-windows"


def test_windows_fallback_refuses_repair_even_with_valid_member(monkeypatch, tmp_path):
    module = load_fallback(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_member", lambda: {"present": True, "valid": True})
    starts = []

    class Thread:
        def __init__(self, target, **kwargs):
            pass

        def start(self):
            starts.append(True)

    monkeypatch.setattr(module.threading, "Thread", Thread)
    result = asyncio.run(module.repair())
    assert result["ok"] is False and result["error"] == "pm_repair_unsupported"
    assert "Windows installer" in result["remedy"]
    assert starts == [], "unsupported repair never starts a native subprocess worker"
    observed = asyncio.run(module.repair_status())
    assert observed["ok"] is False and observed["error"] == "pm_repair_unsupported"
    assert observed["repair"]["state"] == "idle"


def test_windows_health_exposes_update_survival_limitation(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from mordred_hermes.desktop import api

    monkeypatch.setattr(member, "_platform", lambda: "win32", raising=False)
    monkeypatch.setattr(install, "plugin_dir", lambda: NoProfileIOPath(tmp_path / "plugins" / "mordred"))
    result = asyncio.run(api.health())
    assert result["ok"] is True and result["installed"] is True
    assert result["environment"]["platform"] == "win32"
    assert result["member"]["supported"] is False
