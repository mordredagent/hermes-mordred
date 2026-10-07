"""Mordred as a Hermes package-manager member (desktop/member.py) and the shim fallback API."""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mordred_hermes.desktop import install, member

DIST = metadata.distribution("hermes-mordred")
SHIM = Path(install.__file__).parent / "assets" / "dashboard" / "plugin_api.py"


def _package(root: Path, body: str = "x = 1\n") -> Path:
    pkg = root / "pkg" / "mordred_hermes"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "__init__.py").write_text(body)
    (pkg / "sub" / "data.json").write_text("{}")
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "junk.pyc").write_bytes(b"\0")
    return pkg


def test_requirements_drop_hermes_agent_and_expand_self_extras() -> None:
    reqs = member.member_requirements(DIST, ("macos",))
    names = {r.split("[")[0].split(">")[0].split("=")[0].split("<")[0].lower() for r in reqs}
    assert "hermes-agent" not in names and "hermes-mordred" not in names
    assert "ruamel.yaml" in names or "ruamel-yaml" in names  # base requirement
    if sys.platform == "darwin":
        # macos -> hermes-mordred[keyvault] -> argon2-cffi
        assert {"argon2-cffi", "pyobjc-framework-security"} <= names
    assert all(";" not in r for r in reqs)  # markers evaluated for this machine


def test_base_requirements_without_extras() -> None:
    reqs = member.member_requirements(DIST, ())
    assert not any(r.lower().startswith(("argon2", "telethon", "pytest")) for r in reqs)


def test_ensure_member_writes_a_buildable_member_once(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "home" / "plugins" / "mordred"
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=DIST) is True
    data = tomllib.loads((plugin_dir / "pyproject.toml").read_text())
    project = data["project"]
    assert project["name"] == "hermes-mordred" and project["version"] == DIST.version
    assert not any(d.startswith("hermes-agent") for d in project["dependencies"])
    assert project["entry-points"]["hermes_agent.plugins"]["mordred"] == "mordred_hermes.plugin"
    assert project["scripts"]["hermes-mordred"] == "mordred_hermes.wizard.cli:main"
    assert data["build-system"]["build-backend"] == "hatchling.build"
    assert data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["mordred_hermes"]
    assert (plugin_dir / "mordred_hermes" / "sub" / "data.json").is_file()
    assert not (plugin_dir / "mordred_hermes" / "__pycache__").exists()
    assert not (plugin_dir / "plugin.yaml").exists()  # never shadows the entry point
    # The lock lives outside the member folder (pm hashes every byte inside it).
    assert (tmp_path / "home" / "mordred" / ".pm-member.lock").is_file()
    assert not list(plugin_dir.glob(".*"))
    # Unchanged inputs: no rewrite (a rewrite would force a pm rebuild).
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=DIST) is False


def test_ensure_member_refreshes_changed_and_stale_files(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=pkg, dist=DIST)
    (pkg / "__init__.py").write_text("x = 2\n")
    (pkg / "sub" / "data.json").unlink()
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=DIST) is True
    assert (plugin_dir / "mordred_hermes" / "__init__.py").read_text() == "x = 2\n"
    assert not (plugin_dir / "mordred_hermes" / "sub" / "data.json").exists()


def test_ensure_member_keeps_dashboard_files_and_skips_symlinks(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    (plugin_dir / "dashboard").mkdir(parents=True)
    (plugin_dir / "dashboard" / "plugin_api.py").write_text("shim")
    member.ensure_member(plugin_dir, package_root=pkg, dist=DIST)
    assert (plugin_dir / "dashboard" / "plugin_api.py").read_text() == "shim"
    link = tmp_path / "plugins" / "linked"
    link.symlink_to(plugin_dir)
    assert member.ensure_member(link, package_root=pkg, dist=DIST) is False


def test_member_status_and_remove(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    assert member.member_status(plugin_dir) == {"present": False}
    member.ensure_member(plugin_dir, package_root=pkg, dist=DIST)
    status = member.member_status(plugin_dir)
    assert status["present"] and status["valid"] and status["version"] == DIST.version
    assert status["source"] in {"pypi", "path"}
    (plugin_dir / "dashboard").mkdir()
    assert member.remove_member(plugin_dir) is True
    assert not (plugin_dir / "pyproject.toml").exists() and (plugin_dir / "dashboard").is_dir()


def test_install_source_reads_direct_url(tmp_path: Path) -> None:
    source = member.install_source(DIST)
    direct = DIST.read_text("direct_url.json")
    assert source.version == DIST.version
    assert source.kind == ("path" if direct and '"file://' in direct else "pypi")


def test_install_ensure_member_only_on_pm_managed_hermes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(member, "ensure_member", lambda plugin_dir: calls.append(plugin_dir) or True)
    monkeypatch.setattr(member, "pm_managed", lambda: False)
    assert install.ensure_member(tmp_path) is False and calls == []
    monkeypatch.setattr(member, "pm_managed", lambda: True)
    assert install.ensure_member(tmp_path) is True
    assert calls == [tmp_path / "plugins" / "mordred"]


def test_pm_reads_the_member_as_a_workspace_member(tmp_path: Path) -> None:
    """Hermes's own declaration reader accepts the member (needs a Hermes checkout's pm)."""
    declarations = pytest.importorskip("pm.plugin_declarations")
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=pkg, dist=DIST)
    declaration = declarations.read_python_declaration(plugin_dir)
    assert declaration.is_member
    assert not any(r.startswith("hermes-agent") for r in declaration.install_requirements)


# -- the dashboard shim's fallback API ------------------------------------------------------


def _load_shim(monkeypatch: pytest.MonkeyPatch, plugin_dir: Path) -> ModuleType:
    """Load the shim from *plugin_dir*/dashboard as Hermes does, with Mordred absent."""
    pytest.importorskip("fastapi")
    target = plugin_dir / "dashboard" / "plugin_api.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(SHIM.read_bytes())
    monkeypatch.setitem(sys.modules, "mordred_hermes.desktop.api", None)  # import -> ImportError
    spec = importlib.util.spec_from_file_location("hermes_dashboard_plugin_mordred_test", target)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _client(module: ModuleType) -> Any:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(module.router, prefix="/api/plugins/mordred")
    return TestClient(app)


def test_shim_reports_missing_mordred_and_refuses_repair_without_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin_dir = tmp_path / "plugins" / "mordred"
    client = _client(_load_shim(monkeypatch, plugin_dir))
    body = client.get("/api/plugins/mordred/status").json()
    assert body["ok"] is False and body["error"] == "mordred_not_installed" and body["installed"] is False
    assert "mordred_hermes" in body["reason"] and body["member"] == {"present": False}
    assert body["environment"]["python"]
    assert client.post("/api/plugins/mordred/repair", json={}).json()["error"] == "member_missing"


def test_shim_repair_runs_hermes_pm_install_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=_package(tmp_path), dist=DIST)
    module = _load_shim(monkeypatch, plugin_dir)
    seen: list[list[str]] = []

    class _Result:
        returncode = 0
        stdout = "✓ venv\n"
        stderr = ""

    monkeypatch.setattr(module.subprocess, "run", lambda cmd, **kw: seen.append(cmd) or _Result())

    class _Thread:
        def __init__(self, target: Any, **kw: Any) -> None:
            self.target = target

        def start(self) -> None:
            self.target()

    monkeypatch.setattr(module.threading, "Thread", _Thread)
    client = _client(module)
    status = client.get("/api/plugins/mordred/status").json()
    assert status["member"]["valid"] is True and status["member"]["version"] == DIST.version
    assert client.post("/api/plugins/mordred/repair", json={}).json()["ok"] is True
    assert seen == [[sys.executable, "-m", "hermes_cli.main", "pm", "install", "venv"]]
    repair = client.get("/api/plugins/mordred/repair").json()["repair"]
    assert repair["state"] == "done" and repair["code"] == 0 and "venv" in repair["output"]


def test_shim_uses_the_real_router_when_mordred_is_installed() -> None:
    pytest.importorskip("fastapi")
    spec = importlib.util.spec_from_file_location("hermes_dashboard_plugin_mordred_real", SHIM)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from mordred_hermes.desktop import api

    assert module.router is api.router


def test_health_reports_version_environment_and_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from mordred_hermes import __version__
    from mordred_hermes.desktop import api

    monkeypatch.setattr(install, "_home", lambda: tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(api.router)
    body = TestClient(app).get("/health").json()
    assert body["ok"] and body["installed"] and body["version"] == __version__
    assert body["member"] == {"present": False} and body["environment"]["prefix"] == sys.prefix
