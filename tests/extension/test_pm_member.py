"""Mordred as a Hermes package-manager member (desktop/member.py) and the shim fallback API."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tomllib
import venv
import zipfile
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from mordred_hermes.desktop import install, member

DIST = metadata.distribution("hermes-mordred")
SHIM = Path(install.__file__).parent / "assets" / "dashboard" / "plugin_api.py"
PTH_SOURCE = Path(__file__).resolve().parents[2] / "packaging" / "pth"
BOOTSTRAPS = ("mordred_hermes_config_decrypt.pth", "mordred_hermes_runtime.pth")


def _dist(pkg: Path, *, editable: bool = False) -> metadata.Distribution:
    """A distribution rooted in this fixture, never the runner's installation."""
    info = pkg.parent / "hermes_mordred.dist-info"
    info.mkdir(exist_ok=True)
    (info / "METADATA").write_text(DIST.read_text("METADATA") or "")
    (info / "entry_points.txt").write_text(DIST.read_text("entry_points.txt") or "")
    (info / "RECORD").write_text("".join(f"{name},,\n" for name in BOOTSTRAPS))
    if editable:
        (info / "direct_url.json").write_text(
            json.dumps({"url": pkg.parent.parent.as_uri(), "dir_info": {"editable": True}})
        )
    return metadata.PathDistribution(info)


def _package(root: Path, body: str = "x = 1\n") -> Path:
    pkg = root / "src" / "mordred_hermes"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "__init__.py").write_text(body)
    (pkg / "sub" / "data.json").write_text("{}")
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "junk.pyc").write_bytes(b"\0")
    for name in BOOTSTRAPS:
        (pkg.parent / name).write_bytes((PTH_SOURCE / name).read_bytes())
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
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg)) is True
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
    for name in BOOTSTRAPS:
        assert (plugin_dir / name).read_bytes() == (PTH_SOURCE / name).read_bytes()
    # Unchanged inputs: no rewrite (a rewrite would force a pm rebuild).
    before = {p: p.stat().st_mtime_ns for p in plugin_dir.rglob("*") if p.is_file()}
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg)) is False
    assert {p: p.stat().st_mtime_ns for p in before} == before


def test_ensure_member_refreshes_changed_and_stale_files(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
    (pkg / "__init__.py").write_text("x = 2\n")
    (pkg / "sub" / "data.json").unlink()
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg)) is True
    assert (plugin_dir / "mordred_hermes" / "__init__.py").read_text() == "x = 2\n"
    assert not (plugin_dir / "mordred_hermes" / "sub" / "data.json").exists()
    # A bootstrap-only change must refresh even when the package tree matches.
    updated = {name: (PTH_SOURCE / name).read_bytes() + b"# updated canonical bootstrap\n" for name in BOOTSTRAPS}
    for name, content in updated.items():
        (pkg.parent / name).write_bytes(content)
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg)) is True
    for name, content in updated.items():
        assert (plugin_dir / name).read_bytes() == content


@pytest.mark.parametrize("editable, name", [(False, BOOTSTRAPS[0]), (True, BOOTSTRAPS[1])])
def test_member_refuses_missing_bootstrap_before_updating_existing_member(
    tmp_path: Path, name: str, editable: bool
) -> None:
    pkg = _package(tmp_path)
    if editable:
        source_pth = pkg.parent.parent / "packaging" / "pth"
        source_pth.mkdir(parents=True)
        for filename in BOOTSTRAPS:
            shutil.copyfile(PTH_SOURCE / filename, source_pth / filename)
    else:
        source_pth = pkg.parent
    dist = _dist(pkg, editable=editable)
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=pkg, dist=dist)
    for filename in BOOTSTRAPS:
        assert (plugin_dir / filename).read_bytes() == (PTH_SOURCE / filename).read_bytes()
    before = {p.relative_to(plugin_dir): p.read_bytes() for p in plugin_dir.rglob("*") if p.is_file()}
    (source_pth / name).unlink()
    (pkg / "__init__.py").write_text("x = 2\n")
    with pytest.raises(OSError, match=name):
        member.ensure_member(plugin_dir, package_root=pkg, dist=dist)
    assert {p.relative_to(plugin_dir): p.read_bytes() for p in plugin_dir.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize(
    "name, damage", [(BOOTSTRAPS[0], "missing"), (BOOTSTRAPS[1], "empty"), (BOOTSTRAPS[0], "unmapped")]
)
def test_member_health_rejects_incomplete_bootstraps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, damage: str
) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
    if damage == "missing":
        (plugin_dir / name).unlink(missing_ok=True)
    elif damage == "empty":
        (plugin_dir / name).write_bytes(b"")
    else:
        project = plugin_dir / "pyproject.toml"
        project.write_text("\n".join(line for line in project.read_text().splitlines() if name not in line))
    assert member.member_status(plugin_dir)["valid"] is False
    client = _client(_load_shim(monkeypatch, plugin_dir))
    assert client.get("/api/plugins/mordred/status").json()["member"]["valid"] is False
    assert client.post("/api/plugins/mordred/repair", json={}).json()["error"] == "member_missing"


def test_built_member_wheel_preserves_and_executes_both_startup_bootstraps(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not available to build and install the member wheel")
    source = tmp_path / "source"
    pkg = source / "site-packages" / "mordred_hermes"
    shutil.copytree(member._package_root(), pkg, ignore=shutil.ignore_patterns("__pycache__"))
    pth_dir = pkg.parent
    pth_dir.mkdir(parents=True, exist_ok=True)
    for name in BOOTSTRAPS:
        shutil.copyfile(PTH_SOURCE / name, pth_dir / name)
    plugin_dir = tmp_path / "home" / "plugins" / "mordred"
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
    # This is the artifact pm builds, not the top-level project wheel.
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "home")}
    env.pop("MORDRED_CONFIG_DECRYPT", None)
    env.pop("PYTHONPATH", None)
    built = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(tmp_path / "dist")],
        cwd=plugin_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    wheel = next((tmp_path / "dist").glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        for name in BOOTSTRAPS:
            assert name in archive.namelist(), f"member wheel dropped startup bootstrap {name}"
            assert archive.read(name) == (PTH_SOURCE / name).read_bytes()
    venv.EnvBuilder(with_pip=False).create(tmp_path / "venv")
    python = tmp_path / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run(
        [uv, "pip", "install", "--offline", "--no-deps", "--python", str(python), str(wheel)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr
    probe = tmp_path / "hermes"
    probe.write_text(
        "import os, sys\n"
        "assert 'mordred_hermes._runtime_bootstrap' in sys.modules\n"
        "assert 'mordred_hermes.keyvault._config_bootstrap' in sys.modules\n"
        "assert 'mordred_hermes.dbcrypt' in sys.modules\n"
        "assert any(type(f).__name__ == '_PostImportFinder' for f in sys.meta_path)\n"
        "import mordred_hermes\n"
        "assert os.path.commonpath([sys.prefix, mordred_hermes.__file__]) == sys.prefix\n"
        "print('member startup guards active')\n"
    )
    started = subprocess.run(
        [str(python), "-I", str(probe)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30
    )
    assert started.returncode == 0, started.stdout + started.stderr
    assert started.stdout.strip() == "member startup guards active"
    assert not started.stderr


def test_ensure_member_keeps_dashboard_files_and_skips_symlinks(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    (plugin_dir / "dashboard").mkdir(parents=True)
    (plugin_dir / "dashboard" / "plugin_api.py").write_text("shim")
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
    assert (plugin_dir / "dashboard" / "plugin_api.py").read_text() == "shim"
    link = tmp_path / "plugins" / "linked"
    link.symlink_to(plugin_dir)
    assert member.ensure_member(link, package_root=pkg, dist=_dist(pkg)) is False


def test_member_status_and_remove(tmp_path: Path) -> None:
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    assert member.member_status(plugin_dir) == {"present": False}
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
    status = member.member_status(plugin_dir)
    assert status["present"] and status["valid"] and status["version"] == DIST.version
    assert status["source"] in {"pypi", "path"}
    (plugin_dir / "dashboard").mkdir()
    assert member.remove_member(plugin_dir) is True
    assert not (plugin_dir / "pyproject.toml").exists() and (plugin_dir / "dashboard").is_dir()
    assert not any((plugin_dir / name).exists() for name in BOOTSTRAPS)


def test_editable_member_refuses_bootstraps_from_an_unrelated_checkout(tmp_path: Path) -> None:
    pkg = _package(tmp_path / "first")
    other = _package(tmp_path / "other")
    pth = other.parent.parent / "packaging" / "pth"
    pth.mkdir(parents=True)
    for name in BOOTSTRAPS:
        shutil.copyfile(PTH_SOURCE / name, pth / name)
    plugin_dir = tmp_path / "plugins" / "mordred"
    with pytest.raises(OSError, match="editable"):
        member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(other, editable=True))
    assert member.member_status(plugin_dir) == {"present": False}


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
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
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
    pkg = _package(tmp_path)
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
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


def test_a_pm_built_install_never_rewrites_the_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import member

    pm_copy = member.InstallSource(
        "0.2.0a0",
        "path",
        "/h/installs/x/environments/abc/workspace/plugin-sources/mordred-7b50b48140f67e3d",
        True,
        (),
    )
    user = member.InstallSource("0.2.0a0", "path", "/Users/me/repos/hermes-mordred", False, ("macos",))
    assert member.built_from_member(pm_copy)
    assert not member.built_from_member(user)
    assert not member.built_from_member(member.InstallSource("0.2.0a0", "pypi", None, False, ("macos",)))
    pkg = _package(tmp_path)
    plugin_dir = tmp_path / "plugins" / "mordred"
    member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg))
    (plugin_dir / BOOTSTRAPS[0]).unlink(missing_ok=True)
    before = {p.relative_to(plugin_dir): p.read_bytes() for p in plugin_dir.rglob("*") if p.is_file()}
    monkeypatch.setattr(member, "install_source", lambda dist: pm_copy)
    for name in BOOTSTRAPS:
        (pkg.parent / name).unlink()
    assert member.ensure_member(plugin_dir, package_root=pkg, dist=_dist(pkg)) is False
    assert {p.relative_to(plugin_dir): p.read_bytes() for p in plugin_dir.rglob("*") if p.is_file()} == before
    assert member.member_status(plugin_dir)["valid"] is False
