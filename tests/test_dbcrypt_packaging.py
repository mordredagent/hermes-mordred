"""Build artifacts, checked target selection and offline trusted-header admission."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from tests._checked_fixture_helpers import seed_private_directory

ROOT = Path(__file__).resolve().parents[1]
UV = shutil.which("uv") or str(Path(sys.executable).with_name("uv.exe" if os.name == "nt" else "uv"))


def private_receipt_root(path: Path) -> Path:
    # A plain mkdir by an elevated Windows token is Administrators-owned, which
    # the hook refuses; the checked creator yields the user-owned private root.
    seed_private_directory(path)
    return path


def load(path, name):
    assert path.is_file(), f"missing build interface: {path.name}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dbcrypt_extra_includes_driver_and_preserves_macos_frameworks():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    extras = project["optional-dependencies"]
    assert extras.get("dbcrypt", [])[:2] == ["hermes-mordred[keyvault]", "sqlcipher3-wheels>=0.5.4"]
    pin = Requirement(extras["dbcrypt"][2])
    assert pin.name == "sqlcipher3-wheels" and str(pin.specifier) == "==0.5.7"
    assert pin.marker.evaluate({"sys_platform": "win32"})
    assert not pin.marker.evaluate({"sys_platform": "linux"})
    assert not pin.marker.evaluate({"sys_platform": "darwin"})
    assert "hermes-mordred[dbcrypt]" in extras["macos"]
    assert {
        "pyobjc-framework-Security>=10.0",
        "pyobjc-framework-SystemConfiguration>=10.0",
        "pyobjc-framework-Quartz>=10.0",
    } <= set(extras["macos"])


def hook():
    return load(ROOT / "hatch_build.py", "dbcrypt_hatch_build")


def test_non_windows_build_retains_pure_wheel(tmp_path, monkeypatch):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "linux")
    data = {"pure_python": True}
    module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path), "wheel").initialize("standard", data)
    assert data == {"pure_python": True}


@pytest.mark.parametrize("machine", ["ARM64", "x86", "unknown"])
def test_windows_unsupported_architecture_refuses(tmp_path, monkeypatch, machine):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: machine)
    with pytest.raises(RuntimeError, match="x64"):
        module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path), "wheel").initialize("standard", {})


def test_windows_build_requires_verified_headers(tmp_path, monkeypatch):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")
    monkeypatch.delenv("MORDRED_SQLITE_INCLUDE_DIR", raising=False)
    with pytest.raises(RuntimeError, match="MORDRED_SQLITE_INCLUDE_DIR"):
        module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path), "wheel").initialize("standard", {})


def test_windows_build_selects_checked_and_packages_only_production_asset(tmp_path, monkeypatch):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")
    monkeypatch.setenv("MORDRED_SQLITE_INCLUDE_DIR", str(tmp_path))
    for name in ("sqlite3.h", "sqlite3ext.h"):
        (tmp_path / name).write_bytes(b"controlled header bytes")
    monkeypatch.setattr(module, "validate_headers", lambda path: None)  # Actual bytes checked separately.
    commands = []

    def compiler(command, **kwargs):
        commands.append(command)
        directory = Path(command[command.index("-OutputDirectory") + 1])
        directory.mkdir(parents=True, exist_ok=True)
        image = bytearray(256)
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 0x3C, 0x80)
        image[0x80:0x86] = b"PE\0\0\x64\x86"
        (directory / "mordred_dbcrypt_checked.dll").write_bytes(image)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module.subprocess, "run", compiler)
    data = {}
    module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path), "wheel").initialize("standard", data)
    assert commands[0][commands[0].index("-Target") + 1] == "Checked"
    assert data["pure_python"] is False and data["tag"] == "py3-none-win_amd64"
    assert list(data["force_include"].values()) == ["mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"]
    assert Path(next(iter(data["force_include"]))).read_bytes()[0x80:0x86] == b"PE\0\0\x64\x86"


@pytest.mark.parametrize("version", ["editable", "standard"])
def test_opt_in_hook_retains_actual_compiler_receipt_before_staging_cleanup(tmp_path, monkeypatch, version):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")
    headers = tmp_path / "headers"
    headers.mkdir()
    for name in ("sqlite3.h", "sqlite3ext.h"):
        (headers / name).write_bytes(b"controlled header")
    monkeypatch.setattr(module, "validate_headers", lambda path: None)
    monkeypatch.setenv("MORDRED_SQLITE_INCLUDE_DIR", str(headers))
    receipts = tmp_path / "receipts"
    private_receipt_root(receipts)
    monkeypatch.setenv("MORDRED_DBCRYPT_BUILD_RECEIPT_DIR", str(receipts))

    def compiler(argv, **kwargs):
        output = Path(argv[argv.index("-OutputDirectory") + 1])
        image = bytearray(256)
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 0x3C, 0x80)
        image[0x80:0x86] = b"PE\0\0\x64\x86"
        image[-len(version) :] = version.encode()
        (output / "mordred_dbcrypt_checked.dll").write_bytes(image)
        return subprocess.CompletedProcess(argv, 0, b"actual controlled compiler stdout\n", b"")

    monkeypatch.setattr(module.subprocess, "run", compiler)
    monkeypatch.setattr(module, "_capture_compiler", compiler, raising=False)
    data = {}
    module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path / version), "wheel").initialize(version, data)
    paths = list(receipts.glob("*/receipt.json"))
    assert len(paths) == 1, "opt-in build must retain its actual compiler receipt"
    receipt = json.loads(paths[0].read_text())
    assert receipt["status"] == "succeeded" and receipt["version"] == version
    argv = receipt["argv"]
    assert len(argv) == 13 and argv[:6] == [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]
    assert argv[-2:] == ["-Target", "Checked"]
    assert not Path(argv[8]).exists(), "original compiler staging must still be removed"
    assert (paths[0].parent / receipt["stdout"]["path"]).read_bytes() == b"actual controlled compiler stdout\n"
    assert (paths[0].parent / receipt["dll"]["path"]).read_bytes() == Path(
        next(iter(data["force_include"]))
    ).read_bytes()
    assert "hatch_build.py" in receipt["inputs"]


@pytest.mark.parametrize("failure", ["exit", "overflow", "timeout"])
def test_captured_compiler_failure_retains_failed_receipt_without_package_tag(tmp_path, monkeypatch, failure):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")
    headers = tmp_path / "headers"
    headers.mkdir()
    for name in ("sqlite3.h", "sqlite3ext.h"):
        (headers / name).write_bytes(b"controlled header")
    receipts = tmp_path / "receipts"
    private_receipt_root(receipts)
    monkeypatch.setenv("MORDRED_SQLITE_INCLUDE_DIR", str(headers))
    monkeypatch.setenv("MORDRED_DBCRYPT_BUILD_RECEIPT_DIR", str(receipts))
    monkeypatch.setattr(module, "validate_headers", lambda path: None)

    def compiler(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            -2 if failure == "timeout" else 1 if failure == "exit" else 0,
            b"x" * (module.COMPILER_LIMIT + 1) if failure == "overflow" else b"failure",
            b"",
        )

    monkeypatch.setattr(module, "_capture_compiler", compiler)
    data = {}
    with pytest.raises(RuntimeError, match="captured compiler failed"):
        module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path / "wheel"), "wheel").initialize("standard", data)
    path = next(receipts.glob("*/receipt.json"))
    receipt = json.loads(path.read_text())
    assert receipt["status"] == "failed" and "dll" not in receipt and "tag" not in data and "force_include" not in data
    assert (path.parent / receipt["stdout"]["path"]).stat().st_size <= module.COMPILER_LIMIT


@pytest.mark.parametrize("unsafe", ["relative", "checkout", "link", "existing-child"])
def test_build_receipt_output_rejects_unsafe_or_duplicate_paths(tmp_path, monkeypatch, unsafe):
    from types import SimpleNamespace

    module = hook()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    output = tmp_path / "receipts"
    private_receipt_root(output)
    if unsafe == "relative":
        output = Path("relative")
    elif unsafe == "checkout":
        output = checkout
    elif unsafe == "link":
        linked = tmp_path / "linked"
        linked.symlink_to(output, target_is_directory=True)
        output = linked
    else:
        monkeypatch.setattr(module.uuid, "uuid4", lambda: SimpleNamespace(hex="same"))
        (output / "hook-same").mkdir()
    with pytest.raises((RuntimeError, FileExistsError)):
        module._receipt_directory(output, checkout)


def test_header_validation_rejects_arbitrary_caller_headers(tmp_path):
    module = load(ROOT / "tools/dbcrypt_build_headers.py", "dbcrypt_build_headers")
    for name in ("sqlite3.h", "sqlite3ext.h"):
        (tmp_path / name).write_bytes(b"untrusted headers")
    with pytest.raises(RuntimeError, match="digest"):
        module.validate_headers(tmp_path)


def test_packaged_vfs_locator_never_depends_on_checkout_or_env(tmp_path, monkeypatch):
    from mordred_hermes.dbcrypt import _windows_vfs

    monkeypatch.setenv("MORDRED_DBCRYPT_CHECKED_LIBRARY", str(tmp_path / "probe.dll"))
    assert callable(getattr(_windows_vfs, "packaged_library_path", None)), "owned wheel locator is missing"
    path = _windows_vfs.packaged_library_path()
    if os.name == "nt":
        assert path is not None and path.name == "mordred_dbcrypt_vfs.dll"
        assert path.parent.parts[-2:] == ("_native", "dbcrypt-vfs")
        assert not path.is_relative_to(ROOT / "src")
    else:
        assert path is None


def test_sdist_to_fresh_wheel_has_owned_assets_and_extra_outside_checkout(tmp_path):
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "isolated-home")}
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [UV, "build", "--sdist", str(ROOT), "--out-dir", str(tmp_path / "sdist")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    archive = next((tmp_path / "sdist").glob("*.tar.gz"))
    with tarfile.open(archive) as source:
        names = {"/".join(p.split("/")[1:]) for p in source.getnames()}
    assert {
        "hatch_build.py",
        "tools/dbcrypt_build_headers.py",
        "native/dbcrypt-vfs/build.ps1",
        "native/dbcrypt-vfs/vfs.c",
        "native/dbcrypt-vfs/checked_io.c",
        "native/dbcrypt-vfs/checked_io.h",
    } <= names
    result = subprocess.run(
        [UV, "build", "--wheel", str(archive), "--out-dir", str(tmp_path / "wheel")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    wheel = next((tmp_path / "wheel").glob("*.whl"))
    with zipfile.ZipFile(wheel) as artifact:
        metadata = artifact.read(next(n for n in artifact.namelist() if n.endswith(".dist-info/METADATA"))).decode()
        assert "Provides-Extra: dbcrypt" in metadata
        requirements = [Requirement(value) for value in Parser().parsestr(metadata).get_all("Requires-Dist")]
        assert any(
            r.name == "sqlcipher3-wheels" and str(r.specifier) == ">=0.5.4" and r.marker.evaluate({"extra": "dbcrypt"})
            for r in requirements
        )
        native_asset = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
        wheel_metadata = artifact.read(next(n for n in artifact.namelist() if n.endswith(".dist-info/WHEEL"))).decode()
        if os.name == "nt":
            assert wheel.name.endswith("-py3-none-win_amd64.whl")
            assert "Root-Is-Purelib: false" in wheel_metadata
            assert artifact.read(native_asset).startswith(b"MZ")
        else:
            assert wheel.name.endswith("-py3-none-any.whl")
            assert "Root-Is-Purelib: true" in wheel_metadata
            assert native_asset not in artifact.namelist()
    venv = tmp_path / "fresh-venv"
    result = subprocess.run([UV, "venv", str(venv)], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result = subprocess.run(
        [UV, "pip", "install", "--python", str(python), "--no-deps", str(wheel)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    code = """
import sys, types
from pathlib import Path
audit = types.ModuleType('mordred_hermes._audit_support')
audit.safe_audit_append = lambda *args, **kwargs: None
sys.modules[audit.__name__] = audit
from mordred_hermes.dbcrypt import _windows_vfs, database_status
assert Path(_windows_vfs.__file__).resolve().is_relative_to(Path('fresh-venv').resolve())
asset = _windows_vfs.packaged_library_path()
if sys.platform == 'win32':
    assert asset is not None and asset.name == 'mordred_dbcrypt_vfs.dll' and asset.is_file()
else:
    assert asset is None
assert database_status(Path('isolated-home')).authenticated is False
"""
    result = subprocess.run([str(python), "-I", "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_source_digest_failure_leaves_header_directory_absent(tmp_path):
    module = load(ROOT / "tools/dbcrypt_build_headers.py", "dbcrypt_build_headers")
    destination = tmp_path / "headers"
    with pytest.raises(RuntimeError, match="digest"):
        module.prepare_headers(destination, b"tampered source")
    assert not destination.exists()


@pytest.mark.parametrize("failure", ["exit", "missing", "wrong-machine"])
def test_windows_build_failure_never_emits_support_tag(tmp_path, monkeypatch, failure):
    module = hook()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")
    monkeypatch.setenv("MORDRED_SQLITE_INCLUDE_DIR", str(tmp_path))
    for name in ("sqlite3.h", "sqlite3ext.h"):
        (tmp_path / name).write_bytes(b"controlled header bytes")
    monkeypatch.setattr(module, "validate_headers", lambda path: None)

    def compiler(command, **kwargs):
        if failure == "exit":
            raise subprocess.CalledProcessError(1, command)
        if failure == "wrong-machine":
            directory = Path(command[command.index("-OutputDirectory") + 1])
            (directory / "mordred_dbcrypt_checked.dll").write_bytes(b"wrong architecture")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module.subprocess, "run", compiler)
    data = {}
    with pytest.raises((RuntimeError, subprocess.CalledProcessError)):
        module.CustomBuildHook(str(ROOT), {}, None, None, str(tmp_path), "wheel").initialize("standard", data)
    assert "tag" not in data and "force_include" not in data


@pytest.mark.parametrize("installed,expected", [("0.5.7", True), ("0.5.8", False), ("0.5.4", False), (None, False)])
def test_windows_pair_requires_concrete_qualified_driver_without_import(installed, expected, monkeypatch):
    from importlib.metadata import PackageNotFoundError

    from mordred_hermes.dbcrypt import _windows_vfs

    def distribution_version(name):
        assert name == "sqlcipher3-wheels"
        if installed is None:
            raise PackageNotFoundError(name)
        return installed

    assert callable(getattr(_windows_vfs, "driver_distribution_qualified", None)), (
        "concrete driver pair check is missing"
    )
    monkeypatch.setattr(_windows_vfs, "version", distribution_version)
    assert _windows_vfs.driver_distribution_qualified() is expected


def test_actual_editable_install_finds_owned_asset_outside_source(tmp_path):
    source = tmp_path / "editable-source"
    package = source / "src/mordred_hermes/dbcrypt"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    shutil.copyfile(ROOT / "src/mordred_hermes/dbcrypt/_windows_vfs.py", package / "_windows_vfs.py")
    # A controlled non-executable resource exercises real Hatch editable layout.
    (source / "owned-resource.dll").write_bytes(b"owned editable resource")
    unowned = package.parent / "_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
    unowned.parent.mkdir(parents=True)
    unowned.write_bytes(b"unowned source-tree resource")
    (source / "pyproject.toml").write_text("""
[build-system]
requires = ["hatchling>=1.18"]
build-backend = "hatchling.build"
[project]
name = "hermes-mordred"
version = "0.0.0"
[tool.hatch.build.targets.wheel]
packages = ["src/mordred_hermes"]
[tool.hatch.build.targets.wheel.force-include]
"owned-resource.dll" = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
""")
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path / "isolated-home"),
        "MORDRED_DBCRYPT_CHECKED_LIBRARY": str(unowned),
    }
    env.pop("PYTHONPATH", None)
    venv = tmp_path / "editable-venv"
    result = subprocess.run([UV, "venv", str(venv)], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result = subprocess.run(
        [UV, "pip", "install", "--python", str(python), "--no-deps", "--editable", str(source)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    code = """
from pathlib import Path
from mordred_hermes.dbcrypt import _windows_vfs
assert Path(_windows_vfs.__file__).resolve().is_relative_to(Path('editable-source').resolve())
asset = _windows_vfs.packaged_library_path()
assert asset is not None and asset.is_file()
assert asset.is_relative_to(Path('editable-venv').resolve()), asset
assert not asset.is_relative_to(Path('editable-source').resolve()), asset
assert asset.read_bytes() == b'owned editable resource'
"""
    result = subprocess.run(
        [str(python), "-I", "-B", "-c", code], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("ownership", ["not-recorded", "foreign-location"])
def test_locator_refuses_unowned_or_foreign_distribution_asset(tmp_path, monkeypatch, ownership):
    from importlib.metadata import PackagePath
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _windows_vfs

    asset = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
    root = tmp_path / "site-packages"
    (root / asset).parent.mkdir(parents=True)
    (root / asset).write_bytes(b"unowned resource")
    foreign = tmp_path / "foreign.dll"
    foreign.write_bytes(b"foreign resource")
    installed = SimpleNamespace(
        files=[PackagePath(asset)] if ownership == "foreign-location" else [],
        locate_file=lambda entry: root if not str(entry) else foreign,
    )
    # This metadata provider boundary must exist before it can be replaced.
    assert hasattr(_windows_vfs, "distribution"), "installed distribution ownership is not consulted"
    monkeypatch.setattr(_windows_vfs, "distribution", lambda name: installed)
    assert _windows_vfs.packaged_library_path() is None


def test_uv_sync_rebuilds_for_owned_native_inputs_and_header_location(tmp_path):
    import json

    source = tmp_path / "cache-source"
    source.mkdir()
    inputs = ["pyproject.toml", "hatch_build.py", "tools/dbcrypt_build_headers.py"]
    inputs += sorted(
        str(path.relative_to(ROOT)).replace("\\", "/")
        for pattern in ("*.c", "*.h", "build.ps1")
        for path in (ROOT / "native/dbcrypt-vfs").glob(pattern)
    )
    for name in inputs[1:]:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("initial controlled input")
    settings = tomllib.loads((ROOT / "pyproject.toml").read_text()).get("tool", {}).get("uv", {})
    keys = settings.get("cache-keys", [])
    cache_table = ""
    if keys:
        entries = [
            "{ " + ", ".join(f"{key} = {json.dumps(value)}" for key, value in item.items()) + " }" for item in keys
        ]
        cache_table = "\n[tool.uv]\ncache-keys = [" + ", ".join(entries) + "]\n"
    (source / "pyproject.toml").write_text(
        """
[build-system]
requires = []
build-backend = "backend"
backend-path = ["."]
[project]
name = "task8-cache-probe"
version = "0.0.0"
requires-python = ">=3.11"
"""
        + cache_table
    )
    (source / "backend.py").write_text(
        """
import hashlib, os, zipfile
from pathlib import Path
INPUTS = """
        + repr(inputs)
        + """
def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    digest = hashlib.sha256(b"\\0".join(Path(name).read_bytes() for name in INPUTS)
        + os.environ.get("MORDRED_SQLITE_INCLUDE_DIR", "").encode()).hexdigest()
    name = "task8_cache_probe-0.0.0-py3-none-any.whl"
    prefix = "task8_cache_probe-0.0.0.dist-info/"
    data = {
        "task8_cache_probe_build.txt": digest,
        prefix + "METADATA": "Metadata-Version: 2.1\\nName: task8-cache-probe\\nVersion: 0.0.0\\n",
        prefix + "WHEEL": "Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
    }
    data[prefix + "RECORD"] = "".join(item + ",,\\n" for item in [*data, prefix + "RECORD"])
    with zipfile.ZipFile(Path(wheel_directory) / name, "w") as wheel:
        for path, value in data.items():
            wheel.writestr(path, value)
    with Path("build-calls.txt").open("a") as calls:
        calls.write(digest + "\\n")
    return name
build_wheel = build_editable
"""
    )
    venv = tmp_path / "cache-venv"
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path / "isolated-home"),
        "UV_PROJECT_ENVIRONMENT": str(venv),
        "MORDRED_SQLITE_INCLUDE_DIR": str(tmp_path / "headers-one"),
        "UV_PYTHON_DOWNLOADS": "never",
    }
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def sync_payload():
        result = subprocess.run(
            [UV, "sync", "--no-build-isolation", "--offline", "--python", sys.executable],
            cwd=source,
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        result = subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "from importlib.metadata import distribution; "
                "print(distribution('task8-cache-probe').locate_file('task8_cache_probe_build.txt').read_text())",
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    previous = sync_payload()
    builds = (source / "build-calls.txt").read_text()
    assert sync_payload() == previous
    assert (source / "build-calls.txt").read_text() == builds, "unchanged sync unnecessarily rebuilt"
    for name in [*inputs[1:], "pyproject.toml"]:
        path = source / name
        path.write_text(path.read_text() + "\n# changed controlled build input\n")
        current = sync_payload()
        assert current != previous, f"uv retained a stale editable after {name} changed"
        previous = current
    env["MORDRED_SQLITE_INCLUDE_DIR"] = str(tmp_path / "headers-two")
    assert sync_payload() != previous, "uv retained a stale editable after the explicit header location changed"
