"""Acceptance bookkeeping rejects provenance gaps; fixtures are never native proof."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path, PureWindowsPath

import pytest

from tests._dbcrypt_support import acceptance_tool


@pytest.fixture(autouse=True)
def _native_unit_tripwires(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from mordred_hermes.keyvault import _memory_key, _seckey_helper, _windows_custody, wrap
    from mordred_hermes.wizard import memory_cli

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("native entrypoint invoked by a unit contract test")

    monkeypatch.setattr(_seckey_helper, "_run_helper", forbidden)
    monkeypatch.setattr(_memory_key, "linux_memory_backend", forbidden)
    monkeypatch.setattr(_windows_custody, "windows_backend", forbidden)
    monkeypatch.setattr(memory_cli, "enable", forbidden)
    monkeypatch.setattr(wrap, "generate_wrapping_key", forbidden)
    monkeypatch.setattr(wrap, "unwrap_dek", forbidden)
    monkeypatch.setattr(wrap, "get_wrapping_key_public", forbidden)
    original = subprocess.run

    def guarded(argv, *args, **kwargs):
        if "_dbcrypt_acceptance_native.py" in " ".join(str(item) for item in argv):
            forbidden()
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded)


def bundle_fixture(tmp_path: Path) -> tuple[object, Path, dict]:
    """Internally consistent synthetic files; no package/native proof is claimed."""
    tool = acceptance_tool("dbcrypt_acceptance")
    checkout, root = tmp_path / "checkout", tmp_path / "bundle"
    root.mkdir()
    source = checkout / "src/mordred_hermes/__init__.py"
    wheel = root / "wheel-env/lib/site-packages/mordred_hermes/__init__.py"
    relative_files = (
        "tests/test_dbcrypt.py",
        "tests/conftest.py",
        "tools/dbcrypt_acceptance.py",
        "packaging/pth/mordred_hermes_config_decrypt.pth",
        "packaging/pth/mordred_hermes_runtime.pth",
        "artifacts/hermes_mordred-0.3.0a4.tar.gz",
        "artifacts/hermes_mordred-0.3.0a4-py3-none-any.whl",
        "extracted-sdist/hermes_mordred-0.3.0a4/pyproject.toml",
        "extracted-sdist/hermes_mordred-0.3.0a4/src/mordred_hermes/__init__.py",
        "wheel-env/pyvenv.cfg",
        "wheel-env/lib/site-packages/mordred_hermes/__init__.py",
        "wheel-env/lib/site-packages/mordred_hermes_runtime.pth",
    )
    for relative in relative_files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# inert fixture\n")
    source.parent.mkdir(parents=True)
    source.write_text("# inert fixture\n")
    for env in (checkout / ".venv", root / "wheel-env", root / "build-env"):
        python = tool._python(env)
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_text("fixture interpreter, never executed")
    probes = {}
    for mode, env, origin in (("source", checkout / ".venv", source), ("wheel", root / "wheel-env", wheel)):
        driver = env / "lib/site-packages/sqlcipher3/dbapi2.py"
        driver.parent.mkdir(parents=True, exist_ok=True)
        driver.write_text("fixture driver, never executed")
        entrypoint = env / ("Scripts/hermes-mordred.exe" if sys.platform == "win32" else "bin/hermes-mordred")
        entrypoint.parent.mkdir(parents=True, exist_ok=True)
        entrypoint.write_bytes(b"synthetic installed entrypoint; never executed")
        probes[mode + "_probe"] = {
            "maintenance_entrypoint": {"path": str(entrypoint), "sha256": tool.sha256_file(entrypoint)},
            "product_file": str(origin),
            "interpreter": str(tool._python(env)),
            "python_version": "3.13.0",
            "platform": sys.platform,
            "versions": {
                name: "0.3.0a4" if name == "hermes-mordred" else "1.0"
                for name in ("hermes-mordred", "hermes-agent", "sqlcipher3-wheels", "pytest")
            },
            "driver": {"module": str(driver), "sqlite_version": "3.51.1", "cipher_version": "4.12.0 community"},
            "token": {"elevated": False if os.name == "nt" else None, "uid": None if os.name == "nt" else 501},
            "home_is_temporary": True,
            "native_provider": None,
            "native_helper": None,
            "readiness": "not_probed_no_native_collector",
        }
    artifacts = root / "artifacts"
    extracted = root / "extracted-sdist/hermes_mordred-0.3.0a4"
    commands = [
        ["uv", "build", "--sdist", str(checkout), "--out-dir", str(artifacts)],
        *[
            ["uv", "venv", "--no-project", "--python", str(tool._python(checkout / ".venv")), str(root / name)]
            for name in ("build-env", "wheel-env")
        ],
        ["uv", "pip", "install", "--python", str(tool._python(root / "build-env")), "hatchling>=1.18"],
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            str(tool._python(root / "build-env")),
            str(extracted),
            "--out-dir",
            str(artifacts),
        ],
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(tool._python(root / "wheel-env")),
            "--link-mode",
            "copy",
            str(artifacts / "hermes_mordred-0.3.0a4-py3-none-any.whl") + "[dev,keyvault,extension,dbcrypt,telegram]",
        ],
    ]
    manifest = {
        "schema_version": 1,
        "commit": "a" * 40,
        "checkout": str(checkout),
        "created_at": 1000.0,
        "sdist": "artifacts/hermes_mordred-0.3.0a4.tar.gz",
        "wheel": "artifacts/hermes_mordred-0.3.0a4-py3-none-any.whl",
        "extracted_sdist": "extracted-sdist/hermes_mordred-0.3.0a4",
        **probes,
        "native_qualification": "not_run",
        "native_collectors": "not_integrated",
        "missing_native_hooks": [
            "provision",
            "reopen",
            "verify",
            "independent_ec2_observations",
            "collector_records_across_os_reboot_and_stop_start",
        ],
        "build_commands": [
            {"argv": argv, "cwd": str(root), "started_at": 999.0, "finished_at": 1000.0, "returncode": 0}
            for argv in commands
        ],
        "files": {name: tool.sha256_file(root / name) for name in relative_files},
    }
    for artifact in ("sdist", "wheel"):
        manifest[artifact + "_sha256"] = tool.sha256_file(root / manifest[artifact])
    if sys.platform in {"linux", "win32"}:
        manifest["acceptance_commands"] = tool.acceptance_commands(
            checkout=checkout, bundle=root, platform=sys.platform
        )
    (root / "manifest.json").write_text(json.dumps(manifest))
    return tool, root, manifest


def write_manifest(root: Path, manifest: dict) -> None:
    (root / "manifest.json").write_text(json.dumps(manifest))


def test_copied_bundle_preserves_real_pth_gate_test_inputs(tmp_path: Path) -> None:
    import runpy

    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = Path(__file__).resolve().parents[1]
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    tool._copy_inputs(checkout, bundle)
    assert not (bundle / "src").exists()
    assert not (bundle / "mordred_hermes").exists()
    for name in ("test_pth_bootstrap.py", "test_runtime_bootstrap.py"):
        copied = runpy.run_path(str(bundle / "tests" / name))
        assert copied["_eval_pth_engages"]("/opt/venv/bin/hermes") is True
        assert copied["_eval_pth_engages"]("/opt/venv/bin/pytest") is False


@pytest.mark.parametrize("name", ["mordred_hermes_runtime.pth", "mordred_hermes_config_decrypt.pth"])
def test_bundle_pth_gate_inputs_are_required_hash_bound_and_exported(tmp_path: Path, name: str) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    relative = "packaging/pth/" + name
    path = bundle / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# inert startup gate fixture\n")
    manifest["files"][relative] = tool.sha256_file(path)
    write_manifest(bundle, manifest)
    assert tool.validate_bundle(bundle)["files"][relative] == tool.sha256_file(path)
    assert relative in tool._local_bundle_proof(bundle, manifest)["inputs"]
    phase = tmp_path / "phase"
    phase.mkdir()
    proof_ref = tool._export_bundle_evidence({"bundle": bundle, "manifest": manifest}, phase)
    proof = json.loads((tmp_path / proof_ref["path"]).read_text())
    assert proof["inputs"][relative]["sha256"] == manifest["files"][relative]
    path.write_text("# changed gate\n")
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)
    path.unlink()
    del manifest["files"][relative]
    write_manifest(bundle, manifest)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


def test_acceptance_rejects_source_import_in_wheel_run(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = tmp_path / "checkout"
    source = checkout / "src/mordred_hermes/__init__.py"
    source.parent.mkdir(parents=True)
    source.touch()
    environment = tmp_path / "bundle/wheel-env"
    environment.mkdir(parents=True)
    with pytest.raises(tool.AcceptanceRefused, match="wheel_import"):
        tool.validate_import_provenance(source, checkout=checkout, environment=environment, mode="wheel")


def test_import_requires_actual_wheel_environment_and_source_tree(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = tmp_path / "checkout"
    source = checkout / "src/mordred_hermes/__init__.py"
    source.parent.mkdir(parents=True)
    source.touch()
    wheel = tmp_path / "bundle/wheel-env/lib/site-packages/mordred_hermes/__init__.py"
    wheel.parent.mkdir(parents=True)
    wheel.touch()
    tool.validate_import_provenance(wheel, checkout=checkout, environment=wheel.parents[3], mode="wheel")
    tool.validate_import_provenance(source, checkout=checkout, environment=wheel.parents[3], mode="source")
    with pytest.raises(tool.AcceptanceRefused, match="source_import"):
        tool.validate_import_provenance(wheel, checkout=checkout, environment=wheel.parents[3], mode="source")


@pytest.mark.skipif(os.name == "nt", reason="symlink setup requires host privilege on Windows")
def test_import_provenance_resolves_symlink_escape(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    source = tmp_path / "checkout/src/mordred_hermes/__init__.py"
    source.parent.mkdir(parents=True)
    source.touch()
    environment = tmp_path / "wheel-env"
    environment.mkdir()
    link = environment / "mordred_hermes"
    link.symlink_to(source.parent, target_is_directory=True)
    with pytest.raises(tool.AcceptanceRefused, match="wheel_import"):
        tool.validate_import_provenance(
            link / "__init__.py", checkout=tmp_path / "checkout", environment=environment, mode="wheel"
        )


def test_commands_preserve_installed_package_boundary_and_explicit_native_gates(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    checkout, bundle = tmp_path / "checkout", tmp_path / "bundle"
    commands = tool.acceptance_commands(checkout=checkout, bundle=bundle, platform="linux")
    source, wheel = commands[0:2]
    assert source["argv"][:8] == ["uv", "run", "--project", str(checkout), "python", "-m", "pytest", "-q"]
    assert wheel["argv"][:8] == [
        "uv",
        "run",
        "--no-project",
        "--python",
        str(bundle / "wheel-env/bin/python"),
        "python",
        "-m",
        "pytest",
    ]
    assert wheel["cwd"] == str(bundle)
    assert wheel["unset"] == ["PYTHONPATH", "PYTHONHOME"]
    assert str(bundle / "tests/test_dbcrypt.py") in wheel["argv"]
    native = [row for row in commands if row["suite"] == "dbcrypt-native"]
    assert len(native) == 2
    assert all(row["env"]["MORDRED_DBCRYPT_NATIVE_TEST"] == "1" for row in native)
    assert all(row["env"]["MORDRED_DBCRYPT_COLLECTORS_TEST"] == "1" for row in native)
    assert all(row["argv"][-6:-2] == ["-o", "addopts=", "-m", "integration"] for row in native)
    windows = tool.acceptance_commands(checkout=checkout, bundle=bundle, platform="win32")
    assert any(row["env"].get("MORDRED_TEST_WINDOWS_MEMORY_LIVE") == "1" for row in windows)
    assert any(row["suite"] == "windows-vfs" for row in windows)
    assert all("Scripts/python.exe" in row["argv"][4] for row in windows if row["mode"] == "wheel")
    with pytest.raises(tool.AcceptanceRefused, match="unsupported_platform"):
        tool.acceptance_commands(checkout=checkout, bundle=bundle, platform="darwin")


@pytest.mark.parametrize("command_kind", ["linux-acceptance", "windows-acceptance", "windows-package"])
def test_source_commands_preload_copied_plugin_outside_checkout(tmp_path: Path, command_kind: str) -> None:
    """A console-script launch loses the bundle before pytest preloads -p plugins."""
    import shutil
    import subprocess

    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = Path(__file__).resolve().parents[1]
    bundle = tmp_path / "bundle"
    copied_tests = bundle / "tests"
    (copied_tests / "integration").mkdir(parents=True)
    (copied_tests / "__init__.py").touch()
    configuration = bundle / "pyproject.toml"
    configuration.write_text('[tool.pytest.ini_options]\nmarkers = ["integration: inert collection"]\n')
    observation = bundle / "plugin-startup.json"
    plugin = copied_tests / "_dbcrypt_acceptance_native.py"
    plugin.write_text(
        "import importlib.util, json, os, sys\n"
        "from pathlib import Path\n"
        f"Path({str(observation)!r}).write_text(json.dumps({{\n"
        "    'plugin': __file__, 'cwd': os.getcwd(), 'interpreter': sys.executable, 'environment': sys.prefix,\n"
        "    'product': importlib.util.find_spec('mordred_hermes').origin,\n"
        "    'pythonpath': os.environ.get('PYTHONPATH'), 'pythonhome': os.environ.get('PYTHONHOME'),\n"
        "}))\n"
    )
    for name in ("test_dbcrypt_native.py", "test_dbcrypt_collectors.py", "test_dbcrypt_windows_vfs.py"):
        (copied_tests / "integration" / name).write_text(
            "import pytest\npytestmark = pytest.mark.integration\n"
            "def test_synthetic_collection():\n    raise AssertionError('collection only')\n"
        )
    if command_kind == "windows-package":
        command = tool.windows_package_commands(
            checkout=checkout,
            bundle=bundle,
            mode="source",
            basetemp=tmp_path / "pytest-temp",
            configuration=configuration,
        )[0]
        argv = command["argv"]
        cwd = bundle
    else:
        command = next(
            row
            for row in tool.acceptance_commands(
                checkout=checkout,
                bundle=bundle,
                platform="linux" if command_kind == "linux-acceptance" else "win32",
            )
            if row["mode"] == "source" and row["suite"] == "dbcrypt-native"
        )
        argv = [
            *command["argv"],
            "--rootdir",
            str(bundle),
            "-c",
            str(configuration),
            "-p",
            "tests._dbcrypt_acceptance_native",
            "--collect-only",
        ]
        cwd = Path(command["cwd"])
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"}
    }
    environment.update(
        PATH=os.pathsep.join((str(Path(sys.executable).parent), environment.get("PATH", ""))),
        UV_NO_SYNC="1",
        UV_OFFLINE="1",
        UV_PROJECT_ENVIRONMENT=sys.prefix,
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        PYTHONDONTWRITEBYTECODE="1",
        HERMES_HOME=str(tmp_path / "unused-hermes-home"),
    )
    uv_executable = shutil.which("uv", path=environment["PATH"])
    assert uv_executable is not None, "uv must be installed in the selected test environment or PATH"
    result = subprocess.run(
        argv,
        executable=str(Path(uv_executable).resolve()),
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(observation.read_text())
    assert Path(observed["plugin"]).resolve() == plugin.resolve()
    assert Path(observed["cwd"]).resolve() == bundle.resolve()
    assert Path(observed["interpreter"]).samefile(sys.executable)
    assert Path(observed["environment"]).resolve() == Path(sys.prefix).resolve()
    assert Path(observed["product"]).resolve() == checkout / "src/mordred_hermes/__init__.py"
    assert observed["pythonpath"] is None and observed["pythonhome"] is None
    assert not (tmp_path / "unused-hermes-home").exists()


@pytest.mark.parametrize("phase", ["provision", "reopen", "verify"])
def test_runner_does_not_turn_unimplemented_native_phase_into_success(tmp_path: Path, phase: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "mordred-dbcrypt-fixture"
    root.mkdir(mode=0o700)
    output = tmp_path / f"{phase}.json"
    assert tool.run_acceptance(root=root, phase=phase, output=output) != 0
    evidence = json.loads(output.read_text())
    assert evidence["live_accepted"] is False
    assert evidence["status"] == "refused"
    assert evidence["reasons"]
    assert evidence["tests"] == []


def test_live_claim_requires_all_phases_and_stopped_receipt() -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    reasons = tool.acceptance_failures({"live_accepted": True, "native_provider": "EC2 NitroTPM"})
    assert "missing_bundle_provenance" in reasons
    assert "missing_phases" in reasons
    assert "missing_independent_stop_receipt" in reasons
    assert "missing_native_rows" in reasons


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"unexpected_skips": ["native unavailable"]}, "unexpected_skips"),
        ({"platform": "win32", "token": {"elevated": True}}, "ordinary_windows_token_required"),
        ({"native_provider": "software TPM"}, "native_provider_unproven"),
        ({"owned_instance_receipts": [{"state": "running"}]}, "incomplete_final_stop"),
    ],
)
def test_incomplete_evidence_is_rejected(change: dict, reason: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    assert reason in tool.acceptance_failures(change)


def test_frozen_stop_receipt_requires_control_identity_and_actual_stop(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    path = tmp_path / "stop.json"
    value = {
        "version": 1,
        "instance": "i-095cbe655c196c749",
        "run": "a" * 32,
        "account": "123456789012",
        "created": 1000.0,
        "deadline": 1300.0,
        "state": "stopped",
        "start_requested": True,
        "start_uncertain": False,
        "stopped_at": 1200.0,
    }
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    result = tool.load_stop_receipt(path)
    assert result["sha256"] == tool.sha256_file(path)
    assert result["instance"] == value["instance"]
    assert result["stopped_at"] == 1200
    assert "account" not in result
    for field, replacement in [
        ("state", "settling"),
        ("start_requested", False),
        ("stopped_at", None),
        ("start_uncertain", True),
    ]:
        path.write_text(json.dumps({**value, field: replacement}))
        with pytest.raises(tool.AcceptanceRefused, match="stop_receipt"):
            tool.load_stop_receipt(path)


def test_stop_receipt_cannot_be_world_readable(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission check")
    tool = acceptance_tool("dbcrypt_acceptance")
    path = tmp_path / "stop.json"
    path.write_text("{}")
    path.chmod(0o644)
    with pytest.raises(tool.AcceptanceRefused, match="stop_receipt"):
        tool.load_stop_receipt(path)


def test_private_probe_environment_drops_product_injection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    monkeypatch.setenv("PYTHONPATH", "/source")
    monkeypatch.setenv("MORDRED_TEST_INJECT_BACKEND", "unsafe")
    monkeypatch.setenv("MORDRED_CONFIG_DECRYPT", "1")
    environment = tool.probe_environment(tmp_path)
    assert environment["HERMES_HOME"] == str(tmp_path)
    assert "PYTHONPATH" not in environment
    assert "MORDRED_TEST_INJECT_BACKEND" not in environment
    assert "MORDRED_CONFIG_DECRYPT" not in environment


def test_probe_records_actual_interpreter_import_driver_versions_with_private_home(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    result = tool.probe_interpreter(Path(sys.executable), cwd=tmp_path)
    assert Path(result["product_file"]).is_file()
    assert result["interpreter"] == str(Path(sys.executable).resolve())
    assert result["versions"]["hermes-mordred"]
    assert result["versions"]["sqlcipher3-wheels"]
    assert result["driver"]["cipher_version"]
    assert result["home_is_temporary"] is True
    assert result["native_provider"] is None
    assert result["readiness"] == "not_probed_no_native_collector"


def test_bundle_refuses_checkout_output_and_existing_output_before_build(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    inside = checkout / "bundle"
    with pytest.raises(tool.AcceptanceRefused, match="outside_checkout"):
        tool.build_acceptance_bundle(checkout=checkout, output=inside)
    assert not inside.exists()
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(tool.AcceptanceRefused, match="output_already_exists"):
        tool.build_acceptance_bundle(checkout=checkout, output=existing)


@pytest.mark.parametrize("name,kind", [("../escape", "file"), ("package/link", "link"), ("/absolute", "file")])
def test_sdist_extraction_refuses_traversal_and_links(tmp_path: Path, name: str, kind: str) -> None:
    import io
    import tarfile

    tool = acceptance_tool("dbcrypt_acceptance")
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        member = tarfile.TarInfo(name)
        if kind == "link":
            member.type = tarfile.SYMTYPE
            member.linkname = "/outside"
        else:
            member.size = 1
        handle.addfile(member, io.BytesIO(b"x") if kind == "file" else None)
    with pytest.raises(tool.AcceptanceRefused, match="unsafe_sdist"):
        tool.extract_sdist(archive, tmp_path / "extracted")
    assert not (tmp_path / "escape").exists()


def test_bundle_integrity_rejects_changed_copied_test_and_product_on_import_path(tmp_path: Path) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    test = bundle / "tests/test_dbcrypt.py"
    assert tool.validate_bundle(bundle)["files"] == manifest["files"]
    test.write_text("changed\n")
    with pytest.raises(tool.AcceptanceRefused, match="bundle_hash_mismatch"):
        tool.validate_bundle(bundle)
    test.write_text("# inert fixture\n")
    (bundle / "src").mkdir()
    with pytest.raises(tool.AcceptanceRefused, match="product_source_on_test_path"):
        tool.validate_bundle(bundle)


def test_cli_run_reports_refusal_without_cloud_or_product_import(tmp_path: Path) -> None:
    import subprocess

    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "mordred-dbcrypt-cli"
    root.mkdir(mode=0o700)
    output = tmp_path / "evidence.json"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(tool.__file__)),
            "run",
            "--root",
            str(root),
            "--phase",
            "verify",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(output.read_text())["live_accepted"] is False
    assert result.stderr == ""


def test_windows_vfs_commands_separate_source_faults_and_release_wheel(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    commands = tool.acceptance_commands(checkout=tmp_path / "checkout", bundle=tmp_path / "bundle", platform="win32")
    source, wheel = [row for row in commands if row["suite"] == "windows-vfs"]
    assert source["library_kind"] == "CheckedTest"
    assert "-k" not in source["argv"]
    assert wheel["library_kind"] == "packaged Checked"
    assert wheel["argv"][-3:-1] == [
        "-k",
        "not checkedtest and not injected_io and not every_creation and not inherited_dacl_race "
        "and not recovery_exclusive_lock and not shm_shared_lock",
    ]
    assert all("actual_collected_nodeids" in row["requires"] for row in (source, wheel))
    assert "expected_count" not in source and "expected_count" not in wheel


def test_runner_records_validated_bundle_provenance_even_while_native_hooks_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    test = bundle / "tests/test_dbcrypt.py"
    root = tmp_path / "mordred-dbcrypt-refusal"
    root.mkdir(mode=0o700)
    monkeypatch.setenv("DBCRYPT_BUNDLE", str(bundle))
    output = tmp_path / "refusal.json"
    assert tool.run_acceptance(root=root, phase="provision", output=output) == 2
    evidence = json.loads(output.read_text())
    assert evidence["bundle"]["commit"] == manifest["commit"]
    assert evidence["bundle_manifest_sha256"] == tool.sha256_file(bundle / "manifest.json")
    assert evidence["test_counts"] == {"passed": 0, "failed": 0, "skipped": 0, "collected": 0}
    assert "native_phase_inputs_missing" in evidence["reasons"]
    test.write_text("tampered\n")
    output = tmp_path / "tampered.json"
    assert tool.run_acceptance(root=root, phase="provision", output=output) == 2
    assert "bundle_hash_mismatch" in " ".join(json.loads(output.read_text())["reasons"])


@pytest.mark.parametrize(
    "field",
    [
        "commit",
        "checkout",
        "sdist",
        "sdist_sha256",
        "wheel",
        "wheel_sha256",
        "extracted_sdist",
        "source_probe",
        "wheel_probe",
        "created_at",
        "build_commands",
        "native_collectors",
        "missing_native_hooks",
    ],
)
def test_bundle_requires_complete_provenance(tmp_path: Path, field: str) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    del manifest[field]
    write_manifest(bundle, manifest)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


@pytest.mark.parametrize("artifact", ["sdist", "wheel"])
def test_bundle_rejects_artifact_digest_diverging_from_inventory(tmp_path: Path, artifact: str) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    manifest[artifact + "_sha256"] = "0" * 64
    write_manifest(bundle, manifest)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", 42),
        ("commit", "not-a-commit"),
        ("sdist", "artifacts/../artifacts/hermes_mordred-0.3.0a4.tar.gz"),
        ("wheel", "/absolute.whl"),
        ("created_at", True),
        ("files", []),
        ("source_probe", True),
        ("build_commands", [True]),
    ],
)
def test_bundle_rejects_malformed_or_noncanonical_provenance(tmp_path: Path, field: str, value: object) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    manifest[field] = value
    write_manifest(bundle, manifest)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


@pytest.mark.parametrize("mode", ["source", "wheel"])
def test_bundle_rejects_recorded_import_from_opposite_boundary(tmp_path: Path, mode: str) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    opposite = "wheel" if mode == "source" else "source"
    manifest[mode + "_probe"]["product_file"] = manifest[opposite + "_probe"]["product_file"]
    write_manifest(bundle, manifest)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


def test_bundle_rejects_single_arbitrary_file_as_provenance(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    path = tmp_path / "arbitrary.txt"
    path.write_text("arbitrary")
    write_manifest(tmp_path, {"schema_version": 1, "files": {path.name: tool.sha256_file(path)}})
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(tmp_path)


@pytest.mark.parametrize(
    "relative",
    [
        "mordred_hermes.py",
        "sitecustomize.py",
        "conftest.py",
        "pytest.ini",
        "pyproject.toml",
        "setup.cfg",
        "tests/conftest_extra.py",
        "tests/nested/conftest.py",
        "tools/added.py",
        "extracted-sdist/hermes_mordred-0.3.0a4/added.py",
        "wheel-env/lib/site-packages/mordred_hermes/added.py",
        "wheel-env/lib/site-packages/sitecustomize.py",
        "wheel-env/lib/site-packages/sitecustomize.cpython-313-x86_64-linux-gnu.so",
        "wheel-env/lib/site-packages/added.pth",
    ],
)
def test_bundle_rejects_unlisted_import_and_configuration_inputs(tmp_path: Path, relative: str) -> None:
    tool, bundle, _manifest = bundle_fixture(tmp_path)
    added = bundle / relative
    added.parent.mkdir(parents=True, exist_ok=True)
    added.write_text("raise AssertionError('must never execute added input')\n")
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


@pytest.mark.skipif(os.name == "nt", reason="symlink setup requires host privilege on Windows")
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_bundle_rejects_linked_inputs_even_when_contents_and_hashes_match(tmp_path: Path, link_kind: str) -> None:
    tool, bundle, _manifest = bundle_fixture(tmp_path)
    linked = bundle / "tests/test_dbcrypt.py"
    target = bundle / "tools/dbcrypt_acceptance.py"
    linked.unlink()
    if link_kind == "symlink":
        linked.symlink_to(target)
    else:
        os.link(target, linked)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


def test_bundle_allows_only_documented_mutable_outputs_and_bytecode(tmp_path: Path) -> None:
    tool, bundle, _manifest = bundle_fixture(tmp_path)
    for relative in (
        "tests/__pycache__/test_dbcrypt.cpython-313.pyc",
        "__pycache__/probe.cpython-313.pyc",
        ".pytest_cache/README.md",
        "outputs/refused.json",
    ):
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("mutable tooling output")
    tool.validate_bundle(bundle)


def test_existing_linux_memory_suite_is_wheel_only_until_source_adaptation(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    rows = [
        row
        for row in tool.acceptance_commands(
            checkout=tmp_path / "checkout", bundle=tmp_path / "bundle", platform="linux"
        )
        if row["suite"] == "linux-memory"
    ]
    assert len(rows) == 1
    assert rows[0]["mode"] == "wheel"
    assert rows[0]["source_applicability"] == {
        "status": "not_applicable",
        "reason": "existing_linux_memory_suite_requires_installed_runtime",
        "blocked_by": "source_capable_linux_memory_suite_adaptation_pending",
    }


@pytest.mark.parametrize("index", [1, 2, 3])
def test_bundle_rejects_build_stage_provenance_pointing_at_unrelated_environment(tmp_path: Path, index: int) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    manifest["build_commands"][index]["argv"][-1] = "unrelated-environment"
    write_manifest(bundle, manifest)
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_bundle(bundle)


@pytest.mark.skipif(os.name == "nt", reason="symlink setup requires host privilege on Windows")
def test_bundle_accepts_recorded_python_alias_for_same_source_interpreter(tmp_path: Path) -> None:
    tool, bundle, manifest = bundle_fixture(tmp_path)
    interpreter = tool._python(Path(manifest["checkout"]) / ".venv")
    alias = interpreter.with_name("python3")
    alias.symlink_to(interpreter)
    for index in (1, 2):
        manifest["build_commands"][index]["argv"][4] = str(alias)
    write_manifest(bundle, manifest)
    tool.validate_bundle(bundle)


def test_native_phase_inputs_require_explicit_mode_kind_bundle_and_helper(tmp_path: Path, monkeypatch) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    monkeypatch.setenv("MORDRED_DBCRYPT_COLLECTORS_TEST", "1")
    monkeypatch.delenv("DBCRYPT_BUNDLE", raising=False)
    with pytest.raises(tool.AcceptanceRefused, match="native_phase_inputs_missing"):
        tool.native_phase_inputs(tmp_path, "provision")


@pytest.mark.parametrize("when,outcome", [("teardown", "failed"), ("setup", "skipped"), ("call", "failed")])
def test_native_pytest_report_rejects_nonpassing_lifecycle(tmp_path: Path, when: str, outcome: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    report = {
        "nodeids": ["test_x.py::test_native"],
        "deselected": [],
        "collection_errors": [],
        "exitstatus": 0,
        "reports": [
            {"nodeid": "test_x.py::test_native", "when": stage, "outcome": outcome if stage == when else "passed"}
            for stage in ("setup", "call", "teardown")
        ],
    }
    with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
        tool.validate_native_test_report(report)


def test_native_pytest_report_requires_all_collected_nodes_and_nonzero_collection() -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    for value in (
        {"nodeids": [], "reports": [], "exitstatus": 0, "collection_errors": [], "deselected": []},
        {
            "nodeids": ["test_x.py::test_native"],
            "reports": [],
            "exitstatus": 0,
            "collection_errors": [],
            "deselected": [],
        },
    ):
        with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
            tool.validate_native_test_report(value)


def test_native_roots_are_separate_and_task7_cannot_receive_persistence_root(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "mordred-dbcrypt-parent"
    paths = tool.native_fixture_paths(root, "wheel")
    assert len(set(paths.values())) == 3
    assert paths["persistence"].name.endswith("wheel-persistence")
    assert paths["crash"].name.endswith("wheel-crash")
    assert paths["negative"].name.endswith("wheel-negative")
    assert all(path.parent == root for path in paths.values())


def test_native_reopen_requires_mode_boot_and_public_source_continuity() -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    baseline = {
        "mode": "source",
        "bundle_manifest_sha256": "a" * 64,
        "fixture": {"root": {"file_id": "1"}, "source": {"generation": "g"}},
        "logical": {"session": "b" * 64},
        "boot": {"identity": "boot-1"},
    }
    for change, observation in [
        ({"mode": "wheel"}, "process_restart"),
        ({"boot": {"identity": "boot-1"}}, "os_reboot"),
        ({"logical": {"session": "c" * 64}}, "process_restart"),
    ]:
        with pytest.raises(tool.AcceptanceRefused, match="native_reopen_continuity_failed"):
            tool.validate_reopen_continuity(baseline, {**baseline, **change}, observation)


def test_native_verify_does_not_compare_controller_spool_inode_with_guest(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "mordred-dbcrypt-controller-spool"
    root.mkdir(mode=0o700)
    assert tool.verify_native_spool(root)["live_accepted"] is False
    assert "missing_production_matrix" in tool.verify_native_spool(root)["reasons"]


def test_candidate_command_plans_exclude_production_only_activity_gate(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    rows = tool.native_acceptance_commands(
        checkout=tmp_path / "checkout", bundle=tmp_path / "bundle", platform="linux", kind="candidate"
    )
    assert not any("test_dbcrypt_activity.py" in " ".join(row.get("argv", [])) for row in rows)
    assert any(
        row.get("status") == "not_run_requires_production_activation" and row["suite"] == "dbcrypt-activity"
        for row in rows
    )
    production = tool.native_acceptance_commands(
        checkout=tmp_path / "checkout", bundle=tmp_path / "bundle", platform="linux", kind="production"
    )
    assert any(row.get("env", {}).get("MORDRED_DBCRYPT_ACTIVITY_NATIVE_TEST") == "1" for row in production)


def test_windows_candidate_requires_raw_qualification_rows_not_a_passed_boolean(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema": 1, "kind": "windows_vfs_qualification", "passed": True})
    )
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool.validate_windows_qualification(tmp_path, checkout=tmp_path)


def test_native_helper_digest_accepts_synthetic_rows_only_and_rejects_secret_fields() -> None:
    import importlib.util

    path = Path(__file__).parent / "_dbcrypt_acceptance_native.py"
    assert path.is_file(), "fixed native operation helper is missing"
    spec = importlib.util.spec_from_file_location("native_acceptance_helper", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    assert helper.logical_digest([{"id": "synthetic", "text": "日本語"}]) == helper.logical_digest(
        [{"text": "日本語", "id": "synthetic"}]
    )
    with pytest.raises(ValueError, match="synthetic_record_fields_only"):
        helper.logical_digest([{"id": "synthetic", "app_password": "must-not-hash"}])


def test_native_collector_module_exists_and_has_explicit_integration_optin() -> None:
    import ast

    path = Path(__file__).parent / "integration/test_dbcrypt_collectors.py"
    assert path.is_file(), "real native collector gate is missing"
    source = path.read_text()
    ast.parse(source)
    assert "MORDRED_DBCRYPT_COLLECTORS_TEST" in source
    assert "pytest.mark.integration" in source
    assert "_dbcrypt_acceptance_native" in source


def test_missing_native_interface_refuses_before_provider_or_memory_calls(tmp_path: Path, monkeypatch) -> None:
    import runpy

    from mordred_hermes.keyvault import _database_authority

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    monkeypatch.setattr(_database_authority, "require_database_memory_enabled", None)
    with pytest.raises(RuntimeError, match="integrated_native_memory_and_none_conversion_contract_required"):
        helper["native_facts"](tmp_path)


def test_native_child_diagnostics_never_export_exception_secrets(monkeypatch, capsys) -> None:
    import runpy

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))

    def secret_failure(_name):
        raise RuntimeError("mustnotexportsecret")

    helper["main"].__globals__["operation"] = secret_failure
    assert helper["main"]("read") == 2
    output = capsys.readouterr().out
    assert "mustnotexportsecret" not in output and "app_password" not in output
    assert json.loads(output)["reason"] == "native_operation_failed"


def test_damaging_native_operation_refuses_persistence_before_any_product_import(tmp_path, monkeypatch) -> None:
    import runpy

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    root = tmp_path / "mordred-dbcrypt-source-persistence"
    root.mkdir()
    monkeypatch.setenv("MORDRED_DBCRYPT_COLLECTORS_TEST", "1")
    monkeypatch.setenv("MORDRED_DBCRYPT_TEST_ROOT", str(root))
    monkeypatch.setenv("HERMES_HOME", str(root))
    for operation in ("negative", "backup_restore"):
        with pytest.raises(RuntimeError, match="damaging_operations_require_separate_negative_root"):
            helper["operation"](operation)
    with pytest.raises(RuntimeError, match="damaging_operations_require_separate_negative_root"):
        helper["real_helper_unavailability"](root)


def test_offline_verify_ignores_guest_bundle_environment(tmp_path: Path, monkeypatch) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "mordred-dbcrypt-private-spool"
    root.mkdir(mode=0o700)
    monkeypatch.setenv("DBCRYPT_BUNDLE", "/guest-only-path-not-on-controller")
    output = tmp_path / "verify.json"
    assert tool.run_acceptance(root=root, phase="verify", output=output) == 2
    assert json.loads(output.read_text())["reasons"] == ["missing_production_matrix"]


def test_phase_success_boolean_cannot_replace_executed_rows(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    value = {
        "schema_version": 2,
        "status": "production_native_passed",
        "acceptance_kind": "production",
        "bootstrap": "automatic_production",
        "native_rows_complete": True,
        "executions": [{"returncode": 0}],
        "mode": "wheel",
        "platform": "linux",
        "observation": "provision",
    }
    with pytest.raises(tool.AcceptanceRefused, match="native_phase_evidence_incomplete"):
        tool.validate_native_phase_evidence(value, directory=tmp_path)


def test_logical_digest_rejects_nested_data_even_under_a_public_field() -> None:
    import runpy

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    with pytest.raises(ValueError, match="synthetic_record_fields_only"):
        helper["logical_digest"]([{"id": "fixed", "text": {"app_password": "not-synthetic-content"}}])


def test_source_native_run_refuses_checkout_head_drift_before_probe(monkeypatch, tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    monkeypatch.setattr(tool, "_git", lambda *_args: "different-source-head")
    context = {"mode": "source", "manifest": {"checkout": str(tmp_path), "commit": "a" * 40}}
    with pytest.raises(tool.AcceptanceRefused, match="source_checkout_changed_since_bundle"):
        tool.require_native_source_checkout(context)


def test_native_suite_retains_module_coverage_outside_sdist_configuration(tmp_path: Path, monkeypatch) -> None:
    """Run the emitted collection tail, then bind its identities to strict evidence validation."""
    import subprocess

    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    configuration = bundle / "sdist/pyproject.toml"
    configuration.parent.mkdir(parents=True)
    configuration.write_text('[tool.pytest.ini_options]\naddopts = ""\nxfail_strict = true\n')
    module = bundle / "tests/test_example.py"
    module.parent.mkdir()
    module.write_text("def test_example():\n    raise AssertionError('collection must not execute this body')\n")
    monkeypatch.setattr(tool, "validate_bundle", lambda *_: None)
    monkeypatch.setattr(tool, "require_native_source_checkout", lambda *_: None)
    monkeypatch.setattr(tool, "probe_interpreter", lambda *_a, **_k: {"product_file": str(tmp_path)})
    monkeypatch.setattr(tool, "validate_import_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(tool, "_native_environment", lambda *_: {})
    monkeypatch.setattr(tool, "_native_driver", lambda *_: tmp_path / "unused-driver")
    captured = []

    class CollectedCommand(Exception):
        pass

    def capture(_context, argv, _environment, **kwargs):
        assert kwargs["name"] == "affected-collection"
        captured.append(argv)
        raise CollectedCommand

    monkeypatch.setattr(tool, "_native_process", capture)
    plan = {"suite": "affected", "env": {}, "argv": ["unused-python", "-m", "pytest", str(module)]}
    for mode in ("source", "wheel"):
        directory = tmp_path / mode
        directory.mkdir()
        context = {
            "bundle": bundle,
            "manifest": {"checkout": str(tmp_path), "extracted_sdist": "sdist"},
            "mode": mode,
            "kind": "production",
            "fixtures": {kind: tmp_path / kind for kind in ("persistence", "crash", "negative")},
        }
        with pytest.raises(CollectedCommand):
            tool._native_suite(context, plan, directory, tmp_path / "unused-baseline")
    assert captured[0] == captured[1]
    args = captured[0][3:]
    plugin = args.index("-p")
    assert args[plugin + 1] == "tests._dbcrypt_acceptance_native"
    del args[plugin : plugin + 2]  # Only replace the native reporter with the inert capture below.
    output = tmp_path / "collection.json"
    code = """
import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
import pytest
observed = {}
class Capture:
    def pytest_collection_finish(self, session):
        observed.update(nodeids=[item.nodeid for item in session.items],
                        root=str(session.config.rootpath), configuration=str(session.config.inipath),
                        xfail_strict=session.config.getini('xfail_strict'))
result = pytest.main(sys.argv[3:], plugins=[Capture()])
assert not any(name == 'mordred_hermes' or name.startswith('mordred_hermes.') for name in sys.modules)
pathlib.Path(sys.argv[2]).write_text(json.dumps(observed))
raise SystemExit(result)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            code,
            str(Path(pytest.__file__).parent.parent),
            str(output),
            *args,
            "--noconftest",
            "-p",
            "no:cacheprovider",
        ],
        cwd=bundle,
        env={**tool.probe_environment(tmp_path / "unused-home"), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(output.read_text())
    assert observed == {
        "nodeids": ["tests/test_example.py::test_example"],
        "root": str(bundle),
        "configuration": str(configuration),
        "xfail_strict": True,
    }
    collection = {
        "nodeids": observed["nodeids"],
        "reports": [],
        "exitstatus": 0,
        "collection_errors": [],
        "deselected": [],
    }
    # Synthetic passing phases test the evidence consumer; no test body/native code ran.
    report = {
        **collection,
        "reports": [
            {"nodeid": observed["nodeids"][0], "when": when, "outcome": "passed"}
            for when in ("setup", "call", "teardown")
        ],
    }
    references = {}
    for name, value in (("collection", collection), ("report", report)):
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(value))
        references[name] = {"path": path.name, "sha256": tool.sha256_file(path)}
    record = {
        "argv": captured[0][:-1],
        "gate_env": {},
        "suite": "affected",
        "nodeids": observed["nodeids"],
        "counts": {"passed": 1, "platform_na": 0, "skipped": 0},
        "platform_na": [],
        "collection": {"argv": captured[0], "returncode": 0, "report": references["collection"]},
        "pytest_report": references["report"],
    }
    manifest = {"_bundle_path": str(bundle), "extracted_sdist": "sdist", "_inputs": {"tests/test_example.py": module}}
    tool._selected_nodes({"platform": "linux"}, record, plan, manifest, tmp_path)
    windows_plan = {**plan, "argv": ["unused-python", "-m", "pytest", r"C:\bundle\tests\test_example.py"]}
    windows_argv = [
        *windows_plan["argv"],
        "--rootdir",
        r"C:\bundle",
        "-c",
        r"C:\bundle\sdist\pyproject.toml",
        "-p",
        "tests._dbcrypt_acceptance_native",
    ]
    windows_record = {
        **record,
        "argv": windows_argv,
        "collection": {**record["collection"], "argv": [*windows_argv, "--collect-only"]},
    }
    tool._selected_nodes(
        {"platform": "win32"}, windows_record, windows_plan, {**manifest, "_bundle_path": r"C:\bundle"}, tmp_path
    )
    for root in (str(configuration.parent), str(tmp_path / "foreign-root")):
        wrong = json.loads(json.dumps(record))
        for argv in (wrong["argv"], wrong["collection"]["argv"]):
            argv[argv.index("--rootdir") + 1] = root
        with pytest.raises(ValueError, match="inconsistent bundle provenance"):
            tool._selected_nodes({"platform": "linux"}, wrong, plan, manifest, tmp_path)


def helper_copy_fixture(tmp_path: Path):
    """File-safety fixture only; these bytes are never executed as a helper."""
    tool = acceptance_tool("dbcrypt_acceptance")
    parent = tmp_path / "mordred-dbcrypt-parent"
    directory = parent / "owned-helper"
    directory.mkdir(mode=0o700, parents=True)
    parent.chmod(0o700)
    production = tmp_path / "production-helper"
    production.write_bytes(b"inert byte fixture; never executable by a unit test")
    production.chmod(0o700)
    copied = directory / production.name
    copied.write_bytes(production.read_bytes())
    copied.chmod(0o700)
    info = copied.stat()
    value = {
        "schema_version": 1,
        "kind": "dbcrypt_withdrawable_helper",
        "path": str(copied),
        "sha256": tool.sha256_file(copied),
        "production_helper_sha256": tool.sha256_file(production),
        "identity": {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size},
    }
    manifest = parent / "helper-copy.json"
    manifest.write_text(json.dumps(value))
    manifest.chmod(0o600)
    return tool, parent, production, copied, manifest, value


def test_owned_helper_copy_requires_declared_exact_private_identity(tmp_path: Path) -> None:
    tool, parent, production, copied, manifest, value = helper_copy_fixture(tmp_path)
    result = tool.validate_withdrawable_helper(manifest, production=production, parent=parent)
    assert result["path"] == str(copied) and result["identity"] == value["identity"]
    copied.rename(copied.with_name("retained-original-inode"))
    copied.write_bytes(production.read_bytes())
    copied.chmod(0o700)
    with pytest.raises(tool.AcceptanceRefused, match="withdrawable_helper"):
        tool.validate_withdrawable_helper(manifest, production=production, parent=parent)


@pytest.mark.parametrize(
    "damage", ["hash", "identity", "primary", "outside", "public_parent", "public_file", "retained_exists"]
)
def test_owned_helper_copy_refuses_unsafe_or_nonowned_target(tmp_path: Path, damage: str) -> None:
    if os.name == "nt" and damage in {"public_parent", "public_file"}:
        pytest.skip("POSIX mode privacy; Windows uses the actual confidential-directory preflight")
    tool, parent, production, copied, manifest, value = helper_copy_fixture(tmp_path)
    if damage == "hash":
        copied.write_bytes(b"different bytes")
    elif damage == "identity":
        value["identity"]["inode"] += 1
    elif damage == "primary":
        value["path"] = str(production)
    elif damage == "outside":
        value["path"] = str(tmp_path / "unowned-copy")
    elif damage == "public_parent":
        copied.parent.chmod(0o755)
    elif damage == "public_file":
        copied.chmod(0o755)
    else:
        copied.with_name(copied.name + ".task15-withdrawn").write_bytes(b"do not overwrite")
    manifest.write_text(json.dumps(value))
    with pytest.raises(tool.AcceptanceRefused, match="withdrawable_helper"):
        tool.validate_withdrawable_helper(manifest, production=production, parent=parent)


def test_owned_helper_withdrawal_restores_only_copy_on_body_failure(tmp_path: Path) -> None:
    import runpy

    tool, parent, production, copied, manifest, _value = helper_copy_fixture(tmp_path)
    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    before = production.read_bytes()
    with (
        pytest.raises(RuntimeError, match="unit body failure"),
        helper["withdraw_owned_helper"](manifest, production=production, parent=parent),
    ):
        assert not copied.exists()
        assert production.read_bytes() == before
        raise RuntimeError("unit body failure")
    assert copied.read_bytes() == before and production.read_bytes() == before
    tool.validate_withdrawable_helper(manifest, production=production, parent=parent)


def test_owned_helper_withdrawal_never_overwrites_reappeared_copy(tmp_path: Path) -> None:
    import runpy

    _tool, parent, production, copied, manifest, _value = helper_copy_fixture(tmp_path)
    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    with pytest.raises(OSError), helper["withdraw_owned_helper"](manifest, production=production, parent=parent):
        copied.write_bytes(b"unexpected replacement; retain both artifacts")
        copied.chmod(0o600)
    assert copied.read_bytes().startswith(b"unexpected replacement")
    assert copied.with_name(copied.name + ".task15-withdrawn").read_bytes() == production.read_bytes()


def test_owned_helper_probe_boolean_does_not_replace_actual_acquisition_observations() -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    with pytest.raises(tool.AcceptanceRefused, match="helper_withdrawal_evidence_incomplete"):
        tool.validate_helper_withdrawal({"passed": True, "native_metadata_unchanged": True})


def test_native_children_keep_assertions_enabled(monkeypatch, tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    monkeypatch.setenv("PYTHONOPTIMIZE", "2")
    assert tool.probe_environment(tmp_path)["PYTHONOPTIMIZE"] == "0"


def control_action_fixture(tmp_path: Path):
    """Synthetic controller/EC2 records exercise parsing, never cloud or native execution."""
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "control-evidence"
    root.mkdir(mode=0o700)
    instance, run = "i-095cbe655c196c749", "a" * 32

    def saved(name, value, captured=None):
        path = root / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        ref = {"path": name, "sha256": tool.sha256_file(path)}
        if captured is not None:
            ref["captured_at"] = captured
        return ref

    def cloud(name, state, observed, controller_run=run):
        raw = {
            "Reservations": [
                {
                    "OwnerId": "123456789012",
                    "Instances": [
                        {
                            "InstanceId": instance,
                            "State": {"Name": state},
                            "Tags": [{"Key": "mordred:dbcrypt-validation", "Value": controller_run}]
                            if state == "running"
                            else [],
                        }
                    ],
                }
            ]
        }
        raw_ref = saved(name + "-raw.json", raw)
        return saved(
            name + ".json",
            {
                "schema": 1,
                "kind": "ec2_state_observation",
                "instance": instance,
                "controller_run": controller_run,
                "observed_at": observed,
                "state": state,
                "raw": raw_ref,
            },
        )

    armed = {
        "version": 1,
        "instance": instance,
        "run": run,
        "account": "123456789012",
        "created": 1000.0,
        "deadline": 1300.0,
        "state": "armed",
        "start_requested": False,
        "supervisor_pid": None,
        "heartbeat": None,
    }
    ready = {**armed, "supervisor_pid": 99, "heartbeat": 1018.0}
    started = {**ready, "state": "running", "start_requested": True, "start_uncertain": False}
    action = {
        "schema_version": 1,
        "kind": "dbcrypt_control_action",
        "platform": "linux",
        "instance": instance,
        "modes": ["source", "wheel"],
        "sequence": 1,
        "operation": "start",
        "action_at": 1020.0,
        "armed": saved("armed.json", armed, 1001.0),
        "before_action": saved("before.json", ready, 1019.0),
        "started": saved("started.json", started, 1021.0),
        "initial_stopped": cloud("initial-stop", "stopped", 1019.5),
        "running": cloud("running", "running", 1022.0),
    }
    path = root / "action.json"
    path.write_text(json.dumps(action))
    path.chmod(0o600)
    return tool, root, path, action, armed, started, saved, cloud


def test_controller_action_binds_real_receipt_shape_and_mode_without_exposing_account(tmp_path: Path) -> None:
    tool, _root, path, _action, _armed, _started, _saved, _cloud = control_action_fixture(tmp_path)
    result = tool.validate_control_action(path, platform="linux", mode="source", observation="provision")
    assert result["controller_run"] == "a" * 32 and result["sequence"] == 1
    assert result["running_at"] == 1022 and "123456789012" not in json.dumps(result)


@pytest.mark.parametrize(
    "damage",
    [
        "late_arm",
        "stale_supervisor",
        "missing_supervisor",
        "wrong_run",
        "wrong_instance",
        "wrong_mode",
        "uncertain_start",
        "deadline",
        "unowned_running",
        "late_capture",
    ],
)
def test_controller_action_refuses_missing_or_out_of_order_arm_evidence(tmp_path: Path, damage: str) -> None:
    tool, root, path, action, armed, started, saved, cloud = control_action_fixture(tmp_path)
    if damage == "late_arm":
        action["armed"] = saved("armed-late.json", {**armed, "created": 1021.0}, 1021.0)
    elif damage == "stale_supervisor":
        before = json.loads((root / "before.json").read_text())
        action["before_action"] = saved("before-stale.json", {**before, "heartbeat": 1001.0}, 1019.0)
    elif damage == "missing_supervisor":
        action["before_action"] = saved("no-supervisor.json", armed, 1019.0)
    elif damage == "wrong_run":
        action["started"] = saved("wrong-run.json", {**started, "run": "b" * 32}, 1021.0)
    elif damage == "wrong_instance":
        action["instance"] = "i-00f4db5c3a204906b"
    elif damage == "wrong_mode":
        action["modes"] = ["wheel"]
    elif damage == "uncertain_start":
        action["started"] = saved("uncertain.json", {**started, "start_uncertain": True}, 1021.0)
    elif damage == "deadline":
        action["action_at"] = 1240.0
    elif damage == "unowned_running":
        reference = cloud("unowned", "running", 1022.0)
        observation = json.loads((root / reference["path"]).read_text())
        raw = json.loads((root / observation["raw"]["path"]).read_text())
        raw["Reservations"][0]["Instances"][0]["Tags"] = []
        observation["raw"] = saved("unowned-changed-raw.json", raw)
        action["running"] = saved("unowned-changed.json", observation)
    else:
        action["before_action"]["captured_at"] = 1020.5
    path.write_text(json.dumps(action))
    with pytest.raises(tool.AcceptanceRefused, match="controller_action_incomplete"):
        tool.validate_control_action(path, platform="linux", mode="source", observation="provision")


def test_reboot_reuses_the_same_bounded_guard_with_fresh_active_heartbeat(tmp_path: Path) -> None:
    tool, _root, _path, action, _armed, started, saved, cloud = control_action_fixture(tmp_path)
    start_ref = saved("start-action.json", action)
    reboot = {
        **{key: action[key] for key in ("schema_version", "kind", "platform", "instance", "modes", "armed")},
        "sequence": 2,
        "operation": "reboot",
        "action_at": 1060.0,
        "start_action": start_ref,
        "before_action": saved("before-reboot.json", {**started, "heartbeat": 1058.0}, 1059.0),
        "running": cloud("after-reboot", "running", 1070.0),
    }
    reference = saved("reboot-action.json", reboot)
    result = tool.validate_control_action(
        _root / reference["path"], platform="linux", mode="source", observation="os_reboot"
    )
    assert result["controller_run"] == "a" * 32 and result["operation"] == "reboot"
    reboot["before_action"] = action["started"]
    reference = saved("stale-reboot-action.json", reboot)
    with pytest.raises(tool.AcceptanceRefused, match="controller_action_incomplete"):
        tool.validate_control_action(
            _root / reference["path"], platform="linux", mode="source", observation="os_reboot"
        )


def test_stop_start_requires_independent_previous_stop_before_new_arm(tmp_path: Path) -> None:
    tool, root, _path, action, armed, started, saved, cloud = control_action_fixture(tmp_path)
    stopped = {**started, "state": "stopped", "stopped_at": 1101.0}
    previous = saved("previous-stopped.json", stopped, 1101.5)
    observed = cloud("previous-stop", "stopped", 1102.0)
    current = {**armed, "run": "b" * 32, "created": 1110.0, "deadline": 1410.0}
    before = {**current, "supervisor_pid": 100, "heartbeat": 1118.0}
    restarted = {**before, "state": "running", "start_requested": True, "start_uncertain": False}
    cycle = {
        **{key: action[key] for key in ("schema_version", "kind", "platform", "instance", "modes")},
        "sequence": 3,
        "operation": "stop_start",
        "action_at": 1120.0,
        "armed": saved("new-armed.json", current, 1111.0),
        "before_action": saved("new-before.json", before, 1119.0),
        "started": saved("new-started.json", restarted, 1121.0),
        "initial_stopped": cloud("new-initial-stop", "stopped", 1119.5, "b" * 32),
        "running": cloud("new-running", "running", 1122.0, "b" * 32),
        "previous_stop": previous,
        "previous_independent_stop": observed,
    }
    reference = saved("stop-start.json", cycle)
    result = tool.validate_control_action(
        root / reference["path"], platform="linux", mode="source", observation="ec2_stop_start"
    )
    assert result["controller_run"] == "b" * 32 and result["previous_run"] == "a" * 32
    cycle["previous_independent_stop"] = cloud("late-stop", "stopped", 1111.0)
    reference = saved("late-stop-start.json", cycle)
    with pytest.raises(tool.AcceptanceRefused, match="controller_action_incomplete"):
        tool.validate_control_action(
            root / reference["path"], platform="linux", mode="source", observation="ec2_stop_start"
        )


def test_controller_cycle_settlement_requires_matching_stop_and_complete_phase_window(tmp_path: Path) -> None:
    tool, root, _path, action, _armed, started, saved, cloud = control_action_fixture(tmp_path)
    reference = saved("frozen-action.json", action)
    stop = saved("final-controller.json", {**started, "state": "stopped", "stopped_at": 1101.0}, 1101.5)
    observed = cloud("final-stop", "stopped", 1102.0)
    cycles = [{"action": reference, "stopped": stop, "independent_stopped": observed}]
    phase = {
        "platform": "linux",
        "instance": "i-095cbe655c196c749",
        "mode": "source",
        "observation": "provision",
        "controller_run": "a" * 32,
        "control_sequence": 1,
        "control_action": reference,
        "started_at": 1023.0,
        "finished_at": 1030.0,
    }
    rows = tool.validate_control_cycles(root, cycles, [phase])
    assert rows[reference["sha256"]]["stopped_at"] == 1101.0
    with pytest.raises(tool.AcceptanceRefused, match="controller_cycle_correlation_incomplete"):
        tool.validate_control_cycles(root, cycles, [{**phase, "finished_at": 1102.0}])
    wrong = saved("wrong-final.json", {**started, "run": "b" * 32, "state": "stopped", "stopped_at": 1101.0}, 1101.5)
    with pytest.raises(tool.AcceptanceRefused, match="controller_cycle_correlation_incomplete"):
        tool.validate_control_cycles(root, [{**cycles[0], "stopped": wrong}], [phase])


def test_controller_phase_binding_rejects_mode_sequence_or_run_relabel(tmp_path: Path) -> None:
    tool, root, _path, action, _armed, _started, saved, _cloud = control_action_fixture(tmp_path)
    reference = saved("frozen-action.json", action)
    phase = {
        "platform": "linux",
        "instance": "i-095cbe655c196c749",
        "mode": "source",
        "observation": "provision",
        "controller_run": "a" * 32,
        "control_sequence": 1,
        "control_action": reference,
        "started_at": 1023.0,
        "finished_at": 1030.0,
    }
    for change in ({"controller_run": "b" * 32}, {"control_sequence": 2}, {"started_at": 1021.0}):
        with pytest.raises(tool.AcceptanceRefused, match="controller_phase_binding_incomplete"):
            tool.validate_phase_control_binding({**phase, **change}, directory=root)


@pytest.mark.parametrize("prior_text", ["{", "{}", '{"status":"candidate_native_passed","observation":"provision"}'])
def test_reopen_malformed_prior_refuses_before_native_child(tmp_path: Path, monkeypatch, prior_text: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    root = tmp_path / "mordred-dbcrypt-private"
    root.mkdir(mode=0o700)
    action = tmp_path / "action.json"
    action.write_text("{}")
    action.chmod(0o600)
    prior = tmp_path / "prior.json"
    prior.write_text(prior_text)
    prior.chmod(0o600)
    context = {
        "fixtures": {"persistence": root / "mordred-dbcrypt-source-persistence"},
        "control_action_path": action,
        "control_action": {"sha256": tool.sha256_file(action)},
        "prior": prior,
        "kind": "candidate",
        "mode": "source",
    }
    monkeypatch.setattr(tool, "native_phase_inputs", lambda *_args: context)
    monkeypatch.delenv("DBCRYPT_BUNDLE", raising=False)
    monkeypatch.delenv("MORDRED_DBCRYPT_STOP_RECEIPT", raising=False)
    output = tmp_path / "refused.json"
    assert tool.run_acceptance(root=root, phase="reopen", output=output) == 2
    evidence = json.loads(output.read_text())
    assert evidence["status"] == "refused" and evidence["live_accepted"] is False
    assert evidence["reasons"] == ["native_evidence_invalid"]


@pytest.mark.parametrize(
    "node,when,reason",
    [
        (
            "tests/test_dbcrypt_capability.py::test_explicit_diagnosis_authenticates_once_and_releases",
            "setup",
            "windows_posix_authority_fixture",
        ),
        (
            "tests/test_dbcrypt_authority.py::test_fork_invalidates_without_releasing_parent_lease",
            "call",
            "windows_posix_fork",
        ),
        (
            "tests/extension/test_telegram_migrate_store.py::test_any_existing_collected_case",
            "setup",
            "windows_telegram_migration_module",
        ),
    ],
)
def test_reviewed_windows_platform_na_is_counted_separately(node: str, when: str, reason: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    stages = ("setup", "teardown") if when == "setup" else ("setup", "call", "teardown")
    report = {
        "nodeids": [node],
        "deselected": [],
        "collection_errors": [],
        "exitstatus": 0,
        "reports": [
            {
                "nodeid": node,
                "when": stage,
                "outcome": "skipped" if stage == when else "passed",
                "reason_code": reason if stage == when else None,
            }
            for stage in stages
        ],
    }
    actual = tool.validate_native_test_report(report, platform="win32", suite="affected")
    assert actual["counts"] == {"passed": 0, "platform_na": 1, "skipped": 0}
    with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
        tool.validate_native_test_report(report, platform="linux", suite="affected")
    report["reports"][0 if when == "setup" else 1]["reason_code"] = "native_helper_missing"
    with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
        tool.validate_native_test_report(report, platform="win32", suite="affected")


def test_safe_native_report_exports_only_reviewed_skip_code_not_raw_reason() -> None:
    import runpy
    from types import SimpleNamespace

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    report = helper["NativeReport"]()
    report.pytest_runtest_logreport(
        SimpleNamespace(
            nodeid="test_unrecognized.py::test_native",
            when="setup",
            outcome="skipped",
            longrepr=("fixture.py", 1, "Skipped: mustnotexportsecret"),
        )
    )
    assert report.reports[0]["reason_code"] == "unrecognized_skip"
    assert "mustnotexportsecret" not in json.dumps(report.reports)


def qualification_fixture(tmp_path: Path):
    """Synthetic qualification files exercise closure only; never hardware proof."""
    import runpy

    tool = acceptance_tool("dbcrypt_acceptance")
    checkout = Path(__file__).resolve().parents[1]
    root = tmp_path / "qualification"
    root.mkdir()

    def saved(name, value):
        path = root / name
        path.write_text(json.dumps(value))
        return {"path": name, "sha256": tool.sha256_file(path)}

    node = "tests/integration/test_dbcrypt_windows_vfs.py::test_rollback_wal_temp_vacuum_and_bootstrap_lifetime"
    rows = {}
    for name, target in (
        ("checkedtest_source", "CheckedTest"),
        ("checked_source", "Checked"),
        ("checked_wheel", "Checked"),
    ):
        run = {
            "action": "run",
            "target": target,
            "nodeids": [node],
            "collected": 1,
            "pytest_exit_code": 0,
            "reports": [
                {"nodeid": node, "when": stage, "outcome": "passed"} for stage in ("setup", "call", "teardown")
            ],
            "collection_errors": [],
            "dll_sha256": "a" * 64,
            "driver_version": "0.5.7",
            "versions": {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"},
            "bundle_manifest_sha256": "b" * 64,
            "sdist_sha256": "c" * 64,
            "wheel_sha256": "d" * 64,
            "record_owned_packaged_dll": True,
            "test_exports_absent": True,
            "env_dll_override": None,
            "product_module": "/outside/wheel-env/lib/site-packages/mordred_hermes/__init__.py",
            "argv": ["-q", "-k", "rollback"],
        }
        rows[name] = {
            "collect": saved(name + "-collect.json", {**run, "action": "collect"}),
            "run": saved(name + "-run.json", run),
        }
    critical = [
        *(checkout / "native/dbcrypt-vfs").glob("*.c"),
        *(checkout / "native/dbcrypt-vfs").glob("*.h"),
        *(checkout / "src/mordred_hermes/_private_fs").glob("*.py"),
        checkout / "src/mordred_hermes/dbcrypt/_windows_vfs.py",
        checkout / "tests/integration/test_dbcrypt_windows_vfs.py",
    ]
    manifest = {
        "schema": 1,
        "kind": "windows_vfs_qualification",
        "rows": rows,
        "provenance": saved(
            "provenance.json",
            {
                "source_hashes": {path.relative_to(checkout).as_posix(): tool.sha256_file(path) for path in critical},
                "headers": runpy.run_path(str(checkout / "tools/dbcrypt_build_headers.py"))["HEADER_SHA256"],
            },
        ),
        "fixture_verify": saved("fixture.json", {"elevated": False, "sid": "ordinary-test-fixture"}),
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    return tool, root, checkout, manifest, saved


def test_windows_qualification_rejects_self_consistent_focused_subset(tmp_path: Path) -> None:
    tool, root, checkout, _manifest, _saved = qualification_fixture(tmp_path)
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool.validate_windows_qualification(root, checkout=checkout)


@pytest.mark.parametrize(
    "component,field,value",
    [
        ("telegram", "api_id", 23456),
        ("telegram", "api_hash", "b" * 32),
        ("telegram", "session", "different-valid-session"),
        ("telegram", "store_key", b"b" * 32),
        ("mail", "address", "changed@example.invalid"),
        ("mail", "app_password", "different-valid-password"),
        ("mail", "imap_host", "changed.example.invalid"),
        ("mail", "own_addresses", ("changed@example.invalid",)),
        ("mail", "account", "changed"),
        ("mail", "gmail", True),
        ("mail", "mailboxes", {"sent": "Sent"}),
    ],
)
def test_original_private_credential_oracle_rejects_different_valid_fields(component, field, value) -> None:
    import runpy
    from dataclasses import replace

    from mordred_hermes.extension.telegram.secrets import TelegramSecrets
    from mordred_hermes.imports.mail.secrets import MailCredentials

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    telegram = TelegramSecrets(12345, "a" * 32, b"a" * 32, "original-session")
    mail = MailCredentials(
        "owner@example.invalid",
        "original-password",
        "imap.example.invalid",
        993,
        ("owner@example.invalid",),
        "native_sync",
        False,
        {"inbox": "INBOX"},
    )
    reference = helper["_private_credential_values"](telegram, mail)
    helper["_assert_original_credentials"](reference, telegram, mail)
    changed_tg = replace(telegram, **{field: value}) if component == "telegram" else telegram
    changed_mail = replace(mail, **{field: value}) if component == "mail" else mail
    with pytest.raises(RuntimeError, match="original_native_credentials_changed"):
        helper["_assert_original_credentials"](reference, changed_tg, changed_mail)


def test_credential_reference_refuses_destructive_roots_before_sql_import(tmp_path: Path) -> None:
    import runpy

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    for suffix in ("negative", "crash"):
        root = tmp_path / ("mordred-dbcrypt-source-" + suffix)
        with pytest.raises(RuntimeError, match="credential_reference_requires_persistence_root"):
            helper["_credential_reference"](root, root, None, None)
        with pytest.raises(RuntimeError, match="credential_reference_requires_persistence_root"):
            helper["_credential_replacement_probe"](root, root, None, None)


def test_offline_execution_rejects_missing_actual_probe_provenance(tmp_path: Path) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    payload = {
        "schema_version": 2,
        "status": "executed",
        "acceptance_kind": "production",
        "bootstrap": "automatic_production",
        "implementation_sha256": "a" * 64,
    }
    phase = {
        "acceptance_kind": "production",
        "bootstrap": "automatic_production",
        "native_implementation_sha256": "a" * 64,
        "executions": [
            {
                "operation": operation,
                "returncode": 0,
                "started_at": 10.0,
                "finished_at": 11.0,
                "payload": payload,
                "import_probe": {"product_file": "/unrelated/source/__init__.py"},
            }
            for operation in ("preflight", "read")
        ],
    }
    with pytest.raises((tool.AcceptanceRefused, ValueError, KeyError)):
        tool._native_execution_report(phase, tmp_path)


def complete_native_phase_fixture(tmp_path: Path, *, mode="source"):
    from tests._dbcrypt_acceptance_evidence import complete_phase

    bundle_root = tmp_path / "bundle-fixture"
    bundle_root.mkdir()
    control_root = tmp_path / "control-fixture"
    control_root.mkdir()
    helper_root = tmp_path / "helper-fixture"
    helper_root.mkdir()
    return complete_phase(
        bundle_fixture(bundle_root), control_action_fixture(control_root), helper_copy_fixture(helper_root), mode=mode
    )


@pytest.mark.parametrize("mode", ["source", "wheel"])
def test_complete_synthetic_native_phase_has_required_offline_closure(tmp_path: Path, mode: str) -> None:
    tool, spool, phase = complete_native_phase_fixture(tmp_path, mode=mode)
    assert phase["mode"] == mode
    assert tool.validate_native_phase_evidence(phase, directory=spool) == phase
    assert phase["live_accepted"] is False, "unit fixture acceptance is not native qualification"


@pytest.mark.parametrize(
    "damage",
    [
        "missing_public_read",
        "missing_successful_restore",
        "missing_restore_reopen",
        "missing_crash",
        "relabeled_node",
        "missing_profile_component",
        "wrong_probe",
        "wrong_artifact",
        "wrong_read_binding",
        "wrong_bundle_commit",
        "extra_deselection",
        "missing_operation",
        "missing_guarded_runtime",
        "missing_mail_retry",
    ],
)
def test_offline_native_evidence_rejects_incomplete_or_relabeled_closure(tmp_path: Path, damage: str) -> None:
    tool, spool, phase = complete_native_phase_fixture(tmp_path)
    native = next(row for row in phase["executions"] if row.get("suite") == "dbcrypt-native")
    if damage.startswith("missing_") and damage in {
        "missing_public_read",
        "missing_successful_restore",
        "missing_restore_reopen",
    }:
        name = {
            "missing_public_read": "public-collectors",
            "missing_successful_restore": "backup-restore",
            "missing_restore_reopen": "after-restore",
        }[damage]
        native["collector_rows"] = [ref for ref in native["collector_rows"] if Path(ref["path"]).stem != name]
    elif damage in {"missing_guarded_runtime", "missing_mail_retry"}:
        name = "backup-restore" if damage == "missing_guarded_runtime" else "negative"
        reference = next(ref for ref in native["collector_rows"] if Path(ref["path"]).stem == name)
        path = spool / reference["path"]
        value = json.loads(path.read_text())
        if damage == "missing_guarded_runtime":
            value["guarded_runtime_monitor_backup"] = False
        else:
            value["rows"].remove("mail_retired_sql_failure_named_retry")
        path.write_text(json.dumps(value))
        reference["sha256"] = tool.sha256_file(path)
    elif damage in {"missing_crash", "relabeled_node", "extra_deselection"}:
        report_path = spool / native["pytest_report"]["path"]
        report = json.loads(report_path.read_text())
        if damage == "missing_crash":
            report["nodeids"] = [node for node in report["nodeids"] if "encrypt-prepared" not in node]
            report["reports"] = [row for row in report["reports"] if row["nodeid"] in report["nodeids"]]
        elif damage == "relabeled_node":
            report["nodeids"][0] = "tests/integration/test_dbcrypt_native.py::test_focused_subset"
        else:
            report["deselected"] = [
                "tests/integration/test_dbcrypt_native.py::test_native_crash_subprocess_recovery[encrypt-prepared]"
            ]
        report_path.write_text(json.dumps(report))
        native["pytest_report"]["sha256"] = tool.sha256_file(report_path)
    elif damage == "missing_profile_component":
        del phase["logical"]["other:telegram"]
    elif damage == "wrong_probe":
        native["import_probe"] = {**native["import_probe"], "product_file": "/wrong/source/__init__.py"}
    elif damage == "wrong_artifact":
        phase["bundle"]["wheel_sha256"] = "f" * 64
    elif damage == "wrong_read_binding":
        read = next(row for row in phase["executions"] if row.get("operation") == "read")
        read["payload"] = {**read["payload"], "logical": {**read["payload"]["logical"], "root:telegram": "f" * 64}}
    elif damage == "wrong_bundle_commit":
        phase["bundle"]["commit"] = "f" * 40
    else:
        phase["executions"] = [row for row in phase["executions"] if row.get("operation") != "seed"]
    with pytest.raises(tool.AcceptanceRefused, match="native_phase_evidence_incomplete"):
        tool.validate_native_phase_evidence(phase, directory=spool)


def full_qualification_fixture(tmp_path: Path, monkeypatch):
    from tests._dbcrypt_acceptance_evidence import complete_qualification

    directory = tmp_path / "bundle-fixture"
    directory.mkdir()
    return complete_qualification(bundle_fixture(directory), tmp_path, monkeypatch)


def test_full_synthetic_windows_qualification_closes_exact_source_and_release_nodes(
    tmp_path: Path, monkeypatch
) -> None:
    tool, root, checkout, _manifest = full_qualification_fixture(tmp_path, monkeypatch)
    actual = tool._validate_legacy_windows_qualification(root, checkout=checkout)
    assert actual["diagnostic"]["nodeids"] == tool.windows_vfs_required_nodes(checkout, release=False)
    assert actual["wheel"]["nodeids"] == tool.windows_vfs_required_nodes(checkout, release=True)


@pytest.mark.parametrize(
    "damage", ["focused_both", "selection", "deselected", "fixture", "artifact", "source_map", "wheel_hash", "header"]
)
def test_windows_qualification_refuses_subset_selection_or_provenance_gaps(
    tmp_path: Path, monkeypatch, damage: str
) -> None:
    tool, root, checkout, manifest = full_qualification_fixture(tmp_path, monkeypatch)

    def rewrite(reference, edit):
        path = root / reference["path"]
        value = json.loads(path.read_text())
        edit(value)
        path.write_text(json.dumps(value))
        reference["sha256"] = tool.sha256_file(path)

    if damage == "focused_both":
        for links in manifest["rows"].values():
            for reference in links.values():
                rewrite(
                    reference,
                    lambda value: value.update(
                        nodeids=value["nodeids"][:1],
                        collected=1,
                        reports=[row for row in value["reports"] if row["nodeid"] == value["nodeids"][0]],
                    ),
                )
    elif damage == "selection":
        rewrite(manifest["rows"]["checked_source"]["run"], lambda value: value["argv"].extend(["-k", "focused"]))
    elif damage == "deselected":
        rewrite(manifest["rows"]["checked_source"]["run"], lambda value: value.update(deselected=[value["nodeids"][0]]))
    elif damage == "fixture":
        rewrite(manifest["fixture_verify"], lambda value: value.update(sid="different-ordinary-sid"))
    elif damage == "artifact":
        (root / manifest["artifacts"]["checked_source"]["dll"]["path"]).write_bytes(b"changed actual tested artifact")
    elif damage == "source_map":
        rewrite(manifest["source_map"], lambda value: value["files"].update({"native/dbcrypt-vfs/vfs.c": "f" * 64}))
    elif damage == "wheel_hash":
        rewrite(manifest["rows"]["checked_wheel"]["run"], lambda value: value.update(wheel_sha256="f" * 64))
    else:
        (root / manifest["headers"]["sqlite3.h"]["path"]).write_bytes(b"changed header")
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool._validate_legacy_windows_qualification(root, checkout=checkout)


def test_windows_qualification_rejects_artifact_shape_without_real_archive_closure(tmp_path: Path, monkeypatch) -> None:
    tool, root, checkout, manifest = full_qualification_fixture(tmp_path, monkeypatch)
    # Even consistent hashes cannot turn non-archive bytes into a source chain.
    (root / manifest["source_archive"]["path"]).write_bytes(b"not an archive")
    digest = tool.sha256_file(root / manifest["source_archive"]["path"])
    manifest["source_archive"]["sha256"] = digest
    path = root / manifest["provenance"]["path"]
    provenance = json.loads(path.read_text())
    provenance["source_archive_sha256"] = digest
    path.write_text(json.dumps(provenance))
    manifest["provenance"]["sha256"] = tool.sha256_file(path)
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool._validate_legacy_windows_qualification(root, checkout=checkout)


def test_windows_qualification_export_closes_referenced_public_inputs_only(tmp_path: Path, monkeypatch) -> None:
    tool, root, checkout, _manifest = full_qualification_fixture(tmp_path, monkeypatch)
    output = tmp_path / "phase-output"
    output.mkdir()
    reference = tool._export_windows_qualification({"qualification": str(root)}, output)
    copied = tmp_path / reference["path"]
    assert tool.sha256_file(copied) == tool.sha256_file(root / "manifest.json")
    actual = tool._validate_legacy_windows_qualification(copied.parent, checkout=checkout)
    assert actual["manifest_sha256"] == reference["sha256"]


def test_known_na_node_without_a_matching_raw_reason_still_refuses(monkeypatch) -> None:
    import runpy
    from types import SimpleNamespace

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    reporter = helper["NativeReport"]()
    # Parser-only unit model; native factories and subprocess tripwires remain.
    monkeypatch.setitem(reporter.pytest_runtest_logreport.__globals__, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setenv("MORDRED_DBCRYPT_RUN_SUITE", "affected")
    node = "tests/test_dbcrypt_authority.py::test_fork_invalidates_without_releasing_parent_lease"
    reporter.pytest_runtest_logreport(
        SimpleNamespace(nodeid=node, when="call", outcome="skipped", longrepr="unrecognized native prerequisite reason")
    )
    assert reporter.reports[0]["reason_code"] == "unrecognized_skip"


@pytest.mark.parametrize("root_kind", ["symlink", "missing", "file"])
def test_windows_inventory_na_applies_only_to_the_actual_symlink_parameter(monkeypatch, root_kind: str) -> None:
    import runpy
    from types import SimpleNamespace

    tool = acceptance_tool("dbcrypt_acceptance")
    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    reporter = helper["NativeReport"]()
    # Reporting/parser contract only: no Windows/native fixture is invoked.
    monkeypatch.setitem(reporter.pytest_runtest_logreport.__globals__, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setenv("MORDRED_DBCRYPT_RUN_SUITE", "affected")
    node = "tests/test_dbcrypt_inventory.py::test_invalid_root_is_incomplete[" + root_kind + "]"
    reason = "POSIX alias/rename semantics; Windows sharing/rename qualification is Task 5's gate"
    for stage in ("setup", "teardown"):
        reporter.pytest_runtest_logreport(
            SimpleNamespace(
                nodeid=node,
                when=stage,
                outcome="skipped" if stage == "setup" else "passed",
                longrepr=("tests/test_dbcrypt_inventory.py", 259, "Skipped: " + reason),
            )
        )
    report = {
        "nodeids": [node],
        "deselected": [],
        "collection_errors": [],
        "exitstatus": 0,
        "reports": reporter.reports,
    }
    if root_kind == "symlink":
        assert reporter.reports[0]["reason_code"] == "windows_posix_dbcrypt_inventory"
        actual = tool.validate_native_test_report(report, platform="win32", suite="affected")
        assert actual["counts"] == {"passed": 0, "platform_na": 1, "skipped": 0}
    else:
        assert reporter.reports[0]["reason_code"] == "unrecognized_skip"
        # Even a relabelled safe code cannot admit a skip of these required cases.
        for code in ("unrecognized_skip", "windows_posix_dbcrypt_inventory"):
            report["reports"][0]["reason_code"] = code
            with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
                tool.validate_native_test_report(report, platform="win32", suite="affected")


@pytest.mark.parametrize("platform,generation_length", [("linux", 32), ("win32", 64), ("linux", 64), ("win32", 32)])
def test_public_read_generation_follows_the_actual_provider_contract(platform: str, generation_length: int) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    identity = {"platform": platform, "volume": 1, "file_id": "100", "owner": "ordinary-owner"}
    fixture = {
        "root": identity,
        "source": {
            "root": identity,
            "provider": "cng" if platform == "win32" else "tpm",
            "generation": "a" * generation_length,
            "record_sha256": "b" * 64,
        },
    }
    logical = {
        profile + ":" + component: "c" * 64
        for profile in tool.REQUIRED_PROFILES
        for component in tool.REQUIRED_COMPONENTS
    }
    checkout = r"C:\source" if platform == "win32" else "/source"
    module = (
        r"C:\source\.venv\Lib\site-packages\hermes\__init__.py"
        if platform == "win32"
        else "/source/.venv/lib/site-packages/hermes/__init__.py"
    )
    bundle = {"checkout": checkout, "source_probe": {"versions": {"hermes-agent": "1.0"}}}
    phase = {"platform": platform, "mode": "source", "fixture": fixture, "logical": logical}
    payload = {
        "logical": logical,
        "rows": dict.fromkeys(tool.REQUIRED_COMPONENTS),
        "fixture": fixture,
        "facts": {"filesystem": {"identity": identity}},
        "hermes": {"module": module, "version": "1.0", "sha256": "d" * 64},
        "credential_continuity": "original_native_protected_reference",
    }
    if generation_length == (64 if platform == "win32" else 32):
        tool._public_read(payload, phase, bundle, persistence=True)
    else:
        with pytest.raises(ValueError, match="inconsistent bundle provenance"):
            tool._public_read(payload, phase, bundle, persistence=True)


@pytest.mark.parametrize("mode", ["source", "wheel"])
def test_packaged_qualification_has_fixed_commands_without_native_custody_gate(mode: str) -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    rows = tool.windows_package_commands(
        checkout=Path("/checkout"),
        bundle=Path("/bundle"),
        mode=mode,
        basetemp=Path("/private/temp"),
        configuration=Path("/bundle/sdist/pyproject.toml"),
    )
    assert len(rows) == 2
    assert rows[0]["argv"] == [*rows[1]["argv"], "--collect-only"]
    prefix = (
        ["uv", "run", "--project", "/checkout", "python", "-m", "pytest"]
        if mode == "source"
        else [
            "uv",
            "run",
            "--no-project",
            "--python",
            "/bundle/wheel-env/Scripts/python.exe",
            "python",
            "-m",
            "pytest",
        ]
    )
    for row in rows:
        assert row["argv"] == [*prefix, *row["pytest_argv"]]
        args = row["pytest_argv"]
        assert args[args.index("--rootdir") + 1] == "/bundle"
        assert args[args.index("-c") + 1] == "/bundle/sdist/pyproject.toml"
        assert args[args.index("--basetemp") + 1] == "/private/temp"
        assert args[args.index("-k") + 1] == tool.WINDOWS_RELEASE_SELECTION
        assert args[args.index("-p") + 1] == "tests._dbcrypt_acceptance_native"
        assert row["env"] == {"MORDRED_DBCRYPT_WINDOWS_VFS_TEST": "1", "MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY": "1"}


@pytest.mark.parametrize("mode", ["source", "wheel"])
def test_packaged_pytest_preserves_module_identity_outside_sdist_config(tmp_path: Path, mode: str) -> None:
    """The shared command tail must retain identity for sibling bundle tests."""
    import subprocess

    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    configuration = bundle / "extracted-sdist/package/pyproject.toml"
    configuration.parent.mkdir(parents=True)
    configuration.write_text(
        '[tool.pytest.ini_options]\nmarkers = ["integration: inert identity probe"]\nxfail_strict = true\n'
    )
    module = bundle / "tests/integration/test_dbcrypt_windows_vfs.py"
    module.parent.mkdir(parents=True)
    module.write_text(
        "import pytest\npytestmark = pytest.mark.integration\n"
        "def test_first():\n    pass\n"
        "def test_second():\n    pass\n"
        "def test_checkedtest_excluded():\n    raise AssertionError('must be deselected')\n"
    )
    (bundle / "inert_identity.py").write_text(
        "import json, os\nfrom pathlib import Path\n"
        "evidence = {'deselected': [], 'reports': []}\n"
        "def pytest_configure(config):\n"
        "    evidence.update(root=str(config.rootpath), configuration=str(config.inipath),\n"
        "                    xfail_strict=config.getini('xfail_strict'))\n"
        "def pytest_collection_finish(session):\n"
        "    evidence['nodeids'] = [item.nodeid for item in session.items]\n"
        "def pytest_deselected(items):\n"
        "    evidence['deselected'].extend(item.nodeid for item in items)\n"
        "def pytest_runtest_logreport(report):\n"
        "    evidence['reports'].append([report.nodeid, report.when, report.outcome])\n"
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    evidence['exitstatus'] = int(exitstatus)\n"
        "    Path(os.environ['IDENTITY_REPORT']).write_text(json.dumps(evidence))\n"
    )
    home, temporary = tmp_path / "home", tmp_path / "temporary"
    home.mkdir()
    temporary.mkdir()
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    environment.update(
        HOME=str(home),
        USERPROFILE=str(home),
        HERMES_HOME=str(home / "unused-hermes"),
        TMPDIR=str(temporary),
        TMP=str(temporary),
        TEMP=str(temporary),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    rows = tool.windows_package_commands(
        checkout=tmp_path / "unused-checkout",
        bundle=bundle,
        mode=mode,
        basetemp=temporary / "pytest",
        configuration=configuration,
    )
    expected = [
        "tests/integration/test_dbcrypt_windows_vfs.py::test_first",
        "tests/integration/test_dbcrypt_windows_vfs.py::test_second",
    ]
    for row in rows:
        args = list(row["pytest_argv"])
        # Replace only the native plugin; retain the factory's shared pytest tail.
        args[args.index("-p") + 1] = "inert_identity"
        report = tmp_path / f"{row['action']}.json"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", *args, "--noconftest", "-p", "no:cacheprovider"],
            cwd=bundle,
            env={**environment, **row["env"], "IDENTITY_REPORT": str(report)},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        observed = json.loads(report.read_text())
        assert observed["configuration"] == str(configuration)
        assert observed["xfail_strict"] is True
        assert observed["nodeids"] == expected
        assert observed["root"] == str(bundle)
        assert observed["deselected"] == ["tests/integration/test_dbcrypt_windows_vfs.py::test_checkedtest_excluded"]
        assert all(not node.startswith("::") for node in observed["nodeids"] + observed["deselected"])
        assert observed["exitstatus"] == 0
        assert observed["reports"] == (
            []
            if row["action"] == "collect"
            else [[node, phase, "passed"] for node in expected for phase in ("setup", "call", "teardown")]
        )
    assert not (home / "unused-hermes").exists()


def test_legacy_complete_descriptor_cannot_admit_packaged_candidate(tmp_path: Path, monkeypatch) -> None:
    tool, root, checkout, _manifest = full_qualification_fixture(tmp_path, monkeypatch)
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool.validate_windows_qualification(root, checkout=checkout)


def packaged_pipeline_fixture(tmp_path: Path, monkeypatch):
    from tests._dbcrypt_acceptance_evidence import complete_qualification
    from tests._dbcrypt_acceptance_evidence import packaged_pipeline_fixture as prepare

    directory = tmp_path / "prepared-bundle"
    directory.mkdir()
    bundle = bundle_fixture(directory)
    old = complete_qualification(bundle, tmp_path, monkeypatch)
    return (*prepare(old, bundle[1], monkeypatch), bundle[1])


# Exact public owner bytes/text from the Run30 Windows collection failure.
_WINDOWS_OWNER_HEX = "010500000000000515000000fcceaa077e745f7d1a0354daf2030000"
_WINDOWS_OWNER_SID = "S-1-5-21-128634620-2103407742-3662938906-1010"


@pytest.mark.parametrize("damage", [None, "wrong_rid", "truncated", "text_owner", "private_root_refused"])
def test_package_collector_preserves_binary_owner_and_emits_canonical_sid(tmp_path, monkeypatch, damage):
    import contextlib
    import ctypes
    import importlib.metadata
    from types import SimpleNamespace

    import sqlcipher3.dbapi2 as driver

    from mordred_hermes import _database_locking_windows, _private_fs
    from mordred_hermes._database_contracts import RootIdentity
    from mordred_hermes.keyvault import kek
    from tests import _dbcrypt_acceptance_native as collector

    monkeypatch.setattr(kek, "_noop_audit", kek._noop_audit)
    tool = acceptance_tool("dbcrypt_acceptance")
    owner = _WINDOWS_OWNER_HEX
    if damage == "truncated":
        owner = owner[:-2]
    elif damage == "text_owner":
        owner = _WINDOWS_OWNER_SID
    root = tmp_path / "physical-root"
    fixture = tmp_path / "fixtures.json"
    fixture.write_text("{}")
    plan = {"test_root": str(root), "owner_sid": _WINDOWS_OWNER_SID}
    if damage == "wrong_rid":
        plan["owner_sid"] = _WINDOWS_OWNER_SID[:-4] + "1011"
    identity = RootIdentity("win32", 17, "01" * 16, owner)

    @contextlib.contextmanager
    def checked_directory(path):
        assert path == root
        if damage == "private_root_refused":
            raise _private_fs.PrivateFSError("unsafe", "test_root")
        yield None

    monkeypatch.setattr(_private_fs, "open_confidential_directory", checked_directory)
    monkeypatch.setattr(_database_locking_windows, "identify_root", lambda path: identity)
    monkeypatch.setattr(
        ctypes, "windll", SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 0)), raising=False
    )
    monkeypatch.setattr(collector, "sys", SimpleNamespace(platform="win32", executable=sys.executable))
    for name in (
        "MORDRED_DBCRYPT_COLLECTORS_TEST",
        "MORDRED_DBCRYPT_ACCEPTANCE_KIND",
        "MORDRED_WINKEY_HELPER",
        "HERMES_MEMORY_KEY",
        "MORDRED_DBCRYPT_CHECKED_LIBRARY",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "DBCRYPT_BUNDLE": str(tmp_path),
        "MORDRED_DBCRYPT_VFS_DIAGNOSTIC": str(tmp_path / "diagnostic.json"),
        "MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR": str(fixture),
        "MORDRED_DBCRYPT_TEST_ROOT": str(root),
        "MORDRED_DBCRYPT_VFS_PACKAGE_MODE": "source",
    }.items():
        monkeypatch.setenv(name, value)
    # Unavailable Windows/package IO boundaries; SID conversion and collector stay real.
    boundary = {
        **vars(tool),
        "validate_bundle": lambda path: {"checkout": str(tmp_path), "commit": "a" * 40},
        "_local_bundle_proof": lambda *args: {},
        "validate_windows_diagnostic": lambda *args, **kwargs: {
            "provenance": {"headers": {}},
            "diagnostic": {"driver_native_sha256": "b" * 64},
        },
        "_qualification_fixture": lambda *args: plan,
        "matching_build_receipts": lambda *args, **kwargs: [],
        "validate_package_observation": lambda *args, **kwargs: None,
    }
    monkeypatch.setattr(collector, "_tool", lambda: boundary)
    monkeypatch.setattr(collector, "_digest", lambda path: "a" * 64)
    monkeypatch.setattr(
        collector,
        "_observe_packaged_dll",
        lambda: dict.fromkeys(
            (
                "path",
                "sha256",
                "driver_native",
                "driver_native_sha256",
                "record",
                "record_sha256",
                "record_size",
                "installed_at",
            ),
            "b" * 64,
        ),
    )
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.5.7")
    monkeypatch.setattr(
        driver,
        "connect",
        lambda path: SimpleNamespace(
            execute=lambda query: SimpleNamespace(fetchone=lambda: ("4.12.0 community",)),
            close=lambda: None,
        ),
    )
    if damage is not None:
        with pytest.raises((AssertionError, ValueError, _private_fs.PrivateFSError)):
            collector.package_qualification_observation()
    else:
        observed = collector.package_qualification_observation()
        assert observed["sid"] == _WINDOWS_OWNER_SID
        assert observed["filesystem"]["identity"] == {
            "platform": "win32",
            "volume": 17,
            "file_id": "01" * 16,
            "owner": _WINDOWS_OWNER_HEX,
        }


@pytest.mark.parametrize(
    ("owner", "sid", "valid"),
    [
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID, True, id="actual_windows_owner"),
        pytest.param("010100000000000512000000", "S-1-5-18", True, id="system_sid"),
        pytest.param("01010000ffffffffffffffff", "S-1-4294967295-4294967295", True, id="uint32_max"),
        pytest.param("010100010000000000000000", "S-1-0x000100000000-0", True, id="hex_authority"),
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID[:-4] + "1011", False, id="wrong_rid"),
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID.replace("S-1-5", "S-1-6"), False, id="wrong_authority"),
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID + "-0", False, id="extra_subauthority"),
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID.replace("-1010", "-01010"), False, id="leading_zero"),
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID.replace("-1010", "-4294967296"), False, id="rid_overflow"),
        pytest.param(_WINDOWS_OWNER_HEX, "S-1-281474976710656-0", False, id="authority_overflow"),
        pytest.param(_WINDOWS_OWNER_HEX, _WINDOWS_OWNER_SID + " ", False, id="trailing_text"),
        pytest.param(_WINDOWS_OWNER_SID, _WINDOWS_OWNER_SID, False, id="text_owner_alias"),
        pytest.param("S-1-synthetic-ordinary", "S-1-synthetic-ordinary", False, id="fake_alias"),
        *[
            pytest.param(owner, owner, False, id=name)
            for name, owner in (
                ("empty", ""),
                ("invalid_hex", "gg"),
                ("short_header", "0105"),
                ("odd_hex", _WINDOWS_OWNER_HEX[:-1]),
                ("truncated", _WINDOWS_OWNER_HEX[:-2]),
                ("trailing_bytes", _WINDOWS_OWNER_HEX + "00"),
                ("wrong_revision", "02" + _WINDOWS_OWNER_HEX[2:]),
                ("wrong_count", "0104" + _WINDOWS_OWNER_HEX[4:]),
                ("excess_count", "0110000000000005" + "00000000" * 16),
                ("zero_count", "0100000000000005"),
                ("uppercase_hex", _WINDOWS_OWNER_HEX.upper()),
                ("hex_whitespace", "01 " + _WINDOWS_OWNER_HEX[2:]),
            )
        ],
    ],
)
def test_package_validator_requires_canonical_sid_equivalence(tmp_path, monkeypatch, owner, sid, valid):
    tool, root, _checkout, manifest, results, _fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    observed = json.loads((results["source"][0] / "run.json").read_text())["qualification"]
    observed["filesystem"]["identity"]["owner"] = owner
    observed["sid"] = sid
    proof = tool._local_bundle_proof(bundle, manifest)
    proof["bundle_path"] = r"C:\bundle"
    diagnostic = json.loads((root / "provenance.json").read_text())
    kwargs = dict(mode="source", bundle=manifest, proof=proof, directory=bundle, headers=diagnostic["headers"])
    if valid:
        tool.validate_package_observation(observed, **kwargs)
    else:
        with pytest.raises(ValueError, match="inconsistent bundle provenance"):
            tool.validate_package_observation(observed, **kwargs)


def test_packaged_pipeline_assembly_serializes_windows_relative_paths_portably(tmp_path: Path, monkeypatch) -> None:
    class WindowsRelativePath(type(tmp_path)):
        def relative_to(self, *args):
            return PureWindowsPath(super().relative_to(*args).as_posix())

    tool, root, checkout, _manifest, results, _fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    output = WindowsRelativePath(tmp_path / "portable-assembled")
    path = tool.assemble_windows_qualification(
        bundle=bundle,
        diagnostic=root / "manifest.json",
        source_result=results["source"][0] / "result.json",
        wheel_result=results["wheel"][0] / "result.json",
        output=output,
    )
    descriptor = json.loads(path.read_text())
    assert descriptor["results"]["source"]["path"] == "source/result.json"
    assert descriptor["results"]["wheel"]["path"] == "wheel/result.json"
    assert "\\" not in descriptor["wheel_bundle"]["path"]
    tool.validate_windows_qualification(path.parent, checkout=checkout)


def test_packaged_pipeline_assembles_real_inert_artifact_closure_with_distinct_dlls(
    tmp_path: Path, monkeypatch
) -> None:
    tool, root, checkout, _manifest, results, _fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    output = tmp_path / "assembled"
    path = tool.assemble_windows_qualification(
        bundle=bundle,
        diagnostic=root / "manifest.json",
        source_result=results["source"][0] / "result.json",
        wheel_result=results["wheel"][0] / "result.json",
        output=output,
    )
    actual = tool.validate_windows_qualification(path.parent, checkout=checkout)
    assert actual["source"]["dll_sha256"] != actual["wheel"]["dll_sha256"]
    assert actual["diagnostic"]["nodeids"] == tool.windows_vfs_required_nodes(checkout, release=False)
    assert actual["source"]["role"] == "packaged_editable" and actual["wheel"]["role"] == "packaged_wheel"
    historical_plan = json.loads((root / "fixture-plan.json").read_text())["plan"]
    assert actual["fixtures"]["test_root"] != historical_plan["test_root"]
    assert actual["source"]["fixture_root"] == actual["wheel"]["fixture_root"] == actual["fixtures"]["test_root"]
    export = tmp_path / "exported"
    export.mkdir()
    tool._export_windows_qualification({"qualification": str(output)}, export)
    for retained in (output, export / "windows-qualification"):
        for mode in ("source", "wheel"):
            raw = retained / mode / "result.json"
            assert raw.read_bytes() == (results[mode][0] / "result.json").read_bytes()
            value = json.loads(raw.read_text())
            nested = tool._artifact_ref(raw.parent, value["fixtures_descriptor"])
            assert tool.sha256_file(nested) == tool.sha256_file(retained / "fixtures/manifest.json")
            tool._fixture_descriptor(nested)
    damaged = export / "windows-qualification/wheel/fixtures/manifest.json"
    damaged.unlink()
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool.validate_windows_qualification(export / "windows-qualification", checkout=checkout)
    with pytest.raises(OSError):
        tool._qualification_inputs(export / "windows-qualification", json.loads(path.read_text()))
    with pytest.raises(tool.AcceptanceRefused):
        tool.assemble_windows_qualification(
            bundle=bundle,
            diagnostic=root / "manifest.json",
            source_result=results["source"][0] / "result.json",
            wheel_result=results["wheel"][0] / "result.json",
            output=output,
        )


@pytest.mark.parametrize(
    "damage",
    [
        "missing_capture",
        "dll",
        "record",
        "driver",
        "selection",
        "subset",
        "skip",
        "fixture",
        "build_argv",
        "build_input",
        "header",
        "override",
        "current_fixture_mismatch",
        "current_fixture_raw",
    ],
)
def test_packaged_pipeline_refuses_broken_actual_artifact_or_execution_link(
    tmp_path: Path, monkeypatch, damage: str
) -> None:
    tool, root, _checkout, _manifest, results, _fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    source_dir, source = results["source"]
    if damage in {"dll", "record", "driver"}:
        key = {"dll": "dll", "record": "record", "driver": "driver_native"}[damage]
        (source_dir / source["artifacts"][key]["path"]).write_bytes(b"different artifact")
    else:
        path = source_dir / "run.json"
        report = json.loads(path.read_text())
        if damage == "selection":
            report["pytest_argv"].extend(["-k", "focused"])
        elif damage == "subset":
            report["nodeids"] = report["nodeids"][:1]
        elif damage == "skip":
            report["reports"][0]["outcome"] = "skipped"
        elif damage == "fixture":
            report["qualification"]["filesystem"]["identity"]["owner"] = "foreign"
        elif damage == "override":
            report["qualification"]["env_dll_override"] = r"C:\unowned.dll"
        elif damage == "current_fixture_mismatch":
            report["qualification"]["fixture_root"] = r"C:\different-current-guid"
        elif damage == "current_fixture_raw":
            fixture_path = source_dir / "fixtures/manifest.json"
            descriptor = json.loads(fixture_path.read_text())
            (fixture_path.parent / descriptor["fixture_verify"]["path"]).write_text('{"ready": true}')
        else:
            name = report["qualification"]["build_receipts"][0]
            receipt_path = bundle / name
            receipt = json.loads(receipt_path.read_text())
            if damage == "missing_capture":
                report["qualification"]["build_receipts"] = []
            elif damage == "build_argv":
                receipt["argv"].append("-Unreviewed")
            else:
                key = "headers/sqlite3.h" if damage == "header" else "native/dbcrypt-vfs/vfs.c"
                (receipt_path.parent / receipt["inputs"][key]["path"]).write_bytes(b"changed input")
            receipt_path.write_text(json.dumps(receipt))
        path.write_text(json.dumps(report))
        source["run"]["report"]["sha256"] = tool.sha256_file(path)
        (source_dir / "result.json").write_text(json.dumps(source))
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool.assemble_windows_qualification(
            bundle=bundle,
            diagnostic=root / "manifest.json",
            source_result=source_dir / "result.json",
            wheel_result=results["wheel"][0] / "result.json",
            output=tmp_path / "refused",
        )
    assert not (tmp_path / "refused/manifest.json").exists()


def test_candidate_windows_consumes_prerequisite_instead_of_executing_vfs_again() -> None:
    tool = acceptance_tool("dbcrypt_acceptance")
    candidate = tool.native_acceptance_commands(
        checkout=Path("/source"), bundle=Path("/bundle"), platform="win32", kind="candidate"
    )
    rows = [row for row in candidate if row["suite"] == "windows-vfs"]
    assert len(rows) == 2 and all(
        row["status"] == "satisfied_by_qualified_artifact_reference" and "argv" not in row for row in rows
    )
    production = tool.native_acceptance_commands(
        checkout=Path("/source"), bundle=Path("/bundle"), platform="win32", kind="production"
    )
    assert all("argv" in row for row in production if row["suite"] == "windows-vfs")


def test_qualification_plugin_never_enters_custody_or_candidate_branch(tmp_path, monkeypatch) -> None:
    import runpy
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _windows_vfs

    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    configure = helper["pytest_configure"]

    def forbidden(*args, **kwargs):
        raise AssertionError("qualification entered native custody")

    monkeypatch.setitem(configure.__globals__, "native_facts", forbidden)
    monkeypatch.setitem(configure.__globals__, "candidate_eligibility", forbidden)
    monkeypatch.setitem(
        configure.__globals__, "package_qualification_observation", lambda: {"role": "controlled parser observation"}
    )
    monkeypatch.setitem(configure.__globals__, "_digest", lambda path: "a" * 64)
    monkeypatch.setenv("MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY", "1")
    monkeypatch.setenv("MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR", "/fixture/manifest.json")
    loader = tmp_path / "_windows_vfs.py"
    loader.write_text("NATIVE_QUALIFIED: bool = False\n")
    monkeypatch.setattr(_windows_vfs, "__file__", str(loader))
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", False)
    cleanups, reports = [], []
    config = SimpleNamespace(
        invocation_params=SimpleNamespace(args=("fixed",)),
        add_cleanup=cleanups.append,
        pluginmanager=SimpleNamespace(register=lambda reporter, name: reports.append(reporter)),
    )
    configure(config)
    assert _windows_vfs.NATIVE_QUALIFIED is True and reports[0].qualification is not None
    cleanups[0]()
    assert _windows_vfs.NATIVE_QUALIFIED is False


def test_packaged_producer_reaches_only_fixed_children_without_custody_and_retains_failure(
    tmp_path: Path, monkeypatch
) -> None:
    from types import SimpleNamespace

    tool, root, checkout, manifest, results, fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    original_diagnostic = tool.validate_windows_diagnostic
    monkeypatch.setattr(
        tool,
        "validate_windows_diagnostic",
        lambda directory, **kwargs: original_diagnostic(directory, checkout=checkout),
    )
    monkeypatch.setattr(tool, "sys", SimpleNamespace(platform="win32"))
    calls = []

    def child(argv, **kwargs):
        assert argv[:4] == ["uv", "run", "--no-project", "--python"]
        env = kwargs["env"]
        assert env["MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY"] == "1"
        assert not any(
            key in env
            for key in ("MORDRED_WINKEY_HELPER", "MORDRED_DBCRYPT_COLLECTORS_TEST", "MORDRED_DBCRYPT_ACCEPTANCE_KIND")
        )
        action = "collect" if argv[-1] == "--collect-only" else "run"
        Path(env["MORDRED_DBCRYPT_PYTEST_REPORT"]).write_bytes((results["wheel"][0] / (action + ".json")).read_bytes())
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(tool.subprocess, "run", child)
    output = tmp_path / "producer-output"
    # Modelled guest artifact paths cannot be opened on this inert host; keep
    # that honest failure, after proving both fixed children are dispatched.
    with pytest.raises(tool.AcceptanceRefused, match="packaged_windows_qualification_failed"):
        tool.qualify_windows_vfs(
            bundle=bundle,
            mode="wheel",
            diagnostic=root / "manifest.json",
            fixtures=fixtures / "manifest.json",
            output=output,
        )
    expected = tool.windows_package_commands(
        checkout=Path(manifest["checkout"]),
        bundle=bundle,
        mode="wheel",
        basetemp=output / "pytest-temp",
        configuration=bundle / manifest["extracted_sdist"] / "pyproject.toml",
    )
    assert calls == [row["argv"] for row in expected]
    assert json.loads((output / "result.json").read_text())["status"] == "failed"


@pytest.mark.parametrize(
    ("existing", "native_failure"),
    [(None, False), (None, True), ("directory", False), ("file", False), ("link", False), ("dangling-link", False)],
)
def test_bundle_build_windows_receipt_constructor(tmp_path: Path, monkeypatch, existing, native_failure) -> None:
    """Python 3.11's observed OW ACL must never reach the strict build hook."""
    import ast
    import ctypes
    from contextlib import contextmanager
    from types import SimpleNamespace

    from mordred_hermes import _private_fs

    tool = acceptance_tool("dbcrypt_acceptance")
    # Load only the pure admission predicate, without requiring the build-time
    # hatchling dependency or importing/executing any build entrypoint.
    hook_path = Path(__file__).resolve().parents[1] / "hatch_build.py"
    hook_ast = ast.parse(hook_path.read_text())
    predicate = next(
        node for node in hook_ast.body if isinstance(node, ast.FunctionDef) and node.name == "_receipt_dacl_allowed"
    )
    hook = {"Any": object}
    exec(compile(ast.Module(body=[predicate], type_ignores=[]), str(hook_path), "exec"), hook)
    output, checkout, home = tmp_path / "bundle", tmp_path / "checkout", tmp_path / "synthetic-home"
    output.mkdir()
    home.mkdir()
    receipts = output / "artifacts/native-build/wheel"
    user = "S-1-5-21-128634620-2103407742-3662938906-1010"
    allowed = {user, "S-1-5-18", "S-1-5-32-544"}
    trustees = []
    python_leaf_creations = []
    native_creations = []
    closed = []
    original_mkdir = Path.mkdir

    def mkdir(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if path == output / "artifacts" and existing is not None:
            original_mkdir(receipts.parent)
            if existing == "directory":
                original_mkdir(receipts)
            elif existing == "file":
                receipts.write_bytes(b"retained failure")
            else:
                target = tmp_path / "link-target"
                if existing == "link":
                    original_mkdir(target)
                receipts.symlink_to(target, target_is_directory=True)
        if path == receipts:
            python_leaf_creations.append(path)
            trustees[:] = ["S-1-3-4", "S-1-5-18", "S-1-5-32-544"]
        return result

    @contextmanager
    def native_directory(path, *, create=False):
        assert path == receipts and create is True
        assert os.environ["HERMES_HOME"] == str(home)
        assert not path.exists() and not path.is_symlink()
        native_creations.append(path)
        if native_failure:
            raise _private_fs.PrivateFSError("access_denied", "private diagnostic must not escape")
        original_mkdir(path)
        trustees[:] = [user, "S-1-5-18", "S-1-5-32-544"]
        try:
            yield None
        finally:
            closed.append(path)

    class FirstPackageCommand(Exception):
        pass

    def first_build(argv, *, cwd, environment, log):
        assert existing is None and not native_failure, "package command after constructor refusal"
        assert argv == ["uv", "build", "--sdist", str(checkout), "--out-dir", str(output / "artifacts")]
        assert cwd == output and log == []
        assert environment["HERMES_HOME"] == str(home)
        assert environment["MORDRED_DBCRYPT_BUILD_RECEIPT_DIR"] == str(receipts)
        # Exercise the unchanged hook predicate using inert ACE buffers. No
        # Windows API, package manager, compiler, helper or custody operation.
        aces = [ctypes.create_string_buffer(b"\0" * 9) for _ in trustees]
        sid_names = {ctypes.addressof(ace) + 8: sid for ace, sid in zip(aces, trustees, strict=True)}

        def get_ace(_dacl, index, pointer):
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(aces[index])
            return True

        assert hook["_receipt_dacl_allowed"](
            SimpleNamespace(GetAce=get_ace), None, len(aces), allowed, lambda pointer: sid_names[pointer.value]
        ), "strict hook rejects the observed Owner Rights ACL"
        assert closed == [receipts]
        raise FirstPackageCommand

    monkeypatch.setattr(tool, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(_private_fs, "open_private_directory", native_directory)
    monkeypatch.setattr(tool, "_run_build", first_build)
    prior_home = os.environ.get("HERMES_HOME")
    if existing is not None:
        with pytest.raises(tool.AcceptanceRefused, match=r"^bundle_receipt_directory_already_exists$"):
            tool._bundle_build(checkout, output, [], home)
        assert native_creations == []
        if existing == "file":
            assert receipts.read_bytes() == b"retained failure"
        elif existing in {"link", "dangling-link"}:
            assert receipts.is_symlink()
        else:
            assert receipts.is_dir() and list(receipts.iterdir()) == []
    elif native_failure:
        with pytest.raises(tool.AcceptanceRefused, match=r"^bundle_receipt_directory_unavailable$"):
            tool._bundle_build(checkout, output, [], home)
        assert native_creations == [receipts] and not receipts.exists()
    else:
        with pytest.raises(FirstPackageCommand):
            tool._bundle_build(checkout, output, [], home)
        assert native_creations == [receipts]
    assert python_leaf_creations == []
    assert os.environ.get("HERMES_HOME") == prior_home


def test_outer_package_manager_output_is_not_compiler_receipt(tmp_path: Path, monkeypatch) -> None:
    from types import SimpleNamespace

    tool = acceptance_tool("dbcrypt_acceptance")
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="https://user:secret@index.invalid", stderr="password"
        ),
    )
    records = []
    tool._run_build(["uv", "build"], cwd=tmp_path, environment={}, log=records)
    assert "secret" not in json.dumps(records) and "password" not in json.dumps(records)


def test_packaged_receipt_must_belong_to_the_actual_bundle_wheel_build_interval(tmp_path: Path, monkeypatch) -> None:
    tool, _root, _checkout, manifest, results, _fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    observation = json.loads((results["wheel"][0] / "run.json").read_text())["qualification"]
    receipt_path = bundle / observation["build_receipts"][0]
    receipt = json.loads(receipt_path.read_text())
    receipt.update(started_at=1.0, finished_at=2.0)
    receipt_path.write_text(json.dumps(receipt))
    manifest["files"] = tool._bundle_hashes(bundle)
    (bundle / "manifest.json").write_text(json.dumps(manifest))
    observation["bundle_manifest_sha256"] = tool.sha256_file(bundle / "manifest.json")
    proof = tool._local_bundle_proof(bundle, manifest)
    proof["bundle_path"] = r"C:\bundle"
    diagnostic = json.loads((_root / "provenance.json").read_text())
    with pytest.raises(ValueError, match="inconsistent bundle provenance"):
        tool.validate_package_observation(
            observation, mode="wheel", bundle=manifest, proof=proof, directory=bundle, headers=diagnostic["headers"]
        )


def test_full8_explicit_reviewed_source_configuration_is_bound(tmp_path: Path, monkeypatch) -> None:
    tool, root, checkout, manifest = full_qualification_fixture(tmp_path, monkeypatch)
    actual = tool._validate_legacy_windows_qualification(root, checkout=checkout)
    assert actual["diagnostic"]["argv"][1:3] == ["-c", r"C:\qualified\source\pyproject.toml"]
    assert manifest["configuration"]["sha256"] == tool.sha256_file(checkout / "pyproject.toml")


def test_consistently_narrowed_collection_and_run_still_missing_a_crash_case_refuses(tmp_path: Path) -> None:
    tool, spool, phase = complete_native_phase_fixture(tmp_path)
    native = next(row for row in phase["executions"] if row.get("suite") == "dbcrypt-native")
    for reference in (native["pytest_report"], native["collection"]["report"]):
        path = spool / reference["path"]
        report = json.loads(path.read_text())
        report["nodeids"] = [node for node in report["nodeids"] if "encrypt-prepared" not in node]
        report["reports"] = [row for row in report["reports"] if row["nodeid"] in report["nodeids"]]
        path.write_text(json.dumps(report))
        reference["sha256"] = tool.sha256_file(path)
    native["nodeids"] = [node for node in native["nodeids"] if "encrypt-prepared" not in node]
    for counts in (native["counts"], phase["test_counts"]):
        counts["passed"] -= 1
    phase["test_counts"]["collected"] -= 1
    with pytest.raises(tool.AcceptanceRefused, match="native_phase_evidence_incomplete"):
        tool.validate_native_phase_evidence(phase, directory=spool)


def test_offline_wheel_phase_refuses_the_source_import_probe(tmp_path: Path) -> None:
    tool, spool, phase = complete_native_phase_fixture(tmp_path, mode="wheel")
    row = phase["executions"][0]
    path, proof = tool._evidence_ref(spool, phase["bundle_evidence"])
    _, bundle = tool._evidence_ref(path.parent, proof["manifest"])
    row["import_probe"] = bundle["source_probe"]
    with pytest.raises(tool.AcceptanceRefused, match="native_phase_evidence_incomplete"):
        tool.validate_native_phase_evidence(phase, directory=spool)


@pytest.mark.parametrize("removed", ["runtime", "config_decrypt", "both"])
def test_offline_bundle_refuses_consistently_omitted_pth_inputs(tmp_path: Path, removed: str) -> None:
    tool, spool, phase = complete_native_phase_fixture(tmp_path)
    proof_path, proof = tool._evidence_ref(spool, phase["bundle_evidence"])
    manifest_path, manifest = tool._evidence_ref(proof_path.parent, proof["manifest"])
    tool.validate_bundle_evidence(proof, directory=proof_path.parent)
    names = ("runtime", "config_decrypt") if removed == "both" else (removed,)
    for name in names:
        relative = f"packaging/pth/mordred_hermes_{name}.pth"
        del manifest["files"][relative]
        del proof["inputs"][relative]
    manifest_path.write_text(json.dumps(manifest))
    proof["manifest"]["sha256"] = tool.sha256_file(manifest_path)
    with pytest.raises(ValueError, match="inconsistent bundle provenance"):
        tool.validate_bundle_evidence(proof, directory=proof_path.parent)


def test_offline_exported_input_hash_update_cannot_hide_inventory_drift(tmp_path: Path) -> None:
    tool, spool, phase = complete_native_phase_fixture(tmp_path)
    path, proof = tool._evidence_ref(spool, phase["bundle_evidence"])
    reference = proof["inputs"]["tests/_dbcrypt_acceptance_native.py"]
    exported = path.parent / reference["path"]
    exported.write_text("# changed input; no longer the recorded implementation\n")
    reference["sha256"] = tool.sha256_file(exported)
    path.write_text(json.dumps(proof))
    phase["bundle_evidence"]["sha256"] = tool.sha256_file(path)
    with pytest.raises(tool.AcceptanceRefused, match="native_phase_evidence_incomplete"):
        tool.validate_native_phase_evidence(phase, directory=spool)


@pytest.mark.parametrize("damage", ["path", "bytes", "wheel_dll", "missing_wheel_row"])
def test_full8_configuration_and_actual_wheel_dll_remain_bound(tmp_path: Path, monkeypatch, damage: str) -> None:
    tool, root, checkout, manifest = full_qualification_fixture(tmp_path, monkeypatch)

    def rewrite(reference, edit):
        path = root / reference["path"]
        row = json.loads(path.read_text())
        edit(row)
        path.write_text(json.dumps(row))
        reference["sha256"] = tool.sha256_file(path)

    if damage == "path":
        rewrite(
            manifest["rows"]["checkedtest_source"]["run"],
            lambda row: row["argv"].__setitem__(2, r"C:\unrelated\pyproject.toml"),
        )
    elif damage == "bytes":
        path = root / manifest["configuration"]["path"]
        path.write_text(path.read_text() + "\n# different settings\n")
        manifest["configuration"]["sha256"] = tool.sha256_file(path)
    elif damage == "missing_wheel_row":
        del manifest["rows"]["checked_wheel"]
    else:
        reference = manifest["artifacts"]["checked_wheel"]["dll"]
        path = root / reference["path"]
        path.write_bytes(b"different DLL from the recorded packaged wheel")
        reference["sha256"] = tool.sha256_file(path)
        for row_ref in manifest["rows"]["checked_wheel"].values():
            rewrite(row_ref, lambda row: row.update(dll_sha256=reference["sha256"]))
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool._validate_legacy_windows_qualification(root, checkout=checkout)


def test_full8_reused_source_builds_bind_actual_artifacts_and_all_critical_inputs(tmp_path: Path, monkeypatch) -> None:
    tool, root, checkout, manifest = full_qualification_fixture(tmp_path, monkeypatch)
    path = root / manifest["provenance"]["path"]
    provenance = json.loads(path.read_text())
    critical = {
        key: digest
        for key, digest in provenance["source_hashes"].items()
        if key.startswith(("native/dbcrypt-vfs/", "src/mordred_hermes/_private_fs/"))
        or key == "src/mordred_hermes/dbcrypt/_windows_vfs.py"
    }
    reused = {}
    for name in ("checkedtest_source", "checked_source"):
        run = json.loads((root / manifest["rows"][name]["run"]["path"]).read_text())
        reused[run["target"]] = {
            "dll_sha256": run["dll_sha256"],
            "actual_build_stdout_sha256": manifest["artifacts"][name]["build_stdout"]["sha256"],
            "critical_inputs": critical,
            "headers": provenance["headers"],
            "cached_runtime": {
                run["executable"]: run["python_sha256"],
                run["driver_native"]: run["driver_native_sha256"],
            },
        }
    provenance["reused_builds"] = reused
    path.write_text(json.dumps(provenance))
    manifest["provenance"]["sha256"] = tool.sha256_file(path)
    (root / "manifest.json").write_text(json.dumps(manifest))
    assert (
        tool._validate_legacy_windows_qualification(root, checkout=checkout)["source"]["dll_sha256"]
        != tool._validate_legacy_windows_qualification(root, checkout=checkout)["wheel"]["dll_sha256"]
    )
    provenance["reused_builds"]["CheckedTest"]["critical_inputs"] = {
        "native/dbcrypt-vfs/vfs.c": critical["native/dbcrypt-vfs/vfs.c"]
    }
    path.write_text(json.dumps(provenance))
    manifest["provenance"]["sha256"] = tool.sha256_file(path)
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(tool.AcceptanceRefused, match="windows_native_qualification_incomplete"):
        tool._validate_legacy_windows_qualification(root, checkout=checkout)


def test_production_vfs_plans_execute_both_owned_release_selections():
    tool = acceptance_tool("dbcrypt_acceptance")
    rows = tool.native_acceptance_commands(
        checkout=Path("/source"), bundle=Path("/bundle"), platform="win32", kind="production"
    )
    vfs = [row for row in rows if row["suite"] == "windows-vfs"]
    assert {row["mode"] for row in vfs} == {"source", "wheel"}
    for row in vfs:
        assert row["argv"][row["argv"].index("-k") + 1] == tool.WINDOWS_RELEASE_SELECTION
        assert row["library_kind"] == "packaged Checked"


def test_activated_qualification_never_assigns_runtime_eligibility(monkeypatch):
    import runpy
    from types import ModuleType, SimpleNamespace

    import mordred_hermes.dbcrypt as package
    from mordred_hermes.dbcrypt import _windows_vfs

    class NoEligibilityAssignment(ModuleType):
        def __setattr__(self, name, value):
            if name == "NATIVE_QUALIFIED":
                raise AssertionError("activated qualification assigned eligibility")
            super().__setattr__(name, value)

    actual = NoEligibilityAssignment(_windows_vfs.__name__)
    actual.__dict__.update(_windows_vfs.__dict__)
    actual.__dict__["NATIVE_QUALIFIED"] = True
    monkeypatch.setattr(package, "_windows_vfs", actual)
    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    configure = helper["pytest_configure"]
    monkeypatch.setitem(
        configure.__globals__,
        "package_qualification_observation",
        lambda: {"eligibility": {"bootstrap": "automatic_production"}},
    )
    monkeypatch.setitem(configure.__globals__, "_digest", lambda path: "a" * 64)
    monkeypatch.setenv("MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY", "1")
    monkeypatch.setenv("MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR", "/fixture/manifest.json")
    cleanups, reports = [], []
    configure(
        SimpleNamespace(
            invocation_params=SimpleNamespace(args=()),
            add_cleanup=cleanups.append,
            pluginmanager=SimpleNamespace(register=lambda reporter, name: reports.append(reporter)),
        )
    )
    assert actual.NATIVE_QUALIFIED is True and cleanups == []
    assert reports[0].qualification["eligibility"]["bootstrap"] == "automatic_production"


@pytest.mark.parametrize("damage", ["missing", "candidate", "observed_false", "declared_false", "extra_field"])
def test_package_observation_rejects_missing_or_promoted_eligibility(tmp_path, monkeypatch, damage):
    tool, root, _checkout, manifest, results, _fixtures, bundle = packaged_pipeline_fixture(tmp_path, monkeypatch)
    observed = json.loads((results["source"][0] / "run.json").read_text())["qualification"]
    eligibility = {"declared_qualified": True, "observed_qualified": True, "bootstrap": "automatic_production"}
    if damage == "candidate":
        eligibility["bootstrap"] = "explicit_candidate"
    elif damage == "observed_false":
        eligibility["observed_qualified"] = False
    elif damage == "declared_false":
        eligibility["declared_qualified"] = False
    elif damage == "extra_field":
        eligibility["approved"] = True
    if damage != "missing":
        observed["eligibility"] = eligibility
    else:
        observed.pop("eligibility", None)
    proof = tool._local_bundle_proof(bundle, manifest)
    proof["bundle_path"] = r"C:\bundle"
    headers = json.loads((root / "provenance.json").read_text())["headers"]
    with pytest.raises((ValueError, KeyError)):
        tool.validate_package_observation(
            observed, mode="source", bundle=manifest, proof=proof, directory=bundle, headers=headers
        )


@pytest.mark.parametrize("mode", ["source", "wheel"])
@pytest.mark.parametrize("damage", ["candidate", "missing", "integer_flag"])
def test_production_qualification_refuses_candidate_or_untyped_package_rows(mode, damage):
    tool = acceptance_tool("dbcrypt_acceptance")
    eligible = {"declared_qualified": True, "observed_qualified": True, "bootstrap": "automatic_production"}
    qualified = {name: {"eligibility": dict(eligible)} for name in ("source", "wheel")}
    tool.require_production_qualification(qualified)
    if damage == "candidate":
        qualified[mode]["eligibility"] = {
            "declared_qualified": False,
            "observed_qualified": True,
            "bootstrap": "explicit_candidate",
        }
    elif damage == "missing":
        del qualified[mode]["eligibility"]
    else:
        qualified[mode]["eligibility"]["observed_qualified"] = 1
    with pytest.raises((ValueError, KeyError)):
        tool.require_production_qualification(qualified)


@pytest.mark.parametrize("declared,observed", [(True, False), (False, True)])
def test_qualification_rejects_handpatched_initial_eligibility(tmp_path, monkeypatch, declared, observed):
    import runpy
    from types import SimpleNamespace

    from mordred_hermes.dbcrypt import _windows_vfs

    loader = tmp_path / "_windows_vfs.py"
    loader.write_text(f"NATIVE_QUALIFIED: bool = {declared!r}\n")
    monkeypatch.setattr(_windows_vfs, "__file__", str(loader))
    monkeypatch.setattr(_windows_vfs, "NATIVE_QUALIFIED", observed)
    monkeypatch.setenv("MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY", "1")
    helper = runpy.run_path(str(Path(__file__).parent / "_dbcrypt_acceptance_native.py"))
    with pytest.raises(AssertionError, match="runtime eligibility differs"):
        helper["pytest_configure"](SimpleNamespace())


@pytest.mark.parametrize(
    "case",
    [
        "test_automatic_native_startup_installs_real_guarded_shim[linux]",
        "test_automatic_native_startup_installs_real_guarded_shim[win32]",
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody[driver]",
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody[asset]",
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody[qualification]",
    ],
)
def test_startup_posix_fixture_na_is_exact_and_never_native(case, monkeypatch):
    tool = acceptance_tool("dbcrypt_acceptance")
    identity = "test_dbcrypt_capability.py::" + case
    node = "tests/" + identity
    reason = "uses the POSIX authority fixture; Windows native proof is explicit"
    assert tool.WINDOWS_PLATFORM_NA[identity] == (reason, "windows_posix_authority_fixture")
    assert tool.platform_na_reason(node, reason) == "windows_posix_authority_fixture"
    for rejected in (node.split("[")[0], node + "[extra]", node.replace(case, "test_unrecognized")):
        assert tool.platform_na_reason(rejected, reason) is None
    assert tool.platform_na_reason(node, reason + " extra") is None
    assert tool.platform_na_reason(node, reason, platform="linux") is None
    assert tool.platform_na_reason(node, reason, suite="native-storage") is None
    report = {
        "nodeids": [node],
        "deselected": [],
        "collection_errors": [],
        "exitstatus": 0,
        "reports": [
            {"nodeid": node, "when": "setup", "outcome": "skipped", "reason_code": "windows_posix_authority_fixture"},
            {"nodeid": node, "when": "teardown", "outcome": "passed", "reason_code": None},
        ],
    }
    assert tool.validate_native_test_report(report, platform="win32", suite="affected")["counts"] == {
        "passed": 0,
        "platform_na": 1,
        "skipped": 0,
    }
    for suite in ("native-storage", "windows-vfs"):
        with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
            tool.validate_native_test_report(report, platform="win32", suite=suite)
    report["reports"][0]["reason_code"] = "unrecognized_skip"
    with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
        tool.validate_native_test_report(report, platform="win32", suite="affected")
    report["reports"][0]["reason_code"] = "windows_posix_authority_fixture"
    monkeypatch.delitem(tool.WINDOWS_PLATFORM_NA, identity)
    with pytest.raises(tool.AcceptanceRefused, match="native_test_results_incomplete"):
        tool.validate_native_test_report(report, platform="win32", suite="affected")


@pytest.mark.parametrize(
    "name",
    [
        "test_automatic_native_startup_installs_real_guarded_shim",
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody",
    ],
)
def test_startup_posix_fixture_skip_precedes_fixture_setup(name):
    import ast

    source = ast.parse((Path(__file__).parent / "test_dbcrypt_capability.py").read_text())
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == name)
    skips = [
        node
        for node in function.decorator_list
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "skipif"
    ]
    assert len(skips) == 1
    assert ast.dump(skips[0].args[0]) == ast.dump(ast.parse('os.name != "posix"', mode="eval").body)
    assert {kw.arg: ast.literal_eval(kw.value) for kw in skips[0].keywords} == {
        "reason": "uses the POSIX authority fixture; Windows native proof is explicit",
    }


def test_offline_native_evidence_rejects_runtime_label_on_passive_preflight(tmp_path):
    tool, spool, phase = complete_native_phase_fixture(tmp_path)
    phase["executions"][0]["payload"]["bootstrap"] = "automatic_production"
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_native_phase_evidence(phase, directory=spool)


@pytest.mark.parametrize(
    "damage",
    [
        "runtime_provision",
        "passive_read",
        "runtime_preflight_driver",
        "missing_ceremony",
        "extra_ceremony",
        "wrong_home",
        "fake_command",
        "wrong_entrypoint_hash",
        "wrong_entrypoint_bytes",
        "nonzero_ceremony",
        "out_of_order",
        "fabricated_root",
    ],
)
def test_native_ceremony_evidence_rejects_role_or_entrypoint_substitution(tmp_path, damage):
    tool, spool, phase = complete_native_phase_fixture(tmp_path)
    provision = next(row for row in phase["executions"] if row.get("operation") == "provision")
    preflight = phase["executions"][0]
    read = phase["executions"][-1]
    if damage == "runtime_provision":
        provision["payload"]["bootstrap"] = "automatic_production"
    elif damage == "passive_read":
        read["payload"]["bootstrap"] = "passive_prerequisite"
    elif damage == "runtime_preflight_driver":
        preflight["argv"][1] = str(Path(preflight["argv"][1]).with_name("hermes"))
    elif damage == "missing_ceremony":
        provision["payload"]["ceremonies"].pop()
    elif damage == "extra_ceremony":
        provision["payload"]["ceremonies"].append(provision["payload"]["ceremonies"][0])
    elif damage == "wrong_home":
        provision["payload"]["ceremonies"][0]["home"] += "-other"
    elif damage == "fake_command":
        provision["payload"]["ceremonies"][0]["argv"] = ["hermes", "provision"]
    elif damage == "wrong_entrypoint_hash":
        provision["payload"]["ceremonies"][0]["entrypoint_sha256"] = "0" * 64
    elif damage == "wrong_entrypoint_bytes":
        (spool / provision["maintenance_entrypoint_ref"]["path"]).write_bytes(b"substituted console code")
    elif damage == "nonzero_ceremony":
        provision["payload"]["ceremonies"][0]["returncode"] = 1
    elif damage == "out_of_order":
        provision["payload"]["ceremonies"].reverse()
    elif damage == "fabricated_root":
        provision["payload"]["facts"]["filesystem"]["scope"] = "root"
    with pytest.raises(tool.AcceptanceRefused):
        tool.validate_native_phase_evidence(phase, directory=spool)


@pytest.fixture
def native_suite_environment_boundary(tmp_path, monkeypatch):
    """Keep the real scrub/build path; stop at the first subprocess boundary."""
    from types import SimpleNamespace

    tool = acceptance_tool("dbcrypt_acceptance")
    monkeypatch.setattr(tool, "sys", SimpleNamespace(platform="linux"))
    for name in (
        "MORDRED_ACCEPTANCE_COMMIT",
        "MORDRED_LINUX_TPM_PROVIDER",
        "MORDRED_PRIVATE_SECRET",
        "MORDRED_TPM_TEST",
    ):
        monkeypatch.setenv(name, "untrusted-ambient")
    context = {
        "bundle": tmp_path / "bundle",
        "manifest": {"checkout": str(tmp_path / "checkout"), "extracted_sdist": "sdist", "commit": "a" * 40},
        "mode": "wheel",
        "kind": "production",
        "fixtures": {kind: tmp_path / kind for kind in ("persistence", "crash", "negative")},
        "helper_name": "MORDRED_TPMKEY_HELPER",
        "helper": tmp_path / "never-executed-helper",
        "helper_copy_manifest": tmp_path / "helper.json",
        "parent": tmp_path,
    }
    monkeypatch.setattr(tool, "validate_bundle", lambda *_: None)
    monkeypatch.setattr(tool, "require_native_source_checkout", lambda *_: None)
    monkeypatch.setattr(tool, "probe_interpreter", lambda *_a, **_k: {"product_file": str(tmp_path)})
    monkeypatch.setattr(tool, "validate_import_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(tool, "_native_driver", lambda *_: tmp_path / "hermes")
    captured = []

    class ReachedCollection(Exception):
        pass

    def capture(_context, argv, environment, **kwargs):
        captured.append((argv, environment, kwargs))
        raise ReachedCollection

    monkeypatch.setattr(tool, "_native_process", capture)
    directory = tmp_path / "evidence"
    directory.mkdir()
    row = {"suite": "linux-memory", "env": {"MORDRED_LINUX_ORCHESTRATION_TEST": "1"}, "argv": ["inert-pytest"]}
    return tool, context, row, directory, captured, ReachedCollection


def test_linux_memory_suite_supplies_observed_metadata_after_environment_scrub(
    native_suite_environment_boundary, monkeypatch
):
    tool, context, row, directory, captured, stopped = native_suite_environment_boundary
    context.update(control_action_path=directory.parent / "action.json", control_action={"sha256": "b" * 64})
    facts = {"native_provider": "EC2 NitroTPM"}
    monkeypatch.setattr(tool, "_collector_child", lambda *_: {"payload": {"facts": facts}})
    monkeypatch.setattr(tool, "_write_new", lambda *_: None)
    row["mode"] = "wheel"
    monkeypatch.setattr(tool, "native_acceptance_commands", lambda **_: [row])
    with pytest.raises(stopped):
        tool._execute_native_phase(context, phase="provision", directory=directory)
    argv, environment, call = captured[0]
    assert environment["MORDRED_ACCEPTANCE_COMMIT"] == context["manifest"]["commit"]
    assert environment["MORDRED_LINUX_TPM_PROVIDER"] == "EC2 NitroTPM"
    assert environment["MORDRED_LINUX_ORCHESTRATION_TEST"] == "1"
    assert environment["MORDRED_TPMKEY_HELPER"] == str(context["helper"])
    assert environment["HERMES_HOME"] == str(context["fixtures"]["persistence"])
    assert "MORDRED_PRIVATE_SECRET" not in environment and "MORDRED_TPM_TEST" not in environment
    assert argv[-1] == "--collect-only" and call["name"] == "linux-memory-collection"
    assert argv[argv.index("--rootdir") + 1] == str(context["bundle"])


@pytest.mark.parametrize(
    "facts", [None, {}, {"native_provider": "software TPM"}, {"native_provider": "Microsoft Platform Crypto Provider"}]
)
def test_linux_memory_suite_refuses_unobserved_or_wrong_provider(native_suite_environment_boundary, facts):
    tool, context, row, directory, captured, _ = native_suite_environment_boundary
    with pytest.raises(ValueError, match="inconsistent bundle provenance"):
        tool._native_suite(context, row, directory, directory / "baseline", native_facts=facts)
    assert captured == []


@pytest.mark.parametrize("damage", ["commit", "platform"])
def test_linux_memory_suite_refuses_invalid_metadata_context(native_suite_environment_boundary, damage):
    tool, context, row, directory, captured, _ = native_suite_environment_boundary
    if damage == "commit":
        context["manifest"]["commit"] = "unverified"
    else:
        tool.sys.platform = "win32"
    with pytest.raises(ValueError, match="inconsistent bundle provenance"):
        tool._native_suite(
            context, row, directory, directory / "baseline", native_facts={"native_provider": "EC2 NitroTPM"}
        )
    assert captured == []


def test_other_native_suite_does_not_inherit_linux_metadata(native_suite_environment_boundary):
    tool, context, row, directory, captured, stopped = native_suite_environment_boundary
    row.update(suite="affected", env={})
    with pytest.raises(stopped):
        tool._native_suite(context, row, directory, directory / "baseline")
    environment = captured[0][1]
    assert (
        not {"MORDRED_ACCEPTANCE_COMMIT", "MORDRED_LINUX_TPM_PROVIDER", "MORDRED_PRIVATE_SECRET", "MORDRED_TPM_TEST"}
        & environment.keys()
    )


def test_native_phase_supplies_successful_seed_facts_to_suite(tmp_path, monkeypatch):
    tool = acceptance_tool("dbcrypt_acceptance")
    facts = {"native_provider": "EC2 NitroTPM", "boot": "observed-seed"}
    fixtures = {kind: tmp_path / kind for kind in ("persistence", "crash", "negative")}
    context = {
        "fixtures": fixtures,
        "control_action_path": tmp_path / "action.json",
        "control_action": {"sha256": "a" * 64},
        "manifest": {"checkout": str(tmp_path)},
        "bundle": tmp_path / "bundle",
        "kind": "production",
        "mode": "wheel",
    }
    monkeypatch.setattr(
        tool,
        "_collector_child",
        lambda _c, root, op, _d: {
            "payload": {
                "facts": facts if root == fixtures["persistence"] and op == "seed" else {"native_provider": "other"}
            }
        },
    )
    monkeypatch.setattr(tool, "_write_new", lambda *_: None)
    monkeypatch.setattr(tool, "native_acceptance_commands", lambda **_: [{"mode": "wheel", "argv": ["unused"]}])

    class ReachedSuite(Exception):
        pass

    def suite(_context, _row, _directory, _baseline, **kwargs):
        assert kwargs["native_facts"] is facts
        raise ReachedSuite

    monkeypatch.setattr(tool, "_native_suite", suite)
    with pytest.raises(ReachedSuite):
        tool._execute_native_phase(context, phase="provision", directory=tmp_path / "evidence")
