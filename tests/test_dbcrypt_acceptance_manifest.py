"""Acceptance bookkeeping rejects provenance gaps; fixtures are never native proof."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from tests._dbcrypt_support import acceptance_tool


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
        probes[mode + "_probe"] = {
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
    assert source["argv"][:6] == ["uv", "run", "--project", str(checkout), "pytest", "-q"]
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
    assert "native_collectors_not_integrated" in reasons


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
    assert tool.run_acceptance(root=root, phase="verify", output=output) == 2
    evidence = json.loads(output.read_text())
    assert evidence["bundle"]["commit"] == manifest["commit"]
    assert evidence["bundle_manifest_sha256"] == tool.sha256_file(bundle / "manifest.json")
    assert evidence["test_counts"] == {"passed": 0, "failed": 0, "skipped": 0, "collected": 0}
    assert "native_collectors_not_integrated" in evidence["reasons"]
    test.write_text("tampered\n")
    output = tmp_path / "tampered.json"
    assert tool.run_acceptance(root=root, phase="verify", output=output) == 2
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
