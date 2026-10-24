"""Acceptance bookkeeping rejects provenance gaps; fixtures are never native proof."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

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
