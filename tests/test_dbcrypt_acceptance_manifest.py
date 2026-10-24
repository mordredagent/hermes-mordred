"""Acceptance bookkeeping rejects provenance gaps; fixtures are never native proof."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from tests._dbcrypt_support import acceptance_tool


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
    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    test = bundle / "tests/test_dbcrypt.py"
    test.parent.mkdir()
    test.write_text("pass\n")
    manifest = {"schema_version": 1, "files": {"tests/test_dbcrypt.py": tool.sha256_file(test)}}
    (bundle / "manifest.json").write_text(json.dumps(manifest))
    assert tool.validate_bundle(bundle)["files"] == manifest["files"]
    test.write_text("changed\n")
    with pytest.raises(tool.AcceptanceRefused, match="bundle_hash_mismatch"):
        tool.validate_bundle(bundle)
    test.write_text("pass\n")
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
    tool = acceptance_tool("dbcrypt_acceptance")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    test = bundle / "tests/test_dbcrypt.py"
    test.parent.mkdir()
    test.write_text("pass\n")
    manifest = {
        "schema_version": 1,
        "commit": "a" * 40,
        "sdist_sha256": "b" * 64,
        "wheel_sha256": "c" * 64,
        "files": {"tests/test_dbcrypt.py": tool.sha256_file(test)},
    }
    (bundle / "manifest.json").write_text(json.dumps(manifest))
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
