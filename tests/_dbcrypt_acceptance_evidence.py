"""Synthetic exported records for validator tests, never native success evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


def complete_phase(
    bundle_fixture: tuple[Any, ...],
    control_fixture: tuple[Any, ...],
    copy_fixture: tuple[Any, ...],
    *,
    mode: str = "source",
) -> tuple[Any, Path, dict[str, Any]]:
    tool, bundle_path, manifest = bundle_fixture
    _control_tool, spool, _action_path, action, _armed, _started, saved, _cloud = control_fixture
    _copy_tool, parent, production, copied, copy_manifest, _copy_value = copy_fixture
    checkout = Path(__file__).resolve().parents[1]
    manifest = copy.deepcopy(manifest)
    for prepared_mode in ("source", "wheel"):
        manifest[prepared_mode + "_probe"]["platform"] = "linux"
        manifest[prepared_mode + "_probe"]["versions"]["sqlcipher3-wheels"] = "0.5.7"
    plans = tool.native_acceptance_commands(
        checkout=Path(manifest["checkout"]), bundle=bundle_path, platform="linux", kind="production"
    )
    names = {"tests/_dbcrypt_acceptance_native.py", "tools/dbcrypt_acceptance.py"}
    for row in plans:
        names.update(
            "tests/" + arg.replace("\\", "/").split("/tests/", 1)[-1]
            for arg in row.get("argv", [])
            if arg.endswith(".py")
        )
    for name in names:
        target = bundle_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((checkout / name).read_bytes())
    import io
    import tarfile

    configuration = (checkout / "pyproject.toml").read_bytes()
    (bundle_path / manifest["extracted_sdist"] / "pyproject.toml").write_bytes(configuration)
    sdist = bundle_path / manifest["sdist"]
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo(sdist.name.removesuffix(".tar.gz") + "/pyproject.toml")
        member.size = len(configuration)
        archive.addfile(member, io.BytesIO(configuration))
    manifest["sdist_sha256"] = tool.sha256_file(sdist)
    manifest["files"] = tool._bundle_hashes(bundle_path)
    (bundle_path / "manifest.json").write_text(json.dumps(manifest))
    outputs = spool / "phase-files"
    outputs.mkdir()
    bundle_reference = tool._export_bundle_evidence({"bundle": bundle_path, "manifest": manifest}, outputs)
    helper = {
        "path": str(production),
        "sha256": tool.sha256_file(production),
        "version_method": "binary_identity_no_version_command",
    }
    boot = {"method": "proc_boot_id", "identity": "fixed-synthetic-boot"}
    identity: dict[str, Any] = {"platform": "linux", "volume": 1, "file_id": "100", "owner": "501"}
    fixture: dict[str, Any] = {
        "root": identity,
        "source": {"root": identity, "provider": "tpm", "generation": "a" * 32, "record_sha256": "a" * 64},
    }
    facts: dict[str, Any] = {
        "native_provider": "EC2 NitroTPM",
        "device": "/dev/tpmrm0",
        "manufacturer": "AMZN",
        "dmi_vendor": "Amazon EC2",
        "helper": helper,
        "boot": boot,
        "filesystem": {"method": "checked_private_posix", "identity": identity},
    }
    roots = {kind: str(parent / f"mordred-dbcrypt-{mode}-{kind}") for kind in ("persistence", "crash", "negative")}
    logical = {
        profile + ":" + component: "d" * 64
        for profile in tool.REQUIRED_PROFILES
        for component in tool.REQUIRED_COMPONENTS
    }
    phase: dict[str, Any] = {
        "schema_version": 2,
        "phase": "provision",
        "observation": "provision",
        "mode": mode,
        "platform": "linux",
        "acceptance_kind": "production",
        "bootstrap": "automatic_production",
        "status": "production_native_passed",
        "live_accepted": False,
        "bundle_manifest_sha256": tool.sha256_file(bundle_path / "manifest.json"),
        "bundle": {key: manifest[key] for key in ("commit", "sdist_sha256", "wheel_sha256")},
        "bundle_evidence": bundle_reference,
        "native_implementation_sha256": manifest["files"]["tests/_dbcrypt_acceptance_native.py"],
        "fixture": fixture,
        "logical": logical,
        "boot": boot,
        "native_facts": facts,
        "native_roots": roots,
        "control_action": saved("frozen-action.json", action),
        "control_sequence": 1,
        "controller_run": "a" * 32,
        "instance": action["instance"],
        "started_at": 1023.0,
        "finished_at": 1100.0,
        "executions": [],
    }

    fixtures: dict[str, dict[str, Any]] = {}
    for number, kind in enumerate(roots):
        root_identity = {**identity, "file_id": str(100 + number)}
        fixtures[kind] = {"root": root_identity, "source": {**fixture["source"], "root": root_identity}}
    driver = outputs / "hermes"
    helper_path = bundle_path / "tests/_dbcrypt_acceptance_native.py"
    driver.write_text(
        f"import sys, runpy; sys.path.insert(0, {str(bundle_path)!r}); "
        f"raise SystemExit(runpy.run_path({str(helper_path)!r})['main'](sys.argv[1]))\n"
    )
    driver_ref = {"path": driver.relative_to(spool).as_posix(), "sha256": tool.sha256_file(driver)}
    passive_driver = outputs / "native-collector"
    passive_driver.write_bytes(driver.read_bytes())
    passive_ref = {"path": passive_driver.relative_to(spool).as_posix(), "sha256": tool.sha256_file(passive_driver)}
    entrypoint = manifest[mode + "_probe"]["maintenance_entrypoint"]
    entrypoint_copy = outputs / "maintenance-entrypoint"
    entrypoint_copy.write_bytes(Path(entrypoint["path"]).read_bytes())
    entrypoint_ref = {
        "path": entrypoint_copy.relative_to(spool).as_posix(),
        "sha256": tool.sha256_file(entrypoint_copy),
    }

    def payload(operation: str, *, persistence: bool = True, kind: str | None = None) -> dict[str, Any]:
        selected = kind or ("persistence" if persistence else "negative")
        own_facts = {
            **facts,
            "filesystem": {
                "method": "checked_private_posix",
                "identity": fixtures[selected]["root"],
                "scope": "parent" if operation in {"preflight", "provision"} else "root",
                "observed_path": str(
                    Path(roots[selected]).parent if operation in {"preflight", "provision"} else Path(roots[selected])
                ),
            },
        }
        return {
            "schema_version": 2,
            "status": "executed",
            "operation": operation,
            "acceptance_kind": "production",
            "bootstrap": (
                "passive_prerequisite"
                if operation == "preflight"
                else "explicit_native_maintenance"
                if operation == "provision"
                else "automatic_production"
            ),
            "implementation_sha256": phase["native_implementation_sha256"],
            "facts": own_facts,
            "fixture": fixtures[selected],
            "logical": logical,
            "rows": list(tool.REQUIRED_COMPONENTS),
            "credential_continuity": "original_native_protected_reference"
            if persistence
            else "reload_only_sacrificial_no_reference",
            "hermes": {
                "module": str(
                    (Path(manifest["checkout"]) / ".venv" if mode == "source" else bundle_path / "wheel-env")
                    / "lib/site-packages/hermes_state.py"
                ),
                "sha256": "e" * 64,
                "version": manifest["source_probe"]["versions"]["hermes-agent"],
            },
        }

    sequence = [
        ("preflight", "persistence"),
        *(("provision", kind) for kind in roots),
        ("seed", "negative"),
        ("seed", "persistence"),
        ("read", "persistence"),
    ]
    for operation, kind in sequence:
        phase["executions"].append(
            {
                "operation": operation,
                "fixture_path": roots[kind],
                "returncode": 0,
                "started_at": 1024.0,
                "finished_at": 1025.0,
                "cwd": str(bundle_path),
                "mode": mode,
                "bundle_manifest_sha256": phase["bundle_manifest_sha256"],
                "import_probe": manifest[mode + "_probe"],
                "payload": payload(operation, persistence=kind == "persistence", kind=kind),
                "argv": [
                    str(
                        (Path(manifest["checkout"]) / ".venv" if mode == "source" else bundle_path / "wheel-env")
                        / "bin/python"
                    ),
                    str(passive_driver if operation in {"preflight", "provision"} else driver),
                    operation,
                ],
                "driver_ref": passive_ref if operation in {"preflight", "provision"} else driver_ref,
            }
        )
    for record in phase["executions"]:
        if record["operation"] != "provision":
            continue
        root = Path(record["fixture_path"])
        homes = [root] if root.name.endswith("-crash") else [root, root / "profiles/work", root / "profiles/other"]
        commands = [(home, ["encryption", "enable", "memory"]) for home in homes] + [(root, ["databases", "encrypt"])]
        record["payload"]["ceremonies"] = [
            {
                "home": str(home),
                "argv": [entrypoint["path"], *args],
                "entrypoint_sha256": entrypoint["sha256"],
                "started_at": 1024.0 + i / 10,
                "finished_at": 1024.05 + i / 10,
                "returncode": 0,
            }
            for i, (home, args) in enumerate(commands)
        ]
        record["maintenance_entrypoint_ref"] = entrypoint_ref
    source = fixtures["negative"]["source"]
    owned_copy = tool.validate_withdrawable_helper(copy_manifest, production=production, parent=parent)
    withdrawal = {
        "kind": "owned_helper_withdrawal",
        "copy": owned_copy,
        "restored": {"sha256": owned_copy["sha256"], "identity": owned_copy["identity"]},
    }
    for name, code, outcome, found, started in (
        ("initial_acquisition", 0, "acquired", str(copied), 1042.0),
        ("missing_helper_acquisition", 2, "refused", None, 1044.0),
    ):
        withdrawal[name] = {
            "returncode": code,
            "started_at": started,
            "finished_at": started + 1,
            "payload": {
                "operation": "fresh_unpatched_authority",
                "outcome": outcome,
                "bootstrap": "direct_unpatched_authority",
                "helper_found": found,
                "source_before": source,
                "source_after": source,
            },
        }
    sidecars = {
        "public-collectors": payload("read"),
        "before-restore": payload("read", persistence=False),
        "after-restore": payload("read", persistence=False),
        "backup-restore": {
            **payload("backup_restore", persistence=False),
            "component_generation_before": "old",
            "component_generation_after": "new",
            "backup_retained": True,
            "guarded_runtime_monitor_backup": True,
        },
        "restore-finalization-failure": {
            **payload("backup_restore_failure", persistence=False),
            "result": "restore_incomplete",
            "backup_and_native_key_retained": True,
        },
        "negative": {
            **payload("negative", persistence=False),
            "owned_helper_withdrawal": withdrawal,
            "initial_unwraps": 1,
            "operation_unwraps": 0,
            "rows": [
                "held_terminality",
                "unwrap_count",
                "metadata_loss",
                "wrong_key",
                "role_forget",
                "mail_retired_sql_failure_named_retry",
                "broker_helper_guards",
                "fresh_unpatched_native_provider_unavailable",
                "multiprocess_reader_writers",
                "wrong_profile_key",
                "holder_uncertainty_injected",
                "public_encryption_disable",
                "public_encryption_purge",
                "public_keyvault_reset",
                "public_uninstall_helper_guard",
                "public_vault_set-memory-key",
                "cached_access_failure_injected",
                "attach_uri_destinations",
                "wrong_generation",
                "wrong_root_binding",
                "missing_source_no_repair",
                "missing_native_key_observed",
            ],
        },
    }
    proof_path = spool / bundle_reference["path"]
    proof = json.loads(proof_path.read_text())
    validated_bundle = tool.validate_bundle_evidence(proof, directory=proof_path.parent)
    for plan in tool._planned_rows(phase, validated_bundle).values():
        modules = {arg.replace("\\", "/").split("/tests/", 1)[-1] for arg in plan["argv"] if arg.endswith(".py")}
        nodes = set().union(
            *(tool._module_functions(validated_bundle["_inputs"]["tests/" + module], module) for module in modules)
        )
        if plan["suite"] == "linux-memory":
            nodes = {
                "integration/test_linux_memory_orchestration_tpm.py::test_real_tpm_orchestration_and_armed_shape_b_backup["
                + entrance
                + "]"
                for entrance in ("setup", "all")
            }
        if plan["suite"] == "dbcrypt-native":
            nodes = tool._crash_nodes("linux") | tool._module_functions(
                validated_bundle["_inputs"]["tests/integration/test_dbcrypt_collectors.py"],
                "integration/test_dbcrypt_collectors.py",
            )
        report: dict[str, Any] = {
            "nodeids": sorted("tests/" + node for node in nodes),
            "deselected": [],
            "collection_errors": [],
            "exitstatus": 0,
        }
        report["reports"] = [
            {"nodeid": node, "when": stage, "outcome": "passed"}
            for node in report["nodeids"]
            for stage in ("setup", "call", "teardown")
        ]
        for node in report["nodeids"]:
            reason = tool.platform_na_reason(node, platform="linux", suite=plan["suite"])
            if reason:
                report["reports"] = [row for row in report["reports"] if row["nodeid"] != node]
                report["reports"] += [
                    {"nodeid": node, "when": "setup", "outcome": "skipped", "reason_code": reason},
                    {"nodeid": node, "when": "teardown", "outcome": "passed"},
                ]
        parsed = tool.validate_native_test_report(report, platform="linux", suite=plan["suite"])
        argv = [
            *plan["argv"],
            "--rootdir",
            str(bundle_path),
            "-c",
            str(bundle_path / manifest["extracted_sdist"] / "pyproject.toml"),
            "-p",
            "tests._dbcrypt_acceptance_native",
        ]
        phase["executions"].append(
            {
                "suite": plan["suite"],
                "mode": mode,
                "cwd": str(bundle_path),
                "argv": argv,
                "gate_env": plan["env"],
                "returncode": 0,
                "started_at": 1030.0,
                "finished_at": 1090.0,
                "bundle_manifest_sha256": phase["bundle_manifest_sha256"],
                "import_probe": manifest[mode + "_probe"],
                "nodeids": report["nodeids"],
                "counts": parsed["counts"],
                "platform_na": parsed["platform_na"],
                "pytest_report": saved(plan["suite"] + "-run.json", report),
                "collection": {
                    "argv": [*argv, "--collect-only"],
                    "returncode": 0,
                    "report": saved(plan["suite"] + "-collect.json", {**report, "reports": []}),
                },
                "collector_rows": [saved(name + ".json", value) for name, value in sidecars.items()]
                if plan["suite"] == "dbcrypt-native"
                else [],
            }
        )
    final_read = phase["executions"].pop(6)
    phase["executions"].append(final_read)
    for index, record in enumerate(phase["executions"]):
        record["started_at"] = 1024.0 + index if index < 6 else 1030.0 + (index - 6) * 10
        record["finished_at"] = record["started_at"] + (0.5 if index < 6 else 9.0)
        for i, ceremony in enumerate(record.get("payload", {}).get("ceremonies", [])):
            ceremony["started_at"] = record["started_at"] + i / 10
            ceremony["finished_at"] = ceremony["started_at"] + 0.05
    phase["native_facts"] = phase["executions"][-1]["payload"]["facts"]
    phase["test_counts"] = {
        "passed": sum(row.get("counts", {}).get("passed", 0) for row in phase["executions"]),
        "collected": sum(len(row.get("nodeids", [])) for row in phase["executions"]),
        "platform_na": sum(row.get("counts", {}).get("platform_na", 0) for row in phase["executions"]),
        "failed": 0,
        "skipped": 0,
    }
    phase["unexpected_skips"] = []
    return tool, spool, phase


def complete_qualification(
    bundle_fixture: tuple[Any, ...], tmp_path: Path, monkeypatch: Any
) -> tuple[Any, Path, Path, dict[str, Any]]:
    """Full-schema synthetic closure, not a real DLL/build/fixture qualification."""
    import hashlib

    tool, bundle_path, bundle = bundle_fixture
    checkout = Path(__file__).resolve().parents[1]
    root = tmp_path / "qualification"
    root.mkdir()

    def saved(name: str, value: Any) -> dict[str, str]:
        path = root / name
        path.write_text(json.dumps(value))
        return {"path": name, "sha256": tool.sha256_file(path)}

    def binary(name: str, value: bytes) -> dict[str, str]:
        path = root / name
        path.write_bytes(value)
        return {"path": name, "sha256": tool.sha256_file(path)}

    header_values = {"sqlite3.h": b"synthetic unit header", "sqlite3ext.h": b"synthetic unit extension header"}
    headers = {name: hashlib.sha256(value).hexdigest() for name, value in header_values.items()}
    monkeypatch.setattr(tool, "_required_qualification_headers", lambda _checkout: headers)
    critical = [
        *(checkout / "native/dbcrypt-vfs").glob("*.c"),
        *(checkout / "native/dbcrypt-vfs").glob("*.h"),
        *(checkout / "src/mordred_hermes/_private_fs").glob("*.py"),
        checkout / "native/dbcrypt-vfs/build.ps1",
        checkout / "pyproject.toml",
        checkout / "src/mordred_hermes/dbcrypt/_windows_vfs.py",
        checkout / "tests/integration/test_dbcrypt_windows_vfs.py",
    ]
    source_hashes = {path.relative_to(checkout).as_posix(): tool.sha256_file(path) for path in critical}
    import base64
    import io
    import tarfile
    import zipfile

    archive_path = root / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive_file:
        for path in critical:
            archive_file.writestr(path.relative_to(checkout).as_posix(), path.read_bytes())
    archive = {"path": archive_path.name, "sha256": tool.sha256_file(archive_path)}
    provenance = {
        "candidate": "a" * 40,
        "source_hashes": source_hashes,
        "headers": headers,
        "source_archive_sha256": archive["sha256"],
        "source": r"C:\qualified\source",
        "configuration": r"C:\qualified\source\pyproject.toml",
        "configuration_sha256": source_hashes["pyproject.toml"],
    }
    guest_bundle, guest_checkout = r"C:\bundle", r"C:\checkout"
    bundle = copy.deepcopy(bundle)
    bundle["checkout"] = guest_checkout
    for mode in ("source", "wheel"):
        probe = bundle[mode + "_probe"]
        probe["platform"] = "win32"
        probe["token"] = {"elevated": False, "uid": None}
        environment = guest_checkout + r"\.venv" if mode == "source" else guest_bundle + r"\wheel-env"
        probe["interpreter"] = environment + r"\Scripts\python.exe"
        probe["driver"]["module"] = environment + r"\Lib\site-packages\sqlcipher3\dbapi2.py"
        probe["versions"]["sqlcipher3-wheels"] = "0.5.7"
        probe["product_file"] = (
            (guest_checkout + r"\src\mordred_hermes\__init__.py")
            if mode == "source"
            else (guest_bundle + r"\wheel-env\Lib\site-packages\mordred_hermes\__init__.py")
        )
    (bundle_path / bundle["extracted_sdist"] / "pyproject.toml").write_bytes((checkout / "pyproject.toml").read_bytes())
    module = "tests/integration/test_dbcrypt_windows_vfs.py"
    (bundle_path / module).parent.mkdir(parents=True, exist_ok=True)
    (bundle_path / module).write_bytes((checkout / module).read_bytes())
    sdist_path, wheel_path = (bundle_path / bundle[name] for name in ("sdist", "wheel"))
    prefix = sdist_path.name.removesuffix(".tar.gz")
    with tarfile.open(sdist_path, "w:gz") as tar_archive:
        for path in critical:
            content = path.read_bytes()
            member = tarfile.TarInfo(prefix + "/" + path.relative_to(checkout).as_posix())
            member.size = len(content)
            tar_archive.addfile(member, io.BytesIO(content))
    with zipfile.ZipFile(wheel_path, "w") as archive_file:
        for path in critical:
            relative = path.relative_to(checkout).as_posix()
            if relative.startswith("src/"):
                archive_file.writestr(relative.removeprefix("src/"), path.read_bytes())
        native = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
        native_bytes = b"checked_wheel"
        archive_file.writestr(native, native_bytes)
        digest = base64.urlsafe_b64encode(hashlib.sha256(native_bytes).digest()).rstrip(b"=").decode()
        archive_file.writestr(
            "hermes_mordred-0.3.0a4.dist-info/RECORD", f"{native},sha256={digest},{len(native_bytes)}\n"
        )
    bundle["sdist_sha256"], bundle["wheel_sha256"] = (tool.sha256_file(path) for path in (sdist_path, wheel_path))
    from pathlib import PureWindowsPath

    guest_root, guest_source = PureWindowsPath(guest_bundle), PureWindowsPath(guest_checkout)
    source_python = str(guest_source / ".venv/Scripts/python.exe")
    build_python = str(guest_root / "build-env/Scripts/python.exe")
    wheel_python = str(guest_root / "wheel-env/Scripts/python.exe")
    commands = [
        ["uv", "build", "--sdist", str(guest_source), "--out-dir", str(guest_root / "artifacts")],
        *[
            ["uv", "venv", "--no-project", "--python", source_python, str(guest_root / name)]
            for name in ("build-env", "wheel-env")
        ],
        ["uv", "pip", "install", "--python", build_python, "hatchling>=1.18"],
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            build_python,
            str(guest_root / bundle["extracted_sdist"]),
            "--out-dir",
            str(guest_root / "artifacts"),
        ],
        [
            "uv",
            "pip",
            "install",
            "--python",
            wheel_python,
            "--link-mode",
            "copy",
            str(guest_root / bundle["wheel"]) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ],
    ]
    bundle["build_commands"] = [
        {"argv": argv, "cwd": str(guest_root), "started_at": 1.0, "finished_at": 2.0, "returncode": 0}
        for argv in commands
    ]
    bundle["files"] = tool._bundle_hashes(bundle_path)
    (bundle_path / "manifest.json").write_text(json.dumps(bundle))
    phase_dir = root / "proof-export"
    phase_dir.mkdir()
    reference = tool._export_bundle_evidence({"bundle": bundle_path, "manifest": bundle}, phase_dir)
    proof_path = root / reference["path"]
    proof = json.loads(proof_path.read_text())
    proof["bundle_path"] = guest_bundle
    proof_path.write_text(json.dumps(proof))
    reference["sha256"] = tool.sha256_file(proof_path)
    fixture_plan = {
        "owner_sid": "S-1-5-21-128634620-2103407742-3662938906-1010",
        "test_root": r"C:\qualified",
        "non_ntfs_root": r"Q:\owned",
        "reparse_root": r"C:\qualified\reparse",
    }
    manifest = {
        "schema": 1,
        "kind": "windows_vfs_qualification",
        "rows": {},
        "artifacts": {},
        "headers": {name: binary(name, value) for name, value in header_values.items()},
        "provenance": saved("provenance.json", provenance),
        "source_map": saved(
            "source-map.json",
            {
                "candidate": provenance["candidate"],
                "files": source_hashes,
                "delta_files": source_hashes,
                "headers": headers,
            },
        ),
        "source_archive": archive,
        "configuration": binary("pyproject.toml", (checkout / "pyproject.toml").read_bytes()),
        "fixture_plan": saved("fixture-plan.json", {"plan": fixture_plan, "reviewed_plan_sha256": "b" * 64}),
        "fixture_manifest": saved(
            "fixture-manifest.json",
            {
                "schema": 1,
                "owner_sid": fixture_plan["owner_sid"],
                "filesystem": "exFAT",
                **{key: fixture_plan[key] for key in ("non_ntfs_root", "reparse_root")},
            },
        ),
        "fixture_verify": saved(
            "fixture-verify.json",
            {
                "schema": 1,
                "sid": fixture_plan["owner_sid"],
                "ready": True,
                "elevated": False,
                "sentinel_unchanged": True,
                "direct": {"ok": True},
                "unknown": {"ok": True},
                "plan_sha256": "b" * 64,
            },
        ),
        "wheel_bundle": reference,
    }
    script = binary("build.ps1", (checkout / "native/dbcrypt-vfs/build.ps1").read_bytes())
    for name, target in (
        ("checkedtest_source", "CheckedTest"),
        ("checked_source", "Checked"),
        ("checked_wheel", "Checked"),
    ):
        nodes = tool.windows_vfs_required_nodes(checkout, release=target == "Checked")
        filename = "mordred_dbcrypt_checked_test.dll" if target == "CheckedTest" else "mordred_dbcrypt_checked.dll"
        artifacts: dict[str, Any] = {
            "dll": binary(name + ".dll", name.encode()),
            "driver_native": binary(name + ".pyd", b"inert driver"),
            "python": binary(name + "-python.exe", b"inert interpreter"),
            "build_stdout": binary(name + "-build.txt", b"inert build output"),
            "build_script": script,
            "build_argv": [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                r"C:\qualified\source\native\dbcrypt-vfs\build.ps1",
                "-Target",
                target,
                "-OutputDirectory",
                r"C:\qualified\build-" + target,
                "-SqliteIncludeDirectory",
                r"C:\headers",
            ],
        }
        run: dict[str, Any] = {
            "action": "run",
            "target": target,
            "nodeids": nodes,
            "collected": len(nodes),
            "pytest_exit_code": 0,
            "collection_errors": [],
            "reports": [
                {"nodeid": node, "when": stage, "outcome": "passed", "wasxfail": None}
                for node in nodes
                for stage in ("setup", "call", "teardown")
            ],
            "argv": [
                "-q",
                "-c",
                provenance["configuration"],
                "-o",
                "addopts=",
                "-m",
                "integration",
                "--basetemp",
                r"C:\qualified\pytest-run-" + target,
                "tests/integration/test_dbcrypt_windows_vfs.py",
                *(["-k", tool.WINDOWS_RELEASE_SELECTION] if target == "Checked" else []),
            ],
            "dll": r"C:\qualified\build-" + target + "\\" + filename,
            "dll_sha256": artifacts["dll"]["sha256"],
            "driver_native": r"C:\runtime\sqlcipher3\_sqlite3.pyd",
            "driver_native_sha256": artifacts["driver_native"]["sha256"],
            "executable": r"C:\runtime\python.exe",
            "python_sha256": artifacts["python"]["sha256"],
            "product_module": r"C:\qualified\source\src\mordred_hermes\__init__.py",
            "driver_version": "0.5.7",
            "versions": {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"},
        }
        if name == "checked_wheel":
            run.update(
                product_module=bundle["wheel_probe"]["product_file"],
                bundle_manifest_sha256=tool.sha256_file(bundle_path / "manifest.json"),
                sdist_sha256=bundle["sdist_sha256"],
                wheel_sha256=bundle["wheel_sha256"],
                record_owned_packaged_dll=True,
                test_exports_absent=True,
                env_dll_override=None,
            )
        manifest["rows"][name] = {
            "collect": saved(
                name + "-collect.json",
                {**run, "action": "collect", "reports": [], "argv": [*run["argv"], "--collect-only"]},
            ),
            "run": saved(name + "-run.json", run),
        }
        manifest["artifacts"][name] = artifacts
    (root / "manifest.json").write_text(json.dumps(manifest))
    return tool, root, checkout, manifest


def packaged_pipeline_fixture(prepared: tuple[Any, ...], bundle_path: Path, monkeypatch: Any) -> tuple[Any, ...]:
    """Actual inert archives/RECORD/receipt bytes; no Windows/native execution."""
    import base64
    import hashlib
    import io
    import shutil
    import tarfile
    from pathlib import PureWindowsPath

    tool, root, checkout, historical = prepared
    manifest = json.loads((bundle_path / "manifest.json").read_text())
    sdist = bundle_path / manifest["sdist"]
    with tarfile.open(sdist, "r:gz") as archive:
        members = {}
        for member in archive.getmembers():
            if member.isfile():
                stream = archive.extractfile(member)
                assert stream is not None
                members[member.name] = stream.read()
    prefix = sdist.name.removesuffix(".tar.gz") + "/"
    for name in ("hatch_build.py", "tools/dbcrypt_build_headers.py"):
        members[prefix + name] = (checkout / name).read_bytes()
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    manifest["sdist_sha256"] = tool.sha256_file(sdist)
    for row, (started, finished) in zip(
        manifest["build_commands"], ((16, 17), (18, 18.1), (18.2, 18.3), (19, 19.5), (20, 23), (24, 26)), strict=True
    ):
        row.update(started_at=float(started), finished_at=float(finished))
    guest_bundle = PureWindowsPath(r"C:\bundle")
    fixture_dir = root / "operator-fixtures"
    fixture_dir.mkdir()
    fixture: dict[str, Any] = {"schema": 1, "kind": "windows_vfs_fixtures"}
    for key in ("fixture_plan", "fixture_manifest", "fixture_verify"):
        source = root / historical[key]["path"]
        shutil.copyfile(source, fixture_dir / source.name)
        fixture[key] = {"path": source.name, "sha256": tool.sha256_file(source)}
    wrapper_path = fixture_dir / fixture["fixture_plan"]["path"]
    wrapper = json.loads(wrapper_path.read_text())
    wrapper["plan"].update(
        test_root=r"C:\fresh-packaged-0123456789abcdef",
        non_ntfs_root=r"Q:\fresh-0123456789abcdef",
        reparse_root=r"C:\fresh-packaged-0123456789abcdef\qualification-reparse",
    )
    wrapper["reviewed_plan_sha256"] = "d" * 64
    wrapper_path.write_text(json.dumps(wrapper))
    fixture_owned = fixture_dir / fixture["fixture_manifest"]["path"]
    owned = json.loads(fixture_owned.read_text())
    owned.update({key: wrapper["plan"][key] for key in ("non_ntfs_root", "reparse_root")})
    fixture_owned.write_text(json.dumps(owned))
    verify_path = fixture_dir / fixture["fixture_verify"]["path"]
    verified = json.loads(verify_path.read_text())
    verified["plan_sha256"] = "d" * 64
    verify_path.write_text(json.dumps(verified))
    for key in ("fixture_plan", "fixture_manifest", "fixture_verify"):
        fixture[key]["sha256"] = tool.sha256_file(fixture_dir / fixture[key]["path"])
    (fixture_dir / "manifest.json").write_text(json.dumps(fixture))
    fixture_sha = tool.sha256_file(fixture_dir / "manifest.json")
    results = {}
    for mode in ("source", "wheel"):
        env = PureWindowsPath(manifest["checkout"]) / ".venv" if mode == "source" else guest_bundle / "wheel-env"
        source_root = manifest["checkout"] if mode == "source" else str(guest_bundle / manifest["extracted_sdist"])
        asset = b"fresh editable Checked" if mode == "source" else b"checked_wheel"
        receipt_dir = bundle_path / f"artifacts/native-build/{mode}/hook-synthetic"
        receipt_dir.mkdir(parents=True)

        def artifact(directory: Path, name: str, content: bytes) -> dict[str, Any]:
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            return {"path": name, "sha256": tool.sha256_file(target), "size": len(content)}

        inputs = {}
        for name, content in members.items():
            relative = name.removeprefix(prefix)
            if relative in ("hatch_build.py", "tools/dbcrypt_build_headers.py", "native/dbcrypt-vfs/build.ps1") or (
                relative.startswith("native/dbcrypt-vfs/") and relative.endswith((".c", ".h"))
            ):
                inputs[relative] = artifact(receipt_dir, "inputs/" + relative, content)
        for name, ref in historical["headers"].items():
            inputs["headers/" + name] = artifact(
                receipt_dir, "inputs/headers/" + name, (root / ref["path"]).read_bytes()
            )
        staging = PureWindowsPath(r"C:\temp") / mode
        receipt = {
            "schema_version": 1,
            "kind": "dbcrypt_vfs_build",
            "status": "succeeded",
            "version": "editable" if mode == "source" else "standard",
            "source_root": source_root,
            "started_at": 10.0 if mode == "source" else 20.0,
            "finished_at": 12.0 if mode == "source" else 22.0,
            "returncode": 0,
            "cwd": r"C:\build",
            "inputs": inputs,
            "argv": [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(PureWindowsPath(source_root) / "native/dbcrypt-vfs/build.ps1"),
                "-OutputDirectory",
                str(staging),
                "-SqliteIncludeDirectory",
                str(staging / "include"),
                "-Target",
                "Checked",
            ],
            "stdout": artifact(receipt_dir, "stdout.bin", b"controlled compiler output"),
            "stderr": artifact(receipt_dir, "stderr.bin", b""),
            "dll": {
                **artifact(receipt_dir, "mordred_dbcrypt_checked.dll", asset),
                "observed_path": str(staging / "mordred_dbcrypt_checked.dll"),
            },
        }
        (receipt_dir / "receipt.json").write_text(json.dumps(receipt))
        output = root / (mode + "-result")
        output.mkdir()
        shutil.copytree(fixture_dir, output / "fixtures")
        dll_hash = hashlib.sha256(asset).hexdigest()
        encoded = base64.urlsafe_b64encode(bytes.fromhex(dll_hash)).rstrip(b"=").decode()
        record = f"mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll,sha256={encoded},{len(asset)}\n".encode()
        refs = {
            name: artifact(output, name + ".bin", content)
            for name, content in (
                ("dll", asset),
                ("driver_native", b"inert driver"),
                ("python", b"inert interpreter"),
                ("record", record),
            )
        }
        obs = {
            "eligibility": {
                "declared_qualified": True,
                "observed_qualified": True,
                "bootstrap": "automatic_production",
            },
            "mode": mode,
            "role": "packaged_editable" if mode == "source" else "packaged_wheel",
            "commit": manifest["commit"],
            "product_module": manifest[mode + "_probe"]["product_file"],
            "executable": str(env / "Scripts/python.exe"),
            "python_sha256": refs["python"]["sha256"],
            "dll": str(env / "Lib/site-packages/mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"),
            "dll_sha256": dll_hash,
            "driver_native": str(env / "Lib/site-packages/sqlcipher3/_sqlite3.pyd"),
            "driver_native_sha256": refs["driver_native"]["sha256"],
            "record": str(env / "Lib/site-packages/hermes_mordred-0.3.0a4.dist-info/RECORD"),
            "record_sha256": refs["record"]["sha256"],
            "record_size": len(record),
            "installed_at": 15.0 if mode == "source" else 25.0,
            "elevated": False,
            "env_dll_override": None,
            "test_exports_absent": True,
            "driver_version": "0.5.7",
            "versions": {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"},
            "sid": "S-1-5-21-128634620-2103407742-3662938906-1010",
            "fixture_root": wrapper["plan"]["test_root"],
            "filesystem": {
                "method": "checked_confidential_fixed_local_ntfs",
                "identity": {
                    "owner": "010500000000000515000000fcceaa077e745f7d1a0354daf2030000",
                    "platform": "win32",
                },
            },
            "build_receipts": [str((receipt_dir / "receipt.json").relative_to(bundle_path)).replace("\\", "/")],
        }
        result = {
            "schema_version": 1,
            "kind": "packaged_windows_vfs_result",
            "status": "passed",
            "mode": mode,
            "diagnostic_manifest_sha256": tool.sha256_file(root / "manifest.json"),
            "fixtures_sha256": fixture_sha,
            "fixtures_descriptor": {"path": "fixtures/manifest.json", "sha256": fixture_sha},
            "artifacts": refs,
            "dll_sha256": dll_hash,
        }
        required = tool.windows_vfs_required_nodes(checkout, release=True)
        full = tool.windows_vfs_required_nodes(checkout, release=False)
        commands = tool.windows_package_commands(
            checkout=PureWindowsPath(manifest["checkout"]),
            bundle=guest_bundle,
            mode=mode,
            basetemp=PureWindowsPath(r"C:\private") / mode / "pytest-temp",
            configuration=guest_bundle / manifest["extracted_sdist"] / "pyproject.toml",
        )
        for i, action in enumerate(("collect", "run")):
            report = {
                "nodeids": required,
                "deselected": [node for node in full if node not in required],
                "exitstatus": 0,
                "collection_errors": [],
                "reports": []
                if i == 0
                else [
                    {"nodeid": node, "when": stage, "outcome": "passed", "reason_code": None}
                    for node in required
                    for stage in ("setup", "call", "teardown")
                ],
                "pytest_argv": commands[i]["pytest_argv"],
                "fixture_manifest_sha256": fixture_sha,
                "qualification": {**obs, "observed_at": 31.0 + 10 * i},
                "qualification_after": {**obs, "observed_at": 32.0 + 10 * i},
            }
            (output / (action + ".json")).write_text(json.dumps(report))
            result[action] = {
                "argv": commands[i]["argv"],
                "basetemp": str(PureWindowsPath(r"C:\private") / mode / "pytest-temp"),
                "started_at": 30.0 + 10 * i,
                "finished_at": 35.0 + 10 * i,
                "returncode": 0,
                "report": {"path": action + ".json", "sha256": tool.sha256_file(output / (action + ".json"))},
            }
        results[mode] = (output, result)
    manifest["files"] = tool._bundle_hashes(bundle_path)
    (bundle_path / "manifest.json").write_text(json.dumps(manifest))
    digest = tool.sha256_file(bundle_path / "manifest.json")
    for output, result in results.values():
        for action in ("collect", "run"):
            path = output / (action + ".json")
            report = json.loads(path.read_text())
            for key in ("qualification", "qualification_after"):
                report[key]["bundle_manifest_sha256"] = digest
            path.write_text(json.dumps(report))
            result[action]["report"]["sha256"] = tool.sha256_file(path)
        (output / "result.json").write_text(json.dumps(result))
    # Foreign Windows guest paths cannot be stat'ed on this inert host. The
    # assembler's exported-byte validator still closes every actual file below.
    monkeypatch.setattr(tool, "validate_bundle", lambda path: manifest)
    original_export = tool._export_bundle_evidence

    def guest_export(context: dict[str, Any], directory: Path) -> dict[str, str]:
        reference = original_export(context, directory)
        path = directory.parent / reference["path"]
        proof = json.loads(path.read_text())
        proof["bundle_path"] = str(guest_bundle)
        path.write_text(json.dumps(proof))
        return {**reference, "sha256": tool.sha256_file(path)}

    monkeypatch.setattr(tool, "_export_bundle_evidence", guest_export)
    return tool, root, checkout, manifest, results, fixture_dir
