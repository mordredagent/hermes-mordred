"""Bounded build, subprocess and native phase orchestration."""

from __future__ import annotations

import json
import os
import platform as host_platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from _dbcrypt_acceptance_common import (
    _PROBE,
    _PTH_TEST_INPUTS,
    ADDITIONAL_MODULES,
    AFFECTED_MODULES,
    CONTROL_MARGIN,
    RUN_SCHEMA,
    WINDOWS_RELEASE_SELECTION,
    AcceptanceRefused,
    ExecutionAPI,
    Phase,
)


def probe_environment(home: Path, *, _api: ExecutionAPI) -> dict[str, str]:
    # Remove inherited test/emulator/secret-bearing product configuration. Native
    # collectors must reintroduce only their documented, explicit gate variables.
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("MORDRED_", "HERMES_", "PYTEST_", "TPM2TOOLS_", "TSS2_"))
        and key not in {"PYTHONPATH", "PYTHONHOME", "UV_PROJECT", "VIRTUAL_ENV"}
    }
    environment.update(HERMES_HOME=str(home), PYTHONNOUSERSITE="1", PYTHONOPTIMIZE="0", UV_NO_PROGRESS="1")
    return environment


def probe_interpreter(interpreter: Path, *, cwd: Path, _api: ExecutionAPI) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-probe-") as directory:
        result = subprocess.run(  # noqa: S603 - list argv, no shell
            [str(interpreter), "-c", _PROBE],
            cwd=cwd,
            env=_api.probe_environment(Path(directory)),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    if result.returncode:
        raise AcceptanceRefused("interpreter_probe_failed")
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or not value["driver"]["cipher_version"]:
            raise ValueError("missing SQLCipher")
    except (ValueError, KeyError, TypeError) as exc:
        raise AcceptanceRefused("interpreter_probe_invalid") from exc
    return value


def _suites(platform: str, *, _api: ExecutionAPI) -> list[tuple[str, tuple[str, ...], dict[str, str], bool]]:
    suites = [
        ("affected", AFFECTED_MODULES, {}, False),
        (
            "dbcrypt-native",
            ("integration/test_dbcrypt_native.py", "integration/test_dbcrypt_collectors.py"),
            {"MORDRED_DBCRYPT_NATIVE_TEST": "1", "MORDRED_DBCRYPT_COLLECTORS_TEST": "1"},
            True,
        ),
    ]
    if platform == "linux":
        suites.extend(
            [
                (
                    "linux-memory",
                    ("integration/test_linux_memory_orchestration_tpm.py",),
                    {"MORDRED_LINUX_ORCHESTRATION_TEST": "1"},
                    True,
                ),
                (
                    "linux-telegram",
                    ("integration/test_linux_telegram_tpm.py",),
                    {"MORDRED_LINUX_TELEGRAM_TEST": "1"},
                    True,
                ),
            ]
        )
    elif platform == "win32":
        suites.extend(
            [
                (
                    "windows-vfs",
                    ("integration/test_dbcrypt_windows_vfs.py",),
                    {"MORDRED_DBCRYPT_WINDOWS_VFS_TEST": "1"},
                    True,
                ),
                (
                    "windows-custody",
                    ("test_windows_custody_live.py",),
                    {"MORDRED_TEST_WINDOWS_CUSTODY_LIVE": "1"},
                    True,
                ),
                ("windows-memory", ("test_windows_memory_live.py",), {"MORDRED_TEST_WINDOWS_MEMORY_LIVE": "1"}, True),
                (
                    "windows-telegram",
                    ("test_windows_telegram_live.py",),
                    {"MORDRED_TEST_WINDOWS_TELEGRAM_LIVE": "1"},
                    True,
                ),
            ]
        )
    else:
        raise AcceptanceRefused("unsupported_platform")
    return suites


def acceptance_commands(*, checkout: Path, bundle: Path, platform: str, _api: ExecutionAPI) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for suite, modules, gates, integration in _api._suites(platform):
        for mode in ("wheel",) if suite == "linux-memory" else ("source", "wheel"):
            prefix = (
                ["uv", "run", "--project", str(checkout), "python", "-m", "pytest", "-q"]
                if mode == "source"
                else [
                    "uv",
                    "run",
                    "--no-project",
                    "--python",
                    str(_api._python(bundle / "wheel-env", platform)),
                    "python",
                    "-m",
                    "pytest",
                    "-q",
                ]
            )
            commands.append(
                {
                    "suite": suite,
                    "mode": mode,
                    "argv": [
                        *prefix,
                        *(["-o", "addopts=", "-m", "integration"] if integration else []),
                        *(["-k", WINDOWS_RELEASE_SELECTION] if suite == "windows-vfs" and mode == "wheel" else []),
                        *[str(bundle / "tests" / module) for module in modules],
                    ],
                    "cwd": str(bundle),
                    "env": gates,
                    "unset": ["PYTHONPATH", "PYTHONHOME"],
                    "requires": ["private_root", "import_probe_before_run", "actual_native_provider"]
                    if integration
                    else ["import_probe_before_run"],
                }
            )
            if suite == "linux-memory":
                commands[-1]["source_applicability"] = {
                    "status": "not_applicable",
                    "reason": "existing_linux_memory_suite_requires_installed_runtime",
                    "blocked_by": "source_capable_linux_memory_suite_adaptation_pending",
                }
            if suite == "windows-vfs":
                commands[-1]["library_kind"] = "CheckedTest" if mode == "source" else "packaged Checked"
                commands[-1]["requires"].extend(
                    [
                        "actual_collected_nodeids",
                        "matched_library_hash_and_kind",
                        "owned_qualification_fixture_manifest",
                    ]
                )
    return commands


def _write_new(path: Path, value: dict[str, Any], *, _api: ExecutionAPI) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _root_identity(root: Path, *, _api: ExecutionAPI) -> dict[str, Any]:
    if not root.is_absolute() or root != root.resolve(strict=True) or not root.name.startswith("mordred-dbcrypt-"):
        raise AcceptanceRefused("explicit_private_synthetic_root_required")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or (os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise AcceptanceRefused("unsafe_private_root")
    return {
        "path": str(root),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "filesystem": "native_filesystem_probe_not_integrated",
    }


def run_acceptance(*, root: Path, phase: Phase, output: Path, _api: ExecutionAPI) -> int:
    started = time.time()
    context: dict[str, Any] | None = None
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "phase": phase,
        "status": "refused",
        "live_accepted": False,
        "platform": _api.sys.platform,
        "host_release": host_platform.release(),
        "started_at": started,
        "tests": [],
        "test_counts": {"passed": 0, "failed": 0, "skipped": 0, "collected": 0},
        "unexpected_skips": [],
        "native_provider": None,
        "owned_instance_receipts": [],
        "reasons": [],
    }
    try:
        if phase not in ("provision", "reopen", "verify"):
            raise AcceptanceRefused("unsupported_phase")
        evidence["root"] = _api._root_identity(root)
        bundle_text = os.environ.get("DBCRYPT_BUNDLE")
        if bundle_text and phase != "verify":
            bundle = Path(bundle_text)
            manifest = _api.validate_bundle(bundle)
            evidence["bundle"] = {
                key: manifest.get(key)
                for key in ("commit", "sdist_sha256", "wheel_sha256", "source_probe", "wheel_probe")
            }
            evidence["bundle_manifest_sha256"] = _api.sha256_file(bundle / "manifest.json")
        receipt = os.environ.get("MORDRED_DBCRYPT_STOP_RECEIPT")
        if receipt and phase != "verify":
            evidence["owned_instance_receipts"] = [_api.load_stop_receipt(Path(receipt))]
        if phase == "verify":
            evidence.update(_api.verify_native_spool(root))
        else:
            context = _api.native_phase_inputs(root, phase)
            directory = output.parent / (output.stem + "-files")
            directory.mkdir(mode=0o700)
            evidence.update(_api._execute_native_phase(context, phase=phase, directory=directory))
            evidence["reasons"] = ["native_coverage_incomplete"] if not evidence["native_rows_complete"] else []
    except (ValueError, TypeError, KeyError, StopIteration):
        evidence["reasons"].append("native_evidence_invalid")
    except (AcceptanceRefused, OSError, subprocess.SubprocessError) as exc:
        if context is not None:
            evidence["executions"] = context.get("execution_log", [])
        evidence["reasons"].append(str(exc) if isinstance(exc, AcceptanceRefused) else "root_probe_failed")
    evidence["finished_at"] = time.time()
    _api._write_new(output, evidence)
    return 0 if evidence["status"] in {"candidate_native_passed", "production_native_passed"} else 2


def extract_sdist(archive: Path, destination: Path, *, _api: ExecutionAPI) -> Path:
    """Admit regular members only before extracting any archive content."""
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        for member in members:
            name = member.name
            if (
                not (member.isfile() or member.isdir())
                or name.startswith("/")
                or ".." in name.split("/")
                or "\\" in name
                or ":" in name
                or not (destination / name).resolve().is_relative_to(destination.resolve())
            ):
                raise AcceptanceRefused("unsafe_sdist_member")
        destination.mkdir(mode=0o700)
        source.extractall(destination, members=members, filter="data")
    children = list(destination.iterdir())
    if len(children) != 1 or not (children[0] / "pyproject.toml").is_file():
        raise AcceptanceRefused("invalid_sdist_layout")
    return children[0]


def _run_build(
    argv: list[str], *, cwd: Path, environment: dict[str, str], log: list[dict[str, Any]], _api: ExecutionAPI
) -> str:
    started = time.time()
    result = subprocess.run(argv, cwd=cwd, env=environment, text=True, capture_output=True, timeout=900, check=False)  # noqa: S603 - list argv, no shell
    # Dependency tools can print credential-bearing index URLs: retain command,
    # timing and status, never arbitrary subprocess stdout/stderr in evidence.
    log.append(
        {
            "argv": argv,
            "cwd": str(cwd),
            "started_at": started,
            "finished_at": time.time(),
            "returncode": result.returncode,
        }
    )
    if result.returncode:
        raise AcceptanceRefused("bundle_command_failed:" + argv[1])
    return result.stdout


def _git(checkout: Path, *args: str, _api: ExecutionAPI) -> str:
    result = subprocess.run(  # noqa: S603 - list argv, no shell
        ["git", "-C", str(checkout), *args],  # noqa: S607 - PATH lookup of a system tool is intended
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise AcceptanceRefused("checkout_git_provenance_unavailable")
    return result.stdout.strip()


def _copy_inputs(checkout: Path, output: Path, *, _api: ExecutionAPI) -> None:
    names = _api._git(checkout, "ls-files", "-z", "--", "tests", "tools", *_PTH_TEST_INPUTS).split("\0")
    for name in names:
        if not name:
            continue
        source, target = checkout / name, output / name
        if source.is_symlink() or not source.is_file():
            raise AcceptanceRefused("unsafe_checkout_input")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _bundle_artifact(directory: Path, pattern: str, *, _api: ExecutionAPI) -> Path:
    candidates = list(directory.glob(pattern))
    if len(candidates) != 1:
        raise AcceptanceRefused("bundle_artifact_count")
    return candidates[0]


def _bundle_build(
    checkout: Path, output: Path, commands: list[dict[str, Any]], home: Path, *, _api: ExecutionAPI
) -> dict[str, Any]:
    environment = _api.probe_environment(home)
    # Windows build hook requires explicitly prepared, reviewed header inputs.
    # It must never fall back to a network header download or a stale DLL.
    if "MORDRED_SQLITE_INCLUDE_DIR" in os.environ:
        environment["MORDRED_SQLITE_INCLUDE_DIR"] = os.environ["MORDRED_SQLITE_INCLUDE_DIR"]
    artifacts = output / "artifacts"
    artifacts.mkdir()
    if _api.sys.platform == "win32":
        receipts = artifacts / "native-build/wheel"
        receipts.parent.mkdir(parents=True, exist_ok=True)
        if receipts.exists() or receipts.is_symlink():
            raise AcceptanceRefused("bundle_receipt_directory_already_exists")
        previous_home = os.environ.get("HERMES_HOME")
        os.environ["HERMES_HOME"] = str(home)
        try:
            from mordred_hermes._private_fs import PrivateFSError, open_private_directory

            try:
                # Python's Windows mkdir(0700) uses OW, not the explicit user
                # SID required by the unchanged build-hook receipt validator.
                with open_private_directory(receipts, create=True):
                    pass
            except PrivateFSError as exc:
                raise AcceptanceRefused("bundle_receipt_directory_unavailable") from exc
        finally:
            if previous_home is None:
                os.environ.pop("HERMES_HOME", None)
            else:
                os.environ["HERMES_HOME"] = previous_home
        environment["MORDRED_DBCRYPT_BUILD_RECEIPT_DIR"] = str(receipts)
    _api._run_build(
        ["uv", "build", "--sdist", str(checkout), "--out-dir", str(artifacts)],
        cwd=output,
        environment=environment,
        log=commands,
    )
    sdist = _api._bundle_artifact(artifacts, "*.tar.gz")
    extracted = _api.extract_sdist(sdist, output / "extracted-sdist")
    build_env, wheel_env = output / "build-env", output / "wheel-env"
    for directory in (build_env, wheel_env):
        _api._run_build(
            ["uv", "venv", "--no-project", "--python", _api.sys.executable, str(directory)],
            cwd=output,
            environment=environment,
            log=commands,
        )
    _api._run_build(
        ["uv", "pip", "install", "--python", str(_api._python(build_env)), "hatchling>=1.18"],
        cwd=output,
        environment=environment,
        log=commands,
    )
    _api._run_build(
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            str(_api._python(build_env)),
            str(extracted),
            "--out-dir",
            str(artifacts),
        ],
        cwd=output,
        environment=environment,
        log=commands,
    )
    wheel = _api._bundle_artifact(artifacts, "*.whl")
    _api._run_build(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(_api._python(wheel_env)),
            "--link-mode",
            "copy",
            str(wheel) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ],
        cwd=output,
        environment=environment,
        log=commands,
    )
    source_probe = _api.probe_interpreter(_api._python(checkout / ".venv"), cwd=output)
    wheel_probe = _api.probe_interpreter(_api._python(wheel_env), cwd=output)
    _api.validate_import_provenance(
        Path(source_probe["product_file"]), checkout=checkout, environment=wheel_env, mode="source"
    )
    _api.validate_import_provenance(
        Path(wheel_probe["product_file"]), checkout=checkout, environment=wheel_env, mode="wheel"
    )
    if source_probe["versions"]["hermes-mordred"] != wheel_probe["versions"]["hermes-mordred"]:
        raise AcceptanceRefused("source_wheel_version_mismatch")
    return {
        "sdist": sdist.relative_to(output).as_posix(),
        "sdist_sha256": _api.sha256_file(sdist),
        "wheel": wheel.relative_to(output).as_posix(),
        "wheel_sha256": _api.sha256_file(wheel),
        "extracted_sdist": extracted.relative_to(output).as_posix(),
        "source_probe": source_probe,
        "wheel_probe": wheel_probe,
    }


def _site_packages(output: Path, *, _api: ExecutionAPI) -> Path:
    environment = output / "wheel-env"
    candidates = (
        [environment / "Lib/site-packages"]
        if _api.sys.platform == "win32"
        else [environment / "lib/site-packages", *(environment / "lib").glob("python*/site-packages")]
    )
    existing = [path for path in candidates if path.is_dir()]
    _api._require(len(existing) == 1)
    return existing[0]


def _bundle_hashes(output: Path, *, _api: ExecutionAPI) -> dict[str, str]:
    """Inventory only owned trees plus explicit interpreter startup surfaces.

    Bytecode, the root pytest cache and outputs/ are mutable and excluded.
    Third-party dependency trees and the build environment are not rescanned.
    Their recorded versions do not claim a dependency-file integrity guarantee.
    """
    try:
        _api._input_root_layout(output)
        paths = [
            path
            for name in ("tests", "tools", "packaging", "extracted-sdist", "artifacts")
            for path in _api._tree_inputs(output / name)
        ]
        site = _api._site_packages(output)
        paths.extend(_api._tree_inputs(site / "mordred_hermes"))
        paths.append(_api._input_file(output / "wheel-env/pyvenv.cfg"))
        paths.extend(
            _api._input_file(path)
            for path in site.iterdir()
            if path.suffix == ".pth"
            or (
                path.name.split(".", 1)[0] in {"sitecustomize", "usercustomize", "mordred_hermes"}
                and path.name != "mordred_hermes"
            )
        )
        return {path.relative_to(output).as_posix(): _api.sha256_file(path) for path in sorted(paths)}
    except (OSError, ValueError) as exc:
        raise AcceptanceRefused("unsafe_bundle_input_inventory") from exc


def build_acceptance_bundle(
    *, checkout: Path, output: Path, source_build_receipts: Path | None = None, _api: ExecutionAPI
) -> Path:
    checkout, output = checkout.resolve(strict=True), output.resolve()
    if output.is_relative_to(checkout):
        raise AcceptanceRefused("bundle_must_be_outside_checkout")
    if output.exists():
        raise AcceptanceRefused("bundle_output_already_exists")
    if _api.sys.platform == "win32" and source_build_receipts is None:
        raise AcceptanceRefused("source_editable_build_receipts_required")
    commit = _api._git(checkout, "rev-parse", "HEAD")
    if _api._git(checkout, "status", "--porcelain", "--untracked-files=normal"):
        raise AcceptanceRefused("clean_committed_checkout_required")
    output.mkdir(mode=0o700, parents=True)
    commands: list[dict[str, Any]] = []
    try:
        _api._copy_inputs(checkout, output)
        with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-build-") as directory:
            provenance = _api._bundle_build(checkout, output, commands, Path(directory))
        if source_build_receipts is not None:
            _api._copy_build_receipts(source_build_receipts, output / "artifacts/native-build/source")
        if _api._git(checkout, "rev-parse", "HEAD") != commit or _api._git(
            checkout, "status", "--porcelain", "--untracked-files=normal"
        ):
            raise AcceptanceRefused("checkout_changed_during_build")
        manifest = {
            "schema_version": 1,
            "commit": commit,
            "checkout": str(checkout),
            "created_at": time.time(),
            **provenance,
            "build_commands": commands,
            "files": _api._bundle_hashes(output),
            "native_qualification": "not_run",
            "native_collectors": "not_integrated",
            "missing_native_hooks": [
                "provision",
                "reopen",
                "verify",
                "independent_ec2_observations",
                "collector_records_across_os_reboot_and_stop_start",
            ],
        }
        if _api.sys.platform in {"linux", "win32"}:
            manifest["acceptance_commands"] = _api.acceptance_commands(
                checkout=checkout, bundle=output, platform=_api.sys.platform
            )
        _api._write_new(output / "manifest.json", manifest)
        _api.validate_bundle(output)
    except (AcceptanceRefused, OSError, subprocess.SubprocessError) as exc:
        _api._write_new(
            output / "build-failure.json",
            {
                "schema_version": 1,
                "status": "failed",
                "commit": commit,
                "commands": commands,
                "reason": str(exc) if isinstance(exc, AcceptanceRefused) else type(exc).__name__,
                "native_qualification": "not_run",
            },
        )
        raise
    return output


def native_fixture_paths(root: Path, mode: str, *, _api: ExecutionAPI) -> dict[str, Path]:
    if mode not in {"source", "wheel"}:
        raise AcceptanceRefused("native_mode_required")
    return {kind: root / f"mordred-dbcrypt-{mode}-{kind}" for kind in ("persistence", "crash", "negative")}


def require_native_source_checkout(context: dict[str, Any], *, _api: ExecutionAPI) -> None:
    if context["mode"] == "source":
        checkout = Path(context["manifest"]["checkout"])
        if _api._git(checkout, "rev-parse", "HEAD") != context["manifest"]["commit"] or _api._git(
            checkout, "status", "--porcelain", "--untracked-files=normal"
        ):
            raise AcceptanceRefused("source_checkout_changed_since_bundle")


def _native_observation_inputs(phase: Phase, *, _api: ExecutionAPI) -> tuple[str | None, str]:
    prior = os.environ.get("MORDRED_DBCRYPT_PRIOR_EVIDENCE")
    observation = os.environ.get("MORDRED_DBCRYPT_OBSERVATION", "provision")
    if phase == "reopen" and (not prior or observation not in {"process_restart", "os_reboot", "ec2_stop_start"}):
        raise AcceptanceRefused("reopen_prior_and_observation_required")
    if phase == "provision" and observation != "provision":
        raise AcceptanceRefused("provision_observation_required")
    return prior, observation


def native_phase_inputs(root: Path, phase: Phase, *, _api: ExecutionAPI) -> dict[str, Any]:
    names = ("DBCRYPT_BUNDLE", "MORDRED_DBCRYPT_ACCEPTANCE_MODE", "MORDRED_DBCRYPT_ACCEPTANCE_KIND")
    if os.environ.get("MORDRED_DBCRYPT_COLLECTORS_TEST") != "1" or any(not os.environ.get(name) for name in names):
        raise AcceptanceRefused("native_phase_inputs_missing")
    mode, kind = (os.environ[name] for name in names[1:])
    if mode not in {"source", "wheel"} or kind not in {"candidate", "production"}:
        raise AcceptanceRefused("native_mode_or_kind_invalid")
    bundle = _api._absolute(os.environ["DBCRYPT_BUNDLE"])
    manifest = _api.validate_bundle(bundle)
    helper_name = "MORDRED_WINKEY_HELPER" if _api.sys.platform == "win32" else "MORDRED_TPMKEY_HELPER"
    helper_text = os.environ.get(helper_name)
    if _api.sys.platform not in {"linux", "win32"} or not helper_text:
        raise AcceptanceRefused("actual_native_platform_and_helper_required")
    helper = _api._absolute(helper_text)
    _api._input_file(helper)
    forbidden = (
        "HERMES_MEMORY_KEY",
        "MORDRED_TPM_TEST",
        "MORDRED_TPMKEY_STORE",
        "MORDRED_TEST_INJECT_BACKEND",
        "TPM2TOOLS_TCTI",
        "TSS2_TCTI",
    )
    if any(os.environ.get(name) for name in forbidden):
        raise AcceptanceRefused("ambient_key_or_native_emulation_forbidden")
    copy_manifest = os.environ.get("MORDRED_DBCRYPT_WITHDRAWABLE_HELPER_MANIFEST")
    if not copy_manifest:
        raise AcceptanceRefused("owned_withdrawable_helper_manifest_required")
    helper_copy = _api.validate_withdrawable_helper(_api._absolute(copy_manifest), production=helper, parent=root)
    prior, observation = _api._native_observation_inputs(phase)
    action_text = os.environ.get("MORDRED_DBCRYPT_CONTROL_ACTION")
    if not action_text:
        raise AcceptanceRefused("frozen_controller_action_required")
    action_path = _api._absolute(action_text)
    control_action = _api.validate_control_action(
        action_path, platform=_api.sys.platform, mode=mode, observation=observation
    )
    if not control_action["running_at"] <= time.time() < control_action["deadline"] - CONTROL_MARGIN:
        raise AcceptanceRefused("controller_guard_window_not_active")
    qualification = os.environ.get("MORDRED_DBCRYPT_QUALIFICATION_DIRECTORY")
    if _api.sys.platform == "win32":
        if not qualification:
            raise AcceptanceRefused("windows_native_qualification_incomplete")
        qualified = _api._native_windows_qualification(
            _api._absolute(qualification), checkout=Path(manifest["checkout"]), kind=kind
        )
        _api._require(os.environ.get("MORDRED_DBCRYPT_VFS_FIXTURE_ROOT") == qualified["fixtures"]["test_root"])
        fixture_input = os.environ.get("MORDRED_DBCRYPT_QUALIFICATION_MANIFEST")
        _api._require(bool(fixture_input))
        _api._require(
            _api.sha256_file(_api._input_file(Path(str(fixture_input)))) == qualified["fixture_manifest_sha256"]
        )
    return {
        "bundle": bundle,
        "manifest": manifest,
        "mode": mode,
        "kind": kind,
        "helper": helper,
        "helper_name": helper_name,
        "helper_sha256": _api.sha256_file(helper),
        "helper_copy_manifest": Path(copy_manifest),
        "helper_copy": helper_copy,
        "parent": root,
        "prior": _api._absolute(prior) if prior else None,
        "observation": observation,
        "fixtures": _api.native_fixture_paths(root, mode),
        "qualification": qualification,
        "control_action_path": action_path,
        "control_action": control_action,
    }


def _export_windows_qualification(
    context: dict[str, Any], directory: Path, *, _api: ExecutionAPI
) -> dict[str, str] | None:
    if not context.get("qualification"):
        return None
    source = Path(context["qualification"])
    manifest = json.loads((source / "manifest.json").read_text())
    target = directory / "windows-qualification"
    target.mkdir(mode=0o700)
    for path in sorted(_api._qualification_inputs(source, manifest)):
        relative = path.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    path = target / "manifest.json"
    return {"path": path.relative_to(directory.parent).as_posix(), "sha256": _api.sha256_file(path)}


def native_acceptance_commands(
    *, checkout: Path, bundle: Path, platform: str, kind: str, _api: ExecutionAPI
) -> list[dict[str, Any]]:
    rows = _api.acceptance_commands(checkout=checkout, bundle=bundle, platform=platform)
    if platform == "win32":
        rows = _api._native_windows_vfs_rows(rows, kind)
    for row in rows:
        if row["suite"] == "affected":
            row["argv"].extend(str(bundle / "tests" / name) for name in ADDITIONAL_MODULES)
    for suite, module, gate in (
        ("dbcrypt-activity", "integration/test_dbcrypt_activity.py", "MORDRED_DBCRYPT_ACTIVITY_NATIVE_TEST"),
        ("mail-native", "integration/test_mail_native_custody.py", "MORDRED_MAIL_NATIVE_TEST"),
    ):
        for mode in ("source", "wheel"):
            if kind == "candidate" and suite == "dbcrypt-activity":
                rows.append({"suite": suite, "mode": mode, "status": "not_run_requires_production_activation"})
                continue
            prototype = next(row for row in rows if row["suite"] == "dbcrypt-native" and row["mode"] == mode)
            row = {**prototype, "suite": suite, "env": {gate: "1"}}
            row["argv"] = [*prototype["argv"][:-2], str(bundle / "tests" / module)]
            rows.append(row)
    if platform == "win32":
        for suite, module, gate in (
            ("windows-memory-wizard", "test_wizard_windows_memory_live.py", "MORDRED_TEST_WINDOWS_WIZARD_LIVE"),
            (
                "windows-telegram-wizard",
                "test_wizard_windows_telegram_live.py",
                "MORDRED_TEST_WINDOWS_TELEGRAM_WIZARD_LIVE",
            ),
        ):
            for mode in ("source", "wheel"):
                prototype = next(row for row in rows if row["suite"] == "dbcrypt-native" and row["mode"] == mode)
                rows.append(
                    {
                        **prototype,
                        "suite": suite,
                        "env": {gate: "1"},
                        "argv": [*prototype["argv"][:-2], str(bundle / "tests" / module)],
                    }
                )
    return rows


def _export_bundle_evidence(context: dict[str, Any], directory: Path, *, _api: ExecutionAPI) -> dict[str, str]:
    target = directory / "bundle-evidence"
    target.mkdir(mode=0o700)
    proof: dict[str, Any] = {
        "schema_version": 1,
        "kind": "dbcrypt_bundle_evidence",
        "bundle_path": str(context["bundle"]),
        "inputs": {},
        "artifacts": {},
        "native_build": {},
    }
    manifest = context["manifest"]
    config_name = manifest["extracted_sdist"] + "/pyproject.toml"
    names = [
        "manifest.json",
        config_name,
        manifest["sdist"],
        manifest["wheel"],
        *(name for name in manifest["files"] if name.startswith(("tests/", "tools/")) or name in _PTH_TEST_INPUTS),
        *(name for name in manifest["files"] if name.startswith("artifacts/native-build/")),
    ]
    for name in names:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(context["bundle"] / name, path)
        reference = {"path": name, "sha256": _api.sha256_file(path)}
        if name == "manifest.json":
            proof["manifest"] = reference
        elif name == config_name:
            proof["configuration"] = reference
        elif name in (manifest["sdist"], manifest["wheel"]):
            proof["artifacts"]["sdist" if name == manifest["sdist"] else "wheel"] = reference
        elif name.startswith("artifacts/native-build/"):
            proof["native_build"][name] = reference
        else:
            proof["inputs"][name] = reference
    path = target / "proof.json"
    _api._write_new(path, proof)
    return {"path": path.relative_to(directory.parent).as_posix(), "sha256": _api.sha256_file(path)}


def _native_environment(context: dict[str, Any], root: Path, *, _api: ExecutionAPI) -> dict[str, str]:
    environment = _api.probe_environment(root)
    environment.update(
        {
            "DBCRYPT_BUNDLE": str(context["bundle"]),
            "DBCRYPT_CHECKOUT": context["manifest"]["checkout"],
            context["helper_name"]: str(context["helper"]),
            "MORDRED_DBCRYPT_COLLECTORS_TEST": "1",
            "MORDRED_DBCRYPT_TEST_ROOT": str(root),
            "MORDRED_DBCRYPT_ACCEPTANCE_MODE": context["mode"],
            "MORDRED_DBCRYPT_ACCEPTANCE_KIND": context["kind"],
            "MORDRED_HERMES_RUNTIME_PYTHON": str(_api._native_python(context)),
            "MORDRED_HERMES_PYTHON": str(_api._native_python(context)),
            "MORDRED_DBCRYPT_WITHDRAWABLE_HELPER_MANIFEST": str(context["helper_copy_manifest"]),
            "MORDRED_DBCRYPT_PARENT": str(context["parent"]),
        }
    )
    if context.get("qualification"):
        environment["MORDRED_DBCRYPT_QUALIFICATION_DIRECTORY"] = context["qualification"]
    return environment


def _native_python(context: dict[str, Any], *, _api: ExecutionAPI) -> Path:
    base = (
        Path(context["manifest"]["checkout"]) / ".venv"
        if context["mode"] == "source"
        else context["bundle"] / "wheel-env"
    )
    return _api._python(base)


def _native_driver(context: dict[str, Any], directory: Path, *, passive: bool = False, _api: ExecutionAPI) -> Path:
    path = directory / ("native-collector" if passive else "hermes")
    if not path.exists():
        helper = context["bundle"] / "tests/_dbcrypt_acceptance_native.py"
        code = (
            f"import sys, runpy; sys.path.insert(0, {str(context['bundle'])!r}); "
            f"raise SystemExit(runpy.run_path({str(helper)!r})['main'](sys.argv[1]))\n"
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(code)
    return path


def _native_process(
    context: dict[str, Any],
    argv: list[str],
    environment: dict[str, str],
    *,
    timeout: int,
    name: str,
    _api: ExecutionAPI,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    record: dict[str, Any] = {"name": name, "argv": argv, "cwd": str(context["bundle"]), "started_at": time.time()}
    context.setdefault("execution_log", []).append(record)
    try:
        result = subprocess.run(  # noqa: S603 - list argv, no shell
            argv,
            cwd=context["bundle"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        record.update(finished_at=time.time(), returncode=None, status="timed_out")
        raise AcceptanceRefused("native_child_timed_out:" + name) from exc
    record.update(finished_at=time.time(), returncode=result.returncode, status="process_returned")
    return result, record


def _collector_child(
    context: dict[str, Any], root: Path, operation: str, directory: Path, *, _api: ExecutionAPI
) -> dict[str, Any]:
    if operation not in {"preflight", "provision", "seed", "read"}:
        raise AcceptanceRefused("unsupported_fixed_native_operation")
    _api.validate_bundle(context["bundle"])
    _api.require_native_source_checkout(context)
    probe = _api.probe_interpreter(_api._native_python(context), cwd=context["bundle"])
    _api.validate_import_provenance(
        Path(probe["product_file"]),
        checkout=Path(context["manifest"]["checkout"]),
        environment=context["bundle"] / "wheel-env",
        mode=context["mode"],
    )
    helper = context["bundle"] / "tests/_dbcrypt_acceptance_native.py"
    environment = _api._native_environment(context, root)
    driver = _api._native_driver(context, directory)
    environment["MORDRED_DBCRYPT_PRODUCTION_DRIVER"] = str(driver)
    if operation in {"preflight", "provision"}:
        driver = _api._native_driver(context, directory, passive=True)
    if context["kind"] == "candidate":
        code = f"import runpy; raise SystemExit(runpy.run_path({str(helper)!r})['main']({operation!r}))"
        argv = [str(_api._native_python(context)), "-c", code]
    else:
        argv = [str(_api._native_python(context)), str(driver), operation]
    result, record = _api._native_process(context, argv, environment, timeout=900, name=operation)
    record.update(
        operation=operation,
        fixture_path=str(root),
        mode=context["mode"],
        bundle_manifest_sha256=_api.sha256_file(context["bundle"] / "manifest.json"),
    )
    refusal = _api.native_refusal_payload(result.stdout, operation, result.returncode)
    if refusal is not None:
        record["refusal"] = refusal
    try:
        payload = json.loads(result.stdout)
        _api._require(
            result.returncode == 0 and payload["schema_version"] == RUN_SCHEMA and payload["status"] == "executed"
        )
        _api._require(
            payload["operation"] == operation
            and payload["facts"]["native_provider"] in {"EC2 NitroTPM", "Microsoft Platform Crypto Provider"}
        )
        _api._require(payload["facts"]["helper"]["sha256"] == context["helper_sha256"])
        _api._require(payload["acceptance_kind"] == context["kind"])
        _api._require(
            payload["implementation_sha256"] == context["manifest"]["files"]["tests/_dbcrypt_acceptance_native.py"]
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise AcceptanceRefused("native_child_refused_or_failed:" + operation) from exc
    if operation == "provision" and context["kind"] == "production":
        entrypoint = Path(probe["maintenance_entrypoint"]["path"])
        _api._require(_api.sha256_file(entrypoint) == probe["maintenance_entrypoint"]["sha256"])
        copied = directory / "maintenance-entrypoint"
        if not copied.exists():
            shutil.copyfile(entrypoint, copied)
            copied.chmod(0o600)
        _api._require(_api.sha256_file(copied) == probe["maintenance_entrypoint"]["sha256"])
        record["maintenance_entrypoint_ref"] = {
            "path": copied.relative_to(directory.parent).as_posix(),
            "sha256": _api.sha256_file(copied),
        }
    record.update(
        import_probe=probe,
        payload=payload,
        status="executed",
        driver_ref={"path": driver.relative_to(directory.parent).as_posix(), "sha256": _api.sha256_file(driver)},
    )
    return record


def _record_native_test_failure(record: dict[str, Any], report: Path, directory: Path, *, _api: ExecutionAPI) -> None:
    try:
        summary = _api.native_test_failure_summary(report)
        if not _api.native_test_failure_descriptor(summary):
            raise ValueError("invalid_failure_descriptor")
    except Exception:
        # A diagnostic can never replace the original known suite failure.
        summary = {"status": "unavailable", "report_bytes": None, "report_sha256": None, "details": None}
    record["test_failure_summary"] = summary
    if summary["report_sha256"] is not None:
        record["pytest_report"] = {
            "path": report.relative_to(directory.parent).as_posix(),
            "sha256": summary["report_sha256"],
        }


def _native_suite(
    context: dict[str, Any],
    row: dict[str, Any],
    directory: Path,
    baseline: Path,
    *,
    native_facts: dict[str, Any] | None = None,
    _api: ExecutionAPI,
) -> dict[str, Any]:
    _api.validate_bundle(context["bundle"])
    _api.require_native_source_checkout(context)
    probe = _api.probe_interpreter(_api._native_python(context), cwd=context["bundle"])
    _api.validate_import_provenance(
        Path(probe["product_file"]),
        checkout=Path(context["manifest"]["checkout"]),
        environment=context["bundle"] / "wheel-env",
        mode=context["mode"],
    )
    environment = _api._native_environment(context, context["fixtures"]["persistence"])
    environment.update(row["env"])
    if row["suite"] == "linux-memory":
        # These required test metadata are scrubbed with all ambient MORDRED_*
        # values. Bind them to the validated bundle and successful seed facts.
        _api._require(_api.sys.platform == "linux" and _api._hex(context["manifest"]["commit"], 40))
        _api._require(native_facts is not None and native_facts.get("native_provider") == "EC2 NitroTPM")
        assert native_facts is not None
        environment.update(
            MORDRED_ACCEPTANCE_COMMIT=context["manifest"]["commit"],
            MORDRED_LINUX_TPM_PROVIDER=native_facts["native_provider"],
        )
    environment["MORDRED_DBCRYPT_RUN_SUITE"] = row["suite"]
    environment.update(
        MORDRED_DBCRYPT_BASELINE=str(baseline),
        MORDRED_DBCRYPT_PERSISTENCE_ROOT=str(context["fixtures"]["persistence"]),
        MORDRED_DBCRYPT_CRASH_ROOT=str(context["fixtures"]["crash"]),
        MORDRED_DBCRYPT_NEGATIVE_ROOT=str(context["fixtures"]["negative"]),
        MORDRED_WINDOWS_CUSTODY_TEST_ROOT=str(context["fixtures"]["negative"]),
    )
    report = directory / (row["suite"] + ".pytest.json")
    environment["MORDRED_DBCRYPT_PYTEST_REPORT"] = str(report)
    row_directory = directory / (row["suite"] + "-rows")
    row_directory.mkdir(mode=0o700)
    environment["MORDRED_DBCRYPT_ROW_DIRECTORY"] = str(row_directory)
    environment["MORDRED_DBCRYPT_PRODUCTION_DRIVER"] = str(_api._native_driver(context, directory))
    configuration = context["bundle"] / context["manifest"]["extracted_sdist"] / "pyproject.toml"
    argv = [
        *row["argv"],
        "--rootdir",
        str(context["bundle"]),
        "-c",
        str(configuration),
        "-p",
        "tests._dbcrypt_acceptance_native",
    ]
    selected_library = None
    if row["suite"] == "windows-vfs":
        qualification = _api.validate_windows_qualification(
            Path(context["qualification"]), checkout=Path(context["manifest"]["checkout"])
        )
        _api._require(context["kind"] == "production")
        _api.require_production_qualification(qualification)
        for name in ("MORDRED_DBCRYPT_VFS_FIXTURE_ROOT", "MORDRED_DBCRYPT_QUALIFICATION_MANIFEST"):
            if not os.environ.get(name):
                raise AcceptanceRefused("owned_windows_vfs_fixtures_required")
            environment[name] = os.environ[name]
        environment["MORDRED_DBCRYPT_TEST_ROOT"] = environment["MORDRED_DBCRYPT_VFS_FIXTURE_ROOT"]
        _api._require("MORDRED_DBCRYPT_CHECKED_LIBRARY" not in environment)
        selected = qualification[row["mode"]]
        selected_library = {"path": selected["dll"], "sha256": selected["dll_sha256"], "kind": selected["target"]}
    collect_path = directory / (row["suite"] + ".collection.json")
    collect_environment = {**environment, "MORDRED_DBCRYPT_PYTEST_REPORT": str(collect_path)}
    collect_result, collected_record = _api._native_process(
        context, [*argv, "--collect-only"], collect_environment, timeout=300, name=row["suite"] + "-collection"
    )
    if collect_result.returncode != 0 or not collect_path.is_file():
        raise AcceptanceRefused("native_complete_collection_failed:" + row["suite"])
    collection_record = {
        "argv": collected_record["argv"],
        "returncode": collect_result.returncode,
        "report": {
            "path": collect_path.relative_to(directory.parent).as_posix(),
            "sha256": _api.sha256_file(collect_path),
        },
    }
    result, record = _api._native_process(context, argv, environment, timeout=3600, name=row["suite"])
    record.update(
        suite=row["suite"],
        mode=context["mode"],
        import_probe=probe,
        gate_env=row["env"],
        bundle_manifest_sha256=_api.sha256_file(context["bundle"] / "manifest.json"),
        collection=collection_record,
    )
    if selected_library is not None:
        record["windows_library"] = selected_library
    if result.returncode or not report.is_file():
        _api._record_native_test_failure(record, report, directory)
        raise AcceptanceRefused("native_module_failed:" + row["suite"])
    record["pytest_report"] = {
        "path": report.relative_to(directory.parent).as_posix(),
        "sha256": _api.sha256_file(report),
    }
    parsed = _api.validate_native_test_report(
        json.loads(report.read_text()), platform=_api.sys.platform, suite=row["suite"]
    )
    record.update(
        nodeids=parsed["nodeids"],
        counts=parsed["counts"],
        platform_na=parsed["platform_na"],
        status="executed",
        collector_rows=[
            {"path": path.relative_to(directory.parent).as_posix(), "sha256": _api.sha256_file(path)}
            for path in sorted(row_directory.glob("*.json"))
        ],
    )
    return record


def _native_reopen_prior(context: dict[str, Any], directory: Path, *, _api: ExecutionAPI) -> dict[str, Any]:
    if context["prior"] is None:
        raise AcceptanceRefused("native_reopen_prior_missing")
    prior_path = context["prior"]
    if not prior_path.is_relative_to(directory.parent):
        raise AcceptanceRefused("prior_evidence_must_share_private_spool")
    prior = json.loads(_api._private_evidence_file(prior_path).read_text())
    _api._require(prior["status"] == context["kind"] + "_native_passed" and prior["observation"] == "provision")
    _api._require(
        prior["mode"] == context["mode"]
        and prior["bundle_manifest_sha256"] == _api.sha256_file(context["bundle"] / "manifest.json")
    )
    _api._native_phase_coverage(prior, prior_path.parent)
    _api._require(prior["native_roots"] == {key: str(path) for key, path in context["fixtures"].items()})
    return dict(prior)


def _execute_native_phase(
    context: dict[str, Any], *, phase: Phase, directory: Path, _api: ExecutionAPI
) -> dict[str, Any]:
    persistence = context["fixtures"]["persistence"]
    action_path = context["control_action_path"]
    try:
        action_relative = action_path.relative_to(directory.parent)
    except ValueError as exc:
        raise AcceptanceRefused("controller_action_must_share_private_spool") from exc
    action_reference = {"path": action_relative.as_posix(), "sha256": context["control_action"]["sha256"]}
    prior = _api._native_reopen_prior(context, directory) if phase == "reopen" else None
    executions = [_api._collector_child(context, persistence, "preflight", directory)]
    if phase == "provision":
        for fixture in context["fixtures"].values():
            executions.append(_api._collector_child(context, fixture, "provision", directory))
        executions.append(_api._collector_child(context, context["fixtures"]["negative"], "seed", directory))
        executions.append(_api._collector_child(context, persistence, "seed", directory))
        baseline = executions[-1]["payload"]
        baseline_path = directory / "baseline.json"
        _api._write_new(baseline_path, baseline)
        rows = _api.native_acceptance_commands(
            checkout=Path(context["manifest"]["checkout"]),
            bundle=context["bundle"],
            platform=_api.sys.platform,
            kind=context["kind"],
        )
        for row in rows:
            if row["mode"] == context["mode"] and "argv" in row:
                executions.append(
                    _api._native_suite(context, row, directory, baseline_path, native_facts=baseline["facts"])
                )
    executions.append(_api._collector_child(context, persistence, "read", directory))
    actual = executions[-1]["payload"]
    result = {
        "schema_version": RUN_SCHEMA,
        "mode": context["mode"],
        "acceptance_kind": context["kind"],
        "platform": _api.sys.platform,
        "bundle_manifest_sha256": _api.sha256_file(context["bundle"] / "manifest.json"),
        "bundle": {key: context["manifest"][key] for key in ("commit", "sdist_sha256", "wheel_sha256")},
        "fixture": actual["fixture"],
        "logical": actual["logical"],
        "boot": actual["facts"]["boot"],
        "native_facts": actual["facts"],
        "native_roots": {kind: str(path) for kind, path in context["fixtures"].items()},
        "bundle_evidence": _api._export_bundle_evidence(context, directory),
        "qualification_evidence": _api._export_windows_qualification(context, directory),
        "observation": context["observation"],
        "executions": executions,
        "bootstrap": "explicit_candidate" if context["kind"] == "candidate" else "automatic_production",
        "live_accepted": False,
        "unexpected_skips": [],
        "phase": phase,
        "status": context["kind"] + "_native_passed",
        "native_rows_complete": False,
        "native_implementation_sha256": context["manifest"]["files"]["tests/_dbcrypt_acceptance_native.py"],
        "instance": "i-095cbe655c196c749" if _api.sys.platform == "linux" else "i-00f4db5c3a204906b",
        "controller_run": context["control_action"]["controller_run"],
        "control_sequence": context["control_action"]["sequence"],
        "control_action": action_reference,
        "started_at": executions[0]["started_at"],
        "finished_at": time.time(),
        "limitations": ["cached_access_failure_is_injected_not_physical_tpm_disable"],
    }
    if _api.sys.platform == "win32" and context["kind"] == "candidate":
        result["qualified_vfs"] = _api._qualified_vfs_reference(
            _api.validate_windows_qualification(
                Path(context["qualification"]), checkout=Path(context["manifest"]["checkout"])
            ),
            context["mode"],
        )
    result["test_counts"] = {
        "passed": sum(row.get("counts", {}).get("passed", 0) for row in executions),
        "collected": sum(len(row.get("nodeids", [])) for row in executions),
        "platform_na": sum(row.get("counts", {}).get("platform_na", 0) for row in executions),
        "failed": 0,
        "skipped": 0,
    }
    if prior is not None:
        relative = context["prior"].relative_to(directory.parent)
        result["provision_reference"] = {"path": relative.as_posix(), "sha256": _api.sha256_file(context["prior"])}
        _api.validate_reopen_continuity(prior, result, context["observation"])
    _api._require(_api.sha256_file(action_path) == action_reference["sha256"])
    _api._native_phase_coverage(result, directory.parent)
    result["native_rows_complete"] = True
    return result
