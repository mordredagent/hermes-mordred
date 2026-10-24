#!/usr/bin/env python3
"""Bounded installed-package/native acceptance with explicit private fixtures.

Build preparation records immutable artifacts and interpreter probes. Opt-in
native phases require real helper/provider/qualified-driver prerequisites;
missing evidence refuses. Candidate rows never authorize production activation.
This tool never starts, stops or reboots compute or calls a cloud control API.
Frozen operator-furnished receipts are evidence input, not authorization.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import itertools
import json
import math
import os
import platform as host_platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal

Phase = Literal["provision", "reopen", "verify"]
Mode = Literal["source", "wheel"]
# Reviewed Task 5 release contract. Record actual collected node IDs on the
# final tree; historical source/release case counts are not acceptance input.
WINDOWS_RELEASE_SELECTION = (
    "not checkedtest and not injected_io and not every_creation and not inherited_dacl_race "
    "and not recovery_exclusive_lock and not shm_shared_lock"
)
INSTANCES = frozenset({"i-095cbe655c196c749", "i-00f4db5c3a204906b"})
# Explicit containing modules, never an unbounded repository collection.
AFFECTED_MODULES = (
    "test_dbcrypt.py",
    "test_dbcrypt_adoption.py",
    "test_dbcrypt_authority.py",
    "test_dbcrypt_backup.py",
    "test_dbcrypt_capability.py",
    "test_dbcrypt_connections.py",
    "test_dbcrypt_contracts.py",
    "test_dbcrypt_hermes.py",
    "test_dbcrypt_inventory.py",
    "test_dbcrypt_lifecycle.py",
    "test_dbcrypt_locking.py",
    "test_dbcrypt_marker.py",
    "test_dbcrypt_migrate.py",
    "test_dbcrypt_monitor.py",
    "test_dbcrypt_windows_locking.py",
    "test_dbcrypt_windows_maintenance.py",
    "test_dbcrypt_windows_paths.py",
)


class AcceptanceRefused(RuntimeError):
    """A non-secret reason why evidence cannot support acceptance."""


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_import_provenance(path: Path, *, checkout: Path, environment: Path, mode: Mode) -> None:
    origin = path.resolve(strict=True)
    checkout, environment = checkout.resolve(), environment.resolve()
    if mode == "wheel":
        if origin.is_relative_to(checkout) or not origin.is_relative_to(environment):
            raise AcceptanceRefused("wheel_import_outside_installed_environment")
    elif mode == "source":
        if not origin.is_relative_to(checkout / "src/mordred_hermes"):
            raise AcceptanceRefused("source_import_outside_checkout")
    else:
        raise AcceptanceRefused("unknown_import_mode")


def probe_environment(home: Path) -> dict[str, str]:
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


_PROBE = r"""
import importlib.metadata as metadata
import json, os, platform, sys
from pathlib import Path
# HERMES_HOME is set in the parent before interpreter startup and all imports.
assert Path(os.environ['HERMES_HOME']).name.startswith('mordred-dbcrypt-probe-')
import mordred_hermes
from mordred_hermes.keyvault import kek
kek._noop_audit = lambda entry: None
versions = {}
for name in ('hermes-mordred', 'hermes-agent', 'sqlcipher3-wheels', 'pytest'):
    try: versions[name] = metadata.version(name)
    except metadata.PackageNotFoundError: versions[name] = None
import sqlcipher3.dbapi2 as driver
connection = driver.connect(':memory:')
try:
    cipher = connection.execute('PRAGMA cipher_version').fetchone()
finally:
    connection.close()
token = {'elevated': None, 'uid': None}
if os.name == 'nt':
    import ctypes
    token['elevated'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
else:
    token['uid'] = os.getuid()
print(json.dumps({
    'product_file': str(Path(mordred_hermes.__file__).resolve()),
    'interpreter': str(Path(sys.executable).resolve()),
    'python_version': platform.python_version(), 'platform': sys.platform,
    'versions': versions,
    'driver': {'module': str(Path(driver.__file__).resolve()), 'sqlite_version': driver.sqlite_version,
               'cipher_version': cipher[0] if cipher else None},
    'token': token, 'home_is_temporary': True,
    'native_provider': None, 'native_helper': None,
    'readiness': 'not_probed_no_native_collector'
}))
"""


def probe_interpreter(interpreter: Path, *, cwd: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-probe-") as directory:
        result = subprocess.run(
            [str(interpreter), "-c", _PROBE],
            cwd=cwd,
            env=probe_environment(Path(directory)),
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


def _python(environment: Path, platform: str = sys.platform) -> Path:
    return environment / ("Scripts/python.exe" if platform == "win32" else "bin/python")


def _suites(platform: str) -> list[tuple[str, tuple[str, ...], dict[str, str], bool]]:
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


def acceptance_commands(*, checkout: Path, bundle: Path, platform: str) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for suite, modules, gates, integration in _suites(platform):
        for mode in ("wheel",) if suite == "linux-memory" else ("source", "wheel"):
            prefix = (
                ["uv", "run", "--project", str(checkout), "pytest", "-q"]
                if mode == "source"
                else [
                    "uv",
                    "run",
                    "--no-project",
                    "--python",
                    str(_python(bundle / "wheel-env", platform)),
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


def load_stop_receipt(path: Path) -> dict[str, Any]:
    """Read a frozen final controller receipt; do not invoke AWS or trust a flag.

    This validates the existing controller's receipt shape, not authenticity of
    operator input. Full acceptance additionally needs independent EC2 state
    observations bound to this run (not implemented in this inert slice).
    """
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("not a private regular file")
        if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("permissions")
        payload = path.read_bytes()
        value = json.loads(payload)
        created, deadline, stopped = (value.get(key) for key in ("created", "deadline", "stopped_at"))
        if not all(type(item) in (int, float) and math.isfinite(item) for item in (created, deadline, stopped)):
            raise ValueError("timestamps")
        if not 120 <= deadline - created <= 7200 or stopped < created:
            raise ValueError("timestamps")
        if (
            value.get("version") != 1
            or value.get("instance") not in INSTANCES
            or value.get("state") != "stopped"
            or value.get("start_requested") is not True
            or value.get("start_uncertain") is not False
            or not isinstance(value.get("run"), str)
            or len(value["run"]) != 32
            or any(char not in "0123456789abcdef" for char in value["run"])
            or not isinstance(value.get("account"), str)
            or len(value["account"]) != 12
            or not value["account"].isdecimal()
        ):
            raise ValueError("identity or final state")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise AcceptanceRefused("invalid_independent_stop_receipt") from exc
    return {
        **{key: value[key] for key in ("instance", "run", "created", "deadline", "stopped_at", "state")},
        "sha256": hashlib.sha256(payload).hexdigest(),
        "path": str(path.resolve()),
        "verification": "frozen_controller_record_only",
    }


def acceptance_failures(evidence: dict[str, Any]) -> list[str]:
    """Fail closed: bookkeeping fixtures/booleans can never enable qualification."""
    failures = []
    if not evidence.get("executions"):
        failures.append("missing_native_rows")
    bundle = evidence.get("bundle")
    if not isinstance(bundle, dict) or not all(
        bundle.get(key) for key in ("commit", "sdist_sha256", "wheel_sha256", "source_probe", "wheel_probe")
    ):
        failures.append("missing_bundle_provenance")
    if {row.get("phase") for row in evidence.get("phases", []) if isinstance(row, dict)} != {
        "provision",
        "reopen",
        "verify",
    }:
        failures.append("missing_phases")
    if evidence.get("unexpected_skips") != []:
        failures.append("unexpected_skips")
    token = evidence.get("token", {})
    if evidence.get("platform") == "win32" and (not isinstance(token, dict) or token.get("elevated") is not False):
        failures.append("ordinary_windows_token_required")
    if evidence.get("native_provider") not in {"EC2 NitroTPM", "Microsoft Platform Crypto Provider"}:
        failures.append("native_provider_unproven")
    receipts = evidence.get("owned_instance_receipts")
    if not isinstance(receipts, list) or not receipts:
        failures.append("missing_independent_stop_receipt")
    elif any(
        not isinstance(row, dict) or row.get("state") != "stopped" or not row.get("sha256") or not row.get("stopped_at")
        for row in receipts
    ):
        failures.append("incomplete_final_stop")
    return failures


def _write_new(path: Path, value: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _root_identity(root: Path) -> dict[str, Any]:
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


def run_acceptance(*, root: Path, phase: Phase, output: Path) -> int:
    started = time.time()
    context: dict[str, Any] | None = None
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "phase": phase,
        "status": "refused",
        "live_accepted": False,
        "platform": sys.platform,
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
        evidence["root"] = _root_identity(root)
        bundle_text = os.environ.get("DBCRYPT_BUNDLE")
        if bundle_text and phase != "verify":
            bundle = Path(bundle_text)
            manifest = validate_bundle(bundle)
            evidence["bundle"] = {
                key: manifest.get(key)
                for key in ("commit", "sdist_sha256", "wheel_sha256", "source_probe", "wheel_probe")
            }
            evidence["bundle_manifest_sha256"] = sha256_file(bundle / "manifest.json")
        receipt = os.environ.get("MORDRED_DBCRYPT_STOP_RECEIPT")
        if receipt and phase != "verify":
            evidence["owned_instance_receipts"] = [load_stop_receipt(Path(receipt))]
        if phase == "verify":
            evidence.update(verify_native_spool(root))
        else:
            context = native_phase_inputs(root, phase)
            directory = output.parent / (output.stem + "-files")
            directory.mkdir(mode=0o700)
            evidence.update(_execute_native_phase(context, phase=phase, directory=directory))
            evidence["reasons"] = ["native_coverage_incomplete"] if not evidence["native_rows_complete"] else []
    except (ValueError, TypeError, KeyError, StopIteration):
        evidence["reasons"].append("native_evidence_invalid")
    except (AcceptanceRefused, OSError, subprocess.SubprocessError) as exc:
        if context is not None:
            evidence["executions"] = context.get("execution_log", [])
        evidence["reasons"].append(str(exc) if isinstance(exc, AcceptanceRefused) else "root_probe_failed")
    evidence["finished_at"] = time.time()
    _write_new(output, evidence)
    return 0 if evidence["status"] in {"candidate_native_passed", "production_native_passed"} else 2


def extract_sdist(archive: Path, destination: Path) -> Path:
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


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("inconsistent bundle provenance")


def _object(value: Any, required: tuple[str, ...]) -> dict[str, Any]:
    _require(isinstance(value, dict) and all(key in value for key in required))
    return dict(value)


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _timestamp(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _relative(value: Any) -> Path:
    _require(_text(value))
    path = Path(value)
    _require(
        not path.is_absolute()
        and path.as_posix() == value
        and not any(part in {".", ".."} for part in path.parts)
        and "\\" not in value
        and ":" not in value
    )
    return path


def _absolute(value: Any) -> Path:
    _require(_text(value))
    path = Path(value)
    _require(path.is_absolute() and str(path.resolve(strict=True)) == value)
    return path


def _validate_probe(value: Any, *, mode: Mode, checkout: Path, root: Path) -> dict[str, Any]:
    probe = _object(
        value,
        (
            "product_file",
            "interpreter",
            "python_version",
            "platform",
            "versions",
            "driver",
            "token",
            "home_is_temporary",
            "native_provider",
            "native_helper",
            "readiness",
        ),
    )
    _require(probe["platform"] in {"linux", "darwin", "win32"} and _text(probe["python_version"]))
    environment = checkout / ".venv" if mode == "source" else root / "wheel-env"
    interpreter = _absolute(probe["interpreter"])
    _require(interpreter.is_file() and interpreter == _python(environment, probe["platform"]).resolve(strict=True))
    origin = _absolute(probe["product_file"])
    _require(origin.name == "__init__.py" and origin.parent.name == "mordred_hermes")
    validate_import_provenance(origin, checkout=checkout, environment=root / "wheel-env", mode=mode)
    if mode == "wheel":
        _require(origin.parent.parent.name == "site-packages")
    versions = _object(probe["versions"], ("hermes-mordred", "hermes-agent", "sqlcipher3-wheels", "pytest"))
    _require(all(_text(versions[key]) for key in ("hermes-mordred", "hermes-agent", "sqlcipher3-wheels", "pytest")))
    driver = _object(probe["driver"], ("module", "sqlite_version", "cipher_version"))
    _require(all(_text(driver[key]) for key in ("sqlite_version", "cipher_version")))
    _require(_absolute(driver["module"]).is_relative_to(environment) and Path(driver["module"]).is_file())
    token = _object(probe["token"], ("elevated", "uid"))
    _require(type(token["elevated"]) in (bool, type(None)) and (type(token["uid"]) is int or token["uid"] is None))
    _require(probe["home_is_temporary"] is True and probe["native_provider"] is None and probe["native_helper"] is None)
    _require(probe["readiness"] == "not_probed_no_native_collector")
    return probe


def _validate_build_records(value: Any, *, root: Path, checkout: Path, extracted: Path, wheel: Path) -> None:
    _require(isinstance(value, list) and len(value) == 6)
    for row in value:
        record = _object(row, ("argv", "cwd", "started_at", "finished_at", "returncode"))
        _require(
            isinstance(record["argv"], list) and bool(record["argv"]) and all(_text(arg) for arg in record["argv"])
        )
        _require(record["cwd"] == str(root) and type(record["returncode"]) is int and record["returncode"] == 0)
        _require(
            _timestamp(record["started_at"])
            and _timestamp(record["finished_at"])
            and record["finished_at"] >= record["started_at"]
        )
    _require(value[0]["argv"] == ["uv", "build", "--sdist", str(checkout), "--out-dir", str(root / "artifacts")])
    for index, environment in ((1, root / "build-env"), (2, root / "wheel-env")):
        argv = value[index]["argv"]
        _require(len(argv) == 6 and argv[:4] == ["uv", "venv", "--no-project", "--python"])
        _require(argv[-1] == str(environment) and Path(argv[4]).is_absolute())
        _require(Path(argv[4]).resolve(strict=True) == _python(checkout / ".venv").resolve(strict=True))
    _require(
        value[3]["argv"] == ["uv", "pip", "install", "--python", str(_python(root / "build-env")), "hatchling>=1.18"]
    )
    _require(
        value[4]["argv"]
        == [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            str(_python(root / "build-env")),
            str(extracted),
            "--out-dir",
            str(root / "artifacts"),
        ]
    )
    _require(
        value[5]["argv"]
        == [
            "uv",
            "pip",
            "install",
            "--python",
            str(_python(root / "wheel-env")),
            "--link-mode",
            "copy",
            str(wheel) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ]
    )


def _validate_manifest(value: Any, root: Path) -> dict[str, Any]:
    manifest = _object(
        value,
        (
            "schema_version",
            "commit",
            "checkout",
            "created_at",
            "sdist",
            "sdist_sha256",
            "wheel",
            "wheel_sha256",
            "extracted_sdist",
            "source_probe",
            "wheel_probe",
            "build_commands",
            "files",
            "native_qualification",
            "native_collectors",
            "missing_native_hooks",
        ),
    )
    _require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1)
    _require(_hex(manifest["commit"], 40) and _timestamp(manifest["created_at"]))
    checkout = _absolute(manifest["checkout"])
    _require(checkout.is_dir() and not root.is_relative_to(checkout))
    files = manifest["files"]
    _require(isinstance(files, dict) and bool(files))
    for name, digest in files.items():
        _relative(name)
        _require(_hex(digest, 64))
    source = _validate_probe(manifest["source_probe"], mode="source", checkout=checkout, root=root)
    wheel_probe = _validate_probe(manifest["wheel_probe"], mode="wheel", checkout=checkout, root=root)
    _require(source["platform"] == wheel_probe["platform"])
    version = source["versions"]["hermes-mordred"]
    _require(version == wheel_probe["versions"]["hermes-mordred"])
    sdist, wheel = (_relative(manifest[key]) for key in ("sdist", "wheel"))
    _require(sdist.as_posix() == f"artifacts/hermes_mordred-{version}.tar.gz")
    _require(
        wheel.parent == Path("artifacts")
        and wheel.name.startswith(f"hermes_mordred-{version}-")
        and wheel.suffix == ".whl"
    )
    for kind, path in (("sdist", sdist), ("wheel", wheel)):
        digest = manifest[kind + "_sha256"]
        _require(_hex(digest, 64) and files.get(path.as_posix()) == digest and sha256_file(root / path) == digest)
    extracted = _relative(manifest["extracted_sdist"])
    _require(extracted.as_posix() == f"extracted-sdist/{sdist.name[:-7]}")
    required = (
        "tests/test_dbcrypt.py",
        "tests/conftest.py",
        "tools/dbcrypt_acceptance.py",
        (extracted / "pyproject.toml").as_posix(),
        Path(wheel_probe["product_file"]).relative_to(root).as_posix(),
    )
    _require(all(name in files for name in required))
    _validate_build_records(
        manifest["build_commands"], root=root, checkout=checkout, extracted=root / extracted, wheel=root / wheel
    )
    _require(manifest["native_qualification"] == "not_run" and manifest["native_collectors"] == "not_integrated")
    _require(
        manifest["missing_native_hooks"]
        == [
            "provision",
            "reopen",
            "verify",
            "independent_ec2_observations",
            "collector_records_across_os_reboot_and_stop_start",
        ]
    )
    if source["platform"] in {"linux", "win32"}:
        _require(
            manifest.get("acceptance_commands")
            == acceptance_commands(checkout=checkout, bundle=root, platform=source["platform"])
        )
    return manifest


def validate_bundle(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if (root / "src").exists() or (root / "mordred_hermes").exists():
        raise AcceptanceRefused("product_source_on_test_path")
    try:
        manifest = _validate_manifest(json.loads(_input_file(root / "manifest.json").read_text()), root)
        _require(_bundle_hashes(root) == manifest["files"])
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise AcceptanceRefused("bundle_hash_mismatch_or_invalid_provenance") from exc
    return manifest


def _run_build(argv: list[str], *, cwd: Path, environment: dict[str, str], log: list[dict[str, Any]]) -> str:
    started = time.time()
    result = subprocess.run(argv, cwd=cwd, env=environment, text=True, capture_output=True, timeout=900, check=False)
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


def _git(checkout: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(checkout), *args], capture_output=True, text=True, timeout=30, check=False
    )
    if result.returncode:
        raise AcceptanceRefused("checkout_git_provenance_unavailable")
    return result.stdout.strip()


def _copy_inputs(checkout: Path, output: Path) -> None:
    names = _git(checkout, "ls-files", "-z", "--", "tests", "tools").split("\0")
    for name in names:
        if not name:
            continue
        source, target = checkout / name, output / name
        if source.is_symlink() or not source.is_file():
            raise AcceptanceRefused("unsafe_checkout_input")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _bundle_artifact(directory: Path, pattern: str) -> Path:
    candidates = list(directory.glob(pattern))
    if len(candidates) != 1:
        raise AcceptanceRefused("bundle_artifact_count")
    return candidates[0]


def _bundle_build(checkout: Path, output: Path, commands: list[dict[str, Any]], home: Path) -> dict[str, Any]:
    environment = probe_environment(home)
    # Windows build hook requires explicitly prepared, reviewed header inputs.
    # It must never fall back to a network header download or a stale DLL.
    if "MORDRED_SQLITE_INCLUDE_DIR" in os.environ:
        environment["MORDRED_SQLITE_INCLUDE_DIR"] = os.environ["MORDRED_SQLITE_INCLUDE_DIR"]
    artifacts = output / "artifacts"
    artifacts.mkdir()
    if sys.platform == "win32":
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
    _run_build(
        ["uv", "build", "--sdist", str(checkout), "--out-dir", str(artifacts)],
        cwd=output,
        environment=environment,
        log=commands,
    )
    sdist = _bundle_artifact(artifacts, "*.tar.gz")
    extracted = extract_sdist(sdist, output / "extracted-sdist")
    build_env, wheel_env = output / "build-env", output / "wheel-env"
    for directory in (build_env, wheel_env):
        _run_build(
            ["uv", "venv", "--no-project", "--python", sys.executable, str(directory)],
            cwd=output,
            environment=environment,
            log=commands,
        )
    _run_build(
        ["uv", "pip", "install", "--python", str(_python(build_env)), "hatchling>=1.18"],
        cwd=output,
        environment=environment,
        log=commands,
    )
    _run_build(
        [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            str(_python(build_env)),
            str(extracted),
            "--out-dir",
            str(artifacts),
        ],
        cwd=output,
        environment=environment,
        log=commands,
    )
    wheel = _bundle_artifact(artifacts, "*.whl")
    _run_build(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(_python(wheel_env)),
            "--link-mode",
            "copy",
            str(wheel) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ],
        cwd=output,
        environment=environment,
        log=commands,
    )
    source_probe = probe_interpreter(_python(checkout / ".venv"), cwd=output)
    wheel_probe = probe_interpreter(_python(wheel_env), cwd=output)
    validate_import_provenance(
        Path(source_probe["product_file"]), checkout=checkout, environment=wheel_env, mode="source"
    )
    validate_import_provenance(
        Path(wheel_probe["product_file"]), checkout=checkout, environment=wheel_env, mode="wheel"
    )
    if source_probe["versions"]["hermes-mordred"] != wheel_probe["versions"]["hermes-mordred"]:
        raise AcceptanceRefused("source_wheel_version_mismatch")
    return {
        "sdist": sdist.relative_to(output).as_posix(),
        "sdist_sha256": sha256_file(sdist),
        "wheel": wheel.relative_to(output).as_posix(),
        "wheel_sha256": sha256_file(wheel),
        "extracted_sdist": extracted.relative_to(output).as_posix(),
        "source_probe": source_probe,
        "wheel_probe": wheel_probe,
    }


def _input_file(path: Path) -> Path:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return path


def _bytecode(directory: Path) -> None:
    _require(stat.S_ISDIR(directory.lstat().st_mode))
    for path in directory.iterdir():
        _require(path.suffix == ".pyc")
        _input_file(path)


def _tree_inputs(directory: Path) -> list[Path]:
    _require(stat.S_ISDIR(directory.lstat().st_mode))
    files = []
    for path in directory.iterdir():
        if path.name == "__pycache__":
            _bytecode(path)
        elif stat.S_ISDIR(path.lstat().st_mode):
            files.extend(_tree_inputs(path))
        else:
            files.append(_input_file(path))
    return files


def _site_packages(output: Path) -> Path:
    environment = output / "wheel-env"
    candidates = (
        [environment / "Lib/site-packages"]
        if sys.platform == "win32"
        else [environment / "lib/site-packages", *(environment / "lib").glob("python*/site-packages")]
    )
    existing = [path for path in candidates if path.is_dir()]
    _require(len(existing) == 1)
    return existing[0]


def _input_root_layout(output: Path) -> None:
    # Only these top-level locations exist in an acceptance bundle. Mutable
    # evidence belongs under outputs/, never beside copied collection inputs.
    trees = {"tests", "tools", "extracted-sdist", "artifacts", "build-env", "wheel-env"}
    for path in output.iterdir():
        if path.name == "manifest.json":
            _input_file(path)
        elif path.name == "__pycache__":
            _bytecode(path)
        else:
            _require(path.name in trees | {".pytest_cache", "outputs"} and stat.S_ISDIR(path.lstat().st_mode))
    _require(all(stat.S_ISDIR((output / name).lstat().st_mode) for name in trees))


def _bundle_hashes(output: Path) -> dict[str, str]:
    """Inventory only owned trees plus explicit interpreter startup surfaces.

    Bytecode, the root pytest cache and outputs/ are mutable and excluded.
    Third-party dependency trees and the build environment are not rescanned.
    Their recorded versions do not claim a dependency-file integrity guarantee.
    """
    try:
        _input_root_layout(output)
        paths = [
            path for name in ("tests", "tools", "extracted-sdist", "artifacts") for path in _tree_inputs(output / name)
        ]
        site = _site_packages(output)
        paths.extend(_tree_inputs(site / "mordred_hermes"))
        paths.append(_input_file(output / "wheel-env/pyvenv.cfg"))
        paths.extend(
            _input_file(path)
            for path in site.iterdir()
            if path.suffix == ".pth"
            or (
                path.name.split(".", 1)[0] in {"sitecustomize", "usercustomize", "mordred_hermes"}
                and path.name != "mordred_hermes"
            )
        )
        return {path.relative_to(output).as_posix(): sha256_file(path) for path in sorted(paths)}
    except (OSError, ValueError) as exc:
        raise AcceptanceRefused("unsafe_bundle_input_inventory") from exc


def build_acceptance_bundle(*, checkout: Path, output: Path, source_build_receipts: Path | None = None) -> Path:
    checkout, output = checkout.resolve(strict=True), output.resolve()
    if output.is_relative_to(checkout):
        raise AcceptanceRefused("bundle_must_be_outside_checkout")
    if output.exists():
        raise AcceptanceRefused("bundle_output_already_exists")
    if sys.platform == "win32" and source_build_receipts is None:
        raise AcceptanceRefused("source_editable_build_receipts_required")
    commit = _git(checkout, "rev-parse", "HEAD")
    if _git(checkout, "status", "--porcelain", "--untracked-files=normal"):
        raise AcceptanceRefused("clean_committed_checkout_required")
    output.mkdir(mode=0o700, parents=True)
    commands: list[dict[str, Any]] = []
    try:
        _copy_inputs(checkout, output)
        with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-build-") as directory:
            provenance = _bundle_build(checkout, output, commands, Path(directory))
        if source_build_receipts is not None:
            _copy_build_receipts(source_build_receipts, output / "artifacts/native-build/source")
        if _git(checkout, "rev-parse", "HEAD") != commit or _git(
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
            "files": _bundle_hashes(output),
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
        if sys.platform in {"linux", "win32"}:
            manifest["acceptance_commands"] = acceptance_commands(
                checkout=checkout, bundle=output, platform=sys.platform
            )
        _write_new(output / "manifest.json", manifest)
        validate_bundle(output)
    except (AcceptanceRefused, OSError, subprocess.SubprocessError) as exc:
        _write_new(
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


RUN_SCHEMA = 2
ADDITIONAL_MODULES = (
    "test_activity_store.py",
    "test_activity_gate.py",
    "test_activity_schema.py",
    "imports/test_import_store.py",
    "test_mail_cross_platform_storage.py",
    "test_mail_secrets.py",
    "test_mail_imap_sync.py",
    "extension/test_telegram_migrate_store.py",
    "extension/test_telegram_history.py",
    "extension/test_telegram_service_custody.py",
    "test_keyvault_database_authority.py",
    "test_database_mutation_broker.py",
    "test_database_mutation_canonical.py",
    "test_wizard_databases_authority.py",
    "test_runtime_bootstrap.py",
    "test_pth_bootstrap.py",
)


def native_fixture_paths(root: Path, mode: str) -> dict[str, Path]:
    if mode not in {"source", "wheel"}:
        raise AcceptanceRefused("native_mode_required")
    return {kind: root / f"mordred-dbcrypt-{mode}-{kind}" for kind in ("persistence", "crash", "negative")}


def require_native_source_checkout(context: dict[str, Any]) -> None:
    if context["mode"] == "source":
        checkout = Path(context["manifest"]["checkout"])
        if _git(checkout, "rev-parse", "HEAD") != context["manifest"]["commit"] or _git(
            checkout, "status", "--porcelain", "--untracked-files=normal"
        ):
            raise AcceptanceRefused("source_checkout_changed_since_bundle")


def _private_evidence_file(path: Path) -> Path:
    _input_file(path)
    info = path.stat()
    _require(os.name == "nt" or (info.st_uid == os.getuid() and info.st_mode & 0o077 == 0))
    return path


def _owned_copy_directories(parent: Path, copied: Path) -> None:
    current = parent
    for part in (None, *copied.parent.relative_to(parent).parts):
        if part is not None:
            current /= part
        info = current.lstat()
        _require(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400)
        _require(os.name == "nt" or (info.st_uid == os.getuid() and info.st_mode & 0o077 == 0))


def validate_withdrawable_helper(manifest: Path, *, production: Path, parent: Path) -> dict[str, Any]:
    """Admit only the declared private copy of the actual helper, never create it."""
    try:
        parent, production = _absolute(str(parent)), _absolute(str(production))
        value = _object(
            json.loads(_private_evidence_file(manifest).read_text()),
            ("schema_version", "kind", "path", "sha256", "production_helper_sha256", "identity"),
        )
        _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
        _require(value["kind"] == "dbcrypt_withdrawable_helper")
        copied = _absolute(value["path"])
        _require(copied.is_relative_to(parent) and copied != production and not copied.samefile(production))
        _private_evidence_file(copied)
        _owned_copy_directories(parent, copied)
        _require(os.name == "nt" or bool(copied.stat().st_mode & stat.S_IXUSR))
        _require(copied.suffix.lower() == production.suffix.lower())
        expected = _object(value["identity"], ("device", "inode", "size"))
        _require(
            set(expected) == {"device", "inode", "size"}
            and all(type(item) is int and item >= 0 for item in expected.values())
        )
        info = copied.stat()
        _require(expected == {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size})
        _require(_hex(value["sha256"], 64) and value["sha256"] == value["production_helper_sha256"])
        _require(sha256_file(copied) == value["sha256"] == sha256_file(production))
        retained = copied.with_name(copied.name + ".task15-withdrawn")
        _require(not retained.exists() and not retained.is_symlink())
        return {**value, "manifest_sha256": sha256_file(manifest), "retained_path": str(retained)}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("owned_withdrawable_helper_prerequisite_invalid") from exc


def validate_helper_withdrawal(value: Any) -> dict[str, Any]:
    try:
        row = _object(value, ("kind", "copy", "initial_acquisition", "missing_helper_acquisition", "restored"))
        _require(row["kind"] == "owned_helper_withdrawal")
        copied = row["copy"]
        _require(_hex(copied["sha256"], 64) and copied["sha256"] == copied["production_helper_sha256"])
        _require(_hex(copied["manifest_sha256"], 64) and _text(copied["path"]))
        first, missing = row["initial_acquisition"], row["missing_helper_acquisition"]
        _require(first["returncode"] == 0 and missing["returncode"] == 2)
        for observed, outcome in ((first, "acquired"), (missing, "refused")):
            payload = observed["payload"]
            _require(payload["operation"] == "fresh_unpatched_authority" and payload["outcome"] == outcome)
            _require(payload["bootstrap"] == "direct_unpatched_authority")
            _require(payload["source_before"] == payload["source_after"])
            _require(_hex(payload["source_before"]["record_sha256"], 64))
            _require(_timestamp(observed["started_at"]) and observed["finished_at"] >= observed["started_at"])
        _require(first["payload"]["helper_found"] == copied["path"] and missing["payload"]["helper_found"] is None)
        _require(first["payload"]["source_before"] == missing["payload"]["source_before"])
        _require(first["finished_at"] <= missing["started_at"])
        _require(row["restored"]["sha256"] == copied["sha256"] and row["restored"]["identity"] == copied["identity"])
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("helper_withdrawal_evidence_incomplete") from exc
    return row


CONTROL_MARGIN = 60.0  # Existing dbcrypt_acceptance_control.STOP_MARGIN.
PLATFORM_INSTANCE = {"linux": "i-095cbe655c196c749", "win32": "i-00f4db5c3a204906b"}


def _controller_snapshot(directory: Path, reference: Any, stage: str) -> tuple[dict[str, Any], float]:
    path, row = _evidence_ref(directory, reference)
    _private_evidence_file(path)
    captured = reference["captured_at"]
    _require(_timestamp(captured) and type(row["version"]) is int and row["version"] == 1)
    _require(row["instance"] in INSTANCES and _hex(row["run"], 32))
    _require(
        isinstance(row["account"], str)
        and len(row["account"]) == 12
        and row["account"].isascii()
        and row["account"].isdecimal()
    )
    _require(_timestamp(row["created"]) and _timestamp(row["deadline"]))
    _require(120 <= row["deadline"] - row["created"] <= 7200 and row["created"] <= captured)
    expected_state = "armed" if stage in {"armed", "ready"} else "stopped" if stage == "stopped" else "running"
    _require(row["state"] == expected_state and row["start_requested"] is (expected_state != "armed"))
    if stage != "armed":
        _require(type(row["supervisor_pid"]) is int and row["supervisor_pid"] > 0)
        _require(_timestamp(row["heartbeat"]) and row["created"] <= row["heartbeat"] <= captured)
    if expected_state != "armed":
        _require(row["start_uncertain"] is False)
    if stage == "stopped":
        load_stop_receipt(path)
        _require(row["stopped_at"] <= captured)
    return row, float(captured)


def _same_controller_run(first: dict[str, Any], second: dict[str, Any]) -> None:
    _require(all(first[key] == second[key] for key in ("version", "instance", "run", "account", "created", "deadline")))


def _control_start(
    action: dict[str, Any], directory: Path, armed: dict[str, Any], before: dict[str, Any], mode: str
) -> str | None:
    started, captured = _controller_snapshot(directory, action["started"], "started")
    _same_controller_run(armed, started)
    _require(started["supervisor_pid"] == before["supervisor_pid"] and action["action_at"] <= captured)
    initial = _cloud_observation(directory, action["initial_stopped"])
    running = _cloud_observation(directory, action["running"])
    _require(initial["instance"] == armed["instance"] and initial["controller_run"] == armed["run"])
    _require(initial["state"] == "stopped" and initial["_owner"] is None and initial["_account"] == armed["account"])
    _require(armed["created"] <= initial["observed_at"] <= action["action_at"] <= captured <= running["observed_at"])
    previous_run = None
    if action["operation"] == "stop_start" or action["sequence"] > 1:
        stopped, stopped_capture = _controller_snapshot(directory, action["previous_stop"], "stopped")
        observed = _cloud_observation(directory, action["previous_independent_stop"])
        _require(stopped["instance"] == armed["instance"] and stopped["account"] == armed["account"])
        _require(stopped["run"] != armed["run"] and observed["controller_run"] == stopped["run"])
        _require(
            observed["instance"] == armed["instance"] and observed["state"] == "stopped" and observed["_owner"] is None
        )
        _require(
            observed["_account"] == armed["account"] and stopped_capture <= observed["observed_at"] <= armed["created"]
        )
        previous_run = str(stopped["run"])
    return previous_run


def _control_reboot(action: dict[str, Any], directory: Path, armed: dict[str, Any], mode: str) -> None:
    path, anchor = _evidence_ref(directory, action["start_action"])
    _require(anchor["operation"] in {"start", "stop_start"})
    observation = "provision" if anchor["operation"] == "start" else "ec2_stop_start"
    prior = validate_control_action(path, platform=action["platform"], mode=mode, observation=observation)
    anchor_armed, _captured = _controller_snapshot(path.parent, anchor["armed"], "armed")
    _same_controller_run(armed, anchor_armed)
    _require(prior["sequence"] < action["sequence"] and prior["running_at"] < action["action_at"])
    _require(set(action["modes"]) <= set(prior["modes"]))


def validate_control_action(path: Path, *, platform: str, mode: str, observation: str) -> dict[str, Any]:
    """Validate frozen existing-controller and raw-state evidence; never call AWS."""
    try:
        action = _object(
            json.loads(_private_evidence_file(path).read_text()),
            (
                "schema_version",
                "kind",
                "platform",
                "instance",
                "modes",
                "sequence",
                "operation",
                "action_at",
                "armed",
                "before_action",
                "running",
            ),
        )
        _require(
            type(action["schema_version"]) is int
            and action["schema_version"] == 1
            and action["kind"] == "dbcrypt_control_action"
        )
        _require(action["platform"] == platform and action["instance"] == PLATFORM_INSTANCE[platform])
        _require(
            action["operation"]
            == {
                "provision": "start",
                "process_restart": "start",
                "os_reboot": "reboot",
                "ec2_stop_start": "stop_start",
            }[observation]
        )
        _require(
            isinstance(action["modes"], list)
            and mode in action["modes"]
            and action["modes"] == sorted(set(action["modes"]))
        )
        _require(
            set(action["modes"]) <= {"source", "wheel"} and type(action["sequence"]) is int and action["sequence"] > 0
        )
        _require(_timestamp(action["action_at"]))
        armed, armed_capture = _controller_snapshot(path.parent, action["armed"], "armed")
        stage = "active" if action["operation"] == "reboot" else "ready"
        before, before_capture = _controller_snapshot(path.parent, action["before_action"], stage)
        _same_controller_run(armed, before)
        _require(armed["instance"] == action["instance"])
        _require(armed_capture <= before_capture <= action["action_at"] < armed["deadline"] - CONTROL_MARGIN)
        _require(0 <= action["action_at"] - before["heartbeat"] <= 10)
        previous = None
        if action["operation"] == "reboot":
            _control_reboot(action, path.parent, armed, mode)
        else:
            previous = _control_start(action, path.parent, armed, before, mode)
        running = _cloud_observation(path.parent, action["running"])
        _require(running["instance"] == action["instance"] and running["controller_run"] == armed["run"])
        _require(
            running["state"] == "running"
            and running["_owner"] == armed["run"]
            and running["_account"] == armed["account"]
        )
        _require(action["action_at"] <= running["observed_at"] < armed["deadline"])
        return {
            "platform": platform,
            "instance": action["instance"],
            "controller_run": armed["run"],
            "modes": action["modes"],
            "sequence": action["sequence"],
            "operation": action["operation"],
            "action_at": action["action_at"],
            "running_at": running["observed_at"],
            "created": armed["created"],
            "deadline": armed["deadline"],
            "previous_run": previous,
            "sha256": sha256_file(path),
        }
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("controller_action_incomplete") from exc


def validate_phase_control_binding(phase: dict[str, Any], *, directory: Path) -> dict[str, Any]:
    try:
        path, _record = _evidence_ref(directory, phase["control_action"])
        action = validate_control_action(
            path, platform=phase["platform"], mode=phase["mode"], observation=phase["observation"]
        )
        _require(phase["instance"] == action["instance"] and phase["controller_run"] == action["controller_run"])
        _require(phase["control_sequence"] == action["sequence"])
        _require(
            action["running_at"] <= phase["started_at"] <= phase["finished_at"] < action["deadline"] - CONTROL_MARGIN
        )
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("controller_phase_binding_incomplete") from exc
    return action


def _settled_control_cycle(root: Path, value: Any) -> dict[str, Any]:
    cycle = _object(value, ("action", "stopped", "independent_stopped"))
    path, raw = _evidence_ref(root, cycle["action"])
    observation = {"start": "provision", "reboot": "os_reboot", "stop_start": "ec2_stop_start"}[raw["operation"]]
    _require(isinstance(raw["modes"], list) and bool(raw["modes"]))
    action = validate_control_action(path, platform=raw["platform"], mode=raw["modes"][0], observation=observation)
    armed, _capture = _controller_snapshot(path.parent, raw["armed"], "armed")
    stopped, stopped_capture = _controller_snapshot(root, cycle["stopped"], "stopped")
    _same_controller_run(armed, stopped)
    observed = _cloud_observation(root, cycle["independent_stopped"])
    _require(observed["instance"] == action["instance"] and observed["controller_run"] == action["controller_run"])
    _require(observed["state"] == "stopped" and observed["_owner"] is None and observed["_account"] == armed["account"])
    _require(action["running_at"] <= stopped["stopped_at"] <= stopped_capture <= observed["observed_at"])
    return {
        **action,
        "stopped_at": stopped["stopped_at"],
        "independent_stopped_at": observed["observed_at"],
        "stopped_sha256": cycle["stopped"]["sha256"],
        "independent_stopped_sha256": cycle["independent_stopped"]["sha256"],
        "action_path": path,
        "action_record": raw,
    }


def _ordered_control_cycles(cycles: list[dict[str, Any]]) -> None:
    for platform in {row["platform"] for row in cycles}:
        ordered = sorted((row for row in cycles if row["platform"] == platform), key=lambda row: row["sequence"])
        _require([row["sequence"] for row in ordered] == list(range(1, len(ordered) + 1)))
        _require(ordered[0]["operation"] == "start")
        for before, after in itertools.pairwise(ordered):
            _require(before["action_at"] < after["action_at"])
            if after["operation"] == "reboot":
                _require(
                    before["controller_run"] == after["controller_run"]
                    and before["stopped_sha256"] == after["stopped_sha256"]
                )
            else:
                _require(after["previous_run"] == before["controller_run"])
                record = after["action_record"]
                _require(record["previous_stop"]["sha256"] == before["stopped_sha256"])
                _require(record["previous_independent_stop"]["sha256"] == before["independent_stopped_sha256"])
                _require(before["independent_stopped_at"] <= after["created"])


def validate_control_cycles(root: Path, values: Any, phases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    try:
        _require(isinstance(values, list) and bool(values))
        cycles = [_settled_control_cycle(root, row) for row in values]
        by_hash = {row["sha256"]: row for row in cycles}
        _require(
            len(by_hash) == len(cycles) and set(by_hash) == {phase["control_action"]["sha256"] for phase in phases}
        )
        _ordered_control_cycles(cycles)
        for phase in phases:
            action = by_hash[phase["control_action"]["sha256"]]
            _require(phase["platform"] == action["platform"] and phase["instance"] == action["instance"])
            _require(phase["mode"] in action["modes"] and phase["control_sequence"] == action["sequence"])
            _require(phase["controller_run"] == action["controller_run"])
            _require(action["running_at"] <= phase["started_at"] <= phase["finished_at"] <= action["stopped_at"])
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("controller_cycle_correlation_incomplete") from exc
    return by_hash


def _native_observation_inputs(phase: Phase) -> tuple[str | None, str]:
    prior = os.environ.get("MORDRED_DBCRYPT_PRIOR_EVIDENCE")
    observation = os.environ.get("MORDRED_DBCRYPT_OBSERVATION", "provision")
    if phase == "reopen" and (not prior or observation not in {"process_restart", "os_reboot", "ec2_stop_start"}):
        raise AcceptanceRefused("reopen_prior_and_observation_required")
    if phase == "provision" and observation != "provision":
        raise AcceptanceRefused("provision_observation_required")
    return prior, observation


def native_phase_inputs(root: Path, phase: Phase) -> dict[str, Any]:
    names = ("DBCRYPT_BUNDLE", "MORDRED_DBCRYPT_ACCEPTANCE_MODE", "MORDRED_DBCRYPT_ACCEPTANCE_KIND")
    if os.environ.get("MORDRED_DBCRYPT_COLLECTORS_TEST") != "1" or any(not os.environ.get(name) for name in names):
        raise AcceptanceRefused("native_phase_inputs_missing")
    mode, kind = (os.environ[name] for name in names[1:])
    if mode not in {"source", "wheel"} or kind not in {"candidate", "production"}:
        raise AcceptanceRefused("native_mode_or_kind_invalid")
    bundle = _absolute(os.environ["DBCRYPT_BUNDLE"])
    manifest = validate_bundle(bundle)
    helper_name = "MORDRED_WINKEY_HELPER" if sys.platform == "win32" else "MORDRED_TPMKEY_HELPER"
    helper_text = os.environ.get(helper_name)
    if sys.platform not in {"linux", "win32"} or not helper_text:
        raise AcceptanceRefused("actual_native_platform_and_helper_required")
    helper = _absolute(helper_text)
    _input_file(helper)
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
    helper_copy = validate_withdrawable_helper(_absolute(copy_manifest), production=helper, parent=root)
    prior, observation = _native_observation_inputs(phase)
    action_text = os.environ.get("MORDRED_DBCRYPT_CONTROL_ACTION")
    if not action_text:
        raise AcceptanceRefused("frozen_controller_action_required")
    action_path = _absolute(action_text)
    control_action = validate_control_action(action_path, platform=sys.platform, mode=mode, observation=observation)
    if not control_action["running_at"] <= time.time() < control_action["deadline"] - CONTROL_MARGIN:
        raise AcceptanceRefused("controller_guard_window_not_active")
    qualification = os.environ.get("MORDRED_DBCRYPT_QUALIFICATION_DIRECTORY")
    if sys.platform == "win32":
        if not qualification:
            raise AcceptanceRefused("windows_native_qualification_incomplete")
        qualified = validate_windows_qualification(_absolute(qualification), checkout=Path(manifest["checkout"]))
        _require(os.environ.get("MORDRED_DBCRYPT_VFS_FIXTURE_ROOT") == qualified["fixtures"]["test_root"])
        fixture_input = os.environ.get("MORDRED_DBCRYPT_QUALIFICATION_MANIFEST")
        _require(bool(fixture_input))
        _require(sha256_file(_input_file(Path(str(fixture_input)))) == qualified["fixture_manifest_sha256"])
    return {
        "bundle": bundle,
        "manifest": manifest,
        "mode": mode,
        "kind": kind,
        "helper": helper,
        "helper_name": helper_name,
        "helper_sha256": sha256_file(helper),
        "helper_copy_manifest": Path(copy_manifest),
        "helper_copy": helper_copy,
        "parent": root,
        "prior": _absolute(prior) if prior else None,
        "observation": observation,
        "fixtures": native_fixture_paths(root, mode),
        "qualification": qualification,
        "control_action_path": action_path,
        "control_action": control_action,
    }


# Reviewed platform-only N/A surface. Exact cases and original reasons only;
# collection and all applicable cases still execute. Native gates never use it.
WINDOWS_PLATFORM_NA = {
    "test_dbcrypt_authority.py::test_fork_invalidates_without_releasing_parent_lease": (
        "POSIX fork lifetime",
        "windows_posix_fork",
    ),
    "test_dbcrypt_authority.py::test_fork_refuses_before_entering_inherited_thread_lock": (
        "POSIX fork lifetime",
        "windows_posix_fork",
    ),
    "test_dbcrypt_capability.py::test_explicit_diagnosis_authenticates_once_and_releases": (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    "test_dbcrypt_capability.py::test_native_prompt_does_not_revoke_registered_sql_on_changed_metadata": (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    "test_dbcrypt_capability.py::test_diagnosis_authentication_failure_releases_lease": (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    "test_dbcrypt_connections.py::test_fork_held_connection_refuses_before_inherited_locks": (
        "POSIX fork only",
        "windows_posix_fork",
    ),
    "test_dbcrypt_connections.py::test_fork_normal_shutdown_cannot_finalize_inherited_handles": (
        "POSIX fork only",
        "windows_posix_fork",
    ),
    "test_dbcrypt_connections.py::test_closed_connection_retained_cursor_allows_normal_child_exit": (
        "POSIX fork only",
        "windows_posix_fork",
    ),
    "test_dbcrypt_locking.py::test_root_lease_precedes_custody": (
        "POSIX native primitive; Windows lease qualification is Task 5's explicit gate",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_multiprocess_shared_exclusive_and_crash_release": (
        "POSIX process acceptance; Windows lock/rename native gate follows in Task 5",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_root_and_lock_replacement_invalidate_runtime": (
        "POSIX pathname replacement; Windows denies rename and is gated in Task 5",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_fork_discards_inherited_authority_without_unlocking_parent": (
        "POSIX fork ownership",
        "windows_posix_fork",
    ),
    "test_dbcrypt_locking.py::test_unsafe_lock_refuses_without_repair": (
        "POSIX file permissions; checked Windows descriptor cases have their own tests",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_other_user_writable_root_refuses_without_repair": (
        "POSIX ownership/mode admission; Windows uses checked token/DACL tests",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_exclusive_reentry_revalidates_the_original_proof": (
        "POSIX replacement admission; Windows denies native rename",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_holder_scan_distinguishes_empty_visible_and_live_denied": (
        "POSIX proc metadata model; actual Linux holder qualification is a native gate",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_holder_scan_knows_when_a_process_disappeared": (
        "POSIX proc disappearance model",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_locking.py::test_existing_lock_opens_without_nonexclusive_create": (
        "POSIX first-open creation protocol",
        "windows_posix_dbcrypt_locking",
    ),
    "test_dbcrypt_inventory.py::test_symlinked_in_scope_tree_is_unknown_without_following_it": (
        "POSIX alias/rename semantics; Windows sharing/rename qualification is Task 5's gate",
        "windows_posix_dbcrypt_inventory",
    ),
    "test_dbcrypt_inventory.py::test_unrelated_regular_file_alias_is_not_a_database_dependency": (
        "POSIX alias/rename semantics; Windows sharing/rename qualification is Task 5's gate",
        "windows_posix_dbcrypt_inventory",
    ),
    "test_dbcrypt_inventory.py::test_mutation_guard_rechecks_the_lease_after_scan": (
        "POSIX alias/rename semantics; Windows sharing/rename qualification is Task 5's gate",
        "windows_posix_dbcrypt_inventory",
    ),
    "test_dbcrypt_inventory.py::test_invalid_root_is_incomplete[symlink]": (
        "POSIX alias/rename semantics; Windows sharing/rename qualification is Task 5's gate",
        "windows_posix_dbcrypt_inventory",
    ),
    "test_dbcrypt_lifecycle.py::test_a_forked_runtime_keeps_its_lease_after_the_parent_exits": (
        "POSIX fork lifetime",
        "windows_posix_fork",
    ),
    "test_dbcrypt_lifecycle.py::test_offline_sql_fork_quarantines_cursors_before_child_finalization": (
        "POSIX fork lifecycle",
        "windows_posix_fork",
    ),
    "test_dbcrypt_monitor.py::test_the_lock_probe_sees_a_dropped_lock": (
        "POSIX record-lock semantics",
        "windows_posix_dbcrypt_monitor",
    ),
    "test_dbcrypt_monitor.py::test_the_per_turn_check_keeps_hermess_locks_on_its_live_database": (
        "POSIX record-lock semantics",
        "windows_posix_dbcrypt_monitor",
    ),
    "test_dbcrypt_monitor.py::test_an_unprotected_process_is_probed_through_its_own_sqlite": (
        "POSIX record-lock semantics",
        "windows_posix_dbcrypt_monitor",
    ),
    "test_dbcrypt_monitor.py::test_reopening_an_encrypted_copy_keeps_the_locks_of_its_open_connection": (
        "POSIX record-lock semantics",
        "windows_posix_dbcrypt_monitor",
    ),
    "test_mail_imap_sync.py::test_a_second_fetch_while_one_runs_is_sync_in_progress": (
        "POSIX flock",
        "windows_posix_mail_imap_sync",
    ),
    "test_mail_imap_sync.py::test_an_abandoned_lease_releases_the_writer_lock_its_holder_still_keeps": (
        "POSIX flock",
        "windows_posix_mail_imap_sync",
    ),
    "test_mail_imap_sync.py::test_a_failed_revocation_keeps_the_lock_and_a_late_batch_is_still_refused": (
        "POSIX flock",
        "windows_posix_mail_imap_sync",
    ),
    "test_mail_imap_sync.py::test_a_write_in_flight_keeps_the_lock_until_its_worker_exits": (
        "POSIX flock",
        "windows_posix_mail_imap_sync",
    ),
    "test_wizard_databases_authority.py::test_legacy_arm_is_idempotent_in_owned_0755_directory": (
        "POSIX legacy directory modes",
        "windows_posix_wizard_databases_authority",
    ),
    "test_wizard_databases_authority.py::test_legacy_arm_in_0755_directory_refuses_unsafe_or_unknown_entries": (
        "POSIX legacy directory/file admission",
        "windows_posix_wizard_databases_authority",
    ),
    "test_database_mutation_broker.py::test_fork_discards_inherited_custody_and_database_proof": (
        "POSIX fork registry cleanup",
        "windows_posix_fork",
    ),
}
WINDOWS_TELEGRAM_MIGRATION_REASON = "mordred.db (and so migrate-store) is macOS-only; Windows keeps the .enc archive"


def _test_identity(nodeid: str) -> str:
    text = nodeid.replace("\\", "/")
    text = text.split("/tests/", 1)[-1].removeprefix("tests/")
    return text.split("[", 1)[0]


def platform_na_reason(
    nodeid: str, reason: str | None = None, *, platform: str = "win32", suite: str = "affected"
) -> str | None:
    identity = _test_identity(nodeid)
    if platform == "linux" and suite == "dbcrypt-activity":
        return (
            "linux_windows_peer_handles"
            if identity == "integration/test_dbcrypt_activity.py::test_windows_peer_swap_refuses"
            and reason in {None, "Windows checked peer source handles"}
            else None
        )
    if platform != "win32" or suite != "affected":
        return None
    if identity.startswith("extension/test_telegram_migrate_store.py::"):
        expected: tuple[str, str] | None = (WINDOWS_TELEGRAM_MIGRATION_REASON, "windows_telegram_migration_module")
    else:
        expected = WINDOWS_PLATFORM_NA.get(_normalized_node(nodeid), WINDOWS_PLATFORM_NA.get(identity))
    if expected is None or (reason is not None and reason != expected[0]):
        return None
    return expected[1]


def _native_node_outcome(node: str, rows: list[dict[str, Any]], platform: str, suite: str) -> str | None:
    _require(all(not row.get("wasxfail") for row in rows))
    actual = {(row["when"], row["outcome"]) for row in rows}
    skipped = [row for row in rows if row["outcome"] == "skipped"]
    if not skipped:
        _require(len(rows) == 3 and actual == {(stage, "passed") for stage in ("setup", "call", "teardown")})
        return None
    _require(len(skipped) == 1)
    reason = platform_na_reason(node, platform=platform, suite=suite)
    _require(reason is not None and skipped[0].get("reason_code") == reason)
    stage = skipped[0]["when"]
    expected = (
        {("setup", "skipped"), ("teardown", "passed")}
        if stage == "setup"
        else {("setup", "passed"), ("call", "skipped"), ("teardown", "passed")}
    )
    _require(stage in {"setup", "call"} and len(rows) == len(expected) and actual == expected)
    return reason


def validate_native_test_report(value: Any, *, platform: str = "", suite: str = "") -> dict[str, Any]:
    try:
        report = _object(value, ("nodeids", "reports", "exitstatus", "collection_errors", "deselected"))
        nodes = report["nodeids"]
        _require(
            isinstance(nodes, list)
            and bool(nodes)
            and all(_text(node) for node in nodes)
            and len(set(nodes)) == len(nodes)
        )
        _require(type(report["exitstatus"]) is int and report["exitstatus"] == 0 and report["collection_errors"] == [])
        _require(isinstance(report["deselected"], list) and all(_text(node) for node in report["deselected"]))
        _require(all(row["nodeid"] in nodes for row in report["reports"]))
        unavailable = []
        for node in nodes:
            reason = _native_node_outcome(
                node, [row for row in report["reports"] if row["nodeid"] == node], platform, suite
            )
            if reason is not None:
                unavailable.append({"nodeid": node, "reason_code": reason})
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("native_test_results_incomplete") from exc
    return {
        **report,
        "platform_na": unavailable,
        "counts": {"passed": len(nodes) - len(unavailable), "platform_na": len(unavailable), "skipped": 0},
    }


def _evidence_ref(directory: Path, value: Any) -> tuple[Path, dict[str, Any]]:
    reference = _object(value, ("path", "sha256"))
    path = directory / _relative(reference["path"])
    _input_file(path)
    _require(path.resolve().is_relative_to(directory.resolve()) and _hex(reference["sha256"], 64))
    _require(sha256_file(path) == reference["sha256"])
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    _require(isinstance(payload, dict))
    return path, payload


def _artifact_ref(directory: Path, reference: Any) -> Path:
    row = _object(reference, ("path", "sha256"))
    path = _input_file(directory / _relative(row["path"]))
    _require(path.resolve().is_relative_to(directory.resolve()) and _hex(row["sha256"], 64))
    _require(sha256_file(path) == row["sha256"])
    return path


def windows_vfs_required_nodes(checkout: Path, *, release: bool) -> list[str]:
    """Expand this one reviewed literal-parametrized module without importing it."""
    relative = "tests/integration/test_dbcrypt_windows_vfs.py"
    module = ast.parse((checkout / relative).read_text())
    result: list[str] = []
    excluded = (
        "checkedtest",
        "injected_io",
        "every_creation",
        "inherited_dacl_race",
        "recovery_exclusive_lock",
        "shm_shared_lock",
    )
    for node in module.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        if release and any(token in node.name for token in excluded):
            continue
        dimensions = []
        for decorator in reversed(node.decorator_list):
            if isinstance(decorator, ast.Call) and ast.unparse(decorator.func) == "pytest.mark.parametrize":
                _require(len(decorator.args) == 2 and not decorator.keywords)
                names = ast.literal_eval(decorator.args[0]).split(",")
                ids = []
                for values in ast.literal_eval(decorator.args[1]):
                    row = (values,) if len(names) == 1 else values
                    _require(all(type(value) in (str, int, bool) for value in row))
                    ids.append("-".join(str(value).encode("unicode_escape").decode() for value in row))
                _require(len(ids) == len(set(ids)))
                dimensions.append(ids)
        suffixes = ["-".join(values) for values in itertools.product(*dimensions)] if dimensions else []
        result.extend(f"{relative}::{node.name}[{suffix}]" for suffix in suffixes)
        if not dimensions:
            result.append(f"{relative}::{node.name}")
    _require(bool(result) and len(result) == len(set(result)))
    return result


def _qualification_argv(row: dict[str, Any], target: str, action: str, configuration: str) -> None:
    args = row["argv"]
    _require(isinstance(args, list) and args[:3] == ["-q", "-c", configuration])
    _require(args[3:8] == ["-o", "addopts=", "-m", "integration", "--basetemp"])
    _require(_guest_path(args[8], "win32").is_absolute())
    _require(args[9].replace("\\", "/").endswith("tests/integration/test_dbcrypt_windows_vfs.py"))
    tail = ["-k", WINDOWS_RELEASE_SELECTION] if target == "Checked" else []
    tail += ["--collect-only"] if action == "collect" else []
    _require(args[10:] == tail)


def _qualification_row(
    directory: Path, reference: Any, target: str, required: list[str], configuration: str
) -> dict[str, Any]:
    links = _object(reference, ("collect", "run"))
    _, collected = _evidence_ref(directory, links["collect"])
    _, run = _evidence_ref(directory, links["run"])
    for action, row in (("collect", collected), ("run", run)):
        _require(row["action"] == action and row["target"] == target and row["nodeids"] == required)
        _require(type(row["collected"]) is int and row["collected"] == len(required))
        _require(
            type(row["pytest_exit_code"]) is int and row["pytest_exit_code"] == 0 and row["collection_errors"] == []
        )
        _qualification_argv(row, target, action, configuration)
    _require(collected.get("reports", []) == [])
    for key in ("dll_sha256", "driver_native_sha256", "python_sha256"):
        _require(_hex(run[key], 64) and collected[key] == run[key])
    for key in ("dll", "driver_native", "executable", "product_module", "driver_version", "versions"):
        _require(collected[key] == run[key])
    validate_native_test_report({**run, "exitstatus": run["pytest_exit_code"], "deselected": run.get("deselected", [])})
    _require(
        run["driver_version"] == "0.5.7" and run["versions"] == {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"}
    )
    return run


def _qualification_binaries(
    directory: Path, entry: dict[str, Any], row: dict[str, Any], provenance: dict[str, Any]
) -> None:
    for key, digest in (("dll", "dll_sha256"), ("driver_native", "driver_native_sha256"), ("python", "python_sha256")):
        _require(sha256_file(_artifact_ref(directory, entry[key])) == row[digest])
    _artifact_ref(directory, entry["build_stdout"])
    _require(
        sha256_file(_artifact_ref(directory, entry["build_script"]))
        == provenance["source_hashes"]["native/dbcrypt-vfs/build.ps1"]
    )
    args = entry["build_argv"]
    _require(isinstance(args, list) and len(args) == 11 and args[1:4] == ["-NoProfile", "-NonInteractive", "-File"])
    _require(args[5:8] == ["-Target", row["target"], "-OutputDirectory"] and args[9] == "-SqliteIncludeDirectory")
    _require(PureWindowsPath(args[4]).name == "build.ps1")


def _qualification_fixture(directory: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    _, fixture = _evidence_ref(directory, manifest["fixture_verify"])
    _, wrapper = _evidence_ref(directory, manifest["fixture_plan"])
    _, owned = _evidence_ref(directory, manifest["fixture_manifest"])
    plan = wrapper["plan"]
    _require(fixture["schema"] == owned["schema"] == 1 and fixture["ready"] is True and fixture["elevated"] is False)
    _require(
        fixture["sentinel_unchanged"] is True and fixture["direct"]["ok"] is True and fixture["unknown"]["ok"] is True
    )
    _require(_hex(fixture["plan_sha256"], 64) and fixture["plan_sha256"] == wrapper["reviewed_plan_sha256"])
    _require(fixture["sid"] == owned["owner_sid"] == plan["owner_sid"] and _text(fixture["sid"]))
    _require(
        owned["filesystem"] == "exFAT" and all(owned[key] == plan[key] for key in ("non_ntfs_root", "reparse_root"))
    )
    return dict(plan)


def _required_qualification_headers(checkout: Path) -> dict[str, str]:
    import runpy

    return dict(runpy.run_path(str(checkout / "tools/dbcrypt_build_headers.py"))["HEADER_SHA256"])


def _qualification_source(directory: Path, manifest: dict[str, Any], checkout: Path) -> dict[str, Any]:
    _, provenance = _evidence_ref(directory, manifest["provenance"])
    _, source_map = _evidence_ref(directory, manifest["source_map"])
    _require(_hex(provenance["candidate"], 40) and provenance["candidate"] == source_map["candidate"])
    _require(provenance["source_hashes"] == source_map["files"] and provenance["headers"] == source_map["headers"])
    archive = _artifact_ref(directory, manifest["source_archive"])
    _require(sha256_file(archive) == provenance["source_archive_sha256"])
    with zipfile.ZipFile(archive) as source_zip:
        names = source_zip.namelist()
        _require(len(names) == len(set(names)) and set(names) == set(source_map["delta_files"]))
        for name in names:
            _relative(name)
            _require(
                hashlib.sha256(source_zip.read(name)).hexdigest()
                == source_map["delta_files"][name]
                == source_map["files"][name]
            )

    critical = [
        *(checkout / "native/dbcrypt-vfs").glob("*.c"),
        *(checkout / "native/dbcrypt-vfs").glob("*.h"),
        *(checkout / "src/mordred_hermes/_private_fs").glob("*.py"),
        checkout / "native/dbcrypt-vfs/build.ps1",
        checkout / "pyproject.toml",
        checkout / "src/mordred_hermes/dbcrypt/_windows_vfs.py",
        checkout / "tests/integration/test_dbcrypt_windows_vfs.py",
    ]
    _require(
        all(
            provenance["source_hashes"].get(path.relative_to(checkout).as_posix()) == sha256_file(path)
            for path in critical
        )
    )
    configuration = _artifact_ref(directory, manifest["configuration"])
    _require(
        sha256_file(configuration)
        == provenance["configuration_sha256"]
        == provenance["source_hashes"]["pyproject.toml"]
    )
    _require(PureWindowsPath(provenance["configuration"]) == PureWindowsPath(provenance["source"]) / "pyproject.toml")
    expected_headers = _required_qualification_headers(checkout)
    _require(provenance["headers"] == expected_headers and set(manifest["headers"]) == set(expected_headers))
    for name, digest in expected_headers.items():
        _require(sha256_file(_artifact_ref(directory, manifest["headers"][name])) == digest)
    return dict(provenance)


def _qualified_package_artifacts(
    directory: Path, proof: dict[str, Any], bundle: dict[str, Any], row: dict[str, Any], provenance: dict[str, Any]
) -> None:
    wheel_path = _artifact_ref(directory, proof["artifacts"]["wheel"])
    sdist_path = _artifact_ref(directory, proof["artifacts"]["sdist"])
    native_name = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
    critical = {
        name: digest
        for name, digest in provenance["source_hashes"].items()
        if name.startswith(("native/dbcrypt-vfs/", "src/mordred_hermes/_private_fs/"))
        or name == "src/mordred_hermes/dbcrypt/_windows_vfs.py"
    }
    with tarfile.open(sdist_path, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        _require(len(members) == len(archive.getmembers()))
        prefix = Path(bundle["sdist"]).name.removesuffix(".tar.gz")
        for name, digest in critical.items():
            member = members[prefix + "/" + name]
            _require(member.isfile())
            stream = archive.extractfile(member)
            _require(stream is not None)
            assert stream is not None
            _require(hashlib.sha256(stream.read()).hexdigest() == digest)
    with zipfile.ZipFile(wheel_path) as archive:
        _require(len(archive.namelist()) == len(set(archive.namelist())))
        dll = archive.read(native_name)
        _require(hashlib.sha256(dll).hexdigest() == row["dll_sha256"])
        version = bundle["wheel_probe"]["versions"]["hermes-mordred"]
        record = csv.reader(io.StringIO(archive.read(f"hermes_mordred-{version}.dist-info/RECORD").decode()))
        native_entries = [entry for entry in record if entry[0] == native_name]
        encoded = base64.urlsafe_b64encode(hashlib.sha256(dll).digest()).rstrip(b"=").decode()
        _require(len(native_entries) == 1 and native_entries[0][1:] == ["sha256=" + encoded, str(len(dll))])
        for name, digest in critical.items():
            if name.startswith("src/"):
                _require(hashlib.sha256(archive.read(name.removeprefix("src/"))).hexdigest() == digest)
    module = "tests/integration/test_dbcrypt_windows_vfs.py"
    _require(bundle["files"][module] == provenance["source_hashes"][module])


def _validate_legacy_windows_qualification(directory: Path, *, checkout: Path) -> dict[str, Any]:
    try:
        directory = directory.resolve(strict=True)
        manifest = json.loads(_input_file(directory / "manifest.json").read_text())
        _require(manifest["schema"] == 1 and manifest["kind"] == "windows_vfs_qualification")
        full, release = (windows_vfs_required_nodes(checkout, release=value) for value in (False, True))
        rows = manifest["rows"]
        provenance = _qualification_source(directory, manifest, checkout)
        configuration = provenance["configuration"]
        diagnostic = _qualification_row(directory, rows["checkedtest_source"], "CheckedTest", full, configuration)
        source = _qualification_row(directory, rows["checked_source"], "Checked", release, configuration)
        wheel = _qualification_row(directory, rows["checked_wheel"], "Checked", release, configuration)
        excluded = set(full) - set(release)
        for name in ("checkedtest_source", "checked_source", "checked_wheel"):
            for reference in rows[name].values():
                _, raw = _evidence_ref(directory, reference)
                if "deselected" in raw:
                    _require(set(raw["deselected"]) == (set() if name == "checkedtest_source" else excluded))
        plan = _qualification_fixture(directory, manifest)
        for name, row in (("checkedtest_source", diagnostic), ("checked_source", source), ("checked_wheel", wheel)):
            _qualification_binaries(directory, manifest["artifacts"][name], row, provenance)
            if name != "checked_wheel" and "reused_builds" in provenance:
                reused = provenance["reused_builds"][row["target"]]
                _require(reused["dll_sha256"] == row["dll_sha256"])
                _require(manifest["artifacts"][name]["build_stdout"]["sha256"] == reused["actual_build_stdout_sha256"])
                _require(reused["headers"] == provenance["headers"] and bool(reused["critical_inputs"]))
                expected_critical = {
                    key
                    for key in provenance["source_hashes"]
                    if (
                        key.startswith("native/dbcrypt-vfs/")
                        and (key.endswith((".c", ".h")) or key.endswith("/build.ps1"))
                    )
                    or key.startswith("src/mordred_hermes/_private_fs/")
                    or key == "src/mordred_hermes/dbcrypt/_windows_vfs.py"
                }
                _require(set(reused["critical_inputs"]) == expected_critical)

                _require(
                    all(provenance["source_hashes"][key] == digest for key, digest in reused["critical_inputs"].items())
                )
                _require(reused["cached_runtime"][row["executable"]] == row["python_sha256"])
                _require(reused["cached_runtime"][row["driver_native"]] == row["driver_native_sha256"])

        for row in (diagnostic, source):
            _require(PureWindowsPath(row["dll"]).parent.parent == PureWindowsPath(plan["test_root"]))
            _require(
                PureWindowsPath(row["product_module"]).is_relative_to(
                    PureWindowsPath(provenance["source"]) / "src/mordred_hermes"
                )
            )
        _require(
            wheel["record_owned_packaged_dll"] is True
            and wheel["test_exports_absent"] is True
            and wheel["env_dll_override"] is None
        )
        # Artifact/bundle closure is validated by the same fixed offline proof
        # adapter used by phase evidence, never digest-shape or booleans alone.
        proof_path, proof = _evidence_ref(directory, manifest["wheel_bundle"])
        bundle = validate_bundle_evidence(proof, directory=proof_path.parent)
        _require(all(wheel[key] == bundle[key] for key in ("sdist_sha256", "wheel_sha256")))
        _require(wheel["bundle_manifest_sha256"] == proof["manifest"]["sha256"])
        _qualified_package_artifacts(proof_path.parent, proof, bundle, wheel, provenance)
        _validate_exported_import(
            wheel["product_module"], mode="wheel", platform="win32", bundle=bundle, bundle_path=proof["bundle_path"]
        )
        return {
            "manifest_sha256": sha256_file(directory / "manifest.json"),
            "diagnostic": diagnostic,
            "source": source,
            "wheel": wheel,
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        tarfile.TarError,
        zipfile.BadZipFile,
        AcceptanceRefused,
    ) as exc:
        raise AcceptanceRefused("windows_native_qualification_incomplete") from exc


def _qualification_inputs(directory: Path, manifest: dict[str, Any]) -> set[Path]:
    if manifest.get("schema") == 2:
        paths = {directory / "manifest.json"}
        diagnostic_path = _artifact_ref(directory, manifest["diagnostic"])
        paths.update(_diagnostic_files(diagnostic_path.parent, json.loads(diagnostic_path.read_text())))
        fixture_path = _artifact_ref(directory, manifest["fixtures"])
        _, fixture_files = _fixture_descriptor(fixture_path)
        paths.update(fixture_files)
        for reference in manifest["results"].values():
            result_path = _artifact_ref(directory, reference)
            value = json.loads(result_path.read_text())
            paths.add(result_path)
            paths.update(_artifact_ref(result_path.parent, value[action]["report"]) for action in ("collect", "run"))
            paths.update(_artifact_ref(result_path.parent, ref) for ref in value["artifacts"].values())
            nested = _artifact_ref(result_path.parent, value["fixtures_descriptor"])
            _require(sha256_file(nested) == sha256_file(fixture_path))
            _, nested_files = _fixture_descriptor(nested)
            paths.update(nested_files)
        proof_path, proof = _evidence_ref(directory, manifest["wheel_bundle"])
        paths.add(proof_path)
        paths.add(_artifact_ref(proof_path.parent, proof["manifest"]))
        paths.add(_artifact_ref(proof_path.parent, proof["configuration"]))
        paths.update(
            _artifact_ref(proof_path.parent, ref)
            for group in ("inputs", "artifacts", "native_build")
            for ref in proof[group].values()
        )
        return paths
    paths = {directory / "manifest.json"}
    for key in (
        "provenance",
        "source_map",
        "source_archive",
        "fixture_plan",
        "fixture_manifest",
        "fixture_verify",
        "configuration",
    ):
        paths.add(_artifact_ref(directory, manifest[key]))
    paths.update(_artifact_ref(directory, value) for value in manifest["headers"].values())
    for links in manifest["rows"].values():
        paths.update(_artifact_ref(directory, value) for value in links.values())
    for row in manifest["artifacts"].values():
        paths.update(
            _artifact_ref(directory, row[key])
            for key in ("dll", "driver_native", "python", "build_stdout", "build_script")
        )
    proof_path, proof = _evidence_ref(directory, manifest["wheel_bundle"])
    paths.add(proof_path)
    paths.add(_artifact_ref(proof_path.parent, proof["manifest"]))
    paths.add(_artifact_ref(proof_path.parent, proof["configuration"]))
    paths.update(_artifact_ref(proof_path.parent, value) for value in proof["artifacts"].values())
    paths.update(_artifact_ref(proof_path.parent, value) for value in proof["inputs"].values())
    return paths


def _export_windows_qualification(context: dict[str, Any], directory: Path) -> dict[str, str] | None:
    if not context.get("qualification"):
        return None
    source = Path(context["qualification"])
    manifest = json.loads((source / "manifest.json").read_text())
    target = directory / "windows-qualification"
    target.mkdir(mode=0o700)
    for path in sorted(_qualification_inputs(source, manifest)):
        relative = path.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    path = target / "manifest.json"
    return {"path": path.relative_to(directory.parent).as_posix(), "sha256": sha256_file(path)}


def _phase_qualification(phase: dict[str, Any], directory: Path) -> dict[str, Any] | None:
    if phase["platform"] != "win32":
        _require(phase.get("qualification_evidence") is None)
        return None
    path, _manifest = _evidence_ref(directory, phase["qualification_evidence"])
    # The operator runs offline verification from the accepted source tool.
    # Only read current component bytes; no product import or guest path stat.
    qualified = validate_windows_qualification(path.parent, checkout=Path(__file__).resolve().parents[1])
    _require(qualified["manifest_sha256"] == phase["native_facts"]["qualification_manifest_sha256"])
    observed = qualified["source" if phase["mode"] == "source" else "wheel"]
    _require(observed["dll_sha256"] == phase["native_facts"]["dll"]["sha256"])
    if phase["mode"] == "wheel":
        _require(qualified["wheel"]["bundle_manifest_sha256"] == phase["bundle_manifest_sha256"])
    return qualified


def validate_reopen_continuity(before: dict[str, Any], after: dict[str, Any], observation: str) -> None:
    try:
        _require(all(before[key] == after[key] for key in ("mode", "bundle_manifest_sha256", "fixture", "logical")))
        if "native_roots" in before or "native_roots" in after:
            _require(before["native_roots"] == after["native_roots"])
        same_boot = before["boot"]["identity"] == after["boot"]["identity"]
        _require(same_boot if observation == "process_restart" else not same_boot)
        _require(observation in {"process_restart", "os_reboot", "ec2_stop_start"})
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("native_reopen_continuity_failed") from exc


def native_acceptance_commands(*, checkout: Path, bundle: Path, platform: str, kind: str) -> list[dict[str, Any]]:
    rows = acceptance_commands(checkout=checkout, bundle=bundle, platform=platform)
    if platform == "win32" and kind == "candidate":
        rows = [
            {"suite": row["suite"], "mode": row["mode"], "status": "satisfied_by_qualified_artifact_reference"}
            if row["suite"] == "windows-vfs"
            else row
            for row in rows
        ]
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


def _guest_path(value: str, platform: str) -> PurePosixPath | PureWindowsPath:
    path = PureWindowsPath(value) if platform == "win32" else PurePosixPath(value)
    _require(path.is_absolute() and ".." not in path.parts)
    return path


def _validate_exported_import(path: str, *, mode: str, platform: str, bundle: dict[str, Any], bundle_path: str) -> None:
    origin = _guest_path(path, platform)
    checkout, installed = (_guest_path(value, platform) for value in (bundle["checkout"], bundle_path))
    expected = checkout / "src/mordred_hermes" if mode == "source" else installed / "wheel-env"
    _require(origin.is_relative_to(expected) and (mode == "source" or not origin.is_relative_to(checkout)))
    _require(path == bundle[mode + "_probe"]["product_file"])


def _offline_build_records(manifest: dict[str, Any], bundle_path: str) -> None:
    platform = manifest["source_probe"]["platform"]
    root, checkout = (_guest_path(value, platform) for value in (bundle_path, manifest["checkout"]))
    python_name = "Scripts/python.exe" if platform == "win32" else "bin/python"
    source_python = str(checkout / ".venv" / python_name)
    build_python = str(root / "build-env" / python_name)
    wheel_python = str(root / "wheel-env" / python_name)
    rows = manifest["build_commands"]
    _require(isinstance(rows, list) and len(rows) == 6)
    for row in rows:
        _require(row["cwd"] == str(root) and type(row["returncode"]) is int and row["returncode"] == 0)
        _require(
            _timestamp(row["started_at"]) and _timestamp(row["finished_at"]) and row["started_at"] <= row["finished_at"]
        )
    _require(rows[0]["argv"] == ["uv", "build", "--sdist", str(checkout), "--out-dir", str(root / "artifacts")])
    for index, name in ((1, "build-env"), (2, "wheel-env")):
        argv = rows[index]["argv"]
        _require(len(argv) == 6 and argv[:4] == ["uv", "venv", "--no-project", "--python"])
        _require(argv[4] in {source_python, manifest["source_probe"]["interpreter"]} and argv[5] == str(root / name))
    _require(rows[3]["argv"] == ["uv", "pip", "install", "--python", build_python, "hatchling>=1.18"])
    _require(
        rows[4]["argv"]
        == [
            "uv",
            "build",
            "--wheel",
            "--no-build-isolation",
            "--python",
            build_python,
            str(root / manifest["extracted_sdist"]),
            "--out-dir",
            str(root / "artifacts"),
        ]
    )
    _require(
        rows[5]["argv"]
        == [
            "uv",
            "pip",
            "install",
            "--python",
            wheel_python,
            "--link-mode",
            "copy",
            str(root / manifest["wheel"]) + "[dev,keyvault,extension,dbcrypt,telegram]",
        ]
    )


def validate_bundle_evidence(value: Any, *, directory: Path) -> dict[str, Any]:
    """Offline closure over exported preparation manifest, artifacts and test inputs."""
    proof = _object(
        value, ("schema_version", "kind", "bundle_path", "manifest", "artifacts", "inputs", "configuration")
    )
    _require(
        type(proof["schema_version"]) is int
        and proof["schema_version"] == 1
        and proof["kind"] == "dbcrypt_bundle_evidence"
    )
    _, manifest = _evidence_ref(directory, proof["manifest"])
    _require(
        type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and _hex(manifest["commit"], 40)
    )
    _offline_build_records(manifest, proof["bundle_path"])
    files = manifest["files"]
    _require(isinstance(files, dict) and bool(files) and all(_hex(digest, 64) for digest in files.values()))
    required = {name for name in files if name.startswith(("tests/", "tools/"))}
    _require(bool(required) and set(proof["inputs"]) == required)
    inputs = {}
    for name in sorted(required):
        _relative(name)
        path = _artifact_ref(directory, proof["inputs"][name])
        _require(sha256_file(path) == files[name])
        inputs[name] = path
    for kind in ("sdist", "wheel"):
        artifact = _artifact_ref(directory, proof["artifacts"][kind])
        _require(sha256_file(artifact) == manifest[kind + "_sha256"] == files[manifest[kind]])
    captured = {name for name in files if name.startswith("artifacts/native-build/")}
    _require(set(proof.get("native_build", {})) == captured)
    for name in captured:
        _require(sha256_file(_artifact_ref(directory, proof["native_build"][name])) == files[name])
    config_name = manifest["extracted_sdist"] + "/pyproject.toml"
    configuration = _artifact_ref(directory, proof["configuration"])
    _require(sha256_file(configuration) == files[config_name])
    with tarfile.open(_artifact_ref(directory, proof["artifacts"]["sdist"]), "r:gz") as archive:
        member = archive.getmember(Path(manifest["sdist"]).name.removesuffix(".tar.gz") + "/pyproject.toml")
        _require(member.isfile())
        stream = archive.extractfile(member)
        _require(stream is not None)
        assert stream is not None
        _require(hashlib.sha256(stream.read()).hexdigest() == files[config_name])
    platform = manifest["source_probe"]["platform"]
    _require(platform == manifest["wheel_probe"]["platform"] and platform in {"linux", "win32"})
    for mode in ("source", "wheel"):
        probe = manifest[mode + "_probe"]
        _validate_exported_import(
            probe["product_file"], mode=mode, platform=platform, bundle=manifest, bundle_path=proof["bundle_path"]
        )
        _require(probe["versions"]["hermes-mordred"] == manifest["source_probe"]["versions"]["hermes-mordred"])
        environment = (
            _guest_path(manifest["checkout"], platform) / ".venv"
            if mode == "source"
            else _guest_path(proof["bundle_path"], platform) / "wheel-env"
        )
        _require(_guest_path(probe["driver"]["module"], platform).is_relative_to(environment))
        _require(
            probe["driver"]["cipher_version"] == "4.12.0 community"
            and probe["versions"]["sqlcipher3-wheels"] == "0.5.7"
        )

    return {**manifest, "_inputs": inputs, "_bundle_path": proof["bundle_path"]}


def _export_bundle_evidence(context: dict[str, Any], directory: Path) -> dict[str, str]:
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
        *(name for name in manifest["files"] if name.startswith(("tests/", "tools/"))),
        *(name for name in manifest["files"] if name.startswith("artifacts/native-build/")),
    ]
    for name in names:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(context["bundle"] / name, path)
        reference = {"path": name, "sha256": sha256_file(path)}
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
    _write_new(path, proof)
    return {"path": path.relative_to(directory.parent).as_posix(), "sha256": sha256_file(path)}


def _phase_bundle(phase: dict[str, Any], directory: Path) -> dict[str, Any]:
    path, proof = _evidence_ref(directory, phase["bundle_evidence"])
    bundle = validate_bundle_evidence(proof, directory=path.parent)
    _require(phase["bundle_manifest_sha256"] == proof["manifest"]["sha256"])
    _require(phase["bundle"] == {key: bundle[key] for key in ("commit", "sdist_sha256", "wheel_sha256")})
    _require(phase["native_implementation_sha256"] == bundle["files"]["tests/_dbcrypt_acceptance_native.py"])
    _require(phase["platform"] == bundle["source_probe"]["platform"])
    return bundle


def _exported_probe(phase: dict[str, Any], execution: dict[str, Any], bundle: dict[str, Any]) -> None:
    probe = execution["import_probe"]
    _require(probe == bundle[phase["mode"] + "_probe"])
    _validate_exported_import(
        probe["product_file"],
        mode=phase["mode"],
        platform=phase["platform"],
        bundle=bundle,
        bundle_path=bundle["_bundle_path"],
    )
    _require(execution["cwd"] == bundle["_bundle_path"] and execution["mode"] == phase["mode"])
    _require(execution["bundle_manifest_sha256"] == phase["bundle_manifest_sha256"])
    _require(phase["platform"] != "win32" or probe["token"]["elevated"] is False)


def _module_functions(path: Path, relative: str) -> set[str]:
    tree = ast.parse(path.read_text())
    result = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            result.add(relative + "::" + node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            result.update(
                relative + "::" + node.name + "::" + child.name
                for child in node.body
                if isinstance(child, ast.FunctionDef) and child.name.startswith("test_")
            )
    return result


def _normalized_node(node: str) -> str:
    node = node.replace("\\", "/")
    return node.split("/tests/", 1)[-1].removeprefix("tests/")


def _crash_nodes(platform: str) -> set[str]:
    phases = [
        (direction, stage)
        for direction in ("encrypt", "decrypt")
        for stage in ("prepared", "reserved", "verified", "armed", "swapped", "complete", "removed")
    ]
    phases += [("adopt", stage) for stage in ("verified", "armed", "complete")] + [("backup", "published")]
    if platform == "win32":
        phases += [
            (direction, stage) for direction in ("encrypt", "decrypt") for stage in ("retained", "published", "retired")
        ]
    return {
        f"integration/test_dbcrypt_native.py::test_native_crash_subprocess_recovery[{direction}-{stage}]"
        for direction, stage in phases
    }


def _planned_rows(phase: dict[str, Any], bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from typing import cast

    checkout = cast(Path, _guest_path(bundle["checkout"], phase["platform"]))
    root = cast(Path, _guest_path(bundle["_bundle_path"], phase["platform"]))
    return {
        row["suite"]: row
        for row in native_acceptance_commands(
            checkout=checkout, bundle=root, platform=phase["platform"], kind=phase["acceptance_kind"]
        )
        if row["mode"] == phase["mode"] and "argv" in row
    }


def _selected_nodes(
    phase: dict[str, Any], record: dict[str, Any], plan: dict[str, Any], bundle: dict[str, Any], directory: Path
) -> dict[str, Any]:
    configuration = str(
        _guest_path(bundle["_bundle_path"], phase["platform"]) / bundle["extracted_sdist"] / "pyproject.toml"
    )
    expected_argv = [*plan["argv"], "-c", configuration, "-p", "tests._dbcrypt_acceptance_native"]
    _require(record["argv"] == expected_argv and record["gate_env"] == plan["env"])
    collection = record["collection"]
    _require(
        collection["argv"] == [*expected_argv, "--collect-only"]
        and type(collection["returncode"]) is int
        and collection["returncode"] == 0
    )
    _, collected = _evidence_ref(directory, collection["report"])
    _, report = _evidence_ref(directory, record["pytest_report"])
    _require(collected["exitstatus"] == 0 and collected["reports"] == [] and collected["collection_errors"] == [])
    _require(
        report["nodeids"] == collected["nodeids"] == record["nodeids"]
        and report["deselected"] == collected["deselected"]
    )
    parsed = validate_native_test_report(report, platform=phase["platform"], suite=record["suite"])
    _require(record["counts"] == parsed["counts"] and record["platform_na"] == parsed["platform_na"])
    nodes = {_normalized_node(node) for node in report["nodeids"]}
    modules = {arg.replace("\\", "/").split("/tests/", 1)[-1] for arg in plan["argv"] if arg.endswith(".py")}
    _require({node.split("::", 1)[0] for node in nodes} == modules)
    functions = set().union(*(_module_functions(bundle["_inputs"]["tests/" + module], module) for module in modules))
    if record["suite"] != "windows-vfs":
        _require({node.split("[", 1)[0] for node in nodes} == functions)
    excluded: set[str] = set()
    if record["suite"] == "dbcrypt-native":
        collectors = _module_functions(
            bundle["_inputs"]["tests/integration/test_dbcrypt_collectors.py"], "integration/test_dbcrypt_collectors.py"
        )
        _require(nodes == _crash_nodes(phase["platform"]) | collectors)
    if record["suite"] == "linux-memory":
        _require(
            nodes
            == {
                "integration/test_linux_memory_orchestration_tpm.py::test_real_tpm_orchestration_and_armed_shape_b_backup["
                + entrance
                + "]"
                for entrance in ("setup", "all")
            }
        )
    if record["suite"] == "windows-vfs":
        # AST expansion uses only this reviewed module's literal parametrizations.
        copied = bundle["_inputs"]["tests/integration/test_dbcrypt_windows_vfs.py"]
        checkout = copied.parents[2]
        full = {_normalized_node(node) for node in windows_vfs_required_nodes(checkout, release=False)}
        release = {_normalized_node(node) for node in windows_vfs_required_nodes(checkout, release=True)}
        _require(nodes == (full if phase["mode"] == "source" else release))
        excluded = set() if phase["mode"] == "source" else full - release
    _require({_normalized_node(node) for node in report["deselected"]} == excluded)
    return parsed


REQUIRED_COMPONENTS = ("sessiondb", "activity", "telegram", "mail", "credentials", "source_memory", "scoped_siblings")
REQUIRED_PROFILES = ("root", "work", "other")


def _public_read(payload: dict[str, Any], phase: dict[str, Any], bundle: dict[str, Any], *, persistence: bool) -> None:
    _require(
        set(payload["logical"])
        == {profile + ":" + component for profile in REQUIRED_PROFILES for component in REQUIRED_COMPONENTS}
    )
    _require(
        all(_hex(value, 64) for value in payload["logical"].values())
        and set(payload["rows"]) == set(REQUIRED_COMPONENTS)
    )
    _require(payload["fixture"]["root"] == payload["fixture"]["source"]["root"])
    source = payload["fixture"]["source"]
    generation_length = 64 if phase["platform"] == "win32" else 32
    _require(_hex(source["generation"], generation_length) and _hex(source["record_sha256"], 64))
    _require(
        source["provider"] == ("cng" if phase["platform"] == "win32" else "tpm")
        and source["root"]["platform"] == phase["platform"]
    )
    _require(payload["facts"]["filesystem"]["identity"] == source["root"])
    hermes = payload["hermes"]
    _require(
        _hex(hermes["sha256"], 64) and hermes["version"] == bundle[phase["mode"] + "_probe"]["versions"]["hermes-agent"]
    )
    env = (
        _guest_path(bundle["checkout"], phase["platform"]) / ".venv"
        if phase["mode"] == "source"
        else _guest_path(bundle["_bundle_path"], phase["platform"]) / "wheel-env"
    )
    _require(_guest_path(hermes["module"], phase["platform"]).is_relative_to(env))
    if persistence:
        _require(payload["credential_continuity"] == "original_native_protected_reference")
        _require(payload["fixture"] == phase["fixture"] and payload["logical"] == phase["logical"])


def _native_payload(payload: dict[str, Any], phase: dict[str, Any]) -> None:
    _require(payload["schema_version"] == RUN_SCHEMA and payload["status"] == "executed")
    _require(payload["acceptance_kind"] == phase["acceptance_kind"] and payload["bootstrap"] == phase["bootstrap"])
    _require(payload["implementation_sha256"] == phase["native_implementation_sha256"])
    facts = payload["facts"]
    _require(
        facts["native_provider"]
        == ("Microsoft Platform Crypto Provider" if phase["platform"] == "win32" else "EC2 NitroTPM")
    )
    _require(_hex(facts["helper"]["sha256"], 64) and _text(facts["helper"]["path"]))
    _require(facts["helper"] == phase["native_facts"]["helper"] and facts["boot"] == phase["boot"])
    if phase["platform"] == "win32":
        _require(
            facts["elevated"] is False
            and type(facts["implementation_flags"]) is int
            and bool(facts["implementation_flags"] & 1)
            and not facts["implementation_flags"] & 2
        )
        _require(facts["filesystem"]["method"] == "checked_confidential_fixed_local_ntfs")
    else:
        _require(
            facts["filesystem"]["method"] == "checked_private_posix" and facts["device"] in {"/dev/tpmrm0", "/dev/tpm0"}
        )
        _require(facts["manufacturer"] == "AMZN" and facts["dmi_vendor"] == "Amazon EC2")


def _collector_arguments(
    record: dict[str, Any], phase: dict[str, Any], bundle: dict[str, Any], directory: Path
) -> None:
    root = _guest_path(bundle["_bundle_path"], phase["platform"])
    environment = (
        _guest_path(bundle["checkout"], phase["platform"]) / ".venv"
        if phase["mode"] == "source"
        else root / "wheel-env"
    )
    python = str(environment / ("Scripts/python.exe" if phase["platform"] == "win32" else "bin/python"))
    helper = root / "tests/_dbcrypt_acceptance_native.py"
    code = f"import runpy; raise SystemExit(runpy.run_path({str(helper)!r})['main']({record['operation']!r}))"
    if phase["acceptance_kind"] == "candidate":
        _require(record["argv"] == [python, "-c", code])
    else:
        argv = record["argv"]
        _require(len(argv) == 3 and argv[0] == python and argv[2] == record["operation"])
        _require(_guest_path(argv[1], phase["platform"]).name == "hermes")
        expected = (
            f"import sys, runpy; sys.path.insert(0, {str(root)!r}); "
            f"raise SystemExit(runpy.run_path({str(helper)!r})['main'](sys.argv[1]))\n"
        )
        _require(_artifact_ref(directory, record["driver_ref"]).read_text() == expected)


def _provision_fixture_closure(phase: dict[str, Any]) -> None:
    executions, roots = phase["executions"], phase["native_roots"]
    provisioned = {
        row["fixture_path"]: row["payload"]["fixture"] for row in executions if row.get("operation") == "provision"
    }
    _require(set(provisioned) == set(roots.values()))
    _require(len({json.dumps(value["root"], sort_keys=True) for value in provisioned.values()}) == 3)
    for row in executions:
        if row.get("operation") in {"seed", "read"}:
            _require(row["payload"]["fixture"] == provisioned[row["fixture_path"]])


def _native_execution_report(phase: dict[str, Any], directory: Path) -> None:
    bundle = _phase_bundle(phase, directory)
    qualified = _phase_qualification(phase, directory)
    if phase["platform"] == "win32" and phase["acceptance_kind"] == "candidate":
        _require(qualified is not None)
        assert qualified is not None
        _require(phase["qualified_vfs"] == _qualified_vfs_reference(qualified, phase["mode"]))
    executions = phase["executions"]
    _require(isinstance(executions, list) and bool(executions))
    plans = _planned_rows(phase, bundle) if phase["observation"] == "provision" else {}
    suites = [record["suite"] for record in executions if "suite" in record]
    _require(len(suites) == len(set(suites)) and set(suites) == set(plans))
    roots = phase["native_roots"]
    _require(set(roots) == {"persistence", "negative", "crash"} and len(set(roots.values())) == 3)
    for kind, path in roots.items():
        _require(_guest_path(path, phase["platform"]).name == f"mordred-dbcrypt-{phase['mode']}-{kind}")
    operations = []
    for record in executions:
        _require(type(record["returncode"]) is int and record["returncode"] == 0)
        _require(phase["started_at"] <= record["started_at"] <= record["finished_at"] <= phase["finished_at"])
        _exported_probe(phase, record, bundle)
        if "suite" in record:
            _selected_nodes(phase, record, plans[record["suite"]], bundle, directory)
            if record["suite"] == "windows-vfs":
                _require(qualified is not None)
                assert qualified is not None
                actual = qualified["diagnostic" if phase["mode"] == "source" else "wheel"]
                _require(
                    record["windows_library"]
                    == {"path": actual["dll"], "sha256": actual["dll_sha256"], "kind": actual["target"]}
                )
        else:
            payload = record["payload"]
            _collector_arguments(record, phase, bundle, directory)
            _native_payload(payload, phase)
            _require(record["operation"] == payload["operation"] and record["fixture_path"] in roots.values())
            operations.append((record["operation"], record["fixture_path"]))
            if record["operation"] in {"seed", "read"}:
                _public_read(payload, phase, bundle, persistence=record["fixture_path"] == roots["persistence"])
    expected = [("preflight", roots["persistence"]), ("read", roots["persistence"])]
    if phase["observation"] == "provision":
        expected += [("provision", path) for path in roots.values()] + [
            ("seed", roots[kind]) for kind in ("negative", "persistence")
        ]
    _require(sorted(operations) == sorted(expected))
    _require(executions[0].get("operation") == "preflight" and executions[-1].get("operation") == "read")
    _require(suites == list(plans))
    _require(all(first["finished_at"] <= second["started_at"] for first, second in itertools.pairwise(executions)))
    counts = {
        "passed": sum(row.get("counts", {}).get("passed", 0) for row in executions),
        "collected": sum(len(row.get("nodeids", [])) for row in executions),
        "platform_na": sum(row.get("counts", {}).get("platform_na", 0) for row in executions),
        "failed": 0,
        "skipped": 0,
    }
    _require(phase["test_counts"] == counts and phase["unexpected_skips"] == [])

    if phase["observation"] == "provision":
        _provision_fixture_closure(phase)
    read = next(record["payload"] for record in executions if record.get("operation") == "read")
    _require(read["facts"] == phase["native_facts"] and read["facts"]["boot"] == phase["boot"])


def _native_provision_coverage(phase: dict[str, Any], directory: Path) -> None:
    bundle = _phase_bundle(phase, directory)
    collector = next(row for row in phase["executions"] if row.get("suite") == "dbcrypt-native")
    records = {}
    for reference in collector["collector_rows"]:
        path, payload = _evidence_ref(directory, reference)
        _native_payload(payload, phase)
        _require(path.stem not in records)
        records[path.stem] = payload
    _require(
        set(records)
        == {
            "public-collectors",
            "before-restore",
            "backup-restore",
            "after-restore",
            "restore-finalization-failure",
            "negative",
        }
    )
    for name in ("public-collectors", "before-restore", "after-restore"):
        _require(records[name]["operation"] == "read")
        _public_read(records[name], phase, bundle, persistence=name == "public-collectors")
    before, after = records["before-restore"], records["after-restore"]
    _require(before["logical"] == after["logical"] and before["fixture"] == after["fixture"])
    negative_seed = next(
        row["payload"]
        for row in phase["executions"]
        if row.get("operation") == "seed" and row["fixture_path"] == phase["native_roots"]["negative"]
    )
    _require(before["fixture"] == negative_seed["fixture"] and before["logical"] == negative_seed["logical"])
    restored = records["backup-restore"]
    _require(
        restored["operation"] == "backup_restore"
        and restored["component_generation_before"] != restored["component_generation_after"]
        and restored["backup_retained"] is True
        and restored["guarded_runtime_monitor_backup"] is True
    )
    failure = records["restore-finalization-failure"]
    _require(
        failure["operation"] == "backup_restore_failure"
        and failure["result"] == "restore_incomplete"
        and failure["backup_and_native_key_retained"] is True
    )
    negative = records["negative"]
    required = {
        "held_terminality",
        "unwrap_count",
        "metadata_loss",
        "wrong_key",
        "role_forget",
        "mail_retired_sql_failure_named_retry",
        "fresh_unpatched_native_provider_unavailable",
        "multiprocess_reader_writers",
        "wrong_profile_key",
        "holder_uncertainty_injected",
        "public_encryption_disable",
        "public_encryption_purge",
        "public_keyvault_reset",
        "public_uninstall_helper_guard",
    }
    required |= {
        "broker_helper_guards",
        "cached_access_failure_injected",
        "attach_uri_destinations",
        "wrong_generation",
        "wrong_root_binding",
        "missing_source_no_repair",
        "missing_native_key_observed",
    }
    if phase["platform"] != "win32":
        required.add("public_vault_set-memory-key")
    _require(negative["operation"] == "negative" and required <= set(negative["rows"]))
    _require(negative["initial_unwraps"] == 1 and negative["operation_unwraps"] == 0)
    withdrawal = validate_helper_withdrawal(negative["owned_helper_withdrawal"])
    _require(
        collector["started_at"]
        <= withdrawal["initial_acquisition"]["started_at"]
        <= withdrawal["missing_helper_acquisition"]["finished_at"]
        <= collector["finished_at"]
    )

    _require(withdrawal["copy"]["production_helper_sha256"] == phase["native_facts"]["helper"]["sha256"])
    _require(withdrawal["initial_acquisition"]["payload"]["source_before"] == before["fixture"]["source"])


def _native_phase_coverage(phase: dict[str, Any], directory: Path) -> None:
    validate_phase_control_binding(phase, directory=directory)
    _native_execution_report(phase, directory)
    if phase["observation"] == "provision":
        _native_provision_coverage(phase, directory)
    else:
        path, prior = _evidence_ref(directory, phase["provision_reference"])
        _require(prior["observation"] == "provision" and prior["acceptance_kind"] == phase["acceptance_kind"])
        _require(prior["status"] == prior["acceptance_kind"] + "_native_passed")
        _native_phase_coverage(prior, path.parent)
        validate_reopen_continuity(prior, phase, phase["observation"])


def validate_native_phase_evidence(value: Any, *, directory: Path) -> dict[str, Any]:
    try:
        phase = _object(
            value,
            (
                "schema_version",
                "mode",
                "platform",
                "acceptance_kind",
                "bootstrap",
                "observation",
                "executions",
                "fixture",
                "logical",
                "boot",
                "native_implementation_sha256",
            ),
        )
        _require(phase["schema_version"] == RUN_SCHEMA and phase["mode"] in {"source", "wheel"})
        _require(phase.get("status") == "production_native_passed" and phase.get("live_accepted") is False)
        _require(phase["platform"] in {"linux", "win32"} and _hex(phase["native_implementation_sha256"], 64))
        _require(phase["acceptance_kind"] == "production" and phase["bootstrap"] == "automatic_production")
        _require(phase["fixture"]["root"] == phase["fixture"]["source"]["root"])
        _require(_hex(phase["fixture"]["source"]["record_sha256"], 64))
        _native_phase_coverage(phase, directory)
    except (OSError, ValueError, TypeError, KeyError, StopIteration, tarfile.TarError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("native_phase_evidence_incomplete") from exc
    return phase


def _verify_mode_sequences(phases: list[dict[str, Any]]) -> None:
    kinds = ("provision", "process_restart", "os_reboot", "ec2_stop_start")
    for platform in ("linux", "win32"):
        for mode in ("source", "wheel"):
            selected = [row for row in phases if row["platform"] == platform and row["mode"] == mode]
            _require(len(selected) == 4 and {row["observation"] for row in selected} == set(kinds))
            ordered = [next(row for row in selected if row["observation"] == kind) for kind in kinds]
            _require([row["finished_at"] for row in ordered] == sorted(row["finished_at"] for row in ordered))
            baseline = ordered[0]
            for row in ordered[1:]:
                validate_reopen_continuity(baseline, row, row["observation"])
            _require(ordered[2]["boot"]["identity"] != ordered[3]["boot"]["identity"])
            _require(ordered[0]["control_action"]["sha256"] == ordered[1]["control_action"]["sha256"])
            for before, after in itertools.pairwise(ordered[1:]):
                _require(before["finished_at"] < after["_control"]["action_at"])
                _require(before["control_sequence"] < after["control_sequence"])


def _cloud_observation(root: Path, reference: Any) -> dict[str, Any]:
    _, observation = _evidence_ref(root, reference)
    _require(observation["schema"] == 1 and observation["kind"] == "ec2_state_observation")
    _, raw = _evidence_ref(root, observation["raw"])
    rows = [row for reservation in raw["Reservations"] for row in reservation["Instances"]]
    _require(len(rows) == 1 and rows[0]["InstanceId"] == observation["instance"])
    _require(rows[0]["State"]["Name"] == observation["state"] and _timestamp(observation["observed_at"]))
    _require(_hex(observation["controller_run"], 32))
    owners = [tag["Value"] for tag in rows[0].get("Tags", []) if tag.get("Key") == "mordred:dbcrypt-validation"]
    _require(len(owners) <= 1)
    account = raw["Reservations"][0]["OwnerId"]
    return {**observation, "_owner": owners[0] if owners else None, "_account": account}


def _verify_native_stops(root: Path, matrix: dict[str, Any], phases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cycles = validate_control_cycles(root, matrix["control_cycles"], phases)
    _require(len(matrix["stop_receipts"]) == 2)
    receipts = []
    for reference in matrix["stop_receipts"]:
        path, _raw = _evidence_ref(root, reference)
        receipt = load_stop_receipt(path)
        last = max(
            (row for row in cycles.values() if row["instance"] == receipt["instance"]), key=lambda row: row["sequence"]
        )
        _require(receipt["run"] == last["controller_run"] and reference["sha256"] == last["stopped_sha256"])
        _require(
            receipt["stopped_at"] >= max(row["finished_at"] for row in phases if row["instance"] == receipt["instance"])
        )
        receipts.append(receipt)
    _require({row["instance"] for row in receipts} == INSTANCES)
    return receipts


def verify_native_spool(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": RUN_SCHEMA,
        "phase": "verify",
        "status": "refused",
        "live_accepted": False,
        "reasons": [],
    }
    if not (root / "matrix.json").is_file():
        return {**result, "reasons": ["missing_production_matrix"]}
    try:
        matrix = json.loads(_input_file(root / "matrix.json").read_text())
        _require(matrix["schema_version"] == RUN_SCHEMA)
        phases = []
        for reference in matrix["phases"]:
            path, phase = _evidence_ref(root, reference)
            validated = validate_native_phase_evidence(phase, directory=path.parent)
            action = validate_phase_control_binding(validated, directory=path.parent)
            phases.append({**validated, "_control": action})
        _verify_mode_sequences(phases)
        receipts = _verify_native_stops(root, matrix, phases)
        result.update(
            status="production_native_passed", live_accepted=True, phases=len(phases), owned_instance_receipts=receipts
        )
    except (OSError, ValueError, TypeError, KeyError, StopIteration, tarfile.TarError, AcceptanceRefused):
        result["reasons"] = ["production_matrix_incomplete_or_inconsistent"]
    return result


def _native_environment(context: dict[str, Any], root: Path) -> dict[str, str]:
    environment = probe_environment(root)
    environment.update(
        {
            "DBCRYPT_BUNDLE": str(context["bundle"]),
            "DBCRYPT_CHECKOUT": context["manifest"]["checkout"],
            context["helper_name"]: str(context["helper"]),
            "MORDRED_DBCRYPT_COLLECTORS_TEST": "1",
            "MORDRED_DBCRYPT_TEST_ROOT": str(root),
            "MORDRED_DBCRYPT_ACCEPTANCE_MODE": context["mode"],
            "MORDRED_DBCRYPT_ACCEPTANCE_KIND": context["kind"],
            "MORDRED_HERMES_RUNTIME_PYTHON": str(_native_python(context)),
            "MORDRED_HERMES_PYTHON": str(_native_python(context)),
            "MORDRED_DBCRYPT_WITHDRAWABLE_HELPER_MANIFEST": str(context["helper_copy_manifest"]),
            "MORDRED_DBCRYPT_PARENT": str(context["parent"]),
        }
    )
    if context.get("qualification"):
        environment["MORDRED_DBCRYPT_QUALIFICATION_DIRECTORY"] = context["qualification"]
    return environment


def _native_python(context: dict[str, Any]) -> Path:
    base = (
        Path(context["manifest"]["checkout"]) / ".venv"
        if context["mode"] == "source"
        else context["bundle"] / "wheel-env"
    )
    return _python(base)


def _native_driver(context: dict[str, Any], directory: Path) -> Path:
    path = directory / "hermes"
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
    context: dict[str, Any], argv: list[str], environment: dict[str, str], *, timeout: int, name: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    record: dict[str, Any] = {"name": name, "argv": argv, "cwd": str(context["bundle"]), "started_at": time.time()}
    context.setdefault("execution_log", []).append(record)
    try:
        result = subprocess.run(
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


def _collector_child(context: dict[str, Any], root: Path, operation: str, directory: Path) -> dict[str, Any]:
    if operation not in {"preflight", "provision", "seed", "read"}:
        raise AcceptanceRefused("unsupported_fixed_native_operation")
    validate_bundle(context["bundle"])
    require_native_source_checkout(context)
    probe = probe_interpreter(_native_python(context), cwd=context["bundle"])
    validate_import_provenance(
        Path(probe["product_file"]),
        checkout=Path(context["manifest"]["checkout"]),
        environment=context["bundle"] / "wheel-env",
        mode=context["mode"],
    )
    helper = context["bundle"] / "tests/_dbcrypt_acceptance_native.py"
    environment = _native_environment(context, root)
    driver = _native_driver(context, directory)
    environment["MORDRED_DBCRYPT_PRODUCTION_DRIVER"] = str(driver)
    if context["kind"] == "candidate":
        code = f"import runpy; raise SystemExit(runpy.run_path({str(helper)!r})['main']({operation!r}))"
        argv = [str(_native_python(context)), "-c", code]
    else:
        argv = [str(_native_python(context)), str(driver), operation]
    result, record = _native_process(context, argv, environment, timeout=900, name=operation)
    record.update(
        operation=operation,
        fixture_path=str(root),
        mode=context["mode"],
        bundle_manifest_sha256=sha256_file(context["bundle"] / "manifest.json"),
    )
    try:
        payload = json.loads(result.stdout)
        _require(result.returncode == 0 and payload["schema_version"] == RUN_SCHEMA and payload["status"] == "executed")
        _require(
            payload["operation"] == operation
            and payload["facts"]["native_provider"] in {"EC2 NitroTPM", "Microsoft Platform Crypto Provider"}
        )
        _require(payload["facts"]["helper"]["sha256"] == context["helper_sha256"])
        _require(payload["acceptance_kind"] == context["kind"])
        _require(
            payload["implementation_sha256"] == context["manifest"]["files"]["tests/_dbcrypt_acceptance_native.py"]
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise AcceptanceRefused("native_child_refused_or_failed:" + operation) from exc
    record.update(
        import_probe=probe,
        payload=payload,
        status="executed",
        driver_ref={"path": driver.relative_to(directory.parent).as_posix(), "sha256": sha256_file(driver)},
    )
    return record


def _native_suite(context: dict[str, Any], row: dict[str, Any], directory: Path, baseline: Path) -> dict[str, Any]:
    validate_bundle(context["bundle"])
    require_native_source_checkout(context)
    probe = probe_interpreter(_native_python(context), cwd=context["bundle"])
    validate_import_provenance(
        Path(probe["product_file"]),
        checkout=Path(context["manifest"]["checkout"]),
        environment=context["bundle"] / "wheel-env",
        mode=context["mode"],
    )
    environment = _native_environment(context, context["fixtures"]["persistence"])
    environment.update(row["env"])
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
    environment["MORDRED_DBCRYPT_PRODUCTION_DRIVER"] = str(_native_driver(context, directory))
    configuration = context["bundle"] / context["manifest"]["extracted_sdist"] / "pyproject.toml"
    argv = [*row["argv"], "-c", str(configuration), "-p", "tests._dbcrypt_acceptance_native"]
    selected_library = None
    if row["suite"] == "windows-vfs":
        qualification = validate_windows_qualification(
            Path(context["qualification"]), checkout=Path(context["manifest"]["checkout"])
        )
        if row["mode"] == "source":
            raw = qualification["diagnostic"]
            environment["MORDRED_DBCRYPT_CHECKED_LIBRARY"] = raw["dll"]
        for name in ("MORDRED_DBCRYPT_VFS_FIXTURE_ROOT", "MORDRED_DBCRYPT_QUALIFICATION_MANIFEST"):
            if not os.environ.get(name):
                raise AcceptanceRefused("owned_windows_vfs_fixtures_required")
            environment[name] = os.environ[name]
        environment["MORDRED_DBCRYPT_TEST_ROOT"] = environment["MORDRED_DBCRYPT_VFS_FIXTURE_ROOT"]
        selected = qualification["diagnostic" if row["mode"] == "source" else "wheel"]
        selected_library = {"path": selected["dll"], "sha256": selected["dll_sha256"], "kind": selected["target"]}
    collect_path = directory / (row["suite"] + ".collection.json")
    collect_environment = {**environment, "MORDRED_DBCRYPT_PYTEST_REPORT": str(collect_path)}
    collect_result, collected_record = _native_process(
        context, [*argv, "--collect-only"], collect_environment, timeout=300, name=row["suite"] + "-collection"
    )
    if collect_result.returncode != 0 or not collect_path.is_file():
        raise AcceptanceRefused("native_complete_collection_failed:" + row["suite"])
    collection_record = {
        "argv": collected_record["argv"],
        "returncode": collect_result.returncode,
        "report": {"path": collect_path.relative_to(directory.parent).as_posix(), "sha256": sha256_file(collect_path)},
    }
    result, record = _native_process(context, argv, environment, timeout=3600, name=row["suite"])
    record.update(
        suite=row["suite"],
        mode=context["mode"],
        import_probe=probe,
        gate_env=row["env"],
        bundle_manifest_sha256=sha256_file(context["bundle"] / "manifest.json"),
        collection=collection_record,
    )
    if selected_library is not None:
        record["windows_library"] = selected_library
    if report.is_file():
        record["pytest_report"] = {
            "path": report.relative_to(directory.parent).as_posix(),
            "sha256": sha256_file(report),
        }
    if result.returncode or not report.is_file():
        raise AcceptanceRefused("native_module_failed:" + row["suite"])
    parsed = validate_native_test_report(json.loads(report.read_text()), platform=sys.platform, suite=row["suite"])
    record.update(
        nodeids=parsed["nodeids"],
        counts=parsed["counts"],
        platform_na=parsed["platform_na"],
        status="executed",
        collector_rows=[
            {"path": path.relative_to(directory.parent).as_posix(), "sha256": sha256_file(path)}
            for path in sorted(row_directory.glob("*.json"))
        ],
    )
    return record


def _native_reopen_prior(context: dict[str, Any], directory: Path) -> dict[str, Any]:
    if context["prior"] is None:
        raise AcceptanceRefused("native_reopen_prior_missing")
    prior_path = context["prior"]
    if not prior_path.is_relative_to(directory.parent):
        raise AcceptanceRefused("prior_evidence_must_share_private_spool")
    prior = json.loads(_private_evidence_file(prior_path).read_text())
    _require(prior["status"] == context["kind"] + "_native_passed" and prior["observation"] == "provision")
    _require(
        prior["mode"] == context["mode"]
        and prior["bundle_manifest_sha256"] == sha256_file(context["bundle"] / "manifest.json")
    )
    _native_phase_coverage(prior, prior_path.parent)
    _require(prior["native_roots"] == {key: str(path) for key, path in context["fixtures"].items()})
    return dict(prior)


def _execute_native_phase(context: dict[str, Any], *, phase: Phase, directory: Path) -> dict[str, Any]:
    persistence = context["fixtures"]["persistence"]
    action_path = context["control_action_path"]
    try:
        action_relative = action_path.relative_to(directory.parent)
    except ValueError as exc:
        raise AcceptanceRefused("controller_action_must_share_private_spool") from exc
    action_reference = {"path": action_relative.as_posix(), "sha256": context["control_action"]["sha256"]}
    prior = _native_reopen_prior(context, directory) if phase == "reopen" else None
    executions = [_collector_child(context, persistence, "preflight", directory)]
    if phase == "provision":
        for fixture in context["fixtures"].values():
            executions.append(_collector_child(context, fixture, "provision", directory))
        executions.append(_collector_child(context, context["fixtures"]["negative"], "seed", directory))
        executions.append(_collector_child(context, persistence, "seed", directory))
        baseline = executions[-1]["payload"]
        baseline_path = directory / "baseline.json"
        _write_new(baseline_path, baseline)
        rows = native_acceptance_commands(
            checkout=Path(context["manifest"]["checkout"]),
            bundle=context["bundle"],
            platform=sys.platform,
            kind=context["kind"],
        )
        for row in rows:
            if row["mode"] == context["mode"] and "argv" in row:
                executions.append(_native_suite(context, row, directory, baseline_path))
    executions.append(_collector_child(context, persistence, "read", directory))
    actual = executions[-1]["payload"]
    result = {
        "schema_version": RUN_SCHEMA,
        "mode": context["mode"],
        "acceptance_kind": context["kind"],
        "platform": sys.platform,
        "bundle_manifest_sha256": sha256_file(context["bundle"] / "manifest.json"),
        "bundle": {key: context["manifest"][key] for key in ("commit", "sdist_sha256", "wheel_sha256")},
        "fixture": actual["fixture"],
        "logical": actual["logical"],
        "boot": actual["facts"]["boot"],
        "native_facts": actual["facts"],
        "native_roots": {kind: str(path) for kind, path in context["fixtures"].items()},
        "bundle_evidence": _export_bundle_evidence(context, directory),
        "qualification_evidence": _export_windows_qualification(context, directory),
        "observation": context["observation"],
        "executions": executions,
        "bootstrap": "explicit_candidate" if context["kind"] == "candidate" else "automatic_production",
        "live_accepted": False,
        "unexpected_skips": [],
        "phase": phase,
        "status": context["kind"] + "_native_passed",
        "native_rows_complete": False,
        "native_implementation_sha256": context["manifest"]["files"]["tests/_dbcrypt_acceptance_native.py"],
        "instance": "i-095cbe655c196c749" if sys.platform == "linux" else "i-00f4db5c3a204906b",
        "controller_run": context["control_action"]["controller_run"],
        "control_sequence": context["control_action"]["sequence"],
        "control_action": action_reference,
        "started_at": executions[0]["started_at"],
        "finished_at": time.time(),
        "limitations": ["cached_access_failure_is_injected_not_physical_tpm_disable"],
    }
    if sys.platform == "win32" and context["kind"] == "candidate":
        result["qualified_vfs"] = _qualified_vfs_reference(
            validate_windows_qualification(
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
        result["provision_reference"] = {"path": relative.as_posix(), "sha256": sha256_file(context["prior"])}
        validate_reopen_continuity(prior, result, context["observation"])
    _require(sha256_file(action_path) == action_reference["sha256"])
    _native_phase_coverage(result, directory.parent)
    result["native_rows_complete"] = True
    return result


def _build_receipt_files(directory: Path, receipt: dict[str, Any]) -> set[Path]:
    files = {directory / "receipt.json"}
    files.update(_artifact_ref(directory, ref) for ref in receipt.get("inputs", {}).values())
    files.update(_artifact_ref(directory, receipt[key]) for key in ("stdout", "stderr", "dll") if key in receipt)
    return files


def _copy_build_receipts(source: Path, target: Path) -> None:
    _require(source.is_absolute() and source == source.resolve(strict=True))
    source = source.resolve(strict=True)
    target.mkdir(mode=0o700, parents=True)
    receipts = sorted(source.glob("*/receipt.json"))
    _require(bool(receipts))
    for path in receipts:
        receipt = json.loads(_input_file(path).read_text())
        for original in _build_receipt_files(path.parent, receipt):
            destination = target / original.relative_to(source)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with destination.open("xb") as output:
                output.write(_input_file(original).read_bytes())


def _validate_build_receipt(
    path: Path,
    *,
    expected_inputs: dict[str, str],
    source_root: str,
    version: str,
    dll_hash: str,
    installed_at: float,
    observed_at: float,
) -> dict[str, Any]:
    receipt = json.loads(_input_file(path).read_text())
    _require(receipt["schema_version"] == 1 and receipt["kind"] == "dbcrypt_vfs_build")
    _require(
        receipt["status"] == "succeeded"
        and receipt["version"] == version
        and type(receipt["returncode"]) is int
        and receipt["returncode"] == 0
    )
    _require(receipt["source_root"] == source_root and _timestamp(receipt["started_at"]))
    _require(receipt["started_at"] <= receipt["finished_at"] <= installed_at <= observed_at)
    args = receipt["argv"]
    _require(
        len(args) == 13
        and args[:6] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
    )
    root = _guest_path(source_root, "win32")
    _require(_guest_path(args[6], "win32") == root / "native/dbcrypt-vfs/build.ps1")
    _require(
        args[7] == "-OutputDirectory" and args[9] == "-SqliteIncludeDirectory" and args[11:] == ["-Target", "Checked"]
    )
    staging = _guest_path(args[8], "win32")
    _require(_guest_path(args[10], "win32") == staging / "include")
    _require(_guest_path(receipt["dll"]["observed_path"], "win32") == staging / "mordred_dbcrypt_checked.dll")
    _require(set(receipt["inputs"]) == set(expected_inputs))
    for name, digest in expected_inputs.items():
        _require(sha256_file(_artifact_ref(path.parent, receipt["inputs"][name])) == digest)
    dll = _artifact_ref(path.parent, receipt["dll"])
    _require(sha256_file(dll) == dll_hash and dll.stat().st_size == receipt["dll"]["size"])
    for key in ("stdout", "stderr"):
        _require(_artifact_ref(path.parent, receipt[key]).stat().st_size == receipt[key]["size"] <= 1024 * 1024)
    return dict(receipt)


def _package_build_inputs(
    bundle: dict[str, Any], directory: Path, proof: dict[str, Any], headers: dict[str, str]
) -> dict[str, str]:
    expected = {}
    with tarfile.open(_artifact_ref(directory, proof["artifacts"]["sdist"]), "r:gz") as archive:
        prefix = Path(bundle["sdist"]).name.removesuffix(".tar.gz") + "/"
        for member in archive.getmembers():
            name = member.name.removeprefix(prefix)
            if name in {"hatch_build.py", "tools/dbcrypt_build_headers.py", "native/dbcrypt-vfs/build.ps1"} or (
                name.startswith("native/dbcrypt-vfs/") and name.endswith((".c", ".h"))
            ):
                stream = archive.extractfile(member)
                _require(member.isfile() and stream is not None)
                assert stream is not None
                expected[name] = hashlib.sha256(stream.read()).hexdigest()
    _require({"hatch_build.py", "tools/dbcrypt_build_headers.py", "native/dbcrypt-vfs/build.ps1"} <= set(expected))
    return {**expected, **{"headers/" + name: digest for name, digest in headers.items()}}


def _local_bundle_proof(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    def ref(name: str) -> dict[str, str]:
        return {"path": name, "sha256": sha256_file(path / name)}

    return {
        "schema_version": 1,
        "kind": "dbcrypt_bundle_evidence",
        "bundle_path": str(path),
        "manifest": ref("manifest.json"),
        "configuration": ref(manifest["extracted_sdist"] + "/pyproject.toml"),
        "artifacts": {kind: ref(manifest[kind]) for kind in ("sdist", "wheel")},
        "inputs": {name: ref(name) for name in manifest["files"] if name.startswith(("tests/", "tools/"))},
        "native_build": {name: ref(name) for name in manifest["files"] if name.startswith("artifacts/native-build/")},
    }


def matching_build_receipts(
    observed: dict[str, Any], *, bundle: dict[str, Any], proof: dict[str, Any], directory: Path, headers: dict[str, str]
) -> list[str]:
    mode = observed["mode"]
    expected = _package_build_inputs(bundle, directory, proof, headers)
    root = (
        bundle["checkout"]
        if mode == "source"
        else str(_guest_path(proof["bundle_path"], "win32") / bundle["extracted_sdist"])
    )
    matches = []
    for name, reference in proof["native_build"].items():
        if name.startswith("artifacts/native-build/" + mode + "/") and name.endswith("/receipt.json"):
            try:
                _validate_build_receipt(
                    _artifact_ref(directory, reference),
                    expected_inputs=expected,
                    source_root=root,
                    version="editable" if mode == "source" else "standard",
                    dll_hash=observed["dll_sha256"],
                    installed_at=observed["installed_at"],
                    observed_at=observed["observed_at"],
                )
            except (OSError, KeyError, ValueError, TypeError):
                continue
            matches.append(name)
    _require(bool(matches))
    return sorted(matches)


def validate_windows_diagnostic(directory: Path, *, checkout: Path) -> dict[str, Any]:
    """Historical full C proof only; never admits native storage eligibility."""
    manifest = json.loads(_input_file(directory / "manifest.json").read_text())
    _require(manifest["schema"] == 1 and manifest["kind"] in {"windows_vfs_diagnostic", "windows_vfs_qualification"})
    provenance = _qualification_source(directory, manifest, checkout)
    full = windows_vfs_required_nodes(checkout, release=False)
    raw = _qualification_row(
        directory, manifest["rows"]["checkedtest_source"], "CheckedTest", full, provenance["configuration"]
    )
    for reference in manifest["rows"]["checkedtest_source"].values():
        _, row = _evidence_ref(directory, reference)
        _require(row.get("deselected", []) == [])
    _qualification_binaries(directory, manifest["artifacts"]["checkedtest_source"], raw, provenance)
    plan = _qualification_fixture(directory, manifest)
    _require(PureWindowsPath(raw["dll"]).parent.parent == PureWindowsPath(plan["test_root"]))
    _require(
        PureWindowsPath(raw["product_module"]).is_relative_to(
            PureWindowsPath(provenance["source"]) / "src/mordred_hermes"
        )
    )
    if "reused_builds" in provenance:
        reused = provenance["reused_builds"]["CheckedTest"]
        critical = {
            key: digest
            for key, digest in provenance["source_hashes"].items()
            if key.startswith(("native/dbcrypt-vfs/", "src/mordred_hermes/_private_fs/"))
            or key == "src/mordred_hermes/dbcrypt/_windows_vfs.py"
        }
        _require(reused["critical_inputs"] == critical and reused["headers"] == provenance["headers"])
        _require(reused["dll_sha256"] == raw["dll_sha256"])
        _require(
            reused["actual_build_stdout_sha256"]
            == manifest["artifacts"]["checkedtest_source"]["build_stdout"]["sha256"]
        )
        _require(reused["cached_runtime"][raw["executable"]] == raw["python_sha256"])
        _require(reused["cached_runtime"][raw["driver_native"]] == raw["driver_native_sha256"])
    return {
        "manifest": manifest,
        "provenance": provenance,
        "diagnostic": {**raw, "role": "diagnostic_source"},
        "manifest_sha256": sha256_file(directory / "manifest.json"),
        "fixture": plan,
    }


def _diagnostic_files(directory: Path, manifest: dict[str, Any]) -> set[Path]:
    paths = {directory / "manifest.json"}
    for key in (
        "provenance",
        "source_map",
        "source_archive",
        "configuration",
        "fixture_plan",
        "fixture_manifest",
        "fixture_verify",
    ):
        paths.add(_artifact_ref(directory, manifest[key]))
    paths.update(_artifact_ref(directory, ref) for ref in manifest["headers"].values())
    for name in ("checkedtest_source", "checked_source"):
        if name in manifest["rows"]:
            paths.update(_artifact_ref(directory, ref) for ref in manifest["rows"][name].values())
            paths.update(
                _artifact_ref(directory, manifest["artifacts"][name][key])
                for key in ("dll", "driver_native", "python", "build_stdout", "build_script")
            )
    return paths


def windows_package_commands(
    *,
    checkout: Path | PureWindowsPath,
    bundle: Path | PureWindowsPath,
    mode: str,
    basetemp: Path | PureWindowsPath,
    configuration: Path | PureWindowsPath,
) -> list[dict[str, Any]]:
    _require(mode in {"source", "wheel"})
    prefix = (
        ["uv", "run", "--project", str(checkout), "pytest"]
        if mode == "source"
        else [
            "uv",
            "run",
            "--no-project",
            "--python",
            str(bundle / "wheel-env/Scripts/python.exe"),
            "python",
            "-m",
            "pytest",
        ]
    )
    args = [
        "-q",
        "-c",
        str(configuration),
        "-o",
        "addopts=",
        "-m",
        "integration",
        "--basetemp",
        str(basetemp),
        str(bundle / "tests/integration/test_dbcrypt_windows_vfs.py"),
        "-k",
        WINDOWS_RELEASE_SELECTION,
        "-p",
        "tests._dbcrypt_acceptance_native",
    ]
    gates = {"MORDRED_DBCRYPT_WINDOWS_VFS_TEST": "1", "MORDRED_DBCRYPT_VFS_PACKAGE_QUALIFY": "1"}
    return [
        {
            "argv": [*prefix, *args, *(["--collect-only"] if action == "collect" else [])],
            "pytest_argv": [*args, *(["--collect-only"] if action == "collect" else [])],
            "env": gates,
            "action": action,
        }
        for action in ("collect", "run")
    ]


def validate_package_observation(
    observed: dict[str, Any],
    *,
    mode: str,
    bundle: dict[str, Any],
    proof: dict[str, Any],
    directory: Path,
    headers: dict[str, str],
) -> None:
    _require(
        mode in {"source", "wheel"}
        and observed["mode"] == mode
        and observed["role"] == "packaged_" + ("editable" if mode == "source" else "wheel")
    )
    _require(
        observed["bundle_manifest_sha256"] == proof["manifest"]["sha256"] and observed["commit"] == bundle["commit"]
    )
    _require(
        observed["elevated"] is False
        and observed["env_dll_override"] is None
        and observed["test_exports_absent"] is True
    )
    _validate_exported_import(
        observed["product_module"], mode=mode, platform="win32", bundle=bundle, bundle_path=proof["bundle_path"]
    )
    env = (
        _guest_path(bundle["checkout"], "win32") / ".venv"
        if mode == "source"
        else _guest_path(proof["bundle_path"], "win32") / "wheel-env"
    )
    _require(_guest_path(observed["executable"], "win32") == env / "Scripts/python.exe")
    _require(_guest_path(observed["driver_native"], "win32").is_relative_to(env))
    _require(
        _guest_path(observed["dll"], "win32").is_relative_to(env)
        and _guest_path(observed["record"], "win32").is_relative_to(env)
    )
    _require(
        observed["driver_version"] == "0.5.7"
        and observed["versions"] == {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"}
    )
    _require(observed["filesystem"]["method"] == "checked_confidential_fixed_local_ntfs")
    _require(observed["filesystem"]["identity"]["owner"] == observed["sid"])
    expected = _package_build_inputs(bundle, directory, proof, headers)
    root = (
        bundle["checkout"]
        if mode == "source"
        else str(_guest_path(proof["bundle_path"], "win32") / bundle["extracted_sdist"])
    )
    matches = observed["build_receipts"]
    _require(isinstance(matches, list) and bool(matches) and len(matches) == len(set(matches)))
    for name in matches:
        _require(name.startswith("artifacts/native-build/" + mode + "/") and name in proof["native_build"])
        receipt = _validate_build_receipt(
            _artifact_ref(directory, proof["native_build"][name]),
            expected_inputs=expected,
            source_root=root,
            version="editable" if mode == "source" else "standard",
            dll_hash=observed["dll_sha256"],
            installed_at=observed["installed_at"],
            observed_at=observed["observed_at"],
        )
        if mode == "wheel":
            command = bundle["build_commands"][4]
            _require(command["started_at"] <= receipt["started_at"] <= receipt["finished_at"] <= command["finished_at"])
            _require(observed["installed_at"] <= bundle["build_commands"][5]["finished_at"])
        else:
            _require(receipt["finished_at"] <= observed["installed_at"] <= bundle["build_commands"][0]["started_at"])


def _validate_packaged_result(
    directory: Path,
    result: dict[str, Any],
    *,
    mode: str,
    bundle: dict[str, Any],
    proof: dict[str, Any],
    proof_directory: Path,
    diagnostic: dict[str, Any],
    fixtures: dict[str, Any],
) -> dict[str, Any]:
    _require(
        result["schema_version"] == 1
        and result["kind"] == "packaged_windows_vfs_result"
        and result["status"] == "passed"
    )
    _require(result["mode"] == mode and result["diagnostic_manifest_sha256"] == diagnostic["manifest_sha256"])
    _require(result["fixtures_sha256"] == fixtures["manifest_sha256"])
    nested = _artifact_ref(directory, result["fixtures_descriptor"])
    _require(sha256_file(nested) == fixtures["manifest_sha256"])
    _fixture_descriptor(nested)
    paths = {key: _artifact_ref(directory, ref) for key, ref in result["artifacts"].items()}
    required = windows_vfs_required_nodes(Path(__file__).resolve().parents[1], release=True)
    full = windows_vfs_required_nodes(Path(__file__).resolve().parents[1], release=False)
    observations = []
    for index, action in enumerate(("collect", "run")):
        execution = result[action]
        _, report = _evidence_ref(directory, execution["report"])
        obs = report["qualification"]
        _require(obs["fixture_root"] == fixtures["plan"]["test_root"] and obs["sid"] == fixtures["plan"]["owner_sid"])
        validate_package_observation(
            obs,
            mode=mode,
            bundle=bundle,
            proof=proof,
            directory=proof_directory,
            headers=diagnostic["provenance"]["headers"],
        )
        _require(obs["driver_native_sha256"] == diagnostic["diagnostic"]["driver_native_sha256"])
        _require(
            [_normalized_node(node) for node in report["nodeids"]] == [_normalized_node(node) for node in required]
        )
        _require(
            {_normalized_node(node) for node in report["deselected"]}
            == {_normalized_node(node) for node in set(full) - set(required)}
        )
        expected = windows_package_commands(
            checkout=PureWindowsPath(bundle["checkout"]),
            bundle=PureWindowsPath(proof["bundle_path"]),
            mode=mode,
            basetemp=PureWindowsPath(execution["basetemp"]),
            configuration=PureWindowsPath(proof["bundle_path"]) / bundle["extracted_sdist"] / "pyproject.toml",
        )[index]
        _require(execution["argv"] == expected["argv"] and report["pytest_argv"] == expected["pytest_argv"])
        _require(execution["returncode"] == 0 and report["exitstatus"] == 0 and report["collection_errors"] == [])
        _require(execution["started_at"] <= obs["observed_at"] <= execution["finished_at"])
        _require(report["fixture_manifest_sha256"] == fixtures["manifest_sha256"])
        after = report["qualification_after"]
        validate_package_observation(
            after,
            mode=mode,
            bundle=bundle,
            proof=proof,
            directory=proof_directory,
            headers=diagnostic["provenance"]["headers"],
        )
        _require(
            {key: value for key, value in obs.items() if key != "observed_at"}
            == {key: value for key, value in after.items() if key != "observed_at"}
        )
        _require(obs["observed_at"] <= after["observed_at"] <= execution["finished_at"])
        if action == "collect":
            _require(report["reports"] == [])
        else:
            validate_native_test_report(report)
        observations.append(obs)
    _require(result["collect"]["finished_at"] <= result["run"]["started_at"])
    _, collection_report = _evidence_ref(directory, result["collect"]["report"])
    _, run_report = _evidence_ref(directory, result["run"]["report"])
    _require(
        collection_report["nodeids"] == run_report["nodeids"]
        and collection_report["deselected"] == run_report["deselected"]
    )
    before, after = observations
    stable = (
        "mode",
        "role",
        "commit",
        "bundle_manifest_sha256",
        "dll",
        "dll_sha256",
        "driver_native",
        "driver_native_sha256",
        "executable",
        "python_sha256",
        "record",
        "record_sha256",
        "product_module",
        "installed_at",
        "build_receipts",
        "filesystem",
        "sid",
    )
    _require(all(before[key] == after[key] for key in stable))
    for key, digest in (
        ("dll", "dll_sha256"),
        ("driver_native", "driver_native_sha256"),
        ("python", "python_sha256"),
        ("record", "record_sha256"),
    ):
        _require(sha256_file(paths[key]) == after[digest])
    _require(after["record_size"] == paths["record"].stat().st_size)
    asset = "mordred_hermes/_native/dbcrypt-vfs/mordred_dbcrypt_vfs.dll"
    rows = [row for row in csv.reader(io.StringIO(paths["record"].read_text())) if row[0] == asset]
    encoded = base64.urlsafe_b64encode(bytes.fromhex(after["dll_sha256"])).rstrip(b"=").decode()
    _require(len(rows) == 1 and rows[0][1:] == ["sha256=" + encoded, str(paths["dll"].stat().st_size)])
    if mode == "wheel":
        with zipfile.ZipFile(_artifact_ref(proof_directory, proof["artifacts"]["wheel"])) as wheel:
            _require(hashlib.sha256(wheel.read(asset)).hexdigest() == after["dll_sha256"])
    return {
        **after,
        "nodeids": run_report["nodeids"],
        "target": "Checked",
        "argv": result["run"]["argv"],
        "bundle_manifest_sha256": proof["manifest"]["sha256"],
        "sdist_sha256": bundle["sdist_sha256"],
        "wheel_sha256": bundle["wheel_sha256"],
    }


def _copy_referenced(source: Path, files: set[Path], target: Path) -> None:
    target.mkdir(mode=0o700)
    for original in sorted(files):
        relative = original.relative_to(source)
        _relative(relative.as_posix())
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write(_input_file(original).read_bytes())


def _fixture_descriptor(path: Path) -> tuple[dict[str, Any], set[Path]]:
    value = json.loads(_input_file(path).read_text())
    _require(path.name == "manifest.json" and value["schema"] == 1 and value["kind"] == "windows_vfs_fixtures")
    _qualification_fixture(path.parent, value)
    files = {
        path,
        *(_artifact_ref(path.parent, value[key]) for key in ("fixture_plan", "fixture_manifest", "fixture_verify")),
    }
    return value, files


def qualify_windows_vfs(*, bundle: Path, mode: str, diagnostic: Path, fixtures: Path, output: Path) -> Path:
    """One collection and one packaged release run, never custody provisioning."""
    _require(sys.platform == "win32" and mode in {"source", "wheel"})
    manifest = validate_bundle(bundle)
    require_native_source_checkout({"mode": mode, "manifest": manifest})
    historical = validate_windows_diagnostic(diagnostic.parent, checkout=Path(manifest["checkout"]))
    fixture, _files = _fixture_descriptor(fixtures)
    plan = _qualification_fixture(fixtures.parent, fixture)
    _require(
        output.is_absolute()
        and output.parent == output.parent.resolve(strict=True)
        and not output.exists()
        and not output.is_relative_to(bundle)
        and not output.is_relative_to(Path(manifest["checkout"]))
    )
    output.mkdir(mode=0o700)
    result: dict[str, Any] = {
        "schema_version": 1,
        "kind": "packaged_windows_vfs_result",
        "status": "failed",
        "mode": mode,
        "diagnostic_manifest_sha256": historical["manifest_sha256"],
        "fixtures_sha256": sha256_file(fixtures),
    }
    _copy_referenced(fixtures.parent, _files, output / "fixtures")
    result["fixtures_descriptor"] = {"path": "fixtures/manifest.json", "sha256": sha256_file(fixtures)}
    try:
        configuration = bundle / manifest["extracted_sdist"] / "pyproject.toml"
        rows = windows_package_commands(
            checkout=Path(manifest["checkout"]),
            bundle=bundle,
            mode=mode,
            basetemp=output / "pytest-temp",
            configuration=configuration,
        )
        with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-probe-") as home:
            environment = probe_environment(Path(home))
            environment.update(
                DBCRYPT_BUNDLE=str(bundle),
                MORDRED_DBCRYPT_VFS_DIAGNOSTIC=str(diagnostic),
                MORDRED_DBCRYPT_VFS_FIXTURES_DESCRIPTOR=str(fixtures),
                MORDRED_DBCRYPT_VFS_PACKAGE_MODE=mode,
                MORDRED_DBCRYPT_TEST_ROOT=plan["test_root"],
                MORDRED_DBCRYPT_QUALIFICATION_MANIFEST=str(_artifact_ref(fixtures.parent, fixture["fixture_manifest"])),
                UV_NO_SYNC="1",
            )
            for row in rows:
                action = row["action"]
                path = output / (action + ".json")
                started = time.time()
                execution = subprocess.run(
                    row["argv"],
                    cwd=bundle,
                    env={**environment, **row["env"], "MORDRED_DBCRYPT_PYTEST_REPORT": str(path)},
                    capture_output=True,
                    timeout=3600,
                    check=False,
                )
                result[action] = {
                    "argv": row["argv"],
                    "basetemp": str(output / "pytest-temp"),
                    "started_at": started,
                    "finished_at": time.time(),
                    "returncode": execution.returncode,
                    "report": {"path": path.name, "sha256": sha256_file(path)},
                }
                _require(execution.returncode == 0)
        report = json.loads((output / "run.json").read_text())
        observation = report["qualification_after"]
        result["artifacts"] = {}
        for key, original in (
            ("dll", observation["dll"]),
            ("driver_native", observation["driver_native"]),
            ("python", observation["executable"]),
            ("record", observation["record"]),
        ):
            target = output / (key + ".bin")
            observed_path = Path(original)
            _require(
                observed_path.is_absolute()
                and observed_path.resolve(strict=True) == observed_path
                and stat.S_ISREG(observed_path.lstat().st_mode)
            )
            with target.open("xb") as destination:
                destination.write(observed_path.read_bytes())
            result["artifacts"][key] = {"path": target.name, "sha256": sha256_file(target)}
        result["dll_sha256"] = observation["dll_sha256"]
        result["status"] = "passed"
        proof = _local_bundle_proof(bundle, manifest)
        _validate_packaged_result(
            output,
            result,
            mode=mode,
            bundle=manifest,
            proof=proof,
            proof_directory=bundle,
            diagnostic=historical,
            fixtures={"manifest_sha256": sha256_file(fixtures), "plan": plan},
        )
        validate_bundle(bundle)
        require_native_source_checkout({"mode": mode, "manifest": manifest})
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, AcceptanceRefused):
        result["status"] = "failed"
        _write_new(output / "result.json", result)
        raise AcceptanceRefused("packaged_windows_qualification_failed") from None
    _write_new(output / "result.json", result)
    return output / "result.json"


def _assemble_windows_qualification(
    *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path
) -> Path:
    """Offline fixed closure; copies referenced public artifacts only."""
    manifest = validate_bundle(bundle)
    checkout = Path(__file__).resolve().parents[1]
    historical = validate_windows_diagnostic(diagnostic.parent, checkout=checkout)
    _require(
        output.is_absolute()
        and output.parent == output.parent.resolve(strict=True)
        and not output.exists()
        and not output.is_relative_to(bundle)
        and not output.is_relative_to(checkout)
    )
    output.mkdir(mode=0o700)
    _copy_referenced(
        diagnostic.parent, _diagnostic_files(diagnostic.parent, historical["manifest"]), output / "diagnostic"
    )
    # The same original fixture bytes are retained independently of the diagnostic identity.
    # Results bind the operator fixture descriptor's exact bytes; copy it from each producer.
    source_value = json.loads(_input_file(source_result).read_text())
    original_fixtures = _artifact_ref(source_result.parent, source_value["fixtures_descriptor"])
    fixture, fixture_files = _fixture_descriptor(original_fixtures)
    _qualification_fixture(original_fixtures.parent, fixture)
    _copy_referenced(original_fixtures.parent, fixture_files, output / "fixtures")
    refs = {}
    for mode, path in (("source", source_result), ("wheel", wheel_result)):
        value = json.loads(_input_file(path).read_text())
        files = {
            path,
            *(_artifact_ref(path.parent, value[action]["report"]) for action in ("collect", "run")),
            *(_artifact_ref(path.parent, ref) for ref in value["artifacts"].values()),
        }
        nested = _artifact_ref(path.parent, value["fixtures_descriptor"])
        _require(sha256_file(nested) == sha256_file(original_fixtures))
        _, nested_files = _fixture_descriptor(nested)
        files.update(nested_files)
        _copy_referenced(path.parent, files, output / mode)
        copied = output / mode / path.name
        refs[mode] = {"path": str(copied.relative_to(output)), "sha256": sha256_file(copied)}
    export_directory = output / "export"
    export_directory.mkdir(mode=0o700)
    proof = _export_bundle_evidence({"bundle": bundle, "manifest": manifest}, export_directory)
    proof_file = output / proof["path"]
    descriptor = {
        "schema": 2,
        "kind": "windows_vfs_qualification",
        "diagnostic": {"path": "diagnostic/manifest.json", "sha256": sha256_file(diagnostic)},
        "fixtures": {"path": "fixtures/manifest.json", "sha256": sha256_file(original_fixtures)},
        "results": refs,
        "wheel_bundle": {"path": str(proof_file.relative_to(output)), "sha256": sha256_file(proof_file)},
    }
    try:
        _validate_qualification_payload(output, descriptor, checkout=checkout)
    except AcceptanceRefused:
        _write_new(
            output / "assembly-failure.json", {"status": "failed", "reason": "windows_native_qualification_incomplete"}
        )
        raise
    _write_new(output / "manifest.json", descriptor)
    return output / "manifest.json"


def assemble_windows_qualification(
    *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path
) -> Path:
    try:
        return _assemble_windows_qualification(
            bundle=bundle, diagnostic=diagnostic, source_result=source_result, wheel_result=wheel_result, output=output
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        tarfile.TarError,
        zipfile.BadZipFile,
        AcceptanceRefused,
    ):
        raise AcceptanceRefused("windows_native_qualification_incomplete") from None


def _validate_qualification_payload(directory: Path, manifest: dict[str, Any], *, checkout: Path) -> dict[str, Any]:
    _require(manifest["schema"] == 2 and manifest["kind"] == "windows_vfs_qualification")
    path = _artifact_ref(directory, manifest["diagnostic"])
    historical = validate_windows_diagnostic(path.parent, checkout=checkout)
    fixture_path = _artifact_ref(directory, manifest["fixtures"])
    fixture_manifest = json.loads(fixture_path.read_text())
    plan = _qualification_fixture(fixture_path.parent, fixture_manifest)
    fixture = {"manifest_sha256": sha256_file(fixture_path), "plan": plan}
    proof_path, proof = _evidence_ref(directory, manifest["wheel_bundle"])
    bundle = validate_bundle_evidence(proof, directory=proof_path.parent)
    provenance = historical["provenance"]
    # C/header/private-FS/config/test compatibility; the changed hook is bound by each new receipt.
    _qualified_package_artifacts(
        proof_path.parent,
        proof,
        bundle,
        {"dll_sha256": json.loads(_artifact_ref(directory, manifest["results"]["wheel"]).read_text())["dll_sha256"]},
        provenance,
    )
    released = {}
    for mode in ("source", "wheel"):
        result_path = _artifact_ref(directory, manifest["results"][mode])
        result = json.loads(result_path.read_text())
        released[mode] = _validate_packaged_result(
            result_path.parent,
            result,
            mode=mode,
            bundle=bundle,
            proof=proof,
            proof_directory=proof_path.parent,
            diagnostic=historical,
            fixtures=fixture,
        )
    _require(released["source"]["filesystem"] == released["wheel"]["filesystem"])
    return {
        "diagnostic": historical["diagnostic"],
        "source": released["source"],
        "wheel": released["wheel"],
        "prerequisite": manifest,
        "fixtures": plan,
        "fixture_manifest_sha256": fixture_manifest["fixture_manifest"]["sha256"],
    }


def validate_windows_qualification(directory: Path, *, checkout: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(_input_file(directory / "manifest.json").read_text())
        return {
            **_validate_qualification_payload(directory, manifest, checkout=checkout),
            "manifest_sha256": sha256_file(directory / "manifest.json"),
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        tarfile.TarError,
        zipfile.BadZipFile,
        AcceptanceRefused,
    ) as exc:
        raise AcceptanceRefused("windows_native_qualification_incomplete") from exc


def _qualified_vfs_reference(qualified: dict[str, Any], mode: str) -> dict[str, Any]:
    row = qualified[mode]
    return {
        "status": "satisfied_by_qualified_artifact_reference",
        "qualification_manifest_sha256": qualified["manifest_sha256"],
        "mode": mode,
        "dll_sha256": row["dll_sha256"],
        "driver_native_sha256": row["driver_native_sha256"],
        "nodeids": row["nodeids"],
        "original_results": qualified["prerequisite"]["results"],
        "historical_diagnostic": qualified["prerequisite"]["diagnostic"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--checkout", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--source-build-receipts", type=Path)
    qualify = commands.add_parser("qualify-windows-vfs")
    qualify.add_argument("--bundle", type=Path, required=True)
    qualify.add_argument("--mode", choices=("source", "wheel"), required=True)
    qualify.add_argument("--diagnostic", type=Path, required=True)
    qualify.add_argument("--fixtures", type=Path, required=True)
    qualify.add_argument("--output", type=Path, required=True)
    assemble = commands.add_parser("assemble-windows-qualification")
    for name in ("bundle", "diagnostic", "source-result", "wheel-result", "output"):
        assemble.add_argument("--" + name, type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--root", type=Path, required=True)
    run.add_argument("--phase", choices=("provision", "reopen", "verify"), required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            print(
                build_acceptance_bundle(
                    checkout=args.checkout, output=args.output, source_build_receipts=args.source_build_receipts
                )
            )
            return 0
        if args.command == "qualify-windows-vfs":
            print(
                qualify_windows_vfs(
                    bundle=args.bundle,
                    mode=args.mode,
                    diagnostic=args.diagnostic,
                    fixtures=args.fixtures,
                    output=args.output,
                )
            )
            return 0
        if args.command == "assemble-windows-qualification":
            print(
                assemble_windows_qualification(
                    bundle=args.bundle,
                    diagnostic=args.diagnostic,
                    source_result=args.source_result,
                    wheel_result=args.wheel_result,
                    output=args.output,
                )
            )
            return 0
        return run_acceptance(root=args.root, phase=args.phase, output=args.output)
    except (
        AcceptanceRefused,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        tarfile.TarError,
        zipfile.BadZipFile,
        subprocess.SubprocessError,
    ) as exc:
        print(str(exc) if isinstance(exc, AcceptanceRefused) else type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
