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
import hashlib
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
from pathlib import Path
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


def build_acceptance_bundle(*, checkout: Path, output: Path) -> Path:
    checkout, output = checkout.resolve(strict=True), output.resolve()
    if output.is_relative_to(checkout):
        raise AcceptanceRefused("bundle_must_be_outside_checkout")
    if output.exists():
        raise AcceptanceRefused("bundle_output_already_exists")
    commit = _git(checkout, "rev-parse", "HEAD")
    if _git(checkout, "status", "--porcelain", "--untracked-files=normal"):
        raise AcceptanceRefused("clean_committed_checkout_required")
    output.mkdir(mode=0o700, parents=True)
    commands: list[dict[str, Any]] = []
    try:
        _copy_inputs(checkout, output)
        with tempfile.TemporaryDirectory(prefix="mordred-dbcrypt-build-") as directory:
            provenance = _bundle_build(checkout, output, commands, Path(directory))
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
    bundle = Path(os.environ["DBCRYPT_BUNDLE"])
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
    helper_copy = validate_withdrawable_helper(Path(copy_manifest), production=helper, parent=root)
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
        validate_windows_qualification(Path(qualification), checkout=Path(manifest["checkout"]))
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


def validate_native_test_report(value: Any) -> dict[str, Any]:
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
        expected = {(node, stage) for node in nodes for stage in ("setup", "call", "teardown")}
        actual = []
        for row in report["reports"]:
            _require(row["outcome"] == "passed" and not row.get("wasxfail"))
            actual.append((row["nodeid"], row["when"]))
        _require(len(actual) == len(expected) and set(actual) == expected)
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("native_test_results_incomplete") from exc
    return report


def _evidence_ref(directory: Path, value: Any) -> tuple[Path, dict[str, Any]]:
    reference = _object(value, ("path", "sha256"))
    path = directory / _relative(reference["path"])
    _input_file(path)
    _require(path.resolve().is_relative_to(directory.resolve()) and _hex(reference["sha256"], 64))
    _require(sha256_file(path) == reference["sha256"])
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    _require(isinstance(payload, dict))
    return path, payload


def _qualification_row(directory: Path, reference: Any, target: str) -> dict[str, Any]:
    links = _object(reference, ("collect", "run"))
    _, collected = _evidence_ref(directory, links["collect"])
    _, run = _evidence_ref(directory, links["run"])
    _require(collected["action"] == "collect" and run["action"] == "run")
    _require(collected["target"] == target and run["target"] == target)
    _require(collected["nodeids"] == run["nodeids"] and collected["pytest_exit_code"] == 0)
    validate_native_test_report({**run, "exitstatus": run["pytest_exit_code"], "deselected": []})
    _require(run["collected"] == len(run["nodeids"]) and _hex(run["dll_sha256"], 64))
    _require(
        run["driver_version"] == "0.5.7" and run["versions"] == {"sqlite": "3.51.1", "sqlcipher": "4.12.0 community"}
    )
    return run


def validate_windows_qualification(directory: Path, *, checkout: Path) -> dict[str, Any]:
    try:
        _root = directory.resolve(strict=True)
        manifest = json.loads(_input_file(_root / "manifest.json").read_text())
        _require(manifest["schema"] == 1 and manifest["kind"] == "windows_vfs_qualification")
        rows = manifest["rows"]
        diagnostic = _qualification_row(_root, rows["checkedtest_source"], "CheckedTest")
        source = _qualification_row(_root, rows["checked_source"], "Checked")
        wheel = _qualification_row(_root, rows["checked_wheel"], "Checked")
        _require(set(source["nodeids"]) <= set(diagnostic["nodeids"]) and source["nodeids"] == wheel["nodeids"])
        _, provenance = _evidence_ref(_root, manifest["provenance"])
        _, fixture = _evidence_ref(_root, manifest["fixture_verify"])
        _require(fixture["elevated"] is False and _text(fixture["sid"]))
        critical = [
            *(checkout / "native/dbcrypt-vfs").glob("*.c"),
            *(checkout / "native/dbcrypt-vfs").glob("*.h"),
            *(checkout / "src/mordred_hermes/_private_fs").glob("*.py"),
            checkout / "src/mordred_hermes/dbcrypt/_windows_vfs.py",
            checkout / "tests/integration/test_dbcrypt_windows_vfs.py",
        ]
        _require(
            all(
                provenance["source_hashes"].get(path.relative_to(checkout).as_posix()) == sha256_file(path)
                for path in critical
            )
        )
        import runpy

        expected_headers = runpy.run_path(str(checkout / "tools/dbcrypt_build_headers.py"))["HEADER_SHA256"]
        _require(provenance["headers"] == expected_headers)
        for key in ("bundle_manifest_sha256", "sdist_sha256", "wheel_sha256"):
            _require(_hex(wheel[key], 64))
        _require(
            wheel["record_owned_packaged_dll"] is True
            and wheel["test_exports_absent"] is True
            and wheel["env_dll_override"] is None
        )
        _require(
            Path(wheel["product_module"]).parent.name == "mordred_hermes"
            and "site-packages" in Path(wheel["product_module"]).parts
        )
        return {"manifest_sha256": sha256_file(_root / "manifest.json"), "source": source, "wheel": wheel}
    except (OSError, ValueError, TypeError, KeyError, AcceptanceRefused) as exc:
        raise AcceptanceRefused("windows_native_qualification_incomplete") from exc


def validate_reopen_continuity(before: dict[str, Any], after: dict[str, Any], observation: str) -> None:
    try:
        _require(all(before[key] == after[key] for key in ("mode", "bundle_manifest_sha256", "fixture", "logical")))
        same_boot = before["boot"]["identity"] == after["boot"]["identity"]
        _require(same_boot if observation == "process_restart" else not same_boot)
        _require(observation in {"process_restart", "os_reboot", "ec2_stop_start"})
    except (ValueError, TypeError, KeyError) as exc:
        raise AcceptanceRefused("native_reopen_continuity_failed") from exc


def native_acceptance_commands(*, checkout: Path, bundle: Path, platform: str, kind: str) -> list[dict[str, Any]]:
    rows = acceptance_commands(checkout=checkout, bundle=bundle, platform=platform)
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


def _native_execution_report(phase: dict[str, Any], directory: Path) -> None:
    executions = phase["executions"]
    _require(isinstance(executions, list) and bool(executions))
    for execution in executions:
        _require(
            execution["returncode"] == 0
            and _timestamp(execution["started_at"])
            and _timestamp(execution["finished_at"])
        )
        if "pytest_report" in execution:
            _, report = _evidence_ref(directory, execution["pytest_report"])
            validate_native_test_report(report)
        else:
            payload = execution["payload"]
            _require(payload["schema_version"] == RUN_SCHEMA and payload["status"] == "executed")
            _require(
                payload["acceptance_kind"] == phase["acceptance_kind"] and payload["bootstrap"] == phase["bootstrap"]
            )
            _require(payload["implementation_sha256"] == phase["native_implementation_sha256"])
    required = {"preflight", "read"}
    _require(required <= {row.get("operation") for row in executions})


def _native_provision_coverage(phase: dict[str, Any], directory: Path) -> None:
    expected = {row[0] for row in _suites(phase["platform"])} | {"mail-native"}
    if phase["acceptance_kind"] == "production":
        expected.add("dbcrypt-activity")
    if phase["platform"] == "linux" and phase["mode"] == "source":
        expected.remove("linux-memory")
    if phase["platform"] == "win32":
        expected |= {"windows-memory-wizard", "windows-telegram-wizard"}
    _require(expected <= {row.get("suite") for row in phase["executions"]})
    collector = next(row for row in phase["executions"] if row.get("suite") == "dbcrypt-native")
    records = [_evidence_ref(directory, reference)[1] for reference in collector["collector_rows"]]
    for record in records:
        _require(record["schema_version"] == RUN_SCHEMA and record["status"] == "executed")
        _require(record["implementation_sha256"] == phase["native_implementation_sha256"])
        _require(record["acceptance_kind"] == phase["acceptance_kind"] and record["bootstrap"] == phase["bootstrap"])
    negative = next(row for row in records if row.get("operation") == "negative")
    _require("fresh_unpatched_native_provider_unavailable" in negative["rows"])
    validate_helper_withdrawal(negative["owned_helper_withdrawal"])
    _require(
        any(
            row.get("operation") == "backup_restore_failure" and row["result"] == "restore_incomplete"
            for row in records
        )
    )


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
        _require(_hex(phase["fixture"]["source"]["record_sha256"], 64) and bool(phase["logical"]))
        _native_phase_coverage(phase, directory)
    except (OSError, ValueError, TypeError, KeyError, StopIteration, AcceptanceRefused) as exc:
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
    except (OSError, ValueError, TypeError, KeyError, StopIteration, AcceptanceRefused):
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
    record["operation"] = operation
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
    record.update(import_probe=probe, payload=payload, status="executed")
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
    argv = [*row["argv"], "-p", "tests._dbcrypt_acceptance_native"]
    if row["suite"] == "windows-vfs":
        qualification = validate_windows_qualification(
            Path(context["qualification"]), checkout=Path(context["manifest"]["checkout"])
        )
        if row["mode"] == "source":
            descriptor = json.loads((Path(context["qualification"]) / "manifest.json").read_text())
            raw = _qualification_row(
                Path(context["qualification"]), descriptor["rows"]["checkedtest_source"], "CheckedTest"
            )
            environment["MORDRED_DBCRYPT_CHECKED_LIBRARY"] = raw["dll"]
        for name in ("MORDRED_DBCRYPT_VFS_FIXTURE_ROOT", "MORDRED_DBCRYPT_QUALIFICATION_MANIFEST"):
            if not os.environ.get(name):
                raise AcceptanceRefused("owned_windows_vfs_fixtures_required")
            environment[name] = os.environ[name]
        environment["MORDRED_DBCRYPT_TEST_ROOT"] = environment["MORDRED_DBCRYPT_VFS_FIXTURE_ROOT"]
        del qualification
    result, record = _native_process(context, argv, environment, timeout=3600, name=row["suite"])
    record.update(suite=row["suite"], mode=context["mode"], import_probe=probe)
    if report.is_file():
        record["pytest_report"] = {
            "path": report.relative_to(directory.parent).as_posix(),
            "sha256": sha256_file(report),
        }
    if result.returncode or not report.is_file():
        raise AcceptanceRefused("native_module_failed:" + row["suite"])
    parsed = validate_native_test_report(json.loads(report.read_text()))
    record.update(
        nodeids=parsed["nodeids"],
        counts={"passed": len(parsed["nodeids"]), "skipped": 0},
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
    result["test_counts"] = {
        "passed": sum(row.get("counts", {}).get("passed", 0) for row in executions),
        "collected": sum(len(row.get("nodeids", [])) for row in executions),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--checkout", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--root", type=Path, required=True)
    run.add_argument("--phase", choices=("provision", "reopen", "verify"), required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            print(build_acceptance_bundle(checkout=args.checkout, output=args.output))
            return 0
        return run_acceptance(root=args.root, phase=args.phase, output=args.output)
    except (AcceptanceRefused, OSError, subprocess.SubprocessError) as exc:
        print(str(exc) if isinstance(exc, AcceptanceRefused) else type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
