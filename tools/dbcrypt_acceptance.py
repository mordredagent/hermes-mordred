#!/usr/bin/env python3
"""Inert installed-package acceptance preparation, never native qualification.

Builds an external source/sdist/wheel bundle and records real interpreter probes.
Native provision/reopen/verify collectors are not integrated yet: every run
refuses with structured evidence. Neither this tool nor a receipt starts/stops
compute, provisions keys, grants elevation, or calls a cloud control API. A frozen
operator-furnished control receipt is evidence input, not authorization.
"""

from __future__ import annotations

import argparse
import hashlib
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
    environment.update(HERMES_HOME=str(home), PYTHONNOUSERSITE="1", UV_NO_PROGRESS="1")
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
    failures = ["native_collectors_not_integrated"]
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
        "reasons": ["native_collectors_not_integrated"],
    }
    try:
        if phase not in ("provision", "reopen", "verify"):
            raise AcceptanceRefused("unsupported_phase")
        evidence["root"] = _root_identity(root)
        bundle_text = os.environ.get("DBCRYPT_BUNDLE")
        if bundle_text:
            bundle = Path(bundle_text)
            manifest = validate_bundle(bundle)
            evidence["bundle"] = {
                key: manifest.get(key)
                for key in ("commit", "sdist_sha256", "wheel_sha256", "source_probe", "wheel_probe")
            }
            evidence["bundle_manifest_sha256"] = sha256_file(bundle / "manifest.json")
        receipt = os.environ.get("MORDRED_DBCRYPT_STOP_RECEIPT")
        if receipt:
            evidence["owned_instance_receipts"] = [load_stop_receipt(Path(receipt))]
        evidence["reasons"] = acceptance_failures(evidence)
    except (AcceptanceRefused, OSError) as exc:
        evidence["reasons"].append(str(exc) if isinstance(exc, AcceptanceRefused) else "root_probe_failed")
    evidence["finished_at"] = time.time()
    _write_new(output, evidence)
    return 2


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
        _require(
            value[index]["argv"]
            == ["uv", "venv", "--no-project", "--python", str(_python(checkout / ".venv")), str(environment)]
        )
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
