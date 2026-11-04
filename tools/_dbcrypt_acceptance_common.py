"""Shared acceptance contracts, byte references and inert record helpers."""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal, Protocol

Phase = Literal["provision", "reopen", "verify"]

Mode = Literal["source", "wheel"]

WINDOWS_RELEASE_SELECTION = (
    "not checkedtest and not injected_io and not every_creation and not inherited_dacl_race "
    "and not recovery_exclusive_lock and not shm_shared_lock"
)

INSTANCES = frozenset({"i-095cbe655c196c749", "i-00f4db5c3a204906b"})

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


_PROBE = r"""
import importlib.metadata as metadata
import hashlib, json, os, platform, sys
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
entrypoint = Path(sys.prefix) / ('Scripts/hermes-mordred.exe' if os.name == 'nt' else 'bin/hermes-mordred')
entries = tuple(metadata.distribution('hermes-mordred').entry_points.select(
    group='console_scripts', name='hermes-mordred'))
assert len(entries) == 1 and entries[0].value == 'mordred_hermes.wizard.cli:main'
print(json.dumps({
    'maintenance_entrypoint': {'path': str(entrypoint), 'sha256': hashlib.sha256(entrypoint.read_bytes()).hexdigest()},
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

_PTH_TEST_INPUTS = (
    "packaging/pth/mordred_hermes_config_decrypt.pth",
    "packaging/pth/mordred_hermes_runtime.pth",
)

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

CONTROL_MARGIN = 60.0

PLATFORM_INSTANCE = {"linux": "i-095cbe655c196c749", "win32": "i-00f4db5c3a204906b"}

WINDOWS_PLATFORM_NA = {
    "test_dbcrypt_capability.py::test_automatic_native_startup_installs_real_guarded_shim[linux]": (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    "test_dbcrypt_capability.py::test_automatic_native_startup_installs_real_guarded_shim[win32]": (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    (
        "test_dbcrypt_capability.py::"
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody[driver]"
    ): (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    (
        "test_dbcrypt_capability.py::"
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody[asset]"
    ): (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
    (
        "test_dbcrypt_capability.py::"
        "test_automatic_windows_startup_refuses_unavailable_prerequisite_before_custody[qualification]"
    ): (
        "uses the POSIX authority fixture; Windows native proof is explicit",
        "windows_posix_authority_fixture",
    ),
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

REQUIRED_COMPONENTS = ("sessiondb", "activity", "telegram", "mail", "credentials", "source_memory", "scoped_siblings")

REQUIRED_PROFILES = ("root", "work", "other")

NATIVE_REFUSAL_REASONS = {
    "integrated_native_memory_and_none_conversion_contract_required",
    "native_platform_required",
    "explicit_native_collector_optin_required",
    "canonical_synthetic_native_root_required",
    "isolated_native_home_required_before_import",
    "ordinary_windows_token_required",
    "native_cng_provider_unavailable",
    "native_cng_implementation_unobservable",
    "hardware_only_cng_provider_required",
    "real_ec2_tpm_device_required",
    "amazon_tpm_manufacturer_unobservable",
    "native_emulator_and_ambient_keys_forbidden",
    "explicit_production_native_helper_required",
    "candidate_driver_or_inventory_unavailable",
    "owned_checked_distribution_required",
    "native_provision_requires_new_root_no_repair",
    "native_memory_enable_failed_retain_root",
    "requested_presence_must_refuse_before_writes",
    "damaging_operations_require_separate_negative_root",
    "unsupported_fixed_native_operation",
}

NATIVE_FAILURE_STAGES = {
    "operation",
    "root_validation",
    "native_facts",
    "candidate_eligibility",
    "provision",
    "home_setup",
    "memory_authority_check",
    "memory_enable",
    "memory_seed",
    "memory_read",
    "database_encrypt",
    "collect",
    "backup_restore",
    "negative",
    "writer",
}

NATIVE_FAILURE_CATEGORIES = {"assertion", "timeout", "os_error", "value", "type", "runtime", "other"}

NATIVE_TEST_FAILURE_MODULES = frozenset(
    "tests/" + relative
    for relative in (
        *AFFECTED_MODULES,
        *ADDITIONAL_MODULES,
        "integration/test_dbcrypt_native.py",
        "integration/test_dbcrypt_collectors.py",
        "integration/test_linux_memory_orchestration_tpm.py",
        "integration/test_linux_telegram_tpm.py",
        "integration/test_dbcrypt_windows_vfs.py",
        "test_windows_custody_live.py",
        "test_windows_memory_live.py",
        "test_windows_telegram_live.py",
        "integration/test_dbcrypt_activity.py",
        "integration/test_mail_native_custody.py",
        "test_wizard_windows_memory_live.py",
        "test_wizard_windows_telegram_live.py",
    )
)

NATIVE_TEST_FAILURE_HASH_SCHEME = "sha256_canonical_unparameterized_node_base_utf8"


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _python(environment: Path, platform: str = sys.platform) -> Path:
    return environment / ("Scripts/python.exe" if platform == "win32" else "bin/python")


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


def _input_root_layout(output: Path) -> None:
    # Only these top-level locations exist in an acceptance bundle. Mutable
    # evidence belongs under outputs/, never beside copied collection inputs.
    trees = {"tests", "tools", "packaging", "extracted-sdist", "artifacts", "build-env", "wheel-env"}
    for path in output.iterdir():
        if path.name == "manifest.json":
            _input_file(path)
        elif path.name == "__pycache__":
            _bytecode(path)
        else:
            _require(path.name in trees | {".pytest_cache", "outputs"} and stat.S_ISDIR(path.lstat().st_mode))
    _require(all(stat.S_ISDIR((output / name).lstat().st_mode) for name in trees))


def _private_evidence_file(path: Path) -> Path:
    _input_file(path)
    info = path.stat()
    _require(os.name == "nt" or (info.st_uid == os.getuid() and info.st_mode & 0o077 == 0))
    return path


def _test_identity(nodeid: str) -> str:
    text = nodeid.replace("\\", "/")
    text = text.split("/tests/", 1)[-1].removeprefix("tests/")
    return text.split("[", 1)[0]


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


def _guest_path(value: str, platform: str) -> PurePosixPath | PureWindowsPath:
    path = PureWindowsPath(value) if platform == "win32" else PurePosixPath(value)
    _require(path.is_absolute() and ".." not in path.parts)
    return path


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


def native_operation_bootstrap(kind: str, operation: str) -> str:
    _require(
        kind in {"candidate", "production"}
        and operation
        in {
            "preflight",
            "provision",
            "seed",
            "read",
            "negative",
            "backup_restore",
            "backup_restore_failure",
            "writer_a",
            "writer_b",
        }
    )
    if operation == "preflight":
        return "passive_prerequisite"
    if kind == "candidate":
        return "explicit_candidate"
    return "explicit_native_maintenance" if operation == "provision" else "automatic_production"


def native_failure_descriptor(value: Any) -> bool:
    """A closed, content-free location; never an acceptance or authorization."""
    if not isinstance(value, dict) or set(value) != {"stage", "home", "child_returncode", "exception_category"}:
        return False
    code = value["child_returncode"]
    return (
        isinstance(value["stage"], str)
        and value["stage"] in NATIVE_FAILURE_STAGES
        and isinstance(value["home"], str)
        and value["home"] in {"root", "work", "other", "unknown"}
        and isinstance(value["exception_category"], str)
        and value["exception_category"] in NATIVE_FAILURE_CATEGORIES
        and (code is None or (type(code) is int and -(2**31) <= code < 2**32))
    )


def native_refusal_payload(stdout: str, operation: str, returncode: int) -> dict[str, Any] | None:
    """Retain finite refusals and optional closed diagnostics, never arbitrary output."""
    if returncode != 2 or len(stdout.encode("utf-8")) > 4096:
        return None
    try:
        value = json.loads(stdout)
        if (
            isinstance(value, dict)
            and set(value)
            in (
                {"schema_version", "operation", "status", "reason"},
                {"schema_version", "operation", "status", "reason", "failure"},
            )
            and ("failure" not in value or native_failure_descriptor(value["failure"]))
            and type(value["schema_version"]) is int
            and value["schema_version"] == RUN_SCHEMA
            and value["operation"] == operation
            and value["status"] == "refused"
            and isinstance(value["reason"], str)
            and value["reason"] in NATIVE_REFUSAL_REASONS | {"native_operation_failed"}
        ):
            return value
    except (ValueError, TypeError):
        pass
    return None


def native_test_failure_descriptor(value: Any) -> bool:
    """Validate only diagnostic data; this never admits a failed suite."""
    if type(value) is not dict or set(value) != {"status", "report_bytes", "report_sha256", "details"}:
        return False
    status, size, digest, details = (value[key] for key in ("status", "report_bytes", "report_sha256", "details"))
    if status in ("missing", "unavailable"):
        return size is None and digest is None and details is None
    if type(size) is not int or not 0 <= size < 2**63:
        return False
    if status == "oversized":
        return size > 8 * 1024 * 1024 and digest is None and details is None
    if size > 8 * 1024 * 1024 or not _hex(digest, 64):
        return False
    if status == "invalid":
        return details is None
    return status == "available" and _native_test_failure_details(details)


def _native_test_failure_details(details: Any) -> bool:
    if type(details) is not dict or set(details) != {
        "hash_scheme",
        "exitstatus",
        "finding_count",
        "truncated",
        "findings",
    }:
        return False
    code, count, findings = (details[key] for key in ("exitstatus", "finding_count", "findings"))
    if (
        details["hash_scheme"] != NATIVE_TEST_FAILURE_HASH_SCHEME
        or not (code is None or (type(code) is int and -(2**31) <= code < 2**32))
        or type(count) is not int
        or not 0 <= count <= 100000
        or type(details["truncated"]) is not bool
        or details["truncated"] != (count > 16)
        or type(findings) is not list
        or len(findings) != min(count, 16)
    ):
        return False
    for row in findings:
        if type(row) is not dict or set(row) != {"module", "node_base_sha256", "node_suffix_sha256", "outcome", "when"}:
            return False
        if row["outcome"] not in ("failed", "skipped") or row["when"] not in (
            "setup",
            "call",
            "teardown",
            "collection",
            "unknown",
        ):
            return False
        if row["node_suffix_sha256"] is not None and not _hex(row["node_suffix_sha256"], 64):
            return False
        module = row["module"]
        if type(module) is not str or not (
            (module == "unrecognized_nodeid" and row["node_base_sha256"] is None)
            or (module in NATIVE_TEST_FAILURE_MODULES and _hex(row["node_base_sha256"], 64))
        ):
            return False
    return True


def _project_native_test_failure(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError("report_shape")
    reports, collection = value.get("reports", []), value.get("collection_errors", [])
    if type(reports) is not list or type(collection) is not list or len(reports) + len(collection) > 100000:
        raise ValueError("report_bound")
    ordered = (
        [(row, False) for row in reports if type(row) is dict and row.get("outcome") == "failed"]
        + [(row, True) for row in collection if type(row) is dict and row.get("outcome") in ("failed", "skipped")]
        + [(row, False) for row in reports if type(row) is dict and row.get("outcome") == "skipped"]
    )
    code = value.get("exitstatus")
    result: dict[str, Any] = {
        "hash_scheme": NATIVE_TEST_FAILURE_HASH_SCHEME,
        "exitstatus": code if type(code) is int and -(2**31) <= code < 2**32 else None,
        "finding_count": len(ordered),
        "truncated": len(ordered) > 16,
        "findings": [],
    }
    for row, is_collection in ordered[:16]:
        when = row.get("when")
        item = {
            "outcome": row["outcome"],
            "when": "collection" if is_collection else when if when in ("setup", "call", "teardown") else "unknown",
            "module": "unrecognized_nodeid",
            "node_base_sha256": None,
            "node_suffix_sha256": None,
        }
        node = row.get("nodeid")
        # External files collected with an sdist -c can have ::test_name IDs.
        # Strip parameters before any identity operation, independently of
        # whether the report supplies a recognizable module component.
        base = node.split("[", 1)[0] if type(node) is str else None
        if base is not None and len(base) <= 4096:
            module, separator, rest = base.partition("::")
            if rest:
                item["node_suffix_sha256"] = hashlib.sha256(rest.encode()).hexdigest()
            module = module.replace("\\", "/")
            matches = [
                known
                for known in NATIVE_TEST_FAILURE_MODULES
                if module in (known, known.removeprefix("tests/")) or module.endswith("/" + known)
            ]
            if len(matches) == 1:
                item["module"] = matches[0]
                base = matches[0] + ("::" + rest if separator else "")
                item["node_base_sha256"] = hashlib.sha256(base.encode()).hexdigest()
        result["findings"].append(item)
    return result


def native_test_failure_summary(report: Path) -> dict[str, Any]:
    """Read one known failed-suite report, with no raw field or exception export."""
    unavailable = {"status": "unavailable", "report_bytes": None, "report_sha256": None, "details": None}
    try:
        parent, observed = report.parent.lstat(), report.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or any(getattr(info, "st_file_attributes", 0) & 0x400 for info in (parent, observed))
            or (
                os.name != "nt"
                and (
                    parent.st_uid != os.getuid()
                    or observed.st_uid != os.getuid()
                    or stat.S_IMODE(parent.st_mode) != 0o700
                    or stat.S_IMODE(observed.st_mode) != 0o600
                )
            )
        ):
            return unavailable
        if observed.st_size > 8 * 1024 * 1024:
            return (
                {**unavailable, "status": "oversized", "report_bytes": observed.st_size}
                if observed.st_size < 2**63
                else unavailable
            )
        fd = os.open(report, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            before = os.fstat(fd)
            if (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ):
                return unavailable
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(8 * 1024 * 1024 + 1)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or len(raw) != before.st_size:
                return unavailable
        finally:
            os.close(fd)
    except FileNotFoundError:
        return {**unavailable, "status": "missing"}
    except (OSError, ValueError):
        return unavailable
    result = {
        "status": "invalid",
        "report_bytes": len(raw),
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "details": None,
    }
    try:
        details = _project_native_test_failure(json.loads(raw))
    except (ValueError, TypeError, RecursionError):
        return result
    return {**result, "status": "available", "details": details}


class _CallbackAbsolute(Protocol):
    def __call__(self, /, value: Any) -> Path: ...


class _CallbackArtifactRef(Protocol):
    def __call__(self, /, directory: Path, reference: Any) -> Path: ...


class _CallbackAssembleWindowsQualification(Protocol):
    def __call__(
        self, /, *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path
    ) -> Path: ...


class _CallbackBundleArtifact(Protocol):
    def __call__(self, /, directory: Path, pattern: str) -> Path: ...


class _CallbackBundleBuild(Protocol):
    def __call__(
        self, /, checkout: Path, output: Path, commands: list[dict[str, Any]], home: Path
    ) -> dict[str, Any]: ...


class _CallbackBundleHashes(Protocol):
    def __call__(self, /, output: Path) -> dict[str, str]: ...


class _CallbackCollectorChild(Protocol):
    def __call__(self, /, context: dict[str, Any], root: Path, operation: str, directory: Path) -> dict[str, Any]: ...


class _CallbackCopyBuildReceipts(Protocol):
    def __call__(self, /, source: Path, target: Path) -> None: ...


class _CallbackCopyInputs(Protocol):
    def __call__(self, /, checkout: Path, output: Path) -> None: ...


class _CallbackCopyReferenced(Protocol):
    def __call__(self, /, source: Path, files: set[Path], target: Path) -> None: ...


class _CallbackDiagnosticFiles(Protocol):
    def __call__(self, /, directory: Path, manifest: dict[str, Any]) -> set[Path]: ...


class _CallbackExecuteNativePhase(Protocol):
    def __call__(self, /, context: dict[str, Any], *, phase: Phase, directory: Path) -> dict[str, Any]: ...


class _CallbackExportBundleEvidence(Protocol):
    def __call__(self, /, context: dict[str, Any], directory: Path) -> dict[str, str]: ...


class _CallbackExportWindowsQualification(Protocol):
    def __call__(self, /, context: dict[str, Any], directory: Path) -> dict[str, str] | None: ...


class _CallbackFixtureDescriptor(Protocol):
    def __call__(self, /, path: Path) -> tuple[dict[str, Any], set[Path]]: ...


class _CallbackGit(Protocol):
    def __call__(self, /, checkout: Path, *args: str) -> str: ...


class _CallbackHex(Protocol):
    def __call__(self, /, value: Any, length: int) -> bool: ...


class _CallbackInputFile(Protocol):
    def __call__(self, /, path: Path) -> Path: ...


class _CallbackInputRootLayout(Protocol):
    def __call__(self, /, output: Path) -> None: ...


class _CallbackLocalBundleProof(Protocol):
    def __call__(self, /, path: Path, manifest: dict[str, Any]) -> dict[str, Any]: ...


class _CallbackNativeDriver(Protocol):
    def __call__(self, /, context: dict[str, Any], directory: Path, *, passive: bool = False) -> Path: ...


class _CallbackNativeEnvironment(Protocol):
    def __call__(self, /, context: dict[str, Any], root: Path) -> dict[str, str]: ...


class _CallbackNativeObservationInputs(Protocol):
    def __call__(self, /, phase: Phase) -> tuple[str | None, str]: ...


class _CallbackNativePhaseCoverage(Protocol):
    def __call__(self, /, phase: dict[str, Any], directory: Path) -> None: ...


class _CallbackNativeProcess(Protocol):
    def __call__(
        self, /, context: dict[str, Any], argv: list[str], environment: dict[str, str], *, timeout: int, name: str
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]: ...


class _CallbackNativePython(Protocol):
    def __call__(self, /, context: dict[str, Any]) -> Path: ...


class _CallbackNativeReopenPrior(Protocol):
    def __call__(self, /, context: dict[str, Any], directory: Path) -> dict[str, Any]: ...


class _CallbackNativeSuite(Protocol):
    def __call__(
        self,
        /,
        context: dict[str, Any],
        row: dict[str, Any],
        directory: Path,
        baseline: Path,
        *,
        native_facts: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...


class _CallbackNativeWindowsQualification(Protocol):
    def __call__(self, /, directory: Path, *, checkout: Path, kind: str) -> dict[str, Any]: ...


class _CallbackNativeWindowsVfsRows(Protocol):
    def __call__(self, /, rows: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]: ...


class _CallbackPhaseQualification(Protocol):
    def __call__(self, /, phase: dict[str, Any], directory: Path) -> dict[str, Any] | None: ...


class _CallbackPrivateEvidenceFile(Protocol):
    def __call__(self, /, path: Path) -> Path: ...


class _CallbackPython(Protocol):
    def __call__(self, /, environment: Path, platform: str = sys.platform) -> Path: ...


class _CallbackQualificationFixture(Protocol):
    def __call__(self, /, directory: Path, manifest: dict[str, Any]) -> dict[str, Any]: ...


class _CallbackQualificationInputs(Protocol):
    def __call__(self, /, directory: Path, manifest: dict[str, Any]) -> set[Path]: ...


class _CallbackQualifiedVfsReference(Protocol):
    def __call__(self, /, qualified: dict[str, Any], mode: str) -> dict[str, Any]: ...


class _CallbackRecordNativeTestFailure(Protocol):
    def __call__(self, /, record: dict[str, Any], report: Path, directory: Path) -> None: ...


class _CallbackRequire(Protocol):
    def __call__(self, /, condition: bool) -> None: ...


class _CallbackRequiredQualificationHeaders(Protocol):
    def __call__(self, /, checkout: Path) -> dict[str, str]: ...


class _CallbackRootIdentity(Protocol):
    def __call__(self, /, root: Path) -> dict[str, Any]: ...


class _CallbackRunBuild(Protocol):
    def __call__(
        self, /, argv: list[str], *, cwd: Path, environment: dict[str, str], log: list[dict[str, Any]]
    ) -> str: ...


class _CallbackSitePackages(Protocol):
    def __call__(self, /, output: Path) -> Path: ...


class _CallbackSuites(Protocol):
    def __call__(self, /, platform: str) -> list[tuple[str, tuple[str, ...], dict[str, str], bool]]: ...


class _CallbackTreeInputs(Protocol):
    def __call__(self, /, directory: Path) -> list[Path]: ...


class _CallbackValidatePackagedResult(Protocol):
    def __call__(
        self,
        /,
        directory: Path,
        result: dict[str, Any],
        *,
        mode: str,
        bundle: dict[str, Any],
        proof: dict[str, Any],
        proof_directory: Path,
        diagnostic: dict[str, Any],
        fixtures: dict[str, Any],
    ) -> dict[str, Any]: ...


class _CallbackValidateQualificationPayload(Protocol):
    def __call__(self, /, directory: Path, manifest: dict[str, Any], *, checkout: Path) -> dict[str, Any]: ...


class _CallbackWriteNew(Protocol):
    def __call__(self, /, path: Path, value: dict[str, Any]) -> None: ...


class _CallbackAcceptanceCommands(Protocol):
    def __call__(self, /, *, checkout: Path, bundle: Path, platform: str) -> list[dict[str, Any]]: ...


class _CallbackExtractSdist(Protocol):
    def __call__(self, /, archive: Path, destination: Path) -> Path: ...


class _CallbackLoadStopReceipt(Protocol):
    def __call__(self, /, path: Path) -> dict[str, Any]: ...


class _CallbackNativeAcceptanceCommands(Protocol):
    def __call__(self, /, *, checkout: Path, bundle: Path, platform: str, kind: str) -> list[dict[str, Any]]: ...


class _CallbackNativeFixturePaths(Protocol):
    def __call__(self, /, root: Path, mode: str) -> dict[str, Path]: ...


class _CallbackNativePhaseInputs(Protocol):
    def __call__(self, /, root: Path, phase: Phase) -> dict[str, Any]: ...


class _CallbackNativeRefusalPayload(Protocol):
    def __call__(self, /, stdout: str, operation: str, returncode: int) -> dict[str, Any] | None: ...


class _CallbackNativeTestFailureDescriptor(Protocol):
    def __call__(self, /, value: Any) -> bool: ...


class _CallbackNativeTestFailureSummary(Protocol):
    def __call__(self, /, report: Path) -> dict[str, Any]: ...


class _CallbackProbeEnvironment(Protocol):
    def __call__(self, /, home: Path) -> dict[str, str]: ...


class _CallbackProbeInterpreter(Protocol):
    def __call__(self, /, interpreter: Path, *, cwd: Path) -> dict[str, Any]: ...


class _CallbackRequireNativeSourceCheckout(Protocol):
    def __call__(self, /, context: dict[str, Any]) -> None: ...


class _CallbackRequireProductionQualification(Protocol):
    def __call__(self, /, qualified: dict[str, Any]) -> None: ...


class _CallbackSha256File(Protocol):
    def __call__(self, /, path: Path) -> str: ...


class _CallbackValidateBundle(Protocol):
    def __call__(self, /, root: Path) -> dict[str, Any]: ...


class _CallbackValidateControlAction(Protocol):
    def __call__(self, /, path: Path, *, platform: str, mode: str, observation: str) -> dict[str, Any]: ...


class _CallbackValidateImportProvenance(Protocol):
    def __call__(self, /, path: Path, *, checkout: Path, environment: Path, mode: Mode) -> None: ...


class _CallbackValidateNativeTestReport(Protocol):
    def __call__(self, /, value: Any, *, platform: str = "", suite: str = "") -> dict[str, Any]: ...


class _CallbackValidateReopenContinuity(Protocol):
    def __call__(self, /, before: dict[str, Any], after: dict[str, Any], observation: str) -> None: ...


class _CallbackValidateWindowsDiagnostic(Protocol):
    def __call__(self, /, directory: Path, *, checkout: Path) -> dict[str, Any]: ...


class _CallbackValidateWindowsQualification(Protocol):
    def __call__(self, /, directory: Path, *, checkout: Path) -> dict[str, Any]: ...


class _CallbackValidateWithdrawableHelper(Protocol):
    def __call__(self, /, manifest: Path, *, production: Path, parent: Path) -> dict[str, Any]: ...


class _CallbackVerifyNativeSpool(Protocol):
    def __call__(self, /, root: Path) -> dict[str, Any]: ...


class _CallbackWindowsPackageCommands(Protocol):
    def __call__(
        self,
        /,
        *,
        checkout: Path | PureWindowsPath,
        bundle: Path | PureWindowsPath,
        mode: str,
        basetemp: Path | PureWindowsPath,
        configuration: Path | PureWindowsPath,
    ) -> list[dict[str, Any]]: ...


class _CallbackWindowsVfsRequiredNodes(Protocol):
    def __call__(self, /, checkout: Path, *, release: bool) -> list[str]: ...


class SystemAPI(Protocol):
    @property
    def platform(self) -> str: ...

    @property
    def executable(self) -> str: ...


@dataclass(frozen=True)
class EvidenceAPI:
    _bundle_hashes: _CallbackBundleHashes
    _phase_qualification: _CallbackPhaseQualification
    _qualified_vfs_reference: _CallbackQualifiedVfsReference
    acceptance_commands: _CallbackAcceptanceCommands
    native_acceptance_commands: _CallbackNativeAcceptanceCommands
    windows_vfs_required_nodes: _CallbackWindowsVfsRequiredNodes


@dataclass(frozen=True)
class QualificationAPI:
    _required_qualification_headers: _CallbackRequiredQualificationHeaders


@dataclass(frozen=True)
class ExecutionAPI:
    _absolute: _CallbackAbsolute
    _bundle_artifact: _CallbackBundleArtifact
    _bundle_build: _CallbackBundleBuild
    _bundle_hashes: _CallbackBundleHashes
    _collector_child: _CallbackCollectorChild
    _copy_build_receipts: _CallbackCopyBuildReceipts
    _copy_inputs: _CallbackCopyInputs
    _execute_native_phase: _CallbackExecuteNativePhase
    _export_bundle_evidence: _CallbackExportBundleEvidence
    _export_windows_qualification: _CallbackExportWindowsQualification
    _git: _CallbackGit
    _hex: _CallbackHex
    _input_file: _CallbackInputFile
    _input_root_layout: _CallbackInputRootLayout
    _native_driver: _CallbackNativeDriver
    _native_environment: _CallbackNativeEnvironment
    _native_observation_inputs: _CallbackNativeObservationInputs
    _native_phase_coverage: _CallbackNativePhaseCoverage
    _native_process: _CallbackNativeProcess
    _native_python: _CallbackNativePython
    _native_reopen_prior: _CallbackNativeReopenPrior
    _native_suite: _CallbackNativeSuite
    _native_windows_qualification: _CallbackNativeWindowsQualification
    _native_windows_vfs_rows: _CallbackNativeWindowsVfsRows
    _private_evidence_file: _CallbackPrivateEvidenceFile
    _python: _CallbackPython
    _qualification_inputs: _CallbackQualificationInputs
    _qualified_vfs_reference: _CallbackQualifiedVfsReference
    _record_native_test_failure: _CallbackRecordNativeTestFailure
    _require: _CallbackRequire
    _root_identity: _CallbackRootIdentity
    _run_build: _CallbackRunBuild
    _site_packages: _CallbackSitePackages
    _suites: _CallbackSuites
    _tree_inputs: _CallbackTreeInputs
    _write_new: _CallbackWriteNew
    acceptance_commands: _CallbackAcceptanceCommands
    extract_sdist: _CallbackExtractSdist
    load_stop_receipt: _CallbackLoadStopReceipt
    native_acceptance_commands: _CallbackNativeAcceptanceCommands
    native_fixture_paths: _CallbackNativeFixturePaths
    native_phase_inputs: _CallbackNativePhaseInputs
    native_refusal_payload: _CallbackNativeRefusalPayload
    native_test_failure_descriptor: _CallbackNativeTestFailureDescriptor
    native_test_failure_summary: _CallbackNativeTestFailureSummary
    probe_environment: _CallbackProbeEnvironment
    probe_interpreter: _CallbackProbeInterpreter
    require_native_source_checkout: _CallbackRequireNativeSourceCheckout
    require_production_qualification: _CallbackRequireProductionQualification
    sha256_file: _CallbackSha256File
    validate_bundle: _CallbackValidateBundle
    validate_control_action: _CallbackValidateControlAction
    validate_import_provenance: _CallbackValidateImportProvenance
    validate_native_test_report: _CallbackValidateNativeTestReport
    validate_reopen_continuity: _CallbackValidateReopenContinuity
    validate_windows_qualification: _CallbackValidateWindowsQualification
    validate_withdrawable_helper: _CallbackValidateWithdrawableHelper
    verify_native_spool: _CallbackVerifyNativeSpool
    sys: SystemAPI


@dataclass(frozen=True)
class WindowsAPI:
    _artifact_ref: _CallbackArtifactRef
    _assemble_windows_qualification: _CallbackAssembleWindowsQualification
    _copy_referenced: _CallbackCopyReferenced
    _diagnostic_files: _CallbackDiagnosticFiles
    _export_bundle_evidence: _CallbackExportBundleEvidence
    _fixture_descriptor: _CallbackFixtureDescriptor
    _input_file: _CallbackInputFile
    _local_bundle_proof: _CallbackLocalBundleProof
    _qualification_fixture: _CallbackQualificationFixture
    _require: _CallbackRequire
    _validate_packaged_result: _CallbackValidatePackagedResult
    _validate_qualification_payload: _CallbackValidateQualificationPayload
    _write_new: _CallbackWriteNew
    probe_environment: _CallbackProbeEnvironment
    require_native_source_checkout: _CallbackRequireNativeSourceCheckout
    sha256_file: _CallbackSha256File
    validate_bundle: _CallbackValidateBundle
    validate_windows_diagnostic: _CallbackValidateWindowsDiagnostic
    windows_package_commands: _CallbackWindowsPackageCommands
    sys: SystemAPI
