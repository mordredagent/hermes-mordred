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
import os
import subprocess
import sys
import tarfile
import zipfile
from importlib import import_module
from importlib.machinery import ModuleSpec
from importlib.util import module_from_spec
from pathlib import Path
from typing import TYPE_CHECKING, Any


# Separate physical tool copies must never share cached implementations. A
# canonical-path package name gives each copy ordinary relative sibling imports
# while keeping exception identity stable across repeated spec/runpy loads.
def _load_tool_package(directory: Path) -> str:
    name = "_mordred_dbcrypt_acceptance_" + hashlib.sha256(os.fsencode(directory)).hexdigest()
    cached = sys.modules.get(name)
    if cached is not None:
        if cached.__spec__ is None or cached.__spec__.submodule_search_locations != [str(directory)]:
            raise ImportError("acceptance_tool_package_conflict")
        return name
    specification = ModuleSpec(name, loader=None, is_package=True)
    specification.submodule_search_locations = [str(directory)]
    sys.modules.setdefault(name, module_from_spec(specification))
    return name


if TYPE_CHECKING:
    import _dbcrypt_acceptance_common as _common
    import _dbcrypt_acceptance_evidence as _evidence
    import _dbcrypt_acceptance_execution as _execution
    import _dbcrypt_acceptance_windows as _windows
else:
    _package = _load_tool_package(Path(__file__).resolve().parent)
    _common = import_module("._dbcrypt_acceptance_common", package=_package)
    _evidence = import_module("._dbcrypt_acceptance_evidence", package=_package)
    _execution = import_module("._dbcrypt_acceptance_execution", package=_package)
    _windows = import_module("._dbcrypt_acceptance_windows", package=_package)


# Explicit compatibility exports keep their owning module visible and avoid
# copying or forwarding a module namespace.
_PROBE = _common._PROBE
_PTH_TEST_INPUTS = _common._PTH_TEST_INPUTS
ADDITIONAL_MODULES = _common.ADDITIONAL_MODULES
AFFECTED_MODULES = _common.AFFECTED_MODULES
CONTROL_MARGIN = _common.CONTROL_MARGIN
INSTANCES = _common.INSTANCES
NATIVE_FAILURE_CATEGORIES = _common.NATIVE_FAILURE_CATEGORIES
NATIVE_FAILURE_STAGES = _common.NATIVE_FAILURE_STAGES
NATIVE_REFUSAL_REASONS = _common.NATIVE_REFUSAL_REASONS
NATIVE_TEST_FAILURE_HASH_SCHEME = _common.NATIVE_TEST_FAILURE_HASH_SCHEME
NATIVE_TEST_FAILURE_MODULES = _common.NATIVE_TEST_FAILURE_MODULES
PLATFORM_INSTANCE = _common.PLATFORM_INSTANCE
REQUIRED_COMPONENTS = _common.REQUIRED_COMPONENTS
REQUIRED_PROFILES = _common.REQUIRED_PROFILES
RUN_SCHEMA = _common.RUN_SCHEMA
WINDOWS_PLATFORM_NA = _common.WINDOWS_PLATFORM_NA
WINDOWS_RELEASE_SELECTION = _common.WINDOWS_RELEASE_SELECTION
WINDOWS_TELEGRAM_MIGRATION_REASON = _common.WINDOWS_TELEGRAM_MIGRATION_REASON
AcceptanceRefused = _common.AcceptanceRefused
EvidenceAPI = _common.EvidenceAPI
ExecutionAPI = _common.ExecutionAPI
Mode = _common.Mode
Phase = _common.Phase
QualificationAPI = _common.QualificationAPI
SystemAPI = _common.SystemAPI
WindowsAPI = _common.WindowsAPI
_absolute = _common._absolute
_artifact_ref = _common._artifact_ref
_bytecode = _common._bytecode
_evidence_ref = _common._evidence_ref
_guest_path = _common._guest_path
_hex = _common._hex
_input_file = _common._input_file
_input_root_layout = _common._input_root_layout
_module_functions = _common._module_functions
_native_test_failure_details = _common._native_test_failure_details
_normalized_node = _common._normalized_node
_object = _common._object
_private_evidence_file = _common._private_evidence_file
_project_native_test_failure = _common._project_native_test_failure
_python = _common._python
_relative = _common._relative
_require = _common._require
_test_identity = _common._test_identity
_text = _common._text
_timestamp = _common._timestamp
_tree_inputs = _common._tree_inputs
native_failure_descriptor = _common.native_failure_descriptor
native_operation_bootstrap = _common.native_operation_bootstrap
native_refusal_payload = _common.native_refusal_payload
native_test_failure_descriptor = _common.native_test_failure_descriptor
native_test_failure_summary = _common.native_test_failure_summary
sha256_file = _common.sha256_file
_cloud_observation = _evidence._cloud_observation
_collector_arguments = _evidence._collector_arguments
_control_reboot = _evidence._control_reboot
_control_start = _evidence._control_start
_controller_snapshot = _evidence._controller_snapshot
_crash_nodes = _evidence._crash_nodes
_exported_probe = _evidence._exported_probe
_native_node_outcome = _evidence._native_node_outcome
_native_operation_evidence = _evidence._native_operation_evidence
_native_payload = _evidence._native_payload
_native_provision_coverage = _evidence._native_provision_coverage
_offline_build_records = _evidence._offline_build_records
_ordered_control_cycles = _evidence._ordered_control_cycles
_owned_copy_directories = _evidence._owned_copy_directories
_phase_bundle = _evidence._phase_bundle
_provision_fixture_closure = _evidence._provision_fixture_closure
_public_read = _evidence._public_read
_same_controller_run = _evidence._same_controller_run
_settled_control_cycle = _evidence._settled_control_cycle
_validate_build_records = _evidence._validate_build_records
_validate_exported_import = _evidence._validate_exported_import
_validate_probe = _evidence._validate_probe
_verify_mode_sequences = _evidence._verify_mode_sequences
_verify_native_stops = _evidence._verify_native_stops
load_stop_receipt = _evidence.load_stop_receipt
platform_na_reason = _evidence.platform_na_reason
validate_bundle_evidence = _evidence.validate_bundle_evidence
validate_control_action = _evidence.validate_control_action
validate_control_cycles = _evidence.validate_control_cycles
validate_helper_withdrawal = _evidence.validate_helper_withdrawal
validate_import_provenance = _evidence.validate_import_provenance
validate_native_test_report = _evidence.validate_native_test_report
validate_phase_control_binding = _evidence.validate_phase_control_binding
validate_reopen_continuity = _evidence.validate_reopen_continuity
validate_withdrawable_helper = _evidence.validate_withdrawable_helper
_build_receipt_files = _windows._build_receipt_files
_copy_build_receipts = _windows._copy_build_receipts
_copy_referenced = _windows._copy_referenced
_diagnostic_files = _windows._diagnostic_files
_fixture_descriptor = _windows._fixture_descriptor
_local_bundle_proof = _windows._local_bundle_proof
_native_windows_vfs_rows = _windows._native_windows_vfs_rows
_package_build_inputs = _windows._package_build_inputs
_qualification_argv = _windows._qualification_argv
_qualification_binaries = _windows._qualification_binaries
_qualification_fixture = _windows._qualification_fixture
_qualification_inputs = _windows._qualification_inputs
_qualification_row = _windows._qualification_row
_qualified_package_artifacts = _windows._qualified_package_artifacts
_qualified_vfs_reference = _windows._qualified_vfs_reference
_required_qualification_headers = _windows._required_qualification_headers
_validate_build_receipt = _windows._validate_build_receipt
_validate_package_eligibility = _windows._validate_package_eligibility
_validate_packaged_result = _windows._validate_packaged_result
_validate_windows_eligibility = _windows._validate_windows_eligibility
canonical_windows_owner_sid = _windows.canonical_windows_owner_sid
matching_build_receipts = _windows.matching_build_receipts
require_production_qualification = _windows.require_production_qualification
validate_package_observation = _windows.validate_package_observation
windows_activation_declaration = _windows.windows_activation_declaration
windows_package_commands = _windows.windows_package_commands
windows_vfs_required_nodes = _windows.windows_vfs_required_nodes


def _evidence_dependencies() -> EvidenceAPI:
    return EvidenceAPI(
        _bundle_hashes=_bundle_hashes,
        _phase_qualification=_phase_qualification,
        _qualified_vfs_reference=_qualified_vfs_reference,
        acceptance_commands=acceptance_commands,
        native_acceptance_commands=native_acceptance_commands,
        windows_vfs_required_nodes=windows_vfs_required_nodes,
    )


def _qualification_dependencies() -> QualificationAPI:
    return QualificationAPI(
        _required_qualification_headers=_required_qualification_headers,
    )


def _execution_dependencies() -> ExecutionAPI:
    return ExecutionAPI(
        _absolute=_absolute,
        _bundle_artifact=_bundle_artifact,
        _bundle_build=_bundle_build,
        _bundle_hashes=_bundle_hashes,
        _collector_child=_collector_child,
        _copy_build_receipts=_copy_build_receipts,
        _copy_inputs=_copy_inputs,
        _execute_native_phase=_execute_native_phase,
        _export_bundle_evidence=_export_bundle_evidence,
        _export_windows_qualification=_export_windows_qualification,
        _git=_git,
        _hex=_hex,
        _input_file=_input_file,
        _input_root_layout=_input_root_layout,
        _native_driver=_native_driver,
        _native_environment=_native_environment,
        _native_observation_inputs=_native_observation_inputs,
        _native_phase_coverage=_native_phase_coverage,
        _native_process=_native_process,
        _native_python=_native_python,
        _native_reopen_prior=_native_reopen_prior,
        _native_suite=_native_suite,
        _native_windows_qualification=_native_windows_qualification,
        _native_windows_vfs_rows=_native_windows_vfs_rows,
        _private_evidence_file=_private_evidence_file,
        _python=_python,
        _qualification_inputs=_qualification_inputs,
        _qualified_vfs_reference=_qualified_vfs_reference,
        _record_native_test_failure=_record_native_test_failure,
        _require=_require,
        _root_identity=_root_identity,
        _run_build=_run_build,
        _site_packages=_site_packages,
        _suites=_suites,
        _tree_inputs=_tree_inputs,
        _write_new=_write_new,
        acceptance_commands=acceptance_commands,
        extract_sdist=extract_sdist,
        load_stop_receipt=load_stop_receipt,
        native_acceptance_commands=native_acceptance_commands,
        native_fixture_paths=native_fixture_paths,
        native_phase_inputs=native_phase_inputs,
        native_refusal_payload=native_refusal_payload,
        native_test_failure_descriptor=native_test_failure_descriptor,
        native_test_failure_summary=native_test_failure_summary,
        probe_environment=probe_environment,
        probe_interpreter=probe_interpreter,
        require_native_source_checkout=require_native_source_checkout,
        require_production_qualification=require_production_qualification,
        sha256_file=sha256_file,
        validate_bundle=validate_bundle,
        validate_control_action=validate_control_action,
        validate_import_provenance=validate_import_provenance,
        validate_native_test_report=validate_native_test_report,
        validate_reopen_continuity=validate_reopen_continuity,
        validate_windows_qualification=validate_windows_qualification,
        validate_withdrawable_helper=validate_withdrawable_helper,
        verify_native_spool=verify_native_spool,
        sys=sys,
    )


def _windows_dependencies() -> WindowsAPI:
    return WindowsAPI(
        _artifact_ref=_artifact_ref,
        _assemble_windows_qualification=_assemble_windows_qualification,
        _copy_referenced=_copy_referenced,
        _diagnostic_files=_diagnostic_files,
        _export_bundle_evidence=_export_bundle_evidence,
        _fixture_descriptor=_fixture_descriptor,
        _input_file=_input_file,
        _local_bundle_proof=_local_bundle_proof,
        _qualification_fixture=_qualification_fixture,
        _require=_require,
        _validate_packaged_result=_validate_packaged_result,
        _validate_qualification_payload=_validate_qualification_payload,
        _write_new=_write_new,
        probe_environment=probe_environment,
        require_native_source_checkout=require_native_source_checkout,
        sha256_file=sha256_file,
        validate_bundle=validate_bundle,
        validate_windows_diagnostic=validate_windows_diagnostic,
        windows_package_commands=windows_package_commands,
        sys=sys,
    )


def _validate_manifest(value: Any, root: Path) -> dict[str, Any]:
    return _evidence._validate_manifest(value, root, _api=_evidence_dependencies())


def validate_bundle(root: Path) -> dict[str, Any]:
    return _evidence.validate_bundle(root, _api=_evidence_dependencies())


def _planned_rows(phase: dict[str, Any], bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return _evidence._planned_rows(phase, bundle, _api=_evidence_dependencies())


def _selected_nodes(
    phase: dict[str, Any], record: dict[str, Any], plan: dict[str, Any], bundle: dict[str, Any], directory: Path
) -> dict[str, Any]:
    return _evidence._selected_nodes(phase, record, plan, bundle, directory, _api=_evidence_dependencies())


def _native_execution_report(phase: dict[str, Any], directory: Path) -> None:
    _evidence._native_execution_report(phase, directory, _api=_evidence_dependencies())
    return None


def _native_phase_coverage(phase: dict[str, Any], directory: Path) -> None:
    _evidence._native_phase_coverage(phase, directory, _api=_evidence_dependencies())
    return None


def validate_native_phase_evidence(value: Any, *, directory: Path) -> dict[str, Any]:
    return _evidence.validate_native_phase_evidence(value, directory=directory, _api=_evidence_dependencies())


def verify_native_spool(root: Path) -> dict[str, Any]:
    return _evidence.verify_native_spool(root, _api=_evidence_dependencies())


def _qualification_source(directory: Path, manifest: dict[str, Any], checkout: Path) -> dict[str, Any]:
    return _windows._qualification_source(directory, manifest, checkout, _api=_qualification_dependencies())


def _phase_qualification(phase: dict[str, Any], directory: Path) -> dict[str, Any] | None:
    return _windows._phase_qualification(phase, directory, _api=_qualification_dependencies())


def validate_windows_diagnostic(directory: Path, *, checkout: Path) -> dict[str, Any]:
    return _windows.validate_windows_diagnostic(directory, checkout=checkout, _api=_qualification_dependencies())


def _native_windows_qualification(directory: Path, *, checkout: Path, kind: str) -> dict[str, Any]:
    return _windows._native_windows_qualification(
        directory, checkout=checkout, kind=kind, _api=_qualification_dependencies()
    )


def qualify_windows_vfs(*, bundle: Path, mode: str, diagnostic: Path, fixtures: Path, output: Path) -> Path:
    return _windows.qualify_windows_vfs(
        bundle=bundle, mode=mode, diagnostic=diagnostic, fixtures=fixtures, output=output, _api=_windows_dependencies()
    )


def _assemble_windows_qualification(
    *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path
) -> Path:
    return _windows._assemble_windows_qualification(
        bundle=bundle,
        diagnostic=diagnostic,
        source_result=source_result,
        wheel_result=wheel_result,
        output=output,
        _api=_windows_dependencies(),
    )


def assemble_windows_qualification(
    *, bundle: Path, diagnostic: Path, source_result: Path, wheel_result: Path, output: Path
) -> Path:
    return _windows.assemble_windows_qualification(
        bundle=bundle,
        diagnostic=diagnostic,
        source_result=source_result,
        wheel_result=wheel_result,
        output=output,
        _api=_windows_dependencies(),
    )


def _validate_qualification_payload(directory: Path, manifest: dict[str, Any], *, checkout: Path) -> dict[str, Any]:
    return _windows._validate_qualification_payload(
        directory, manifest, checkout=checkout, _api=_qualification_dependencies()
    )


def validate_windows_qualification(directory: Path, *, checkout: Path) -> dict[str, Any]:
    return _windows.validate_windows_qualification(directory, checkout=checkout, _api=_qualification_dependencies())


def probe_environment(home: Path) -> dict[str, str]:
    return _execution.probe_environment(home, _api=_execution_dependencies())


def probe_interpreter(interpreter: Path, *, cwd: Path) -> dict[str, Any]:
    return _execution.probe_interpreter(interpreter, cwd=cwd, _api=_execution_dependencies())


def _suites(platform: str) -> list[tuple[str, tuple[str, ...], dict[str, str], bool]]:
    return _execution._suites(platform, _api=_execution_dependencies())


def acceptance_commands(*, checkout: Path, bundle: Path, platform: str) -> list[dict[str, Any]]:
    return _execution.acceptance_commands(
        checkout=checkout, bundle=bundle, platform=platform, _api=_execution_dependencies()
    )


def _write_new(path: Path, value: dict[str, Any]) -> None:
    _execution._write_new(path, value, _api=_execution_dependencies())
    return None


def _root_identity(root: Path) -> dict[str, Any]:
    return _execution._root_identity(root, _api=_execution_dependencies())


def run_acceptance(*, root: Path, phase: Phase, output: Path) -> int:
    return _execution.run_acceptance(root=root, phase=phase, output=output, _api=_execution_dependencies())


def extract_sdist(archive: Path, destination: Path) -> Path:
    return _execution.extract_sdist(archive, destination, _api=_execution_dependencies())


def _run_build(argv: list[str], *, cwd: Path, environment: dict[str, str], log: list[dict[str, Any]]) -> str:
    return _execution._run_build(argv, cwd=cwd, environment=environment, log=log, _api=_execution_dependencies())


def _git(checkout: Path, *args: str) -> str:
    return _execution._git(checkout, *args, _api=_execution_dependencies())


def _copy_inputs(checkout: Path, output: Path) -> None:
    _execution._copy_inputs(checkout, output, _api=_execution_dependencies())
    return None


def _bundle_artifact(directory: Path, pattern: str) -> Path:
    return _execution._bundle_artifact(directory, pattern, _api=_execution_dependencies())


def _bundle_build(checkout: Path, output: Path, commands: list[dict[str, Any]], home: Path) -> dict[str, Any]:
    return _execution._bundle_build(checkout, output, commands, home, _api=_execution_dependencies())


def _site_packages(output: Path) -> Path:
    return _execution._site_packages(output, _api=_execution_dependencies())


def _bundle_hashes(output: Path) -> dict[str, str]:
    return _execution._bundle_hashes(output, _api=_execution_dependencies())


def build_acceptance_bundle(*, checkout: Path, output: Path, source_build_receipts: Path | None = None) -> Path:
    return _execution.build_acceptance_bundle(
        checkout=checkout, output=output, source_build_receipts=source_build_receipts, _api=_execution_dependencies()
    )


def native_fixture_paths(root: Path, mode: str) -> dict[str, Path]:
    return _execution.native_fixture_paths(root, mode, _api=_execution_dependencies())


def require_native_source_checkout(context: dict[str, Any]) -> None:
    _execution.require_native_source_checkout(context, _api=_execution_dependencies())
    return None


def _native_observation_inputs(phase: Phase) -> tuple[str | None, str]:
    return _execution._native_observation_inputs(phase, _api=_execution_dependencies())


def native_phase_inputs(root: Path, phase: Phase) -> dict[str, Any]:
    return _execution.native_phase_inputs(root, phase, _api=_execution_dependencies())


def _export_windows_qualification(context: dict[str, Any], directory: Path) -> dict[str, str] | None:
    return _execution._export_windows_qualification(context, directory, _api=_execution_dependencies())


def native_acceptance_commands(*, checkout: Path, bundle: Path, platform: str, kind: str) -> list[dict[str, Any]]:
    return _execution.native_acceptance_commands(
        checkout=checkout, bundle=bundle, platform=platform, kind=kind, _api=_execution_dependencies()
    )


def _export_bundle_evidence(context: dict[str, Any], directory: Path) -> dict[str, str]:
    return _execution._export_bundle_evidence(context, directory, _api=_execution_dependencies())


def _native_environment(context: dict[str, Any], root: Path) -> dict[str, str]:
    return _execution._native_environment(context, root, _api=_execution_dependencies())


def _native_python(context: dict[str, Any]) -> Path:
    return _execution._native_python(context, _api=_execution_dependencies())


def _native_driver(context: dict[str, Any], directory: Path, *, passive: bool = False) -> Path:
    return _execution._native_driver(context, directory, passive=passive, _api=_execution_dependencies())


def _native_process(
    context: dict[str, Any], argv: list[str], environment: dict[str, str], *, timeout: int, name: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    return _execution._native_process(
        context, argv, environment, timeout=timeout, name=name, _api=_execution_dependencies()
    )


def _collector_child(context: dict[str, Any], root: Path, operation: str, directory: Path) -> dict[str, Any]:
    return _execution._collector_child(context, root, operation, directory, _api=_execution_dependencies())


def _record_native_test_failure(record: dict[str, Any], report: Path, directory: Path) -> None:
    _execution._record_native_test_failure(record, report, directory, _api=_execution_dependencies())
    return None


def _native_suite(
    context: dict[str, Any],
    row: dict[str, Any],
    directory: Path,
    baseline: Path,
    *,
    native_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _execution._native_suite(
        context, row, directory, baseline, native_facts=native_facts, _api=_execution_dependencies()
    )


def _native_reopen_prior(context: dict[str, Any], directory: Path) -> dict[str, Any]:
    return _execution._native_reopen_prior(context, directory, _api=_execution_dependencies())


def _execute_native_phase(context: dict[str, Any], *, phase: Phase, directory: Path) -> dict[str, Any]:
    return _execution._execute_native_phase(context, phase=phase, directory=directory, _api=_execution_dependencies())


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
