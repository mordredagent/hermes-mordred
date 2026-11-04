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
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

# Scripts, arbitrary spec_from_file_location names and runpy do not establish a
# package context. Anchor sibling imports to the tool's actual exported location.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))


import sys
from pathlib import Path

import _dbcrypt_acceptance_evidence as _evidence
import _dbcrypt_acceptance_execution as _execution
import _dbcrypt_acceptance_windows as _windows
from _dbcrypt_acceptance_common import (
    _PROBE as _PROBE,
)
from _dbcrypt_acceptance_common import (
    _PTH_TEST_INPUTS as _PTH_TEST_INPUTS,
)
from _dbcrypt_acceptance_common import (
    ADDITIONAL_MODULES as ADDITIONAL_MODULES,
)
from _dbcrypt_acceptance_common import (
    AFFECTED_MODULES as AFFECTED_MODULES,
)
from _dbcrypt_acceptance_common import (
    CONTROL_MARGIN as CONTROL_MARGIN,
)
from _dbcrypt_acceptance_common import (
    INSTANCES as INSTANCES,
)
from _dbcrypt_acceptance_common import (
    NATIVE_FAILURE_CATEGORIES as NATIVE_FAILURE_CATEGORIES,
)
from _dbcrypt_acceptance_common import (
    NATIVE_FAILURE_STAGES as NATIVE_FAILURE_STAGES,
)
from _dbcrypt_acceptance_common import (
    NATIVE_REFUSAL_REASONS as NATIVE_REFUSAL_REASONS,
)
from _dbcrypt_acceptance_common import (
    NATIVE_TEST_FAILURE_HASH_SCHEME as NATIVE_TEST_FAILURE_HASH_SCHEME,
)
from _dbcrypt_acceptance_common import (
    NATIVE_TEST_FAILURE_MODULES as NATIVE_TEST_FAILURE_MODULES,
)
from _dbcrypt_acceptance_common import (
    PLATFORM_INSTANCE as PLATFORM_INSTANCE,
)
from _dbcrypt_acceptance_common import (
    REQUIRED_COMPONENTS as REQUIRED_COMPONENTS,
)
from _dbcrypt_acceptance_common import (
    REQUIRED_PROFILES as REQUIRED_PROFILES,
)
from _dbcrypt_acceptance_common import (
    RUN_SCHEMA as RUN_SCHEMA,
)
from _dbcrypt_acceptance_common import (
    WINDOWS_PLATFORM_NA as WINDOWS_PLATFORM_NA,
)
from _dbcrypt_acceptance_common import (
    WINDOWS_RELEASE_SELECTION as WINDOWS_RELEASE_SELECTION,
)
from _dbcrypt_acceptance_common import (
    WINDOWS_TELEGRAM_MIGRATION_REASON as WINDOWS_TELEGRAM_MIGRATION_REASON,
)
from _dbcrypt_acceptance_common import (
    AcceptanceRefused as AcceptanceRefused,
)
from _dbcrypt_acceptance_common import (
    EvidenceAPI as EvidenceAPI,
)
from _dbcrypt_acceptance_common import (
    ExecutionAPI as ExecutionAPI,
)
from _dbcrypt_acceptance_common import (
    Mode as Mode,
)
from _dbcrypt_acceptance_common import (
    Phase as Phase,
)
from _dbcrypt_acceptance_common import (
    QualificationAPI as QualificationAPI,
)
from _dbcrypt_acceptance_common import (
    SystemAPI as SystemAPI,
)
from _dbcrypt_acceptance_common import (
    WindowsAPI as WindowsAPI,
)
from _dbcrypt_acceptance_common import (
    _absolute as _absolute,
)
from _dbcrypt_acceptance_common import (
    _artifact_ref as _artifact_ref,
)
from _dbcrypt_acceptance_common import (
    _bytecode as _bytecode,
)
from _dbcrypt_acceptance_common import (
    _evidence_ref as _evidence_ref,
)
from _dbcrypt_acceptance_common import (
    _guest_path as _guest_path,
)
from _dbcrypt_acceptance_common import (
    _hex as _hex,
)
from _dbcrypt_acceptance_common import (
    _input_file as _input_file,
)
from _dbcrypt_acceptance_common import (
    _input_root_layout as _input_root_layout,
)
from _dbcrypt_acceptance_common import (
    _module_functions as _module_functions,
)
from _dbcrypt_acceptance_common import (
    _native_test_failure_details as _native_test_failure_details,
)
from _dbcrypt_acceptance_common import (
    _normalized_node as _normalized_node,
)
from _dbcrypt_acceptance_common import (
    _object as _object,
)
from _dbcrypt_acceptance_common import (
    _private_evidence_file as _private_evidence_file,
)
from _dbcrypt_acceptance_common import (
    _project_native_test_failure as _project_native_test_failure,
)
from _dbcrypt_acceptance_common import (
    _python as _python,
)
from _dbcrypt_acceptance_common import (
    _relative as _relative,
)
from _dbcrypt_acceptance_common import (
    _require as _require,
)
from _dbcrypt_acceptance_common import (
    _test_identity as _test_identity,
)
from _dbcrypt_acceptance_common import (
    _text as _text,
)
from _dbcrypt_acceptance_common import (
    _timestamp as _timestamp,
)
from _dbcrypt_acceptance_common import (
    _tree_inputs as _tree_inputs,
)
from _dbcrypt_acceptance_common import (
    native_failure_descriptor as native_failure_descriptor,
)
from _dbcrypt_acceptance_common import (
    native_operation_bootstrap as native_operation_bootstrap,
)
from _dbcrypt_acceptance_common import (
    native_refusal_payload as native_refusal_payload,
)
from _dbcrypt_acceptance_common import (
    native_test_failure_descriptor as native_test_failure_descriptor,
)
from _dbcrypt_acceptance_common import (
    native_test_failure_summary as native_test_failure_summary,
)
from _dbcrypt_acceptance_common import (
    sha256_file as sha256_file,
)
from _dbcrypt_acceptance_evidence import (
    _cloud_observation as _cloud_observation,
)
from _dbcrypt_acceptance_evidence import (
    _collector_arguments as _collector_arguments,
)
from _dbcrypt_acceptance_evidence import (
    _control_reboot as _control_reboot,
)
from _dbcrypt_acceptance_evidence import (
    _control_start as _control_start,
)
from _dbcrypt_acceptance_evidence import (
    _controller_snapshot as _controller_snapshot,
)
from _dbcrypt_acceptance_evidence import (
    _crash_nodes as _crash_nodes,
)
from _dbcrypt_acceptance_evidence import (
    _exported_probe as _exported_probe,
)
from _dbcrypt_acceptance_evidence import (
    _native_node_outcome as _native_node_outcome,
)
from _dbcrypt_acceptance_evidence import (
    _native_operation_evidence as _native_operation_evidence,
)
from _dbcrypt_acceptance_evidence import (
    _native_payload as _native_payload,
)
from _dbcrypt_acceptance_evidence import (
    _native_provision_coverage as _native_provision_coverage,
)
from _dbcrypt_acceptance_evidence import (
    _offline_build_records as _offline_build_records,
)
from _dbcrypt_acceptance_evidence import (
    _ordered_control_cycles as _ordered_control_cycles,
)
from _dbcrypt_acceptance_evidence import (
    _owned_copy_directories as _owned_copy_directories,
)
from _dbcrypt_acceptance_evidence import (
    _phase_bundle as _phase_bundle,
)
from _dbcrypt_acceptance_evidence import (
    _provision_fixture_closure as _provision_fixture_closure,
)
from _dbcrypt_acceptance_evidence import (
    _public_read as _public_read,
)
from _dbcrypt_acceptance_evidence import (
    _same_controller_run as _same_controller_run,
)
from _dbcrypt_acceptance_evidence import (
    _settled_control_cycle as _settled_control_cycle,
)
from _dbcrypt_acceptance_evidence import (
    _validate_build_records as _validate_build_records,
)
from _dbcrypt_acceptance_evidence import (
    _validate_exported_import as _validate_exported_import,
)
from _dbcrypt_acceptance_evidence import (
    _validate_probe as _validate_probe,
)
from _dbcrypt_acceptance_evidence import (
    _verify_mode_sequences as _verify_mode_sequences,
)
from _dbcrypt_acceptance_evidence import (
    _verify_native_stops as _verify_native_stops,
)
from _dbcrypt_acceptance_evidence import (
    load_stop_receipt as load_stop_receipt,
)
from _dbcrypt_acceptance_evidence import (
    platform_na_reason as platform_na_reason,
)
from _dbcrypt_acceptance_evidence import (
    validate_bundle_evidence as validate_bundle_evidence,
)
from _dbcrypt_acceptance_evidence import (
    validate_control_action as validate_control_action,
)
from _dbcrypt_acceptance_evidence import (
    validate_control_cycles as validate_control_cycles,
)
from _dbcrypt_acceptance_evidence import (
    validate_helper_withdrawal as validate_helper_withdrawal,
)
from _dbcrypt_acceptance_evidence import (
    validate_import_provenance as validate_import_provenance,
)
from _dbcrypt_acceptance_evidence import (
    validate_native_test_report as validate_native_test_report,
)
from _dbcrypt_acceptance_evidence import (
    validate_phase_control_binding as validate_phase_control_binding,
)
from _dbcrypt_acceptance_evidence import (
    validate_reopen_continuity as validate_reopen_continuity,
)
from _dbcrypt_acceptance_evidence import (
    validate_withdrawable_helper as validate_withdrawable_helper,
)
from _dbcrypt_acceptance_windows import (
    _build_receipt_files as _build_receipt_files,
)
from _dbcrypt_acceptance_windows import (
    _copy_build_receipts as _copy_build_receipts,
)
from _dbcrypt_acceptance_windows import (
    _copy_referenced as _copy_referenced,
)
from _dbcrypt_acceptance_windows import (
    _diagnostic_files as _diagnostic_files,
)
from _dbcrypt_acceptance_windows import (
    _fixture_descriptor as _fixture_descriptor,
)
from _dbcrypt_acceptance_windows import (
    _local_bundle_proof as _local_bundle_proof,
)
from _dbcrypt_acceptance_windows import (
    _native_windows_vfs_rows as _native_windows_vfs_rows,
)
from _dbcrypt_acceptance_windows import (
    _package_build_inputs as _package_build_inputs,
)
from _dbcrypt_acceptance_windows import (
    _qualification_argv as _qualification_argv,
)
from _dbcrypt_acceptance_windows import (
    _qualification_binaries as _qualification_binaries,
)
from _dbcrypt_acceptance_windows import (
    _qualification_fixture as _qualification_fixture,
)
from _dbcrypt_acceptance_windows import (
    _qualification_inputs as _qualification_inputs,
)
from _dbcrypt_acceptance_windows import (
    _qualification_row as _qualification_row,
)
from _dbcrypt_acceptance_windows import (
    _qualified_package_artifacts as _qualified_package_artifacts,
)
from _dbcrypt_acceptance_windows import (
    _qualified_vfs_reference as _qualified_vfs_reference,
)
from _dbcrypt_acceptance_windows import (
    _required_qualification_headers as _required_qualification_headers,
)
from _dbcrypt_acceptance_windows import (
    _validate_build_receipt as _validate_build_receipt,
)
from _dbcrypt_acceptance_windows import (
    _validate_package_eligibility as _validate_package_eligibility,
)
from _dbcrypt_acceptance_windows import (
    _validate_packaged_result as _validate_packaged_result,
)
from _dbcrypt_acceptance_windows import (
    _validate_windows_eligibility as _validate_windows_eligibility,
)
from _dbcrypt_acceptance_windows import (
    canonical_windows_owner_sid as canonical_windows_owner_sid,
)
from _dbcrypt_acceptance_windows import (
    matching_build_receipts as matching_build_receipts,
)
from _dbcrypt_acceptance_windows import (
    require_production_qualification as require_production_qualification,
)
from _dbcrypt_acceptance_windows import (
    validate_package_observation as validate_package_observation,
)
from _dbcrypt_acceptance_windows import (
    windows_activation_declaration as windows_activation_declaration,
)
from _dbcrypt_acceptance_windows import (
    windows_package_commands as windows_package_commands,
)
from _dbcrypt_acceptance_windows import (
    windows_vfs_required_nodes as windows_vfs_required_nodes,
)


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
