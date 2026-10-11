#!/usr/bin/env python3
"""Run explicit critical regressions for quick feedback, not full acceptance."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Existing tests retain their complete assertions and fixtures. Select individual
# parameter cases where a broad matrix is unnecessary for everyday feedback.
COMMON_CASES = (
    ("checked filesystem roundtrip", "tests/test_private_fs.py::test_private_create_read_replace"),
    ("crashed lock owner release", "tests/test_private_fs_processes.py::test_crashed_owner_releases_lock"),
    ("config publication failure", "tests/test_config_io.py::test_verify_pair_failure_retains_marker"),
    (
        "config uncertainty retention",
        "tests/test_config_io.py::test_caught_post_publication_verification_failure_is_retained[write]",
    ),
    (
        "retained key refusal",
        "tests/test_windows_custody.py::test_retained_state_without_manifest_never_generates[memory-key.wrapped]",
    ),
    ("copied profile refusal", "tests/test_windows_custody.py::test_physical_rename_keeps_key_but_copied_home_refuses"),
    (
        "installed memory enable/read/disable",
        "tests/test_windows_memory_lifecycle.py::test_enable_fresh_read_rerun_and_disable",
    ),
    (
        "credential custody refusal",
        "tests/test_windows_telegram_custody.py::test_sealed_credentials_without_a_role_refuse_and_never_generate",
    ),
    (
        "busy forget preserves credentials",
        "tests/test_desktop_windows_logout.py::test_forget_busy_refusal_keeps_credentials_archive_and_remote_session",
    ),
    (
        "forget before remote revoke",
        "tests/test_desktop_windows_logout.py::test_successful_forget_wipes_before_remote_revoke_and_keeps_other_roles",
    ),
    ("authentication required", "tests/extension/test_extension_api_server.py::test_auth_required_before_commands"),
    (
        "page credential isolation",
        "tests/extension/test_extension_api_server.py::test_page_session_cannot_touch_credentials",
    ),
    (
        "connected-client shutdown/restart",
        "tests/extension/test_extension_serve_shutdown.py::test_serve_stops_within_bound_with_clients_connected_and_restarts",
    ),
    ("installed package entry point", "tests/test_imports.py::test_entry_points_resolve"),
    ("real component registration", "tests/test_imports.py::test_plugin_imports[mordred_hermes.plugin]"),
    ("plugin refusal propagation", "tests/test_mordred_plugin.py::test_fail_closed_refusal_propagates"),
    (
        "pending policy refusal",
        "tests/test_windows_privacy_policy.py::test_cached_tool_allow_refuses_pending_generation",
    ),
)
POSIX_CASES = (
    ("real symlink/hardlink refusal", "tests/test_private_fs_posix.py::test_symlink_and_hardlink_refused"),
    ("real unsafe permissions refusal", "tests/test_private_fs_posix.py::test_unsafe_objects_never_repaired[file]"),
)
WINDOWS_CASES = (
    ("real unsafe DACL refusal", "tests/test_private_fs_windows.py::test_broad_acl_is_refused_without_repair"),
    ("real junction refusal", "tests/test_private_fs_windows.py::test_junction_at_final_or_parent_is_refused"),
    ("real hardlink refusal", "tests/test_private_fs_windows.py::test_hardlink_read_refused"),
)
MACOS_CASES = (
    (
        "real macOS ancestor ACL refusal",
        "tests/test_private_fs_posix.py::test_macos_ancestor_acl_refused_before_private_creation"
        "[everyone allow read,execute,file_inherit,directory_inherit]",
    ),
)


def select_cases(platform: str) -> tuple[tuple[str, str], ...]:
    if platform == "win32":
        return COMMON_CASES + WINDOWS_CASES
    if platform == "darwin":
        return COMMON_CASES + POSIX_CASES + MACOS_CASES
    if platform == "linux":
        return COMMON_CASES + POSIX_CASES
    raise ValueError(f"unsupported critical-test platform: {platform}")


def run_cases(nodes: Sequence[str], *, collect_only: bool = False, junitxml: Path | None = None) -> int:
    if not nodes:
        raise ValueError("empty critical selection would run the full suite")
    command = [sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "--strict-markers", "-m", "not integration"]
    command += ["--collect-only"] if collect_only else ["--durations=10"]
    if junitxml is not None:
        command.append(f"--junitxml={junitxml}")
    return subprocess.run([*command, *nodes], cwd=ROOT, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--list", action="store_true", help="list selected risks and exact existing node IDs")
    modes.add_argument("--dry-run", action="store_true", help="collect exact node IDs; missing nodes fail")
    parser.add_argument("--junitxml", type=Path, help="write pytest evidence to this file")
    args = parser.parse_args(argv)
    try:
        cases = select_cases(sys.platform)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        f"Critical feedback: {len(cases)} selected cases on {sys.platform}; full acceptance remains separate.",
        flush=True,
    )
    if args.list:
        for risk, node in cases:
            print(f"{risk}: {node}")
        return 0
    return run_cases([node for _risk, node in cases], collect_only=args.dry_run, junitxml=args.junitxml)


if __name__ == "__main__":
    sys.exit(main())
