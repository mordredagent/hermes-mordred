"""Scope reduction needs complete history and explicitly reviewed ownership."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def scope_tool():
    # A missing feature is an assertion failure before import during the RED run.
    assert (ROOT / "tools/ci_change_scope.py").is_file(), "complete change classifier is missing"
    spec = importlib.util.spec_from_file_location("ci_change_scope", ROOT / "tools/ci_change_scope.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def change(path: str, status: str = "modified", **extra: object) -> dict:
    return {"filename": path, "status": status, **extra}


@pytest.mark.parametrize(
    "path,final,docs,macos,families,packs",
    [
        ("src/mordred_hermes/llm_guard/health.py", False, False, False, (), ()),
        ("src/mordred_hermes/network/guidance.py", False, False, False, (), ()),
        ("src/mordred_hermes/network/runtime.py", False, False, False, ("network",), ("tor",)),
        ("src/mordred_hermes/network/hooks.py", False, False, False, ("network",), ("floor", "tor")),
        ("src/mordred_hermes/llm_guard/_policy_settings.py", False, False, False, ("llm", "privacy"), ()),
        ("src/mordred_hermes/privacy_check/policy.py", False, False, False, ("llm", "privacy"), ()),
        ("src/mordred_hermes/privacy_check/_keyvault_probe.py", False, False, True, (), ()),
        ("src/mordred_hermes/desktop/member.py", False, False, True, ("extension",), ()),
        ("src/mordred_hermes/extension/telegram/hermes_tools.py", False, False, False, (), ("features", "floor")),
        ("src/mordred_hermes/extension/web/index.html", False, False, False, (), ("package",)),
        ("README.md", False, False, False, (), ("package",)),
        ("docs/user/USAGE.md", False, True, False, (), ()),
        ("src/mordred_hermes/wizard/_term.py", False, False, False, (), ()),
        ("tests/test_llm_windows_policy_native.py", False, False, False, ("llm", "privacy"), ()),
        ("tests/test_desktop_capture.py", False, False, True, ("extension",), ()),
        ("tests/test_local_adapter.py", False, False, False, (), ("floor",)),
        ("src/mordred_hermes/llm_guard/future.py", True, False, True, (), ()),
        ("src/mordred_hermes/keyvault/ethereum.py", True, False, True, (), ()),
        ("src/mordred_hermes/extension/telegram/windows_secrets.py", True, False, True, (), ()),
        ("tests/test_config_io_windows.py", True, False, True, (), ()),
        ("tools/ci_test_policy.py", True, False, True, (), ()),
    ],
)
def test_reviewed_ownership_selects_required_workers(path, final, docs, macos, families, packs):
    result = scope_tool().classify_changes([change(path)])
    assert (result.final, result.docs, result.macos, result.families, result.linux_packs) == (
        final,
        docs,
        macos,
        families,
        packs,
    )


@pytest.mark.parametrize("status", ["added", "removed", "renamed", "copied", "unknown"])
def test_new_deleted_and_renamed_paths_never_inherit_ordinary_eligibility(status):
    result = scope_tool().classify_changes(
        [
            change(
                "src/mordred_hermes/llm_guard/health.py", status, previous_filename="src/mordred_hermes/keyvault/api.py"
            )
        ]
    )
    assert result.final


@pytest.mark.parametrize(
    "changes", [[], [{"filename": "README.md"}], [change("../README.md")], [change("README.md"), change("README.md")]]
)
def test_empty_malformed_duplicate_scope_fails_closed(changes):
    assert scope_tool().classify_changes(changes).final


def test_sensitive_overrides_win_even_if_inventory_accidentally_allowlists_them(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"schema_version": 1, "paths": {"src/mordred_hermes/keyvault/api.py": []}}))
    assert scope_tool().classify_changes([change("src/mordred_hermes/keyvault/api.py")], inventory_path=path).final


def test_whole_windows_family_preserves_native_selector_order():
    result = scope_tool().classify_changes([change("tests/test_network_windows_tor.py")])
    assert result.windows_modules == (
        "tests/test_network_windows_policy.py",
        "tests/test_network_windows_policy_native.py",
        "tests/test_network_windows_tor.py",
        "tests/test_network_windows_tor_lifecycle.py",
        "tests/test_network_windows_vpn.py",
        "tests/test_network_windows_routes_native.py",
    )


def test_inventory_entries_exist_and_windows_assets_need_wheel():
    module = scope_tool()
    inventory = json.loads((ROOT / "tools/ci_scope_paths.json").read_text())
    assert all((ROOT / path).is_file() for path in inventory["paths"])
    result = module.classify_changes([change("src/mordred_hermes/desktop/assets/desktop/plugin.js")])
    assert result.families == ("extension",)
    assert result.windows_packs == ("windows-wheel",)
    assert result.linux_packs == ("package",)


def pr_metadata(count=101):
    return {"number": 7, "changed_files": count, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}


def test_pr_scope_fetches_every_page_and_checks_exact_count():
    module = scope_tool()
    meta = pr_metadata()
    calls = []

    def get_json(path):
        calls.append(path)
        if "/files?" not in path:
            return meta
        page = int(path.rsplit("=", 1)[1])
        return [change(f"docs/example-{i}.md") for i in (range(100) if page == 1 else [100])]

    result = module.pull_request_changes("owner/repo", meta, get_json=get_json)
    assert len(result) == 101
    assert calls == [
        "/repos/owner/repo/pulls/7",
        "/repos/owner/repo/pulls/7/files?per_page=100&page=1",
        "/repos/owner/repo/pulls/7/files?per_page=100&page=2",
        "/repos/owner/repo/pulls/7",
    ]


@pytest.mark.parametrize(
    "failure", ["truncated", "duplicate", "head_changed", "base_changed", "count_changed", "over_cap", "api_error"]
)
def test_unprovable_pr_scope_is_rejected(failure):
    module = scope_tool()
    meta = pr_metadata(3001 if failure == "over_cap" else 2)
    reads = 0

    def get_json(path):
        nonlocal reads
        if failure == "api_error":
            raise OSError("unavailable")
        if "/files?" in path:
            return (
                [change("README.md")]
                if failure == "truncated"
                else [change("README.md"), change("README.md" if failure == "duplicate" else "docs/user/USAGE.md")]
            )
        reads += 1
        current = json.loads(json.dumps(meta))
        if reads == 2:
            if failure in {"head_changed", "base_changed"}:
                current[failure.split("_")[0]]["sha"] = "c" * 40
            if failure == "count_changed":
                current["changed_files"] = 3
        return current

    with pytest.raises((ValueError, OSError)):
        module.pull_request_changes("owner/repo", meta, get_json=get_json)


def test_push_diff_requires_exact_ancestry_and_reads_rename_names(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "CI test")
    (tmp_path / "old name.py").write_text("content\n")
    git("add", ".")
    git("commit", "-qm", "base")
    before = git("rev-parse", "HEAD")
    git("mv", "old name.py", "new name.py")
    git("commit", "-qm", "rename")
    after = git("rev-parse", "HEAD")
    assert scope_tool().push_changes(before, after, root=tmp_path) == [
        change("new name.py", "renamed", previous_filename="old name.py")
    ]
    with pytest.raises(ValueError):
        scope_tool().push_changes(after, before, root=tmp_path)


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_keyvault_crypto.py",
        "tests/test_dbcrypt.py",
        "tests/test_config_io_windows.py",
        "tests/test_private_fs.py",
        "tests/extension/test_extension_pairing.py",
        "tests/extension/test_telegram_memory_guard_windows.py",
        "tests/test_wizard_memory_cli.py",
        "tests/test_runtime_bootstrap.py",
        "tests/test_user_installer.py",
    ],
)
def test_sensitive_test_owners_cannot_accidentally_become_portable(path, tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"schema_version": 1, "paths": {path: []}}))
    assert scope_tool().classify_changes([change(path)], inventory_path=inventory).final


def test_docs_mixed_with_code_cannot_skip_execution_workers():
    result = scope_tool().classify_changes(
        [change("docs/user/USAGE.md"), change("src/mordred_hermes/llm_guard/health.py")]
    )
    assert not result.docs and not result.final


def test_unmapped_wizard_setup_owner_stays_final_even_in_extension_test_directory():
    assert scope_tool().classify_changes([change("tests/extension/test_telegram_setup.py")]).final
