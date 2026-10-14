#!/usr/bin/env python3
"""Bounded, complete change discovery and a finite reviewed CI ownership table."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple, cast

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = Path(__file__).with_name("ci_scope_paths.json")
FAMILIES = ("network", "llm", "privacy", "extension")
LINUX_PACKS = ("features", "floor", "package", "tor")
TAGS = frozenset((*FAMILIES, *LINUX_PACKS, "macos", "windows-wheel", "docs"))
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class Scope(NamedTuple):
    final: bool
    docs: bool
    macos: bool
    families: tuple[str, ...]
    linux_packs: tuple[str, ...]
    windows_packs: tuple[str, ...]
    windows_modules: tuple[str, ...]
    reason: str


def final_scope(reason: str) -> Scope:
    return Scope(True, False, True, (), (), (), (), reason)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _inventory(path: Path = INVENTORY) -> dict[str, object]:
    value: object = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("paths"), dict):
        raise ValueError("invalid scope inventory")
    return value


def native_modules() -> tuple[str, ...]:
    """Original 84 whole-module selector, in the external harness's order."""
    value = _inventory().get("native_modules")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(p, str) and re.fullmatch(r"tests/[\w/]+\.py", p) for p in value)
    ):
        raise ValueError("invalid native selector")
    if len(value) != len(set(value)):
        raise ValueError("duplicate native module")
    return tuple(value)


def windows_family_modules(families: Sequence[str]) -> tuple[str, ...]:
    if not set(families) <= set(FAMILIES):
        raise ValueError("unknown Windows family")
    patterns = {
        "network": ("tests/test_network_windows_*.py",),
        "llm": ("tests/test_llm_windows_policy*.py",),
        "privacy": ("tests/test_windows_privacy_*.py",),
        "extension": (
            "tests/extension/test_*windows*.py",
            "tests/test_desktop_windows_*.py",
            "tests/test_windows_telegram_*.py",
            "tests/test_wizard_windows_telegram*.py",
            "tests/test_desktop_capture.py",
            "tests/extension/test_desktop_api.py",
            "tests/extension/test_desktop_platform.py",
            "tests/extension/test_extension_serve_shutdown.py",
        ),
    }
    return tuple(
        module
        for module in native_modules()
        if any(fnmatch.fnmatchcase(module, pattern) for family in families for pattern in patterns[family])
    )


def _sensitive(path: str) -> bool:
    # Overrides stay ahead of the inventory: an accidental entry cannot grant a
    # portable route to a shared custody/bootstrap boundary.
    if path.startswith(("native/", "packaging/", ".github/", "tools/", "docs/dev/")) or path in {
        "AGENTS.md",
        "pyproject.toml",
        "uv.lock",
        "scripts/install.sh",
        "scripts/install.ps1",
        "scripts/keyvault_offline_digest.py",
    }:
        return True
    if path.startswith("tests/"):
        name = Path(path).name
        if name == "test_keyvault_probe.py":
            return False  # The privacy component's macOS capability probe.
        sensitive_tests = (
            "test_keyvault_*",
            "test_keychain_*",
            "test_dbcrypt*",
            "test_private_fs*",
            "test_config_io*",
            "test_config_readers*",
            "test_yaml_io*",
            "test_file_lock*",
            "test_policy_io*",
            "test_policy_types*",
            "test_audit_session*",
            "test_audit_factory*",
            "test_audit_rotation*",
            "test_log_rotation*",
            "test_mordred_plugin*",
            "test_pth_bootstrap*",
            "test_runtime_bootstrap*",
            "test_windows_runtime*",
            "test_extension_crypto*",
            "test_extension_e2e*",
            "test_extension_pairing*",
            "test_extension_webauthn*",
            "test_extension_rpc*",
            "test_extension_api*",
            "test_telegram_memory_guard*",
            "test_telegram_single_unseal*",
            "test_telegram_import*",
            "test_windows_telegram_*",
            "test_windows_custody*",
            "test_windows_memory*",
            "test_windows_database*",
            "test_windows_encrypted_audit*",
            "test_windows_capability*",
            "test_wizard_*vault*",
            "test_wizard_*memory*",
            "test_wizard_*encryption*",
            "test_wizard_*database*",
            "test_wizard_*install*",
            "test_wizard_config*",
            "test_wizard_env*",
            "test_wizard_setup*",
            "test_wizard_workspace*",
            "test_configure*",
            "test_credentials_writer*",
            "test_env_file_writer*",
            "test_policy_writer*",
            "test_*installer*",
            "test_*install_ownership*",
            "test_install_dispatch*",
            "test_desktop_windows_install*",
            "test_native_helper*",
            "test_winkey*",
        )
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in sensitive_tests)
    base = "src/mordred_hermes/"
    if not path.startswith(base):
        return False
    rel = path.removeprefix(base)
    if "/" not in rel:
        return True
    if rel.startswith(("keyvault/", "dbcrypt/", "_private_fs/")):
        return True
    if rel in {
        "extension/crypto.py",
        "extension/e2e.py",
        "extension/pairing.py",
        "extension/webauthn.py",
        "extension/rpc.py",
        "extension/api.py",
        "desktop/install.py",
        "desktop/_windows_assets.py",
    }:
        return True
    if rel.startswith("extension/telegram/") and Path(rel).name in {
        "memory_guard.py",
        "secrets.py",
        "windows_secrets.py",
        "_windows_archive.py",
        "store.py",
        "hardening.py",
    }:
        return True
    if rel.startswith("wizard/"):
        name = Path(rel).name
        return name in {
            "configure.py",
            "credentials_writer.py",
            "env_file_writer.py",
            "policy_writer.py",
            "setup_cli.py",
            "config_decrypt_cli.py",
            "env_decrypt_cli.py",
            "workspace_cli.py",
        } or any(token in name for token in ("vault", "keyvault", "memory", "encryption", "database", "install"))
    return False


def _valid_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
        and not any(ord(char) < 32 for char in value)
    )


def validate_changes(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise ValueError("missing changed files")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for record in value:
        if (
            not isinstance(record, dict)
            or not _valid_path(record.get("filename"))
            or record.get("status") not in {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"}
        ):
            raise ValueError("invalid changed file")
        path = cast(str, record["filename"])
        if path in seen:
            raise ValueError("duplicate changed file")
        if record["status"] in {"renamed", "copied"} and not _valid_path(record.get("previous_filename")):
            raise ValueError("missing old path")
        seen.add(path)
        result.append(record)
    return result


def classify_changes(changes: object, *, inventory_path: Path = INVENTORY) -> Scope:
    """Only known existing modified files can select reduced work."""
    try:
        records = validate_changes(changes)
        paths = cast(dict[str, object], _inventory(inventory_path)["paths"])
        tags: set[str] = set()
        all_docs = True
        for record in records:
            path = cast(str, record["filename"])
            if record["status"] != "modified":
                return final_scope("new, deleted, renamed or otherwise non-modified path")
            if _sensitive(path):
                return final_scope("shared security or infrastructure boundary")
            entry = paths.get(path)
            if not isinstance(entry, list) or not all(isinstance(tag, str) and tag in TAGS for tag in entry):
                return final_scope("path has no reviewed ownership")
            if "docs" in entry and (not path.startswith("docs/user/") or not path.endswith(".md")):
                return final_scope("documentation route is limited to reviewed user Markdown")
            tags.update(entry)
            all_docs = all_docs and entry == ["docs"]
        families = tuple(family for family in FAMILIES if family in tags)
        windows_packs = ("windows-wheel",) if "windows-wheel" in tags else ()
        return Scope(
            False,
            all_docs,
            "macos" in tags,
            families,
            tuple(pack for pack in LINUX_PACKS if pack in tags),
            windows_packs,
            windows_family_modules(families),
            "complete reviewed change scope",
        )
    except (ValueError, OSError, TypeError):
        return final_scope("invalid or unavailable change scope")


def github_json(path: str) -> object:
    """Read bounded JSON from the fixed GitHub API origin, never remote URLs."""
    if not path.startswith("/repos/"):
        raise ValueError("invalid API path")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request("https://api.github.com" + path, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(8 * 1024 * 1024 + 1)
    if len(body) > 8 * 1024 * 1024:
        raise ValueError("API response exceeds limit")
    return json.loads(body)


def _pr_identity(pr: Mapping[str, object]) -> tuple[int, str, str, int]:
    number, count = pr.get("number"), pr.get("changed_files")
    head, base = pr.get("head"), pr.get("base")
    if (
        type(number) is not int
        or number < 1
        or type(count) is not int
        or not 1 <= count <= 3000
        or not isinstance(head, dict)
        or not isinstance(base, dict)
    ):
        raise ValueError("incomplete PR identity or file count")
    head_sha, base_sha = head.get("sha"), base.get("sha")
    if (
        not isinstance(head_sha, str)
        or not SHA.fullmatch(head_sha)
        or not isinstance(base_sha, str)
        or not SHA.fullmatch(base_sha)
    ):
        raise ValueError("invalid PR SHAs")
    return number, head_sha, base_sha, count


def pull_request_changes(
    repository: str, pr: Mapping[str, object], *, get_json: Callable[[str], object] = github_json
) -> list[dict[str, object]]:
    """Cumulative PR files, paginated and checked against stable metadata."""
    if not REPOSITORY.fullmatch(repository):
        raise ValueError("invalid repository")
    identity = _pr_identity(pr)
    number, _, _, count = identity
    endpoint = f"/repos/{repository}/pulls/{number}"

    def check_identity() -> None:
        latest = get_json(endpoint)
        if not isinstance(latest, dict) or _pr_identity(latest) != identity:
            raise ValueError("PR changed while scope was collected")

    check_identity()
    files: list[object] = []
    for page in range(1, (count + 99) // 100 + 1):
        batch = get_json(f"{endpoint}/files?per_page=100&page={page}")
        expected = min(100, count - len(files))
        if not isinstance(batch, list) or len(batch) != expected:
            raise ValueError("incomplete PR file page")
        files.extend(batch)
    result = validate_changes(files)
    if len(result) != count:
        raise ValueError("PR file count mismatch")
    check_identity()
    return result


def push_changes(before: str, after: str, *, root: Path = ROOT) -> list[dict[str, object]]:
    """Use the complete local commit range only after proving ancestry."""
    if (
        not SHA.fullmatch(before)
        or not SHA.fullmatch(after)
        or before == "0" * 40
        or after == "0" * 40
        or before == after
    ):
        raise ValueError("invalid push range")
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", before, after], cwd=root, capture_output=True, check=False
    )
    if ancestry.returncode:
        raise ValueError("push before SHA is not an available ancestor")
    diff = (
        subprocess.run(
            ["git", "diff", "--name-status", "-z", "--find-renames", before, after, "--"],
            cwd=root,
            capture_output=True,
            check=True,
        )
        .stdout.decode("utf-8", errors="strict")
        .split("\0")
    )
    if diff[-1] != "":
        raise ValueError("unterminated git diff")
    diff.pop()
    result: list[dict[str, object]] = []
    index = 0
    while index < len(diff):
        status = diff[index]
        index += 1
        if status.startswith(("R", "C")):
            if index + 1 >= len(diff):
                raise ValueError("truncated rename")
            result.append(
                {
                    "filename": diff[index + 1],
                    "status": "renamed" if status.startswith("R") else "copied",
                    "previous_filename": diff[index],
                }
            )
            index += 2
        else:
            if index >= len(diff) or status not in {"M", "A", "D", "T"}:
                raise ValueError("unknown git diff status")
            result.append(
                {
                    "filename": diff[index],
                    "status": {"M": "modified", "A": "added", "D": "removed", "T": "changed"}[status],
                }
            )
            index += 1
    return validate_changes(result)
