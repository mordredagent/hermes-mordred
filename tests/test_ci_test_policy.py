"""Exercise CI decisions and persisted worker contracts from real event shapes."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/ci_test_policy.py"
HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40


def tool():
    spec = importlib.util.spec_from_file_location("ci_test_policy", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "build_policy"), "complete scope policy is missing"
    return module


def event(*, draft=False, action="synchronize", target="dev", labels=()):
    return {
        "action": action,
        "number": 7,
        "pull_request": {
            "number": 7,
            "draft": draft,
            "labels": [{"name": name} for name in labels],
            "changed_files": 1,
            "head": {"sha": HEAD},
            "base": {"sha": BASE, "ref": target},
            "merge_commit_sha": MERGE,
        },
    }


def environment(event_name="pull_request", ref="refs/pull/7/merge", sha=MERGE):
    return {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_REF": ref,
        "GITHUB_SHA": sha,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
    }


def decide(
    payload=None, path="src/mordred_hermes/llm_guard/health.py", *, event_name="pull_request", env=None, **kwargs
):
    payload = payload if payload is not None else event()

    def get_json(endpoint):
        return [{"filename": path, "status": "modified"}] if "/files?" in endpoint else payload["pull_request"]

    return tool().build_policy(event_name, payload, env=env or environment(), get_json=get_json, **kwargs)


def test_ready_portable_changes_get_one_whole_linux_worker():
    result = decide()
    assert result["mode"] == "ordinary"
    assert result["linux_versions"] == ["3.12"]
    assert result["linux_packs"] == ["main", "static"]
    assert result["macos_packs"] == result["windows_packs"] == []
    assert result["macos"] is result["windows"] is False
    assert result["pr"] == {"number": 7, "head_sha": HEAD, "base_sha": BASE, "merge_sha": MERGE}
    assert (result["tested_sha"], result["run_id"], result["run_attempt"]) == (MERGE, 123, 2)


def test_network_change_adds_integration_and_whole_windows_family():
    result = decide(path="src/mordred_hermes/network/hooks.py")
    assert result["mode"] == "ordinary"
    assert result["linux_packs"] == ["main", "static", "floor", "tor"]
    assert result["windows_packs"] == ["main"]
    assert result["windows"] is True and result["macos"] is False
    assert len(result["windows_modules"]) == 6
    assert "tests/test_network_windows_tor_lifecycle.py" in result["windows_modules"]


@pytest.mark.parametrize(
    "path", ["src/mordred_hermes/keyvault/api.py", "tests/new_test.py", ".github/workflows/ci.yml"]
)
def test_sensitive_or_unknown_ready_changes_select_all_final_packs(path):
    result = decide(path=path)
    assert result["mode"] == "final"
    assert result["linux_versions"] == ["3.11", "3.13"]
    assert result["support_python"] == result["platform_python"] == "3.11"
    assert result["linux_packs"] == ["main", "static", "features", "floor", "package", "tor", "tpm", "swtpm"]
    assert result["macos_packs"] == ["main", "swift", "tpm"]
    assert result["windows_packs"] == ["main", "winkey", "windows-wheel"]
    assert len(result["windows_modules"]) == 84


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened", "converted_to_draft"])
def test_known_draft_changes_are_feedback_even_when_sensitive(action):
    result = decide(event(draft=True, action=action), path="pyproject.toml")
    assert result["mode"] == "critical"
    assert result["linux_packs"] == ["main", "static"]
    assert result["macos_packs"] == result["windows_packs"] == ["main"]
    assert result["windows_modules"] == []


@pytest.mark.parametrize(
    "payload",
    [
        event(draft=True, labels=["ci:full"]),
        event(draft=True, target="main"),
        event(draft=True, action="ready_for_review"),
        event(draft=True, action="labeled"),
    ],
)
def test_overrides_and_unknown_actions_never_reduce_work(payload):
    assert decide(payload)["mode"] == "final"


def test_docs_pr_has_no_execution_workers_but_readme_needs_package():
    result = decide(path="docs/user/USAGE.md")
    assert result["mode"] == "docs"
    assert result["linux_versions"] == result["linux_packs"] == []
    assert result["macos"] is result["windows"] is False
    assert decide(path="README.md")["linux_packs"] == ["main", "static", "package"]


@pytest.mark.parametrize("path", ["docs/dev/CI.md", "docs/dev/SPEC.md", "docs/dev/PLAN.md", "docs/dev/setup.md"])
def test_developer_contract_changes_require_final_validation(path):
    result = decide(path=path)
    assert result["mode"] == "final"
    assert result["linux_versions"] == ["3.11", "3.13"]
    assert result["macos"] is result["windows"] is True


@pytest.mark.parametrize("failure", ["api_error", "missing_count", "missing_draft", "labels", "sha", "ref", "base_ref"])
def test_incomplete_scope_or_metadata_does_not_get_draft_exception(failure):
    module = tool()
    payload = event(draft=True)
    env = environment()
    if failure == "missing_count":
        del payload["pull_request"]["changed_files"]
    if failure == "missing_draft":
        del payload["pull_request"]["draft"]
    if failure == "labels":
        payload["pull_request"]["labels"] = ["ci:full"]
    if failure == "sha":
        payload["pull_request"]["merge_commit_sha"] = "d" * 40
    if failure == "ref":
        env["GITHUB_REF"] = "refs/heads/dev"
    if failure == "base_ref":
        payload["pull_request"]["base"]["ref"] = "unexpected"

    def get_json(endpoint):
        if failure == "api_error":
            raise OSError("offline")
        return [{"filename": "README.md", "status": "modified"}] if "/files?" in endpoint else payload["pull_request"]

    assert module.build_policy("pull_request", payload, env=env, get_json=get_json)["mode"] == "final"


@pytest.mark.parametrize(
    "name,ref", [("push", "refs/heads/main"), ("workflow_dispatch", "refs/heads/dev"), ("unexpected", "refs/heads/dev")]
)
def test_branch_and_manual_final_routes_do_not_need_scope_api(name, ref):
    def no_api(endpoint):
        raise AssertionError("forced final must not need API")

    assert tool().build_policy(name, {}, env=environment(name, ref), get_json=no_api)["mode"] == "final"


def test_dev_push_uses_exact_accepted_before_and_real_git_range(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "CI test")
    source = tmp_path / "src/mordred_hermes/llm_guard/health.py"
    source.parent.mkdir(parents=True)
    source.write_text("first\n")
    git("add", ".")
    git("commit", "-qm", "baseline")
    before = git("rev-parse", "HEAD")
    source.write_text("second\n")
    git("commit", "-qam", "portable")
    after = git("rev-parse", "HEAD")
    payload = {
        "ref": "refs/heads/dev",
        "before": before,
        "after": after,
        "created": False,
        "deleted": False,
        "forced": False,
    }
    calls = []

    def accepted(repo, sha, branch, minimum_mode="final"):
        calls.append((repo, sha, branch, minimum_mode))
        return True

    result = tool().build_policy(
        "push", payload, env=environment("push", "refs/heads/dev", after), baseline_check=accepted, root=tmp_path
    )
    assert result["mode"] == "ordinary"
    assert calls == [("owner/repo", before, "dev", "ordinary")]
    for mutation in [{"forced": True}, {"created": True}, {"before": "0" * 40}, {"after": HEAD}]:
        result = tool().build_policy(
            "push",
            {**payload, **mutation},
            env=environment("push", "refs/heads/dev", after),
            baseline_check=accepted,
            root=tmp_path,
        )
        assert result["mode"] == "final"
    for check in [lambda *a, **kw: False, lambda *a, **kw: (_ for _ in ()).throw(OSError("API error"))]:
        assert (
            tool().build_policy(
                "push", payload, env=environment("push", "refs/heads/dev", after), baseline_check=check, root=tmp_path
            )["mode"]
            == "final"
        )


def test_standalone_bootstrap_cli_writes_exact_contract_without_site_packages(tmp_path):
    payload = tmp_path / "event.json"
    payload.write_text("{}")
    output, policy = tmp_path / "output", tmp_path / "policy.json"
    env = {
        **os.environ,
        **environment("workflow_dispatch", "refs/heads/dev"),
        "GITHUB_EVENT_PATH": str(payload),
        "GITHUB_OUTPUT": str(output),
    }
    result = subprocess.run(
        [sys.executable, "-S", str(TOOL), "--policy-file", str(policy)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(policy.read_text())
    assert document["mode"] == "final"
    assert document["schema_version"] == 1
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert values["mode"] == "final" and values["windows"] == "true"
    assert json.loads(values["linux_versions"]) == ["3.11", "3.13"]
    assert len(json.loads(values["windows_modules"])) == 84
