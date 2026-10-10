"""Draft feedback must never suppress final/manual/branch regression gates."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/ci_test_policy.py"


def tool():
    assert TOOL.is_file(), "CI event classifier is missing"
    spec = importlib.util.spec_from_file_location("ci_test_policy", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "event,payload,want_full",
    [
        ("pull_request", {"action": "opened", "pull_request": {"draft": True}}, False),
        ("pull_request", {"action": "synchronize", "pull_request": {"draft": True}}, False),
        ("pull_request", {"action": "reopened", "pull_request": {"draft": True}}, False),
        ("pull_request", {"action": "converted_to_draft", "pull_request": {"draft": True}}, False),
        ("pull_request", {"action": "ready_for_review", "pull_request": {"draft": False}}, True),
        ("pull_request", {"action": "ready_for_review", "pull_request": {"draft": True}}, True),
        ("pull_request", {"action": "opened", "pull_request": {"draft": False}}, True),
        ("pull_request", {"action": "synchronize", "pull_request": {"draft": False}}, True),
        ("pull_request", {"action": "reopened", "pull_request": {"draft": False}}, True),
        ("pull_request", {"action": "synchronize"}, True),
        ("pull_request", {"action": "synchronize", "pull_request": {"draft": "true"}}, True),
        ("pull_request", {"action": "unexpected", "pull_request": {"draft": True}}, True),
        ("pull_request", {"action": [], "pull_request": {"draft": True}}, True),
        ("pull_request", {"action": "opened", "pull_request": None}, True),
        ("push", {"ref": "refs/heads/dev"}, True),
        ("push", {"ref": "refs/heads/main"}, True),
        ("workflow_dispatch", {"pull_request": {"draft": True}}, True),
    ],
)
def test_event_policy_fails_safe_to_full(event: str, payload: dict, want_full: bool) -> None:
    assert tool().full_suite(event, payload) is want_full


def test_classifier_writes_real_github_outputs(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"action": "opened", "pull_request": {"draft": True}}))
    output = tmp_path / "output"
    assert (
        tool().main(["--event-name", "pull_request", "--event-path", str(event), "--github-output", str(output)]) == 0
    )
    assert output.read_text() == "full=false\ncritical=true\n"


def test_workflow_retains_full_jobs_and_event_routes() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    events = workflow.get("on", workflow.get(True))  # PyYAML YAML1.1 treats on as a boolean.
    assert "workflow_dispatch" in events
    assert "ready_for_review" in events["pull_request"]["types"]
    assert "paths" not in events["pull_request"]  # Conversion cannot be filtered out by file paths.
    assert events["push"]["branches"] == ["main", "dev"]
    jobs = workflow["jobs"]
    full_jobs = {
        "windows-private-fs",
        "winkey-helper",
        "test",
        "feature-extras",
        "package-smoke",
        "hermes-floor",
        "integration-tor",
        "sekey-helper",
        "tpmkey-helper",
        "tpmkey-helper-tpm",
    }
    assert full_jobs <= jobs.keys()
    for name in full_jobs:
        assert jobs[name]["if"] == "needs.ci-policy.outputs.full == 'true'"
        assert "ci-policy" in jobs[name]["needs"]
    assert jobs["test"]["strategy"]["matrix"]["python-version"] == ["3.11", "3.12", "3.13"]
    assert jobs["windows-private-fs"]["strategy"]["matrix"]["shard"] == [1, 2, 3]
    critical = jobs["critical-feedback"]
    assert critical["if"] == "needs.ci-policy.outputs.critical == 'true'"
    assert critical["strategy"]["matrix"]["os"] == ["ubuntu-24.04", "macos-latest", "windows-2022"]
    assert critical["strategy"]["fail-fast"] is False
    assert next(s for s in critical["steps"] if s.get("name") == "Set up Python")["with"]["python-version"] == "3.12"
    assert any("--strict src tools scripts/keyvault_offline_digest.py" in s.get("run", "") for s in critical["steps"])
    assert any("ruff check src tests scripts tools" in s.get("run", "") for s in critical["steps"])
    assert any("shellcheck scripts/*.sh native/*/build.sh" in s.get("run", "") for s in critical["steps"])
    assert any("policy dry-run skills/mordred-status" in s.get("run", "") for s in critical["steps"])
