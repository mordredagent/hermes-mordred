"""Security invariants for the executable upstream-main drift canary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "upstream-check.yml"


def _load_workflow() -> dict[str, Any]:
    loaded = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_executable_upstream_code_is_isolated_from_issue_write_permission() -> None:
    workflow = _load_workflow()
    assert workflow["permissions"] == {}

    check_job = workflow["jobs"]["drift_check"]
    assert check_job["permissions"] == {"contents": "read"}
    assert "issues" not in check_job["permissions"]
    assert all("actions/github-script@" not in step.get("uses", "") for step in check_job["steps"])

    checkout = next(step for step in check_job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False

    report_job = workflow["jobs"]["report"]
    assert report_job["needs"] == "drift_check"
    assert report_job["permissions"] == {"issues": "write"}
    assert all("actions/checkout@" not in step.get("uses", "") for step in report_job["steps"])
    assert all("run" not in step for step in report_job["steps"])
