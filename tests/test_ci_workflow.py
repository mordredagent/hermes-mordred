"""The CI graph must schedule only the requested acceptance scope."""

from __future__ import annotations

import itertools
import json
import re
import shlex
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


def scheduled_jobs(outputs: dict[str, str]) -> list[str]:
    """Evaluate the small job-level routing dialect against literal fixtures."""
    jobs: list[str] = []
    for name, job in workflow()["jobs"].items():
        condition = job.get("if", "always()")
        if condition != "always()":
            match = re.fullmatch(r"needs\.ci-policy\.outputs\.(\w+)\s*(==|!=)\s*'([^']*)'", condition)
            assert match is not None, f"unhandled job routing: {name}: {condition}"
            key, operation, value = match.groups()
            equal = outputs.get(key, "") == value
            if equal != (operation == "=="):
                continue
        axes = job.get("strategy", {}).get("matrix", {})
        sizes: list[int] = []
        for values in axes.values():
            if isinstance(values, str):
                match = re.fullmatch(r"\$\{\{ fromJSON\(needs\.ci-policy\.outputs\.(\w+)\) \}\}", values)
                assert match is not None
                values = json.loads(outputs[match.group(1)])
            sizes.append(len(values))
        count = len(list(itertools.product(*(range(size) for size in sizes))))
        jobs.extend([name] * count)
    return jobs


@pytest.mark.parametrize(
    "mode,macos,windows,want",
    [
        ("ordinary", False, False, ["ci-policy", "linux", "ci-acceptance"]),
        ("ordinary", True, False, ["ci-policy", "linux", "macos", "ci-acceptance"]),
        ("ordinary", True, True, ["ci-policy", "linux", "macos", "windows-private-fs", "ci-acceptance"]),
        ("critical", False, False, ["ci-policy", "linux", "ci-acceptance"]),
        ("docs", False, False, ["ci-policy", "ci-acceptance"]),
        ("final", True, True, ["ci-policy", "linux", "linux", "macos", "windows-private-fs", "ci-acceptance"]),
    ],
)
def test_only_requested_workers_are_scheduled(mode, macos, windows, want) -> None:
    outputs = {
        "mode": mode,
        "linux_versions": json.dumps([] if mode == "docs" else ["3.11", "3.13"] if mode == "final" else ["3.12"]),
        "macos": str(macos).lower(),
        "windows": str(windows).lower(),
        # Characterize the pre-change graph's real fan-out too.
        "full": str(mode != "critical").lower(),
        "critical": str(mode == "critical").lower(),
    }
    assert scheduled_jobs(outputs) == want


def test_acceptance_runs_after_failures_and_checks_every_worker() -> None:
    jobs = workflow()["jobs"]
    assert "ci-acceptance" in jobs, "no positive scope acceptance job"
    acceptance = jobs["ci-acceptance"]
    assert acceptance["if"] == "always()"
    assert set(acceptance["needs"]) == {"ci-policy", "linux", "macos", "windows-private-fs"}
    assert acceptance["name"] == "CI acceptance"
    assert not any(step.get("continue-on-error") for job in jobs.values() for step in job["steps"])


def test_ready_conversion_and_manual_validation_cannot_be_path_filtered() -> None:
    events = workflow().get("on", workflow().get(True))
    assert set(events["pull_request"]["types"]) == {
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
        "converted_to_draft",
    }
    assert "paths" not in events["pull_request"]
    assert "workflow_dispatch" in events
    assert events["push"]["branches"] == ["main", "dev"]


def test_release_requires_exact_branch_final_acceptance() -> None:
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    gate = release["jobs"]["ci-gate"]
    check = next(step for step in gate["steps"] if "check_ci_evidence.py" in step.get("run", ""))
    assert "--minimum-mode final" in check["run"]
    assert '--sha "$SHA"' in check["run"]
    assert '--branch "$BRANCH"' in check["run"]
    assert check["env"]["BRANCH"] == "${{ github.ref_name }}"
    assert check["if"] == "${{ !inputs.skip-ci-gate }}"
    assert gate["permissions"] == {"actions": "read", "contents": "read"}
    validation = next(step for step in gate["steps"] if step.get("name") == "Validate target, ref, and release inputs")
    assert '"$TARGET" = "pypi"' in validation["run"]
    assert '"$RELEASE_REF" != "refs/heads/main"' in validation["run"]
    assert '"$SKIP_CI_GATE" = "true"' in validation["run"]


def test_documentation_route_runs_every_required_contract_module() -> None:
    step = next(step for step in workflow()["jobs"]["ci-acceptance"]["steps"] if step.get("id") == "docs_tests")
    assert set(re.findall(r"tests/test_\w+\.py", step["run"])) == {
        "tests/test_docs_links.py",
        "tests/test_ux_guidance_guard.py",
        "tests/test_packaging_versions.py",
        "tests/test_user_installer.py",
    }


def test_auxiliary_environments_are_outside_repository_document_scans() -> None:
    jobs = workflow()["jobs"]
    auxiliary = {
        "feature_install",
        "floor_install",
        "package_build",
        "integration_install",
        "swtpm_python",
        "docs_install",
    }
    checked = set()
    for job in jobs.values():
        for step in job["steps"]:
            if step.get("id") not in auxiliary:
                continue
            creation = next(line for line in step["run"].splitlines() if line.startswith("python -m venv "))
            target = shlex.split(creation)[-1]
            assert target.startswith("$RUNNER_TEMP/"), f"{step['id']} dependencies would enter repository scans"
            checked.add(step["id"])
    assert checked == auxiliary
