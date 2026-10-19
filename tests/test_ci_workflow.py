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
        pack_condition = re.fullmatch(r"contains\(fromJSON\(needs\.ci-policy\.outputs\.(\w+)\), '([^']+)'\)", condition)
        if pack_condition:
            key, pack = pack_condition.groups()
            if pack not in json.loads(outputs[key]):
                continue
        elif condition != "always()":
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
        (
            "final",
            True,
            True,
            [
                "ci-policy",
                "linux",
                "linux",
                "linux-floor",
                "macos",
                "windows-private-fs",
                "windows-private-fs",
                "windows-private-fs",
                "windows-private-fs",
                "ci-acceptance",
            ],
        ),
    ],
)
def test_only_requested_workers_are_scheduled(mode, macos, windows, want) -> None:
    outputs = {
        "mode": mode,
        "linux_versions": json.dumps([] if mode == "docs" else ["3.11", "3.13"] if mode == "final" else ["3.12"]),
        "macos": str(macos).lower(),
        "windows": str(windows).lower(),
        "windows_shards": json.dumps([1, 2, 3, 4] if mode == "final" else [1] if windows else []),
        "linux_packs": json.dumps(["main", "static", "floor"] if mode == "final" else ["main", "static"]),
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
    assert set(acceptance["needs"]) == {"ci-policy", "linux", "linux-floor", "macos", "windows-private-fs"}
    assert acceptance["name"] == "CI acceptance"
    assert not any(step.get("continue-on-error") for job in jobs.values() for step in job["steps"])


def test_floor_runs_in_parallel_with_main_only_when_requested() -> None:
    outputs = {
        "mode": "ordinary",
        "linux_versions": '["3.12"]',
        "macos": "false",
        "windows": "false",
        "windows_shards": "[]",
        "linux_packs": '["main", "static", "floor"]',
    }
    assert scheduled_jobs(outputs) == ["ci-policy", "linux", "linux-floor", "ci-acceptance"]
    jobs = workflow()["jobs"]
    floor = jobs["linux-floor"]
    assert floor["needs"] == ["ci-policy"]
    floor_ids = {s.get("id") for s in floor["steps"]}
    assert {"floor_install", "floor_guard", "floor_tests", "evidence"} <= floor_ids
    assert not {"floor_install", "floor_guard", "floor_tests"} & {s.get("id") for s in jobs["linux"]["steps"]}
    test = next(s for s in floor["steps"] if s.get("id") == "floor_tests")
    assert "-m pytest -q --deselect" in test["run"]
    assert "--role floor" in next(s for s in floor["steps"] if s.get("id") == "evidence")["run"]


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


def test_native_matrix_records_each_shard_and_runs_support_only_once() -> None:
    job = workflow()["jobs"]["windows-private-fs"]
    assert job["name"] == "windows-private-fs (${{ matrix.shard }})"
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"] == {"shard": "${{ fromJSON(needs.ci-policy.outputs.windows_shards) }}"}
    native = next(step for step in job["steps"] if step.get("id") == "native")
    assert native["env"]["CI_SHARD"] == "${{ matrix.shard }}"
    assert native["env"]["CI_SHARD_COUNT"] == "${{ strategy.job-total }}"
    assert native["env"]["CI_TIER"] == "${{ needs.ci-policy.outputs.windows_test_tier }}"
    assert "--manifest native-selection.json" in native["run"]
    for step in job["steps"]:
        condition = step.get("if", "")
        if "windows_packs" in condition:
            assert "matrix.shard == 1" in condition
        if step.get("uses", "").startswith("actions/upload-artifact@"):
            assert "matrix.shard" in step["with"]["name"]
    evidence = next(step for step in job["steps"] if step.get("id") == "evidence")
    assert evidence["env"]["CI_SHARD"] == "${{ matrix.shard }}"
    assert '--shard "$CI_SHARD"' in evidence["run"]
    assert "--native-manifest native-selection.json" in evidence["run"]
