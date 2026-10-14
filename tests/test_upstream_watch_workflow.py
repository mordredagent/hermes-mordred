"""The issue-writing runner normalizes candidate status data before API inputs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from ruamel.yaml import YAML

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/upstream-check.yml"


def workflow():
    return YAML(typ="safe").load(WORKFLOW.read_text())


def test_upstream_execution_has_no_issue_write_authority():
    config = workflow()
    assert config["permissions"] == {}
    check = config["jobs"]["drift-check"]
    assert check["permissions"] == {"contents": "read"}
    assert check["steps"][0]["with"]["persist-credentials"] is False
    report = config["jobs"]["report"]
    assert report["permissions"] == {"issues": "write"}
    assert report["if"] == "always()"
    assert len(report["steps"]) == 1
    assert re.fullmatch(r"actions/github-script@[0-9a-f]{40}", report["steps"][0]["uses"])
    assert not any("secrets" in str(step) for step in check["steps"])
    assert all(not ("run" in step or "checkout@" in step.get("uses", "")) for step in report["steps"])


def test_report_candidate_values_reach_exact_javascript_boundary_unchanged():
    env = workflow()["jobs"]["report"]["steps"][0]["env"]
    assert env == {
        "CHECK_RESULT": "${{ needs.drift-check.result }}",
        "PYPI_STATUS": "${{ needs.drift-check.outputs.pypi_status }}",
        "MAIN_STATUS": "${{ needs.drift-check.outputs.main_status }}",
        "MEMORY_STATUS": "${{ needs.drift-check.outputs.memory_status }}",
    }


def _report_calls(values, existing):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the github-script boundary")
    script = workflow()["jobs"]["report"]["steps"][0]["with"]["script"]
    harness = """
const calls = [];
const context = {repo:{owner:"mordredagent",repo:"hermes-mordred"},serverUrl:"https://github.com",runId:123};
const github = {rest:{issues:{
listForRepo: async arg => {calls.push(["list",arg]);return {data: EXISTING ? [{number:42}]:[]};},
create: async arg => calls.push(["create",arg]),
createComment: async arg => calls.push(["comment",arg])}}};
(async () => { SCRIPT })().then(()=>process.stdout.write(JSON.stringify(calls)))
.catch(e=>{console.error(e);process.exit(1)});
""".replace("EXISTING", json.dumps(existing)).replace("SCRIPT", script)
    keys = ("CHECK_RESULT", "PYPI_STATUS", "MAIN_STATUS", "MEMORY_STATUS")
    env = {k: v for k, v in os.environ.items() if k not in keys}
    env.update({k: v for k, v in values.items() if v is not None})
    proc = subprocess.run([node, "-e", harness], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "INJECTED_UNTRUSTED_TEXT" not in proc.stdout
    return json.loads(proc.stdout)


def _assert_issue(calls, existing, expected_lines):
    assert [call[0] for call in calls] == ["list", "comment" if existing else "create"]
    target = calls[-1][1]
    assert target["owner"] == "mordredagent"
    assert target["repo"] == "hermes-mordred"
    if existing:
        assert target["issue_number"] == 42
    else:
        assert target["labels"] == ["actionable", "upstream-drift"]
    body = target["body"]
    assert body.splitlines()[2:6] == expected_lines
    assert "https://github.com/mordredagent/hermes-mordred/actions/runs/123" in body


@pytest.mark.parametrize("existing", [False])
def test_exact_success_all_ok_makes_zero_issue_api_calls(existing):
    assert (
        _report_calls(
            {"CHECK_RESULT": "success", "PYPI_STATUS": "ok", "MAIN_STATUS": "ok", "MEMORY_STATUS": "ok"}, existing
        )
        == []
    )


@pytest.mark.parametrize("existing", [False])
@pytest.mark.parametrize("field,index", [("PYPI_STATUS", 1), ("MAIN_STATUS", 2), ("MEMORY_STATUS", 3)])
@pytest.mark.parametrize(
    "candidate,want",
    [
        ("drift", "drift"),
        ("OK", "unavailable"),
        ("Ok", "unavailable"),
        ("DRIFT", "unavailable"),
        ("Drift", "unavailable"),
        ("", "unavailable"),
        (None, "unavailable"),
        (" ok", "unavailable"),
        ("ok ", "unavailable"),
        ("ok\nINJECTED_UNTRUSTED_TEXT", "unavailable"),
        ("unknown", "unavailable"),
        ("INJECTED_UNTRUSTED_TEXT", "unavailable"),
    ],
)
def test_each_candidate_status_is_exact_before_issue_inputs(existing, field, index, candidate, want):
    values = {"CHECK_RESULT": "success", "PYPI_STATUS": "ok", "MAIN_STATUS": "ok", "MEMORY_STATUS": "ok"}
    values[field] = candidate
    expected = [
        "Execution: success.",
        "PyPI hook contract: ok.",
        "Main hook contract: ok.",
        "Main memory/Journey seams: ok.",
    ]
    prefixes = {
        "PYPI_STATUS": "PyPI hook contract",
        "MAIN_STATUS": "Main hook contract",
        "MEMORY_STATUS": "Main memory/Journey seams",
    }
    expected[index] = prefixes[field] + ": " + want + "."
    _assert_issue(_report_calls(values, existing), existing, expected)


@pytest.mark.parametrize("existing", [False])
def test_all_uppercase_ok_still_reports_unavailable(existing):
    calls = _report_calls(
        {"CHECK_RESULT": "success", "PYPI_STATUS": "OK", "MAIN_STATUS": "OK", "MEMORY_STATUS": "OK"}, existing
    )
    _assert_issue(
        calls,
        existing,
        [
            "Execution: success.",
            "PyPI hook contract: unavailable.",
            "Main hook contract: unavailable.",
            "Main memory/Journey seams: unavailable.",
        ],
    )


@pytest.mark.parametrize("existing", [False])
@pytest.mark.parametrize(
    "result", ["failure", "cancelled", "skipped", "", None, "SUCCESS", "Success", "INJECTED_UNTRUSTED_TEXT"]
)
def test_execution_requires_exact_success_even_with_all_ok(existing, result):
    calls = _report_calls(
        {"CHECK_RESULT": result, "PYPI_STATUS": "ok", "MAIN_STATUS": "ok", "MEMORY_STATUS": "ok"}, existing
    )
    _assert_issue(
        calls,
        existing,
        [
            "Execution: unavailable.",
            "PyPI hook contract: ok.",
            "Main hook contract: ok.",
            "Main memory/Journey seams: ok.",
        ],
    )


# Normalization and body construction precede the create/comment branch.
# All status permutations above exercise create; this pins the other consumer.
def test_existing_issue_receives_normalized_comment():
    calls = _report_calls(
        {
            "CHECK_RESULT": "INJECTED_UNTRUSTED_TEXT",
            "PYPI_STATUS": "drift",
            "MAIN_STATUS": "ok\nINJECTED_UNTRUSTED_TEXT",
            "MEMORY_STATUS": "OK",
        },
        True,
    )
    _assert_issue(
        calls,
        True,
        [
            "Execution: unavailable.",
            "PyPI hook contract: drift.",
            "Main hook contract: unavailable.",
            "Main memory/Journey seams: unavailable.",
        ],
    )


@pytest.mark.parametrize(
    "pypi_code,main_code,want",
    [
        (0, 0, ["pypi_status=ok", "main_status=ok"]),
        (1, 2, ["pypi_status=drift", "main_status=unavailable"]),
        (2, 1, ["pypi_status=unavailable", "main_status=drift"]),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="Linux workflow shell boundary requires POSIX Bash")
def test_static_scan_execution_classifies_setup_failures(tmp_path, pypi_code, main_code, want):
    import os
    import sys

    scanner = tmp_path / "tools" / "check_hook_payload_drift.py"
    scanner.parent.mkdir()
    scanner.write_text(
        "import sys\nprint('unprivileged diagnostics')\nraise SystemExit("
        + str(main_code)
        + " if 'hermes-upstream' in sys.argv else "
        + str(pypi_code)
        + ")\n"
    )
    output = tmp_path / "outputs"
    check = workflow()["jobs"]["drift-check"]
    script = next(step["run"] for step in check["steps"] if step.get("id") == "ast")
    env = {
        **os.environ,
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        "GITHUB_OUTPUT": str(output),
        "HERMES_HOME": str(tmp_path / "home"),
    }
    proc = subprocess.run(
        ["/bin/bash", "-e", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert output.read_text().splitlines() == want


@pytest.mark.parametrize(
    "exit_code,file_status,want",
    [
        (0, "ok", "ok"),
        (1, "drift", "drift"),
        (0, None, "unavailable"),
        (0, "", "unavailable"),
        (0, "drift", "unavailable"),
        (1, "ok", "unavailable"),
        (2, "drift", "unavailable"),
        (0, "INJECTED", "unavailable"),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="Linux workflow shell boundary requires POSIX Bash")
def test_memory_step_requires_matching_complete_status(tmp_path, exit_code, file_status, want):
    import os

    runtime = tmp_path / "memory-canary" / "bin" / "python"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("#!/bin/sh\nexit " + str(exit_code) + "\n")
    runtime.chmod(0o700)
    if file_status is not None:
        (tmp_path / "memory-status.txt").write_text(file_status + "\n")
    output = tmp_path / "outputs"
    script = next(step["run"] for step in workflow()["jobs"]["drift-check"]["steps"] if step.get("id") == "memory")
    env = {**os.environ, "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(output)}
    proc = subprocess.run(
        ["/bin/bash", "-e", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert output.read_text() == "memory_status=" + want + "\n"
