"""The issue-writing runner consumes only normalized tokens and trusted context."""

from __future__ import annotations

import json
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
    assert "always()" in report["if"]
    assert len(report["steps"]) == 1
    assert "github-script@" in report["steps"][0]["uses"]
    assert not any("secrets" in str(step) for step in check["steps"])
    assert all(not ("run" in step or "checkout@" in step.get("uses", "")) for step in report["steps"])


@pytest.mark.parametrize(
    "result,pypi,main,memory,want_api,word",
    [
        ("success", "ok", "ok", "ok", False, ""),
        ("success", "ok", "drift", "ok", True, "drift"),
        ("failure", "ok", "ok", "ok", True, "unavailable"),
        ("cancelled", "", "", "", True, "unavailable"),
        ("success", "ok", "ok", "", True, "unavailable"),
        ("success", "ok", "ok", "INJECTED_UNTRUSTED_TEXT", True, "unavailable"),
        ("success", "ok", "ok", "ok\nINJECTED_UNTRUSTED_TEXT", True, "unavailable"),
        ("INJECTED_UNTRUSTED_TEXT", "ok", "ok", "ok", True, "unavailable"),
    ],
)
@pytest.mark.parametrize("existing", [False, True])
def test_report_executes_only_allowlisted_statuses(result, pypi, main, memory, want_api, word, existing):
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
const core = {info:()=>{}};
(async () => { SCRIPT })().then(()=>process.stdout.write(JSON.stringify(calls)))
.catch(e=>{console.error(e);process.exit(1)});
""".replace("EXISTING", json.dumps(existing)).replace("SCRIPT", script)
    import os

    env = {**os.environ, "CHECK_RESULT": result, "PYPI_STATUS": pypi, "MAIN_STATUS": main, "MEMORY_STATUS": memory}
    proc = subprocess.run([node, "-e", harness], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    calls = json.loads(proc.stdout)
    assert bool(calls) is want_api
    assert "INJECTED_UNTRUSTED_TEXT" not in proc.stdout
    if want_api:
        assert calls[-1][0] == ("comment" if existing else "create")
        assert word in calls[-1][1]["body"]
        assert "https://github.com/mordredagent/hermes-mordred/actions/runs/123" in calls[-1][1]["body"]


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
