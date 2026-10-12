"""CI evidence must prove the exact workers and scope, never merely a green run."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def evidence_tool():
    path = ROOT / "tools/ci_evidence.py"
    assert path.is_file(), "CI evidence validator is missing"
    spec = importlib.util.spec_from_file_location("ci_evidence", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(mode="ordinary"):
    return {
        "schema_version": 1,
        "mode": mode,
        "repository": "owner/repo",
        "workflow_path": ".github/workflows/ci.yml",
        "event_name": "push",
        "ref": "refs/heads/dev",
        "tested_sha": SHA,
        "run_id": 42,
        "run_attempt": 2,
        "pr": None,
        "linux_versions": ["3.12"],
        "platform_python": "3.12",
        "support_python": "3.12",
        "macos": False,
        "windows": False,
        "linux_packs": ["main", "static"],
        "macos_packs": [],
        "windows_packs": [],
        "windows_modules": [],
        "reason": "portable change",
    }


def successful_steps(*names):
    return {name: {"outcome": "success", "conclusion": "success"} for name in names}


def linux_steps():
    return successful_steps("install", "mypy", "pytest", "ruff", "shellcheck", "status")


def needs():
    return {
        "ci-policy": {"result": "success", "outputs": {}},
        "linux": {"result": "success", "outputs": {}},
        "macos": {"result": "skipped", "outputs": {}},
        "windows-private-fs": {"result": "skipped", "outputs": {}},
    }


def worker(tool, p=None, steps=None):
    return tool.build_worker(p or policy(), "linux", "3.12", steps or linux_steps(), actual_python="3.12")


def test_complete_ordinary_evidence_is_not_release_evidence():
    tool = evidence_tool()
    result = tool.accept(policy(), [worker(tool)], needs(), {})
    assert result["accepted"] is True
    assert result["policy"]["mode"] == "ordinary"
    assert result["workers"][0]["actual_python"] == "3.12"


@pytest.mark.parametrize("state", ["skipped", "failure", "cancelled", None])
def test_required_step_without_success_cannot_authorize_acceptance(state):
    tool = evidence_tool()
    steps = linux_steps()
    if state is None:
        del steps["pytest"]
    else:
        steps["pytest"] = {"outcome": state, "conclusion": state}
    manifest = worker(tool, steps=steps)
    assert manifest["success"] is False
    with pytest.raises(ValueError):
        tool.accept(policy(), [manifest], needs(), {})


def test_continue_on_error_cannot_hide_failed_outcome():
    tool = evidence_tool()
    steps = linux_steps()
    steps["pytest"]["outcome"] = "failure"
    with pytest.raises(ValueError):
        tool.accept(policy(), [worker(tool, steps=steps)], needs(), {})


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "stale_sha", "stale_attempt"])
def test_acceptance_requires_exact_worker_identity(mutation):
    tool = evidence_tool()
    manifests = [worker(tool)]
    if mutation == "missing":
        manifests.clear()
    elif mutation == "duplicate":
        manifests.append(copy.deepcopy(manifests[0]))
    elif mutation == "unknown":
        manifests[0]["os"] = "other"
    elif mutation == "stale_sha":
        manifests[0]["context"]["tested_sha"] = "b" * 40
    else:
        manifests[0]["context"]["run_attempt"] = 1
    with pytest.raises(ValueError):
        tool.accept(policy(), manifests, needs(), {})


@pytest.mark.parametrize(
    "job,state",
    [
        ("linux", "skipped"),
        ("linux", "failure"),
        ("linux", "cancelled"),
        ("ci-policy", "failure"),
        ("macos", "success"),
    ],
)
def test_needs_results_are_checked_even_when_manifests_claim_success(job, state):
    tool = evidence_tool()
    jobs = needs()
    jobs[job]["result"] = state
    with pytest.raises(ValueError):
        tool.accept(policy(), [worker(tool)], jobs, {})


def test_declared_interpreter_cannot_substitute_for_actual_interpreter():
    tool = evidence_tool()
    with pytest.raises(ValueError):
        tool.build_worker(policy(), "linux", "3.12", linux_steps(), actual_python="3.11")


def test_critical_success_is_explicitly_feedback_only():
    tool = evidence_tool()
    p = policy("critical")
    result = tool.accept(p, [worker(tool, p)], needs(), {})
    assert result["accepted"] is False
    assert result["feedback_only"] is True


def test_docs_acceptance_requires_checks_executed_in_acceptance_job():
    tool = evidence_tool()
    p = policy("docs")
    p.update(linux_versions=[], linux_packs=[])
    jobs = needs()
    jobs["linux"]["result"] = "skipped"
    with pytest.raises(ValueError):
        tool.accept(p, [], jobs, {})
    assert tool.accept(p, [], jobs, successful_steps("docs_tests"))["accepted"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("run_attempt", True),
        ("workflow_path", ".github/workflows/other.yml"),
        ("linux_versions", ["3.11"]),
        ("linux_packs", ["main"]),
        ("windows", "false"),
    ],
)
def test_policy_tampering_cannot_reduce_required_evidence(field, value):
    tool = evidence_tool()
    p = policy()
    p[field] = value
    with pytest.raises(ValueError):
        worker(tool, p)


def test_pr_context_must_identify_tested_merge_commit():
    tool = evidence_tool()
    p = policy()
    p.update(
        event_name="pull_request",
        ref="refs/pull/7/merge",
        pr={"number": 7, "head_sha": "b" * 40, "base_sha": "c" * 40, "merge_sha": "d" * 40},
    )
    with pytest.raises(ValueError):
        worker(tool, p)


def test_duplicate_json_fields_are_rejected():
    tool = evidence_tool()
    with pytest.raises(ValueError):
        tool.parse_json('{"accepted": false, "accepted": true}')


def test_acceptance_cli_rejects_unexpected_files(tmp_path, monkeypatch):
    tool = evidence_tool()
    p = policy()
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(p))
    directory = tmp_path / "workers"
    directory.mkdir()
    (directory / "worker.json").write_text(json.dumps(worker(tool)))
    (directory / "surprise.json").write_text("{}")
    for key, value in {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/heads/dev",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/heads/dev",
        "CI_NEEDS_JSON": json.dumps(needs()),
        "CI_STEPS_JSON": "{}",
    }.items():
        monkeypatch.setenv(key, value)
    output = tmp_path / "evidence.json"
    assert (
        tool.main(["accept", "--policy", str(policy_path), "--workers", str(directory), "--output", str(output)]) == 1
    )
    assert not output.exists()


def checker_tool():
    path = ROOT / "tools/check_ci_evidence.py"
    assert path.is_file(), "Remote CI evidence checker is missing"
    spec = importlib.util.spec_from_file_location("check_ci_evidence", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def final_policy():
    p = policy("final")
    inventory = json.loads((ROOT / "tools/ci_scope_paths.json").read_text())
    p.update(
        linux_versions=["3.11", "3.13"],
        support_python="3.11",
        platform_python="3.11",
        macos=True,
        windows=True,
        linux_packs=["main", "static", "features", "floor", "package", "tor", "tpm", "swtpm"],
        macos_packs=["main", "swift", "tpm"],
        windows_packs=["main", "winkey", "windows-wheel"],
        windows_modules=inventory["native_modules"],
    )
    return p


def final_evidence():
    tool = evidence_tool()
    p = final_policy()
    # Independent complete step lists catch missing pack mappings or omitted workers.
    manifests = [
        tool.build_worker(
            p,
            "linux",
            "3.11",
            successful_steps(
                "install",
                "mypy",
                "pytest",
                "ruff",
                "shellcheck",
                "status",
                "feature_install",
                "feature_imports",
                "feature_tests",
                "floor_install",
                "floor_guard",
                "floor_tests",
                "package_build",
                "package_smoke",
                "integration_install",
                "docker_verify",
                "tor_build",
                "tor_tests",
                "tpm_system",
                "rust_tools",
                "tpm_fmt",
                "tpm_clippy",
                "tpm_test",
                "tpm_msrv",
                "swtpm_start",
                "swtpm_rust",
                "swtpm_python",
            ),
            actual_python="3.11",
        ),
        tool.build_worker(p, "linux", "3.13", successful_steps("install", "mypy", "pytest"), actual_python="3.13"),
        tool.build_worker(
            p,
            "macos",
            "3.11",
            successful_steps(
                "install",
                "mypy",
                "pytest",
                "status",
                "swift_info",
                "swift_build",
                "rust_tools",
                "tpm_fmt",
                "tpm_clippy",
                "tpm_test",
            ),
            actual_python="3.11",
        ),
        tool.build_worker(
            p,
            "windows",
            "3.11",
            successful_steps(
                "install",
                "private_home",
                "native",
                "winkey_fmt",
                "winkey_clippy",
                "winkey_test",
                "winkey_msrv_install",
                "winkey_msrv_test",
                "winkey_python",
                "wheel",
            ),
            actual_python="3.11",
        ),
    ]
    jobs = needs()
    jobs["macos"]["result"] = jobs["windows-private-fs"]["result"] = "success"
    return tool.accept(p, manifests, jobs, {})


def test_final_requires_both_linux_versions_and_every_support_pack():
    tool = evidence_tool()
    evidence = final_evidence()
    assert evidence["accepted"] is True
    assert [(w["os"], w["python"]) for w in evidence["workers"]] == [
        ("linux", "3.11"),
        ("linux", "3.13"),
        ("macos", "3.11"),
        ("windows", "3.11"),
    ]
    for index in range(4):
        damaged = copy.deepcopy(evidence)
        damaged["workers"].pop(index)
        with pytest.raises(ValueError):
            tool.validate_acceptance(damaged)
    for os_name, pack in [
        ("linux", "features"),
        ("linux", "floor"),
        ("linux", "package"),
        ("linux", "tor"),
        ("linux", "tpm"),
        ("linux", "swtpm"),
        ("macos", "swift"),
        ("macos", "tpm"),
        ("windows", "winkey"),
        ("windows", "windows-wheel"),
    ]:
        damaged = copy.deepcopy(evidence)
        manifest = next(w for w in damaged["workers"] if w["os"] == os_name)
        del manifest["packs"][pack]
        with pytest.raises(ValueError):
            tool.validate_acceptance(damaged)


def archive(evidence, name="evidence.json"):
    import io
    import zipfile

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr(name, json.dumps(evidence))
    return stream.getvalue()


def api_fixture(evidence):
    p = evidence["policy"]
    run = {
        "id": 42,
        "run_attempt": 2,
        "path": ".github/workflows/ci.yml",
        "event": p["event_name"],
        "head_sha": p["tested_sha"],
        "head_branch": "dev",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": "owner/repo"},
        "run_started_at": "2026-10-12T00:00:00Z",
    }
    artifacts = [
        {
            "id": 19,
            "name": "ci-acceptance-evidence-42-2",
            "expired": False,
            "size_in_bytes": 5000,
            "workflow_run": {"id": 42, "head_sha": SHA, "head_branch": "dev"},
            "created_at": "2026-10-12T00:10:00Z",
        }
    ]
    names = ["ci-policy", "linux (3.11)", "linux (3.13)", "macos", "windows-private-fs", "CI acceptance"]
    if p["mode"] != "final":
        names = ["ci-policy", "linux (3.12)", "CI acceptance"]
    jobs = [
        {
            "id": index,
            "run_id": 42,
            "run_attempt": 2,
            "head_sha": SHA,
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "completed_at": "2026-10-12T00:11:00Z",
        }
        for index, name in enumerate(names, 1)
    ]
    responses = {
        "actions/workflows/ci.yml/runs?head_sha=" + SHA + "&branch=dev&per_page=100&page=1": {
            "total_count": 1,
            "workflow_runs": [run],
        },
        "actions/runs/42/attempts/2": run,
        "actions/runs/42/attempts/2/jobs?per_page=100&page=1": {"total_count": len(jobs), "jobs": jobs},
        "actions/runs/42/artifacts?per_page=100&page=1": {"total_count": 1, "artifacts": artifacts},
        "actions/artifacts/19/zip": archive(evidence),
    }
    return responses


def install_api(monkeypatch, checker, responses):
    def request(self, path, *, binary=False):
        value = responses[path]
        if isinstance(value, Exception):
            raise value
        assert binary == isinstance(value, bytes)
        return copy.deepcopy(value)

    monkeypatch.setattr(checker.GitHub, "request", request)


def test_remote_final_evidence_accepts_exact_selected_branch(monkeypatch):
    checker = checker_tool()
    install_api(monkeypatch, checker, api_fixture(final_evidence()))
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is True
    assert checker.main(["--repo", "owner/repo", "--sha", SHA, "--branch", "dev"]) == 0


def test_ordinary_is_eligible_only_for_baseline_not_release(monkeypatch):
    tool = evidence_tool()
    checker = checker_tool()
    evidence = tool.accept(policy(), [worker(tool)], needs(), {})
    install_api(monkeypatch, checker, api_fixture(evidence))
    assert checker.has_ci_evidence("owner/repo", SHA, "dev", "ordinary") is True
    assert checker.has_ci_evidence("owner/repo", SHA, "dev", "final") is False
    assert checker.main(["--repo", "owner/repo", "--sha", SHA, "--branch", "dev"]) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "sha",
        "branch",
        "workflow",
        "event",
        "run_failed",
        "run_cancelled",
        "attempt",
        "acceptance_skipped",
        "linux_missing",
        "linux_failed",
        "job_attempt",
        "job_sha",
        "artifact_attempt",
        "artifact_sha",
        "expired",
        "duplicate_artifact",
        "zip_path",
        "zip_invalid",
        "oversized",
        "api_failure",
        "missing_pagination",
    ],
)
def test_remote_rejects_cheap_stale_missing_or_untrusted_evidence(monkeypatch, mutation):
    checker = checker_tool()
    evidence = final_evidence()
    responses = api_fixture(evidence)
    run = responses["actions/runs/42/attempts/2"]
    jobs_page = responses["actions/runs/42/attempts/2/jobs?per_page=100&page=1"]
    artifacts_page = responses["actions/runs/42/artifacts?per_page=100&page=1"]
    artifact = artifacts_page["artifacts"][0]
    if mutation in ("sha", "branch", "workflow", "event", "run_failed", "run_cancelled", "attempt"):
        key, value = {
            "sha": ("head_sha", "b" * 40),
            "branch": ("head_branch", "main"),
            "workflow": ("path", ".github/workflows/fake.yml"),
            "event": ("event", "pull_request"),
            "run_failed": ("conclusion", "failure"),
            "run_cancelled": ("conclusion", "cancelled"),
            "attempt": ("run_attempt", 1),
        }[mutation]
        run[key] = value
    elif mutation == "acceptance_skipped":
        jobs_page["jobs"][-1]["conclusion"] = "skipped"
    elif mutation == "linux_missing":
        jobs_page["jobs"].pop(2)
        jobs_page["total_count"] -= 1
    elif mutation == "linux_failed":
        jobs_page["jobs"][2]["conclusion"] = "failure"
    elif mutation == "job_attempt":
        jobs_page["jobs"][2]["run_attempt"] = 1
    elif mutation == "job_sha":
        jobs_page["jobs"][2]["head_sha"] = "b" * 40
    elif mutation == "artifact_attempt":
        artifact["name"] = "ci-acceptance-evidence-42-1"
    elif mutation == "artifact_sha":
        artifact["workflow_run"]["head_sha"] = "b" * 40
    elif mutation == "expired":
        artifact["expired"] = True
    elif mutation == "duplicate_artifact":
        artifacts_page["artifacts"].append(copy.deepcopy(artifact))
        artifacts_page["total_count"] += 1
    elif mutation == "zip_path":
        responses["actions/artifacts/19/zip"] = archive(evidence, "../evidence.json")
    elif mutation == "zip_invalid":
        responses["actions/artifacts/19/zip"] = b"not a ZIP"
    elif mutation == "oversized":
        artifact["size_in_bytes"] = 100_000_000
    elif mutation == "api_failure":
        responses["actions/runs/42/artifacts?per_page=100&page=1"] = OSError("offline")
    else:
        jobs_page["total_count"] = 1000
    install_api(monkeypatch, checker, responses)
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is False


@pytest.mark.parametrize("kind", ["worker_schema", "worker_attempt", "acceptance_schema"])
def test_boolean_numbers_are_not_valid_schema_or_run_identity(kind):
    tool = evidence_tool()
    p = policy()
    p["run_attempt"] = 1
    evidence = tool.accept(p, [worker(tool, p)], needs(), {})
    if kind == "worker_schema":
        evidence["workers"][0]["schema_version"] = True
    elif kind == "worker_attempt":
        evidence["workers"][0]["context"]["run_attempt"] = True
    else:
        evidence["schema_version"] = True
    with pytest.raises(ValueError):
        tool.validate_acceptance(evidence)


def test_policy_loader_validates_before_returning_paths(tmp_path):
    tool = evidence_tool()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy()))
    assert tool.load_policy(path)["linux_versions"] == ["3.12"]
    damaged = policy()
    damaged["windows_modules"] = ["; echo untrusted"]
    path.write_text(json.dumps(damaged))
    with pytest.raises(ValueError):
        tool.load_policy(path)


def test_remote_collects_all_pages_before_accepting_artifact(monkeypatch):
    checker = checker_tool()
    responses = api_fixture(final_evidence())
    original = responses["actions/runs/42/artifacts?per_page=100&page=1"]["artifacts"]
    other = [{"id": index + 100, "name": "unrelated"} for index in range(100)]
    responses["actions/runs/42/artifacts?per_page=100&page=1"] = {"total_count": 101, "artifacts": other}
    responses["actions/runs/42/artifacts?per_page=100&page=2"] = {"total_count": 101, "artifacts": original}
    install_api(monkeypatch, checker, responses)
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is True
    responses["actions/runs/42/artifacts?per_page=100&page=2"] = OSError("page 2 unavailable")
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is False


@pytest.mark.parametrize("mutation", ["count_changed", "duplicate", "negative_count", "over_limit"])
def test_api_pagination_never_accepts_partial_or_duplicate_data(monkeypatch, mutation):
    checker = checker_tool()
    first = [{"id": index + 1} for index in range(100)]
    second = [{"id": 101}]
    responses = {
        "items?per_page=100&page=1": {"total_count": 101, "items": first},
        "items?per_page=100&page=2": {"total_count": 101, "items": second},
    }
    if mutation == "count_changed":
        responses["items?per_page=100&page=2"]["total_count"] = 102
    elif mutation == "duplicate":
        second[0]["id"] = 1
    else:
        responses["items?per_page=100&page=1"]["total_count"] = -1 if mutation == "negative_count" else 1001
    install_api(monkeypatch, checker, responses)
    with pytest.raises(ValueError):
        checker.GitHub("owner/repo").pages("items", "items")


def test_archive_and_response_bounds_are_enforced_without_extraction(tmp_path, monkeypatch):
    import io
    import zipfile

    checker = checker_tool()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        checker.bounded_read(io.BytesIO(b"123456"), 5)
    huge = io.BytesIO()
    with zipfile.ZipFile(huge, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("evidence.json", " " * (1024 * 1024 + 1))
    with pytest.raises(ValueError):
        checker.archive_evidence(huge.getvalue())
    with pytest.raises(ValueError):
        checker.archive_evidence(archive({}, "../evidence.json"))
    assert list(tmp_path.iterdir()) == []


def test_cross_host_artifact_redirect_strips_authorization():
    from urllib.request import Request

    checker = checker_tool()
    request = Request(
        "https://api.github.com/repos/owner/repo/actions/artifacts/1/zip", headers={"Authorization": "Bearer synthetic"}
    )
    redirected = checker.SafeRedirect().redirect_request(
        request, None, 302, "Found", {}, "https://storage.example.test/artifact.zip"
    )
    assert redirected.get_header("Authorization") is None
    with pytest.raises(ValueError):
        checker.SafeRedirect().redirect_request(
            request, None, 302, "Found", {}, "http://storage.example.test/artifact.zip"
        )


@pytest.mark.parametrize("mode", ["critical", "docs"])
def test_feedback_and_docs_can_never_be_branch_baselines(monkeypatch, mode):
    tool = evidence_tool()
    checker = checker_tool()
    p = policy(mode)
    jobs = needs()
    workers = [worker(tool, p)] if mode == "critical" else []
    if mode == "docs":
        p.update(linux_versions=[], linux_packs=[])
        jobs["linux"]["result"] = "skipped"
    evidence = tool.accept(p, workers, jobs, successful_steps("docs_tests"))
    install_api(monkeypatch, checker, api_fixture(evidence))
    assert checker.has_ci_evidence("owner/repo", SHA, "dev", "ordinary") is False


def test_manual_final_branch_run_is_eligible_without_individual_job_attempt_fields(monkeypatch):
    checker = checker_tool()
    evidence = final_evidence()
    evidence["policy"]["event_name"] = "workflow_dispatch"
    for manifest in evidence["workers"]:
        manifest["context"]["event_name"] = "workflow_dispatch"
    responses = api_fixture(evidence)
    for job in responses["actions/runs/42/attempts/2/jobs?per_page=100&page=1"]["jobs"]:
        del job["run_attempt"]
    install_api(monkeypatch, checker, responses)
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is True


@pytest.mark.parametrize("created", ["2026-10-11T23:59:59Z", "2026-10-12T00:11:01Z", None])
def test_artifact_creation_must_be_inside_successful_attempt(monkeypatch, created):
    checker = checker_tool()
    responses = api_fixture(final_evidence())
    responses["actions/runs/42/artifacts?per_page=100&page=1"]["artifacts"][0]["created_at"] = created
    install_api(monkeypatch, checker, responses)
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_SHA", "b" * 40),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/fake.yml@refs/heads/dev"),
    ],
)
def test_live_github_environment_must_match_policy(field, value):
    tool = evidence_tool()
    environ = {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/heads/dev",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/heads/dev",
    }
    tool.validate_environment(policy(), environ)
    environ[field] = value
    with pytest.raises(ValueError):
        tool.validate_environment(policy(), environ)


def test_pr_base_change_invalidates_same_head_and_merge_context(tmp_path):
    tool = evidence_tool()
    p = policy()
    p.update(
        event_name="pull_request",
        ref="refs/pull/7/merge",
        pr={"number": 7, "head_sha": "b" * 40, "base_sha": "c" * 40, "merge_sha": SHA},
    )
    event_path = tmp_path / "event.json"
    event = {
        "number": 7,
        "pull_request": {"head": {"sha": "b" * 40}, "base": {"sha": "c" * 40}, "merge_commit_sha": SHA},
    }
    event_path.write_text(json.dumps(event))
    environ = {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/pull/7/merge",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/pull/7/merge",
        "GITHUB_EVENT_PATH": str(event_path),
    }
    tool.validate_environment(p, environ)
    event["pull_request"]["base"]["sha"] = "d" * 40
    event_path.write_text(json.dumps(event))
    with pytest.raises(ValueError):
        tool.validate_environment(p, environ)


def test_worker_cli_checks_real_interpreter_before_writing(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    tool = evidence_tool()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy()))
    output = tmp_path / "worker.json"
    for key, value in {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/heads/dev",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/heads/dev",
        "CI_STEPS_JSON": json.dumps(linux_steps()),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "version_info", SimpleNamespace(major=3, minor=11))
    args = ["worker", "--policy", str(path), "--os", "linux", "--python", "3.12", "--output", str(output)]
    assert tool.main(args) == 1
    assert not output.exists()
    monkeypatch.setattr(sys, "version_info", SimpleNamespace(major=3, minor=12))
    assert tool.main(args) == 0
    assert json.loads(output.read_text())["actual_python"] == "3.12"


def test_http_client_bounds_actual_response_reads(monkeypatch):
    import io
    from types import SimpleNamespace

    checker = checker_tool()
    opener = SimpleNamespace(open=lambda request, timeout: io.BytesIO(b" " * (4 * 1024 * 1024 + 1)))
    monkeypatch.setattr(checker, "build_opener", lambda handler: opener)
    with pytest.raises(ValueError):
        checker.GitHub("owner/repo").request("actions/runs")


def test_final_policy_cannot_drop_native_modules_or_support_packs():
    tool = evidence_tool()
    p = final_policy()
    p["windows_modules"].pop()
    with pytest.raises(ValueError):
        tool.validate_policy(p)
    for os_name in ("linux", "macos", "windows"):
        p = final_policy()
        p[f"{os_name}_packs"].pop()
        with pytest.raises(ValueError):
            tool.validate_policy(p)


def test_partial_native_family_cannot_claim_ordinary_acceptance():
    tool = evidence_tool()
    p = policy()
    p.update(windows=True, windows_packs=["main"], windows_modules=["tests/test_network_windows_policy.py"])
    with pytest.raises(ValueError):
        tool.validate_policy(p)


def test_corrupt_deflate_data_fails_closed(monkeypatch):
    checker = checker_tool()
    responses = api_fixture(final_evidence())
    raw = bytearray(responses["actions/artifacts/19/zip"])
    raw[30 + len("evidence.json")] = 255  # Invalid deflate block type, inside a valid ZIP directory.
    responses["actions/artifacts/19/zip"] = bytes(raw)
    install_api(monkeypatch, checker, responses)
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is False


def test_complete_ordinary_native_family_and_wheel_only_scope_are_valid():
    tool = evidence_tool()
    native = json.loads((ROOT / "tools/ci_scope_paths.json").read_text())["native_modules"]
    network = [name for name in native if name.startswith("tests/test_network_windows_")]
    assert len(network) > 1
    p = policy()
    p.update(windows=True, windows_packs=["main"], windows_modules=network)
    assert ("windows", "3.12") in tool.expected_workers(p)
    p.update(windows_packs=["main", "windows-wheel"], windows_modules=[])
    tool.validate_policy(p)


@pytest.mark.parametrize("field,value", [("ref", "refs/heads/main"), ("tested_sha", "b" * 40), ("run_attempt", 1)])
def test_artifact_claims_must_match_external_run_metadata(monkeypatch, field, value):
    checker = checker_tool()
    evidence = final_evidence()
    responses = api_fixture(evidence)
    evidence["policy"][field] = value
    for manifest in evidence["workers"]:
        manifest["context"][field] = value
    responses["actions/artifacts/19/zip"] = archive(evidence)
    install_api(monkeypatch, checker, responses)
    assert checker.has_ci_evidence("owner/repo", SHA, "dev") is False


def test_acceptance_cli_writes_complete_manifest_only_after_validation(tmp_path, monkeypatch):
    tool = evidence_tool()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy()))
    directory = tmp_path / "workers" / "ci-worker-evidence-linux-3.12-42-2"
    directory.mkdir(parents=True)
    (directory / "worker.json").write_text(json.dumps(worker(tool)))
    output = tmp_path / "evidence.json"
    for key, value in {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/heads/dev",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/heads/dev",
        "CI_NEEDS_JSON": json.dumps(needs()),
        "CI_STEPS_JSON": "{}",
    }.items():
        monkeypatch.setenv(key, value)
    assert (
        tool.main(["accept", "--policy", str(path), "--workers", str(directory.parent), "--output", str(output)]) == 0
    )
    evidence = json.loads(output.read_text())
    assert evidence["accepted"] is True
    assert tool.validate_acceptance(evidence)["tested_sha"] == SHA


def pr_event_context(tmp_path):
    p = policy()
    p.update(
        event_name="pull_request",
        ref="refs/pull/7/merge",
        pr={"number": 7, "head_sha": "b" * 40, "base_sha": "c" * 40, "merge_sha": SHA},
    )
    event = {
        "number": 7,
        "pull_request": {"head": {"sha": "b" * 40}, "base": {"sha": "c" * 40}, "merge_commit_sha": None},
    }
    environ = {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_SHA": SHA,
        "GITHUB_REF": "refs/pull/7/merge",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/pull/7/merge",
        "GITHUB_EVENT_PATH": str(tmp_path / "event.json"),
    }
    return p, event, environ


@pytest.mark.parametrize("raw_merge", [None, "missing", SHA, "d" * 40])
def test_pr_event_merge_field_is_advisory_when_policy_matches_github_sha(tmp_path, raw_merge):
    tool = evidence_tool()
    p, event, environ = pr_event_context(tmp_path)
    if raw_merge == "missing":
        del event["pull_request"]["merge_commit_sha"]
    else:
        event["pull_request"]["merge_commit_sha"] = raw_merge
    Path(environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(event))
    tool.validate_policy(p)
    tool.validate_environment(p, environ)
    assert p["pr"]["merge_sha"] == SHA


@pytest.mark.parametrize(
    "mutation",
    ["head", "base", "number", "policy_merge", "github_sha", "workflow", "ref"],
)
@pytest.mark.parametrize("raw_merge", [None, "d" * 40])
def test_advisory_pr_merge_does_not_relax_other_provenance_checks(tmp_path, mutation, raw_merge):
    tool = evidence_tool()
    p, event, environ = pr_event_context(tmp_path)
    event["pull_request"]["merge_commit_sha"] = raw_merge
    if mutation in ("head", "base"):
        event["pull_request"][mutation]["sha"] = "d" * 40
    elif mutation == "number":
        event["number"] = 8
    elif mutation == "policy_merge":
        p["pr"]["merge_sha"] = "d" * 40
    elif mutation == "github_sha":
        environ["GITHUB_SHA"] = "d" * 40
    elif mutation == "workflow":
        environ["GITHUB_WORKFLOW_REF"] = "owner/repo/.github/workflows/other.yml@refs/pull/7/merge"
    else:
        environ["GITHUB_REF"] = "refs/pull/8/merge"
    Path(environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(event))
    with pytest.raises(ValueError):
        tool.validate_environment(p, environ)


@pytest.mark.parametrize("raw_merge", ["", "not-a-sha", "g" * 40, [], {}, True])
def test_malformed_nonnull_pr_merge_metadata_is_rejected(tmp_path, raw_merge):
    tool = evidence_tool()
    p, event, environ = pr_event_context(tmp_path)
    event["pull_request"]["merge_commit_sha"] = raw_merge
    Path(environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(event))
    with pytest.raises(ValueError):
        tool.validate_environment(p, environ)
