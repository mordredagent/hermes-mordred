#!/usr/bin/env python3
"""Fail closed unless an exact branch commit has accepted CI evidence.

Only ci.yml push/dispatch runs can provide branch evidence. The acceptance
manifest, actual attempt jobs, and artifact provenance must all agree.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from typing import IO, Any
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_evidence import (
    MAX_JSON_BYTES,
    WORKFLOW,
    Json,
    expected_workers,
    parse_json,
    require,
    validate_acceptance,
    worker_job_name,
)

MAX_API_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 1000


class SafeRedirect(HTTPRedirectHandler):
    """Artifact redirects must not forward a GitHub token to storage hosts."""

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Request | None:
        require(urlparse(newurl).scheme == "https", "refusing non-HTTPS redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urlparse(newurl).netloc != urlparse(req.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


def bounded_read(stream: IO[bytes], limit: int) -> bytes:
    raw = stream.read(limit + 1)
    require(len(raw) <= limit, "response exceeds size limit")
    return raw


class GitHub:
    def __init__(self, repo: str) -> None:
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is not None, "invalid repository")
        self.base = f"https://api.github.com/repos/{repo}/"
        self.token = os.environ.get("GH_TOKEN", "")

    def request(self, path: str, *, binary: bool = False) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hermes-mordred-ci-evidence",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(self.base + path, headers=headers)
        with build_opener(SafeRedirect()).open(request, timeout=30) as response:
            raw = bounded_read(response, MAX_ARCHIVE_BYTES if binary else MAX_API_BYTES)
        if binary:
            return raw
        # API pages have a separate (larger) bound from the tiny evidence file.
        require(len(raw) <= MAX_API_BYTES, "API response exceeds size limit")
        return parse_json(raw)  # The stricter JSON bound is intentionally fail-closed.

    def pages(self, path: str, key: str) -> list[Json]:
        items: list[Json] = []
        total: int | None = None
        separator = "&" if "?" in path else "?"
        for page in range(1, MAX_ITEMS // 100 + 1):
            data = self.request(f"{path}{separator}per_page=100&page={page}")
            require(isinstance(data, dict), "invalid API page")
            count = data.get("total_count")
            require(type(count) is int and 0 <= count <= MAX_ITEMS, "invalid or excessive API count")
            require(total is None or count == total, "API count changed during pagination")
            total = count
            batch = data.get(key)
            require(isinstance(batch, list) and all(isinstance(item, dict) for item in batch), "invalid API items")
            require(len(batch) <= 100, "oversized API page")
            items.extend(batch)
            require(len(items) <= total, "API count does not match items")
            if len(items) == total:
                ids = [item.get("id") for item in items]
                require(
                    all(type(identifier) is int and identifier > 0 for identifier in ids), "invalid API item identity"
                )
                require(len(ids) == len(set(ids)), "duplicate API items")
                return items
            require(len(batch) == 100, "incomplete API page")
        raise ValueError("incomplete API pagination")


def archive_evidence(raw: bytes) -> Json:
    require(len(raw) <= MAX_ARCHIVE_BYTES, "archive exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 1 and entries[0].filename == "evidence.json", "unexpected archive entries")
        entry = entries[0]
        require(
            not entry.is_dir() and entry.file_size <= MAX_JSON_BYTES and not entry.flag_bits & 1,
            "invalid archive entry",
        )
        require((entry.external_attr >> 16) & 0o170000 != 0o120000, "symlink archive entry")
        with archive.open(entry) as stream:
            return parse_json(bounded_read(stream, MAX_JSON_BYTES))


def _matches_run(run: Json, repo: str, sha: str, branch: str) -> bool:
    return (
        run.get("path") == WORKFLOW
        and run.get("event") in ("push", "workflow_dispatch")
        and run.get("head_sha") == sha
        and run.get("head_branch") == branch
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and isinstance(run.get("repository"), dict)
        and run["repository"].get("full_name") == repo
    )


def _timestamp(value: Any) -> datetime:
    require(isinstance(value, str), "missing provenance timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "timestamp has no timezone")
    return result


def _check_jobs(jobs: list[Json], policy: Json) -> Json:
    required = {"ci-policy", "CI acceptance"}
    for identity in expected_workers(policy):
        required.add(worker_job_name(*identity))
    by_name = {job.get("name"): job for job in jobs}
    require(len(by_name) == len(jobs), "duplicate job names")
    require(required <= by_name.keys(), "missing required GitHub jobs")
    optional = {"macos", "windows-private-fs", "linux-floor"} - required
    require(set(by_name) <= required | optional, "unexpected GitHub jobs")
    for name, job in by_name.items():
        require(
            job.get("run_id") == policy["run_id"] and job.get("head_sha") == policy["tested_sha"],
            "job run/SHA mismatch",
        )
        # The attempt-specific endpoint is authoritative; older API schemas omit
        # run_attempt on individual job objects. If supplied it must agree too.
        require(job.get("run_attempt", policy["run_attempt"]) == policy["run_attempt"], "job attempt mismatch")
        result = "success" if name in required else "skipped"
        require(
            job.get("status") == "completed" and job.get("conclusion") == result, f"unsuccessful GitHub job: {name}"
        )
    return dict(by_name["CI acceptance"])


def _artifact(api: GitHub, run: Json, sha: str, branch: str) -> tuple[Json, Json]:
    artifacts = api.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
    name = f"ci-acceptance-evidence-{run['id']}-{run['run_attempt']}"
    matching = [artifact for artifact in artifacts if artifact.get("name") == name]
    require(len(matching) == 1, "missing or duplicate acceptance artifact")
    artifact = matching[0]
    require(artifact.get("expired") is False, "expired artifact")
    size = artifact.get("size_in_bytes")
    require(type(size) is int and 0 < size <= MAX_ARCHIVE_BYTES, "invalid artifact size")
    provenance: Any = artifact.get("workflow_run")
    require(isinstance(provenance, dict), "missing artifact provenance")
    require(
        provenance.get("id") == run["id"]
        and provenance.get("head_sha") == sha
        and provenance.get("head_branch") == branch,
        "artifact provenance mismatch",
    )
    raw = api.request(f"actions/artifacts/{artifact['id']}/zip", binary=True)
    require(isinstance(raw, bytes), "invalid archive response")
    return artifact, archive_evidence(raw)


def _verify_run(api: GitHub, listed: Json, repo: str, sha: str, branch: str, minimum_mode: str) -> bool:
    attempt = listed.get("run_attempt")
    require(type(attempt) is int and attempt > 0, "invalid run attempt")
    run = api.request(f"actions/runs/{listed['id']}/attempts/{attempt}")
    require(isinstance(run, dict) and _matches_run(run, repo, sha, branch), "attempt metadata mismatch")
    require(run.get("id") == listed["id"] and run.get("run_attempt") == attempt, "attempt identity mismatch")
    artifact, evidence = _artifact(api, run, sha, branch)
    policy = validate_acceptance(evidence)
    allowed = ("final",) if minimum_mode == "final" else ("ordinary", "final")
    if evidence["accepted"] is not True or policy["mode"] not in allowed:
        return False
    if minimum_mode == "final" and policy["windows_test_tier"] != "full":
        return False
    expected = {
        "repository": repo,
        "tested_sha": sha,
        "ref": f"refs/heads/{branch}",
        "event_name": run["event"],
        "run_id": run["id"],
        "run_attempt": attempt,
        "pr": None,
    }
    require(all(policy[key] == value for key, value in expected.items()), "evidence context mismatch")
    jobs = api.pages(f"actions/runs/{run['id']}/attempts/{attempt}/jobs", "jobs")
    acceptance = _check_jobs(jobs, policy)
    created = _timestamp(artifact.get("created_at"))
    require(
        _timestamp(run.get("run_started_at")) <= created <= _timestamp(acceptance.get("completed_at")),
        "artifact was not produced during this attempt",
    )
    return True


def has_ci_evidence(repo: str, sha: str, branch: str, minimum_mode: str = "final") -> bool:
    """Return False on missing, incomplete, malformed, stale or unavailable evidence."""
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "invalid SHA")
        require(
            bool(branch) and not branch.startswith("refs/") and not any(ord(c) < 32 for c in branch), "invalid branch"
        )
        require(minimum_mode in ("ordinary", "final"), "invalid minimum mode")
        api = GitHub(repo)
        query = urlencode({"head_sha": sha, "branch": branch})
        runs = api.pages(f"actions/workflows/ci.yml/runs?{query}", "workflow_runs")
        for run in runs:
            if _matches_run(run, repo, sha, branch) and _verify_run(api, run, repo, sha, branch, minimum_mode):
                return True
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        zipfile.BadZipFile,
        zlib.error,
        EOFError,
        RuntimeError,
    ):
        # This function is also used by routing: any uncertainty selects final.
        return False
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--minimum-mode", choices=("ordinary", "final"), default="final")
    args = parser.parse_args(argv)
    if not has_ci_evidence(args.repo, args.sha, args.branch, args.minimum_mode):
        print(f"No validated {args.minimum_mode} CI evidence for {args.repo} {args.branch}@{args.sha}", file=sys.stderr)
        return 1
    print(f"Validated {args.minimum_mode} CI evidence for {args.repo} {args.branch}@{args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
