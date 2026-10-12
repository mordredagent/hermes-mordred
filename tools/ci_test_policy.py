#!/usr/bin/env python3
"""Select explicit CI worker/check packs, conservatively defaulting to final."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

# Hermes itself ships a `tools` package. Load these repository siblings directly
# so both file-based imports and the stdlib-only CLI work outside the checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_change_scope import (
    REPOSITORY,
    ROOT,
    SHA,
    Scope,
    classify_changes,
    final_scope,
    github_json,
    native_modules,
    pull_request_changes,
    push_changes,
)

DRAFT_ACTIONS = {"opened", "synchronize", "reopened", "converted_to_draft"}
PR_ACTIONS = DRAFT_ACTIONS | {"ready_for_review"}
FINAL_LINUX_PACKS = ["main", "static", "features", "floor", "package", "tor", "tpm", "swtpm"]
FINAL_MACOS_PACKS = ["main", "swift", "tpm"]
FINAL_WINDOWS_PACKS = ["main", "winkey", "windows-wheel"]
OUTPUT_KEYS = (
    "mode",
    "linux_versions",
    "platform_python",
    "support_python",
    "macos",
    "windows",
    "linux_packs",
    "macos_packs",
    "windows_packs",
    "windows_modules",
)


def accepted_baseline(repository: str, sha: str, branch: str, minimum_mode: str = "ordinary") -> bool:
    # Lazy import avoids a checker/policy dependency cycle and avoids an API
    # dependency for forced-final events. Missing checker is not acceptance.
    from check_ci_evidence import has_ci_evidence

    return has_ci_evidence(repository, sha, branch, minimum_mode=minimum_mode)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise ValueError("run identifiers must be positive")
    return number


def _pr_context(event: Mapping[str, object]) -> dict[str, object] | None:
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        return None
    head, base = pr.get("head"), pr.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        return None
    return {
        "number": pr.get("number"),
        "head_sha": head.get("sha"),
        "base_sha": base.get("sha"),
        "merge_sha": pr.get("merge_commit_sha"),
    }


def _pr_mode(
    event: Mapping[str, object], env: Mapping[str, str], get_json: Callable[[str], object]
) -> tuple[str, Scope]:
    pr = event.get("pull_request")
    action = event.get("action")
    if not isinstance(pr, dict) or not isinstance(action, str) or action not in PR_ACTIONS:
        return "final", final_scope("unknown PR metadata or event action")
    base = pr.get("base")
    labels = pr.get("labels")
    if (
        not isinstance(base, dict)
        or base.get("ref") not in {"dev", "main"}
        or type(pr.get("draft")) is not bool
        or not isinstance(labels, list)
        or not all(isinstance(label, dict) and isinstance(label.get("name"), str) for label in labels)
    ):
        return "final", final_scope("incomplete PR policy metadata")
    if base["ref"] == "main" or any(label["name"] == "ci:full" for label in labels):
        return "final", final_scope("main-target PR or explicit ci:full override")
    number = pr.get("number")
    if (
        type(number) is not int
        or number < 1
        or event.get("number") != number
        or env.get("GITHUB_REF") != f"refs/pull/{number}/merge"
        or pr.get("merge_commit_sha") != env.get("GITHUB_SHA")
    ):
        return "final", final_scope("PR tested merge context does not match the event")
    if pr["draft"] and action not in DRAFT_ACTIONS:
        return "final", final_scope("inconsistent draft event")
    changes = pull_request_changes(env["GITHUB_REPOSITORY"], pr, get_json=get_json)
    scope = classify_changes(changes)
    if pr["draft"]:
        return "critical", scope
    return ("final" if scope.final else "docs" if scope.docs else "ordinary"), scope


def _push_mode(
    event: Mapping[str, object], env: Mapping[str, str], baseline_check: Callable[..., bool], root: Path
) -> tuple[str, Scope]:
    if env.get("GITHUB_REF") != "refs/heads/dev" or event.get("ref") != "refs/heads/dev":
        return "final", final_scope("non-dev branch push")
    before, after = event.get("before"), event.get("after")
    if (
        any(event.get(flag) is not False for flag in ("forced", "created", "deleted"))
        or not isinstance(before, str)
        or not SHA.fullmatch(before)
        or before == "0" * 40
        or not isinstance(after, str)
        or after != env.get("GITHUB_SHA")
    ):
        return "final", final_scope("initial, forced or incomplete push context")
    # Read the exact complete ancestry range before asking whether that exact
    # baseline was accepted. Nearby successful commits are never substituted.
    changes = push_changes(before, after, root=root)
    if not baseline_check(env["GITHUB_REPOSITORY"], before, "dev", minimum_mode="ordinary"):
        return "final", final_scope("exact before SHA lacks trusted acceptance")
    scope = classify_changes(changes)
    return ("final" if scope.final else "ordinary"), scope


def build_policy(
    event_name: str,
    event: Mapping[str, object],
    *,
    env: Mapping[str, str] | None = None,
    get_json: Callable[[str], object] = github_json,
    baseline_check: Callable[..., bool] = accepted_baseline,
    root: Path = ROOT,
) -> dict[str, object]:
    """Resolve scope from complete event context; unavailable evidence is final."""
    context = os.environ if env is None else env
    mode, scope = "final", final_scope("manual or unrecognized event requires final validation")
    try:
        if (
            not REPOSITORY.fullmatch(context.get("GITHUB_REPOSITORY", ""))
            or not SHA.fullmatch(context.get("GITHUB_SHA", ""))
            or context.get("GITHUB_EVENT_NAME") != event_name
        ):
            scope = final_scope("invalid workflow provenance")
        elif event_name == "pull_request":
            mode, scope = _pr_mode(event, context, get_json)
        elif event_name == "push":
            mode, scope = _push_mode(event, context, baseline_check, root)
    except (ValueError, OSError, TypeError, KeyError, ImportError, subprocess.SubprocessError):
        mode, scope = "final", final_scope("complete scope or trusted baseline unavailable")
    final = mode == "final"
    docs = mode == "docs"
    critical = mode == "critical"
    macos = not docs and (final or scope.macos)
    windows = not docs and (final or scope.final or bool(scope.families) or bool(scope.windows_packs))
    version = "3.11" if final else "3.12"
    linux_packs = (
        FINAL_LINUX_PACKS.copy()
        if final
        else []
        if docs
        else ["main", "static", *(() if critical else scope.linux_packs)]
    )
    return {
        "schema_version": 1,
        "mode": mode,
        "repository": context.get("GITHUB_REPOSITORY", ""),
        "workflow_path": ".github/workflows/ci.yml",
        "event_name": event_name,
        "ref": context.get("GITHUB_REF", ""),
        "tested_sha": context.get("GITHUB_SHA", ""),
        "run_id": _positive_int(context.get("GITHUB_RUN_ID", "0")),
        "run_attempt": _positive_int(context.get("GITHUB_RUN_ATTEMPT", "0")),
        "pr": _pr_context(event) if event_name == "pull_request" else None,
        "linux_versions": ["3.11", "3.13"] if final else [] if docs else ["3.12"],
        "platform_python": version,
        "support_python": version,
        "macos": macos,
        "windows": windows,
        "linux_packs": linux_packs,
        "macos_packs": FINAL_MACOS_PACKS.copy() if final else ["main"] if macos else [],
        "windows_packs": FINAL_WINDOWS_PACKS.copy()
        if final
        else ["main", *(() if critical else scope.windows_packs)]
        if windows
        else [],
        "windows_modules": list(native_modules()) if final else [] if critical else list(scope.windows_modules),
        "reason": "draft feedback only; " + scope.reason if critical else scope.reason,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME"))
    parser.add_argument("--event-path", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    parser.add_argument("--github-output", type=Path, default=os.environ.get("GITHUB_OUTPUT"))
    parser.add_argument("--policy-file", type=Path, default=Path("ci-policy.json"))
    args = parser.parse_args(argv)
    if not args.event_name or not args.event_path:
        parser.error("event name and event path are required")
    try:
        event: object = json.loads(args.event_path.read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            parser.error("event payload must be an object")
        policy = build_policy(args.event_name, cast(dict[str, object], event))
        args.policy_file.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as stream:
                for key in OUTPUT_KEYS:
                    value = policy[key]
                    rendered = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
                    stream.write(f"{key}={rendered}\n")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"{policy['mode']}: {policy['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
