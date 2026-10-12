#!/usr/bin/env python3
"""Record blocking CI step outcomes and validate the exact selected worker set.

These manifests are claims made by ci.yml. The remote checker additionally
requires successful GitHub run/job metadata from the same run attempt.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_test_plan import exclusions_digest, exclusions_for, plan_native_modules

WORKFLOW = ".github/workflows/ci.yml"
MAX_JSON_BYTES = 1024 * 1024
CONTEXT_KEYS = (
    "schema_version",
    "mode",
    "repository",
    "workflow_path",
    "event_name",
    "ref",
    "tested_sha",
    "run_id",
    "run_attempt",
    "pr",
    "windows_shards",
    "windows_test_tier",
    "windows_exclusions_sha256",
)
POLICY_KEYS = {
    *CONTEXT_KEYS,
    "linux_versions",
    "platform_python",
    "support_python",
    "macos",
    "windows",
    "linux_packs",
    "macos_packs",
    "windows_packs",
    "windows_modules",
    "reason",
}
FINAL_PACKS = {
    "linux": ["main", "static", "features", "floor", "package", "tor", "tpm", "swtpm"],
    "macos": ["main", "swift", "tpm"],
    "windows": ["main", "winkey", "windows-wheel"],
}
PACK_STEPS = {
    "static": ("ruff", "shellcheck", "status"),
    "features": ("feature_install", "feature_imports", "feature_tests"),
    "floor": ("floor_install", "floor_guard", "floor_tests"),
    "package": ("package_build", "package_smoke"),
    "tor": ("integration_install", "docker_verify", "tor_build", "tor_tests"),
    "swift": ("swift_info", "swift_build"),
    "swtpm": ("tpm_system", "swtpm_start", "swtpm_rust", "swtpm_python"),
    "winkey": (
        "winkey_fmt",
        "winkey_clippy",
        "winkey_test",
        "winkey_msrv_install",
        "winkey_msrv_test",
        "winkey_python",
    ),
    "windows-wheel": ("wheel",),
}
Json = dict[str, Any]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> Json:
    result: Json = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: str | bytes) -> Json:
    require(len(raw) <= MAX_JSON_BYTES, "JSON exceeds size limit")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    require(isinstance(value, dict), "expected JSON object")
    return dict(value)


def read_json(path: Path) -> Json:
    with path.open("rb") as stream:
        return parse_json(stream.read(MAX_JSON_BYTES + 1))


def load_policy(path: Path) -> Json:
    """Read and validate scope before a runner consumes module paths."""
    policy = read_json(path)
    validate_policy(policy)
    return policy


def _same_json(left: Json, right: Json) -> bool:
    # Python equality conflates True with 1, which is invalid for identity fields.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value) and len(value) == len(set(value))


def validate_context(policy: Json) -> None:
    require(type(policy.get("schema_version")) is int and policy["schema_version"] == 2, "unsupported schema")
    require(policy.get("workflow_path") == WORKFLOW, "unexpected workflow")
    require(
        isinstance(policy.get("repository"), str)
        and re.fullmatch(r"[\w.-]+/[\w.-]+", policy["repository"]) is not None,
        "invalid repository",
    )
    require(_sha(policy.get("tested_sha")), "invalid tested SHA")
    require(_positive_int(policy.get("run_id")) and _positive_int(policy.get("run_attempt")), "invalid run identity")
    require(isinstance(policy.get("event_name"), str) and bool(policy["event_name"]), "missing event")
    require(isinstance(policy.get("ref"), str) and policy["ref"].startswith("refs/"), "invalid ref")
    pr: Any = policy.get("pr")
    if policy["event_name"] == "pull_request":
        require(
            isinstance(pr, dict) and set(pr) == {"number", "head_sha", "base_sha", "merge_sha"}, "missing PR context"
        )
        require(
            _positive_int(pr["number"]) and all(_sha(pr[key]) for key in ("head_sha", "base_sha", "merge_sha")),
            "invalid PR context",
        )
        require(
            pr["merge_sha"] == policy["tested_sha"] and policy["ref"] == f"refs/pull/{pr['number']}/merge",
            "PR context does not identify tested merge",
        )
    else:
        require(pr is None, "unexpected PR context")


def _validate_windows_modules(policy: Json) -> None:
    modules = policy["windows_modules"]
    require(_strings(modules), "invalid Windows modules")
    require(policy["windows"] or not modules, "unrequested Windows modules")
    if modules or policy["mode"] == "final":
        # The checked-in scope inventory is the single frozen native selector.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from ci_change_scope import native_modules, windows_family_modules

        native = native_modules()
        require(modules == [item for item in native if item in modules], "unknown or reordered Windows modules")
        if policy["mode"] == "final":
            require(modules == list(native), "incomplete final Windows selector")
        elif policy["mode"] == "ordinary":
            families = [set(windows_family_modules([family])) for family in ("network", "llm", "privacy", "extension")]
            complete = set().union(*(family for family in families if family <= set(modules)))
            require(set(modules) == complete, "incomplete ordinary Windows family")
        else:
            require(not modules, "critical workers use the critical preset")


def _validate_packs(policy: Json, os_name: str) -> None:
    packs = policy[f"{os_name}_packs"]
    require(_strings(packs), f"invalid {os_name} packs")
    selected = bool(policy["linux_versions"]) if os_name == "linux" else policy[os_name]
    required = ["main", "static"] if os_name == "linux" else ["main"]
    if not selected:
        require(not packs, "unrequested packs")
    elif policy["mode"] == "final":
        require(packs == FINAL_PACKS[os_name], f"incomplete final {os_name} packs")
    elif policy["mode"] == "critical":
        require(packs == required, "critical mode cannot claim optional packs")
    else:
        require(all(pack in packs for pack in required), "missing base pack")
        require(packs == [pack for pack in FINAL_PACKS[os_name] if pack in packs], "unknown or reordered packs")


def validate_policy(policy: Json) -> None:
    require(set(policy) == POLICY_KEYS, "unexpected policy fields")
    validate_context(policy)
    mode = policy["mode"]
    require(mode in ("critical", "ordinary", "docs", "final"), "unknown mode")
    versions = [] if mode == "docs" else ["3.11", "3.13"] if mode == "final" else ["3.12"]
    require(policy["linux_versions"] == versions, "incorrect Linux interpreter set")
    version = "3.11" if mode == "final" else "3.12"
    require(
        policy["platform_python"] == version and policy["support_python"] == version, "incorrect support interpreter"
    )
    require(type(policy["macos"]) is bool and type(policy["windows"]) is bool, "invalid platform flags")
    if mode in ("docs", "final"):
        require(
            policy["macos"] is (mode == "final") and policy["windows"] is (mode == "final"), "incorrect platform set"
        )
    require(isinstance(policy["reason"], str) and bool(policy["reason"]), "missing policy reason")
    for os_name in FINAL_PACKS:
        _validate_packs(policy, os_name)
    shards = [1, 2] if mode == "final" else [1] if policy["windows"] else []
    require(
        type(policy["windows_shards"]) is list
        and all(type(s) is int for s in policy["windows_shards"])
        and policy["windows_shards"] == shards,
        "incorrect Windows shards",
    )
    tier = policy["windows_test_tier"]
    allowed_tiers = ("full", "routine") if mode == "final" else ("full",) if policy["windows"] else ("none",)
    require(tier in allowed_tiers, "incorrect Windows tier")
    if tier == "routine":
        require(
            policy["event_name"] == "pull_request"
            or (policy["event_name"] == "push" and policy["ref"] == "refs/heads/dev"),
            "routine tier requires dev event provenance",
        )
    require(
        policy["windows_exclusions_sha256"] == exclusions_digest("full" if tier == "none" else tier),
        "incorrect Windows exclusions digest",
    )
    _validate_windows_modules(policy)


def expected_workers(policy: Json) -> dict[tuple[str, str, int], list[str]]:
    validate_policy(policy)
    expected = {
        ("linux", version, 1): policy["linux_packs"] if version == policy["support_python"] else ["main"]
        for version in policy["linux_versions"]
    }
    for os_name in ("macos", "windows"):
        if policy[os_name]:
            for shard in policy["windows_shards"] if os_name == "windows" else [1]:
                expected[(os_name, policy["platform_python"], shard)] = (
                    policy[f"{os_name}_packs"] if shard == 1 else ["main"]
                )
    return expected


def pack_steps(pack: str, os_name: str, mode: str) -> tuple[str, ...]:
    if pack == "main":
        if os_name == "windows":
            return ("install", "private_home", "native")
        if os_name == "macos":
            return ("install", "pytest", "status") if mode == "critical" else ("install", "mypy", "pytest", "status")
        return ("install", "mypy", "pytest")
    if pack == "tpm":
        common = ("rust_tools", "tpm_fmt", "tpm_clippy", "tpm_test")
        return ("tpm_system", *common, "tpm_msrv") if os_name == "linux" else common
    return PACK_STEPS[pack]


def _step(steps: Json, name: str) -> Json:
    value = steps.get(name, {})
    require(isinstance(value, dict), f"invalid step {name}")
    return {"outcome": value.get("outcome", "missing"), "conclusion": value.get("conclusion", "missing")}


def _succeeded(step: Json) -> bool:
    return step == {"outcome": "success", "conclusion": "success"}


def validate_native_selection(policy: Json, selection: Json, shard: int) -> None:
    """Validate actual collection and outcomes against the complete shared plan."""
    require(
        set(selection)
        == {
            "schema_version",
            "tier",
            "shard",
            "shard_count",
            "modules",
            "excluded_nodeids",
            "tests",
            "collected_count",
            "collection_sha256",
            "exit_code",
        },
        "unexpected native fields",
    )
    count = len(policy["windows_shards"])
    tier = policy["windows_test_tier"]
    modules = plan_native_modules(policy["windows_modules"], tier=tier, shard=shard, count=count)
    require(type(selection["schema_version"]) is int and selection["schema_version"] == 1, "invalid native schema")
    require(
        type(selection["shard"]) is int
        and selection["shard"] == shard
        and type(selection["shard_count"]) is int
        and selection["shard_count"] == count,
        "invalid native shard",
    )
    require(selection["tier"] == tier and selection["modules"] == modules, "incorrect native selection")
    excluded = exclusions_for(modules, tier)
    require(selection["excluded_nodeids"] == excluded, "incorrect native exclusions")
    tests = selection["tests"]
    require(isinstance(tests, list), "missing native tests")
    ids = list(excluded)
    for test in tests:
        require(isinstance(test, dict) and set(test) == {"nodeid", "outcome"}, "invalid native test")
        require(isinstance(test["nodeid"], str) and "::" in test["nodeid"], "invalid native node ID")
        require(test["outcome"] in ("passed", "skipped"), "unsuccessful native test")
        ids.append(test["nodeid"])
    require(len(ids) == len(set(ids)), "duplicate native test")
    require({nodeid.split("::", 1)[0] for nodeid in ids} == set(modules), "incomplete or foreign native modules")
    require(
        type(selection["collected_count"]) is int and selection["collected_count"] == len(ids), "incorrect native count"
    )
    digest = hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()
    require(selection["collection_sha256"] == digest, "incorrect native collection digest")
    require(type(selection["exit_code"]) is int and selection["exit_code"] == 0, "native execution failed")


def build_worker(
    policy: Json,
    os_name: str,
    python: str,
    steps: Json,
    *,
    actual_python: str,
    shard: int = 1,
    native_selection: Json | None = None,
) -> Json:
    expected = expected_workers(policy)
    require(type(shard) is int and (os_name, python, shard) in expected, "unrequested worker")
    require(actual_python == python, "actual interpreter does not match selected interpreter")
    packs = {
        pack: {name: _step(steps, name) for name in pack_steps(pack, os_name, policy["mode"])}
        for pack in expected[(os_name, python, shard)]
    }
    native_ok = True
    if os_name == "windows" and policy["mode"] == "final":
        native_ok = isinstance(native_selection, dict)
        if isinstance(native_selection, dict):
            try:
                validate_native_selection(policy, native_selection, shard)
            except (ValueError, TypeError, KeyError):
                native_ok = False
    else:
        require(native_selection is None, "unrequested native manifest")
    return {
        "schema_version": 2,
        "kind": "worker",
        "context": {key: policy[key] for key in CONTEXT_KEYS},
        "os": os_name,
        "python": python,
        "actual_python": actual_python,
        "shard": shard,
        "native_selection": native_selection,
        "packs": packs,
        "success": native_ok and all(_succeeded(step) for pack in packs.values() for step in pack.values()),
    }


def _validate_worker(policy: Json, worker: Json) -> tuple[str, str, int]:
    require(isinstance(worker.get("packs"), dict), "missing worker packs")
    steps: Json = {}
    for pack in worker["packs"].values():
        require(isinstance(pack, dict), "invalid worker pack")
        for name, value in pack.items():
            require(name not in steps or value == steps[name], "inconsistent shared step")
            steps[name] = value
    expected = build_worker(
        policy,
        worker.get("os", ""),
        worker.get("python", ""),
        steps,
        actual_python=worker.get("actual_python", ""),
        shard=worker.get("shard", 0),
        native_selection=worker.get("native_selection"),
    )
    require(_same_json(worker, expected) and expected["success"] is True, "incomplete or mismatched worker evidence")
    return worker["os"], worker["python"], worker["shard"]


def expected_needs(policy: Json) -> dict[str, str]:
    return {
        "ci-policy": "success",
        "linux": "success" if policy["linux_versions"] else "skipped",
        "macos": "success" if policy["macos"] else "skipped",
        "windows-private-fs": "success" if policy["windows"] else "skipped",
    }


def accept(policy: Json, workers: list[Json], needs: Json, steps: Json) -> Json:
    expected = expected_workers(policy)
    require(set(needs) == set(expected_needs(policy)), "missing or unexpected job results")
    for name, result in expected_needs(policy).items():
        require(isinstance(needs[name], dict) and needs[name].get("result") == result, f"unexpected job result: {name}")
    actual = [_validate_worker(policy, worker) for worker in workers]
    require(len(actual) == len(set(actual)) and set(actual) == set(expected), "missing, duplicate or unknown worker")
    docs_steps = {"docs_tests": _step(steps, "docs_tests")} if policy["mode"] == "docs" else {}
    require(all(_succeeded(step) for step in docs_steps.values()), "documentation checks did not succeed")
    return {
        "schema_version": 2,
        "kind": "acceptance",
        "policy": policy,
        "workers": sorted(workers, key=lambda worker: (worker["os"], worker["python"], worker["shard"])),
        "needs": {name: {"result": value["result"]} for name, value in needs.items()},
        "docs_steps": docs_steps,
        "accepted": policy["mode"] != "critical",
        "feedback_only": policy["mode"] == "critical",
    }


def validate_acceptance(evidence: Json) -> Json:
    require(
        isinstance(evidence.get("policy"), dict) and isinstance(evidence.get("workers"), list),
        "invalid acceptance evidence",
    )
    require(
        isinstance(evidence.get("needs"), dict) and isinstance(evidence.get("docs_steps"), dict), "missing job evidence"
    )
    require(all(isinstance(worker, dict) for worker in evidence["workers"]), "invalid workers")
    expected = accept(evidence["policy"], evidence["workers"], evidence["needs"], evidence["docs_steps"])
    require(_same_json(evidence, expected), "inconsistent acceptance evidence")
    return dict(evidence["policy"])


def validate_environment(policy: Json, environ: Mapping[str, str]) -> None:
    fields = {
        "GITHUB_REPOSITORY": "repository",
        "GITHUB_SHA": "tested_sha",
        "GITHUB_REF": "ref",
        "GITHUB_EVENT_NAME": "event_name",
        "GITHUB_RUN_ID": "run_id",
        "GITHUB_RUN_ATTEMPT": "run_attempt",
    }
    for env_key, policy_key in fields.items():
        require(environ.get(env_key) == str(policy[policy_key]), f"policy differs from {env_key}")
    workflow_ref = f"{policy['repository']}/{WORKFLOW}@{policy['ref']}"
    require(environ.get("GITHUB_WORKFLOW_REF") == workflow_ref, "workflow provenance mismatch")
    if policy["event_name"] == "pull_request":
        event = read_json(Path(environ.get("GITHUB_EVENT_PATH", "")))
        pr = event.get("pull_request", {})
        require(isinstance(pr, dict), "invalid PR event")
        # This asynchronous field can be missing or name an earlier merge.
        # The policy job instead proves checkout HEAD/GITHUB_SHA and the exact
        # ordered base/head parents. The bindings above preserve that identity.
        raw_merge_sha = pr.get("merge_commit_sha")
        require(raw_merge_sha is None or _sha(raw_merge_sha), "invalid PR merge metadata")
        current = {
            "number": event.get("number"),
            "head_sha": pr.get("head", {}).get("sha"),
            "base_sha": pr.get("base", {}).get("sha"),
            "merge_sha": policy["tested_sha"],
        }
        require(policy["pr"] == current, "stale PR context")


def load_workers(directory: Path) -> list[Json]:
    if not directory.exists():
        return []
    files = list(directory.rglob("*"))
    require(len(files) <= 32, "too many worker evidence files")
    require(
        all(not path.is_symlink() and (path.is_dir() or path.name == "worker.json") for path in files),
        "unexpected worker evidence file",
    )
    return [read_json(path) for path in sorted(files) if path.is_file()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("worker", "accept"))
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--os", choices=("linux", "macos", "windows"))
    parser.add_argument("--python")
    parser.add_argument("--workers", type=Path)
    parser.add_argument("--shard", type=int, default=1)
    parser.add_argument("--native-manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        validate_environment(policy, os.environ)
        steps = parse_json(os.environ.get("CI_STEPS_JSON", "{}"))
        if args.command == "worker":
            actual_os = {"linux": "linux", "darwin": "macos", "win32": "windows"}.get(sys.platform)
            require(args.os == actual_os, "actual OS does not match selected worker")
            native_selection = None
            if args.native_manifest is not None:
                with contextlib.suppress(ValueError, OSError):
                    native_selection = read_json(args.native_manifest)
            evidence = build_worker(
                policy,
                args.os,
                args.python,
                steps,
                actual_python=f"{sys.version_info.major}.{sys.version_info.minor}",
                shard=args.shard,
                native_selection=native_selection,
            )
        else:
            require(args.workers is not None, "--workers is required for acceptance")
            evidence = accept(
                policy, load_workers(args.workers), parse_json(os.environ.get("CI_NEEDS_JSON", "{}")), steps
            )
        args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(f"CI evidence refused: {exc}", file=sys.stderr)
        return 1
    print(f"Recorded {evidence['kind']} evidence ({policy['mode']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
