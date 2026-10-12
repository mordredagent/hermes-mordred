#!/usr/bin/env python3
"""Run native pytest and record the actual collection and exact exclusions."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import pytest


class NativeSelection:
    """Bind a shard manifest to collected node IDs and their actual outcomes."""

    def __init__(
        self,
        *,
        tier: str,
        shard: int,
        shard_count: int,
        modules: list[str],
        exclusions: list[str],
        output: Path,
    ) -> None:
        self.tier = tier
        self.shard = shard
        self.shard_count = shard_count
        self.modules = modules
        self.exclusions = sorted(exclusions)
        self.output = output
        self.collected: list[str] = []
        self.selected: list[str] = []
        self.outcomes: dict[str, str] = {}

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, config: pytest.Config, items: list[pytest.Item]) -> None:
        self.collected = [item.nodeid for item in items]
        if len(self.collected) != len(set(self.collected)):
            raise pytest.UsageError("duplicate native test node IDs")
        missing = set(self.exclusions) - set(self.collected)
        if missing:
            raise pytest.UsageError(f"reviewed native exclusions missing from collection: {sorted(missing)}")
        excluded = set(self.exclusions)
        omitted = [item for item in items if item.nodeid in excluded]
        items[:] = [item for item in items if item.nodeid not in excluded]
        self.selected = [item.nodeid for item in items]
        if omitted:
            config.hook.pytest_deselected(items=omitted)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.failed:
            self.outcomes[report.nodeid] = "failed"
        elif self.outcomes.get(report.nodeid) != "failed":
            if report.skipped:
                self.outcomes[report.nodeid] = "skipped"
            elif report.when == "call":
                self.outcomes[report.nodeid] = "passed"

    @pytest.hookimpl(trylast=True)
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        complete = set(self.outcomes) == set(self.selected) and bool(self.selected)
        if exitstatus == 0 and not complete:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
        manifest = {
            "schema_version": 1,
            "tier": self.tier,
            "shard": self.shard,
            "shard_count": self.shard_count,
            "modules": self.modules,
            "excluded_nodeids": self.exclusions,
            "tests": [{"nodeid": node, "outcome": self.outcomes.get(node, "failed")} for node in self.selected],
            "collected_count": len(self.collected),
            "collection_sha256": hashlib.sha256("\n".join(sorted(self.collected)).encode()).hexdigest(),
            "exit_code": int(session.exitstatus),
        }
        self.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("full", "routine"), required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--junitxml", type=Path, required=True)
    parser.add_argument("modules", nargs="+")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from native_test_plan import exclusions_for

    args.manifest.unlink(missing_ok=True)
    selection = NativeSelection(
        tier=args.tier,
        shard=args.shard,
        shard_count=args.shard_count,
        modules=args.modules,
        exclusions=exclusions_for(args.modules, args.tier),
        output=args.manifest,
    )
    return int(
        pytest.main(
            ["-q", "-o", "addopts=", "--durations=20", f"--junitxml={args.junitxml}", *args.modules],
            plugins=[selection],
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
