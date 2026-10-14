"""Whole-module balancing must preserve coverage and exact case exclusions."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def planner():
    path = ROOT / "tools/native_test_plan.py"
    assert path.exists(), "shared native planner is missing"
    spec = importlib.util.spec_from_file_location("native_test_plan", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reviewed_native_inventory_is_balanced_without_losing_modules():
    plan = planner()
    durations = json.loads((ROOT / "tools/native_test_durations.json").read_text())
    modules = list(durations["seconds"])
    shards = [plan.plan_native_modules(modules, tier="routine", shard=i, count=2) for i in (1, 2)]
    assert len(modules) == 84
    assert set(shards[0]).isdisjoint(shards[1])
    assert set(shards[0] + shards[1]) == set(modules)
    weights = [sum(durations["routine_seconds"][m] for m in shard) for shard in shards]
    weights[0] += durations["support_seconds"]
    assert max(weights) < 1400
    assert abs(weights[0] - weights[1]) < 1
    assert shards == [plan.plan_native_modules(modules, tier="routine", shard=i, count=2) for i in (1, 2)]
    assert all(shard == [m for m in modules if m in shard] for shard in shards)


def test_unknown_modules_are_included_and_single_shard_preserves_order():
    plan = planner()
    modules = ["tests/new_a.py", "tests/new_b.py", "tests/new_c.py"]
    assert plan.plan_native_modules(modules, tier="full", shard=1, count=1) == modules
    assert plan.plan_native_modules(modules, tier="full", shard=2, count=2) == modules


@pytest.mark.parametrize(
    "tier,shard,count", [("none", 1, 1), ("full", 0, 2), ("full", 3, 2), ("full", 1, 0), ("full", True, 2)]
)
def test_invalid_plan_cannot_silently_drop_tests(tier, shard, count):
    with pytest.raises(ValueError):
        planner().plan_native_modules(["tests/new.py"], tier=tier, shard=shard, count=count)


def test_exact_exclusions_do_not_expand_to_new_parameters():
    plan = planner()
    module = "tests/test_wizard_windows_memory.py"
    excluded = plan.exclusions_for([module], "routine")
    assert excluded == [
        module + "::test_lifecycle_never_writes_memory_or_markers_itself",
        module + "::test_windows_enable_all_override_keeps_installed_runtime_proof[darwin]",
        module + "::test_windows_enable_all_override_keeps_installed_runtime_proof[linux]",
    ]
    assert module + "::test_windows_enable_all_override_keeps_installed_runtime_proof[windows]" not in excluded
    assert plan.exclusions_for([module], "full") == []
    assert plan.exclusions_digest("full") == hashlib.sha256(b"[]").hexdigest()
    profile = json.loads((ROOT / "tools/native_test_profile.json").read_text())
    nodeids = sorted(item["nodeid"] for item in profile["routine_exclusions"])
    assert len(nodeids) == len(set(nodeids)) == 28
    assert (
        plan.exclusions_digest("routine")
        == hashlib.sha256(json.dumps(nodeids, separators=(",", ":")).encode()).hexdigest()
    )
