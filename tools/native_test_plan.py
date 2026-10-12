"""Shared deterministic Windows selection, using reviewed exact case IDs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _fixture(name: str) -> dict[str, Any]:
    with (ROOT / name).open(encoding="utf-8") as stream:
        value: dict[str, Any] = json.load(stream)
    return value


def _tier(tier: str) -> None:
    if tier not in ("full", "routine"):
        raise ValueError(f"unsupported native tier: {tier}")


def plan_native_modules(modules: Sequence[str], *, tier: str, shard: int, count: int) -> list[str]:
    """Balance whole modules with LPT; preserve selector order within a shard.

    The first shard owns the helper packs, whose observed cost is included in
    balancing. New modules always run, with a one-second provisional weight.
    """
    _tier(tier)
    if type(count) is not int or type(shard) is not int or not 1 <= shard <= count:
        raise ValueError("native shard must be between 1 and shard count")
    if len(modules) != len(set(modules)):
        raise ValueError("duplicate native module")
    if count == 1:
        return list(modules)
    data = _fixture("native_test_durations.json")
    weights = data["routine_seconds" if tier == "routine" else "seconds"]
    loads = [float(data["support_seconds"]), *([0.0] * (count - 1))]
    assignments: dict[str, int] = {}
    # Python's stable sorting breaks duration ties by original selector order.
    for module in sorted(modules, key=lambda item: -float(weights.get(item, 1.0))):
        index = min(range(count), key=lambda candidate: (loads[candidate], candidate))
        assignments[module] = index + 1
        loads[index] += float(weights.get(module, 1.0))
    return [module for module in modules if assignments[module] == shard]


def exclusions_for(modules: Sequence[str], tier: str) -> list[str]:
    """Return exact reviewed nodeids, never function or parameter prefixes."""
    _tier(tier)
    if tier == "full":
        return []
    selected = set(modules)
    nodeids = [item["nodeid"] for item in _fixture("native_test_profile.json")["routine_exclusions"]]
    if len(nodeids) != len(set(nodeids)) or any("::" not in nodeid for nodeid in nodeids):
        raise ValueError("invalid reviewed native exclusions")
    return sorted(nodeid for nodeid in nodeids if nodeid.split("::", 1)[0] in selected)


def exclusions_digest(tier: str) -> str:
    """Bind the policy to the canonical complete reviewed exclusion list."""
    _tier(tier)
    profile = _fixture("native_test_profile.json")
    modules = [item["nodeid"].split("::", 1)[0] for item in profile["routine_exclusions"]]
    encoded = json.dumps(exclusions_for(modules, tier), separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
