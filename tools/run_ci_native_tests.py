#!/usr/bin/env python3
"""Run complete mapped Windows modules plus every remaining critical case."""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def select_nodes(modules: Sequence[str], critical_nodes: Sequence[str]) -> list[str]:
    """Whole modules cover their critical nodes; retain other critical cases."""
    if len(modules) != len(set(modules)) or any(
        not re.fullmatch(r"tests/(?:\w+/)*test_\w+\.py", module) for module in modules
    ):
        raise ValueError("native modules must be unique repository test paths")
    selected = list(modules) + [node for node in critical_nodes if node.split("::", 1)[0] not in modules]
    if not selected:
        raise ValueError("empty native selection would run the full suite")
    return selected


def _load_sibling(name: str) -> ModuleType:
    # Hermes also ships a top-level tools package; importing that namespace can
    # silently resolve installed upstream tools instead of this checkout.
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load CI tool: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--junitxml", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = _load_sibling("ci_evidence").load_policy(args.policy)
        if policy.get("mode") not in {"ordinary", "critical"} or policy.get("windows") is not True:
            raise ValueError("selected native runner requires a Windows ordinary/critical policy")
        modules = policy["windows_modules"]
        if not isinstance(modules, list) or any(not isinstance(module, str) for module in modules):
            raise ValueError("native modules must be a list of paths")
        if any(not (ROOT / module).is_file() for module in modules):
            raise ValueError("a selected native module is missing")
        critical = _load_sibling("run_critical_tests")
        nodes = select_nodes(modules, [node for _risk, node in critical.select_cases(sys.platform)])
    except (KeyError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(
        f"Selected native feedback: {len(modules)} complete modules and {len(nodes) - len(modules)} critical cases.",
        flush=True,
    )
    return int(critical.run_cases(nodes, collect_only=args.dry_run, junitxml=args.junitxml))


if __name__ == "__main__":
    sys.exit(main())
