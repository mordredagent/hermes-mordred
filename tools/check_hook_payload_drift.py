#!/usr/bin/env python3
"""Detect Hermes hook *payload field* drift (TODO §Cross-cutting L474).

``upstream-check.yml``'s name check asserts the hook names Mordred registers
still exist in ``hermes_cli.plugins.VALID_HOOKS``. This tool goes one level
deeper: it statically extracts every core ``invoke_hook("<name>", key=value,
...)`` dispatch site from a Hermes source tree (pure ``ast`` — nothing is
imported or executed, so it needs no upstream install) and verifies that the
payload fields Mordred's plugins consume (``tools/hook_payload_contract.json``)
are passed at every dispatch site.

Rules:

- A contract hook with **no** dispatch site at all is drift — the hook name
  may still be in ``VALID_HOOKS`` while core stopped firing it.
- A contract field missing at **any** literal dispatch site is drift — the
  plugins read these via ``kwargs.get`` so they would degrade silently.
- A site spreading ``**kwargs`` is statically unknowable and is skipped.

Exit status: 0 = no drift, 1 = drift (report on stdout), 2 = usage error.

Usage::

    python tools/check_hook_payload_drift.py \
        --hermes-root ../hermes-upstream \
        --contract tools/hook_payload_contract.json
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

#: Directory names never scanned (relative to ``--hermes-root``). ``tests``
#: and third-party ``plugins`` dispatch hooks for their own purposes; the
#: contract is about *core* dispatch sites. ``mordred-hermes`` keeps the
#: vendored-fork self-scan (and the canary test) from matching our own code.
DEFAULT_EXCLUDES = frozenset(
    {
        "__pycache__",
        "node_modules",
        "tests",
        "mordred-hermes",
        "website",
        "web",
        "plugins",
        "docs",
    }
)

#: Callee names that count as a hook dispatch. Core uses the plain import and
#: the ``invoke_hook as _invoke_hook`` alias; attribute calls
#: (``plugins.invoke_hook``) are matched by attribute name.
_DISPATCH_NAMES = frozenset({"invoke_hook", "_invoke_hook"})


@dataclass(frozen=True)
class DispatchSite:
    """One literal ``invoke_hook("<hook>", ...)`` call in the scanned tree."""

    file: str
    line: int
    fields: frozenset[str]
    has_dynamic_kwargs: bool


def _hook_name(node: ast.Call) -> str | None:
    """The literal hook name when ``node`` is a dispatch call, else None."""
    func = node.func
    if isinstance(func, ast.Name):
        callee = func.id
    elif isinstance(func, ast.Attribute):
        callee = func.attr
    else:
        return None
    if callee not in _DISPATCH_NAMES or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def extract_hook_payload_fields(
    root: Path, excludes: frozenset[str] = DEFAULT_EXCLUDES
) -> dict[str, list[DispatchSite]]:
    """Map hook name → dispatch sites found under ``root``.

    Unparseable / undecodable files are skipped: the scan must keep working
    against whatever an upstream checkout contains (templates, py2 relics).
    Hidden directories (``.git``, ``.venv``) are always skipped.
    """
    sites: dict[str, list[DispatchSite]] = {}
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        parents = rel.parts[:-1]
        if any(part in excludes or part.startswith(".") for part in parents):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            hook = _hook_name(node)
            if hook is None:
                continue
            sites.setdefault(hook, []).append(
                DispatchSite(
                    file=str(rel),
                    line=node.lineno,
                    fields=frozenset(
                        kw.arg for kw in node.keywords if kw.arg is not None
                    ),
                    has_dynamic_kwargs=any(kw.arg is None for kw in node.keywords),
                )
            )
    return sites


def compare(
    contract: dict[str, list[str]], sites: dict[str, list[DispatchSite]]
) -> list[str]:
    """Drift messages for every contract violation (empty list = no drift)."""
    drift: list[str] = []
    for hook in sorted(contract):
        hook_sites = sites.get(hook, [])
        if not hook_sites:
            drift.append(
                f"{hook}: no invoke_hook dispatch site found — core may have "
                "stopped firing this hook"
            )
            continue
        for site in hook_sites:
            if site.has_dynamic_kwargs:
                continue
            missing = sorted(set(contract[hook]) - set(site.fields))
            if missing:
                drift.append(
                    f"{hook}: {site.file}:{site.line} missing payload "
                    f"field(s): {', '.join(missing)}"
                )
    return drift


def load_contract(path: Path) -> dict[str, list[str]]:
    """Load the contract, dropping ``_``-prefixed comment keys."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--hermes-root",
        required=True,
        type=Path,
        help="root of the Hermes source tree to scan (e.g. an upstream clone)",
    )
    parser.add_argument(
        "--contract",
        required=True,
        type=Path,
        help="path to hook_payload_contract.json",
    )
    args = parser.parse_args(argv)
    if not args.hermes_root.is_dir():
        print(f"error: --hermes-root {args.hermes_root} is not a directory")
        return 2

    contract = load_contract(args.contract)
    sites = extract_hook_payload_fields(args.hermes_root)
    drift = compare(contract, sites)
    if drift:
        print("hook payload drift detected:")
        for entry in drift:
            print(f"  - {entry}")
        return 1
    scanned = sum(len(v) for v in sites.values())
    print(
        f"hook payload contract satisfied "
        f"({len(contract)} hooks, {scanned} dispatch sites scanned)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
