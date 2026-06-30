#!/usr/bin/env python3
"""Bump the mordred-hermes version everywhere it is hardcoded, in lockstep.

The build's single source of truth is ``src/mordred_hermes/__about__.py`` —
Hatch reads ``__version__`` from it (``[tool.hatch.version] path``). But a
release version also appears in surfaces that are not auto-derived from it:

  - src/mordred_hermes/__about__.py    (__version__ — the canonical source)
  - docs/dev/VERSION                 (docs-tree marker; a human mirror)
  - src/mordred_hermes/*/plugin.yaml    (each plugin manifest's ``version:``)

This rewrites all of them at once so a release bump is one command instead of
seven hand-edits. ``tests/test_packaging_versions.py`` pins that they agree,
so CI catches any surface a hand-edit forgets. The name-reservation stub
(``packaging/name-reservation/pyproject.toml``) is intentionally NOT touched —
it stays permanently at ``0.0.0.dev0`` (M7).

Usage:
    python tools/bump_version.py 0.1.0a1
    python tools/bump_version.py 0.1.0 --dry-run
    python tools/bump_version.py 0.1.0a0 --allow-non-increasing   # re-sync only
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from packaging.version import InvalidVersion, Version

_PKG_ROOT = Path(__file__).resolve().parent.parent
_ABOUT = _PKG_ROOT / "src" / "mordred_hermes" / "__about__.py"
_DOC_VERSION = _PKG_ROOT / "docs" / "dev" / "VERSION"

_ABOUT_VALUE_RE = re.compile(r"""(?m)^__version__\s*=\s*["']([^"']+)["']\s*$""")
_ABOUT_LINE_RE = re.compile(r"""(?m)^__version__\s*=\s*["'][^"']+["'][^\n]*$""")
_MANIFEST_LINE_RE = re.compile(r"(?m)^version:[^\n]*$")


def _plugin_manifests() -> list[Path]:
    return sorted(_PKG_ROOT.glob("src/mordred_hermes/*/plugin.yaml"))


def _current_version() -> str:
    match = _ABOUT_VALUE_RE.search(_ABOUT.read_text(encoding="utf-8"))
    if match is None:
        sys.exit(f"error: no __version__ assignment found in {_ABOUT}")
    return match.group(1)


def _rewrite(path: Path, pattern: re.Pattern[str], replacement: str, *, dry_run: bool) -> bool:
    """Replace the first ``pattern`` match in ``path`` with ``replacement``.

    Returns True if the file changed. ``replacement`` is passed through a lambda
    so backslashes in a version string can't be misread as regex group refs.
    """
    text = path.read_text(encoding="utf-8")
    new_text, n = pattern.subn(lambda _m: replacement, text, count=1)
    if n == 0:
        sys.exit(f"error: pattern {pattern.pattern!r} not found in {path}")
    if new_text == text:
        return False
    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bump mordred-hermes version in lockstep.")
    parser.add_argument("version", help="new PEP 440 version, e.g. 0.1.0a1 / 0.1.0b0 / 0.1.0")
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing")
    parser.add_argument(
        "--allow-non-increasing",
        action="store_true",
        help="permit a version <= the current one (e.g. to re-sync drifted files)",
    )
    args = parser.parse_args(argv)

    try:
        new = Version(args.version)
    except InvalidVersion:
        sys.exit(f"error: {args.version!r} is not a valid PEP 440 version")

    current = Version(_current_version())
    if new <= current and not args.allow_non_increasing:
        sys.exit(
            f"error: new version {new} is not greater than current {current}. "
            "Pass --allow-non-increasing to override (e.g. re-syncing drifted files)."
        )

    # Version() may canonicalize (e.g. 0.1.0-alpha0 -> 0.1.0a0); write that form.
    new_str = str(new)
    targets: list[tuple[Path, re.Pattern[str], str]] = [
        (_ABOUT, _ABOUT_LINE_RE, f'__version__ = "{new_str}"'),
    ]
    if _DOC_VERSION.exists():
        targets.append((_DOC_VERSION, re.compile(r"(?s).*"), f"{new_str}\n"))
    else:
        print(f"warning: docs marker {_DOC_VERSION} absent — skipping", file=sys.stderr)
    for manifest in _plugin_manifests():
        targets.append((manifest, _MANIFEST_LINE_RE, f"version: {new_str}"))

    label = "would update" if args.dry_run else "updated"
    changed = 0
    for path, pattern, replacement in targets:
        if _rewrite(path, pattern, replacement, dry_run=args.dry_run):
            changed += 1
            print(f"  {label}: {path.relative_to(_PKG_ROOT)}")
        else:
            print(f"  unchanged: {path.relative_to(_PKG_ROOT)}")

    print(f"\n{current} -> {new_str}  ({changed} file(s) {label})")
    if not args.dry_run:
        print(
            "\nNext: add a changelog entry, then verify with\n"
            "  .venv/bin/python -m pytest tests/test_packaging_versions.py\n"
            "  uv build   # confirm sdist + wheel still build"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
