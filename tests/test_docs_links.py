"""Keep maintained Markdown links inside the repository valid."""

from __future__ import annotations

import html
import re
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

_EXCLUDED_DIRS = {".claude", ".git", ".pytest_cache", ".venv"}
_INLINE_LINK_RE = re.compile(r"!?\[[^\]\n]*\]\(\s*(?:<(?P<angle>[^>]+)>|(?P<plain>[^\s)]+))")
_REFERENCE_LINK_RE = re.compile(
    r"^\s*\[[^\]\n]+\]:\s*(?:<(?P<angle>[^>]+)>|(?P<plain>\S+))",
    re.MULTILINE,
)
_HTML_LINK_RE = re.compile(r"\bhref=[\"'](?P<target>[^\"']+)[\"']", re.IGNORECASE)
_EXPLICIT_ANCHOR_RE = re.compile(
    r"<a\s+[^>]*(?:id|name)=[\"'](?P<anchor>[^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$", re.MULTILINE)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _markdown_files() -> list[Path]:
    return [
        path
        for path in sorted(ROOT.rglob("*.md"))
        if not any(part in _EXCLUDED_DIRS for part in path.relative_to(ROOT).parts)
    ]


def _without_fenced_code(text: str) -> str:
    """Blank fenced blocks while retaining line numbers for diagnostics."""
    output: list[str] = []
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        marker = line.lstrip()[:3]
        if marker in {"```", "~~~"}:
            fence = None if fence == marker else marker if fence is None else fence
            output.append("\n" if line.endswith("\n") else "")
        elif fence is None:
            output.append(line)
        else:
            output.append("\n" if line.endswith("\n") else "")
    return "".join(output)


def _destinations(text: str) -> list[tuple[int, str]]:
    visible = _without_fenced_code(text)
    found: list[tuple[int, str]] = []
    for pattern in (_INLINE_LINK_RE, _REFERENCE_LINK_RE):
        for match in pattern.finditer(visible):
            target = match.group("angle") or match.group("plain")
            found.append((visible.count("\n", 0, match.start()) + 1, target))
    for match in _HTML_LINK_RE.finditer(visible):
        found.append((visible.count("\n", 0, match.start()) + 1, match.group("target")))
    return found


def _github_slug(title: str) -> str:
    title = html.unescape(re.sub(r"<[^>]+>", "", title)).lower()
    title = re.sub(r"[`*_~]", "", title)
    chars = [char for char in title if char in {"-", "_", " "} or unicodedata.category(char)[0] in {"L", "N"}]
    return "".join(chars).strip().replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    anchors = {html.unescape(match.group("anchor")) for match in _EXPLICIT_ANCHOR_RE.finditer(text)}
    occurrences: dict[str, int] = {}
    for match in _HEADING_RE.finditer(_without_fenced_code(text)):
        base = _github_slug(match.group("title"))
        index = occurrences.get(base, 0)
        occurrences[base] = index + 1
        anchors.add(base if index == 0 else f"{base}-{index}")
    return anchors


def _local_target(source: Path, destination: str) -> tuple[Path, str] | None:
    destination = html.unescape(destination.strip())
    if not destination or destination.startswith("//") or _SCHEME_RE.match(destination):
        return None

    path_text, _, fragment = destination.partition("#")
    path_text = unquote(path_text.partition("?")[0])
    if not path_text:
        target = source
    elif path_text.startswith("/"):
        target = ROOT / path_text.lstrip("/")
    else:
        target = source.parent / path_text
    return target.resolve(), unquote(fragment)


def test_local_markdown_links_resolve() -> None:
    failures: list[str] = []
    root = ROOT.resolve()

    for source in _markdown_files():
        text = source.read_text(encoding="utf-8")
        for line, destination in _destinations(text):
            resolved = _local_target(source, destination)
            if resolved is None:
                continue
            target, fragment = resolved
            label = f"{source.relative_to(ROOT)}:{line}: {destination}"
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{label} escapes the repository")
                continue
            if not target.exists():
                failures.append(f"{label} does not exist")
                continue
            if fragment and target.is_file() and target.suffix.lower() == ".md" and fragment not in _anchors(target):
                failures.append(f"{label} has no matching anchor")

    assert not failures, "broken local Markdown links:\n" + "\n".join(failures)
