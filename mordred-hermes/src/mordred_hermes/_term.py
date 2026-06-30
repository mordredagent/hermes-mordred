"""mordred_hermes._term — minimal, dependency-free terminal styling.

The Mordred CLI is plain ``print()`` with no colour. This module centralises the
small amount of ANSI styling the CLI needs so every command styles output the
same way and the same TTY / ``NO_COLOR`` gate is applied in one place.

Lives at the package root (sibling to :mod:`mordred_hermes._home` /
:mod:`mordred_hermes._yaml_io`) rather than under ``wizard`` so non-wizard
packages — notably ``keyvault._env_write_guard`` — can style output without
importing the wizard layer. A ``wizard._term`` re-export facade preserves the
historical import path so existing call sites and monkeypatch pins are unchanged.

Design contract:

- **Pure functions, no global mutable state.** The string builders take an
  explicit ``enabled`` flag and return styled-or-plain text; the caller decides
  with :func:`should_color`. This keeps ``render_text``-style functions
  colour-free by default so their existing exact-output tests stay valid — a
  renderer threads ``enabled=color`` (default ``False``) down to these helpers.
- **No third-party dependency.** Mordred deliberately minimises its supply
  chain; a ~100-line stdlib ANSI helper covers everything this CLI needs, so we
  do not pull in ``rich``/``colorama``.
- **Honours the ecosystem env vars.** ``NO_COLOR`` (https://no-color.org)
  disables colour whenever present (any value); ``FORCE_COLOR`` re-enables it
  even off a tty; ``TERM=dumb`` disables it. ``NO_COLOR`` wins over
  ``FORCE_COLOR`` when both are set — the fail-safe is plain output.
- **Glyphs degrade to ASCII** when the destination stream's encoding is not
  UTF-capable, so a non-UTF terminal never shows mojibake.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import IO, Any

__all__ = [
    "bold",
    "dim",
    "emit_error",
    "emit_note",
    "emit_warn",
    "error",
    "glyph",
    "heading",
    "hint",
    "info",
    "should_color",
    "success",
    "supports_unicode",
    "warn",
]

_RESET = "\033[0m"

# SGR codes used by the semantic helpers. Kept private — call sites use the
# named helpers (``success``/``warn``/…), never raw codes.
_BOLD = "1"
_DIM = "2"
_RED = "31"
_GREEN = "32"
_YELLOW = "33"
_CYAN = "36"

#: (unicode, ascii) pairs for every glyph the CLI renders. ASCII fallbacks are
#: chosen to read sensibly in a monospace terminal that cannot show the symbol.
_GLYPHS: dict[str, tuple[str, str]] = {
    "on": ("●", "*"),
    "off": ("○", "-"),
    "paused": ("⏸", "="),
    "sealed": ("●", "*"),
    "open": ("◐", "~"),
    "ok": ("✓", "+"),
    "fail": ("✗", "x"),
    "arrow": ("→", "->"),
}


def should_color(stream: Any, *, env: Mapping[str, str] | None = None) -> bool:
    """Whether ANSI colour should be emitted to *stream*.

    ``True`` only when the stream is a real terminal and nothing in the
    environment vetoes colour. Resolution order (first match wins):

    1. ``NO_COLOR`` present (any value) -> ``False`` (fail-safe to plain).
    2. ``FORCE_COLOR`` present and not ``"0"`` -> ``True`` (even off a tty).
    3. ``TERM=dumb`` -> ``False``.
    4. otherwise -> ``stream.isatty()`` (a stream lacking ``isatty`` -> ``False``).
    """
    environ = os.environ if env is None else env
    if "NO_COLOR" in environ:
        return False
    force = environ.get("FORCE_COLOR")
    if force is not None and force != "0":
        return True
    if environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        # A closed or detached stream can raise on isatty(); treat as non-tty.
        return False


def supports_unicode(stream: Any) -> bool:
    """Whether *stream* can encode the UTF glyphs (else ASCII fallback applies)."""
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    return "utf" in encoding.lower()


def _style(text: str, code: str, *, enabled: bool) -> str:
    """Wrap *text* in the SGR *code* when *enabled*, else return it unchanged."""
    if not enabled:
        return text
    return f"\033[{code}m{text}{_RESET}"


def success(text: str, *, enabled: bool) -> str:
    """Green — a completed / protected / healthy state."""
    return _style(text, _GREEN, enabled=enabled)


def warn(text: str, *, enabled: bool) -> str:
    """Yellow — a paused / attention-needed state."""
    return _style(text, _YELLOW, enabled=enabled)


def error(text: str, *, enabled: bool) -> str:
    """Red — a failure / refusal state."""
    return _style(text, _RED, enabled=enabled)


def hint(text: str, *, enabled: bool) -> str:
    """Dim — secondary guidance (e.g. a 'Next:' line, a legend)."""
    return _style(text, _DIM, enabled=enabled)


def dim(text: str, *, enabled: bool) -> str:
    """Dim — de-emphasised text (e.g. an 'off' / not-set-up state)."""
    return _style(text, _DIM, enabled=enabled)


def info(text: str, *, enabled: bool) -> str:
    """Cyan — an in-use / transient state (e.g. a mounted workspace)."""
    return _style(text, _CYAN, enabled=enabled)


def bold(text: str, *, enabled: bool) -> str:
    """Bold — emphasis."""
    return _style(text, _BOLD, enabled=enabled)


def heading(text: str, *, enabled: bool) -> str:
    """Bold — a section heading (same SGR as :func:`bold`, named for intent)."""
    return _style(text, _BOLD, enabled=enabled)


def glyph(name: str, *, ascii_only: bool = False) -> str:
    """The glyph for *name*, ASCII when *ascii_only* (non-UTF terminal)."""
    unicode_glyph, ascii_glyph = _GLYPHS[name]
    return ascii_glyph if ascii_only else unicode_glyph


def _emit(label: str, code: str, message: str, *, stream: IO[str] | None, env: Mapping[str, str] | None) -> None:
    """Print ``<label>: <message>`` to *stream*, colouring the label when allowed."""
    dest = sys.stderr if stream is None else stream
    enabled = should_color(dest, env=env)
    prefix = _style(f"{label}:", code, enabled=enabled)
    print(f"{prefix} {message}", file=dest)


def emit_error(message: str, *, stream: IO[str] | None = None, env: Mapping[str, str] | None = None) -> None:
    """Print ``error: <message>`` to stderr (red label when the stream is a tty)."""
    _emit("error", _RED, message, stream=stream, env=env)


def emit_warn(message: str, *, stream: IO[str] | None = None, env: Mapping[str, str] | None = None) -> None:
    """Print ``warning: <message>`` to stderr (yellow label when the stream is a tty)."""
    _emit("warning", _YELLOW, message, stream=stream, env=env)


def emit_note(message: str, *, stream: IO[str] | None = None, env: Mapping[str, str] | None = None) -> None:
    """Print ``note: <message>`` to stderr (cyan label when the stream is a tty).

    For advisory / informational diagnostics that are not failures — e.g. a
    best-effort cleanup that degraded. Defaults to stderr like
    :func:`emit_error` / :func:`emit_warn` so stdout stays reserved for a
    command's primary output.
    """
    _emit("note", _CYAN, message, stream=stream, env=env)
