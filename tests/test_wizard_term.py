"""Tests for ``mordred_hermes.wizard._term`` — the shared terminal-styling helper.

The wizard CLI is plain ``print()`` with no colour. ``_term`` centralises the
small amount of ANSI styling the CLI needs so every command styles output the
same way and the same TTY / ``NO_COLOR`` gate is applied everywhere.

Contract under test:

- ``should_color`` gates on ``isatty()`` and honours ``NO_COLOR`` (any value),
  ``FORCE_COLOR`` (overrides a non-tty), and ``TERM=dumb``. ``NO_COLOR`` wins
  over ``FORCE_COLOR`` when both are set (fail-safe to plain output).
- The string helpers (``success`` / ``warn`` / ``error`` / ``hint`` / ``bold`` /
  ``heading``) are pure: they take an explicit ``enabled`` and return styled or
  byte-identical plain text, so render code stays colour-free and testable.
- ``glyph`` degrades to ASCII when the stream encoding is not UTF-capable.
- ``emit_error`` / ``emit_warn`` auto-gate on the destination stream and prefix
  ``error:`` / ``warning:`` consistently.
"""

from __future__ import annotations

import io

import pytest

from mordred_hermes.wizard import _term


class _FakeStream:
    """Minimal stand-in for a stdout/stderr stream with controllable tty + encoding."""

    def __init__(self, *, tty: bool, encoding: str | None = "utf-8") -> None:
        self._tty = tty
        self.encoding = encoding

    def isatty(self) -> bool:
        return self._tty


# -----------------------------------------------------------------------------
# should_color — the single TTY / NO_COLOR / FORCE_COLOR gate
# -----------------------------------------------------------------------------
class TestShouldColor:
    def test_false_when_not_a_tty(self) -> None:
        assert _term.should_color(_FakeStream(tty=False), env={}) is False

    def test_true_for_tty_without_no_color(self) -> None:
        assert _term.should_color(_FakeStream(tty=True), env={}) is True

    def test_false_when_no_color_set(self) -> None:
        assert _term.should_color(_FakeStream(tty=True), env={"NO_COLOR": "1"}) is False

    def test_no_color_wins_even_with_empty_value(self) -> None:
        # https://no-color.org — presence disables, regardless of value.
        assert _term.should_color(_FakeStream(tty=True), env={"NO_COLOR": ""}) is False

    def test_force_color_overrides_non_tty(self) -> None:
        assert _term.should_color(_FakeStream(tty=False), env={"FORCE_COLOR": "1"}) is True

    def test_force_color_zero_does_not_force(self) -> None:
        assert _term.should_color(_FakeStream(tty=False), env={"FORCE_COLOR": "0"}) is False

    def test_term_dumb_disables_on_tty(self) -> None:
        assert _term.should_color(_FakeStream(tty=True), env={"TERM": "dumb"}) is False

    def test_no_color_beats_force_color(self) -> None:
        assert _term.should_color(_FakeStream(tty=True), env={"NO_COLOR": "1", "FORCE_COLOR": "1"}) is False

    def test_handles_stream_without_isatty(self) -> None:
        assert _term.should_color(object(), env={}) is False


# -----------------------------------------------------------------------------
# String helpers — pure, explicit enabled, byte-identical when disabled
# -----------------------------------------------------------------------------
class TestStringHelpers:
    def test_success_wraps_in_green_when_enabled(self) -> None:
        out = _term.success("ok", enabled=True)
        assert out.startswith("\033[32m")
        assert out.endswith("\033[0m")
        assert "ok" in out

    def test_plain_when_disabled_is_byte_identical(self) -> None:
        assert _term.success("ok", enabled=False) == "ok"
        assert _term.error("bad", enabled=False) == "bad"
        assert _term.warn("hmm", enabled=False) == "hmm"
        assert _term.hint("psst", enabled=False) == "psst"
        assert _term.bold("h", enabled=False) == "h"
        assert _term.heading("H", enabled=False) == "H"

    def test_error_uses_red(self) -> None:
        assert "\033[31m" in _term.error("bad", enabled=True)

    def test_warn_uses_yellow(self) -> None:
        assert "\033[33m" in _term.warn("hmm", enabled=True)

    def test_hint_uses_dim(self) -> None:
        assert "\033[2m" in _term.hint("psst", enabled=True)

    def test_bold_and_heading_use_bold(self) -> None:
        assert "\033[1m" in _term.bold("h", enabled=True)
        assert "\033[1m" in _term.heading("H", enabled=True)


# -----------------------------------------------------------------------------
# glyph — UTF-aware symbols with ASCII fallback
# -----------------------------------------------------------------------------
class TestGlyph:
    def test_unicode_glyphs(self) -> None:
        assert _term.glyph("on") == "●"
        assert _term.glyph("off") == "○"
        assert _term.glyph("paused") == "⏸"

    def test_ascii_fallback(self) -> None:
        assert _term.glyph("on", ascii_only=True) == "*"
        assert _term.glyph("off", ascii_only=True) == "-"
        assert _term.glyph("paused", ascii_only=True) == "="

    def test_supports_unicode_true_for_utf8(self) -> None:
        assert _term.supports_unicode(_FakeStream(tty=True, encoding="UTF-8")) is True

    def test_supports_unicode_false_for_ascii(self) -> None:
        assert _term.supports_unicode(_FakeStream(tty=True, encoding="ascii")) is False

    def test_supports_unicode_false_when_no_encoding(self) -> None:
        assert _term.supports_unicode(_FakeStream(tty=True, encoding=None)) is False
        assert _term.supports_unicode(object()) is False


# -----------------------------------------------------------------------------
# emit_error / emit_warn — auto-gated, consistently prefixed
# -----------------------------------------------------------------------------
class TestEmit:
    def test_emit_error_writes_prefix_plain_to_non_tty(self) -> None:
        buf = io.StringIO()  # not a tty -> no colour
        _term.emit_error("boom", stream=buf, env={})
        out = buf.getvalue()
        assert out.startswith("error: boom")
        assert "\033" not in out

    def test_emit_error_colours_when_forced(self) -> None:
        buf = io.StringIO()
        _term.emit_error("boom", stream=buf, env={"FORCE_COLOR": "1"})
        out = buf.getvalue()
        assert "\033[31m" in out
        assert "boom" in out

    def test_emit_warn_writes_warning_prefix(self) -> None:
        buf = io.StringIO()
        _term.emit_warn("careful", stream=buf, env={})
        assert buf.getvalue().startswith("warning: careful")

    def test_emit_note_writes_note_prefix_plain_to_non_tty(self) -> None:
        buf = io.StringIO()  # not a tty -> no colour
        _term.emit_note("heads up", stream=buf, env={})
        out = buf.getvalue()
        assert out.startswith("note: heads up")
        assert "\033" not in out

    def test_emit_note_colours_cyan_when_forced(self) -> None:
        buf = io.StringIO()
        _term.emit_note("heads up", stream=buf, env={"FORCE_COLOR": "1"})
        out = buf.getvalue()
        assert "\033[36m" in out  # cyan label
        assert "heads up" in out

    def test_emit_note_defaults_to_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        # Like emit_error / emit_warn, a note is a diagnostic and defaults to
        # stderr (so stdout stays reserved for primary command output).
        _term.emit_note("fyi", env={})
        captured = capsys.readouterr()
        assert captured.err.startswith("note: fyi")
        assert captured.out == ""
