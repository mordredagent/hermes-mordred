"""One process-wide stdout/stderr capture at a time for the Desktop API (C11 round 1).

``sys.stdout``/``sys.stderr`` are process globals. The Desktop captures the
wizard's output in worker threads (memory ceremony, uninstall plan and run,
helper builds), so two overlapping redirects could restore the streams in the
wrong order, and text printed by unrelated threads could land in a response.
``desktop._capture.captured_output`` serializes every capture behind one lock
and keeps only the capturing thread's text.
"""

from __future__ import annotations

import sys
import threading
import time

import pytest


def capture():
    from mordred_hermes.desktop import _capture

    return _capture


def test_capture_keeps_only_the_owning_threads_text(capsys):
    started, release = threading.Event(), threading.Event()
    box: dict[str, str] = {}

    def owner() -> None:
        with capture().captured_output() as out:
            print("owner line")
            started.set()
            release.wait(5)
            print("owner tail", file=sys.stderr)
        box["out"] = out.getvalue()

    thread = threading.Thread(target=owner)
    thread.start()
    assert started.wait(5)
    print("unrelated thread line")
    release.set()
    thread.join(5)
    assert box["out"] == "owner line\nowner tail\n"
    assert "unrelated thread line" in capsys.readouterr().out, "other threads keep the real stream"


def test_captures_never_overlap_and_restore_the_original_streams():
    original_out, original_err = sys.stdout, sys.stderr
    events: list[str] = []
    first_inside = threading.Event()
    release_first = threading.Event()

    def first() -> None:
        with capture().captured_output():
            events.append("first in")
            first_inside.set()
            release_first.wait(5)
            events.append("first out")

    def second() -> None:
        with capture().captured_output():
            events.append("second in")
        events.append("second done")

    one = threading.Thread(target=first)
    one.start()
    assert first_inside.wait(5)
    two = threading.Thread(target=second)
    two.start()
    time.sleep(0.2)
    assert events == ["first in"], "the second capture waits for the first"
    release_first.set()
    one.join(5)
    two.join(5)
    assert events == ["first in", "first out", "second in", "second done"]
    assert sys.stdout is original_out and sys.stderr is original_err


def test_capture_tolerates_absent_streams(monkeypatch):
    """Under ``pythonw`` (a windowed Desktop runtime) ``sys.stdout`` may be ``None``."""
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    with capture().captured_output() as out:
        print("captured")
    assert out.getvalue() == "captured\n"
    assert sys.stdout is None and sys.stderr is None


def test_nested_capture_in_one_thread_does_not_deadlock():
    with capture().captured_output() as outer:
        print("outer")
        with capture().captured_output() as inner:
            print("inner")
        print("outer again")
    assert inner.getvalue() == "inner\n"
    assert outer.getvalue() == "outer\nouter again\n"


@pytest.mark.parametrize("module", ["api", "_windows"])
def test_desktop_code_has_no_raw_redirects(module):
    from importlib.util import find_spec

    spec = find_spec(f"mordred_hermes.desktop.{module}")
    assert spec is not None and spec.origin is not None
    with open(spec.origin, encoding="utf-8") as handle:
        text = handle.read()
    assert "redirect_stdout" not in text and "redirect_stderr" not in text, "every capture goes through _capture"
