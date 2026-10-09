"""One process-wide stdout/stderr capture at a time for the Desktop API.

The Desktop runs wizard functions that report by printing (the Windows memory
ceremony, the uninstall plan and run, the helper builds) in worker threads.
``sys.stdout``/``sys.stderr`` are process globals, so two overlapping
``contextlib.redirect_stdout`` blocks can restore the streams in the wrong
order, and text printed meanwhile by an unrelated thread would land in a
response. :func:`captured_output` therefore:

- serializes every capture in the process behind one re-entrant lock (a
  nested capture in the same thread simply stacks);
- keeps only the capturing thread's text; other threads keep writing to the
  real stream (or nowhere when it is ``None`` under a windowed runtime);
- always restores exactly the streams it replaced.

A structured wizard result would remove the need to capture at all (recorded
for the C6-telegram slice).
"""

from __future__ import annotations

import io
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TextIO

__all__ = ["captured_output"]

_LOCK = threading.RLock()


class _ThreadStream(io.TextIOBase):
    """Writes from the owning thread go to ``buffer``; every other thread passes through."""

    def __init__(self, owner: int, buffer: io.StringIO, passthrough: TextIO | None) -> None:
        super().__init__()
        self._owner = owner
        self._buffer = buffer
        self._passthrough = passthrough

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        if threading.get_ident() == self._owner:
            return self._buffer.write(text)
        if self._passthrough is not None:
            return self._passthrough.write(text)
        return len(text)

    def flush(self) -> None:
        if threading.get_ident() != self._owner and self._passthrough is not None:
            self._passthrough.flush()

    def isatty(self) -> bool:
        return False


@contextmanager
def captured_output() -> Iterator[io.StringIO]:
    """Capture this thread's stdout and stderr into one buffer, one capture per process at a time."""
    buffer = io.StringIO()
    with _LOCK:
        owner = threading.get_ident()
        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout = _ThreadStream(owner, buffer, stdout)
        sys.stderr = _ThreadStream(owner, buffer, stderr)
        try:
            yield buffer
        finally:
            sys.stdout, sys.stderr = stdout, stderr
