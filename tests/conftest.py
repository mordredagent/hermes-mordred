"""Root pytest conftest: make the suite self-isolating against the developer's
real Hermes home.

``src/mordred_hermes/_home.py`` resolves ``HERMES_BASE`` **at import time**
(``HERMES_BASE: Final = hermes_home()``), and several plugins derive their
``DEFAULT_*`` path constants from that frozen value. That means the very first
import of ``mordred_hermes`` (or any of its plugins) anywhere in the process —
including pytest's own test collection — permanently decides which Hermes
home the whole run operates against.

So this has to happen here, at **module import time**, before pytest imports
any test module that could import ``mordred_hermes`` first. It must NOT be a
fixture or a hook (those only run after collection has already imported test
modules) and this module itself must NOT import ``mordred_hermes`` or
``hermes`` — doing either would freeze ``HERMES_BASE`` against whatever
``HERMES_HOME`` happens to be set (or unset, falling back to ``~/.hermes``)
at that point, before we get a chance to set it below.

``setdefault``-style semantics: an explicit ``HERMES_HOME`` from the caller or
CI is left untouched and wins as-is. Only a *bare* invocation (no
``HERMES_HOME`` in the environment) gets a throwaway temp directory, cleaned
up at interpreter exit.

That ``atexit`` cleanup means a test must never leave a *detached* child
process running that inherited this ambient ``HERMES_HOME``: every subprocess
test today either passes its own ``tmp_path`` via ``env=`` or joins the child
before returning, and new ones should do the same.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest

if "HERMES_HOME" not in os.environ:
    _home = tempfile.mkdtemp(prefix="mordred-tests-home-")
    os.environ["HERMES_HOME"] = _home
    atexit.register(shutil.rmtree, _home, ignore_errors=True)


def pytest_collection_finish(session: pytest.Session) -> None:
    """Refuse extension execution if the runner loses its local autouse fixtures.

    Pytest 9.1.0/9.1.1 can orphan directory conftests with interleaved file
    arguments. Check the public fixture closure after normal deselection;
    ``memory_plain`` still requires the fixture, whose body implements that opt-out.
    """
    extension = Path(__file__).parent / "extension"
    required = {"_isolated_home", "_memory_encryption_on"}
    missing = []
    for item in session.items:
        if isinstance(item, pytest.Function) and item.path.is_relative_to(extension):
            absent = required.difference(item.fixturenames)
            if absent:
                missing.append(f"{item.nodeid}: {', '.join(sorted(absent))}")
    if missing:
        raise pytest.UsageError("extension isolation fixtures missing; refusing test execution:\n" + "\n".join(missing))
