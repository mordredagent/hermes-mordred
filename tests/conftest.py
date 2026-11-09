"""Root pytest conftest: make the suite self-isolating against the developer's
real Hermes home.

``src/mordred_hermes/_core/_home.py`` resolves ``HERMES_BASE`` **at import time**
(``HERMES_BASE: Final = hermes_home()``), and several plugins derive their
``DEFAULT_*`` path constants from that frozen value. That means the very first
import of ``mordred_hermes`` (or any of its plugins) anywhere in the process —
including pytest's own test collection — permanently decides which Hermes
home the whole run operates against.

The serial fallback happens here at **module import time**. Real xdist workers
replace the inherited home in early ``pytest_configure``, before test-module
collection; fixtures run too late. This module itself must NOT import ``mordred_hermes`` or
``hermes`` — doing either would freeze ``HERMES_BASE`` against whatever
``HERMES_HOME`` happens to be set (or unset, falling back to ``~/.hermes``)
at that point, before we get a chance to set it below.

``setdefault``-style semantics: an explicit ``HERMES_HOME`` from the caller or
CI is left untouched in serial runs and wins as-is. Only a *bare* invocation (no
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
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests._keyvault_receipts import RegisterFakeBackend

if "HERMES_HOME" not in os.environ:
    _home = tempfile.mkdtemp(prefix="mordred-tests-home-")
    os.environ["HERMES_HOME"] = _home
    atexit.register(shutil.rmtree, _home, ignore_errors=True)


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """Give genuine workers private homes before any product paths can freeze.

    A nested serial pytest inherits PYTEST_XDIST_WORKER, but has no workerinput.
    Never remove or replace its caller-owned home based on environment alone.
    """
    if getattr(config, "workerinput", None) is None:
        return
    imported = sorted(name for name in sys.modules if name == "mordred_hermes" or name.startswith("mordred_hermes."))
    if imported:
        raise pytest.UsageError("product modules imported before worker home isolation: " + ", ".join(imported))
    home = tempfile.mkdtemp(prefix="mordred-tests-worker-home-")
    os.environ["HERMES_HOME"] = home
    config.add_cleanup(lambda: shutil.rmtree(home, ignore_errors=True))


@pytest.fixture
def fake_native_creation_receipts(monkeypatch: pytest.MonkeyPatch) -> RegisterFakeBackend:
    """Explicit legacy-test opt-in; native backends retain production receipts."""
    from tests._keyvault_receipts import install_fake_creation_receipts

    return install_fake_creation_receipts(monkeypatch)


@pytest.fixture(autouse=True)
def _memory_key_holder_isolation() -> Iterator[None]:
    """Each test starts and ends with an empty holder and no ambient memory key.

    Imported here, not at module scope: see the module docstring.
    """
    from mordred_hermes.keyvault import _memory_key_holder

    _memory_key_holder._reset_for_tests()
    os.environ.pop(_memory_key_holder.MEMORY_KEY_ENV, None)
    yield
    _memory_key_holder._reset_for_tests()
    os.environ.pop(_memory_key_holder.MEMORY_KEY_ENV, None)


@pytest.fixture(autouse=True)
def _platform_registry_hook_isolation() -> Iterator[None]:
    """Undo the E2E ``PlatformRegistry.create_adapter`` hook after each test.

    Tests that call the real plugin ``register()`` hook the installed Hermes
    registry class; without this it stays hooked for the rest of the session.
    Only an already-imported registry is touched: importing ``gateway`` here
    would cache it for tests that simulate an unimportable gateway.
    """
    yield
    registry_module = sys.modules.get("gateway.platform_registry")
    registry_cls = getattr(registry_module, "PlatformRegistry", None)
    if registry_cls is None:
        return
    create = registry_cls.__dict__.get("create_adapter")
    while getattr(create, "__mordred_wrapped__", False) and getattr(create, "__wrapped__", None) is not None:
        create = create.__wrapped__
    if create is not None and create is not registry_cls.__dict__.get("create_adapter"):
        registry_cls.create_adapter = create


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
