"""Both layers end to end: the page's route schedules, startup converts, status reports the result.

Real leases, marker, journal, SQLCipher conversion and shim, as in
``tests/test_dbcrypt_startup.py``. Hardware is the software ``FakeBackend``. Only
the startup step (``dbcrypt.install``) may use custody: every route call runs with
``migrate``, ``arm`` and ``KeyProvider`` forbidden.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlcipher3")

from mordred_hermes import dbcrypt
from mordred_hermes._core._database_lifecycle import acquire_exclusive
from mordred_hermes.dbcrypt import _migrate, _shim, _startup
from mordred_hermes.dbcrypt._maintenance import convert_home
from mordred_hermes.desktop import _seams, api
from tests.test_dbcrypt_authority import native_root as native_root
from tests.test_dbcrypt_startup import (
    _configure_policy,
    _databases,
    _is_plaintext,
    _plain_db,
    _record,
    _release_process_state,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX authority fixture; Windows native proof is explicit")

SCHEDULED = {"ok": True, "action": "scheduled", "restart_required": True}


@pytest.fixture(params=["linux", "win32", "darwin"])
def scheduled_home(
    request: pytest.FixtureRequest, native_root: Any, desktop: Any, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Any]:
    """A plaintext, unarmed, enrolled home served by the Desktop API, nothing scheduled yet."""
    root, backend, key, snapshot = native_root
    dbcrypt.marker_path(root).unlink()
    _plain_db(root / "state.db")
    _plain_db(root / "profiles/work/state.db")
    _configure_policy(monkeypatch, root, request.param)
    monkeypatch.setattr(api, "_home", lambda: root)
    monkeypatch.setattr(_seams, "sqlcipher_available", lambda: True)
    backend.calls.clear()
    yield SimpleNamespace(root=root, backend=backend, key=key, snapshot=snapshot, desktop=desktop)
    _release_process_state(root)


def _route(home: Any, monkeypatch: pytest.MonkeyPatch, method: str, path: str) -> dict[str, Any]:
    """One route call that fails the test if it converts, arms or reaches custody."""

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("a Desktop route converted, armed or reached native custody")

    calls = list(home.backend.calls)
    with monkeypatch.context() as guarded:
        guarded.setattr(_migrate, "migrate", forbidden)
        guarded.setattr(dbcrypt._runtime, "arm", forbidden)
        guarded.setattr(dbcrypt, "arm", forbidden)
        guarded.setattr("mordred_hermes.dbcrypt._key.KeyProvider", forbidden)
        answer = home.desktop.get(path) if method == "get" else home.desktop.post(path, {})
    assert home.backend.calls == calls, "a route must never reach custody"
    return dict(answer)


def _restart(root: Path) -> None:
    """The process ends: its provider and leases go with it."""
    _release_process_state(root)
    dbcrypt._runtime._PROVIDER = None


def test_press_then_startup_converts_and_status_reports_done(
    scheduled_home: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = scheduled_home
    root = home.root
    before = _databases(root)

    assert _route(home, monkeypatch, "post", "/databases/encrypt") == SCHEDULED
    assert _migrate.pending_path(root).exists() and not dbcrypt.marker_path(root).exists()
    assert _databases(root) == before, "the press only schedules"
    status = _route(home, monkeypatch, "get", "/databases/status")
    assert status["encrypt_pending"] is True and status["armed"] is False
    assert status["runtime_protected"] is False and status["startup_outcome"] is None
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == SCHEDULED  # idempotent

    assert dbcrypt.install(home=root) is True  # the next start, before any database opens

    assert _shim.is_installed() and not _migrate.pending_path(root).exists()
    assert not _is_plaintext(root / "state.db") and not _is_plaintext(root / "profiles/work/state.db")
    calls = list(home.backend.calls)
    status = _route(home, monkeypatch, "get", "/databases/status")
    assert status == {
        "ok": True,
        "supported": True,
        "armed": True,
        "encrypt_pending": False,
        "decrypt_pending": False,
        "journal": False,
        "runtime_protected": True,
        "databases": [],
        "plaintext_backups": 0,
        "startup_outcome": None,
    }
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == {"ok": True, "action": "done"}
    assert _route(home, monkeypatch, "post", "/databases/cancel") == {
        "ok": True,
        "action": "attention",
        "code": "databases_cancel_refused",
    }
    assert home.backend.calls == calls, "polling a protected process never re-authenticates"


def test_armed_by_another_process_needs_a_restart(scheduled_home: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    home = scheduled_home
    root = home.root
    _route(home, monkeypatch, "post", "/databases/encrypt")
    # This backend started before the conversion, so it holds no authority.
    with acquire_exclusive(root, timeout=0) as lease:
        convert_home(root, lease=lease, decrypting=False)
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == {
        "ok": True,
        "action": "needs_restart",
        "restart_required": True,
    }
    assert _route(home, monkeypatch, "get", "/databases/status")["runtime_protected"] is False


def test_interrupted_attempt_shows_its_code_then_cancel_and_press_converts(
    scheduled_home: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = scheduled_home
    root = home.root
    before = _databases(root)
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == SCHEDULED
    _record(root, "attempting")  # a previous holder was killed while waiting on a prompt

    assert dbcrypt.install(home=root) is False  # the next start makes no custody call and continues plain
    assert home.backend.calls == [] and not _shim.is_installed() and _databases(root) == before
    status = _route(home, monkeypatch, "get", "/databases/status")
    assert status["startup_outcome"] == "auth_interrupted" and status["encrypt_pending"] is True
    attention = {"ok": True, "action": "attention", "code": "startup_auth_interrupted"}
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == attention

    # Restarting alone never retries: the code is sticky until the owner cancels.
    _restart(root)
    assert dbcrypt.install(home=root) is False
    assert home.backend.calls == [] and _route(home, monkeypatch, "post", "/databases/encrypt") == attention

    assert _route(home, monkeypatch, "post", "/databases/cancel") == {"ok": True, "action": "cancelled"}
    assert not (root / "mordred" / _startup.RECORD_NAME).exists() and not _migrate.pending_path(root).exists()
    assert _databases(root) == before, "cancelling converts nothing"
    status = _route(home, monkeypatch, "get", "/databases/status")
    assert status["encrypt_pending"] is False and status["startup_outcome"] is None

    assert _route(home, monkeypatch, "post", "/databases/encrypt") == SCHEDULED
    _restart(root)
    assert dbcrypt.install(home=root) is True
    assert not _is_plaintext(root / "state.db")
    status = _route(home, monkeypatch, "get", "/databases/status")
    assert status["armed"] is True and status["runtime_protected"] is True and status["startup_outcome"] is None
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == {"ok": True, "action": "done"}


@pytest.mark.parametrize(
    ("prepare", "code"),
    [
        (lambda root, monkeypatch: (root / "mordred/memory-vault.marker").unlink(), "startup_memory_required"),
        (
            lambda root, monkeypatch: monkeypatch.setattr(_startup, "STARTUP_CONVERSION_MAX_BYTES", 1),
            "startup_too_large",
        ),
    ],
    ids=["memory", "too-large-after-the-press"],
)
def test_a_postponed_start_shows_its_code_on_the_next_page_load(
    scheduled_home: Any, monkeypatch: pytest.MonkeyPatch, prepare: Any, code: str
) -> None:
    home = scheduled_home
    root = home.root
    before = _databases(root)
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == SCHEDULED
    prepare(root, monkeypatch)
    assert dbcrypt.install(home=root) is False
    assert home.backend.calls == [] and _databases(root) == before
    assert _route(home, monkeypatch, "get", "/databases/status")["startup_outcome"] is not None
    assert _route(home, monkeypatch, "post", "/databases/encrypt") == {"ok": True, "action": "attention", "code": code}
