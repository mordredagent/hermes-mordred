"""Trusted caller adapters; never read presence identities from tool arguments."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from ._presence import presence_scope


def _home() -> Path:
    from .._core._home import hermes_home

    return hermes_home().resolve()


def _check_in_profile(home: Path, check: Callable[[], bool]) -> bool:
    # Rebind only the framework's profile selector in a fresh context. Keeping
    # copy_context() in a reuse entry could retain unrelated request secrets.
    def evaluate() -> bool:
        try:
            import hermes_constants
        except ImportError:
            return _home() == home and check()
        select = getattr(hermes_constants, "set_hermes_home_override", None)
        reset = getattr(hermes_constants, "reset_hermes_home_override", None)
        if not callable(select) or not callable(reset):
            return _home() == home and check()
        token = select(str(home))
        try:
            return check()
        finally:
            reset(token)

    return contextvars.Context().run(evaluate)


def profile_guard(home: Path, check: Callable[[], bool] | None = None) -> Callable[[], bool]:
    # A request's profile ContextVar is absent on the independent monitor.
    # Observe process-level changes in an empty context; bind profile-specific
    # callbacks explicitly. The broker revokes prior scopes when this caller
    # selects another profile, including scopes still negotiating capabilities.
    baseline = contextvars.Context().run(_home)

    def current() -> bool:
        if contextvars.Context().run(_home) != baseline:
            return False
        return check is None or _check_in_profile(home, check)

    return current


@contextlib.contextmanager
def hermes_presence(session_id: str | None, purpose: str = "telegram") -> Iterator[None]:
    if not isinstance(session_id, str) or not session_id:
        yield
        return
    home = _home()
    with presence_scope(home, ("hermes", session_id), purpose, valid=profile_guard(home)):
        yield


@contextlib.contextmanager
def desktop_presence(request: Any, purpose: str) -> Iterator[None]:
    # Inspect the already-loaded host only. Importing web_server would construct
    # another app/token and cannot authenticate this request. Unrecognized hosts
    # (including child ASGI proxies without auth state) retain one-shot prompts.
    host = sys.modules.get("hermes_cli.web_server")
    app: Any = request.app
    if host is None or app is None or app is not getattr(host, "app", None):
        yield
        return
    state: Any = getattr(app, "state", None)
    token = getattr(host, "_SESSION_TOKEN", None)
    verify = getattr(host, "_has_valid_session_token", None)
    if (
        state is None
        or getattr(state, "auth_required", False)
        or not isinstance(token, str)
        or not token
        or not callable(verify)
        or not verify(request)
    ):
        yield
        return
    generation = hashlib.sha256(token.encode()).hexdigest()
    home = _home()
    profile_current = profile_guard(home)

    def current() -> bool:
        value = getattr(host, "_SESSION_TOKEN", None)
        return (
            profile_current()
            and sys.modules.get("hermes_cli.web_server") is host
            and getattr(host, "app", None) is app
            and getattr(app, "state", None) is state
            and not getattr(state, "auth_required", False)
            and isinstance(value, str)
            and hashlib.sha256(value.encode()).hexdigest() == generation
        )

    with presence_scope(home, ("desktop", generation), purpose, valid=current):
        yield
