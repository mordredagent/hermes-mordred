"""Trusted caller adapters; never read presence identities from tool arguments."""

from __future__ import annotations

import contextlib
import hashlib
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ._presence import presence_scope


def _home() -> Path:
    from .._core._home import hermes_home

    return hermes_home().resolve()


@contextlib.contextmanager
def hermes_presence(session_id: str | None, purpose: str = "telegram") -> Iterator[None]:
    if not isinstance(session_id, str) or not session_id:
        yield
        return
    home = _home()
    with presence_scope(home, ("hermes", session_id), purpose, valid=lambda: _home() == home):
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

    def current() -> bool:
        value = getattr(host, "_SESSION_TOKEN", None)
        return (
            _home() == home
            and sys.modules.get("hermes_cli.web_server") is host
            and getattr(host, "app", None) is app
            and getattr(app, "state", None) is state
            and not getattr(state, "auth_required", False)
            and isinstance(value, str)
            and hashlib.sha256(value.encode()).hexdigest() == generation
        )

    with presence_scope(home, ("desktop", generation), purpose, valid=current):
        yield
