"""Read a request body by hand, so FastAPI never validates (and echoes) it.

A route that declares ``body: dict`` lets FastAPI answer a malformed body with
HTTP 422 whose ``detail[].input`` repeats what was sent: an app password, a
Telegram code or a Venice key posted as a JSON array would come straight back
(and land in Desktop's log of non-2xx answers). Every secret-bearing route
therefore takes the raw ``Request`` and calls :func:`read_object`, which
answers ``{"ok": false, "error": "invalid_body"}`` (HTTP 200, no echo) for
anything but a JSON object. An empty body is an empty object.
"""

from __future__ import annotations

import json
from typing import Any, Final

from fastapi import Request
from fastapi.responses import JSONResponse

__all__ = ["INVALID_BODY", "MAX_BODY_BYTES", "invalid_body", "read_object"]

INVALID_BODY: Final = "invalid_body"
#: Every body the page sends is a few hundred bytes; anything far larger is not ours.
MAX_BODY_BYTES: Final = 64 * 1024


def invalid_body() -> JSONResponse:
    return JSONResponse({"ok": False, "error": INVALID_BODY}, status_code=200)


async def read_object(request: Request) -> dict[str, Any] | JSONResponse:
    """The body as a JSON object, or the ``invalid_body`` answer; the body is never logged or echoed."""
    try:
        raw = await request.body()
    except Exception:  # a client that disconnected mid-body: nothing to answer with
        return invalid_body()
    if len(raw) > MAX_BODY_BYTES:
        return invalid_body()
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        return invalid_body()
    return value if isinstance(value, dict) else invalid_body()
