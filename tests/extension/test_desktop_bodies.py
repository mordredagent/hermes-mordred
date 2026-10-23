"""Secret-bearing Desktop routes read their bodies themselves: no FastAPI 422 can echo a secret."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi import FastAPI
from fastapi.routing import APIRoute

from mordred_hermes.desktop import api

from ._desktop_support import PREFIX

CANARY = "BODY-CANARY-7f3a91"

SECRET_BEARING = [
    "/telegram/login/start",
    "/telegram/login/flow_ABCDEFGH1234/code",
    "/telegram/login/flow_ABCDEFGH1234/password",
    "/llm/venice",
    "/llm/local",
    "/vault/prepare",
    "/vault/flow_ABCDEFGH1234/commit",
    "/mail/setup/start",
    "/mail/setup/flow_ABCDEFGH1234/finish",
    "/mail/forget",
    "/uninstall",
]
# Not secret-bearing, but hand-read too (new routes).
ALSO_HAND_READ = ["/mail/fetch", "/databases/encrypt"]

MALFORMED = [
    f'["{CANARY}"]'.encode(),  # a JSON array
    f'"{CANARY}"'.encode(),  # a JSON string
    b"42",
    f'{{"app_password": "{CANARY}"'.encode(),  # truncated JSON
    f"api_key={CANARY}".encode(),  # a form body
    b"\xff\xfe" + CANARY.encode(),  # not UTF-8
]


@pytest.mark.parametrize("path", SECRET_BEARING + ALSO_HAND_READ)
@pytest.mark.parametrize("raw", MALFORMED)
def test_malformed_or_non_object_bodies_answer_invalid_body_without_echo(desktop: Any, path: str, raw: bytes) -> None:
    response = desktop.http.post(PREFIX + path, content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 200  # never FastAPI's 422 (which echoes ``input``)
    assert response.json() == {"ok": False, "error": "invalid_body"}
    assert CANARY not in response.text
    assert not desktop.leaked() and not any(CANARY in line for line in desktop.logs.lines)


def test_an_oversized_body_is_refused_unread(desktop: Any) -> None:
    raw = b'{"app_password": "' + b"x" * (70 * 1024) + b'"}'
    response = desktop.http.post(PREFIX + "/mail/setup/start", content=raw)
    assert response.json() == {"ok": False, "error": "invalid_body"}


def test_fastapi_never_validates_a_body_for_these_routes() -> None:
    routes = {route.path: route for route in api.router.routes if isinstance(route, APIRoute)}
    for path in SECRET_BEARING + ALSO_HAND_READ:
        template = path.replace("flow_ABCDEFGH1234", "{flow_id}")
        route = routes[template]
        assert route.body_field is None, template  # no body parameter: FastAPI has nothing to validate or echo
    # And the bodiless cancel route accepts an empty body.
    assert routes["/mail/setup/{flow_id}/cancel"].body_field is None
    # The OpenAPI schema agrees: no request body is declared for any of them.
    app = FastAPI()
    app.include_router(api.router, prefix=PREFIX)
    paths = app.openapi()["paths"]
    for path in SECRET_BEARING + ALSO_HAND_READ:
        template = PREFIX + path.replace("flow_ABCDEFGH1234", "{flow_id}")
        assert "requestBody" not in paths[template]["post"], template


def test_an_empty_body_is_an_empty_object(desktop: Any) -> None:
    response = desktop.http.post(PREFIX + "/mail/setup/flow_ABCDEFGH1234/cancel")
    assert response.json() == {"ok": True}
    # /vault/prepare takes {} (no body at all is the same).
    assert desktop.http.post(PREFIX + "/vault/prepare").json()["ok"] in (True, False)
