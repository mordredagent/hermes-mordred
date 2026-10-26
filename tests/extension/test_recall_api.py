"""``recall_query`` / ``recall_open`` / ``recall_dismiss`` on the /ext gateway.

The selection must arrive sealed with K_extchat and every result leaves sealed;
refusals are content-free codes. The service is a fake: store behaviour is
covered in ``tests/recall``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import pairing
from mordred_hermes.extension.crypto import decrypt_message, encrypt_message_v2, hkdf_subkey, key_id
from mordred_hermes.recall.service import RecallError

_AES = b"\x02" * 32
_EK = hkdf_subkey(_AES, "mordred-extchat-v1", "extchat")


class _FakeWS:
    def __init__(self) -> None:
        self.closed = False
        self.sent: list[dict[str, Any]] = []

    async def send_str(self, data: str) -> None:
        self.sent.append(json.loads(data))


async def _no_chat(_content: str, _context: dict[str, Any]) -> Any:
    if False:
        yield ""


class _FakeRecall:
    def __init__(self, fail: str | None = None) -> None:
        self.fail = fail
        self.calls: list[tuple[str, Any]] = []

    def _check(self) -> None:
        if self.fail == "boom":
            raise RuntimeError("secret store text")
        if self.fail is not None:
            raise RecallError(self.fail)

    def query(self, text: str, *, limit: int = 8) -> dict[str, Any]:
        self.calls.append(("query", (text, limit)))
        self._check()
        return {"query": text, "confidence": "high", "cards": [{"uid": "tg:-1:1#a", "excerpt": "経費精算は27日"}]}

    def open(self, part_uid: str, *, before: int = 2, after: int = 2) -> list[dict[str, Any]]:
        self.calls.append(("open", (part_uid, before, after)))
        self._check()
        return [{"part_uid": part_uid, "text": "前後の発言", "anchor": True}]

    def dismiss(self, conv_uid: str) -> None:
        self.calls.append(("dismiss", conv_uid))
        self._check()


def _conn(svc: Any, *, page: bool = False) -> Any:
    token = "recall-test-token"
    pairing._save_pairing(
        pairing.Pairing(
            aes_key=_AES,
            ext_token=token,
            ext_pubkey_b64="ext",
            hermes_pubkey_b64="hermes",
            paired_at=1.0,
        )
    )
    conn = extension_api._Connection(_FakeWS(), _no_chat, recall_service=svc, page_token="p" if page else None)
    conn.authed = True
    if page:
        conn._page_authenticated = True
    else:
        conn._authentication_generation = pairing.authentication_generation_fingerprint(token)
    return conn


def _dispatch(conn: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    asyncio.run(conn.dispatch(json.dumps(payload)))
    return list(conn.ws.sent)


def _sealed(text: str) -> str:
    return encrypt_message_v2(_EK, text, key_id(_EK))


def test_query_decrypts_the_selection_and_seals_the_cards() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": _sealed("経費精算"), "limit": 5})
    assert svc.calls == [("query", ("経費精算", 5))]
    assert frame["type"] == "recall_result" and frame["ok"] is True and frame["id"] == "q"
    assert "経費精算" not in json.dumps(frame, ensure_ascii=False)
    payload = json.loads(decrypt_message(_EK, frame["content"]))
    assert payload["cards"][0]["excerpt"] == "経費精算は27日"


def test_query_refuses_a_plaintext_selection_without_touching_the_store() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": "経費精算"})
    assert frame == {"id": "q", "type": "recall_result", "ok": False, "error": "invalid_request"}
    assert svc.calls == []


def test_query_rejects_bad_limits_and_undecryptable_text() -> None:
    svc = _FakeRecall()
    for limit in (0, 21, True, "8"):
        [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": _sealed("x"), "limit": limit})
        assert frame["error"] == "invalid_request"
    other = hkdf_subkey(b"\x03" * 32, "mordred-extchat-v1", "extchat")
    foreign = encrypt_message_v2(other, "x", key_id(other))
    [frame] = _dispatch(_conn(svc), {"id": "q", "type": "recall_query", "text": foreign})
    assert frame["error"] == "undecryptable"
    assert svc.calls == []


def test_store_failures_become_codes_without_content() -> None:
    [frame] = _dispatch(
        _conn(_FakeRecall("import_store_unavailable")), {"id": "q", "type": "recall_query", "text": _sealed("x")}
    )
    assert frame == {"id": "q", "type": "recall_result", "ok": False, "error": "import_store_unavailable"}
    [frame] = _dispatch(_conn(_FakeRecall("boom")), {"id": "o", "type": "recall_open", "part_uid": "tg:-1:1#a"})
    assert frame == {"id": "o", "type": "recall_opened", "ok": False, "error": "recall_unavailable"}


def test_open_seals_the_context_and_bounds_the_window() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(
        _conn(svc), {"id": "o", "type": "recall_open", "part_uid": "mail:work:<a@example.com>#a", "before": 1}
    )
    assert svc.calls == [("open", ("mail:work:<a@example.com>#a", 1, 2))]
    assert json.loads(decrypt_message(_EK, frame["content"]))["parts"][0]["text"] == "前後の発言"
    for bad in ({"part_uid": ""}, {"part_uid": "a\nb"}, {"part_uid": "x", "after": 6}, {"part_uid": 3}):
        [frame] = _dispatch(_conn(svc), {"id": "o", "type": "recall_open", **bad})
        assert frame["error"] == "invalid_request"
    assert len(svc.calls) == 1


def test_dismiss_acknowledges() -> None:
    svc = _FakeRecall()
    [frame] = _dispatch(_conn(svc), {"id": "d", "type": "recall_dismiss", "conv_uid": "tg:-1"})
    assert frame == {"id": "d", "type": "recall_dismissed", "ok": True}
    assert svc.calls == [("dismiss", "tg:-1")]


def test_page_sessions_cannot_recall() -> None:
    svc = _FakeRecall()
    for payload in (
        {"id": "q", "type": "recall_query", "text": _sealed("x")},
        {"id": "o", "type": "recall_open", "part_uid": "tg:-1:1#a"},
        {"id": "d", "type": "recall_dismiss", "conv_uid": "tg:-1"},
    ):
        conn = _conn(svc, page=True)
        [frame] = _dispatch(conn, payload)
        assert frame == {"id": payload["id"], "type": "error", "reason": "page_session_forbidden"}
    assert svc.calls == []
