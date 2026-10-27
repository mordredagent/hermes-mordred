"""``imports_status`` / ``imports_call`` on the /ext gateway, and :class:`ImportsApi` behind them.

Both bodies cross the wire sealed with K_extchat; refusals are content-free
codes, and nothing registers twice (a running job is returned, a configured
account refuses a new setup). Libraries are fakes: the import store and the
local readers are covered in ``tests/imports``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.extension import api as extension_api
from mordred_hermes.extension import pairing
from mordred_hermes.extension.crypto import decrypt_message, encrypt_message_v2, hkdf_subkey, key_id
from mordred_hermes.extension.imports_api import ImportsApi, ImportsRefusal

_AES = b"\x03" * 32
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


class _FakeImports:
    def __init__(self, refusal: str | None = None) -> None:
        self.refusal = refusal
        self.calls: list[dict[str, Any]] = []

    async def status(self) -> dict[str, Any]:
        return {"telegram": {"logged_in": True, "account_label": "私のアカウント"}, "jobs": []}

    async def call(self, body: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(body)
        if self.refusal is not None:
            raise ImportsRefusal(self.refusal)
        return {"flow_id": "flow-0001", "step": "code"}


def _conn(imports: Any, *, page: bool = False) -> Any:
    token = "imports-test-token"
    pairing._save_pairing(
        pairing.Pairing(aes_key=_AES, ext_token=token, ext_pubkey_b64="ext", hermes_pubkey_b64="hermes", paired_at=1.0)
    )
    conn = extension_api._Connection(_FakeWS(), _no_chat, imports_api=imports, page_token="p" if page else None)
    conn.authed = True
    if page:
        conn._page_authenticated = True
    else:
        conn._authentication_generation = pairing.authentication_generation_fingerprint(token)
    return conn


def _dispatch(conn: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    asyncio.run(conn.dispatch(json.dumps(payload)))
    return list(conn.ws.sent)


def _sealed(value: Any) -> str:
    return encrypt_message_v2(_EK, json.dumps(value, ensure_ascii=False), key_id(_EK))


def test_status_leaves_sealed() -> None:
    [frame] = _dispatch(_conn(_FakeImports()), {"id": "s", "type": "imports_status"})
    assert frame["type"] == "imports_status_result" and frame["ok"] is True
    assert "私のアカウント" not in json.dumps(frame, ensure_ascii=False)
    assert json.loads(decrypt_message(_EK, frame["content"]))["telegram"]["account_label"] == "私のアカウント"


def test_call_decrypts_the_body_and_seals_the_answer() -> None:
    imports = _FakeImports()
    body = {"op": "telegram_login_start", "phone": "+810000000000"}
    [frame] = _dispatch(_conn(imports), {"id": "c", "type": "imports_call", "content": _sealed(body)})
    assert imports.calls == [body]
    assert frame["type"] == "imports_call_result" and frame["ok"] is True
    assert json.loads(decrypt_message(_EK, frame["content"])) == {"flow_id": "flow-0001", "step": "code"}


def test_plaintext_and_undecryptable_bodies_are_refused() -> None:
    imports = _FakeImports()
    [plain] = _dispatch(_conn(imports), {"id": "c", "type": "imports_call", "content": '{"op": "job"}'})
    assert plain == {"id": "c", "type": "imports_call_result", "ok": False, "error": "invalid_request"}
    other = encrypt_message_v2(b"\x09" * 32, "{}", key_id(b"\x09" * 32))
    [bad] = _dispatch(_conn(imports), {"id": "c", "type": "imports_call", "content": other})
    assert bad["error"] == "undecryptable" and imports.calls == []


def test_refusal_codes_pass_through() -> None:
    body = {"op": "mail_setup_start", "address": "a@example.com", "app_password": "x"}
    [frame] = _dispatch(
        _conn(_FakeImports("mail_already_configured")), {"id": "c", "type": "imports_call", "content": _sealed(body)}
    )
    assert frame == {"id": "c", "type": "imports_call_result", "ok": False, "error": "mail_already_configured"}


def test_page_sessions_never_reach_imports() -> None:
    imports = _FakeImports()
    [frame] = _dispatch(_conn(imports, page=True), {"id": "s", "type": "imports_status"})
    assert frame == {"id": "s", "type": "error", "reason": "page_session_forbidden"}
    assert imports.calls == []


# -- ImportsApi ------------------------------------------------------------------------


class _Telegram:
    async def status(self) -> dict[str, Any]:
        return {"configured": True, "logged_in": True}


def _api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ImportsApi:
    api = ImportsApi(telegram_service=_Telegram, home=lambda: tmp_path, platform="darwin")

    async def allowed() -> None:
        return None

    monkeypatch.setattr(api, "_require_memory", allowed)
    monkeypatch.setattr(api, "_require_hermes_model", allowed)
    return api


def test_local_import_runs_once_and_reports_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    from mordred_hermes.imports import local
    from mordred_hermes.imports.local.runner import LocalImportResult

    release = threading.Event()
    runs: list[str] = []

    def fake_run(source: str, *, home: Path, progress: Any) -> LocalImportResult:
        runs.append(source)
        progress({"files_done": 1, "files_total": 2})
        release.wait(5)
        return LocalImportResult(source=source, files_seen=2, files_changed=2, inserted=3)

    monkeypatch.setattr(local, "run_local_import", fake_run)
    api = _api(tmp_path, monkeypatch)

    async def scenario() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        first = await api.call({"op": "local_import", "source": "codex"})
        second = await api.call({"op": "local_import", "source": "codex"})
        release.set()
        for _ in range(200):
            view = await api.call({"op": "job", "job_id": first["job_id"]})
            if view["state"] != "running":
                return first, second, view
            await asyncio.sleep(0.01)
        raise AssertionError("job did not finish")

    first, second, done = asyncio.run(scenario())
    assert (first["already_running"], second["already_running"]) == (False, True)
    assert second["job_id"] == first["job_id"] and runs == ["codex"]
    assert done["state"] == "done" and done["progress"]["result"]["inserted"] == 3


def test_local_import_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.imports import local

    def missing(source: str, *, home: Path, progress: Any) -> Any:
        raise local.LocalImportError("source_not_found")

    monkeypatch.setattr(local, "run_local_import", missing)
    api = _api(tmp_path, monkeypatch)

    async def scenario() -> dict[str, Any]:
        job = await api.call({"op": "local_import", "source": "grok_bot"})
        for _ in range(200):
            view = await api.call({"op": "job", "job_id": job["job_id"]})
            if view["state"] != "running":
                return view
            await asyncio.sleep(0.01)
        raise AssertionError("job did not finish")

    assert asyncio.run(scenario())["error"] == "source_not_found"
    with pytest.raises(ImportsRefusal) as unknown:
        asyncio.run(api.call({"op": "local_import", "source": "telegram"}))
    assert unknown.value.code == "invalid_request"


def test_a_logged_in_telegram_refuses_a_second_login(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.extension.telegram.login_flow import LoginError

    class Flows:
        async def start(self, **_kwargs: Any) -> Any:
            raise LoginError("telegram_already_logged_in")

    api = _api(tmp_path, monkeypatch)
    api._telegram_flows = Flows()
    with pytest.raises(ImportsRefusal) as refused:
        asyncio.run(api.call({"op": "telegram_login_start", "phone": "+810000000000"}))
    assert refused.value.code == "telegram_already_logged_in"


def test_configured_mail_refuses_a_second_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.imports.mail.setup_flow import MailSetupError

    class Flows:
        def start(self, **_kwargs: Any) -> Any:
            raise MailSetupError("mail_already_configured")

    api = _api(tmp_path, monkeypatch)
    api._mail_flows = Flows()
    body = {"op": "mail_setup_start", "address": "a@example.com", "app_password": "abcdabcdabcdabcd"}
    with pytest.raises(ImportsRefusal) as refused:
        asyncio.run(api.call(body))
    assert refused.value.code == "mail_already_configured"


def test_unknown_ops_and_bad_fields_are_invalid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api(tmp_path, monkeypatch)
    for body in (
        {"op": "drop_tables"},
        {"op": "telegram_login_code", "flow_id": "x", "code": "1"},
        {"op": "telegram_sync", "days": 0},
        {"op": "mail_fetch", "max": 5000},
        {"op": "job", "job_id": "../../etc"},
    ):
        with pytest.raises(ImportsRefusal) as refused:
            asyncio.run(api.call(body))
        assert refused.value.code == "invalid_request", body


def test_non_darwin_refuses_mail_and_local_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api(tmp_path, monkeypatch)
    api._platform = "linux"
    for body in ({"op": "local_import", "source": "codex"}, {"op": "mail_fetch"}):
        with pytest.raises(ImportsRefusal) as refused:
            asyncio.run(api.call(body))
        assert refused.value.code == "unsupported_platform"


def test_status_merges_the_desktop_sections_with_local_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import _status_v4
    from mordred_hermes.extension import imports_api
    from mordred_hermes.imports import local

    monkeypatch.setattr(
        _status_v4,
        "imports_sections",
        lambda _home, _platform: {"imports": {"available": True}, "mail": {"configured": True}},
    )
    monkeypatch.setattr(local, "local_status", lambda: {"codex": {"available": True}, "grok_bot": {"available": False}})
    monkeypatch.setattr(
        imports_api, "_local_counts", lambda _home: {"codex": {"conversations": 2, "messages": 9, "last_import_at": 7}}
    )
    status = asyncio.run(_api(tmp_path, monkeypatch).status())
    assert status["mail"] == {"configured": True}
    assert status["telegram"] == {"configured": True, "logged_in": True}
    assert status["local"]["codex"] == {"available": True, "conversations": 2, "messages": 9, "last_import_at": 7}
    assert status["local"]["grok_bot"] == {
        "available": False,
        "conversations": 0,
        "messages": 0,
        "last_import_at": None,
    }
    assert status["jobs"] == []
