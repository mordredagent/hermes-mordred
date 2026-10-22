"""Reader mode (privacy_check.egress + _reader_sessions): imported text never triggers actions."""

from __future__ import annotations

import os
import re
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_args

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.privacy_check import _reader_sessions, egress, hooks
from mordred_hermes.privacy_check._audit_reasons import EgressRule, ReasonCode

_POSIX = os.name != "nt"
_LOCKED_TOOLS = (
    "write_file",
    "patch",
    "memory",
    "terminal",
    "execute_code",
    "send_message",
    "send_email",
    "telegram_send_message",
    "discord_admin",
    "slack_post",
    "delegate_task",
    "cronjob_manage",
    "cronjob",
    "kanban_create",
    "image_generate",
    "wallet_transfer",
    "mcp_foo",
    "mcp__server__tool",
    "browser_click",
    "browser_type",
    "a2a_call",
    "some_unknown_tool",
)


def _sid() -> str:
    return f"reader-{uuid.uuid4().hex}"


class _Hook:
    """``pre_tool_call`` against a lenient state whose Hermes home is ``tmp_path``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        self.home = home
        self.audit: list[dict[str, Any]] = []
        self.policy = egress.EgressPolicy(level="off")
        state = SimpleNamespace(
            audit=SimpleNamespace(append=lambda entry: self.audit.append(dict(entry))),
            policy_mode="lenient",
            config_path=home / "config.yaml",
            checked=None,
        )
        monkeypatch.setattr(hooks._runtime, "ensure_state", lambda: state)
        monkeypatch.setattr(hooks._runtime, "is_poisoned", lambda: False)
        monkeypatch.setattr(hooks, "safe_audit_append", lambda writer, entry, logger: self.audit.append(dict(entry)))
        monkeypatch.setattr(egress, "load_policy", lambda *a, **k: self.policy)

    def __call__(self, tool: str, args: dict[str, Any] | None = None, session: str | None = None) -> Any:
        kwargs: dict[str, Any] = {"tool_name": tool, "args": args or {}}
        if session is not None:
            kwargs["session_id"] = session
        return hooks.pre_tool_call(**kwargs)

    def rules(self) -> list[str]:
        return [entry.get("rule", entry["reason"]) for entry in self.audit]


@pytest.fixture
def hook(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Hook:
    return _Hook(monkeypatch, tmp_path)


def _forget_in_process(session: str) -> None:
    """Simulate a Hermes restart for one session: the in-process sets are gone."""
    with egress._SESSIONS.lock:
        egress._SESSIONS.reader.discard(session)
        egress._SESSIONS.tainted.discard(session)


def _seed_record(home: Path, data: bytes) -> None:
    with (
        open_private_directory(_reader_sessions.record_path(home).parent, create=True) as directory,
        directory.transaction() as tx,
    ):
        try:
            tx.replace_bytes(_reader_sessions.FILE_NAME, data)
        except Exception:
            tx.create_bytes(_reader_sessions.FILE_NAME, data)


# -- entering reader mode ------------------------------------------------------------------


def test_reader_tool_at_level_off_is_allowed_taints_and_records_durably(hook: _Hook) -> None:
    session = _sid()
    assert hook("telegram_ask", {"question": "q"}, session) is None
    assert egress.is_tainted(session) and egress.reader_mode_established(session)
    path = _reader_sessions.record_path(hook.home)
    raw = path.read_bytes()
    assert session.encode() not in raw
    assert _reader_sessions.load(hook.home) == (_reader_sessions.digest(session),)
    if _POSIX:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_reader_mode_entry_is_audited_once_without_arguments(hook: _Hook) -> None:
    session = _sid()
    assert hook("telegram_ask", {"question": "secret question"}, session) is None
    assert hook("mordred_history_search", {"query": "secret query"}, session) is None
    entries = [e for e in hook.audit if e["reason"] == "policy.egress.reader_mode"]
    assert len(entries) == 1
    assert entries[0]["decision"] == "allow" and entries[0]["tool_name"] == "telegram_ask"
    assert "secret" not in repr(hook.audit) and "args" not in entries[0]


def test_reader_tools_taint_even_when_taint_is_disabled(hook: _Hook) -> None:
    hook.policy = egress.EgressPolicy(level="off", taint=False)
    session = _sid()
    assert hook("telegram_chats", {}, session) is None
    assert egress.is_tainted(session) and egress.reader_mode_established(session)


@pytest.mark.parametrize("level", ["off", "ask", "lockdown"])
def test_reader_tool_without_a_session_is_refused(hook: _Hook, level: str) -> None:
    hook.policy = egress.EgressPolicy(level=level)
    result = hook("telegram_ask", {"question": "q"})
    assert result is not None and result["action"] == "block"
    assert hook.rules()[-1] == "egress.reader_no_session"
    decision = egress.decide("mordred_history_search", {}, None, egress.EgressPolicy(level=level))
    assert not decision.allow and decision.reason == "egress.reader_no_session"
    assert not _reader_sessions.record_path(hook.home).exists()


def test_failed_record_blocks_the_read_and_leaves_no_in_process_state(
    hook: _Hook, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(home: Path, session_id: str) -> None:
        raise _reader_sessions.ReaderRecordError("storage_io")

    monkeypatch.setattr(_reader_sessions, "record", refuse)
    session = _sid()
    result = hook("telegram_ask", {"question": "q"}, session)
    assert result is not None and result["action"] == "block" and "storage_io" in result["message"]
    assert hook.rules()[-1] == "egress.reader_unrecorded"
    assert not egress.is_tainted(session) and not egress.reader_mode_established(session)
    assert not any(e["reason"] == "policy.egress.reader_mode" for e in hook.audit)


def test_unauditable_reader_entry_refuses_this_read_and_retries(hook: _Hook, monkeypatch: pytest.MonkeyPatch) -> None:
    session = _sid()
    real_record = hooks._record
    monkeypatch.setattr(hooks, "_record", lambda state, entry: False)  # Windows: entry not written
    result = hook("telegram_ask", {"question": "q"}, session)
    assert result is not None and result["action"] == "block"
    assert not egress.reader_mode_established(session)
    assert egress.is_reader_session(session, home=hook.home)  # the durable record stands
    monkeypatch.setattr(hooks, "_record", real_record)
    assert hook("telegram_ask", {"question": "q"}, session) is None
    assert [e["reason"] for e in hook.audit].count("policy.egress.reader_mode") == 1


def test_unexpected_error_while_entering_reader_mode_blocks(hook: _Hook, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(session_id: str) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(egress, "mark_reader", broken)
    result = hook("telegram_ask", {"question": "q"}, _sid())
    assert result is not None and result["action"] == "block"


@pytest.mark.skipif(not _POSIX, reason="POSIX directory modes")
def test_unsafe_record_directory_blocks_the_read(hook: _Hook) -> None:
    directory = hook.home / "mordred"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)
    session = _sid()
    result = hook("telegram_ask", {"question": "q"}, session)
    assert result is not None and result["action"] == "block" and "storage_unsafe" in result["message"]
    assert hook.rules()[-1] == "egress.reader_unrecorded"
    assert not egress.reader_mode_established(session)


def test_operator_blocklist_still_blocks_reader_tools_at_level_off(hook: _Hook) -> None:
    hook.policy = egress.parse_policy({"level": "off", "blocked_tools": ["telegram_ask"]})
    session = _sid()
    result = hook("telegram_ask", {"question": "q"}, session)
    assert result is not None and result["action"] == "block"
    assert hook.rules()[-1] == "egress.blocked_tool"
    assert not egress.reader_mode_established(session)
    # Other tools keep the old meaning of "off": the blocklist does not apply.
    policy = egress.parse_policy({"level": "off", "blocked_tools": ["image_generate"]})
    assert egress.decide("image_generate", {}, _sid(), policy).allow


# -- the reader guard ----------------------------------------------------------------------


@pytest.mark.parametrize("tool", _LOCKED_TOOLS)
def test_reader_session_refuses_actions_at_level_off(hook: _Hook, tool: str) -> None:
    session = _sid()
    assert hook("telegram_ask", {"question": "q"}, session) is None
    result = hook(tool, {"command": "ls", "path": "/tmp/x"}, session)
    assert result is not None and result["action"] == "block", tool
    assert hook.rules()[-1] == "egress.reader_locked"
    assert "imported history" in result["message"]


@pytest.mark.parametrize("level", ["off", "blocklist", "ask", "search", "lockdown"])
def test_reader_session_keeps_read_only_tools(hook: _Hook, level: str) -> None:
    hook.policy = egress.EgressPolicy(level=level)
    session = _sid()
    assert hook("telegram_ask", {"question": "q"}, session) is None
    for tool in ("read_file", "session_search", "search_files", "skill_view", "todo", "clarify", "telegram_chats"):
        assert hook(tool, {"path": "/tmp/x"}, session) is None, (level, tool)


def test_reader_session_asks_before_web_use_at_level_off(hook: _Hook) -> None:
    session = _sid()
    assert hook("telegram_ask", {"question": "q"}, session) is None
    result = hook("web_search", {"query": "weather"}, session)
    assert result is not None and result["action"] == "approve"
    assert "imported private history" in result["message"] and "weather" in result["message"]
    assert result["rule_key"].startswith("mordred.egress.reader_web:web_search:")
    assert hook.rules()[-1] == "egress.reader_web"
    fetch = hook("web_extract", {"urls": ["https://docs.example.com/a"]}, session)
    assert fetch is not None and fetch["action"] == "approve" and "docs.example.com" in fetch["message"]
    # A blocklisted destination stays refused outright.
    paste = hook("web_extract", {"urls": ["https://pastebin.com/raw/x"]}, session)
    assert paste is not None and paste["action"] == "block"


def test_stricter_level_rules_win_over_the_reader_web_prompt() -> None:
    session = _sid()
    egress.mark_reader(session)
    locked = egress.decide("web_extract", {"urls": ["https://example.com"]}, session, egress.EgressPolicy("lockdown"))
    assert not locked.allow and not locked.approve
    searched = egress.decide("web_search", {"query": "x"}, session, egress.EgressPolicy("search"))
    assert not searched.allow and not searched.approve  # taint raises "search" to lockdown
    relaxed = egress.decide("web_search", {"query": "x"}, session, egress.EgressPolicy("search", taint=False))
    assert relaxed.approve and relaxed.reason == "egress.reader_web"


def test_other_sessions_are_unaffected(hook: _Hook) -> None:
    reader, other = _sid(), _sid()
    assert hook("telegram_ask", {"question": "q"}, reader) is None
    assert hook("terminal", {"command": "ls"}, other) is None
    assert hook("write_file", {"path": "/tmp/x"}, other) is None


def test_durable_record_survives_a_restart(hook: _Hook) -> None:
    session = _sid()
    assert hook("telegram_ask", {"question": "q"}, session) is None
    _forget_in_process(session)
    assert not egress.reader_mode_established(session)
    assert egress.is_reader_session(session, home=hook.home)
    result = hook("write_file", {"path": "/tmp/x"}, session)
    assert result is not None and hook.rules()[-1] == "egress.reader_locked"
    # The handler-side check needs this process's hook to have run again.
    assert hook("telegram_ask", {"question": "q"}, session) is None
    assert egress.reader_mode_established(session)
    assert _reader_sessions.load(hook.home) == (_reader_sessions.digest(session),)


def test_unreadable_record_fails_closed(hook: _Hook) -> None:
    _seed_record(hook.home, b"{not json")
    session = _sid()
    result = hook("read_file", {"path": "/tmp/x"}, session)
    assert result is not None and result["action"] == "block"
    assert hook.rules()[-1] == "egress.evaluation_failed"
    with pytest.raises(_reader_sessions.ReaderRecordError) as err:
        _reader_sessions.record(hook.home, session)
    assert err.value.code == "corrupt"


# -- Tool Search bridge --------------------------------------------------------------------


def _bridge(*calls: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    return {"calls": [{"name": name, "arguments": arguments} for name, arguments in calls]}


def test_bridge_batch_with_a_reader_tool_and_an_action_is_refused_whole(hook: _Hook) -> None:
    session = _sid()
    batch = _bridge(("telegram_ask", {"question": "q"}), ("terminal", {"command": "ls"}))
    result = hook("tool_call", batch, session)
    assert result is not None and result["action"] == "block"
    assert hook.rules()[-1] == "egress.reader_locked"
    assert not egress.reader_mode_established(session)
    assert not _reader_sessions.record_path(hook.home).exists()
    # The order inside the batch does not matter.
    reverse = _bridge(("send_message", {}), ("mordred_history_search", {}))
    assert not egress.decide("tool_call", reverse, session, egress.EgressPolicy("off")).allow


def test_bridge_batch_of_reads_enters_reader_mode(hook: _Hook) -> None:
    session = _sid()
    batch = _bridge(("read_file", {"path": "/tmp/x"}), ("telegram_ask", {"question": "q"}))
    assert hook("tool_call", batch, session) is None
    assert egress.reader_mode_established(session)
    assert hook("tool_call", _bridge(("session_search", {})), session) is None
    blocked = hook("tool_call", _bridge(("write_file", {"path": "/tmp/x"})), session)
    assert blocked is not None and hook.rules()[-1] == "egress.reader_locked"


def test_bridge_batch_that_asks_still_records_reader_mode_first(hook: _Hook) -> None:
    session = _sid()
    batch = _bridge(("telegram_ask", {"question": "q"}), ("web_search", {"query": "x"}))
    decision = egress.decide("tool_call", batch, session, egress.EgressPolicy("off"))
    assert decision.approve and decision.reader and decision.reason == "egress.reader_web"
    result = hook("tool_call", batch, session)
    assert result is not None and result["action"] == "approve"
    assert egress.reader_mode_established(session)
    # A refusal later in the batch outranks an earlier prompt.
    mixed = _bridge(("web_search", {"query": "x"}), ("telegram_ask", {}), ("terminal", {"command": "ls"}))
    refused = egress.decide("tool_call", mixed, _sid(), egress.EgressPolicy("off"))
    assert not refused.allow and not refused.approve and refused.reason == "egress.reader_locked"


# -- durable record ------------------------------------------------------------------------


def test_record_is_idempotent_and_hashes_ids(tmp_path: Path) -> None:
    _reader_sessions.record(tmp_path, "abc")
    _reader_sessions.record(tmp_path, "abc")
    assert _reader_sessions.load(tmp_path) == (_reader_sessions.digest("abc"),)
    assert _reader_sessions.contains(tmp_path, "abc") and not _reader_sessions.contains(tmp_path, "abd")
    assert b"abc" not in _reader_sessions.record_path(tmp_path).read_bytes()
    with pytest.raises(_reader_sessions.ReaderRecordError):
        _reader_sessions.record(tmp_path, "")


def test_missing_record_reads_as_empty(tmp_path: Path) -> None:
    assert _reader_sessions.load(tmp_path) == ()
    assert not _reader_sessions.contains(tmp_path, "x")
    assert not (tmp_path / "mordred").exists()


def test_eviction_keeps_at_most_512_newest_entries(tmp_path: Path) -> None:
    full = [_reader_sessions.digest(f"old-{i}") for i in range(_reader_sessions.MAX_ENTRIES)]
    _seed_record(tmp_path, _reader_sessions._encode(full))
    assert _reader_sessions.contains(tmp_path, "old-0")
    _reader_sessions.record(tmp_path, "newest")
    stored = _reader_sessions.load(tmp_path)
    assert len(stored) == _reader_sessions.MAX_ENTRIES
    assert stored[-1] == _reader_sessions.digest("newest") and stored[0] == full[1]
    assert not _reader_sessions.contains(tmp_path, "old-0")


@pytest.mark.parametrize(
    "data",
    [
        b'{"version": 2, "sessions": []}',
        b'{"version": true, "sessions": []}',
        b'{"version": 1, "sessions": ["nothex"]}',
        b'{"version": 1, "sessions": [], "extra": 1}',
        b"[]",
        b"\xff",
    ],
)
def test_malformed_records_are_refused(tmp_path: Path, data: bytes) -> None:
    _seed_record(tmp_path, data)
    with pytest.raises(_reader_sessions.ReaderRecordError):
        _reader_sessions.load(tmp_path)


def test_oversized_record_is_refused(tmp_path: Path) -> None:
    too_many = [_reader_sessions.digest(str(i)) for i in range(_reader_sessions.MAX_ENTRIES + 1)]
    _seed_record(tmp_path, _reader_sessions._encode(too_many))
    with pytest.raises(_reader_sessions.ReaderRecordError) as err:
        _reader_sessions.load(tmp_path)
    assert err.value.code == "corrupt"


# -- vocabulary ----------------------------------------------------------------------------


def test_reader_codes_are_registered() -> None:
    rules = set(get_args(EgressRule))
    assert {
        "egress.reader_no_session",
        "egress.reader_unrecorded",
        "egress.reader_locked",
        "egress.reader_web",
    } <= rules
    assert "policy.egress.reader_mode" in get_args(ReasonCode)


def test_every_emitted_egress_rule_is_registered() -> None:
    package = Path(egress.__file__).parent
    emitted: set[str] = set()
    for name in ("egress.py", "hooks.py"):
        emitted |= set(re.findall(r"\"(egress\.[a-z_]+)\"", (package / name).read_text(encoding="utf-8")))
    assert emitted and emitted <= set(get_args(EgressRule))


def test_reader_tool_sets_are_consistent() -> None:
    assert {"telegram_ask", "telegram_chats"} <= egress.READER_TOOLS <= egress.READER_ALLOWED
    assert egress.FIRST_PARTY_TOOLS == egress.TAINT_SOURCES == egress.READER_TOOLS
    assert not egress.READER_ALLOWED & egress.READER_WEB_TOOLS
    assert not (egress.PERSIST_TOOLS | egress.EXEC_TOOLS) & (egress.READER_ALLOWED | egress.READER_WEB_TOOLS)
    assert {"web_search", "web_extract", "browser_navigate", "fetch_url"} <= egress.READER_WEB_TOOLS
