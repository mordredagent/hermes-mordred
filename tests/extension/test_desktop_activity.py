"""``/activity/history`` and ``/status.activity``: the browser-history switches from the Desktop page.

``GET`` reads ``plugins.mordred_activity.history_enabled`` / ``history_tools_enabled``
through the activity config loader; ``POST {"history": bool}`` or ``{"tools": bool}``
(one key, a JSON boolean, nothing else) changes that one key with the CLI's round-trip
writer (``activity use`` / ``activity tools``) and answers the new state without a
restart. Neither opens the activity store, runs the protection gate or prompts; no
other config value, and no parser text, ever leaves the route.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.desktop import _seams, _status_v4, api

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths (macOS fixture)")

CANARY = "canary-model-5b1d"
CONFIG = f"""\
# operator notes stay
model:
  default: {CANARY}  # inline comment
plugins:
  mordred_activity:
    enabled: true   # feature on
    excluded_sites:
      - bank.example
  mordred_network:
    default_path: tor
"""
UNREADABLE = {"history": None, "tools": None, "source": "unreadable"}


def config(desktop: Any) -> Path:
    return Path(desktop.home) / "config.yaml"


@pytest.fixture
def configured(desktop: Any) -> Any:
    config(desktop).write_text(CONFIG, encoding="utf-8")
    return desktop


def _with(line: str) -> str:
    return CONFIG.replace("      - bank.example\n", f"      - bank.example\n    {line}\n")


# -- GET ------------------------------------------------------------------------------------------


def test_get_without_a_config_answers_the_defaults(desktop: Any) -> None:
    assert desktop.get("/activity/history") == {"ok": True, "history": True, "tools": True}
    assert not config(desktop).exists()


def test_get_reads_both_switches(desktop: Any) -> None:
    config(desktop).write_text(_with("history_tools_enabled: false"), encoding="utf-8")
    assert desktop.get("/activity/history") == {"ok": True, "history": True, "tools": False}
    config(desktop).write_text(_with("history_enabled: false"), encoding="utf-8")
    assert desktop.get("/activity/history") == {"ok": True, "history": False, "tools": True}


def test_an_unparsable_config_is_config_unreadable_and_quoted_nowhere(desktop: Any) -> None:
    config(desktop).write_text(f"plugins: [{CANARY}\nsecret: {CANARY}\n", encoding="utf-8")
    answers = [desktop.get("/activity/history"), desktop.get("/status?client_version=4")]
    assert answers[0] == {"ok": False, "error": "config_unreadable"}
    assert answers[1]["ok"] is True and answers[1]["activity"] == UNREADABLE
    assert CANARY not in str(answers) and not any(CANARY in line for line in desktop.logs.lines)


def test_a_failing_read_is_config_unreadable_and_never_fails_the_status(
    configured: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(home: Path) -> dict[str, bool]:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(_seams, "activity_history", boom)
    assert configured.get("/activity/history") == {"ok": False, "error": "config_unreadable"}
    status = configured.get("/status?client_version=4")
    assert status["ok"] is True and status["activity"] == UNREADABLE
    assert not any(CANARY in line for line in configured.logs.lines)


# -- POST -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "line", "state"),
    [
        ({"history": False}, "history_enabled: false", {"history": False, "tools": True}),
        ({"history": True}, "history_enabled: true", {"history": True, "tools": True}),
        ({"tools": False}, "history_tools_enabled: false", {"history": True, "tools": False}),
        ({"tools": True}, "history_tools_enabled: true", {"history": True, "tools": True}),
    ],
)
def test_post_changes_one_key_and_answers_the_new_state_without_a_restart(
    configured: Any, body: dict[str, bool], line: str, state: dict[str, bool]
) -> None:
    answer = configured.post("/activity/history", body)
    assert answer == {"ok": True, **state, "restart_required": False}
    assert config(configured).read_text(encoding="utf-8") == _with(line)  # every other byte is kept
    assert configured.get("/activity/history") == {"ok": True, **state}
    assert configured.get("/status?client_version=4")["activity"] == {**state, "source": "config"}


def test_the_two_switches_round_trip_to_the_original_meaning(configured: Any) -> None:
    configured.post("/activity/history", {"tools": False})
    configured.post("/activity/history", {"history": False})
    assert configured.get("/activity/history") == {"ok": True, "history": False, "tools": False}
    loaded = ActivityConfig.load(Path(configured.home))
    assert (loaded.enabled, loaded.excluded_sites, loaded.history_active) == (True, {"bank.example"}, False)
    configured.post("/activity/history", {"history": True})
    answer = configured.post("/activity/history", {"tools": True})
    assert answer == {"ok": True, "history": True, "tools": True, "restart_required": False}
    assert config(configured).read_text(encoding="utf-8") == _with(
        "history_tools_enabled: true\n    history_enabled: true"
    )


def test_post_passes_the_config_key_to_the_writer_seam(configured: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Path, str, bool]] = []
    monkeypatch.setattr(_seams, "set_history_switch", lambda home, key, value: calls.append((home, key, value)))
    configured.post("/activity/history", {"tools": False})
    configured.post("/activity/history", {"history": True})
    home = Path(configured.home)
    assert calls == [(home, "history_tools_enabled", False), (home, "history_enabled", True)]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"history": True, "tools": False},
        {"history": "true"},
        {"tools": 1},
        {"tools": 0},
        {"history": None},
        {"history": [True]},
        {"enabled": True},
        {"history_enabled": False},
        {"direct": True},
    ],
)
def test_only_one_known_key_with_a_json_boolean_is_accepted(configured: Any, body: dict[str, Any]) -> None:
    assert configured.post("/activity/history", body) == {"ok": False, "error": "invalid_body"}
    assert config(configured).read_text(encoding="utf-8") == CONFIG


@pytest.mark.parametrize("raw", [b"[true]", b"true", b'{"tools": fals', b"tools=false", b""])
def test_a_malformed_or_empty_body_is_invalid_body(configured: Any, raw: bytes) -> None:
    assert configured.post("/activity/history", raw=raw) == {"ok": False, "error": "invalid_body"}
    assert config(configured).read_text(encoding="utf-8") == CONFIG


def test_an_unexpected_write_failure_is_config_write_failed_without_its_text(
    configured: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(home: Path, key: str, value: bool) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(_seams, "set_history_switch", boom)
    assert configured.post("/activity/history", {"tools": False}) == {"ok": False, "error": "config_write_failed"}
    assert not any(CANARY in line for line in configured.logs.lines)


@pytest.mark.parametrize(
    "text",
    [
        "plugins:\n- mordred\n",  # plugins is not a mapping
        "base: &shared\n  enabled: true\nplugins:\n  mordred_activity: *shared\n  mordred_network: *shared\n",
        f"plugins: [{CANARY}\nsecret: {CANARY}\n",  # unparsable: the parser's text quotes the line
    ],
    ids=["not-a-mapping", "yaml-anchor", "unparsable"],
)
def test_a_refused_write_leaves_the_file_and_quotes_nothing(desktop: Any, text: str) -> None:
    config(desktop).write_text(text, encoding="utf-8")
    answer = desktop.post("/activity/history", {"tools": False})
    assert answer == {"ok": False, "error": "config_write_failed"}
    assert config(desktop).read_text(encoding="utf-8") == text
    assert CANARY not in str(answer) and not any(CANARY in line for line in desktop.logs.lines)


def test_an_unreadable_state_after_the_write_is_config_unreadable(
    configured: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(home: Path) -> dict[str, bool]:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(_seams, "activity_history", boom)
    assert configured.post("/activity/history", {"tools": False}) == {"ok": False, "error": "config_unreadable"}
    assert config(configured).read_text(encoding="utf-8") == _with("history_tools_enabled: false")


# -- no store, no gate, no prompt -----------------------------------------------------------------


class _Tripped(BaseException):
    """Not an ``Exception``: no fallback handler on these routes can swallow it into a state."""


def test_no_store_gate_or_touch_id_seam_is_touched(configured: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def wire(name: str) -> Any:
        def tripped(*_args: object, **_kwargs: object) -> object:
            calls.append(name)
            raise _Tripped(name)

        return tripped

    for target in (
        "mordred_hermes.activity._gate.check_protection",
        "mordred_hermes.activity._gate.open_store",
        "mordred_hermes.activity._gate.keyed_opener",
        "mordred_hermes.activity._history_access.reader",
        "mordred_hermes.dbcrypt._key.KeyProvider",
        "mordred_hermes.dbcrypt._key._inject_vault_env",
        "mordred_hermes.extension.telegram.tee.hardware_backend",
        "mordred_hermes.keyvault._anchor_keychain.default_anchor_store",
    ):
        monkeypatch.setattr(target, wire(target))
    monkeypatch.setattr(_seams, "run_ceremony", wire("run_ceremony"))
    assert configured.get("/activity/history")["ok"] is True
    assert configured.post("/activity/history", {"tools": False})["ok"] is True
    assert configured.post("/activity/history", {"history": False})["ok"] is True
    assert configured.get("/activity/history") == {"ok": True, "history": False, "tools": False}
    assert calls == []


# -- /status.activity -----------------------------------------------------------------------------


def test_the_status_projection_drops_everything_but_the_two_switches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_seams, "activity_history", lambda home: {"history": False, "tools": True, "extra": CANARY})
    assert _status_v4.activity_safe(Path("/unused")) == {"history": False, "tools": True, "source": "config"}
    monkeypatch.setattr(_seams, "activity_history", lambda home: {"history": "yes", "tools": True})
    assert _status_v4.activity_safe(Path("/unused")) == UNREADABLE
    monkeypatch.setattr(_seams, "activity_history", lambda home: {"history": True})
    assert _status_v4.activity_safe(Path("/unused")) == UNREADABLE


@pytest.mark.parametrize("version", [1, 2, 3])
def test_older_clients_get_no_activity_key(configured: Any, version: int) -> None:
    assert "activity" not in configured.get(f"/status?client_version={version}")


def test_linux_status_carries_activity_too(configured: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    configured.post("/activity/history", {"tools": False})
    assert configured.get("/status?client_version=4")["activity"] == {
        "history": True,
        "tools": False,
        "source": "config",
    }


def test_no_answer_or_log_carries_another_config_value(configured: Any) -> None:
    answers = [
        configured.get("/activity/history"),
        configured.post("/activity/history", {"tools": False}),
        configured.get("/status?client_version=4"),
        configured.post("/activity/history", {"tools": True}),
    ]
    assert CANARY not in str(answers) and not any(CANARY in line for line in configured.logs.lines)
    assert not configured.leaked(answers)
