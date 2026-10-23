"""``/tools/direct`` and ``/status.tools``: Hermes's direct tool calls from the Desktop page.

``GET`` reads ``tools.tool_search.enabled``; ``POST {"direct": bool}`` (a JSON boolean,
nothing else) changes it on the owner's explicit request and asks for a restart.
Failures are the closed codes of ``wizard.direct_tools``; no other config value ever
leaves the route.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")

from mordred_hermes.desktop import _seams, _status_v4, api
from mordred_hermes.wizard.direct_tools import ERROR_CODES, DirectToolsError

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the POSIX writer path (macOS fixture)")

CANARY = "canary-model-3e8a"
CONFIG = f"# kept\nmodel:\n  default: {CANARY}\n"


def config(desktop: Any) -> Path:
    return Path(desktop.home) / "config.yaml"


@pytest.fixture
def configured(desktop: Any) -> Any:
    path = config(desktop)
    path.write_text(CONFIG, encoding="utf-8")
    path.chmod(0o600)
    return desktop


def test_get_reads_the_default(configured: Any) -> None:
    assert configured.get("/tools/direct") == {"ok": True, "direct": False, "source": "default"}


def test_post_true_writes_off_and_asks_for_a_restart(configured: Any) -> None:
    answer = configured.post("/tools/direct", {"direct": True})
    assert answer == {"ok": True, "direct": True, "restart_required": True}
    text = config(configured).read_text(encoding="utf-8")
    assert text == CONFIG + 'tools:\n  tool_search:\n    enabled: "off"\n'
    assert configured.get("/tools/direct") == {"ok": True, "direct": True, "source": "config"}
    assert configured.get("/status?client_version=4")["tools"] == {"direct": True, "source": "config"}


def test_post_false_removes_the_key(configured: Any) -> None:
    configured.post("/tools/direct", {"direct": True})
    answer = configured.post("/tools/direct", {"direct": False})
    assert answer == {"ok": True, "direct": False, "restart_required": True}
    assert config(configured).read_text(encoding="utf-8") == CONFIG
    assert configured.get("/status?client_version=4")["tools"] == {"direct": False, "source": "default"}


@pytest.mark.parametrize(
    "body", [{}, {"direct": "true"}, {"direct": 1}, {"direct": 0}, {"direct": None}, {"direct": [True]}, {"on": True}]
)
def test_only_a_json_boolean_is_accepted(configured: Any, body: dict[str, Any]) -> None:
    assert configured.post("/tools/direct", body) == {"ok": False, "error": "invalid_body"}
    assert config(configured).read_text(encoding="utf-8") == CONFIG


@pytest.mark.parametrize("raw", [b"[true]", b"true", b'{"direct": tru', b"direct=true"])
def test_a_malformed_body_is_invalid_body(configured: Any, raw: bytes) -> None:
    assert configured.post("/tools/direct", raw=raw) == {"ok": False, "error": "invalid_body"}
    assert config(configured).read_text(encoding="utf-8") == CONFIG


@pytest.mark.parametrize("code", ERROR_CODES)
def test_library_refusals_pass_their_closed_code(configured: Any, monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    def refuse(home: Path, enabled: bool) -> None:
        raise DirectToolsError(code)

    monkeypatch.setattr(_seams, "set_direct_tools", refuse)
    assert configured.post("/tools/direct", {"direct": True}) == {"ok": False, "error": code}


def test_an_unexpected_failure_is_config_write_failed_without_its_text(
    configured: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(home: Path, enabled: bool) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(_seams, "set_direct_tools", boom)
    answer = configured.post("/tools/direct", {"direct": True})
    assert answer == {"ok": False, "error": "config_write_failed"}
    assert not any(CANARY in line for line in configured.logs.lines)


def test_an_unreadable_config_is_a_code_and_a_status_state(configured: Any) -> None:
    config(configured).write_text(f"model: [{CANARY}\n", encoding="utf-8")
    assert configured.get("/tools/direct") == {"ok": False, "error": "config_unreadable"}
    assert configured.post("/tools/direct", {"direct": True}) == {"ok": False, "error": "config_unreadable"}
    status = configured.get("/status?client_version=4")
    assert status["ok"] is True and status["tools"] == {"direct": None, "source": "unreadable"}
    assert CANARY not in str(status) and not any(CANARY in line for line in configured.logs.lines)


def test_a_sealed_away_config_is_refused_as_vault_managed(desktop: Any) -> None:
    from mordred_hermes.keyvault._config_bootstrap import _marker_path

    marker = _marker_path(Path(desktop.home))
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("vault-managed\n", encoding="utf-8")
    assert desktop.get("/tools/direct") == {"ok": False, "error": "config_vault_managed"}
    assert desktop.post("/tools/direct", {"direct": True}) == {"ok": False, "error": "config_vault_managed"}
    assert not config(desktop).exists()
    assert desktop.get("/status?client_version=4")["tools"] == {"direct": None, "source": "unreadable"}


def test_a_failing_read_never_fails_the_status(configured: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(home: Path) -> dict[str, Any]:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(_seams, "tools_mode", boom)
    status = configured.get("/status?client_version=4")
    assert status["ok"] is True and status["tools"] == {"direct": None, "source": "unreadable"}
    assert configured.get("/tools/direct") == {"ok": False, "error": "config_unreadable"}
    assert not any(CANARY in line for line in configured.logs.lines)


def test_the_status_projection_drops_everything_but_direct_and_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _seams, "tools_mode", lambda home: {"direct": True, "source": "config", "raw": "off", "extra": CANARY}
    )
    assert _status_v4.tools_safe(Path("/unused")) == {"direct": True, "source": "config"}
    monkeypatch.setattr(_seams, "tools_mode", lambda home: {"direct": "yes", "source": CANARY})
    assert _status_v4.tools_safe(Path("/unused")) == {"direct": None, "source": "unreadable"}


@pytest.mark.parametrize("version", [1, 2, 3])
def test_older_clients_get_no_tools_key(configured: Any, version: int) -> None:
    assert "tools" not in configured.get(f"/status?client_version={version}")


def test_linux_status_carries_tools_too(configured: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "sys", SimpleNamespace(platform="linux"))
    configured.post("/tools/direct", {"direct": True})
    assert configured.get("/status?client_version=4")["tools"] == {"direct": True, "source": "config"}


def test_no_answer_or_log_carries_another_config_value(configured: Any) -> None:
    answers = [
        configured.get("/tools/direct"),
        configured.post("/tools/direct", {"direct": True}),
        configured.get("/tools/direct"),
        configured.get("/status?client_version=4"),
        configured.post("/tools/direct", {"direct": False}),
    ]
    assert CANARY not in str(answers) and not any(CANARY in line for line in configured.logs.lines)
    assert not configured.leaked(answers)


def test_an_aliased_tool_search_is_refused_by_the_route(desktop: Any) -> None:
    text = "base: &a\n  enabled: auto\ntools:\n  tool_search: *a\n"
    config(desktop).write_text(text, encoding="utf-8")
    assert desktop.post("/tools/direct", {"direct": True}) == {"ok": False, "error": "config_unsupported_shape"}
    assert config(desktop).read_text(encoding="utf-8") == text


def test_a_yaml_warning_is_unreadable_and_quoted_nowhere(desktop: Any, capfd: pytest.CaptureFixture[str]) -> None:
    config(desktop).write_text(f"model: &m {CANARY}\nother: &m {CANARY}-2\n", encoding="utf-8")
    status = desktop.get("/status?client_version=4")
    assert status["tools"] == {"direct": None, "source": "unreadable"}
    assert desktop.get("/tools/direct") == {"ok": False, "error": "config_unreadable"}
    assert desktop.post("/tools/direct", {"direct": True}) == {"ok": False, "error": "config_unreadable"}
    out, err = capfd.readouterr()
    assert CANARY not in out + err and not any(CANARY in line for line in desktop.logs.lines)
